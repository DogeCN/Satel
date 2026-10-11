package coord

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/websocket"

	"satel/internal/desync"
	"satel/internal/strategy"
)

// 单条隧道流的缓冲上限。超过就不再往协调端读，给 TCP 施加背压——与 NetMaster
// 的背压做法一致：控制面与隧道面共用一条连接，不限流会把整条连接拖垮。
const streamBuf = 1 << 20

// 建连与重试的超时。
const (
	dialTimeout  = 10 * time.Second
	maxRetries   = 2
	streamClosed = "control: stream closed"
)

var errConnLost = errors.New("coord: 控制连接断开")

// Conn 是到协调端的长连接。控制面（BUNDLE/REPORT/EVOLVE）与隧道面（OPEN/DATA/
// CLOSE）共用它——40 条浏览器连接也只对应一次 TLS + ECH 握手。
type Conn struct {
	host string
	port string
	key  []byte
	fp   string
	caps []string
	doh  string

	mu      sync.Mutex
	ws      *websocket.Conn
	pending map[uint32]chan frame
	streams map[uint32]*streamConn
	nextID  uint32
	gen     uint64
	closed  bool

	wmu    sync.Mutex // 串行化写
	cmux   sync.Mutex // 串行化建连
	ips    []string
	echCfg []byte
	boot   *strategy.Spec
	plain  bool // ws:// 明文（仅本地/测试）；wss:// 走 TLS+ECH
}

// NewConn 造一个尚未建连的 Conn。第一次使用时才真正拨号。
func NewConn(host, port string, key []byte, fp string, caps []string) *Conn {
	return &Conn{
		host:    host,
		port:    port,
		key:     key,
		fp:      fp,
		caps:    caps,
		pending: map[uint32]chan frame{},
		streams: map[uint32]*streamConn{},
	}
}

// SetPlain 切到 ws:// 明文。只给本地与测试用：线上必须 wss，否则帧是裸奔的。
func (c *Conn) SetPlain(v bool) { c.plain = v }

// SetDoH 记录用于取 ECH 配置的 DoH 端点（供重连时复用）。
func (c *Conn) SetDoH(doh string) { c.doh = doh }

// SetIPs 固定优先拨的边缘 IP（DoH 解析结果）。空 = 用系统解析。
func (c *Conn) SetIPs(ips []string) { c.ips = ips }

// SetECH 换 ECH 配置并作废当前连接（下次使用时用新配置重连）。
func (c *Conn) SetECH(cfg []byte) {
	c.mu.Lock()
	changed := !bytesEqual(c.echCfg, cfg)
	c.echCfg = cfg
	c.mu.Unlock()
	if changed {
		c.drop()
	}
}

// SetBootstrap 换控制通道的自举分片招法。nil = 关闭自举分片。
func (c *Conn) SetBootstrap(spec *strategy.Spec) { c.boot = spec }

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- 配置 -------------------------------------------------------------------

func (c *Conn) tlsConfig() *tls.Config {
	cfg := &tls.Config{
		ServerName: c.host,
		// 用 ECH 时必须是 TLS 1.3。
		MinVersion: tls.VersionTLS13,
	}
	if len(c.echCfg) > 0 {
		cfg.EncryptedClientHelloConfigList = c.echCfg
	}
	return cfg
}

func (c *Conn) dialAddr() string {
	if len(c.ips) > 0 {
		return net.JoinHostPort(c.ips[0], c.port)
	}
	return net.JoinHostPort(c.host, c.port)
}

// --- 建连 -------------------------------------------------------------------

// ensure 保证有一条可用连接。幂等：已有就直接返回。
func (c *Conn) ensure(ctx context.Context) (*websocket.Conn, uint64, error) {
	c.mu.Lock()
	ws, gen := c.ws, c.gen
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, 0, errors.New("coord: 已关闭")
	}
	if ws != nil {
		return ws, gen, nil
	}

	c.cmux.Lock()
	defer c.cmux.Unlock()

	// 等锁期间可能已经有人建好了
	c.mu.Lock()
	if c.ws != nil {
		ws, gen = c.ws, c.gen
		c.mu.Unlock()
		return ws, gen, nil
	}
	c.mu.Unlock()

	ws, gen, err := c.dial(ctx)
	if err != nil {
		return nil, 0, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		ws.Close()
		return nil, 0, errors.New("coord: 已关闭")
	}
	c.ws, c.gen = ws, gen
	c.mu.Unlock()
	return ws, gen, nil
}

// dial 完成 TCP → 自举分片 → TLS(ECH) → WS 升级 → HELLO 鉴权。
func (c *Conn) dial(ctx context.Context) (*websocket.Conn, uint64, error) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	raw, err := (&net.Dialer{}).DialContext(dctx, "tcp", c.dialAddr())
	if err != nil {
		return nil, 0, fmt.Errorf("coord: 拨号 %s 失败: %w", c.dialAddr(), err)
	}
	var transport net.Conn
	if c.plain {
		transport = raw
	} else {
		// 控制通道自己也是被墙的，所以首段也过分片——工具用自己的招法保护自己的通道。
		conn := desync.WrapConn(raw, c.boot, strategy.ProtoTLS, desync.Options{})
		tc := tls.Client(conn, c.tlsConfig())
		if err := tc.HandshakeContext(dctx); err != nil {
			raw.Close()
			// ECH 被服务端拒绝时它会带回一份新的 RetryConfigList，装上再试一次。
			var rej *tls.ECHRejectionError
			if errors.As(err, &rej) && len(rej.RetryConfigList) > 0 {
				c.SetECH(rej.RetryConfigList)
				return c.dial(ctx)
			}
			return nil, 0, fmt.Errorf("coord: 控制通道 TLS 失败: %w", err)
		}
		_ = tc.SetDeadline(time.Time{})
		transport = tc
	}

	scheme := "wss"
	if c.plain {
		scheme = "ws"
	}
	wsURL := scheme + "://" + net.JoinHostPort(c.host, c.port) + "/"
	cfg, err := websocket.NewConfig(wsURL, "http://"+c.host)
	if err != nil {
		transport.Close()
		return nil, 0, fmt.Errorf("coord: 构造 WS 请求失败: %w", err)
	}
	ws, err := websocket.NewClient(cfg, transport)
	if err != nil {
		transport.Close()
		return nil, 0, fmt.Errorf("coord: WS 升级失败: %w", err)
	}
	// PayloadType 只对 Conn.Write 生效；我们走 websocket.Message，它对 []byte
	// 自动用 BinaryFrame，所以这里不需要设。

	gen := c.nextGen()
	if err := c.hello(ws); err != nil {
		ws.Close()
		return nil, 0, err
	}
	go c.readLoop(ws, gen)
	return ws, gen, nil
}

// hello 发首帧并等 STATUS。必须在 readLoop 启动之前做——第一帧是唯一的同步点。
func (c *Conn) hello(ws *websocket.Conn) error {
	ts := time.Now().Unix()
	auth := signHello(c.key, ts)
	payload := encodeHello(ts, auth, c.fp, c.caps)
	_ = ws.SetWriteDeadline(time.Now().Add(dialTimeout))
	if err := websocket.Message.Send(ws, encodeFrame(opHello, 0, payload)); err != nil {
		return fmt.Errorf("coord: 发送 HELLO 失败: %w", err)
	}
	_ = ws.SetWriteDeadline(time.Time{})

	_ = ws.SetReadDeadline(time.Now().Add(dialTimeout))
	var data []byte
	if err := websocket.Message.Receive(ws, &data); err != nil {
		return fmt.Errorf("coord: 等待 HELLO 应答失败: %w", err)
	}
	_ = ws.SetReadDeadline(time.Time{})

	f, err := decodeFrame(data)
	if err != nil {
		return fmt.Errorf("coord: HELLO 应答不是合法帧: %w", err)
	}
	if f.op != opStatus {
		return fmt.Errorf("coord: HELLO 应答 opcode %d，期望 STATUS", f.op)
	}
	code, msg, err := decodeStatus(f.data)
	if err != nil {
		return err
	}
	if code != statusOK {
		return fmt.Errorf("coord: 协调端拒绝建连 (code=%d %s)", code, msg)
	}
	return nil
}

func (c *Conn) nextGen() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	return c.gen
}

// write 发**一条 WS 消息**。
//
// 必须用 websocket.Message 而不是 Conn.Write：Conn.Write/Read 是**流式** API，
// 缓冲区不够时会部分读写，下一帧的字节会被当成当前帧的续篇——对一个"一条消息
// 就是一帧"的协议，那会把字节流切错位。症状很隐蔽：:80 这类一次往返的请求看着
// 正常，隧道里跑 TLS（多轮往返、首飞行段几 KB）就报 bad record MAC / record 版本
// 不符。Message.Send 对 []byte 自动用 BinaryFrame。
func (c *Conn) write(ws *websocket.Conn, raw []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return websocket.Message.Send(ws, raw)
}

// --- 读循环 -----------------------------------------------------------------

func (c *Conn) readLoop(ws *websocket.Conn, gen uint64) {
	defer func() {
		ws.Close()
		c.mu.Lock()
		if c.gen == gen {
			c.ws = nil
			for id, ch := range c.pending {
				close(ch)
				delete(c.pending, id)
			}
			for id, s := range c.streams {
				s.fail(errConnLost)
				delete(c.streams, id)
			}
		}
		c.mu.Unlock()
	}()

	for {
		// Message.Receive 一次取回**整条消息**（内部 io.ReadAll(frame)），
		// 与帧的边界严格对齐——不能换成 Conn.Read，理由见 write 的注释。
		var data []byte
		if err := websocket.Message.Receive(ws, &data); err != nil {
			return
		}
		f, err := decodeFrame(data)
		if err != nil {
			continue // 单帧坏不影响后续
		}
		c.dispatch(f, gen)
	}
}

func (c *Conn) dispatch(f frame, gen uint64) {
	switch f.op {
	case opData:
		c.mu.Lock()
		s := c.streams[f.id]
		c.mu.Unlock()
		if s != nil {
			s.deliver(f.data)
		}
	case opClose:
		c.mu.Lock()
		s := c.streams[f.id]
		delete(c.streams, f.id)
		c.mu.Unlock()
		if s != nil {
			s.closeRead(string(f.data))
		}
	case opOpened:
		c.mu.Lock()
		s := c.streams[f.id]
		c.mu.Unlock()
		if s != nil && len(f.data) > 0 {
			select {
			case s.opened <- openResult{code: f.data[0]}:
			default:
			}
		}
	case opStatus, opBundleResp, opReportResp, opEvolveResp:
		c.mu.Lock()
		ch := c.pending[f.id]
		c.mu.Unlock()
		if ch != nil {
			select {
			case ch <- f:
			default: // 等待者已经走了
			}
		}
	}
}

// --- 请求-响应 --------------------------------------------------------------

// RoundTrip 发一帧请求并等响应。连接在途中断了会自动重连并重发一次。
func (c *Conn) RoundTrip(ctx context.Context, op opcode, payload []byte) (frame, error) {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		ws, _, err := c.ensure(ctx)
		if err != nil {
			lastErr = err
			continue
		}
		id := c.allocID()
		ch := make(chan frame, 1)
		c.mu.Lock()
		c.pending[id] = ch
		c.mu.Unlock()

		if err := c.write(ws, encodeFrame(op, id, payload)); err != nil {
			c.mu.Lock()
			delete(c.pending, id)
			c.mu.Unlock()
			lastErr = err
			c.drop()
			continue // 重连后重放
		}
		select {
		case f := <-ch:
			return f, nil
		case <-ctx.Done():
			c.mu.Lock()
			delete(c.pending, id)
			c.mu.Unlock()
			return frame{}, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("coord: 请求失败")
	}
	return frame{}, lastErr
}

func (c *Conn) allocID() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	if c.nextID == 0 {
		c.nextID++
	}
	return c.nextID
}

// drop 让当前连接失效：关掉 WS（readLoop 会清空 pending/streams）。
func (c *Conn) drop() {
	c.mu.Lock()
	ws := c.ws
	c.ws = nil
	c.mu.Unlock()
	if ws != nil {
		ws.Close()
	}
}

// --- 隧道 -------------------------------------------------------------------

type openResult struct {
	code byte
}

// Open 在控制连接上开一条到 host:port 的原始字节流。
func (c *Conn) Open(ctx context.Context, host string, port int) (net.Conn, error) {
	payload, err := encodeOpen(host, port)
	if err != nil {
		return nil, err
	}
	ws, _, err := c.ensure(ctx)
	if err != nil {
		return nil, err
	}
	id := c.allocID()
	sc := newStreamConn(c, ws, id)

	c.mu.Lock()
	c.streams[id] = sc
	c.mu.Unlock()

	if err := c.write(ws, encodeFrame(opOpen, id, payload)); err != nil {
		c.mu.Lock()
		delete(c.streams, id)
		c.mu.Unlock()
		return nil, err
	}
	select {
	case r := <-sc.opened:
		if r.code != openOK {
			c.mu.Lock()
			delete(c.streams, id)
			c.mu.Unlock()
			return nil, fmt.Errorf("coord: 协调端拒绝打开 %s:%d (code=%d)", host, port, r.code)
		}
		return sc, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.streams, id)
		c.mu.Unlock()
		return nil, ctx.Err()
	case <-sc.done:
		return nil, errConnLost
	}
}

// --- 生命周期 ---------------------------------------------------------------

// Close 关闭连接并唤醒所有等待者。
func (c *Conn) Close() error {
	c.mu.Lock()
	c.closed = true
	ws := c.ws
	c.ws = nil
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	for id, s := range c.streams {
		s.fail(errConnLost)
		delete(c.streams, id)
	}
	c.mu.Unlock()
	if ws != nil {
		return ws.Close()
	}
	return nil
}

// --- 隧道流 -----------------------------------------------------------------

// TunnelClosedError 是"对端把隧道关了"的错误。服务端把失败原因放在 CLOSE 帧的
// payload 里（见 server/src/ws.js 的 pumpToClient），这里原样带出来——
// 否则隧道失败在调用方只是一句没有线索的 EOF，排查时无从下手。
type TunnelClosedError struct{ Why string }

func (e *TunnelClosedError) Error() string { return "coord: 隧道被对端关闭: " + e.Why }

// Reason 返回服务端给的原因（可能是空串）。
func (e *TunnelClosedError) Reason() string { return e.Why }

type streamConn struct {
	c      *Conn
	ws     *websocket.Conn
	id     uint32
	opened chan openResult
	done   chan struct{}

	mu     sync.Mutex
	in     chan []byte
	buf    []byte
	eof    bool
	err    error
	closed bool

	rdDl, wrDl time.Time
}

func newStreamConn(c *Conn, ws *websocket.Conn, id uint32) *streamConn {
	return &streamConn{
		c:      c,
		ws:     ws,
		id:     id,
		opened: make(chan openResult, 1),
		done:   make(chan struct{}),
		in:     make(chan []byte, 64),
	}
}

func (s *streamConn) deliver(b []byte) {
	s.mu.Lock()
	if s.closed || s.eof {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	// 满了就阻塞：这就是背压——不再从协调端读，TCP 窗口自然收缩。
	select {
	case s.in <- append([]byte(nil), b...):
	case <-s.done:
	}
}

func (s *streamConn) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.shutdown()
}

// closeRead 标记读侧结束。reason 非空时作为错误返回——服务端把失败原因放在
// CLOSE 帧的 payload 里，隧道失败不应该只表现为一个没有线索的 EOF。
func (s *streamConn) closeRead(reason string) {
	s.mu.Lock()
	s.eof = true
	if reason != "" && s.err == nil {
		s.err = &TunnelClosedError{Why: reason}
	}
	s.mu.Unlock()
	s.shutdown()
}

func (s *streamConn) shutdown() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	close(s.done)
}

// Read 从隧道读。收到 CLOSE 或协调端断开时返回 io.EOF。
func (s *streamConn) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.buf) > 0 {
			n := copy(p, s.buf)
			s.buf = s.buf[n:]
			s.mu.Unlock()
			return n, nil
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return 0, err
		}
		if s.eof {
			err := s.err
			s.mu.Unlock()
			if err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		dl := s.rdDl
		s.mu.Unlock()

		var timeout <-chan time.Time
		if !dl.IsZero() {
			t := time.NewTimer(time.Until(dl))
			defer t.Stop()
			timeout = t.C
		}
		select {
		case b := <-s.in:
			s.mu.Lock()
			s.buf = b
			s.mu.Unlock()
		case <-s.done:
			s.mu.Lock()
			err := s.err
			s.mu.Unlock()
			if err != nil {
				return 0, err
			}
			return 0, io.EOF
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// Write 把数据送进隧道。
func (s *streamConn) Write(p []byte) (int, error) {
	s.mu.Lock()
	closed, err := s.closed, s.err
	s.mu.Unlock()
	if closed {
		if err != nil {
			return 0, err
		}
		return 0, net.ErrClosed
	}
	if err := s.c.write(s.ws, encodeFrame(opData, s.id, p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close 关闭这条流（半关闭：仍可读，只是不再写）。
func (s *streamConn) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.c.mu.Lock()
	delete(s.c.streams, s.id)
	s.c.mu.Unlock()
	_ = s.c.write(s.ws, encodeFrame(opClose, s.id, nil))
	close(s.done)
	return nil
}

func (s *streamConn) LocalAddr() net.Addr  { return streamAddr{} }
func (s *streamConn) RemoteAddr() net.Addr { return streamAddr{} }

func (s *streamConn) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.rdDl, s.wrDl = t, t
	s.mu.Unlock()
	return nil
}

func (s *streamConn) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.rdDl = t
	s.mu.Unlock()
	return nil
}

func (s *streamConn) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.wrDl = t
	s.mu.Unlock()
	return nil
}

type streamAddr struct{}

func (streamAddr) Network() string { return "satel-ws" }
func (streamAddr) String() string  { return "coordinator" }
