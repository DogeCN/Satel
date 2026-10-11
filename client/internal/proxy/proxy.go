// Package proxy 是本地入口：一个端口同时接 SOCKS5 与 HTTP CONNECT，把目标连接
// 交给探测阶梯——明文直连 → 候选策略逐个尝试 → 全失败即断开。判定只看传输层：
// 首字节有没有在窗口内回来。
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"satel/internal/desync"
	"satel/internal/ech"
	"satel/internal/engine"
	"satel/internal/failkind"
	"satel/internal/flight"
	"satel/internal/mitm"
	"satel/internal/proxyip"
	"satel/internal/resolver"
	"satel/internal/strategy"
)

// Server 是本地代理。零值不可用，用 New 构造。
type Server struct {
	Engine      *engine.Engine
	Resolver    *resolver.DoH // 目标解析器；nil = 系统 DNS
	MITM        *mitm.CA      // TLS 终止层；nil = 不启用（信任区安装失败时）
	DoH         string        // 取共享 ECH 配置用的 DoH 端点
	DialTimeout time.Duration // 上游建连超时
	CaptureWait time.Duration // 等客户端首段的上限
	ProbeWait   time.Duration // 每个候选等首字节的窗口
	Log         func(format string, args ...any)

	// Tunnel 经协调端开一条到目标的原始字节通道；nil = 不可用（离线模式）。
	// 用于非 Cloudflare 承载的被墙站。
	Tunnel func(ctx context.Context, host string, port int) (net.Conn, error)
	// Relay 是本机侧的中继池（按可用性自排序），用于 CF 承载且锁国区的站。
	Relay *proxyip.Pool
}

// New 用合理的默认值构造。
func New(e *engine.Engine) *Server {
	return &Server{
		Engine:      e,
		DialTimeout: 5 * time.Second,
		CaptureWait: 10 * time.Second,
		ProbeWait:   3 * time.Second,
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log(format, args...)
	}
}

// Serve 循环接受连接，每条连接一个 goroutine。
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	head, err := br.Peek(1)
	if err != nil {
		return
	}
	var host string
	var port int
	if head[0] == 0x05 {
		host, port, err = s.socks5(c, br)
	} else {
		host, port, err = s.httpConnect(c, br)
	}
	if err != nil {
		s.logf("[in] 握手失败: %v", err)
		return
	}
	s.tunnel(c, br, host, port)
}

// tunnel 是核心阶梯：抄下首段 → 按记忆层给的方法列表逐个试 → 成功即转普通转发。
//
// 阶梯**形状不再硬编码**：direct / 策略 / ech / tunnel / proxyip 都是"方法"，
// 由 engine.Memory 按后验排好序。唯一的固定策略是"新 host 先打 direct 拿信号"
// ——那是探测，不是决策。
func (s *Server) tunnel(c net.Conn, br *bufio.Reader, host string, port int) {
	bc := bcWrap(c, br)
	fl, tail, err := flight.Capture(bc, "", s.CaptureWait)
	if err != nil {
		s.logf("[in] %s 未收到首段: %v", host, err)
		return
	}
	proto := flight.Detect(fl)
	if proto == "" {
		proto = strategy.ProtoTLS
	}

	// 解析一次：isCF 是分组特征，也供后面拨号。分组只在**第一次失败拿到类别**时
	// 才用上 isCF——所以这里不必（也不该）提前把"信号"编进 group 键。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	isCF := ech.AnyCloudflare(s.lookup(ctx, host))
	cancel()

	// @ech/@proxyip/@tunnel 都要先终止客户端 TLS，而终止是一次性的：第一次
	// Terminate 就消费掉了 ClientHello，之后 ctls.Close() 还会关掉底层连接。
	// 所以三者不能各自独立尝试——先终止一次拿到会话，再在这个会话里依次试上游。
	var sess *clientSession
	var sessErr error
	var tcpDown bool

	// 阶梯不是一次性排好的：每打完一枪都把剩余方法重排。因为"新 host 先打 direct
	// 拿信号"这一枪本身就产出分组特征——它一失败，host 就被归进 isCF+类别 的组，
	// 组先验立刻可用。实测 zh.wikipedia 首访：direct 失败后按组直达 @tunnel，
	// 而不是把 11 条策略挨个烧完；第二次访问同一 host 更是零 miss 直奔 @tunnel。
	//
	// 唯一不能跨越的边界是 TLS 终止：openSession 一旦消费掉 ClientHello，包级
	// 方法（split/tlsrf/…）就再无机会，所以 sess 非 nil 时必须跳过它们。
	var plan []string
	tried := map[string]bool{}
	for {
		if plan == nil {
			plan = s.Engine.Methods(host, proto)
		}
		method := ""
		for _, m := range plan {
			if !tried[m] {
				method = m
				break
			}
		}
		if method == "" {
			break
		}
		tried[method] = true

		if !engine.NeedsTermination(method) {
			if tcpDown || sess != nil {
				// TCP 层不可达、或客户端 TLS 已被终止消费：包级方法没有赢面。
				continue
			}
			ok, down := s.trySimple(c, bc, host, port, proto, isCF, method, fl, tail)
			if ok {
				return
			}
			if down {
				tcpDown = true
			}
			plan = nil
			continue
		}
		if sess == nil {
			sess, sessErr = s.openSession(c, host, fl, tail)
			if sessErr != nil {
				s.logf("[mitm] %s 无法终止客户端 TLS，本连接不再尝试上游方法: %v", host, sessErr)
				break
			}
		}
		k, merr := s.tryTerminating(sess, method, host)
		s.Engine.Record(host, proto, method, nil, k, isCF)
		if k == failkind.None {
			s.logf("[%s] %s", strings.TrimPrefix(method, "@"), host)
			return
		}
		s.logf("[miss] %s %s: %s%s", host, method, k.Label(), reasonSuffix(merr))
		plan = nil
	}
	s.logf("[fail] %s 方法列表用尽", host)
}

// reasonSuffix 把失败原因附到日志后面，让人不必靠猜。
//
// 两级来源：
//  1. 服务端在 CLOSE 帧 payload 里给的 reason（协调端拨不了 Cloudflare 自有网段时
//     就会给出 "Stream was cancelled."）；
//  2. 没有 reason 就用错误本身的文本——**这一条很关键**：不加的话，@ech 这类失败
//     在日志里只剩一个笼统的"其它"，而隧道路径却有原因，两边不对称、排查时只能靠猜。
//
// 过长的错误截断，避免一行日志刷屏。
func reasonSuffix(err error) string {
	if err == nil {
		return ""
	}
	var t interface{ Reason() string }
	if errors.As(err, &t) {
		if r := t.Reason(); r != "" {
			return " [" + r + "]"
		}
	}
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120] + "…"
	}
	return " (" + msg + ")"
}

// tryMethod 按一个方法尝试；成功即接管连接并返回 true。
func (s *Server) trySimple(c net.Conn, bc *bufConn, host string, port int,
	proto string, isCF bool, method string, fl, tail []byte) (ok bool, tcpDown bool) {

	switch {
	case method == engine.MethodDirect:
		up, first, _, _, err := s.attempt(host, port, fl, tail, nil)
		if err != nil {
			k := failkind.Classify(err)
			s.Engine.Record(host, proto, method, nil, k, isCF)
			s.logf("[miss] %s direct: %s%s", host, k.Label(), reasonSuffix(err))
			return false, !k.Reachable()
		}
		s.Engine.Record(host, proto, method, nil, failkind.None, isCF)
		s.logf("[direct] %s", host)
		s.finish(c, bc, up, first)
		return true, false

	default: // 策略 ID：不消耗客户端 TLS，可反复试
		spec := s.Engine.SpecByID(method)
		if spec == nil {
			return false, false
		}
		up, first, rtt, unsup, err := s.attempt(host, port, fl, tail, spec)
		k := failkind.None
		if err != nil {
			k = failkind.Classify(err)
		}
		s.Engine.RecordAttempt(host, proto, spec, err == nil, rtt, unsup, k)
		if err == nil {
			s.Engine.Record(host, proto, method, spec, failkind.None, isCF)
			s.logf("[ok] %s <- %s (%dms)%s", host, method, rtt.Milliseconds(), unsupNote(unsup))
			s.finish(c, bc, up, first)
			return true, false
		}
		s.Engine.Record(host, proto, method, spec, k, isCF)
		s.logf("[miss] %s %s: %s", host, method, k.Label())
		if !k.Reachable() {
			// 拨号不通：TCP 都没建立，包级改写没有任何赢面。
			// 把信号回传给调用方**真的跳过**后续包级方法——只打日志不跳会白烧
			// 每个方法一个拨号超时（实测 4 条策略 = 20 秒）。
			s.logf("[skip] %s TCP 层不可达，跳过后续包级方法", host)
			return false, true
		}
		return false, false
	}
}

type clientSession struct {
	ctls *tls.Conn
	host string
}

// openSession 终止客户端 TLS，把明文流交给上游方法。
//
// **只能调用一次**：Terminate 会消费掉客户端的 ClientHello，之后任何一次
// ctls.Close() 都会关掉底层连接。三个上游方法必须共用这一个会话。
func (s *Server) openSession(c net.Conn, host string, fl, tail []byte) (*clientSession, error) {
	if s.MITM == nil {
		return nil, errors.New("本地 CA 不可用（未装入信任区）")
	}
	pre := make([]byte, 0, len(fl)+len(tail))
	pre = append(pre, fl...)
	pre = append(pre, tail...)
	ctls, err := s.MITM.Terminate(c, pre)
	if err != nil {
		s.logf("[mitm] %s 客户端握手失败: %v", host, err)
		return nil, err
	}
	return &clientSession{ctls: ctls, host: host}, nil
}

// tryTerminating 在已终止的会话上试一个上游方法。成功即接管连接。
func (s *Server) tryTerminating(sess *clientSession, method, host string) (failkind.Kind, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	ctls := sess.ctls
	unsupported := errors.New("该方法在当前配置下不可用")

	var up net.Conn
	var err error
	switch method {
	case engine.MethodECH:
		prof, perr := ech.Cloudflare(ctx, s.DoH)
		if perr != nil {
			return failkind.Other, perr
		}
		up, err = mitm.DialECH(ctx, prof.IP, host, prof.ECHConfig, 8*time.Second)
	case engine.MethodTunnel:
		if s.Tunnel == nil {
			return failkind.Other, unsupported
		}
		raw, terr := s.Tunnel(ctx, host, 443)
		if terr != nil {
			return failkind.Classify(terr), terr
		}
		// 通道另一端只转字节，TLS 得我们来说
		up, err = mitm.Handshake(ctx, raw, host, nil, 10*time.Second)
		if err != nil {
			raw.Close()
			return failkind.Classify(err), err
		}
	case engine.MethodProxy:
		if s.Relay == nil {
			return failkind.Other, unsupported
		}
		up, err = s.Relay.Dial(ctx, host, 443, 10*time.Second)
	default:
		return failkind.Other, unsupported
	}
	if err != nil {
		return failkind.Classify(err), err
	}
	defer up.Close()

	// 等客户端的首个请求（明文，MITM 已解密）
	req, rerr := readChunk(ctls, 5*time.Second)
	if rerr != nil {
		s.logf("[idle] %s 客户端未发请求即断开", host)
		return failkind.Canceled, rerr
	}

	if _, err := up.Write(req); err != nil {
		return failkind.Classify(err), err
	}
	_ = up.SetReadDeadline(time.Now().Add(8 * time.Second))
	resp, rerr := readChunk(up, 8*time.Second)
	_ = up.SetReadDeadline(time.Time{})
	if rerr != nil && len(resp) == 0 {
		return failkind.Classify(rerr), rerr
	}
	if method == engine.MethodECH && isBlockedStatus(resp) {
		// ECH 直连被地区/机器人策略拦下——这是"上游活着但拒绝"，不是隧道故障。
		return failkind.Other, errors.New("ECH 直连被上游以 4xx 拒绝")
	}

	if _, err := ctls.Write(resp); err != nil {
		return failkind.Write, err
	}
	relayBoth(ctls, up)
	return failkind.None, nil
}

// isPseudoMethod 判断方法 ID 是四种伪方法之一（@direct/@ech/@tunnel/@proxyip）。
func isPseudoMethod(id string) bool {
	for _, p := range engine.PseudoMethods {
		if p == id {
			return true
		}
	}
	return false
}

func bcWrap(c net.Conn, br *bufio.Reader) *bufConn { return &bufConn{Conn: c, r: br} }

// lookup 解析目标地址；解析器不可用时退回系统解析。
func (s *Server) lookup(ctx context.Context, host string) []string {
	if s.Resolver != nil {
		if ips, err := s.Resolver.LookupHost(ctx, host); err == nil {
			return ips
		}
	}
	ips, _ := net.DefaultResolver.LookupHost(ctx, host)
	return ips
}

// readChunk 读一段（可能是请求头，也可能是它的一部分）。字节流语义下，读多读少
// 都不影响正确性——缓冲下来的前缀原样重放即可。
func readChunk(c net.Conn, timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 16*1024)
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	n, err := c.Read(buf)
	_ = c.SetReadDeadline(time.Time{})
	if n == 0 {
		if err == nil {
			err = errors.New("proxy: 读到 0 字节")
		}
		return nil, err
	}
	return buf[:n], nil
}

// writeAndPeek 把 req 写出去并读回一段响应。
func writeAndPeek(up net.Conn, req []byte, timeout time.Duration) ([]byte, error) {
	if _, err := up.Write(req); err != nil {
		return nil, err
	}
	return readChunk(up, timeout)
}

// isBlockedStatus 判断响应是否是被地区/机器人策略拦下。
func isBlockedStatus(resp []byte) bool {
	line := firstLine(resp)
	if !strings.HasPrefix(line, "HTTP/1.") {
		return false
	}
	return strings.Contains(line, " 403") || strings.Contains(line, " 451")
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

// relayBoth 在两条已解密的连接之间双向转发。
func relayBoth(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(b, a); closeWrite(b) }()
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); closeWrite(a) }()
	wg.Wait()
}

// attempt 建一条上游连接并应用策略（spec==nil 即明文直连），返回首个响应字节。
func (s *Server) attempt(host string, port int, fl, tail []byte, spec *strategy.Spec) (net.Conn, []byte, time.Duration, bool, error) {
	up, err := resolver.DialOne(context.Background(), s.Resolver, host, port, s.DialTimeout)
	if err != nil {
		return nil, nil, 0, false, err
	}
	start := time.Now()
	unsup := false
	if spec != nil {
		res, aerr := desync.Apply(up, spec, fl, tail, desync.Options{})
		unsup = len(res.Unsupported) > 0
		if aerr != nil {
			up.Close()
			return nil, nil, time.Since(start), unsup, aerr
		}
	} else {
		if err := writeAll(up, fl); err != nil {
			up.Close()
			return nil, nil, time.Since(start), false, err
		}
		if len(tail) > 0 {
			if err := writeAll(up, tail); err != nil {
				up.Close()
				return nil, nil, time.Since(start), false, err
			}
		}
	}
	first, perr := s.waitFirst(up)
	if perr != nil {
		up.Close()
		return nil, nil, time.Since(start), unsup, perr
	}
	return up, first, time.Since(start), unsup, nil
}

// waitFirst 等上游的首个字节；把读到的字节交回调用方（必须转给客户端）。
func (s *Server) waitFirst(up net.Conn) ([]byte, error) {
	buf := make([]byte, 4096)
	_ = up.SetReadDeadline(time.Now().Add(s.ProbeWait))
	n, err := up.Read(buf)
	_ = up.SetReadDeadline(time.Time{})
	if n > 0 {
		// TLS 告警（记录类型 0x15）不是"通了"——它是握手被拒。把它当成功会把
		// 一个死连接交给客户端，用户看到的是一个莫名的安全错误。
		if isTLSAlert(buf[:n]) {
			return nil, errors.New("probe: 上游返回 TLS 告警（握手被拒）")
		}
		return buf[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("probe: 上游零字节")
}

// isTLSAlert 判断首包是否为 TLS 告警记录。
func isTLSAlert(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x15 && b[1] == 0x03
}

// finish 把探到的首包交给客户端，然后双向转发。
func (s *Server) finish(c net.Conn, bc *bufConn, up net.Conn, first []byte) {
	defer up.Close()
	if len(first) > 0 {
		if err := writeAll(c, first); err != nil {
			return
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, bc)
		closeWrite(up)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c, up)
		closeWrite(c)
	}()
	wg.Wait()
}

func (s *Server) socks5(c net.Conn, br *bufio.Reader) (string, int, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return "", 0, err
	}
	if hdr[0] != 0x05 {
		return "", 0, fmt.Errorf("socks5: 版本 %d 非 5", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return "", 0, err
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // 无认证
		return "", 0, err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return "", 0, err
	}
	if req[1] != 0x01 { // 只支持 CONNECT
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", 0, fmt.Errorf("socks5: 命令 %d 不支持", req[1])
	}
	host, port, err := readAddr(br, req[3])
	if err != nil {
		return "", 0, err
	}
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func readAddr(r io.Reader, atyp byte) (string, int, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 6)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		return net.IP(b[:4]).String(), int(binary.BigEndian.Uint16(b[4:])), nil
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		b := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		return string(b[:len(b)-2]), int(binary.BigEndian.Uint16(b[len(b)-2:])), nil
	case 0x04:
		b := make([]byte, 18)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		return net.IP(b[:16]).String(), int(binary.BigEndian.Uint16(b[16:])), nil
	}
	return "", 0, fmt.Errorf("socks5: 未知 ATYP %d", atyp)
}

func (s *Server) httpConnect(c net.Conn, br *bufio.Reader) (string, int, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", 0, err
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 {
		return "", 0, errors.New("http: 请求行非法")
	}
	if !strings.EqualFold(parts[0], "CONNECT") {
		_, _ = c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"))
		return "", 0, fmt.Errorf("http: 只支持 CONNECT，收到 %s", parts[0])
	}
	host, portStr, err := net.SplitHostPort(parts[1])
	if err != nil {
		host, portStr = parts[1], "443"
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return "", 0, err
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// bufConn 让 Capture 从 bufio.Reader 读（握手期间可能已缓冲了首段的一部分），
// 而 deadline 仍作用在底层连接上。
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func writeAll(c net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("proxy: 写入 0 字节")
		}
		b = b[n:]
	}
	return nil
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func unsupNote(unsup bool) string {
	if unsup {
		return " [含不支持的招法]"
	}
	return ""
}
