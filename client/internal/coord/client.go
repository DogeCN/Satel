// Package coord 是到协调端的客户端。传输层是一条长连接：控制面与隧道面共用，
// 建连时用 HELLO 鉴权一次，之后帧不再签名。
package coord

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"satel/internal/ech"
	"satel/internal/strategy"
)

// Strategy 是下发的一条策略。客户端不信任 ID——会本地重算校验。
type Strategy struct {
	ID   string
	Spec string
}

// Bundle 是 /v1/bundle 的等价物（走 BUNDLE_RESP 帧）。
//
// Hints 是协调端从全体客户端回报里挖出来的后缀经验，与策略库同帧下发——省一次
// 往返，也保证"策略"与"怎么用这些策略"是同一版本的世界观。
type Bundle struct {
	Version int
	Items   []Strategy
	Hints   []Hint
}

// Hint 是一条后缀经验：某类后缀上某方法的历史结论。
// OK/Fail 是全体客户端累计的成败次数，Hosts 是贡献过的主机数，
// Expires 是 Unix 秒（服务端给短 TTL，因为封锁态势变得快）。
type Hint struct {
	Suffix  string
	Method  string
	OK      int
	Fail    int
	Hosts   int
	Expires int64
}

// Item 是一条**方法级**效果回报。线上是二进制字段，见 frame.go 的 reportEntry。
//
// Host 是明文主机名（不再哈希）；Method 是伪方法 ID 或 8 位策略 ID；Kind 是失败
// 类别（failkind.Key()，成功为 "ok"）。Kind 让协调端能区分"直连被复位"与"直连
// 黑洞"——"把 GFW 黑名单长出来"靠的就是这个信号。
type Item struct {
	Host   string
	Method string
	Kind   string
	OK     int
	Unsup  int
	RTTms  int
	TS     int64
	// Proto 是这批回报的协议（"tls"/"http"）。
	Proto string
	// Batch 是幂等键：连接断开重发时用**同一个**值，协调端才能分辨
	// "同一批重发"与"新一批"。由调用方在攒批时生成一次；留空则按批内容派生。
	Batch string
}

// Client 是协调端客户端。零值不可用，用 New。
type Client struct {
	conn *Conn
	now  func() time.Time
}

// New 造一个客户端。base 形如 wss://satel.example.com（可带尾斜杠）。
// 连接是惰性的：第一次真正用到时才拨号。
func New(base, password, fp string, caps []string) (*Client, error) {
	if base == "" {
		return nil, fmt.Errorf("coord: base 为空")
	}
	if password == "" {
		return nil, fmt.Errorf("coord: password 为空")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("coord: base 非法: %w", err)
	}
	if u.Scheme != "wss" && u.Scheme != "ws" {
		return nil, fmt.Errorf("coord: base 需要 ws/wss scheme，实际 %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("coord: base 缺主机名")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	sum := sha256.Sum256([]byte("satel/v1/" + password))
	c := NewConn(host, port, sum[:], fp, caps)
	// ws:// 明文只给本地与测试用；线上应当是 wss。
	c.SetPlain(u.Scheme == "ws")
	// 控制通道自己也会被墙：首段也过分片。内置库已按实测排序，第一条是能赢的招法。
	if b := strategy.BuiltinFor(strategy.ProtoTLS); len(b) > 0 {
		c.SetBootstrap(b[0])
	}
	return &Client{conn: c, now: time.Now}, nil
}

// SetDoH 记录用于取 ECH 配置的 DoH 端点。
func (c *Client) SetDoH(doh string) { c.conn.SetDoH(doh) }

// SetBootstrap 换控制通道的自举分片招法。nil = 关闭。
func (c *Client) SetBootstrap(spec *strategy.Spec) { c.conn.SetBootstrap(spec) }

// Close 关闭连接。调用方必须关，否则进程退出时会残留一条连接。
func (c *Client) Close() error { return c.conn.Close() }

// Tunnel 经协调端开一条到 host:port 的原始字节通道。
//
// 用于非 Cloudflare 承载的被墙站：它们在本地是 IP 黑洞，包级改写无解；协调端的
// 出口不受此限。通道内由调用方自己做 TLS，DPI 只看得到一条到协调端的 ECH 连接。
//
// 走的是和控制通道同一条链路——ECH + 优选边缘 IP + 自举分片 + 多路复用。
func (c *Client) Tunnel(ctx context.Context, host string, port int) (net.Conn, error) {
	return c.conn.Open(ctx, host, port)
}

// EnableECH 取 Cloudflare 的共享 ECH 配置与一个可达边缘 IP，装到连接上。
//
// 为什么用共享配置：被墙的 Cloudflare 承载域名大多**自己不发布** ECH 配置
// （实测 medium/discord/chatgpt 的 HTTPS RR 里都没有 ech=），但 crypto.cloudflare.com
// 上有一份共享的——用它 + 任意 CF 边缘 IP，把内层 SNI 设成真域名即可。实测
// discord.com / chatgpt.com 握手后 ECHAccepted=true。
func (c *Client) EnableECH(ctx context.Context, doh string) error {
	c.conn.SetDoH(doh)
	prof, err := ech.Fetch(ctx, doh, ech.CloudflareHost)
	if err != nil {
		return fmt.Errorf("coord: 取 Cloudflare 共享 ECH 配置失败: %w", err)
	}
	if len(prof.ECHConfig) == 0 {
		return fmt.Errorf("coord: %s 未发布 ECH 配置", ech.CloudflareHost)
	}
	c.conn.SetECH(prof.ECHConfig)
	if len(prof.IPv4) > 0 {
		c.conn.SetIPs(prof.IPv4)
	}
	return nil
}

// FetchBundle 拉取某 proto 的策略库。客户端不校验 ID（调用方做），也不信 score。
func (c *Client) FetchBundle(ctx context.Context, proto string, n int) (*Bundle, error) {
	if n <= 0 {
		n = 8
	}
	if n > maxBundleN {
		n = maxBundleN
	}
	f, err := c.conn.RoundTrip(ctx, opBundle, encodeBundle(proto, n))
	if err != nil {
		return nil, err
	}
	if f.op == opStatus {
		code, msg, _ := decodeStatus(f.data)
		return nil, fmt.Errorf("coord: 协调端返回 STATUS(code=%d %s)", code, msg)
	}
	if f.op != opBundleResp {
		return nil, fmt.Errorf("coord: 期望 BUNDLE_RESP，收到 opcode %d", f.op)
	}
	version, items, hints, err := decodeBundleResp(f.data)
	if err != nil {
		return nil, err
	}
	b := &Bundle{Version: version, Items: make([]Strategy, 0, len(items))}
	for _, it := range items {
		b.Items = append(b.Items, Strategy{ID: it.id, Spec: it.spec})
	}
	for _, h := range hints {
		b.Hints = append(b.Hints, Hint{
			Suffix: h.suffix, Method: h.method,
			OK: int(h.ok), Fail: int(h.fail), Hosts: int(h.hosts),
			Expires: int64(h.expires),
		})
	}
	return b, nil
}

// Report 上报一批效果。超出上限的会被截断。
func (c *Client) Report(ctx context.Context, items []Item) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	if len(items) > maxReportN {
		items = items[:maxReportN]
	}
	entries := make([]reportEntry, 0, len(items))
	for _, it := range items {
		ts := it.TS
		if ts == 0 {
			ts = c.now().Unix()
		}
		kind := it.Kind
		if kind == "" {
			if it.OK != 0 {
				kind = "ok"
			} else {
				kind = "other"
			}
		}
		entries = append(entries, reportEntry{
			host: it.Host, method: it.Method,
			ok: it.OK != 0, unsup: it.Unsup != 0,
			rtt: uint32(it.RTTms), ts: uint64(ts), kind: kind, proto: it.Proto,
		})
	}
	batch := items[0].Batch
	if batch == "" {
		// 按批内容派生：同一批数据（含序号）重发得到同一 ID，天然幂等。
		batch = batchIDFor(entries)
	}
	payload, err := encodeReport(batch, entries)
	if err != nil {
		return 0, err
	}
	f, err := c.conn.RoundTrip(ctx, opReport, payload)
	if err != nil {
		return 0, err
	}
	if f.op == opStatus {
		code, msg, _ := decodeStatus(f.data)
		return 0, fmt.Errorf("coord: 协调端返回 STATUS(code=%d %s)", code, msg)
	}
	if f.op != opReportResp {
		return 0, fmt.Errorf("coord: 期望 REPORT_RESP，收到 opcode %d", f.op)
	}
	if len(f.data) < 4 {
		return 0, fmt.Errorf("coord: REPORT_RESP 太短")
	}
	return int(binary.BigEndian.Uint32(f.data)), nil
}

// Evolve 触发一代演化。需要管理员密钥（与口令独立的共享密钥）。
func (c *Client) Evolve(ctx context.Context, adminKey string) (map[string]any, error) {
	f, err := c.conn.RoundTrip(ctx, opEvolve, encodeEvolve(adminKey))
	if err != nil {
		return nil, err
	}
	if f.op == opStatus {
		code, msg, _ := decodeStatus(f.data)
		return nil, fmt.Errorf("coord: 协调端拒绝 (code=%d %s)", code, msg)
	}
	if f.op != opEvolveResp {
		return nil, fmt.Errorf("coord: 期望 EVOLVE_RESP，收到 opcode %d", f.op)
	}
	if len(f.data) < 16 {
		return nil, fmt.Errorf("coord: EVOLVE_RESP 太短")
	}
	return map[string]any{
		"generation": int(binary.BigEndian.Uint32(f.data[0:])),
		"born":       int(binary.BigEndian.Uint32(f.data[4:])),
		"retired":    int(binary.BigEndian.Uint32(f.data[8:])),
		"pool":       int(binary.BigEndian.Uint32(f.data[12:])),
	}, nil
}

// TrimScheme 去掉 base 的 scheme 与尾斜杠，给日志用。
func TrimScheme(base string) string {
	return strings.TrimPrefix(strings.TrimPrefix(strings.TrimRight(base, "/"), "wss://"), "ws://")
}
