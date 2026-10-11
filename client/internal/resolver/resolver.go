// Package resolver 解析目标主机名。走 DoH，避免本地 DNS 污染把连接引到黑洞 IP
// ——SNI 分片只解决"连接被 RST"，解决不了"连到了错的服务器"。
//
// 端点为什么是这个组合（2026-10-12 实测）：
//
//	Cloudflare Gateway (xwfpeb16ii.…gateway.com)  干净且稳定，但慢（0.5–2.5s）
//	doh.pub / 1.12.12.12                        快（~70ms），但对封锁域名**经常**返回
//	                                           污染答案（discord 10 次全错），且跨
//	                                           分钟会翻转
//	223.5.5.5                                   支持 HTTPS RR(ECH)，但 A 记录 10/10 污染
//
// 所以：Gateway 为主（正确性优先，延迟由缓存吸收），doh.pub 兜底（主端点不可达时
// 用，宁可偶尔拿到污染答案也比完全没有强），系统 DNS 最后。
package resolver

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"satel/internal/ech"
)

// 每次拨号最多尝试几个解析结果，避免在几十个 IP 上逐个等超时。
const maxTryIPs = 3

// 默认端点。Cloudflare Gateway 干净但慢；doh.pub 快但对封锁域名不可靠——
// 前者求正确，后者求可用，两条都要。
var defaultEndpoints = []string{
	"https://xwfpeb16ii.cloudflare-gateway.com/dns-query",
	"https://doh.pub/dns-query",
}

type entry struct {
	ips   []string
	until time.Time
}

// DoH 是带内存缓存的多端点解析器。零值不可用，用 NewDoH 构造。
type DoH struct {
	// Endpoints 按优先级排列。空 = 用 defaultEndpoints。
	Endpoints []string
	TTL       time.Duration
	Timeout   time.Duration

	mu    sync.Mutex
	cache map[string]entry
	sys   *net.Resolver
}

// NewDoH 构造解析器。endpoint 可以是单个地址（逗号分隔多个表示优先级）。
func NewDoH(endpoint string) *DoH {
	var eps []string
	for _, e := range splitEndpoints(endpoint) {
		eps = append(eps, e)
	}
	if len(eps) == 0 {
		eps = defaultEndpoints
	}
	return &DoH{
		Endpoints: eps,
		TTL:       10 * time.Minute,
		Timeout:   8 * time.Second,
		cache:     map[string]entry{},
		sys:       net.DefaultResolver,
	}
}

func splitEndpoints(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := trimSpace(s[start:i])
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\n' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}

// LookupHost 返回 host 的地址列表。IP 字面量原样返回。
// 顺序：缓存 → 各 DoH 端点依次 → 系统解析。
func (d *DoH) LookupHost(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}
	if ips, ok := d.cached(host); ok {
		return ips, nil
	}
	for _, ep := range d.Endpoints {
		cctx, cancel := context.WithTimeout(ctx, d.Timeout)
		ips, err := ech.ResolveA(cctx, ep, host)
		cancel()
		if err == nil && len(ips) > 0 {
			d.store(host, ips)
			return ips, nil
		}
	}
	addrs, err := d.sys.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	d.store(host, addrs)
	return addrs, nil
}

// Primary 返回优先级最高的端点——取 ECH 配置之类的旁路查询用它；没有配置则空。
func (d *DoH) Primary() string {
	if len(d.Endpoints) == 0 {
		return ""
	}
	return d.Endpoints[0]
}

func (d *DoH) cached(host string) ([]string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.cache[host]
	if !ok || time.Now().After(e.until) {
		return nil, false
	}
	return e.ips, true
}

func (d *DoH) store(host string, ips []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache[host] = entry{ips: ips, until: time.Now().Add(d.TTL)}
}

// dialer 是 ctx 感知的拨号器：context 取消/截止会立刻中断 TCP 连接与 DNS 查询，
// 而不是干等 timeout。
var dialer = &net.Dialer{KeepAlive: 30 * time.Second}

// dialContext 解析 host 并连到 port。ctx 的取消/截止同时作用于 DNS 与 TCP。
func dialContext(ctx context.Context, r *DoH, host string, port int, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if r == nil {
		return dialer.DialContext(ctx, "tcp", addr)
	}
	ips, err := r.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		return dialer.DialContext(ctx, "tcp", addr)
	}
	if len(ips) > maxTryIPs {
		ips = ips[:maxTryIPs]
	}
	var lastErr error
	for _, ip := range ips {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c, derr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if derr == nil {
			return c, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

// Dial 解析 host 并连到 port，ctx 取消/截止即中断（DNS 与 TCP 都受其约束）。
func Dial(ctx context.Context, r *DoH, host string, port int, timeout time.Duration) (net.Conn, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return dialContext(ctx, r, host, port, timeout)
}

// DialOne 只尝试解析出的第一个地址，ctx 取消/截止即中断。
//
// 用于"先快速判定 TCP 层是否可达"的场景：黑洞 IP 上逐个试满会白付 N 倍超时，
// 而这一步的目的只是判断"拨得通吗"，不是"找到能拨通的那个"。
func DialOne(ctx context.Context, r *DoH, host string, port int, timeout time.Duration) (net.Conn, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return dialContext(ctx, r, host, port, timeout)
}
