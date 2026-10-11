// Package ech 从 DoH 的 HTTPS RR 里取 ECH 配置与边缘 IP。
//
// 为什么需要：控制通道（客户端 → 协调端）走的是普通 TLS，明文 SNI 会被阻断设备
// 按域名 RST。ECH 把真实 SNI 加密进 ClientHello，外层只露出 cloudflare-ech.com，
// 于是这条路能直连。DoH 用 IP 字面量直连（223.5.5.5），避免引导阶段的 DNS 污染。
//
// 同一套机制也用于 MITM 上游：见 cloudflare.go 的共享配置。
package ech

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Record 是 HTTPS RR 里我们用得上的部分。
type Record struct {
	// ECHConfig 是已解码的 ECHConfigList；RR 里没有 ech= 时为 nil。
	ECHConfig []byte
	// IPv4 是 ipv4hint 给出的边缘地址（可能是空）。
	IPv4 []string
}

var (
	// 各 DoH 提供方对 HTTPS RR 展示格式里参数值的引号处理**不一致**：AliDNS 给
	// ech="A2…"，Cloudflare Gateway 给 ech=A2…（无引号）。两种都必须认，否则换端点
	// 就会静默地拿不到 ECH 配置，MITM 分支整条失效。
	echRe  = regexp.MustCompile(`ech="([^"]*)"|ech=([^\s]*)`)
	hintRe = regexp.MustCompile(`ipv4hint="([^"]*)"|ipv4hint=([^\s]*)`)
)

type dohAnswer struct {
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dohResp struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
}

// dohClient 专用于 DoH：不走 ECH、不做分片（DoH 端点本身不被墙）。
var dohClient = &http.Client{Timeout: 8 * time.Second}

// Fetch 查 host 的 HTTPS RR（type 65）。
func Fetch(ctx context.Context, endpoint, host string) (*Record, error) {
	resp, err := query(ctx, endpoint, host, "HTTPS")
	if err != nil {
		return nil, err
	}
	rec := &Record{}
	for _, a := range resp.Answer {
		if a.Type != 65 {
			continue
		}
		cfg, ips, perr := parseHTTPSData(a.Data)
		if perr != nil {
			return nil, perr
		}
		if cfg != nil {
			rec.ECHConfig = cfg
		}
		rec.IPv4 = append(rec.IPv4, ips...)
	}
	return rec, nil
}

// parseHTTPSData 解析一条 HTTPS RR 的展示格式，取出 ech= 与 ipv4hint=。
// 独立成函数以便离线测试。
// firstGroup 取正则的第一个非空捕获组——带引号与不带引号两种形式各占一组。
func firstGroup(m []string) string {
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return ""
}

func parseHTTPSData(data string) (echCfg []byte, ipv4 []string, err error) {
	if m := echRe.FindStringSubmatch(data); m != nil {
		cfg, derr := decodeBase64(firstGroup(m))
		if derr != nil {
			return nil, nil, fmt.Errorf("ech: ech 参数解码失败: %w", derr)
		}
		echCfg = cfg
	}
	if m := hintRe.FindStringSubmatch(data); m != nil {
		for _, ip := range strings.Split(firstGroup(m), ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				ipv4 = append(ipv4, ip)
			}
		}
	}
	return echCfg, ipv4, nil
}

// ResolveA 查 host 的 A 记录，用于绕过本地 DNS 污染。
func ResolveA(ctx context.Context, endpoint, host string) ([]string, error) {
	resp, err := query(ctx, endpoint, host, "A")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range resp.Answer {
		if a.Type == 1 && a.Data != "" {
			out = append(out, a.Data)
		}
	}
	return out, nil
}

func query(ctx context.Context, endpoint, host, rrtype string) (*dohResp, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("ech: DoH 端点为 空")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("ech: DoH 端点非法: %w", err)
	}
	q := u.Query()
	q.Set("name", host)
	q.Set("type", rrtype)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-json")
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ech: DoH 请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ech: DoH 返回 %d", resp.StatusCode)
	}
	var out dohResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("ech: DoH 响应解析失败: %w", err)
	}
	if out.Status != 0 {
		return nil, fmt.Errorf("ech: DoH 状态 %d", out.Status)
	}
	return &out, nil
}

// decodeBase64 兼容标准与 URL-safe 两种 base64。
func decodeBase64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// --- Cloudflare 共享 ECH 配置 -------------------------------------------------
//
// 被墙的 Cloudflare 承载域名大多**自己不发布** ECH 配置（实测 medium.com /
// discord.com / chatgpt.com 的 HTTPS RR 里都没有 ech=）。但 Cloudflare 在
// crypto.cloudflare.com 上发布了一份**共享配置**，把它的内层 SNI 换成任意
// CF 承载的域名都能被边缘解密——实测 ECHAccepted=true，discord.com 拿到 200。
// 所以这里取一次、缓存复用，不必按域名取。

// CloudflareHost 是 Cloudflare 发布**共享** ECH 配置的域名。被墙的 CF 承载
// 域名大多自己不发布 ECH 配置，但这份共享的配合任意 CF 边缘 IP 都能用——
// 实测 discord.com / chatgpt.com 握手后 ECHAccepted=true。
const CloudflareHost = "crypto.cloudflare.com"

// Profile 是 Cloudflare 的共享 ECH 配置与一个可达边缘 IP。
type Profile struct {
	ECHConfig []byte
	IP        string
}

var (
	cfMu       sync.Mutex
	cfCached   *Profile
	cfCachedAt time.Time
)

const cfProfileTTL = time.Hour

// Cloudflare 返回共享 ECH 配置 + 边缘 IP（带 1 小时缓存）。
func Cloudflare(ctx context.Context, endpoint string) (*Profile, error) {
	cfMu.Lock()
	if cfCached != nil && time.Since(cfCachedAt) < cfProfileTTL {
		p := cfCached
		cfMu.Unlock()
		return p, nil
	}
	cfMu.Unlock()

	rec, err := Fetch(ctx, endpoint, CloudflareHost)
	if err != nil {
		return nil, fmt.Errorf("ech: 取 Cloudflare 共享 ECH 配置失败: %w", err)
	}
	if len(rec.ECHConfig) == 0 {
		return nil, fmt.Errorf("ech: %s 未发布 ECH 配置", CloudflareHost)
	}
	ips := rec.IPv4
	if len(ips) == 0 {
		if a, aerr := ResolveA(ctx, endpoint, CloudflareHost); aerr == nil {
			ips = a
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("ech: 没有可用的 Cloudflare 边缘 IP")
	}
	p := &Profile{ECHConfig: rec.ECHConfig, IP: ips[0]}

	cfMu.Lock()
	cfCached, cfCachedAt = p, time.Now()
	cfMu.Unlock()
	return p, nil
}
