// Package probe 是测量仪：对目标逐条策略试一次，报告哪条让连接真的活过来。
//
// 两种模式：
//   - 合成 ClientHello：只问"有没有字节回来"，快，但请求不是合法握手；
//   - 真实 TLS 握手：走完整 handshake，问"这个站现在能不能用"，是可信的判据。
//
// 并且可以固定拨号 IP 与覆盖 SNI，用来做对照实验（同一个 IP 换 SNI 打，判断
// 封锁是按 SNI 特征还是按 IP/流）。
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"satel/internal/desync"
	"satel/internal/failkind"
	"satel/internal/flight"
	"satel/internal/resolver"
	"satel/internal/strategy"
)

var errZeroWrite = errors.New("probe: 写入 0 字节")

// Options 控制测量方式。
type Options struct {
	Timeout time.Duration
	DoH     *resolver.DoH // nil = 系统解析

	// IP 非空时固定拨这个地址（跳过解析），用于对照实验。
	IP string
	// SNI 非空时覆盖握手用的服务器名。
	SNI string
	// Handshake 为真时做真实 TLS 握手，否则只发合成 ClientHello 看有无回包。
	Handshake bool
	// Socks5 非空时经该 SOCKS5 代理连接目标（"host:port"），用于对比第三方
	// 实现：此时基线（spec=nil）测的就是那个实现自己的效果。
	Socks5 string
	// Fetch 为真时，握手成功后还要真发一个 HTTP 请求并读响应状态行与正文开头。
	// 这是唯一能穿透 MITM 假象的判据。
	Fetch bool
	// HTTPProxy 非空时经该 HTTP CONNECT 代理连接目标。与 Socks5 不同，这里把
	// **主机名**原样交给代理（由它自己解析），因为多数实现内置 DoH——这才是
	// 用户真实的使用姿势。
	HTTPProxy string
}

// dialTarget 按 Options 决定怎么连：经代理，还是直接拨。
func dialTarget(ctx context.Context, host string, port int, opt Options) (net.Conn, error) {
	dialHost := host
	if opt.IP != "" {
		dialHost = opt.IP
	}
	switch {
	case opt.HTTPProxy != "":
		return dialHTTPProxy(ctx, opt.HTTPProxy, dialHost, port, opt.Timeout)
	case opt.Socks5 != "":
		// 经 SOCKS5：先把目标解析成 IP（代理不做 DoH，让它自己解析会被污染）。
		ip := dialHost
		if net.ParseIP(ip) == nil {
			r, err := resolveOne(ctx, opt.DoH, ip)
			if err != nil {
				return nil, err
			}
			ip = r
		}
		return dialSocks5(ctx, opt.Socks5, ip, port, opt.Timeout)
	default:
		return resolver.Dial(ctx, opt.DoH, dialHost, port, opt.Timeout)
	}
}

// dialHTTPProxy 走一遍 HTTP CONNECT 握手。
func dialHTTPProxy(ctx context.Context, proxy, target string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	hostport := net.JoinHostPort(target, strconv.Itoa(port))
	req := "CONNECT " + hostport + " HTTP/1.1\r\nHost: " + hostport +
		"\r\nProxy-Connection: keep-alive\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		c.Close()
		return nil, err
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			c.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if !strings.Contains(status, " 200") {
		c.Close()
		return nil, fmt.Errorf("probe: HTTP 代理拒绝: %s", strings.TrimSpace(status))
	}
	// CONNECT 应答可能把后续字节一起读进了 bufio，必须继续从它读。
	return &readerConn{Conn: c, r: br}, nil
}

// readerConn 让调用方继续从 bufio.Reader 读，避免丢掉已缓冲的字节。
type readerConn struct {
	net.Conn
	r *bufio.Reader
}

func (rc *readerConn) Read(p []byte) (int, error) { return rc.r.Read(p) }

// dialSocks5 走一遍 SOCKS5 握手，用 IPv4 字面量作为目标（不依赖代理侧解析）。
func dialSocks5(ctx context.Context, proxy, ip string, port int, timeout time.Duration) (net.Conn, error) {
	ip4 := net.ParseIP(ip).To4()
	if ip4 == nil {
		return nil, errors.New("probe: SOCKS5 目标只支持 IPv4")
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (net.Conn, error) { c.Close(); return nil, e }

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		return fail(err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		return fail(errors.New("probe: SOCKS5 认证协商失败"))
	}
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip4...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	rep := make([]byte, 4)
	if _, err := io.ReadFull(c, rep); err != nil {
		return fail(err)
	}
	if rep[1] != 0x00 {
		return fail(fmt.Errorf("probe: SOCKS5 CONNECT 被拒 (0x%02x)", rep[1]))
	}
	switch rep[3] {
	case 0x01:
		_, err = io.ReadFull(c, make([]byte, 6))
	case 0x04:
		_, err = io.ReadFull(c, make([]byte, 18))
	case 0x03:
		l := make([]byte, 1)
		if _, err = io.ReadFull(c, l); err == nil {
			_, err = io.ReadFull(c, make([]byte, int(l[0])+2))
		}
	}
	if err != nil {
		return fail(err)
	}
	return c, nil
}

// Result 是一条策略（或明文基线）的结果。Spec 为 nil 表示不做任何改写。
type Result struct {
	Spec  *strategy.Spec
	OK    bool
	RTT   time.Duration
	Unsup bool
	Err   error

	// 证书信息：用来识别 MITM。若代理自己终止了 TLS，握手照样"成功"，但证书
	// 是它本地签的——不记这个就会把 MITM 的假象当成"绕过成功"。
	CertSubject    string
	CertIssuer     string
	CertSelfSigned bool

	// Fetch 模式下的响应信息。
	Headers   string // 关键响应头（Date / Server / Via / CF-RAY / X-Cache / Age）
	Status    string // HTTP 状态行
	BodyBytes int    // 读到的正文长度
	BodyHead  string // 正文开头若干字节（判真假页面用）
}

// fetchOnce 在已握手的 TLS 连接上发一个带随机 query 的 GET（防缓存），读状态行、
// 关键响应头与正文开头。目标不可达时（含经 MITM 代理的情况）拿不到真实响应。
func fetchOnce(tc *tls.Conn, host string, timeout time.Duration, r *Result) error {
	// 随机 query：真实服务器会回一份新内容，本地伪造/缓存则往往原样吐同一份。
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	req := "GET /?satel=" + nonce + " HTTP/1.1\r\nHost: " + host +
		"\r\nUser-Agent: Mozilla/5.0 (satel-probe)\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if _, err := tc.Write([]byte(req)); err != nil {
		return err
	}
	br := bufio.NewReader(tc)
	status, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	r.Status = strings.TrimSpace(status)

	// 头：挑几个能揭示路径的字段
	var hdrs []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		l := strings.TrimSpace(line)
		for _, k := range []string{"Date:", "Server:", "Via:", "CF-RAY:", "X-Cache:", "Age:", "Content-Length:"} {
			if strings.HasPrefix(l, k) {
				hdrs = append(hdrs, l)
			}
		}
	}
	r.Headers = strings.Join(hdrs, " | ")

	body, _ := io.ReadAll(io.LimitReader(br, 400))
	r.BodyBytes = len(body)
	head := strings.Join(strings.Fields(string(body)), " ")
	if len(head) > 120 {
		head = head[:120]
	}
	r.BodyHead = head

	if strings.Contains(status, " 5") {
		return fmt.Errorf("probe: 上游不可达: %s", strings.TrimSpace(status))
	}
	if len(body) == 0 {
		return errors.New("probe: 无响应正文")
	}
	return nil
}

// Run 依次尝试明文基线与每条策略。specs 为空时用内置 TLS 库。
func Run(ctx context.Context, host string, port int, specs []*strategy.Spec, opt Options) []Result {
	if len(specs) == 0 {
		specs = strategy.BuiltinFor(strategy.ProtoTLS)
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	sni := host
	if opt.SNI != "" {
		sni = opt.SNI
	}
	hello := flight.SyntheticClientHello(sni)

	out := make([]Result, 0, len(specs)+1)
	try := func(spec *strategy.Spec) Result {
		r := Result{Spec: spec}
		start := time.Now()
		up, err := dialTarget(ctx, host, port, opt)
		if err != nil {
			r.Err = err
			return r
		}
		defer up.Close()

		if opt.Handshake {
			if spec != nil {
				up = desync.WrapConn(up, spec, strategy.ProtoTLS, desync.Options{})
			}
			tc := tls.Client(up, &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: true, // 只判"握手是否完成"，不校验证书
				MinVersion:         tls.VersionTLS12,
			})
			_ = tc.SetDeadline(time.Now().Add(opt.Timeout))
			herr := tc.Handshake()
			r.RTT = time.Since(start)
			if herr == nil {
				r.OK = true
				// 记证书，用来识别 MITM：本地 CA 签的证书说明代理自己终止了 TLS，
				// 那样的"成功"不代表目标可达。
				if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
					leaf := cs.PeerCertificates[0]
					r.CertSubject = leaf.Subject.CommonName
					r.CertIssuer = leaf.Issuer.CommonName
					r.CertSelfSigned = leaf.Issuer.String() == leaf.Subject.String()
				}
				if opt.Fetch {
					// 真发一个请求并读状态行：MITM 能让握手"成功"，但目标不可达时
					// 拿不到真实页面。这是唯一能穿透 MITM 假象的判据。
					if ferr := fetchOnce(tc, sni, opt.Timeout, &r); ferr != nil {
						r.OK = false
						r.Err = ferr
					}
				}
			} else {
				r.Err = herr
			}
			return r
		}

		if spec == nil {
			if werr := writeAll(up, hello); werr != nil {
				r.Err = werr
				return r
			}
		} else {
			ar, aerr := desync.Apply(up, spec, hello, nil, desync.Options{})
			r.Unsup = len(ar.Unsupported) > 0
			if aerr != nil {
				r.Err = aerr
				return r
			}
		}
		_ = up.SetReadDeadline(time.Now().Add(opt.Timeout))
		n, rerr := up.Read(make([]byte, 4096))
		r.RTT = time.Since(start)
		if n > 0 {
			r.OK = true
		} else if rerr != nil {
			r.Err = rerr
		}
		return r
	}

	select {
	case <-ctx.Done():
		return out
	default:
	}
	out = append(out, try(nil))
	for _, spec := range specs {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		out = append(out, try(spec))
	}
	return out
}

// DialRaw 只做一次 TCP 连接，用于区分"连不上"与"连上了但数据被丢"。
func DialRaw(ctx context.Context, host string, port int, opt Options) (net.Conn, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	return dialTarget(ctx, host, port, opt)
}

// SendProbe 在已建立的连接上发一段原始负载并等回包，用来判断"这个 IP 收不收
// 任意数据"。payload 为空则只等待（测连接建立后是否被立刻复位）。
func SendProbe(conn net.Conn, payload []byte, timeout time.Duration) (int, error) {
	if len(payload) > 0 {
		if err := writeAll(conn, payload); err != nil {
			return 0, err
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(make([]byte, 4096))
	if n > 0 {
		return n, nil
	}
	return 0, err
}

// 失败分类统一走 failkind：它把"超时"与"复位"分开（超时可能只是服务端在等
// ClientHello，复位才是主动阻断的证据），而且是**机器可读**的枚举。展示串由
// Kind.Label() 提供，不参与判等。
//
// 本包用 Kind 同时表达两类信息，边界是：err != nil 时是失败类别；err == nil
// 且 Step.OK 为真时是 None（成功）。其余一律 failkind.Other。

// kindOf 把一个错误归类；err 为 nil 时返回 Other（不是"成功"，别混淆）。
func kindOf(err error) failkind.Kind {
	if err == nil {
		return failkind.Other
	}
	return failkind.Classify(err)
}

// Step 是对照实验的一步。Kind 是失败类别（failkind），成功与否看 OK。
type Step struct {
	Name string
	Kind failkind.Kind
	OK   bool
	Note string
	Err  error
}

// benignSNI 是"几乎不可能被拦"的域名。
const benignSNI = "www.bing.com"

// Control 跑一组对照实验，判定封锁判据：
//
//	⓪ 仪器自检：对一个已知可用的站做真实 TLS 握手，必须成功
//	① TCP 连接后静置   → 超时=正常；复位=连接建立即被拦
//	② 发 1 字节        → 复位=按流拦，与内容无关
//	③ 发明文 HTTP      → 复位=与 TLS 无关
//	④ 目标 SNI + 目标 IP 的真实 TLS 握手
//	⑤ 无害 SNI + 目标 IP 的真实 TLS 握手（同 IP 换 SNI）
func Control(ctx context.Context, host string, port int, opt Options) []Step {
	if opt.Timeout <= 0 {
		opt.Timeout = 4 * time.Second
	}
	var steps []Step
	add := func(name string, kind failkind.Kind, ok bool, note string, err error) {
		steps = append(steps, Step{Name: name, Kind: kind, OK: ok, Note: note, Err: err})
	}

	ip, ierr := resolveOne(ctx, opt.DoH, host)
	if ierr != nil {
		add("解析 "+host, failkind.Other, false, "", ierr)
		return steps
	}
	add("解析 "+host, failkind.None, true, "→ "+ip, nil)

	// ⓪ 仪器自检
	if self, ok := sanityCheck(ctx, port, opt); !ok {
		steps = append(steps, self)
		return steps
	} else {
		steps = append(steps, self)
	}

	dialOpt := opt
	dialOpt.IP = ip

	// ① 只连接、不发数据
	if c, err := DialRaw(ctx, host, port, dialOpt); err != nil {
		add("① TCP 连接后静置", failkind.Classify(err), false, "", err)
	} else {
		_, rerr := SendProbe(c, nil, 3*time.Second)
		c.Close()
		add("① TCP 连接后静置", failkind.Classify(rerr), false, noteFor(rerr, "3s 内无复位"), rerr)
	}

	// ② 1 字节
	if c, err := DialRaw(ctx, host, port, dialOpt); err != nil {
		add("② 发 1 字节", failkind.Classify(err), false, "", err)
	} else {
		_, rerr := SendProbe(c, []byte{0x00}, 3*time.Second)
		c.Close()
		add("② 发 1 字节", failkind.Classify(rerr), false, noteFor(rerr, "3s 内无复位"), rerr)
	}

	// ③ 明文 HTTP
	if c, err := DialRaw(ctx, host, port, dialOpt); err != nil {
		add("③ 发明文 HTTP", failkind.Classify(err), false, "", err)
	} else {
		req := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
		_, rerr := SendProbe(c, req, 3*time.Second)
		c.Close()
		add("③ 发明文 HTTP", failkind.Classify(rerr), false, noteFor(rerr, "3s 内无复位"), rerr)
	}

	// ④⑤ 同 IP 换 SNI
	for _, tc := range []struct {
		name string
		sni  string
	}{
		{"④ TLS 握手 @ 目标 IP，SNI=" + host, host},
		{"⑤ TLS 握手 @ 目标 IP，SNI=" + benignSNI, benignSNI},
	} {
		o := opt
		o.IP, o.SNI, o.Handshake = ip, tc.sni, true
		res := Run(ctx, host, port, []*strategy.Spec{}, o)
		if len(res) > 0 && res[0].OK {
			add(tc.name, failkind.None, true, fmtDur(res[0].RTT), nil)
		} else {
			var e error
			if len(res) > 0 {
				e = res[0].Err
			}
			add(tc.name, kindOf(e), false, "", e)
		}
	}
	return steps
}

// SharedIPControl 是唯一没有混淆变量的对照：在同一个 IP 上只换 SNI。
// Cloudflare 边缘同时承载被墙域名与正常域名，因此这个 IP 一定"能通"——如果
// 正常 SNI 通、被墙 SNI 断，那判据只可能是 ClientHello 里的明文域名。
func SharedIPControl(ctx context.Context, goodSNI, badSNI string, port int, opt Options) []Step {
	if opt.Timeout <= 0 {
		opt.Timeout = 4 * time.Second
	}
	var steps []Step
	ip, err := resolveOne(ctx, opt.DoH, goodSNI)
	if err != nil {
		return append(steps, Step{Name: "解析 " + goodSNI, Kind: failkind.Other, Err: err})
	}
	steps = append(steps, Step{Name: "共享 IP " + ip, Kind: failkind.None, OK: true, Note: "对照基准"})
	for _, tc := range []struct {
		name string
		sni  string
	}{
		{"正常 SNI " + goodSNI, goodSNI},
		{"被墙 SNI " + badSNI, badSNI},
	} {
		o := opt
		o.IP, o.SNI, o.Handshake = ip, tc.sni, true
		res := Run(ctx, goodSNI, port, []*strategy.Spec{}, o)
		if len(res) > 0 && res[0].OK {
			steps = append(steps, Step{Name: tc.name, Kind: failkind.None, Note: fmtDur(res[0].RTT)})
		} else {
			var e error
			if len(res) > 0 {
				e = res[0].Err
			}
			steps = append(steps, Step{Name: tc.name, Kind: kindOf(e), Err: e})
		}
	}
	return steps
}

// sanityCheck 用 www.baidu.com 做仪器自检：它必须能握手成功，否则是环境或
// 测量工具本身有问题，后面的结论都不可信。
func sanityCheck(ctx context.Context, port int, opt Options) (Step, bool) {
	const host = "www.baidu.com"
	ip, err := resolveOne(ctx, opt.DoH, host)
	if err != nil {
		return Step{Name: "⓪ 仪器自检 " + host, Kind: failkind.Other, Err: err}, false
	}
	o := opt
	o.IP, o.SNI, o.Handshake = ip, host, true
	res := Run(ctx, host, port, []*strategy.Spec{}, o)
	if len(res) > 0 && res[0].OK {
		return Step{Name: "⓪ 仪器自检 " + host, Kind: failkind.None, Note: fmtDur(res[0].RTT)}, true
	}
	var e error
	if len(res) > 0 {
		e = res[0].Err
	}
	return Step{Name: "⓪ 仪器自检 " + host, Kind: kindOf(e), Note: "测量环境不可信", Err: e}, false
}

func noteFor(err error, okNote string) string {
	if err == nil {
		return okNote
	}
	return ""
}

func fmtDur(d time.Duration) string { return d.Round(time.Millisecond).String() }

func resolveOne(ctx context.Context, r *resolver.DoH, host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}
	if r != nil {
		if ips, err := r.LookupHost(ctx, host); err == nil && len(ips) > 0 {
			return ips[0], nil
		}
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = errors.New("probe: 解析无结果")
		}
		return "", err
	}
	return ips[0], nil
}

func writeAll(c net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return errZeroWrite
		}
		b = b[n:]
	}
	return nil
}

// PortOf 从字符串取端口，非法时返回 def。
func PortOf(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 65535 {
		return def
	}
	return n
}
