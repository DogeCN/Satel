// Command satel 是严格单文件的本地 DPI 绕过客户端。
//
// 不写任何配置文件：口令来自 flag/环境变量，策略库与记忆全部驻留内存，退出即消失。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"satel/internal/coord"
	"satel/internal/desync"
	"satel/internal/engine"
	"satel/internal/failkind"
	"satel/internal/mitm"
	"satel/internal/probe"
	"satel/internal/proxy"
	"satel/internal/proxyip"
	"satel/internal/resolver"
	"satel/internal/strategy"
)

const version = "0.1.0"

// reportInterval 是方法级结论的上报间隔，与策略库拉取间隔（--sync-interval）
// 解耦：拉取 15 分钟一次就够，而回报要跟上浏览产生的观测速度，否则协调端看到的
// 永远是半小时前的世界。
const reportInterval = 45 * time.Second

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		os.Exit(serve(os.Args[2:]))
	case "probe":
		os.Exit(probeCmd(os.Args[2:]))
	case "diag":
		os.Exit(diagCmd(os.Args[2:]))
	case "admin":
		os.Exit(adminCmd(os.Args[2:]))
	case "remove-ca":
		os.Exit(removeCACmd(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Printf("satel %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `satel `+version+` — 本地 DPI 绕过客户端（单文件）

用法:
  satel serve [flags]              起本地代理（SOCKS5 + HTTP CONNECT 同一端口）
  satel probe [flags] <host>       自检：逐条策略撞目标，看哪条通
  satel diag [flags] <host>        对照实验：判定这个域名的封锁判据
  satel admin evolve [flags]       手动触发一代演化（需要 --admin-key）
  satel remove-ca [flags]          清除信任区里的 Satel CA 与落盘私钥
  satel version                    打印版本

serve 常用 flag:
  --listen 127.0.0.1:18080         监听地址（:0 自动选端口）
  --worker wss://xxx               协调端；留空=离线，仅用内置策略
  --password <pw>                  口令（也可用环境变量 SATEL_PASSWORD / PASSWORD）
  --probe-wait 3s                  每个候选等首字节的窗口
  --sync-interval 15m              拉取策略库/回报效果的间隔
  --ech=true                       用 ECH 隐藏控制通道 SNI
  --ca-file <path>                 开发通道：CA 落盘复用（空=严格零落盘，每次启动弹确认框）

  --v                              详细日志

probe 常用 flag:
  --handshake                      做真实 TLS 握手（默认只发合成 ClientHello）
  --fetch                          握手后再真发 HTTP 请求（穿透 MITM 假象）
  --ip <addr> --sni <name>         固定拨号地址 / 覆盖 SNI（做对照实验）
  --socks5 / --http-proxy <addr>   经代理连接（对比第三方实现）

CA 生命周期：默认**严格零落盘**——启动装一张临时 CA，退出即删，不写任何文件；
代价是 Windows 每次启动弹一次根证书确认框。开发时反复重启受不了，用
--ca-file <path> 打开落盘复用通道（只写这一个文件，之后启动只查不装）。
satel remove-ca 随时把信任区清干净。
`)
}
func defaultFP() string { return fmt.Sprintf("%s-%s-1", runtime.GOOS, runtime.GOARCH) }

// envPassword 依次取 SATEL_PASSWORD、PASSWORD。
func envPassword() string {
	if v := os.Getenv("SATEL_PASSWORD"); v != "" {
		return v
	}
	return os.Getenv("PASSWORD")
}

func serve(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:18080", "本地监听地址")
	worker := fs.String("worker", os.Getenv("SATEL_WORKER"), "协调端 URL（留空=离线）")
	password := fs.String("password", envPassword(), "口令")
	fp := fs.String("fp", defaultFP(), "客户端指纹")
	probeWait := fs.Duration("probe-wait", 3*time.Second, "每个候选等首字节的窗口")
	captureWait := fs.Duration("capture-wait", 10*time.Second, "等客户端首段的上限")
	syncEvery := fs.Duration("sync-interval", 15*time.Minute, "同步间隔")
	echOn := fs.Bool("ech", true, "用 ECH 隐藏控制通道的 SNI")
	bootstrap := fs.String("bootstrap", "", "控制通道自举招法（canonical）；空=默认 tlsrf")
	doh := fs.String("doh", "", "DoH 端点（逗号分隔表示优先级；空=内置默认）")
	caFile := fs.String("ca-file", "", "开发通道：把 CA 落盘复用（Windows 装根证书会弹确认框）。空=严格零落盘")
	verbose := fs.Bool("v", false, "详细日志")
	_ = fs.Parse(args)

	logf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "%s "+format+"\n", append([]any{time.Now().Format("15:04:05")}, a...)...)
	}

	// TLS 终止层：本网络里唯一有效的两类技巧（ECH、域名前置）都必须自己发起 TLS。
	//
	// 默认**严格零落盘**：启动装一张临时 CA，退出即删，不写任何文件。代价是 Windows
	// 每次启动都会弹一次根证书确认框。开发时反复重启受不了，`--ca-file <path>` 打开
	// 落盘复用通道（只写这一个文件；之后启动只查不装，查不弹框）。
	var ca *mitm.CA
	ephemeral := func(c *mitm.CA) {
		ca = c
		logf("[mitm] 临时 CA 已装入信任区（退出时移除，不落盘）")
		defer func() {
			if rerr := c.Remove(); rerr != nil {
				logf("[mitm] CA 移除失败（satel remove-ca 可清理 %q）: %v", mitm.CAName, rerr)
			} else {
				logf("[mitm] 临时 CA 已移除")
			}
		}()
	}

	if *caFile == "" {
		if c, cerr := mitm.NewCA(); cerr != nil {
			logf("[mitm] 生成 CA 失败，MITM 路径不启用: %v", cerr)
		} else if ierr := c.Install(); ierr != nil {
			logf("[mitm] CA 装入信任区失败，MITM 路径不启用: %v", ierr)
		} else {
			ephemeral(c)
		}
	} else {
		c, _, cerr := mitm.LoadOrCreate(*caFile)
		switch {
		case cerr != nil:
			logf("[mitm] 载入/生成 CA 失败，MITM 路径不启用: %v", cerr)
		case c.Installed():
			ca = c
			logf("[mitm] 开发通道：复用 %s 的 CA（已在信任区，不重装、不删）", *caFile)
		default:
			if ierr := c.Install(); ierr != nil {
				logf("[mitm] CA 装入信任区失败，MITM 路径不启用: %v", ierr)
			} else {
				ca = c
				logf("[mitm] 开发通道：CA 已装入信任区并落盘 %s（satel remove-ca 可清理）", *caFile)
			}
		}
	}

	var client *coord.Client
	if *worker != "" {
		if *password == "" {
			fmt.Fprintln(os.Stderr, "错误: 指定 --worker 时必须提供口令（--password 或 SATEL_PASSWORD）")
			return 2
		}
		c, err := coord.New(*worker, *password, *fp, desync.SupportedOps())
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			return 2
		}
		client = c
	}

	if client != nil && *bootstrap != "" {
		s, perr := strategy.Parse(*bootstrap)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "错误: --bootstrap 非法: %v\n", perr)
			return 2
		}
		client.SetBootstrap(s)
	}

	// 解析器同时决定两件事：目标解析的降级链，以及取 ECH 配置用的主端点。
	dohRes := resolver.NewDoH(*doh)

	if client != nil && *echOn {
		ectx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		err := client.EnableECH(ectx, dohRes.Primary())
		cancel()
		if err != nil {
			logf("[ech] 未启用: %v（继续用自举分片）", err)
		} else {
			logf("[ech] 控制通道 SNI 已隐藏")
		}
	}

	eng := engine.New(client)
	srv := proxy.New(eng)
	srv.ProbeWait = *probeWait
	srv.CaptureWait = *captureWait
	srv.MITM = ca
	srv.DoH = dohRes.Primary()
	srv.Relay = proxyip.NewPool(relaysFromEnv(), srv.Resolver)
	if client != nil {
		srv.Tunnel = client.Tunnel
	}
	// 解析不再走协调端：/v1/dns 随传输层重写一起删掉了。实测 Cloudflare Gateway
	// 端点对被墙域名干净且稳定，且它自身不被 SNI 拦，不需要多绕一跳。
	srv.Resolver = dohRes
	if *verbose {
		srv.Log = logf
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 监听 %s 失败: %v\n", *listen, err)
		return 1
	}
	mode := "离线（内置策略库）"
	if client != nil {
		mode = "协调端 " + *worker
	}
	logf("satel %s 监听 %s | %s | 招法 %s", version, ln.Addr(), mode, strings.Join(desync.SupportedOps(), ","))
	logf("系统代理指向 %s 即可（SOCKS5 与 HTTP CONNECT 共用此端口）", ln.Addr())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if client != nil {
		go syncLoop(ctx, client, eng, *syncEvery, logf)
	}
	go sweepLoop(ctx, eng, 5*time.Minute)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	err = srv.Serve(ln)
	// 先把攒下的效果发完，再关控制连接——顺序反了会丢这批数据。
	flushReports(context.Background(), client, eng, logf)
	if client != nil {
		if cerr := client.Close(); cerr != nil {
			logf("关闭控制连接: %v", cerr)
		}
	}
	if err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
		logf("serve 结束: %v", err)
		return 1
	}
	logf("已退出")
	return 0
}

func syncLoop(ctx context.Context, c *coord.Client, eng *engine.Engine, every time.Duration, logf func(string, ...any)) {
	pull := func() {
		for _, proto := range []string{strategy.ProtoTLS, strategy.ProtoHTTP} {
			bctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			b, err := c.FetchBundle(bctx, proto, 8)
			cancel()
			if err != nil {
				logf("[sync] %s 策略库拉取失败: %v", proto, err)
				continue
			}
			specs := make([]*strategy.Spec, 0, len(b.Items))
			bad := 0
			for _, st := range b.Items {
				s, err := strategy.Parse(st.Spec)
				// 不信任下发的 id：本地重算并校验，不符即丢。
				if err != nil || s.ID() != st.ID {
					bad++
					continue
				}
				specs = append(specs, s)
			}
			eng.SetBundle(proto, specs)
			// hints 两个 proto 各带一份、内容相同（协调端不区分），装两次无害；
			// 但只在第一次装，免得刷掉另一份里更新的 expires。
			if len(b.Hints) > 0 {
				eng.SetHints(b.Hints)
				logf("[sync] 后缀经验 %d 条", len(b.Hints))
			}
			logf("[sync] %s 策略库 v%d: %d 条可用（丢弃 %d 条）", proto, b.Version, len(specs), bad)
		}
	}
	// 回报与拉取分开节流。**只按固定周期回报是不够的**：syncLoop 在监听前就跑完
	// 第一次 flush，那之后浏览器才开始产生方法级结论，于是这批结论要等满一个周期
	// （默认 15 分钟）才上报——实测真机上就是这样，队列里躺着 item 而 Worker 侧
	// outcome 表一条都没有。所以这里加一个短周期专门看队列。
	//
	// 先回报再拉取：回报的是旧策略池下攒下的观测，先落地再拉新池，观测与池版本
	// 的对应关系不会串。
	flushReports(ctx, c, eng, logf)
	pull()

	reportEvery := every
	if reportEvery > reportInterval {
		reportEvery = reportInterval
	}
	rt := time.NewTicker(reportEvery)
	defer rt.Stop()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rt.C:
			flushReports(ctx, c, eng, logf)
		case <-t.C:
			pull()
		}
	}
}

func flushReports(ctx context.Context, c *coord.Client, eng *engine.Engine, logf func(string, ...any)) {
	items := eng.Drain()
	if len(items) == 0 || c == nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	n, err := c.Report(rctx, items)
	if err != nil {
		logf("[sync] 回报失败（本批 %d 条丢弃）: %v", len(items), err)
		return
	}
	logf("[sync] 回报 %d/%d 条", n, len(items))
}

func sweepLoop(ctx context.Context, eng *engine.Engine, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			eng.Sweep()
		}
	}
}

func probeCmd(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	port := fs.Int("port", 443, "目标端口")
	timeout := fs.Duration("timeout", 4*time.Second, "每条策略的等待窗口")
	only := fs.String("strategy", "", "只测指定的一条 canonical 策略")
	doh := fs.String("doh", "", "DoH 端点（空=内置默认）")
	ip := fs.String("ip", "", "固定拨号地址（跳过解析，做对照实验用）")
	sni := fs.String("sni", "", "覆盖握手 SNI（做对照实验用）")
	handshake := fs.Bool("handshake", false, "做真实 TLS 握手（默认只发合成 ClientHello 看有无回包）")
	socks5 := fs.String("socks5", "", "经该 SOCKS5 代理连接目标（对比第三方实现用）")
	httpProxy := fs.String("http-proxy", "", "经该 HTTP CONNECT 代理连接目标（对比第三方实现用）")
	fetch := fs.Bool("fetch", false, "握手后再真发 HTTP 请求（穿透 MITM 假象的唯一判据）")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "用法: satel probe [flags] <host>")
		return 2
	}
	host := fs.Arg(0)

	var specs []*strategy.Spec
	if *only != "" {
		s, err := strategy.Parse(*only)
		if err != nil {
			fmt.Fprintf(os.Stderr, "策略非法: %v\n", err)
			return 2
		}
		specs = []*strategy.Spec{s}
	}

	dohRes := buildResolver(*doh)

	mode := "合成 ClientHello"
	if *handshake {
		mode = "真实 TLS 握手"
	}
	target := host
	if *ip != "" {
		target = fmt.Sprintf("%s @ %s", host, *ip)
	}
	if *sni != "" && *sni != host {
		target += fmt.Sprintf(" (SNI=%s)", *sni)
	}
	fmt.Printf("探测 %s:%d（%s，窗口 %s）\n", target, *port, mode, *timeout)
	results := probe.Run(context.Background(), host, *port, specs, probe.Options{
		Timeout:   *timeout,
		DoH:       dohRes,
		IP:        *ip,
		SNI:       *sni,
		Handshake: *handshake,
		Socks5:    *socks5,
		HTTPProxy: *httpProxy,
		Fetch:     *fetch,
	})
	wins := 0
	for _, r := range results {
		name := "明文直连"
		if r.Spec != nil {
			name = r.Spec.Canonical()
		}
		extra := ""
		if r.Unsup {
			extra += " [含不支持的招法]"
		}
		switch {
		case r.OK:
			wins++
			cert := ""
			if r.Status != "" {
				cert += fmt.Sprintf("  %s body=%dB %s", r.Status, r.BodyBytes, r.Headers)
			}
			if r.CertIssuer != "" {
				cert += fmt.Sprintf("  [证书: %s ← %s]", r.CertSubject, r.CertIssuer)
				if r.CertSelfSigned {
					cert += "  ⚠自签/MITM"
				}
			}
			fmt.Printf("  通  %6dms  %s%s%s\n", r.RTT.Milliseconds(), name, extra, cert)
		default:
			if r.Err != nil {
				extra += "  " + shortErr(r.Err)
			}
			fmt.Printf("  断          %s%s\n", name, extra)
		}
	}
	fmt.Printf("共 %d 条，%d 条通\n", len(results), wins)
	return 0
}

// buildResolver 造解析器。/v1/dns 已随传输层重写删除，目标解析不再绕协调端——
// 实测 Cloudflare Gateway 端点对被墙域名干净且稳定，且它自身不被 SNI 拦，
// 不值得为此多绕一跳控制连接。
func buildResolver(doh string) *resolver.DoH {
	return resolver.NewDoH(doh)
}

// diagCmd 跑对照实验，判定封锁的判据是 SNI 特征还是 IP/流。这是决定"本地绕过
// 有没有戏"的关键一问。
func diagCmd(args []string) int {
	fs := flag.NewFlagSet("diag", flag.ExitOnError)
	port := fs.Int("port", 443, "目标端口")
	timeout := fs.Duration("timeout", 4*time.Second, "每步的等待窗口")
	doh := fs.String("doh", "", "DoH 端点（空=内置默认）")
	worker := fs.String("worker", os.Getenv("SATEL_WORKER"), "共享 IP 对照里缺省用它作被墙 SNI")
	shared := fs.Bool("shared-ip", false, "只跑共享 IP 对照（同一 IP 换 SNI，无混淆变量）")
	goodSNI := fs.String("good-sni", "www.cloudflare.com", "共享 IP 对照里的正常 SNI")
	badSNI := fs.String("bad-sni", "", "共享 IP 对照里的被墙 SNI（缺省用协调端域名）")
	_ = fs.Parse(args)

	dohRes := buildResolver(*doh)
	opt := probe.Options{Timeout: *timeout, DoH: dohRes}

	if *shared || fs.NArg() < 1 {
		bad := *badSNI
		if bad == "" {
			bad = hostOf(*worker)
		}
		if bad == "" {
			fmt.Fprintln(os.Stderr, "用法: satel diag [flags] <host>   或  satel diag --shared-ip --bad-sni <域名>")
			return 2
		}
		fmt.Printf("共享 IP 对照（每步窗口 %s）\n\n", *timeout)
		steps := probe.SharedIPControl(context.Background(), *goodSNI, bad, *port, opt)
		printSteps(steps)
		fmt.Println()
		fmt.Println(sharedVerdict(steps))
		return 0
	}

	host := fs.Arg(0)
	fmt.Printf("对照实验 %s:%d（每步窗口 %s）\n\n", host, *port, *timeout)
	steps := probe.Control(context.Background(), host, *port, opt)
	printSteps(steps)
	fmt.Println()
	fmt.Println(verdict(steps))
	return 0
}

func printSteps(steps []probe.Step) {
	for _, s := range steps {
		note := s.Note
		if note == "" && s.Err != nil {
			note = shortErr(s.Err)
		}
		fmt.Printf("  %-10s %-48s %s\n", s.Kind.Label(), s.Name, note)
	}
}

// sharedVerdict 把共享 IP 对照翻成结论。
func sharedVerdict(steps []probe.Step) string {
	get := func(sub string) (probe.Step, bool) {
		for _, s := range steps {
			if strings.Contains(s.Name, sub) {
				return s, true
			}
		}
		return probe.Step{}, false
	}
	good, okG := get("正常 SNI")
	bad, okB := get("被墙 SNI")
	if !okG || !okB {
		return "结论: 对照未跑完。"
	}
	switch {
	case good.OK && !bad.OK:
		return "结论: **SNI 特征封锁**（无混淆变量）。同一个 IP 上，正常 SNI 握手成功、" +
			"被墙 SNI 失败——判据只能是 ClientHello 里的明文域名。\n" +
			"      → 本地绕过有戏：用 tlsrf 或 split+oob 试（实测这两条能破无状态封锁）。\n" +
			"        若它们也全败，说明是状态化重组，本地无解——交给隧道。"
	case good.OK && bad.OK:
		return "结论: 该被墙域名此刻在共享 IP 上能握手——它没被 SNI 拦（可能只被 DNS 污染拦）。"
	default:
		return "结论: 基准 SNI 都没通（" + good.Kind.Label() + "），对照无效——换一个共享 IP 再试。"
	}
}

func hostOf(u string) string {
	if u == "" {
		return ""
	}
	p, err := url.Parse(u)
	if err != nil || p.Hostname() == "" {
		return strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	}
	return p.Hostname()
}

// verdict 把对照实验结果翻成结论。
func verdict(steps []probe.Step) string {
	get := func(sub string) (probe.Step, bool) {
		for _, s := range steps {
			if strings.Contains(s.Name, sub) {
				return s, true
			}
		}
		return probe.Step{}, false
	}
	oneByte, ok1 := get("② 发 1 字节")
	target, ok2 := get("④ TLS 握手")
	benign, ok3 := get("⑤ TLS 握手")
	if !ok1 || !ok2 || !ok3 {
		return "结论: 实验未跑完（解析或连接在早期就失败）。"
	}
	switch {
	case benign.OK && target.OK:
		return "结论: 目标直接可用——此刻没有封锁在起作用。"
	case benign.OK && !target.OK:
		return "结论: **SNI 特征封锁**（同 IP 换 SNI 对照成立）。用 tlsrf / split+oob 试；" +
			"若也全败则为状态化重组，本地无解。"
	case oneByte.Kind == failkind.Reset:
		return "结论: **IP/流级封锁**。连 1 个字节都触发复位，与内容和 SNI 都无关——" +
			"本地绕过在原理上无解，只有隧道/代理能过。"
	default:
		return "结论: 目标 SNI 与无害 SNI 都不通，但 1 字节不触发复位——该 IP 可能不承载" +
			"这个域名（SNI 路由不匹配），有混淆变量。请用 --shared-ip 做无混淆对照。"
	}
}

// adminCmd 是运维入口：被墙网络里 curl 连不上（控制通道要 ECH），所以把触发演化
// 做进同一个二进制。
func adminCmd(args []string) int {
	if len(args) < 1 || args[0] != "evolve" {
		fmt.Fprintln(os.Stderr, "用法: satel admin evolve --worker <url> --password <pw> --admin-key <key>")
		return 2
	}
	fs := flag.NewFlagSet("admin evolve", flag.ExitOnError)
	worker := fs.String("worker", os.Getenv("SATEL_WORKER"), "协调端 URL")
	password := fs.String("password", envPassword(), "口令")
	adminKey := fs.String("admin-key", envAdminKey(), "管理员密钥")
	fp := fs.String("fp", defaultFP(), "客户端指纹")
	echOn := fs.Bool("ech", true, "用 ECH 隐藏控制通道的 SNI")
	bootstrap := fs.String("bootstrap", "", "控制通道自举招法（canonical）；空=默认 tlsrf")
	doh := fs.String("doh", "", "DoH 端点（空=内置默认）")
	_ = fs.Parse(args[1:])

	if *worker == "" || *password == "" || *adminKey == "" {
		fmt.Fprintln(os.Stderr, "错误: 需要 --worker、--password、--admin-key")
		return 2
	}
	c, err := coord.New(*worker, *password, *fp, desync.SupportedOps())
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		return 2
	}
	defer func() { _ = c.Close() }()
	if *bootstrap != "" {
		s, perr := strategy.Parse(*bootstrap)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "错误: --bootstrap 非法: %v\n", perr)
			return 2
		}
		c.SetBootstrap(s)
	}
	if *echOn {
		ectx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		if err := c.EnableECH(ectx, resolver.NewDoH(*doh).Primary()); err != nil {
			fmt.Fprintf(os.Stderr, "[ech] 未启用: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "[ech] 控制通道 SNI 已隐藏")
		}
		cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.Evolve(ctx, *adminKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		return 1
	}
	fmt.Printf("演化完成: %v\n", res)
	return 0
}

func envAdminKey() string {
	if v := os.Getenv("SATEL_ADMIN_KEY"); v != "" {
		return v
	}
	return os.Getenv("ADMIN_KEY")
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 60 {
		s = s[:60] + "…"
	}
	return "(" + s + ")"
}

// relaysFromEnv 返回本机中继候选：SATEL_PROXYIP 非空时用它（自建中继优先），
// 否则用内置的公共候选。候选用逗号分隔，形如 "host:443,1.2.3.4:8443"。
func relaysFromEnv() []string {
	if v := strings.TrimSpace(os.Getenv("SATEL_PROXYIP")); v != "" {
		var out []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return proxyip.DefaultRelays
}

// removeCACmd 清除本机上的 Satel CA：信任区里所有同名证书，以及落盘的私钥文件。
//
// 为什么单独一个子命令：开了 --ca-file 落盘通道后 CA 会留在信任区里，且进程被
// 强杀时 defer 跑不到。用户必须有一条不依赖"程序正常退出"的退路——被强杀、换
// 机器、或者只是不再信任它，都该能一键清干净。
func removeCACmd(args []string) int {
	fs := flag.NewFlagSet("remove-ca", flag.ExitOnError)
	caFile := fs.String("ca-file", "", "CA 文件路径（空=默认位置）")
	_ = fs.Parse(args)
	path := *caFile
	if path == "" {
		path = mitm.DefaultPath()
	}
	n, fileGone, err := mitm.RemoveAll(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		return 1
	}
	fmt.Printf("信任区移除 %d 张 %q 证书", n, mitm.CAName)
	if fileGone {
		fmt.Printf("；已删除 %s", path)
	} else {
		fmt.Printf("；%s 不存在，跳过", path)
	}
	fmt.Println()
	return 0
}
