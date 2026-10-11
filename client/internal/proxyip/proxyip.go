// Package proxyip 是本机侧的中继池：直连一个第三方中继，让它把连接转发到目标。
//
// 用于 **Cloudflare 承载且锁国区**的站：Workers 的 connect() 拨不了 CF 自己的网段，
// 而本机经中继能拿到一个非国内的出口——目标看到的是中继的 IP，地区封锁就不成立。
// 这也是为什么它必须放在本机而不是 Worker 里：放进 Worker 会多烧一跳子请求配额，
// 而且绕不开"CF 连不了 CF"这条平台限制。
//
// 这一型中继是 **SNI 路由**：它不是 HTTP CONNECT 代理（实测对 CONNECT 回 400），
// 而是读客户端 ClientHello 里的 SNI 并据此转发。所以用法是把**目标域名**当作 SNI
// 直接跟中继握手。
//
// 池的顺序是**全局共享**的：成功置顶、失败置底、连续失败进冷却。这个顺序对所有
// 目标主机生效——对 host A 的观测同样改进 host B 的首选。
package proxyip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"satel/internal/resolver"
)

// DefaultRelays 是默认中继候选（CMLiussss 域名型），取自 NetMaster 已验证的那份表。
//
// 可用性警告：公共中继被拉黑是常态。2026-10-11 实测 9 条里只有 1 条能给出
// Cloudflare 真证书，其余或被复位、或超时、或域名已失效。它们不是稳定依赖——
// 所以 Pool 会在内存里维护可用性顺序（成功置顶、失败置底并冷却），而不是每
// 次都从静态顺序从头试一遍。真正可靠的是自建中继，可用 SATEL_PROXYIP 指定。
var DefaultRelays = []string{
	"ProxyIP.KR.CMLiussss.net",
	"ProxyIP.JP.CMLiussss.net",
	"ProxyIP.HK.CMLiussss.net",
	"ProxyIP.Vultr.CMLiussss.net",
	"ProxyIP.Aliyun.CMLiussss.net",
	"ProxyIP.Oracle.CMLiussss.net",
	"ProxyIP.DigitalOcean.CMLiussss.net",
	"ProxyIP.Multacom.CMLiussss.net",
	"ProxyIP.DE.tp2024.CMLiussss.net",
}

// 竞速与记账参数。
const (
	// cooldown 是连续失败后的暂缓时长。公共中继常常是暂时性抽风，
	// 冷却比立刻再试更划算。
	cooldown = 2 * time.Minute
	// maxFails 是连续失败到这个次数后强制冷却（冷却期间不参与调度）。
	maxFails = 3
	// raceStagger 是竞速起跑的错开间隔：每条比前一条晚这么久起跑。
	// 250ms 是经典 Happy Eyeballs 的量级——让首选先抢跑，又不让胜者等太久。
	raceStagger = 250 * time.Millisecond
	// maxRaceBatch 是单次请求最多参竞的中继数。
	maxRaceBatch = 3
	// maxRaceInflight 是单次请求同时在途的拨号数。
	maxRaceInflight = 2
	// maxDialBudget 是单次请求的拨号总预算上限（另受调用方 timeout 与 ctx 约束）。
	maxDialBudget = 6 * time.Second
)

// maxGlobalDial 是进程级同时在途的中继拨号数上限。
// 多个请求同时竞速时，避免所有中继被一起拉起把出口打满。
const maxGlobalDial = 4

// globalDialSlots 是**进程级**（而非 per-Pool）的在途拨号信号量：
// 无论有多少个 Pool / 多少路请求，同时进行的中继拨号不超过 maxGlobalDial。
var globalDialSlots = make(chan struct{}, maxGlobalDial)

// 竞速相关错误。它们不指向某条中继"坏了"，记账时必须区别于真实失败。
var (
	errBudget    = errors.New("proxyip: 拨号预算已用尽")
	errAllFailed = errors.New("候选中继全部失败")
)

// entry 是一条中继的内存状态。
type entry struct {
	addr  string
	fails int
	until time.Time // 冷却截止；零值表示未冷却
	ok    int
}

// Pool 是一个内存里的中继池：按可用性自排序，受限竞速。
// 全部在内存中，进程退出即消失——不落盘，符合"零配置"。
// 并发安全。
type Pool struct {
	mu       sync.Mutex
	entries  []*entry
	resolver *resolver.DoH
	now      func() time.Time

	// dial 注入拨号实现（测试用）。nil = 走真实中继握手。
	dial func(ctx context.Context, relay, host string, port int, timeout time.Duration) (net.Conn, error)
	// trust 注入证书信任根（测试用）。nil = 系统根。
	// 证书**始终校验**：这个握手就是到目标的端到端 TLS。
	trust *x509.CertPool
}

// NewPool 用候选地址构造中继池。resolver 可为 nil（退回系统解析）。
func NewPool(relays []string, r *resolver.DoH) *Pool {
	p := &Pool{resolver: r, now: time.Now}
	for _, a := range relays {
		if a = strings.TrimSpace(a); a != "" {
			p.entries = append(p.entries, &entry{addr: a})
		}
	}
	return p
}

// SetNow 注入时钟（测试用）。
func (p *Pool) SetNow(f func() time.Time) {
	p.mu.Lock()
	p.now = f
	p.mu.Unlock()
}

// SetDial 注入拨号实现（测试用）：绕开真实网络与真实中继证书。
// 必须在并发拨号之前设置。
func (p *Pool) SetDial(f func(ctx context.Context, relay, host string, port int, timeout time.Duration) (net.Conn, error)) {
	p.mu.Lock()
	p.dial = f
	p.mu.Unlock()
}

// SetTrust 注入证书信任根（测试用）。证书始终校验，注入只是换一份根。
// 必须在并发拨号之前设置。
func (p *Pool) SetTrust(pool *x509.CertPool) {
	p.mu.Lock()
	p.trust = pool
	p.mu.Unlock()
}

// Dial 返回一条通往目标的中继连接。
//
// 每次请求都是一次**受限竞速**：队首（历史最可用）立即起跑，其余最多
// maxRaceBatch-1 条候选按 250ms 错开跟进，同时最多 maxRaceInflight 条在途；
// 任一候选失败会立刻唤醒下一条（快速失败加速）。第一个握手成功者胜出，其余取消。
// 没有"只打队首"的快路径—— proven 的队首同样只领先 250ms，挂起时不会让整路
// 请求干等一个超时。
//
// 总预算 = min(调用方 timeout, maxDialBudget)，并受调用方 ctx 截止约束。
// 落败者被取消时**不记失败**（它只是没跑赢），只有真正拨不通的才记。
func (p *Pool) Dial(ctx context.Context, host string, port int, timeout time.Duration) (net.Conn, error) {
	ready := p.ready()
	if len(ready) == 0 {
		return nil, fmt.Errorf("proxyip: 没有可用的候选中继（共 %d 条，均在冷却中）", p.size())
	}

	budget := maxDialBudget
	if timeout > 0 && timeout < budget {
		budget = timeout
	}
	deadline := time.Now().Add(budget)
	rctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	batch := ready
	if len(batch) > maxRaceBatch {
		batch = batch[:maxRaceBatch]
	}
	conn, addr, reasons, err := p.race(rctx, batch, host, port, deadline)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return nil, fmt.Errorf("proxyip: 已取消: %w", err)
		case errors.Is(err, errAllFailed):
			return nil, fmt.Errorf("proxyip: %d 条候选全部失败: %s", len(reasons), strings.Join(reasons, " | "))
		default:
			return nil, fmt.Errorf("proxyip: 竞速未完成: %w", err)
		}
	}
	if conn == nil {
		return nil, fmt.Errorf("proxyip: %d 条候选全部失败: %s", len(reasons), strings.Join(reasons, " | "))
	}
	p.noteOK(addr)
	return conn, nil
}

// Order 返回当前的尝试顺序（测试与诊断用）。
func (p *Pool) Order() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, e.addr)
	}
	return out
}

// Stats 返回每条中继的成功/失败计数（诊断用）。
func (p *Pool) Stats() map[string][2]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string][2]int, len(p.entries))
	for _, e := range p.entries {
		out[e.addr] = [2]int{e.ok, e.fails}
	}
	return out
}

func (p *Pool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// ready 返回当前可参竞的候选：未冷却的，按池内顺序（成功置顶、失败置底）。
// 冷却中的中继**不参与本次调度**——它刚被证实不可用，重复试只会重复付费。
func (p *Pool) ready() []*entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	out := make([]*entry, 0, len(p.entries))
	for _, e := range p.entries {
		if !e.until.IsZero() && now.Before(e.until) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// skip 判断一条中继是否仍在冷却。
func (p *Pool) skip(e *entry) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !e.until.IsZero() && p.now().Before(e.until)
}

// noteOK 把成功的中继置顶并清空惩罚。
func (p *Pool) noteOK(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, e := range p.entries {
		if e.addr != addr {
			continue
		}
		e.fails = 0
		e.until = time.Time{}
		e.ok++
		if i == 0 {
			return
		}
		copy(p.entries[1:], p.entries[:i])
		p.entries[0] = e
		return
	}
}

// noteFail 把失败的中继置底；连续失败到 maxFails 额外加一段冷却。
func (p *Pool) noteFail(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, e := range p.entries {
		if e.addr != addr {
			continue
		}
		e.fails++
		if e.fails >= maxFails {
			e.until = p.now().Add(cooldown)
		}
		if i == len(p.entries)-1 {
			return
		}
		copy(p.entries[i:], p.entries[i+1:])
		p.entries[len(p.entries)-1] = e
		return
	}
}

// starter 管单次请求的起跑门：保序 + 在途上限 + 硬性地板。
//
// 第 i 条起跑需同时满足：inflight 未满、轮到它（next==i）、且
//   - 它的地板（i×raceStagger）已到，**或**
//   - 它之前的候选都已结束（快速失败 → 立刻让位，不必干等地板）。
//
// 地板必须真实存在：否则一次 finish 的广播会把后面候选瞬间放行，250ms 错开
// 形同虚设，队首的"先跑"优势也随之消失。done() 在上报**之后**调用——胜者的
// outcome 先进队列，后继者才可能因"前驱已结束"被放行，胜负因此确定。
type starter struct {
	mu       sync.Mutex
	wake     chan struct{}
	finished []bool
	next     int // 下一个允许起跑的下标
	inflight int
	stopped  bool
}

func newStarter(n int) *starter {
	return &starter{finished: make([]bool, n)}
}

// wait 等到第 i 条可以起跑。返回 false 表示整批已结束（已有胜者或 ctx 取消）。
func (s *starter) wait(i int, floor time.Duration, done <-chan struct{}) bool {
	t := time.NewTimer(floor)
	defer t.Stop()
	floorOk := floor <= 0
	for {
		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			return false
		}
		predsDone := true
		for j := 0; j < i; j++ {
			if !s.finished[j] {
				predsDone = false
				break
			}
		}
		if s.next == i && s.inflight < maxRaceInflight && (floorOk || predsDone) {
			s.next++
			s.inflight++
			s.mu.Unlock()
			return true
		}
		if s.wake == nil {
			s.wake = make(chan struct{})
		}
		w := s.wake
		s.mu.Unlock()
		select {
		case <-w:
			// 状态变了：重判（地板未到且前驱未完仍不放行）。
		case <-t.C:
			floorOk = true
		case <-done:
			return false
		}
	}
}

// done 标记第 i 条已结束（上报完毕），释放在途名额并唤醒等待者。
func (s *starter) done(i int) {
	s.mu.Lock()
	s.finished[i] = true
	s.inflight--
	s.mu.Unlock()
	s.broadcast()
}

// stop 结束整批起跑。
func (s *starter) stop() {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	s.broadcast()
}

func (s *starter) broadcast() {
	s.mu.Lock()
	if s.wake != nil {
		close(s.wake)
		s.wake = nil
	}
	s.mu.Unlock()
}

// race 让一批候选错开起跑、抢第一个成功的握手。
// 每条候选恰好上报一个 outcome（起跑失败也上报），所以收尾时按差额 drain 即可。
func (p *Pool) race(rctx context.Context, batch []*entry, host string, port int, deadline time.Time) (net.Conn, string, []string, error) {
	type outcome struct {
		conn net.Conn
		addr string
		err  error
		late bool // 没起跑：竞速已结束或被取消
	}
	ch := make(chan outcome, len(batch))
	st := newStarter(len(batch))

	for i, e := range batch {
		go func(e *entry, i int) {
			if !st.wait(i, time.Duration(i)*raceStagger, rctx.Done()) {
				ch <- outcome{addr: e.addr, err: rctx.Err(), late: true}
				st.done(i)
				return
			}
			conn, err := p.attempt(rctx, e.addr, host, port, deadline)
			// 先上报再标记结束：胜者的 outcome 先进队列，后继者才可能因"前驱已结束"
			// 被放行——否则后面的候选可能抢在胜者之前起跑并赢下这一轮。
			ch <- outcome{conn: conn, addr: e.addr, err: err}
			st.done(i)
		}(e, i)
	}

	var reasons []string
	// drain 只收剩余上报、关掉迟到连接：ch 有 len(batch) 缓冲，所以必定收得完，
	// 不会悬挂 goroutine。
	drain := func(remaining int) {
		if remaining <= 0 {
			return
		}
		go func() {
			for j := 0; j < remaining; j++ {
				if r := <-ch; r.conn != nil {
					r.conn.Close()
				}
			}
		}()
	}

	consumed := 0 // 已取走上报的条数（无论成败）
	for consumed < len(batch) {
		select {
		case r := <-ch:
			consumed++
			if r.err == nil {
				st.stop()
				drain(len(batch) - consumed)
				return r.conn, r.addr, reasons, nil
			}
			switch {
			case r.late:
				// 没起跑，无所谓失败。
			case errors.Is(r.err, errBudget):
				reasons = append(reasons, r.addr+" "+errBudget.Error())
			case errors.Is(r.err, context.Canceled), errors.Is(r.err, context.DeadlineExceeded):
				// 我们主动取消 / 预算耗尽：不是中继的错。
				reasons = append(reasons, r.addr+" 未完成: "+r.err.Error())
			default:
				p.noteFail(r.addr)
				reasons = append(reasons, r.err.Error())
			}
		case <-rctx.Done():
			st.stop()
			drain(len(batch) - consumed)
			return nil, "", reasons, rctx.Err()
		}
	}
	return nil, "", reasons, errAllFailed
}

// attempt 单条候选的一次拨号，受全局并发上限与本次预算约束。
func (p *Pool) attempt(ctx context.Context, relay, host string, port int, deadline time.Time) (net.Conn, error) {
	select {
	case globalDialSlots <- struct{}{}:
		defer func() { <-globalDialSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	left := time.Until(deadline)
	if left <= 0 {
		return nil, errBudget
	}
	// dial/trust 由 SetDial/SetTrust 在并发拨号前设定，读取仍需持锁。
	p.mu.Lock()
	dial, trust := p.dial, p.trust
	p.mu.Unlock()
	if dial != nil {
		return dial(ctx, relay, host, port, left)
	}
	return dialOne(ctx, p.resolver, relay, host, port, left, trust)
}

// dialOne 与单条中继握手：SNI 填**目标域名**，让它按 SNI 转发。
//
// 信任模型（别再改回 InsecureSkipVerify）：这一层 TLS **就是到目标的端到端 TLS**。
// 中继只负责把 ClientHello 转给目标、把目标回传的证书链送回来；握手**之后**的连接
// 是通往目标的明文管道。调用方 mitm.Terminate 得到的是已解密的连接，会把解密的
// HTTP 直接灌进这条连接（proxy.tryTerminating → relayBoth），其上不会再有 TLS。
// 所以这里必须按 host 校验证书——不校验等于把目标握手的信任全部交给中继与链路。
//
// 也不发 CONNECT：这一型中继根本不认 HTTP CONNECT（实测回 400）。
func dialOne(ctx context.Context, r *resolver.DoH, relay, host string, port int, timeout time.Duration, trust *x509.CertPool) (net.Conn, error) {
	relayHost, relayPort, err := splitRelay(relay)
	if err != nil {
		return nil, err
	}
	raw, err := resolver.Dial(ctx, r, relayHost, relayPort, timeout)
	if err != nil {
		return nil, fmt.Errorf("proxyip: 连中继 %s 失败: %w", relay, err)
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))

	tlsConf := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		RootCAs:    trust, // nil = 系统根
	}
	tlsConn := tls.Client(raw, tlsConf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("proxyip: 经 %s 握手失败: %w", relay, err)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	// 握手之后这条连接就是通往目标的一条管道，直接返回。
	return tlsConn, nil
}

func splitRelay(relay string) (string, int, error) {
	relay = strings.TrimSpace(relay)
	if relay == "" {
		return "", 0, fmt.Errorf("proxyip: 空中继地址")
	}
	host, portStr, err := net.SplitHostPort(relay)
	if err != nil {
		// 没写端口，默认 443
		return relay, 443, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("proxyip: 端口非法: %s", relay)
	}
	return host, port, nil
}
