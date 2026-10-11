package proxyip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 这一文件钉住**受限竞速**的行为契约。全部走注入拨号（harness_test.go），
// 不碰真实网络：每条候选的表现是写死的，时序只由 250ms 错开与在途上限决定。

// TestDialTriesAtMostMaxRaceBatch 单次请求最多参竞 maxRaceBatch 条：
// 不该把整张候选表一次烧完（实测 9 条串行 = 34 秒）。
//
// 注意"最多"而非"恰好"：全部挂起时在途槽位被占满（maxRaceInflight=2），
// 后续候选起不了——这正是 TestDialMaxInflight 钉住的契约，两条测试必须自洽。
func TestDialTriesAtMostMaxRaceBatch(t *testing.T) {
	h := newHarness(t)
	var relays []string
	for i := 0; i < 8; i++ {
		relays = append(relays, h.hang(fmt.Sprintf("hang%d", i)))
	}
	p := h.pool(relays)

	const timeout = 900 * time.Millisecond
	start := time.Now()
	if _, err := p.Dial(context.Background(), "example.com", 443, timeout); err == nil {
		t.Fatal("全部挂起，应失败")
	}
	el := time.Since(start)
	// 上限：最后一条起跑 (maxRaceBatch-1)×250ms 之后 + 一个超时。
	want := time.Duration(maxRaceBatch-1)*raceStagger + timeout
	if el > want+400*time.Millisecond {
		t.Fatalf("耗时 %v，超过 maxRaceBatch=%d 的错开上限 %v", el, maxRaceBatch, want)
	}
	if n := len(h.dialed()); n == 0 || n > maxRaceBatch {
		t.Fatalf("参竞 %d 条，应在 1..%d 之间: %v", n, maxRaceBatch, h.dialed())
	}
	// 超出批次的候选绝不能被拨到——这就是"有界"。
	for i := maxRaceBatch; i < 8; i++ {
		if c := h.started(fmt.Sprintf("hang%d", i)); c != 0 {
			t.Fatalf("hang%d 超出批次上限却被拨了 %d 次", i, c)
		}
	}
}

// TestDialBudgetBoundedByCallerAndCap 总预算 = min(调用方 timeout, maxDialBudget)，
// 再受调用方 ctx 截止约束。调用方给 60s 时也必须封顶在 maxDialBudget。
func TestDialBudgetBoundedByCallerAndCap(t *testing.T) {
	h := newHarness(t)
	hang := h.hang("hang")
	p := h.pool([]string{hang})

	start := time.Now()
	if _, err := p.Dial(context.Background(), "example.com", 443, 60*time.Second); err == nil {
		t.Fatal("挂起，应失败")
	}
	el := time.Since(start)
	if el > maxDialBudget+2*time.Second {
		t.Fatalf("预算应封顶在 %v，实际 %v", maxDialBudget, el)
	}
	if el < maxDialBudget {
		t.Fatalf("预算没用满就返回了：%v", el)
	}
}

// TestDialBudgetHonoursCallerDeadline 调用方 ctx 的截止优先于一切：
// 比 maxDialBudget 早到期时必须在到期点返回。
func TestDialBudgetHonoursCallerDeadline(t *testing.T) {
	h := newHarness(t)
	p := h.pool([]string{h.hang("hang")})

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := p.Dial(ctx, "example.com", 443, 60*time.Second); err == nil {
		t.Fatal("应失败")
	}
	if el := time.Since(start); el > 1500*time.Millisecond {
		t.Fatalf("调用方 700ms 截止未被遵守: %v", el)
	}
}

// TestDialMaxInflight 同时最多 maxRaceInflight 条在途：第 1 条立即起跑，
// 第 2 条 250ms 后起跑（在途=2 已达上限），第 3 条必须等其中一条结束。
// 契约断言的是**峰值不超过上限**；"三条都拨到"不是契约（胜者即时返回时来不及）。
func TestDialMaxInflight(t *testing.T) {
	h := newHarness(t)
	var inflight, maxSeen int32
	var mu sync.Mutex

	mk := func(name string, d time.Duration) string {
		return h.relay(name, behavior{delay: d, conn: newFakeConn(), onDial: func(ctx context.Context) {
			n := atomic.AddInt32(&inflight, 1)
			mu.Lock()
			if n > maxSeen {
				maxSeen = n
			}
			mu.Unlock()
			time.Sleep(d)
			atomic.AddInt32(&inflight, -1)
		}})
	}
	relays := []string{mk("a", 400*time.Millisecond), mk("b", 400*time.Millisecond), mk("c", 400*time.Millisecond)}
	p := h.pool(relays)

	conn, err := p.Dial(context.Background(), "example.com", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("应有一条成功: %v", err)
	}
	conn.Close()

	mu.Lock()
	defer mu.Unlock()
	if maxSeen > maxRaceInflight {
		t.Fatalf("同时在途 %d 条，超过上限 %d", maxSeen, maxRaceInflight)
	}
	if maxSeen < 2 {
		t.Fatalf("在途峰值只有 %d——没有真正并发", maxSeen)
	}
}

// TestFastFailureAcceleratesNext 快速失败立刻唤醒下一条，不必等它自己的 250ms 地板。
func TestFastFailureAcceleratesNext(t *testing.T) {
	h := newHarness(t)
	var t0 time.Time
	var tSecond time.Duration
	var once sync.Once

	first := h.relay("first", behavior{err: errFakeRefused, onDial: func(ctx context.Context) {
		once.Do(func() { t0 = time.Now() })
	}})
	second := h.relay("second", behavior{conn: newFakeConn(), onDial: func(ctx context.Context) {
		once.Do(func() { tSecond = time.Since(t0) })
	}})
	p := h.pool([]string{first, second})

	conn, err := p.Dial(context.Background(), "example.com", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("第二条应起跑并胜出: %v", err)
	}
	conn.Close()
	waitFor(t, "第二条被拨", func() bool { return h.started(second) == 1 })
	if tSecond > raceStagger/2 {
		t.Fatalf("第二条起跑晚了 %v——快速失败没有加速", tSecond)
	}
}

// TestStaggerFloorHoldsWhilePredecessorInFlight 250ms 地板必须真实存在：
// 前驱**仍在途**（挂起）时，后继不得被一次广播瞬间放行。地板没了，"错开竞速"
// 就退化成"同时全发"，队首的先跑优势随之消失。
func TestStaggerFloorHoldsWhilePredecessorInFlight(t *testing.T) {
	h := newHarness(t)
	var starts []time.Duration
	var base time.Time
	rec := func(ctx context.Context) {
		if base.IsZero() {
			base = time.Now()
		}
		starts = append(starts, time.Since(base))
	}
	a := h.relay("a", behavior{hangCtx: true, onDial: rec}) // 队首挂起、永不返回
	b := h.relay("b", behavior{delay: 5 * time.Millisecond, conn: newFakeConn(), onDial: rec})
	p := h.pool([]string{a, b})

	conn, err := p.Dial(context.Background(), "example.com", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("后位候选应胜出: %v", err)
	}
	conn.Close()
	if len(starts) < 2 {
		t.Fatal("两条都该起跑")
	}
	if gap := starts[1] - starts[0]; gap < raceStagger-60*time.Millisecond {
		t.Fatalf("前驱在途时第 2 条仅 %v 就起跑——250ms 地板失效: %v", gap, starts)
	}
}

// TestHeadWinsTie 回归：三条都"瞬间成功"时，队首必须赢。
// 这条钉住 winner 选择：结果不能取决于 goroutine 抢到通道的顺序，而应取决于
// 谁先起跑（队首领先 250ms）。否则全局排序会被随机抖动污染。
func TestHeadWinsTie(t *testing.T) {
	h := newHarness(t)
	a := h.ok("a", 0)
	h.ok("b", 0)
	h.ok("c", 0)
	p := h.pool([]string{a, "b", "c"})

	for i := 0; i < 20; i++ {
		conn, err := p.Dial(context.Background(), "example.com", 443, 2*time.Second)
		if err != nil {
			t.Fatalf("应有一条成功: %v", err)
		}
		conn.Close()
		if got := p.Order()[0]; got != "a" {
			t.Fatalf("第 %d 轮：队首 %s 应稳赢，实际 %s; order=%v", i, a, got, p.Order())
		}
	}
}

// TestSuccessImmediatelyWinsAndLosersClosed 胜者即时返回；随后迟到的成功连接
// 必须被关闭（否则泄漏），且落败者不记失败（它可能完全健康，只是没跑赢）。
func TestSuccessImmediatelyWinsAndLosersClosed(t *testing.T) {
	h := newHarness(t)
	winnerConn := newFakeConn()
	loserConn := newFakeConn()
	winner := h.relay("winner", behavior{delay: 200 * time.Millisecond, conn: winnerConn})
	loser := h.lateOK("loser", 1200*time.Millisecond)
	_ = loserConn
	p := h.pool([]string{winner, loser})

	start := time.Now()
	conn, err := p.Dial(context.Background(), "example.com", 443, 5*time.Second)
	if err != nil {
		t.Fatalf("应胜出: %v", err)
	}
	if el := time.Since(start); el > 800*time.Millisecond {
		t.Fatalf("胜者 200ms 就绪，却等了 %v——胜出不够即时", el)
	}
	if conn != net.Conn(winnerConn) {
		t.Fatal("返回的不是胜者的连接")
	}
	conn.Close()

	// 落败者迟到的成功连接必须被关闭（而不是泄漏）。
	waitFor(t, "落败者交出连接", func() bool { return h.succeeded(loser) == 1 })
	waitFor(t, "落败者连接被关闭", func() bool { return h.closedConns() >= 1 })
	if st := p.Stats()[loser]; st[1] != 0 {
		t.Fatalf("竞速落败者不该被记失败: %v", st)
	}
	if got := p.Order()[0]; got != winner {
		t.Fatalf("胜者应置顶: %v", p.Order())
	}
}

// TestGenuineFailureCounted 真正拨不通的候选要记失败并置底。
func TestGenuineFailureCounted(t *testing.T) {
	h := newHarness(t)
	bad := h.fail("bad")
	good := h.ok("good", 0)
	p := h.pool([]string{bad, good})

	conn, err := p.Dial(context.Background(), "example.com", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("后位候选应胜出: %v", err)
	}
	conn.Close()
	if st := p.Stats()[bad]; st[1] != 1 {
		t.Fatalf("连接被拒应记一次失败: %v", st)
	}
	if got := p.Order(); got[0] != good || got[len(got)-1] != bad {
		t.Fatalf("成功置顶、失败置底: %v", got)
	}
}

// TestCooledRelayNotScheduled 冷却中的中继不参与调度——不新起一条注定失败的拨号。
func TestCooledRelayNotScheduled(t *testing.T) {
	h := newHarness(t)
	forced := h.fail("cooled")
	other := h.ok("other", 0)
	p := h.pool([]string{forced, other})
	for i := 0; i < maxFails; i++ {
		p.noteFail(forced)
	}
	if ready := p.ready(); len(ready) != 1 || ready[0].addr != other {
		t.Fatalf("冷却中的中继仍在调度名单: %v", ready)
	}

	conn, err := p.Dial(context.Background(), "example.com", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("应走未冷却的候选: %v", err)
	}
	conn.Close()
	if c := h.started(forced); c != 0 {
		t.Fatalf("冷却中的中继被拨了 %d 次", c)
	}
	if got := p.Order()[0]; got != other {
		t.Fatalf("胜者应置顶: %v", p.Order())
	}
}

// TestAllCooledFailsFast 全部在冷却中时直接失败，不做无谓拨号。
func TestAllCooledFailsFast(t *testing.T) {
	h := newHarness(t)
	a := h.fail("a")
	b := h.fail("b")
	p := h.pool([]string{a, b})
	for i := 0; i < maxFails; i++ {
		p.noteFail(a)
		p.noteFail(b)
	}
	if _, err := p.Dial(context.Background(), "example.com", 443, 2*time.Second); err == nil {
		t.Fatal("全部冷却应返回错误")
	}
	if n := len(h.dialed()); n != 0 {
		t.Fatalf("全部冷却时不该拨号，却拨了 %v", h.dialed())
	}
}

// TestGlobalPoolOrderAcrossHosts 顺序是**全局共享**的：对 host A 的成功观测
// 立刻改变 host B 的首选。这正是"进程级健康池"的意义。
// 只放一条候选，避开竞速并发带来的顺序不确定——这里要断言的是记账，不是起跑。
func TestGlobalPoolOrderAcrossHosts(t *testing.T) {
	h := newHarness(t)
	a := h.ok("a", 0)
	b := h.ok("b", 0)
	c := h.ok("c", 0)
	p := h.pool([]string{a, b, c})

	conn, err := p.Dial(context.Background(), "host-a.example", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("host A 拨号失败: %v", err)
	}
	conn.Close()
	p.noteOK(c) // 让 c 成为"已证明可用"，对所有 host 生效

	// host B 的 Dial 一定跑 c：它是唯一参竞候选（批次 = 1）。
	conn, err = p.Dial(context.Background(), "host-b.example", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("host B 拨号失败: %v", err)
	}
	conn.Close()
	if got := p.Order()[0]; got != c {
		t.Fatalf("跨 host 的顺序未共享: %v", p.Order())
	}
}

// TestCancellationPropagatesAndClosesLosers ctx 取消必须让在途拨号立刻返回，
// 不记失败，迟到的成功连接被关闭。
func TestCancellationPropagatesAndClosesLosers(t *testing.T) {
	h := newHarness(t)
	stalled := h.hang("stalled")
	late := h.lateOK("late", 1500*time.Millisecond)
	p := h.pool([]string{stalled, late})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := p.Dial(ctx, "example.com", 443, 10*time.Second)
		done <- err
	}()
	waitFor(t, "两条候选都已起跑", func() bool { return h.started(stalled) == 1 && h.started(late) == 1 })
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("取消应返回 context.Canceled，实际 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("取消后 Dial 未及时返回——ctx 没有传到拨号层")
	}
	if st := p.Stats()[stalled]; st[1] != 0 {
		t.Fatalf("被取消的尝试不该记失败: %v", st)
	}
	waitFor(t, "迟到连接被关闭", func() bool { return h.closedConns() >= 1 })
}

// TestGlobalConcurrencyBounded 进程级上限：多个池同时竞速时，在途拨号不超过
// maxGlobalDial——防止并发请求一起把所有中继拉起、把出口打满。
func TestGlobalConcurrencyBounded(t *testing.T) {
	h := newHarness(t)
	var inflight, maxSeen int32
	var mu sync.Mutex

	mk := func(name string) string {
		return h.relay(name, behavior{delay: 250 * time.Millisecond, conn: newFakeConn(), onDial: func(ctx context.Context) {
			n := atomic.AddInt32(&inflight, 1)
			mu.Lock()
			if n > maxSeen {
				maxSeen = n
			}
			mu.Unlock()
			time.Sleep(250 * time.Millisecond)
			atomic.AddInt32(&inflight, -1)
		}})
	}
	// 6 个池 × 3 条候选 = 18 次拨号，若无限流峰值会远超 maxGlobalDial。
	var pools []*Pool
	for i := 0; i < 6; i++ {
		pools = append(pools, h.pool([]string{mk(fmt.Sprintf("r%d-a", i)), mk(fmt.Sprintf("r%d-b", i)), mk(fmt.Sprintf("r%d-c", i))}))
	}

	var wg sync.WaitGroup
	for _, p := range pools {
		wg.Add(1)
		go func(p *Pool) {
			defer wg.Done()
			conn, err := p.Dial(context.Background(), "example.com", 443, 3*time.Second)
			if err == nil {
				conn.Close()
			}
		}(p)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if maxSeen > maxGlobalDial {
		t.Fatalf("进程级在途拨号峰值 %d，超过上限 %d", maxSeen, maxGlobalDial)
	}
	if maxSeen < 2 {
		t.Fatalf("峰值只有 %d——全局信号量没有真正共享", maxSeen)
	}
}

// TestNoGoroutineLeakAfterRace 竞速结束后不该留下挂起的 goroutine：
// 每条候选都恰好上报一次，drain 必定收完。
func TestNoGoroutineLeakAfterRace(t *testing.T) {
	h := newHarness(t)
	relays := []string{h.ok("a", 100*time.Millisecond), h.hang("b"), h.hang("c"), h.hang("d")}
	p := h.pool(relays)

	before := runtimeNumGoroutine()
	conn, err := p.Dial(context.Background(), "example.com", 443, 5*time.Second)
	if err != nil {
		t.Fatalf("应胜出: %v", err)
	}
	conn.Close()
	waitFor(t, "所有起跑的候选都已返回", func() bool { return h.returnedCount() == len(h.dialed()) })
	// 给一点时间让 defer 收尾，然后对比 goroutine 数。
	time.Sleep(100 * time.Millisecond)
	if after := runtimeNumGoroutine(); after > before+2 {
		t.Fatalf("goroutine 从 %d 涨到 %d——疑似泄漏", before, after)
	}
}
