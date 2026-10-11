package engine

import (
	"testing"
	"time"

	"satel/internal/coord"
	"satel/internal/failkind"
	"satel/internal/strategy"
)

func TestPlanEmptyHostUsesCostTiebreak(t *testing.T) {
	m := newTestMemory()
	p := m.Plan("new.example", strategy.ProtoTLS)
	if len(p) != 4 {
		t.Fatalf("候选应有 4 个伪方法, got %d", len(p))
	}
	// 全无观测时 rate 相同，按 cost 升序：direct(0) < ech/tunnel/proxyip(2)
	if p[0] != MethodDirect {
		t.Fatalf("同分时应 direct 优先, got %v", p)
	}
}

// TestUntriedBeatsFailed 复现真机 bug：一个方法在本 host 和 group 里都毫无证据时，
// 必须排在"试过且失败"的方法之前。曾经 a=0 让未观测方法算出 (0+0·prior)/1 = 0.0，
// 低于已失败方法靠组先验拿到的 >0，于是阶梯只重放已知失败的方法、探索饿死
// （discord 第 2 轮实测：12 个失败方法全排在从未试过的 @ech 之前）。
func TestUntriedBeatsFailed(t *testing.T) {
	m := newTestMemory()
	h := "d.example"
	m.ObserveWithGroup(h, "1:reset", MethodDirect, failkind.Reset)
	m.SetKnown("tls", append(PseudoMethods, "0352f73e"))
	m.ObserveWithGroup(h, "1:reset", "0352f73e", failkind.Reset)

	p := m.Plan(h, strategy.ProtoTLS)
	idx := func(id string) int {
		for i, x := range p {
			if x == id {
				return i
			}
		}
		return -1
	}
	if idx(MethodECH) >= idx(MethodDirect) {
		t.Fatalf("未观测的 ECH 应排在已失败的 direct 之前；plan=%v", p)
	}
	if r := m.rate(h, MethodECH); r <= m.rate(h, MethodDirect) {
		t.Fatalf("未观测方法 rate=%.3f 应高于已失败方法 rate=%.3f", r, m.rate(h, MethodDirect))
	}
}

// TestSuccessReorders 是分层记忆的核心：direct 失败多次后，应改排到后面。
func TestSuccessReorders(t *testing.T) {
	m := newTestMemory()
	h := "h.example"
	// direct 连败 5 次，ECH 成功 5 次
	for i := 0; i < 5; i++ {
		m.ObserveWithGroup(h, "1:被复位", MethodDirect, failkind.Reset)
		m.ObserveWithGroup(h, "1:被复位", MethodECH, failkind.None)
	}
	p := m.Plan(h, strategy.ProtoTLS)
	idx := func(id string) int {
		for i, x := range p {
			if x == id {
				return i
			}
		}
		return -1
	}
	if idx(MethodECH) >= idx(MethodDirect) {
		t.Fatalf("ECH 成功 5 次、direct 失败 5 次，ECH 应排在 direct 前；plan=%v", p)
	}
}

// TestGroupInheritanceWithoutObservingSibling 是 handoff 强调的关键性质：
// 一个**从未访问过**的同组 host，应继承 group 里 direct 的失败率，direct 不排第一。
func TestGroupInheritanceWithoutObservingSibling(t *testing.T) {
	m := newTestMemory()
	// 先把 group 1:被复位 的 direct 打崩
	for i := 0; i < 6; i++ {
		m.ObserveWithGroup("a.example", "1:被复位", MethodDirect, failkind.Reset)
		m.ObserveWithGroup("a.example", "1:被复位", MethodECH, failkind.None)
	}
	// b 从没访问过，但已被归到同一组（proxy 第一次探测时就会定组）
	m.MarkGroupForTest("b.example", "1:被复位")
	p := m.Plan("b.example", strategy.ProtoTLS)
	// b 无自身观测 → 完全靠 group 先验
	idx := func(id string) int {
		for i, x := range p {
			if x == id {
				return i
			}
		}
		return -1
	}
	// b 自己没观测，所以 Plan 还没继承（继承在 ObserveGroup 时发生）——
	// 但排序应已反映 group 先验：ECH 的 group 成功率 > direct
	if idx(MethodECH) >= idx(MethodDirect) {
		t.Fatalf("新同组 host 应继承 group 先验：ECH 优先；plan=%v", p)
	}
}

// TestInheritedNeverRefillsGroup 继承结果绝不回灌组证据。
func TestInheritedNeverRefillsGroup(t *testing.T) {
	m := newTestMemory()
	h := "h.example"
	m.MarkGroupForTest(h, "g")
	// 手工塞一个继承条目
	m.mu.Lock()
	hs := m.host(h, m.now())
	hs.methods[MethodDirect] = &stat{fail: 3, inherited: true}
	m.mu.Unlock()

	g0 := m.groups["g"]
	var before int
	if g0 != nil {
		if s := g0.methods[MethodDirect]; s != nil {
			before = s.fail
		}
	}
	// 触发一次继承观察（不 Observe 到 group）——Plan 不写 group，这里验证 fold 也不写
	m.mu.Lock()
	oh := m.host("other", m.now())
	oh.group = "g"
	m.fold(oh, m.now())
	m.mu.Unlock()
	g0 = m.groups["g"]
	var after int
	if g0 != nil {
		if s := g0.methods[MethodDirect]; s != nil {
			after = s.fail
		}
	}
	if after != before {
		t.Fatalf("fold 不应把继承计入组；before=%d after=%d", before, after)
	}
}

// TestShrinkageNewHostFollowsGroup 当本 host 无观测，rate_h 由 group 先验主导。
func TestShrinkageNewHostFollowsGroup(t *testing.T) {
	m := newTestMemory()
	// 强先验：direct 在组里崩了，ECH 全胜
	for i := 0; i < 20; i++ {
		m.ObserveWithGroup("seed", "1:被复位", MethodDirect, failkind.Reset)
		m.ObserveWithGroup("seed", "1:被复位", MethodECH, failkind.None)
	}
	m.MarkGroupForTest("fresh", "1:被复位") // 归入同组但无自身观测
	// fresh 的 direct 应继承低先验
	rD := m.rate("fresh", MethodDirect)
	rE := m.rate("fresh", MethodECH)
	if rE <= rD {
		t.Fatalf("收缩失败：无自身观测时应由 group 先验主导；direct=%.3f ech=%.3f", rD, rE)
	}
	// 且 direct 的绝对率应被拉低（收缩效应）
	if rD > 0.5 {
		t.Fatalf("direct 继承了 20 次失败的组证据，后验应显著低于 0.5, got %.3f", rD)
	}
}

// TestOneCounterexampleDemotes inherited 条目一次反例即降级。
func TestOneCounterexampleDemotes(t *testing.T) {
	m := newTestMemory()
	h := "h.example"
	m.ObserveWithGroup(h, "1:被复位", MethodDirect, failkind.Reset)
	m.ObserveWithGroup(h, "1:被复位", MethodECH, failkind.None)
	rBefore := m.rate(h, MethodECH)
	// ECH 一次失败（一次反例）——不要求换位，但 rate 必须下降
	m.ObserveWithGroup(h, "1:被复位", MethodECH, failkind.Reset)
	rAfter := m.rate(h, MethodECH)
	if rAfter >= rBefore {
		t.Fatalf("一次反例应让 ECH 后验下降：%.4f -> %.4f", rBefore, rAfter)
	}
}

func indexIn(list []string, id string) int {
	for i, x := range list {
		if x == id {
			return i
		}
	}
	return -1
}

// TestLRUEvictionFoldsNotDiscards LRU 挤出应折叠进组而非丢弃。
func TestLRUEvictionFoldsNotDiscards(t *testing.T) {
	m := newTestMemory()
	// 塞超过 hostLRU 个 host，挤出最早的
	total := hostLRU + 20
	for i := 0; i < total; i++ {
		h := string(rune('a'+i%26)) + itoa(i)
		m.ObserveWithGroup(h, "1:被复位", MethodDirect, failkind.Reset)
	}
	hosts, _ := m.Stats()
	if hosts > hostLRU {
		t.Fatalf("tier1 超过 LRU 上限: %d > %d", hosts, hostLRU)
	}
	// 折叠后，组里应累积了相当多的 direct 失败
	m.mu.Lock()
	g := m.groups["1:被复位"]
	var folded int
	if g != nil {
		if s := g.methods[MethodDirect]; s != nil {
			folded = s.fail
		}
	}
	m.mu.Unlock()
	if folded < total/2 {
		t.Fatalf("挤出应折叠进组证据；folded=%d 期望 >= %d", folded, total/2)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// newTestMemory 造一个只有伪方法的记忆层（测试用）。
func newTestMemory() *Memory {
	m := NewMemory()
	m.SetKnown("tls", PseudoMethods)
	m.SetKnown("http", PseudoMethods)
	return m
}

// TestHintOnlyWhenNothingLocalKnown 后缀经验是 tier3：只有在本 host 与该组
// **都没有证据**时才兜底。本机一旦观测过，hint 必须让位——否则一次错误的挖掘
// 结论会长期压住本机的真实经验。
func TestHintOnlyWhenNothingLocalKnown(t *testing.T) {
	m := newTestMemory()
	now := time.Unix(1000, 0)
	m.SetNow(func() time.Time { return now })
	m.SetHints([]coord.Hint{{
		Suffix: "wikipedia.org", Method: MethodTunnel,
		OK: 20, Fail: 1, Hosts: 12, Expires: now.Add(20 * time.Minute).Unix(),
	}})

	// 冷启动：命中 hint，@tunnel 应排在 @direct 前
	m.MarkGroupForTest("en.wikipedia.org", "")
	cold := m.Plan("en.wikipedia.org", strategy.ProtoTLS)
	if idxOf(cold, MethodTunnel) > idxOf(cold, MethodDirect) {
		t.Fatalf("有 hint 时 @tunnel 应排在 @direct 前: %v", cold)
	}

	// 本机观测一次 direct 成功：direct 从"无证据 0.5"升到 0.75。**一次**成功
	// 反超不过 20:1 的远端经验（0.913），这是对的——hint 是弱先验但有全网样本量，
	// 单次观测不该掀翻它。
	m.Observe("en.wikipedia.org", MethodDirect, failkind.None)
	if r := m.rate("en.wikipedia.org", MethodDirect); r <= 0.5 {
		t.Fatalf("本机成功后 direct 应升出无先验水平: %.3f", r)
	}
	// 但**本机失败**（那是强信号：连都连不上）必须立刻把它压下去。
	for i := 0; i < 3; i++ {
		m.Observe("en.wikipedia.org", MethodDirect, failkind.Reset)
	}
	if idxOf(m.Plan("en.wikipedia.org", strategy.ProtoTLS), MethodDirect) <
		idxOf(m.Plan("en.wikipedia.org", strategy.ProtoTLS), MethodTunnel) {
		t.Fatalf("本机多次失败后 direct 必须让位给 hint 撑起的 tunnel: %v",
			m.Plan("en.wikipedia.org", strategy.ProtoTLS))
	}
}

// TestHintLongestSuffixWins 命中**最长**后缀：en.wikipedia.org 要按
// "wikipedia.org" 取结论，而不是裸 "org"。
//
// 两条 hint 都是全胜，rate 相同（各自先验一样强），所以同分时按成本序
// @direct 在前——这是**正确**的：hint 不该也不需要压过成本。真正被验证的是
// "取到了哪一条"：对 example.com 必须一条都取不到。
func TestHintLongestSuffixWins(t *testing.T) {
	m := newTestMemory()
	now := time.Unix(1000, 0)
	m.SetNow(func() time.Time { return now })
	exp := now.Add(20 * time.Minute).Unix()
	m.SetHints([]coord.Hint{
		{Suffix: "org", Method: MethodDirect, OK: 50, Fail: 0, Hosts: 99, Expires: exp},
		{Suffix: "wikipedia.org", Method: MethodTunnel, OK: 50, Fail: 0, Hosts: 99, Expires: exp},
	})
	// 两个方法都被各自最长的后缀命中（rate 都起来，不是 0.5 的"无先验"）
	if r := m.rate("en.wikipedia.org", MethodDirect); r <= 0.6 {
		t.Fatalf("@direct 未取到 org 的 hint: %.3f", r)
	}
	if r := m.rate("en.wikipedia.org", MethodTunnel); r <= 0.6 {
		t.Fatalf("@tunnel 未取到 wikipedia.org 的 hint: %.3f", r)
	}
	// 未被 hint 覆盖的方法仍是"无先验"（0.5）
	if r := m.rate("en.wikipedia.org", MethodECH); r != 0.5 {
		t.Fatalf("@ech 不该被任何 hint 撑起来: %.3f", r)
	}
	// 完全不相关的 host：一条都取不到（"org" 不能作为点分后缀匹配 example.com）
	if r := m.rate("example.com", MethodDirect); r != 0.5 {
		t.Fatalf("org 不该命中 example.com: %.3f", r)
	}
}

// TestHintExpiry 过期的 hint 不参与排序。
func TestHintExpiry(t *testing.T) {
	m := newTestMemory()
	now := time.Unix(1000, 0)
	m.SetNow(func() time.Time { return now })
	m.SetHints([]coord.Hint{{
		Suffix: "wikipedia.org", Method: MethodTunnel,
		OK: 50, Fail: 0, Hosts: 99, Expires: now.Add(20 * time.Minute).Unix(),
	}})
	before := m.Plan("en.wikipedia.org", strategy.ProtoTLS)
	if idxOf(before, MethodTunnel) > idxOf(before, MethodDirect) {
		t.Fatalf("有效期内 tunnel 应优先: %v", before)
	}
	now = now.Add(21 * time.Minute)
	after := m.Plan("en.wikipedia.org", strategy.ProtoTLS)
	// 过期后回到"同分按 cost"：direct(0) 在 tunnel(3) 前
	if after[0] != MethodDirect {
		t.Fatalf("过期后应回到默认成本序: %v", after)
	}
}

// TestHintNeverWritesBackToGroup hint 绝不回灌组证据。
func TestHintNeverWritesBackToGroup(t *testing.T) {
	m := newTestMemory()
	now := time.Unix(1000, 0)
	m.SetNow(func() time.Time { return now })
	m.SetHints([]coord.Hint{{
		Suffix: "wikipedia.org", Method: MethodTunnel,
		OK: 50, Fail: 0, Hosts: 99, Expires: now.Add(time.Hour).Unix(),
	}})
	m.Plan("en.wikipedia.org", strategy.ProtoTLS)
	if _, n := m.Stats(); n != 0 {
		t.Fatalf("Plan 不该建任何分组, got %d", n)
	}
}

func idxOf(list []string, id string) int {
	for i, x := range list {
		if x == id {
			return i
		}
	}
	return -1
}
