package engine

import (
	"strings"
	"testing"

	"satel/internal/failkind"
	"satel/internal/strategy"
)

// TestBundleStrategiesEnterPlan 是阻断 bug 的回归测试：
// SetBundle 换池子后必须同步 Memory 的候选方法全集，否则新策略进了池子却
// 永远进不了 Plan——Worker 演化出来的策略就等于空转。
func TestBundleStrategiesEnterPlan(t *testing.T) {
	e := New(nil)

	before := e.Methods("x.example", strategy.ProtoTLS)
	if len(before) == 0 {
		t.Fatal("初始候选不应为空")
	}

	newSpec, err := strategy.Parse("tls|split(at=mid,count=5,delay_ms=30,len=3,pos=0)")
	if err != nil {
		t.Fatal(err)
	}
	e.SetBundle(strategy.ProtoTLS, []*strategy.Spec{newSpec})

	if len(e.Pool(strategy.ProtoTLS)) < 2 {
		t.Fatalf("新策略应已入池，实际 %d 条", len(e.Pool(strategy.ProtoTLS)))
	}
	after := e.Methods("x.example", strategy.ProtoTLS)
	for _, id := range after {
		if id == newSpec.ID() {
			return
		}
	}
	t.Fatalf("新策略 %s 不在候选里，Worker 演化对路由无效。候选: %v", newSpec.ID(), after)
}

// TestGroupOnlyOnEvidence 确认分组只在"带方向的失败"上建立：
// direct 成功不应该造出一个垃圾分组，更不该用 isCF=None 把它提前钉死。
func TestGroupOnlyOnEvidence(t *testing.T) {
	m := newTestMemory()

	// 一个完全可达的站：只记成功
	m.Observe("ok.example", MethodDirect, failkind.None)
	hosts, groups := m.Stats()
	if hosts != 1 {
		t.Fatalf("host 数 %d, want 1", hosts)
	}
	if groups != 0 {
		t.Fatalf("只有成功观测时不该建组，实际 %d 个: %v", groups, keys(m))
	}

	// 一个被 dial 超时的站：失败带类别，且调用方给了 isCF
	m.ObserveWithGroup("black.example", GroupKey(true, failkind.DialTimeout), MethodDirect, failkind.DialTimeout)
	if _, groups = m.Stats(); groups != 1 {
		t.Fatalf("带类别的失败应建一个组，实际 %d 个", groups)
	}
	// 空 group 的桶不允许出现
	for _, g := range keys(m) {
		if g == "" || len(g) < 3 {
			t.Fatalf("出现了非法分组键 %q", g)
		}
	}
}

// TestGroupKeyUsesStableToken 锁住"展示串不能当 map 键"这条约定：
// group 键必须含 failkind.Key() 的机器键，而不是 Label() 的中文。
func TestGroupKeyUsesStableToken(t *testing.T) {
	g := GroupKey(true, failkind.Reset)
	if g != "1:reset" {
		t.Fatalf("GroupKey(true, Reset) = %q, want \"1:reset\"", g)
	}
	if got := GroupKey(false, failkind.ReadTimeout); got != "0:readtimeout" {
		t.Fatalf("GroupKey(false, ReadTimeout) = %q", got)
	}
	if failkind.Reset.Label() == failkind.Reset.Key() {
		t.Fatal("展示串与机器键相同——这正是要避免的耦合")
	}
}

// TestObserveNeverGroups 补上 TestGroupOnlyOnEvidence 留的缺口。
//
// 那条测试只验了**成功**观测不建组；而曾存在的那段死代码恰恰是"**失败**时按
// kind 推导 group"——把 Reachable()（连接建没建起来）当成 isCF（是否 CF 承载）的
// 近似。那是错的启发式（非 CF 的站一样会被 RST、CF 的边缘 IP 一样可能被黑洞），
// 且因调用条件互斥而永不执行。这个测试把"失败也不建组"钉住：
// Observe 的语义是**只记 host 层**，分组只能由 ObserveWithGroup 显式给定。
func TestObserveNeverGroups(t *testing.T) {
	m := newTestMemory()

	// 各种失败类别都走 Observe——包括那个当年会被误推成 isCF=true 的 Reset
	for _, k := range []failkind.Kind{
		failkind.Reset, failkind.DialTimeout, failkind.ReadTimeout,
		failkind.TLSAlert, failkind.DialRefused, failkind.Other,
	} {
		m.Observe("h.example", MethodDirect, k)
	}
	m.Observe("h.example", MethodDirect, failkind.None)

	hosts, groups := m.Stats()
	if hosts != 1 {
		t.Fatalf("host 层应记下 1 个主机, got %d", hosts)
	}
	if groups != 0 {
		t.Fatalf("Observe 不该建任何分组（分组只由 ObserveWithGroup 显式给定），"+
			"却建了 %d 个: %v", groups, keys(m))
	}
	// host 层证据本身要记全：6 次失败 + 1 次成功
	if r := m.rate("h.example", MethodDirect); r > 0.2 {
		t.Fatalf("6 败 1 胜后后验应很低, got %.3f", r)
	}
}

// TestGroupPinnedByFirstFailure 分组由**第一次**带方向的观测钉住，之后不漂移。
//
// 规格要的是"这个 host 属于哪一类"——它不该随着后续某个方法碰巧以别的类别失败
// 而改籍。改籍会让先验错乱，且症状（新域名莫名先跳过 direct）极难定位。
func TestGroupPinnedByFirstFailure(t *testing.T) {
	m := newTestMemory()

	first := GroupKey(true, failkind.Reset)
	m.ObserveWithGroup("h.example", first, MethodDirect, failkind.Reset)
	// 后续一次"另一个组"的失败，不该把它挪走
	m.ObserveWithGroup("h.example", GroupKey(false, failkind.DialTimeout), MethodECH, failkind.DialTimeout)

	m.mu.Lock()
	got := m.hosts["h.example"].group
	other := m.groups[GroupKey(false, failkind.DialTimeout)]
	pinned := m.groups[first]
	var directFail, echFail int
	if pinned != nil {
		if s := pinned.methods[MethodDirect]; s != nil {
			directFail = s.fail
		}
		if s := pinned.methods[MethodECH]; s != nil {
			echFail = s.fail
		}
	}
	total := len(m.groups)
	m.mu.Unlock()

	if got != first {
		t.Fatalf("分组被后来的观测挪走了: %q, want %q", got, first)
	}
	// 第二个"组键"不该被凭空建出来：host 只属于一个类，后续观测的证据要落进
	// 它被钉住的那个组，而不是按每次失败的类别另开一组。
	if other != nil || total != 1 {
		t.Fatalf("不该按后续失败的类别另开分组：组数=%d other=%v", total, other != nil)
	}
	// 而两次观测的证据都要进那个钉住的组
	if directFail != 1 || echFail != 1 {
		t.Fatalf("后续观测的证据没落进钉住的组: direct.fail=%d ech.fail=%d", directFail, echFail)
	}
}

func keys(m *Memory) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.groups))
	for g := range m.groups {
		out = append(out, g)
	}
	return out
}

// TestProtoDoesNotClobberCandidates 是第二个阻断 bug 的回归测试。
//
// SetBundle 是逐 proto 调用的（syncLoop 先 tls 后 http）。候选全集若合成一个全局
// 列表，后一个 proto 会把前一个整个覆盖——TLS 主机的计划里就只剩 HTTP 策略，
// SpecByID 一个都找不到、全部静默跳过，连记忆都不记。
func TestProtoDoesNotClobberCandidates(t *testing.T) {
	e := New(nil)

	tlsSpec, err := strategy.Parse("tls|split(at=mid,count=5,delay_ms=30,len=3,pos=0)")
	if err != nil {
		t.Fatal(err)
	}
	httpSpec, err := strategy.Parse("http|hostsplit(gap=3)")
	if err != nil {
		t.Fatal(err)
	}

	// syncLoop 的顺序：先 tls，再 http
	e.SetBundle(strategy.ProtoTLS, []*strategy.Spec{tlsSpec})
	e.SetBundle(strategy.ProtoHTTP, []*strategy.Spec{httpSpec})

	tlsPlan := e.Methods("x.example", strategy.ProtoTLS)
	if !contains(tlsPlan, tlsSpec.ID()) {
		t.Fatalf("HTTP 的 SetBundle 覆盖了 TLS 候选，TLS 计划里没有 %s: %v", tlsSpec.ID(), tlsPlan)
	}
	if contains(tlsPlan, httpSpec.ID()) {
		t.Fatalf("TLS 计划里混进了 HTTP 策略 %s: %v", httpSpec.ID(), tlsPlan)
	}
	// 而且计划里的每个策略都必须能在池里解析出来——这是"计划有效"的硬条件
	for _, id := range tlsPlan {
		if !strings.HasPrefix(id, "@") && e.SpecByID(id) == nil {
			t.Fatalf("计划里的 %s 在池里找不到，会被静默跳过", id)
		}
	}

	httpPlan := e.Methods("x.example", strategy.ProtoHTTP)
	if !contains(httpPlan, httpSpec.ID()) {
		t.Fatalf("HTTP 计划里没有 %s: %v", httpSpec.ID(), httpPlan)
	}
}

func contains(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}
