package engine

import (
	"testing"
	"time"

	"satel/internal/failkind"
	"satel/internal/strategy"
)

func strategyProtoTLS() string { return strategy.ProtoTLS }

func firstStrategy(e *Engine) *strategy.Spec { return e.Pool(strategy.ProtoTLS)[0] }

func mustParse(t *testing.T, s string) *strategy.Spec {
	t.Helper()
	sp, err := strategy.Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return sp
}

func indexOf(list []string, id string) int {
	for i, x := range list {
		if x == id {
			return i
		}
	}
	return -1
}

// --- Engine 层：方法列表取代 verdict 状态机 ----------------------------------

func TestMethodsDefaultsToCostTiebreak(t *testing.T) {
	e := New(nil)
	p := e.Methods("example.com", strategy.ProtoTLS)
	if len(p) == 0 {
		t.Fatal("应有方法候选")
	}
	if p[0] != MethodDirect {
		t.Fatalf("无观测时 direct 应优先, got %v", p)
	}
}

func TestSuccessReordersMethods(t *testing.T) {
	e := New(nil)
	h := "blocked.example"
	spec := firstStrategy(e)
	for i := 0; i < 5; i++ {
		e.Record(h, strategy.ProtoTLS, MethodDirect, nil, failkind.Reset, true)
		e.Record(h, strategy.ProtoTLS, spec.ID(), spec, failkind.None, true)
	}
	p := e.Methods(h, strategy.ProtoTLS)
	if indexOf(p, spec.ID()) >= indexOf(p, MethodDirect) {
		t.Fatalf("成功的策略应排在失败的 direct 前: %v", p)
	}
}

func TestGroupInheritance(t *testing.T) {
	e := New(nil)
	for i := 0; i < 6; i++ {
		e.Record("a.example", strategy.ProtoTLS, MethodDirect, nil, failkind.Reset, true)
		e.Record("a.example", strategy.ProtoTLS, MethodECH, nil, failkind.None, true)
	}
	e.mem.MarkGroupForTest("b.example", GroupKey(true, failkind.Reset))
	p := e.Methods("b.example", strategy.ProtoTLS)
	if indexOf(p, MethodECH) >= indexOf(p, MethodDirect) {
		t.Fatalf("同组新 host 应继承 group 先验（ECH 优先）: %v", p)
	}
}

func TestDialFailurePushesDirectDown(t *testing.T) {
	e := New(nil)
	h := "blackhole.example"
	// 拨号超时会同时喂 direct 与所有包级策略（它们都会失败）
	for i := 0; i < 4; i++ {
		e.Record(h, strategy.ProtoTLS, MethodDirect, nil, failkind.DialTimeout, false)
		e.Record(h, strategy.ProtoTLS, MethodTunnel, nil, failkind.None, false)
	}
	p := e.Methods(h, strategy.ProtoTLS)
	if indexOf(p, MethodTunnel) >= indexOf(p, MethodDirect) {
		t.Fatalf("拨号不通时隧道应排在 direct 前: %v", p)
	}
}

func TestHerdGuard(t *testing.T) {
	e := New(nil)
	if !e.Claim("busy.example") {
		t.Fatal("首个探测者应取得探测权")
	}
	if e.Claim("busy.example") {
		t.Fatal("第二个不应取得探测权")
	}
	e.Release("busy.example")
	if !e.Claim("busy.example") {
		t.Fatal("释放后应可再取")
	}
}

func TestSetBundleMergesAndDedupes(t *testing.T) {
	e := New(nil)
	before := len(e.Pool(strategy.ProtoTLS))
	custom := mustParse(t, "tls|tlsrf(chunk=4,delay_ms=6,limit=200)")
	e.SetBundle(strategy.ProtoTLS, []*strategy.Spec{custom})
	pool := e.Pool(strategy.ProtoTLS)
	if pool[0].ID() != custom.ID() {
		t.Fatalf("下发策略应排最前, got %s", pool[0].ID())
	}
	if len(pool) != before+1 {
		t.Fatalf("合并后 %d 条, want %d", len(pool), before+1)
	}
}

func TestSetBundleRejectsEmpty(t *testing.T) {
	e := New(nil)
	before := len(e.Pool(strategy.ProtoTLS))
	e.SetBundle(strategy.ProtoTLS, nil)
	if len(e.Pool(strategy.ProtoTLS)) != before {
		t.Fatal("空 bundle 不应清空候选池")
	}
}

func TestReportsOnlyWithClient(t *testing.T) {
	e := New(nil)
	spec := firstStrategy(e)
	e.RecordAttempt("example.com", "tls", spec, true, 10*time.Millisecond, false, failkind.None)
	if e.Pending() != 0 {
		t.Fatal("无 Worker 时不应产生回报")
	}
}

func TestCanceledNotEvidence(t *testing.T) {
	e := New(nil)
	e.Record("x.example", strategy.ProtoTLS, MethodDirect, nil, failkind.Canceled, false)
	// Canceled 完全不该建立记忆条目（浏览器关页面会刷出大量这种）
	hosts, groups := e.Stats()
	if hosts != 0 || groups != 0 {
		t.Fatalf("Canceled 不该建立任何记忆条目：hosts=%d groups=%d", hosts, groups)
	}
}

func TestSweepKeepsLive(t *testing.T) {
	e := New(nil)
	e.Record("a.example", strategy.ProtoTLS, MethodDirect, nil, failkind.None, false)
	e.Record("b.example", strategy.ProtoTLS, MethodDirect, nil, failkind.Reset, true)
	hosts, _ := e.Stats()
	if hosts < 2 {
		t.Fatalf("应有至少 2 个 host, got %d", hosts)
	}
	if n := e.Sweep(); n != 0 {
		t.Fatalf("未过期却清了 %d 条", n)
	}
}
