// Package engine 是自适应层：决定某个主机该试哪些策略、谁去试、试完记住什么。
//
// 三件事：
//  1. 候选排序——把记忆里"已验证可行"的策略提到最前，省掉注定失败的尝试；
//  2. 惊群挡板——首屏几十条连接打同一个主机时，只让一条去探测，其余用记忆；
//  3. 效果回报——按主机哈希 + 策略 ID 记账，攒批交给 Worker。
package engine

import (
	"sync"
	"time"

	"satel/internal/coord"
	"satel/internal/failkind"
	"satel/internal/strategy"
)

const (
	ttlDirect   = 6 * time.Hour
	ttlStrategy = 6 * time.Hour
	ttlBlocked  = 30 * time.Minute
	reportCap   = 512
	poolCap     = 32
)

// Engine 是自适应层。并发安全。
type Engine struct {
	mu       sync.Mutex
	pool     map[string][]*strategy.Spec
	mem      *Memory
	inflight map[string]struct{}
	reports  []coord.Item
	client   *coord.Client
	now      func() time.Time
}

// New 构造引擎，用内置策略库初始化候选池。
func New(client *coord.Client) *Engine {
	e := &Engine{
		pool:     map[string][]*strategy.Spec{},
		inflight: map[string]struct{}{},
		client:   client,
		now:      time.Now,
	}
	e.pool[strategy.ProtoTLS] = strategy.BuiltinFor(strategy.ProtoTLS)
	e.pool[strategy.ProtoHTTP] = strategy.BuiltinFor(strategy.ProtoHTTP)
	e.mem = NewMemory()
	e.mem.SetNow(func() time.Time { return e.now() })
	for _, proto := range []string{strategy.ProtoTLS, strategy.ProtoHTTP} {
		e.mem.SetKnown(proto, e.knownMethodsLocked(proto))
	}
	return e
}

// knownMethodsLocked 返回某 proto 的全部可选方法 ID（伪方法 + 池中策略）。
func (e *Engine) knownMethodsLocked(proto string) []string {
	out := make([]string, 0, len(e.pool[proto])+len(PseudoMethods))
	out = append(out, PseudoMethods...)
	for _, s := range e.pool[proto] {
		out = append(out, strategyMethod(s))
	}
	return out
}

// Methods 返回该 host 当前该试的方法列表（按后验排序）。
func (e *Engine) Methods(host, proto string) []string {
	e.mu.Lock()
	if e.mem == nil {
		e.mem = NewMemory()
		e.mem.SetNow(func() time.Time { return e.now() })
	}
	e.mu.Unlock()
	return e.mem.Plan(host, proto)
}

// SpecByID 按方法 ID 取策略（伪方法返回 nil）。
func (e *Engine) SpecByID(id string) *strategy.Spec {
	e.mu.Lock()
	pools := make([][]*strategy.Spec, 0, len(e.pool))
	for _, p := range e.pool {
		pools = append(pools, p)
	}
	e.mu.Unlock()
	// 方法 ID 跨 proto 唯一，所以搜全部池——只看 TLS 池会让 HTTP 策略全部落空。
	for _, pool := range pools {
		for _, s := range pool {
			if s.ID() == id {
				return s
			}
		}
	}
	return nil
}

// SetNow 注入时钟（测试用）。
func (e *Engine) SetNow(f func() time.Time) { e.now = f }

// SetBundle 用 Worker 下发的策略替换候选池；全部非法时保留原池。
// 客户端不信任下发的顺序与分数，只取"有哪些策略"，顺序由本地记忆决定。
// SetHints 装入协调端下发的后缀经验（见 Memory.SetHints）。
// 与 SetBundle 分开：hints 不是策略，不参与候选池，只做排序先验。
func (e *Engine) SetHints(hints []coord.Hint) {
	if e.mem == nil {
		return
	}
	e.mem.SetHints(hints)
}

func (e *Engine) SetBundle(proto string, specs []*strategy.Spec) {
	if len(specs) == 0 {
		return
	}
	if len(specs) > poolCap {
		specs = specs[:poolCap]
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	// 保留内置作为兜底：合并去重，下发在前。
	seen := map[string]bool{}
	merged := make([]*strategy.Spec, 0, len(specs)+8)
	for _, s := range specs {
		if s == nil || seen[s.ID()] {
			continue
		}
		seen[s.ID()] = true
		merged = append(merged, s)
	}
	for _, s := range strategy.BuiltinFor(proto) {
		if seen[s.ID()] {
			continue
		}
		seen[s.ID()] = true
		merged = append(merged, s)
	}
	e.pool[proto] = merged
	// **必须同步候选方法全集**：否则新策略进了池子却永远进不了 Plan——
	// Worker 演化出来的策略就等于空转。
	if e.mem != nil {
		e.mem.SetKnown(proto, e.knownMethodsLocked(proto))
	}
}

// Pool 返回当前候选池快照。
func (e *Engine) Pool(proto string) []*strategy.Spec {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*strategy.Spec(nil), e.pool[proto]...)
}

// Claim 尝试取得该主机的探测权。true = 本次调用者是唯一探测者。
func (e *Engine) Claim(host string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, busy := e.inflight[host]; busy {
		return false
	}
	e.inflight[host] = struct{}{}
	return true
}

// Release 释放探测权。
func (e *Engine) Release(host string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.inflight, host)
}

// RecordAttempt 记一次单策略尝试并排队上报（不改记忆）。
//
// proto 是**必填**的：协调端按 (host, proto, method) 建 method_stat，空 proto 会被
// 整条拒收（proto 不给默认值——分不清"客户端没想清楚"和"故意说 tls"）。
//
// kind 是失败类别（成功传 failkind.None），随回报一起上网——协调端据此能看到
// "这条策略为什么没成"，而不只是"没成"。
func (e *Engine) RecordAttempt(host, proto string, spec *strategy.Spec, ok bool, rtt time.Duration, unsup bool, kind failkind.Kind) {
	if spec == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reportLocked(coord.Item{
		Host:   host,
		Method: spec.ID(),
		Kind:   kind.Key(),
		Proto:  proto,
		OK:     b2i(ok),
		RTTms:  int(rtt.Milliseconds()),
		Unsup:  b2i(unsup),
		TS:     e.now().Unix(),
	})
}

// reportLocked 入队一条回报并压上限。调用方已持锁。
func (e *Engine) reportLocked(it coord.Item) {
	if e.client == nil {
		return
	}
	e.reports = append(e.reports, it)
	if len(e.reports) > reportCap {
		e.reports = e.reports[len(e.reports)-reportCap:]
	}
}

// Record 记一次方法在某 host 上的结果。**kind == failkind.None 即成功**，其余是
// 失败类别；不单独传 ok bool——两者同时传会出现 `ok=true` 配 `kind=Reset` 这种
// 自相矛盾的调用，而派生值不可能矛盾。
//
// method 是伪方法 ID 或策略 ID；spec 非 nil 时额外用于回报（策略）。
//
// isCF 只在**失败且类别可用**时才参与分组（那正是"第一次 direct 尝试的失败类别"
// 的落点）：成功不带分组信号——从"通了"学不到"这属于哪一类"。
func (e *Engine) Record(host, proto, method string, spec *strategy.Spec, kind failkind.Kind, isCF bool) {
	ok := kind == failkind.None
	// 回报点只有两处：策略走 RecordAttempt（那里才有 rtt/unsup），伪方法（spec==nil）
	// 走这里。两边都记会把同一次尝试报两遍。
	if spec == nil && method != "" {
		e.mu.Lock()
		e.reportLocked(coord.Item{
			Host: host, Method: method, Kind: kind.Key(),
			Proto: proto,
			OK:    b2i(ok), TS: e.now().Unix(),
		})
		e.mu.Unlock()
	}
	if method == "" {
		return
	}
	if !ok && kind.IsEvidence() {
		e.mem.ObserveWithGroup(host, GroupKey(isCF, kind), method, kind)
		return
	}
	e.mem.Observe(host, method, kind)
}

// RecordAttempt 记一次单策略尝试（用于回报与统计，不改记忆）。
// Drain 取走并清空待上报的效果。
func (e *Engine) Drain() []coord.Item {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.reports) == 0 {
		return nil
	}
	out := e.reports
	e.reports = nil
	return out
}

// Pending 返回待上报条数。
func (e *Engine) Pending() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.reports)
}

// Sweep 清扫过期记忆（委托给 Memory，它会把过期条目折叠进 group）。
func (e *Engine) Sweep() int { return e.mem.Sweep() }

// Stats 返回记忆规模：tier1 host 数 / tier2 group 数。
func (e *Engine) Stats() (hosts, groups int) { return e.mem.Stats() }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
