// 记忆层（B 阶段）。
//
// 目标：把"每主机一个赢家 + blocked 标志"换成"有序方法列表 + 计数器 + 两层记忆"。
// 归纳用分层经验贝叶斯，**不动 wire、不动 D1**（本机先行）。
//
// 为什么要有第二层（group）：单个主机上观测太少时无从判断，但"同类站点"往往表现
// 一致。group 键只用**知道答案之前就能算出来**的特征（见 groupKey），否则循环论证。
package engine

import (
	"sort"
	"strings"
	"sync"
	"time"

	"satel/internal/coord"
	"satel/internal/failkind"
)

// 记忆参数。
const (
	hostLRU         = 512 // tier1 工作集上限
	ttlSuccess      = 6 * time.Hour
	ttlFailure      = 30 * time.Minute
	aMax            = 8   // 分层贝叶斯的伪计数上限
	hintWeight      = 1.0 // tier3 后缀经验的伪计数：小到压不过任何本机观测
	hintWeightShare = 0.5 // hint 在 prior 里占的份额；其余留给"中性先验"
	groupTTL        = 24 * time.Hour
	inheritedTTL    = 20 * time.Minute // 继承来的条目存活更短：一次反例即降级
)

// stat 是单个方法在某层（或某 host）上的计数。
type stat struct {
	ok, fail  int
	inherited bool // 由 group 继承而来，绝不回灌组证据
}

func (s *stat) n() int        { return s.ok + s.fail }
func (s *stat) touched() bool { return s.n() > 0 }

// row 是 Plan 内部的一次排序项。
type row struct {
	id   string
	rate float64
}

// hostStat 是 tier1：每个 host 的工作集。
type hostStat struct {
	methods map[string]*stat
	group   string
	last    time.Time // LRU 依据
	until   time.Time // 整条记忆的失效时间
}

// groupStat 是 tier2 归档：只接受**观测**证据。
type groupStat struct {
	methods map[string]*stat
	hosts   int // 贡献过多少 host，用于收缩
	last    time.Time
}

// groupKey 是"知道答案之前就能算出来"的特征：`isCF:firstDirectSignal`。
//
// isCF 来自解析结果；firstDirectSignal 是第一次 direct 尝试的失败类别——那一枪
// 必然要打（成本一个探测窗口），产出的是观测不是预测。所以第一个 host 就能归类，
// 不需要先访问过兄弟域名。
//
// 于是 GFW 黑名单**不需要任何导入**：访问过几个 CF 承载的被墙站后，group=1:reset
// 里 direct 的后验自然掉下去，新来的同组 host 直接继承"别先试 direct"。
func groupKey(isCF bool, firstKind failkind.Kind) string {
	b := "0"
	if isCF {
		b = "1"
	}
	// 用 failkind 的**机器键**而不是展示串：分组会进 map，改一次中文文案不该
	// 悄悄改掉分组身份。
	return b + ":" + firstKind.Key()
}

// hint 是协调端从全体客户端回报里挖出来的**后缀经验**：例如"*.wikipedia.org 上
// @tunnel 比 direct 靠谱"。map 的 key 是 "suffix|method"——同一条后缀对不同方法
// 各有结论（"这个后缀上 direct 总被复位、@tunnel 稳"），压成一个条目就只能存
// 一个方法，另一个方法被静默丢掉。它是 tier3，比 group 更弱：
//
//   - 不是本机观测，只当**先验**用，绝不回灌任何一层的证据；
//   - 短 TTL（协调端给的 expires，服务端侧 20 分钟级）；
//   - 一次反例即失效——本机观测永远盖得过它。
//
// 为什么值得要：组内只有 1–2 个 host 时，分层收缩的 a 很小、组先验很弱，而全体
// 客户端的数据能把"这类后缀该怎么走"先撑起来，省掉本机重复探测。
type hint struct {
	ok, fail int
	hosts    int
	until    time.Time
}

// Memory 是两层记忆。并发安全。全部在内存，进程退出即消失（零配置）。
//
// 三层：host(tier1) → group(tier2) → hint(tier3)。前两层是本机观测，第三层是
// 协调端汇总的全体客户端经验，只当先验。
type Memory struct {
	mu     sync.Mutex
	hosts  map[string]*hostStat  // tier1
	order  []string              // tier1 LRU 顺序，最新在末尾
	groups map[string]*groupStat // tier2
	hints  map[string]*hint      // tier3：key = suffix，见 hint

	// 已知方法全集，**按 proto 分开**。合成一个全局列表会出致命错误：
	// SetBundle 是逐 proto 调用的，最后一个 proto 会把另一个 proto 的候选整个覆盖，
	// 结果 TLS 主机的计划里列着 HTTP 策略，SpecByID 一个都找不到、全部静默跳过。
	known map[string][]string

	now func() time.Time
}

// NewMemory 构造记忆层。用 SetKnown 逐 proto 注入可选方法。
func NewMemory() *Memory {
	return &Memory{
		hosts:  map[string]*hostStat{},
		groups: map[string]*groupStat{},
		hints:  map[string]*hint{},
		known:  map[string][]string{},
		now:    time.Now,
	}
}

// SetNow 注入时钟（测试用）。
func (m *Memory) SetNow(f func() time.Time) {
	m.mu.Lock()
	m.now = f
	m.mu.Unlock()
}

// Observe 只记 **host 层**证据，不进分组统计。分组只由 ObserveWithGroup 显式给定。
//
// 这里曾经按 kind 粗推导 group（把"连接建没建起来"近似成"是否 CF 承载"）。那既是
// **错的**启发式——非 CF 的站一样会被 RST、CF 的边缘 IP 一样可能被黑洞——又是
// **死代码**：Record 只在成功或类别不可用时才走到这里，与推导所需的条件互斥，
// group 恒为空。删掉比留着安全：留着会让下一个调用者静默按错的分组走。
func (m *Memory) Observe(host, method string, kind failkind.Kind) {
	m.ObserveWithGroup(host, "", method, kind)
}

// ObserveWithGroup 记一次观测，并（在 group 非空时）把它归入指定分组。
//
// **成功由 kind == failkind.None 表达，不再单独传 ok bool**：两者同时传会出现
// "ok=true 配 kind=Reset" 这种自相矛盾的调用，而派生值不可能矛盾。
//
// group 传空表示"还不知道"（成功、或第一次尝试尚未拿到失败类别）。记忆层不会用
// 空 group 建垃圾分组；只有真正带方向的观测才把 host 钉在某个 (isCF, 信号) 组上
// ——这就是规格里"第一次 direct 尝试的失败类别"的落点。
func (m *Memory) ObserveWithGroup(host, group, method string, kind failkind.Kind) {
	ok := kind == failkind.None
	// 成功的观测永远有效（是最强证据）；失败才看是否值得计入（Canceled 不算）。
	if !ok && !kind.IsEvidence() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	hs := m.host(host, now)
	st := hs.methods[method]
	if st == nil {
		st = &stat{}
		hs.methods[method] = st
	}
	st.inherited = false
	if ok {
		st.ok++
	} else {
		st.fail++
	}
	if hs.group == "" && group != "" {
		hs.group = group
	}
	hs.until = now.Add(ttlSuccess)
	if hs.group == "" {
		return // 没有组就不建组统计——否则会攒出一个键为空的垃圾桶
	}
	g := m.group(hs.group, now)
	gs := g.methods[method]
	if gs == nil {
		gs = &stat{}
		g.methods[method] = gs
	}
	if ok {
		gs.ok++
	} else {
		gs.fail++
	}
}

// SetKnown 更新"可选方法全集"。装包后必须调用，否则新策略进不了候选——
// 这是 Worker 演化能影响路由的前提。
func (m *Memory) SetKnown(proto string, methods []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]bool{}
	out := make([]string, 0, len(methods))
	for _, id := range methods {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if m.known == nil {
		m.known = map[string][]string{}
	}
	m.known[proto] = out
}

// host 取（或建）tier1 条目，并顺带做 LRU 触碰。
func (m *Memory) host(host string, now time.Time) *hostStat {
	hs := m.hosts[host]
	if hs == nil {
		hs = &hostStat{methods: map[string]*stat{}}
		m.hosts[host] = hs
		m.order = append(m.order, host)
		// 挤出时**折叠**进 group，不丢弃
		for len(m.order) > hostLRU {
			oldest := m.order[0]
			m.order = m.order[1:]
			if oh := m.hosts[oldest]; oh != nil {
				m.fold(oh, now)
			}
			delete(m.hosts, oldest)
		}
	}
	hs.last = now
	// 刷新 LRU 位置
	for i, x := range m.order {
		if x == host {
			m.order = append(m.order[:i], m.order[i+1:]...)
			m.order = append(m.order, host)
			break
		}
	}
	return hs
}

func (m *Memory) group(g string, now time.Time) *groupStat {
	gs := m.groups[g]
	if gs == nil {
		gs = &groupStat{methods: map[string]*stat{}}
		m.groups[g] = gs
	}
	gs.last = now
	return gs
}

// fold 把一个 host 的观测折进它的 group（LRU 挤出/周期折叠共用）。
// 只折 observed（inherited=false）的计数。
func (m *Memory) fold(hs *hostStat, now time.Time) {
	if hs.group == "" {
		return
	}
	g := m.group(hs.group, now)
	for method, st := range hs.methods {
		if st.inherited || !st.touched() {
			continue
		}
		gs := g.methods[method]
		if gs == nil {
			gs = &stat{}
			g.methods[method] = gs
		}
		gs.ok += st.ok
		gs.fail += st.fail
	}
	g.hosts++
}

// Sweep 过期记忆与折叠，返回清掉的 host 数。
func (m *Memory) Sweep() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	n := 0
	kept := m.order[:0]
	for _, host := range m.order {
		hs := m.hosts[host]
		if hs == nil {
			continue
		}
		if now.After(hs.until) {
			m.fold(hs, now)
			delete(m.hosts, host)
			n++
			continue
		}
		kept = append(kept, host)
	}
	m.order = kept
	// group 过期清理
	for g, gs := range m.groups {
		if now.Sub(gs.last) > groupTTL {
			delete(m.groups, g)
		}
	}
	return n
}

// rate_h 的分层经验贝叶斯后验：
//
//	prior_rate(m) = (ok_g(m) + 1) / (ok_g(m) + fail_g(m) + 2)
//	a             = clamp(ok_g(m) + fail_g(m), 1, A_MAX)
//	rate_h(m)     = (ok_h(m) + a·prior_rate(m)) / (n_h(m) + a)
//
// 分层收缩：本 host 观测多就以本 host 为主（a 相对 n_h 小），观测少就靠 group 的
// 先验（a 大）。继承来的条目只用于排序，不进组证据。
func (m *Memory) rate(host, method string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	hs := m.hosts[host]
	return m.rateLocked(host, method, hs)
}

// Plan 返回按 rate_h 降序、且与 cost 破平的方法列表。继承的条目先验弱、TTL 短，
// 一次反例即降级（Observe 把 inherited 清掉并重记）。
func (m *Memory) Plan(host, proto string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	hs := m.hosts[host]

	// 候选 = 已知伪方法 ∪ 该 host 记忆里出现过的策略方法 ∪ 已知策略
	cand := map[string]bool{}
	for _, id := range m.known[proto] {
		cand[id] = true
	}
	if hs != nil {
		for id := range hs.methods {
			cand[id] = true
		}
	}

	rows := make([]row, 0, len(cand))
	for id := range cand {
		r := m.rateLocked(host, id, hs)
		rows = append(rows, row{id, r})
	}
	// 降序；同分按 cost 升序，再按 id 字典序（确定性）
	sortRows(rows)
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.id
	}
	return out
}

// rateLocked 是 rate 的无锁版本（调用方已持锁）。
func (m *Memory) rateLocked(host, method string, hs *hostStat) float64 {
	var h0, h1 int
	if hs != nil {
		if st := hs.methods[method]; st != nil {
			h0, h1 = st.ok, st.fail
		}
	}
	nh := h0 + h1
	var g0, g1 int
	if hs != nil && hs.group != "" {
		if gs := m.groups[hs.group]; gs != nil {
			if st := gs.methods[method]; st != nil {
				g0, g1 = st.ok, st.fail
			}
		}
	}
	prior := float64(g0+1) / float64(g0+g1+2)
	a := float64(g0 + g1)
	if a > aMax {
		a = aMax
	}
	// 下限 1：组里对某方法毫无证据时，先验只值一个伪计数。少了它，a=0 会让
	// 未观测方法算出 (0 + 0·prior)/(n_h + 0) = 0——比"试过且失败"（有组先验，>0）
	// 还低，于是阶梯永远重放已知失败的方法，探索饿死（实测 discord 第 2 轮即如此）。
	// 有下限后未观测方法 ≈ prior ≈ 0.5，即"不确定"，排在已知失败之前。
	if a < 1 {
		a = 1
	}
	// tier3 后缀经验是**弱先验**：它来自全体客户端的统计，不是本机观测，所以它的
	// 伪计数必须小到"任何本机观测都能压过它"——否则一次错误的挖掘结论会长期压住
	// 本机的真实经验。
	//
	// 关键在分母：hint 只能替代 prior 与伪计数 a，不能让它免于分母的稀释。把它直接
	// 当 a（哪怕很小）仍会让"零观测方法"的 rate 逼近 prior 的全权值，而本机只观测
	// 一次时 rate =(1 + a·prior)/(1 + a) 天然低于它——那样"一次反例即降级"就失效了。
	// 正确做法是把 hint 折进 prior 与 a 一起按比例缩放：a 取 hintWeight，但 prior
	// 只用它一部分权重（hintWeightShare），让本机的一次成功有压倒性发言权。
	if g0+g1 == 0 {
		if h := m.hintFor(host, method); h != nil {
			hintRate := float64(h.ok+1) / float64(h.ok+h.fail+2)
			// prior = 组先验(0.5) 与 hint 的加权平均，hint 占 share 权重
			prior = (1-hintWeightShare)*0.5 + hintWeightShare*hintRate
			a = hintWeight
		}
	}
	return (float64(h0) + a*prior) / (float64(nh) + a)
}

// hintFor 找 host 命中的、未过期的后缀经验，且**该方法在其中确有证据**：
// 取最长匹配的后缀。
// 例：en.wikipedia.org 命中 "wikipedia.org" 而不是裸 "org"。
//
// 必须按 method 过滤：一条后缀经验只描述某一个方法的结论（"这个后缀上 @tunnel
// 靠谱"），它对别的方法不发表意见。不过滤的话，"有 hint"会让该后缀下**所有**
// 未观测方法一起拿到高先验，等于用一个结论污染整张候选表。
func (m *Memory) hintFor(host, method string) *hint {
	if len(m.hints) == 0 {
		return nil
	}
	now := m.now()
	best := ""
	for k := range m.hints {
		// key = suffix + "|" + method：拆出后缀部分再比。
		i := strings.IndexByte(k, '|')
		if i < 0 || k[i+1:] != method {
			continue
		}
		suffix := k[:i]
		if host != suffix && !strings.HasSuffix(host, "."+suffix) {
			continue
		}
		if !now.Before(m.hints[k].until) {
			continue // 过期的不算
		}
		if len(suffix) > len(best) {
			best = suffix
		}
	}
	if best == "" {
		return nil
	}
	h := m.hints[best+"|"+method]
	if h.ok+h.fail == 0 {
		return nil
	}
	return h
}

// hintKey 拼 tier3 的 map key。方法 ID 不会是 "|"（伪方法以 @ 开头、策略是 hex），
// 所以这个分隔符不会撞车。
func hintKey(suffix, method string) string { return suffix + "|" + method }

// SetHints 装入协调端下发的后缀经验。整份替换（协调端每批都给全量），
// expires 由服务端给出、客户端照抄，不做二次延长。
//
// **绝不写回 tier1/tier2**：它不是本机观测，只是排序先验。写回去会让它获得
// 和本机观测同等的证据力，一次错误的挖掘结论就再难被证伪。
func (m *Memory) SetHints(rs []coord.Hint) {
	if len(rs) == 0 {
		return
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range rs {
		if r.Suffix == "" || r.Method == "" {
			continue
		}
		until := time.Unix(r.Expires, 0)
		if !now.Before(until) {
			delete(m.hints, r.Suffix)
			continue
		}
		key := hintKey(r.Suffix, r.Method)
		cur := m.hints[key]
		if cur == nil {
			cur = &hint{}
			m.hints[key] = cur
		}
		cur.ok, cur.fail, cur.hosts, cur.until = r.OK, r.Fail, r.Hosts, until
	}
}

// Stats 各类记忆条数（诊断用）：hosts / groups / reported。
func (m *Memory) Stats() (hosts, groups int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.hosts), len(m.groups)
}

// MarkGroupForTest 供测试构造分层场景：直接钉住某 host 所属的组。
func (m *Memory) MarkGroupForTest(host, group string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	hs := m.host(host, m.now())
	hs.group = group
}

// sortRows 按 rate 降序、cost 升序、id 字典序稳定排序。
func sortRows(rows []row) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].rate != rows[j].rate {
			return rows[i].rate > rows[j].rate
		}
		ci, cj := methodCost(rows[i].id), methodCost(rows[j].id)
		if ci != cj {
			return ci < cj
		}
		return rows[i].id < rows[j].id
	})
}

// TopMethodFor 返回该 host 后验最高的可记忆方法（仅供诊断/测试）。
func (e *Engine) TopMethodFor(host string) string {
	p := e.mem.Plan(host, "")
	if len(p) == 0 {
		return ""
	}
	return p[0]
}
