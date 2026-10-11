package proxyip

import (
	"context"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// 这一文件提供**确定性**的注入式拨号测试：不碰真实网络、不碰真实证书，
// 每条候选的行为由脚本写死（成功/失败/挂起/取消），从而钉住竞速的每一条约束。
//
// 与 race_test.go 的分工：那边用本地 TLS/TCP 服务端验证真实握手路径，
// 这边用注入函数验证调度约束（上限、错开、预算、记账、清理）。

// fakeConn 是零依赖的 net.Conn 替身：所有操作都立即成功/返回零值。
type fakeConn struct {
	mu     sync.Mutex
	closed bool
	closeN int
}

func newFakeConn() *fakeConn { return &fakeConn{} }

func (c *fakeConn) Read([]byte) (int, error)         { return 0, nil }
func (c *fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *fakeConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.closeN++
	return nil
}
func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// behavior 描述一条候选中继在被拨时的表现。
type behavior struct {
	delay   time.Duration // 起跑后多久返回
	conn    net.Conn      // 成功时返回的连接
	err     error         // 失败时返回的错误（conn 为 nil 时）
	hangCtx bool          // true = 一直挂起直到 ctx 结束
	// ignoreCtx 让 delay/hang 期间的等待**不理会** ctx 取消。
	// 用来模拟"不响应取消的拨号"——正是迟到的成功连接必须被 drain 关掉的那条路径。
	ignoreCtx bool
	onDial    func(ctx context.Context)
}

// harness 注入拨号实现并记录每次拨号的起跑，供断言。
// 记录发生在拨号**开始时**——否则"挂起/被取消"的候选永远不会出现在统计里。
type harness struct {
	t *testing.T

	mu     sync.Mutex
	calls  []callRec
	conns  []*fakeConn // 由 harness 创建的连接（用于清理断言）
	relays map[string]behavior
}

type callRec struct {
	relay string
	conn  net.Conn
	err   error
	done  bool // 是否已返回
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return &harness{t: t, relays: map[string]behavior{}}
}

// relay 注册一条候选的行为，返回它的地址。
// 所有注册必须在并发拨号开始前完成（h.pool 之后不要注册）。
func (h *harness) relay(addr string, b behavior) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, dup := h.relays[addr]; dup {
		h.t.Fatalf("中继地址重复注册: %s", addr)
	}
	h.relays[addr] = b
	return addr
}

// ok 注册"一定握手成功"的中继。可指定 delay。
func (h *harness) ok(addr string, delay time.Duration) string {
	return h.relay(addr, behavior{delay: delay, conn: newFakeConn()})
}

// lateOK 注册"会迟到地返回一个成功连接"的中继：等待期间不响应取消，
// 用来验证迟到的胜者连接会被关闭而不是泄漏。
func (h *harness) lateOK(addr string, delay time.Duration) string {
	return h.relay(addr, behavior{delay: delay, conn: newFakeConn(), ignoreCtx: true})
}

// fail 注册"一定失败"的中继。
func (h *harness) fail(addr string) string {
	return h.relay(addr, behavior{err: errFakeRefused})
}

// hang 注册"挂起到 ctx 结束"的中继。
func (h *harness) hang(addr string) string {
	return h.relay(addr, behavior{hangCtx: true})
}

var errFakeRefused = &net.OpError{Op: "dial", Err: errFake("connection refused")}

type errFake string

func (e errFake) Error() string { return string(e) }

// pool 构造一个装配了注入拨号的池。
func (h *harness) pool(relays []string) *Pool {
	p := NewPool(relays, nil)
	p.SetDial(h.dial)
	return p
}

func (h *harness) dial(ctx context.Context, relay, host string, port int, timeout time.Duration) (net.Conn, error) {
	h.mu.Lock()
	b, ok := h.relays[relay]
	if !ok {
		h.mu.Unlock()
		return nil, errFake("unregistered relay " + relay)
	}
	h.calls = append(h.calls, callRec{relay: relay})
	idx := len(h.calls) - 1
	h.mu.Unlock()

	if b.onDial != nil {
		b.onDial(ctx)
	}
	if b.hangCtx {
		if b.ignoreCtx {
			time.Sleep(time.Hour) // 永不返回：只可能是 goroutine 泄漏，测试会卡住
		}
		<-ctx.Done()
		h.finish(idx, nil, ctx.Err())
		return nil, ctx.Err()
	}
	if b.delay > 0 {
		if b.ignoreCtx {
			time.Sleep(b.delay)
		} else {
			select {
			case <-time.After(b.delay):
			case <-ctx.Done():
				h.finish(idx, nil, ctx.Err())
				return nil, ctx.Err()
			}
		}
	}
	h.finish(idx, b.conn, b.err)
	return b.conn, b.err
}

func (h *harness) finish(idx int, conn net.Conn, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if idx < len(h.calls) {
		h.calls[idx].conn = conn
		h.calls[idx].err = err
		h.calls[idx].done = true
	}
	if fc, ok := conn.(*fakeConn); ok {
		h.conns = append(h.conns, fc)
	}
}

// started 返回已起跑的拨号次数（不论是否返回）。
func (h *harness) started(addr string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, c := range h.calls {
		if c.relay == addr {
			n++
		}
	}
	return n
}

// dialed 返回已起跑的中继地址（按起跑顺序）。
func (h *harness) dialed() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.calls))
	for _, c := range h.calls {
		out = append(out, c.relay)
	}
	return out
}

// succeeded 返回某条中继最终返回成功连接的次数。
func (h *harness) succeeded(addr string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, c := range h.calls {
		if c.relay == addr && c.done && c.err == nil && c.conn != nil {
			n++
		}
	}
	return n
}

// returnedCount 返回已返回的拨号次数（起跑了且已结束）。
func (h *harness) returnedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, c := range h.calls {
		if c.done {
			n++
		}
	}
	return n
}

// closedConns 统计已关闭的连接数。
func (h *harness) closedConns() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, c := range h.conns {
		if c.isClosed() {
			n++
		}
	}
	return n
}

// totalConns 统计 harness 交出过的连接总数（成功路径）。
func (h *harness) totalConns() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}

// runtimeNumGoroutine 返回当前 goroutine 数（泄漏检测用）。
func runtimeNumGoroutine() int { return runtime.NumGoroutine() }
