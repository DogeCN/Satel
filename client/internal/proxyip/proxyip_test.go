package proxyip

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSplitRelay(t *testing.T) {
	host, port, err := splitRelay("relay.example.com")
	if err != nil || host != "relay.example.com" || port != 443 {
		t.Fatalf("无端口时应默认 443: %s %d %v", host, port, err)
	}
	host, port, err = splitRelay("relay.example.com:8443")
	if err != nil || host != "relay.example.com" || port != 8443 {
		t.Fatalf("带端口: %s %d %v", host, port, err)
	}
	if _, _, err := splitRelay("  "); err == nil {
		t.Fatal("空白应报错")
	}
	if _, _, err := splitRelay("h:notaport"); err == nil {
		t.Fatal("非法端口应报错")
	}
	if _, _, err := splitRelay("h:99999"); err == nil {
		t.Fatal("越界端口应报错")
	}
}

func TestNewPoolDropsEmpty(t *testing.T) {
	p := NewPool([]string{"a:443", "  ", "b:443"}, nil)
	if got := p.Order(); len(got) != 2 || got[0] != "a:443" || got[1] != "b:443" {
		t.Fatalf("空条目未被丢弃: %v", got)
	}
}

func TestDialWithNoRelays(t *testing.T) {
	if _, err := NewPool(nil, nil).Dial(context.Background(), "example.com", 443, time.Second); err == nil {
		t.Fatal("无候选应返回错误")
	}
}

// TestSuccessMovesToFront 是这条需求的核心：成功的中继置顶。
func TestSuccessMovesToFront(t *testing.T) {
	p := NewPool([]string{"a:1", "b:1", "c:1"}, nil)
	// 直接调内部记账接口，避免依赖真实网络
	p.noteOK("c:1")
	if got := p.Order(); got[0] != "c:1" {
		t.Fatalf("成功的中继未置顶: %v", got)
	}
	// 再来一次成功，顺序应稳定
	p.noteOK("b:1")
	if got := p.Order(); got[0] != "b:1" || got[1] != "c:1" {
		t.Fatalf("顺序不对: %v", got)
	}
}

// TestFailureMovesToBack 失败的中继置底。
func TestFailureMovesToBack(t *testing.T) {
	p := NewPool([]string{"a:1", "b:1", "c:1"}, nil)
	p.noteFail("a:1")
	if got := p.Order(); got[len(got)-1] != "a:1" {
		t.Fatalf("失败的中继未置底: %v", got)
	}
}

// TestCooldownAfterMaxFails 连续失败到 maxFails 后进入冷却：冷却期间**不参与调度"
// （不再只是排序靠后——重复试一条刚被证实不可用的中继只会重复付费）。
// 冷却过期后它重新可被尝试，但位置仍在最后——因为"失败置底"是独立的一维，
// 不会因冷却结束而撤销。要上升只能靠成功（noteOK）。
func TestCooldownAfterMaxFails(t *testing.T) {
	now := time.Unix(1000, 0)
	p := NewPool([]string{"a:1", "b:1"}, nil)
	p.SetNow(func() time.Time { return now })

	for i := 0; i < maxFails; i++ {
		p.noteFail("a:1")
	}
	var target *entry
	for _, e := range p.entries {
		if e.addr == "a:1" {
			target = e
		}
	}
	if target == nil {
		t.Fatal("找不到 a:1")
	}
	if !p.skip(target) {
		t.Fatal("达到 maxFails 后应进入冷却")
	}
	if ready := p.ready(); len(ready) != 1 || ready[0].addr != "b:1" {
		t.Fatalf("冷却中的中继不应参与调度: %v", ready)
	}

	// 冷却过期：重新可被尝试，但仍在最后。
	now = now.Add(cooldown + time.Second)
	if p.skip(target) {
		t.Fatal("冷却过期后不应再被跳过")
	}
	ready := p.ready()
	if len(ready) != 2 || ready[1].addr != "a:1" {
		t.Fatalf("冷却过期后应重新可尝试但仍排最后: %v", ready)
	}
	// 成功一次就应立刻置顶
	p.noteOK("a:1")
	if got := p.Order()[0]; got != "a:1" {
		t.Fatalf("成功后应置顶: %v", got)
	}
}

func TestStats(t *testing.T) {
	p := NewPool([]string{"a:1", "b:1"}, nil)
	p.noteOK("a:1")
	p.noteFail("b:1")
	st := p.Stats()
	if st["a:1"][0] != 1 || st["a:1"][1] != 0 {
		t.Fatalf("a 的统计不对: %v", st["a:1"])
	}
	if st["b:1"][1] != 1 {
		t.Fatalf("b 的统计不对: %v", st["b:1"])
	}
}

// TestDialReportsAllFailures 验证失败信息带每条候选的原因——只报最后一条会掩盖
// 真正的问题（实测里就因此把"SNI 填错了"误读成"中继全挂"）。
func TestDialReportsAllFailures(t *testing.T) {
	p := NewPool([]string{"127.0.0.1:1", "127.0.0.1:2"}, nil)
	_, err := p.Dial(context.Background(), "example.com", 443, 500*time.Millisecond)
	if err == nil {
		t.Fatal("应失败")
	}
	msg := err.Error()
	for _, want := range []string{"127.0.0.1:1", "127.0.0.1:2"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("错误信息未包含候选 %s: %s", want, msg)
		}
	}
}

func TestDefaultRelaysValid(t *testing.T) {
	if len(DefaultRelays) == 0 {
		t.Fatal("默认中继表不应为空")
	}
	for _, r := range DefaultRelays {
		if _, _, err := splitRelay(r); err != nil {
			t.Fatalf("默认中继 %q 格式非法: %v", r, err)
		}
	}
}

// TestPoolConcurrent 并发安全：多个 goroutine 同时拨号与记账不应 panic 或死锁。
func TestPoolConcurrent(t *testing.T) {
	p := NewPool([]string{"a:1", "b:1", "c:1"}, nil)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			if i%2 == 0 {
				p.noteOK("c:1")
			} else {
				p.noteFail("a:1")
			}
			_, _ = p.Dial(context.Background(), "example.com", 443, 100*time.Millisecond)
			_ = p.Order()
			_ = p.Stats()
		}(i)
	}
	for i := 0; i < 8; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("并发测试中卡住")
		}
	}
}

// 保证 dialOne 的格式错误路径被覆盖（不会真的拨号）。
func TestDialOneBadRelay(t *testing.T) {
	if _, err := dialOne(context.Background(), nil, "h:99999", "x", 443, time.Second, nil); err == nil {
		t.Fatal("非法中继地址应报错")
	}
}

// TestProvenHeadStillStaggers 钉住关键契约：**已证明可用的队首不是独占快路径**。
// 它仍然只领先 250ms——这样即使它突然挂起，后面的候选已经在跑，整路请求不必
// 干等满一个超时。"快路径"指的是它几乎总是先赢，而不是别人不起跑。
func TestProvenHeadStillStaggers(t *testing.T) {
	h := newHarness(t)
	winner := h.ok("winner", 0)
	stall := h.hang("stall")
	p := h.pool([]string{stall, winner})
	p.noteOK(stall) // 挂起的那条成为"已证明可用"的队首

	conn, err := p.Dial(context.Background(), "example.com", 443, 1500*time.Millisecond)
	if err != nil {
		t.Fatalf("后位候选应能胜出: %v", err)
	}
	conn.Close()
	if got := p.Order()[0]; got != winner {
		t.Fatalf("胜者应置顶: %v", got)
	}
	if st := p.Stats()[stall]; st[1] != 0 {
		t.Fatalf("被取消的挂起候选不该记失败: %v", st)
	}
}

var _ net.Conn
