package resolver

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestIPLiteralPassThrough(t *testing.T) {
	d := NewDoH("https://example.invalid/dns-query")
	// IP 字面量不应触发任何网络请求
	ips, err := d.LookupHost(context.Background(), "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "192.0.2.7" {
		t.Fatalf("ips = %v", ips)
	}
}

func TestDefaultEndpoints(t *testing.T) {
	d := NewDoH("")
	if len(d.Endpoints) == 0 {
		t.Fatal("空配置应回落到内置默认端点")
	}
	if !strings.Contains(d.Endpoints[0], "cloudflare-gateway.com") {
		t.Fatalf("主端点应是干净但慢的 Cloudflare Gateway，实际 %q", d.Endpoints[0])
	}
	if d.Primary() != d.Endpoints[0] {
		t.Fatalf("Primary() = %q, want %q", d.Primary(), d.Endpoints[0])
	}
	// 慢端点在前、快但不可靠的在后：正确性优先于延迟
	if !strings.Contains(d.Endpoints[1], "doh.pub") {
		t.Fatalf("备端点应是 doh.pub，实际 %q", d.Endpoints[1])
	}
}

func TestSplitEndpoints(t *testing.T) {
	got := splitEndpoints(" a , b ,, c ")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("splitEndpoints = %#v", got)
	}
	if len(splitEndpoints("  ")) != 0 {
		t.Fatal("全空白应得到空切片")
	}
	d := NewDoH("https://x.invalid/a,https://y.invalid/b")
	if len(d.Endpoints) != 2 || d.Primary() != "https://x.invalid/a" {
		t.Fatalf("Endpoints = %v", d.Endpoints)
	}
}

func TestCacheHitAvoidsSecondLookup(t *testing.T) {
	d := NewDoH("https://example.invalid/dns-query")
	d.store("x.example", []string{"203.0.113.9"})
	ips, ok := d.cached("x.example")
	if !ok || len(ips) != 1 || ips[0] != "203.0.113.9" {
		t.Fatalf("cached = %v, ok=%v", ips, ok)
	}
}

func TestCacheExpiry(t *testing.T) {
	d := NewDoH("https://example.invalid/dns-query")
	d.mu.Lock()
	d.cache["y.example"] = entry{ips: []string{"1.2.3.4"}, until: time.Now().Add(-time.Second)}
	d.mu.Unlock()
	if _, ok := d.cached("y.example"); ok {
		t.Fatal("过期缓存不应命中")
	}
}

func TestLookupFallsThroughToSystem(t *testing.T) {
	// 主备 DoH 都不可达时应退回系统解析，而不是整体失败
	d := NewDoH("https://127.0.0.1:1/a,https://127.0.0.1:1/b")
	d.Timeout = 200 * time.Millisecond
	ips, err := d.LookupHost(context.Background(), "localhost")
	if err != nil {
		t.Skipf("本机无系统解析结果: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("退回系统解析后仍无结果")
	}
}

func TestDialOneUsesFirstAddress(t *testing.T) {
	d := NewDoH("https://example.invalid/dns-query")
	d.store("127.0.0.1", []string{"127.0.0.1"})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	c, err := DialOne(context.Background(), d, "127.0.0.1", port, 2*time.Second)
	if err != nil {
		t.Fatalf("DialOne: %v", err)
	}
	c.Close()
}

func TestDialWithNilResolver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	c, err := Dial(context.Background(), nil, "127.0.0.1", port, 2*time.Second)
	if err != nil {
		t.Fatalf("nil 解析器应退回 ctx 感知拨号: %v", err)
	}
	c.Close()
}

// blackholeIP 是 TEST-NET-1 的保留地址（RFC 5737）：不可路由，SYN 无人应答，
// 连接会一直停在 SYN-SENT。用来验证 ctx 取消/timeout 能中断**进行中**的连接
// ——本地 listener 做不到，因为它会立即 accept、连接当场成功返回。
const blackholeIP = "192.0.2.1"

// TestDialCancellationInterruptsTCP ctx 取消必须**立刻**中断正在进行的 TCP 连接，
// 而不是干等 timeout。这条钉住 resolver.Dial 不再使用 net.DialTimeout 的改动。
//
// 用 TEST-NET-1 的黑洞地址（192.0.2.1:80）：SYN 无响应，连接始终停在 SYN-SENT，
// 正是"取消能中断"的可测场景。本地 listener 做不到——它会立即 accept，连接早已
// 成功返回，取消无从触发。
func TestDialCancellationInterruptsTCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Dial(ctx, nil, blackholeIP, 80, 30*time.Second)
		done <- err
	}()
	time.Sleep(150 * time.Millisecond) // 让连接进入 SYN-SENT
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("取消应返回 context.Canceled，实际 %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ctx 取消未中断 TCP 连接——仍在等 30s 超时")
	}
}

// TestDialTimeoutCapsContext ctx 无取消时，timeout 自身必须生效（否则会无限挂起）。
func TestDialTimeoutCapsContext(t *testing.T) {
	start := time.Now()
	if _, err := Dial(context.Background(), nil, blackholeIP, 80, 500*time.Millisecond); err == nil {
		t.Fatal("黑洞地址应失败")
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("timeout 未生效: %v", el)
	}
}

// TestDialOneCancellation ctx 取消同样中断 DialOne。
func TestDialOneCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := DialOne(ctx, nil, blackholeIP, 80, 30*time.Second)
		done <- err
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("取消应返回 context.Canceled，实际 %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ctx 取消未中断 DialOne")
	}
}

// TestDialRespectsCallerContextDeadline 调用方 ctx 的更早截止优先于 timeout。
func TestDialRespectsCallerContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Dial(ctx, nil, blackholeIP, 80, 30*time.Second); err == nil {
		t.Fatal("应失败")
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("调用方截止未被遵守: %v", el)
	}
}
