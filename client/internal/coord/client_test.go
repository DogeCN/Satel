package coord

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// testCoord 是一个最小但真实的协调端：起 WS、校验 HELLO、按 opcode 应答。
// 它不碰 D1——本文件只验证传输层（帧、鉴权、请求-响应、隧道流）。
type testCoord struct {
	srv        *httptest.Server
	password   string
	echoTunnel bool

	mu       sync.Mutex
	hello    bool
	badAuth  int
	reports  []reportEntry
	bundles  int
	evolves  int
	seenHost string
	seenPort int
	openFail bool
	streams  map[uint32]bool
}

func (tc *testCoord) key() []byte {
	sum := sha256.Sum256([]byte("satel/v1/" + tc.password))
	return sum[:]
}

func (tc *testCoord) send(ws *websocket.Conn, raw []byte) {
	_, _ = ws.Write(raw)
}

func (tc *testCoord) serve(ws *websocket.Conn) {
	buf := make([]byte, 64*1024)

	// 首帧必须是 HELLO
	n, err := ws.Read(buf)
	if err != nil {
		return
	}
	f, err := decodeFrame(buf[:n])
	if err != nil || f.op != opHello {
		return
	}
	ts, auth, fp, caps, err := decodeHello(f.data)
	if err != nil {
		return
	}
	if fp == "" || len(caps) == 0 || auth != signHello(tc.key(), ts) {
		tc.mu.Lock()
		tc.badAuth++
		tc.mu.Unlock()
		ws.Close()
		return
	}
	tc.mu.Lock()
	tc.hello = true
	tc.mu.Unlock()
	tc.send(ws, encodeFrame(opStatus, 0, encodeStatus(statusOK, "")))

	for {
		n, err := ws.Read(buf)
		if err != nil {
			return
		}
		f, err := decodeFrame(buf[:n])
		if err != nil {
			continue
		}
		switch f.op {
		case opBundle:
			proto, _, _ := decodeBundle(f.data)
			tc.mu.Lock()
			tc.bundles++
			tc.mu.Unlock()
			payload, perr := encodeBundleResp(7, []bundleEntry{
				{id: "15c0e805", spec: "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)"},
				{id: "78c3d41b", spec: "tls|" + proto + "|tlsrf(chunk=8,delay_ms=8,limit=400)"},
			}, nil)
			if perr != nil {
				return
			}
			tc.send(ws, encodeFrame(opBundleResp, f.id, payload))
		case opReport:
			_, items, derr := decodeReport(f.data)
			if derr != nil {
				continue
			}
			tc.mu.Lock()
			tc.reports = append(tc.reports, items...)
			tc.mu.Unlock()
			tc.send(ws, encodeFrame(opReportResp, f.id, encodeReportResp(len(items))))
		case opEvolve:
			key, _ := decodeEvolve(f.data)
			if key != "admin-secret" {
				tc.send(ws, encodeFrame(opStatus, f.id, encodeStatus(statusAuthFail, "admin")))
				continue
			}
			tc.mu.Lock()
			tc.evolves++
			tc.mu.Unlock()
			tc.send(ws, encodeFrame(opEvolveResp, f.id, encodeEvolveResp(3, 6, 4, 48)))
		case opOpen:
			host, port, derr := decodeOpen(f.data)
			if derr != nil {
				continue
			}
			tc.mu.Lock()
			tc.seenHost, tc.seenPort = host, port
			fail := tc.openFail
			tc.mu.Unlock()
			if fail {
				tc.send(ws, encodeFrame(opOpened, f.id, encodeOpened(openFail)))
				continue
			}
			tc.mu.Lock()
			tc.streams[f.id] = true
			tc.mu.Unlock()
			tc.send(ws, encodeFrame(opOpened, f.id, encodeOpened(openOK)))
		case opData:
			tc.mu.Lock()
			open := tc.streams[f.id]
			tc.mu.Unlock()
			if open && tc.echoTunnel {
				tc.send(ws, encodeFrame(opData, f.id, f.data))
			}
		case opClose:
			tc.mu.Lock()
			delete(tc.streams, f.id)
			tc.mu.Unlock()
			tc.send(ws, encodeFrame(opClose, f.id, nil))
		}
	}
}

func newTestCoord(t *testing.T, pw string, echo bool) (*testCoord, string) {
	t.Helper()
	tc := &testCoord{password: pw, echoTunnel: echo, streams: map[uint32]bool{}}
	tc.srv = httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) { tc.serve(ws) }))
	t.Cleanup(tc.srv.Close)
	return tc, "ws://" + strings.TrimPrefix(tc.srv.URL, "http://")
}

func newTestClient(t *testing.T, base, pw string) *Client {
	t.Helper()
	c, err := New(base, pw, "windows-amd64-1", []string{"split", "tlsrf"})
	if err != nil {
		t.Fatal(err)
	}
	c.SetBootstrap(nil) // 测试里没有 DPI，不需要自举分片
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func ctxT(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), d)
}

// --- HELLO 与鉴权 -----------------------------------------------------------

func TestClientHelloHandshake(t *testing.T) {
	_, base := newTestCoord(t, "pw-1", false)
	c := newTestClient(t, base, "pw-1")
	ctx, cancel := ctxT(t, 5*time.Second)
	defer cancel()
	if _, err := c.FetchBundle(ctx, "tls", 4); err != nil {
		t.Fatalf("HELLO 之后应能拿到策略库: %v", err)
	}
}

func TestClientWrongPasswordRejected(t *testing.T) {
	_, base := newTestCoord(t, "right", false)
	c := newTestClient(t, base, "wrong")
	ctx, cancel := ctxT(t, 5*time.Second)
	defer cancel()
	if _, err := c.FetchBundle(ctx, "tls", 4); err == nil {
		t.Fatal("错误口令应被拒绝")
	}
}

// --- 三个请求-响应 opcode ----------------------------------------------------

func TestClientBundleRoundTrip(t *testing.T) {
	tc, base := newTestCoord(t, "pw", false)
	c := newTestClient(t, base, "pw")
	ctx, cancel := ctxT(t, 5*time.Second)
	defer cancel()

	b, err := c.FetchBundle(ctx, "tls", 8)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != 7 || len(b.Items) != 2 {
		t.Fatalf("bundle = version %d, %d 条", b.Version, len(b.Items))
	}
	if b.Items[0].ID != "15c0e805" {
		t.Fatalf("首条 ID = %s", b.Items[0].ID)
	}
	if !strings.Contains(b.Items[1].Spec, "tlsrf") {
		t.Fatalf("第二条 spec = %s", b.Items[1].Spec)
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.bundles != 1 {
		t.Fatalf("服务端收到 %d 次 BUNDLE", tc.bundles)
	}
}

func TestClientReportRoundTrip(t *testing.T) {
	tc, base := newTestCoord(t, "pw", false)
	c := newTestClient(t, base, "pw")
	ctx, cancel := ctxT(t, 5*time.Second)
	defer cancel()

	items := []Item{
		{Host: "example.com", Method: "15c0e805", Kind: "ok", OK: 1, RTTms: 118},
		{Host: "b.example", Method: "@proxyip", Kind: "reset", OK: 0, Unsup: 1},
	}
	n, err := c.Report(ctx, items)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("accepted = %d, want 2", n)
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if len(tc.reports) != 2 {
		t.Fatalf("服务端收到 %d 条", len(tc.reports))
	}
	// 明文主机名直传，不再哈希。
	if tc.reports[0].host != "example.com" || !tc.reports[0].ok || tc.reports[0].kind != "ok" {
		t.Fatalf("第一条 = %+v", tc.reports[0])
	}
	if tc.reports[1].method != "@proxyip" || !tc.reports[1].unsup || tc.reports[1].rtt != 0 {
		t.Fatalf("第二条 = %+v", tc.reports[1])
	}
}

func TestClientEvolveRoundTrip(t *testing.T) {
	tc, base := newTestCoord(t, "pw", false)
	c := newTestClient(t, base, "pw")
	ctx, cancel := ctxT(t, 5*time.Second)
	defer cancel()

	res, err := c.Evolve(ctx, "admin-secret")
	if err != nil {
		t.Fatal(err)
	}
	if res["generation"] != 3 || res["born"] != 6 || res["retired"] != 4 || res["pool"] != 48 {
		t.Fatalf("evolve = %v", res)
	}
	if _, err := c.Evolve(ctx, "wrong"); err == nil {
		t.Fatal("错误管理员密钥应被拒绝")
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.evolves != 1 {
		t.Fatalf("服务端接受 %d 次 EVOLVE", tc.evolves)
	}
}

// --- 隧道：OPEN / DATA / CLOSE ----------------------------------------------

func TestClientTunnelEcho(t *testing.T) {
	tc, base := newTestCoord(t, "pw", true)
	c := newTestClient(t, base, "pw")
	ctx, cancel := ctxT(t, 10*time.Second)
	defer cancel()

	conn, err := c.Tunnel(ctx, "www.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("hello-tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("回显 = %q, want %q", got, msg)
	}

	// 再走一轮，确认流没坏
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}

	tc.mu.Lock()
	if tc.seenHost != "www.example.com" || tc.seenPort != 443 {
		tc.mu.Unlock()
		t.Fatalf("服务端看到的 OPEN = %s:%d", tc.seenHost, tc.seenPort)
	}
	tc.mu.Unlock()

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClientTunnelOpenRejected(t *testing.T) {
	tc, base := newTestCoord(t, "pw", false)
	tc.openFail = true
	c := newTestClient(t, base, "pw")
	ctx, cancel := ctxT(t, 5*time.Second)
	defer cancel()
	if _, err := c.Tunnel(ctx, "x.example", 443); err == nil {
		t.Fatal("服务端拒绝 OPEN 时应返回错误")
	}
}

// --- 连接复用 ---------------------------------------------------------------

func TestClientReusesSingleConnection(t *testing.T) {
	tc, base := newTestCoord(t, "pw", false)
	c := newTestClient(t, base, "pw")
	ctx, cancel := ctxT(t, 10*time.Second)
	defer cancel()
	for i := 0; i < 5; i++ {
		if _, err := c.FetchBundle(ctx, "tls", 4); err != nil {
			t.Fatalf("第 %d 次拉取失败: %v", i, err)
		}
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.bundles != 5 {
		t.Fatalf("服务端收到 %d 次 BUNDLE", tc.bundles)
	}
	if tc.badAuth != 0 {
		t.Fatalf("鉴权失败 %d 次", tc.badAuth)
	}
}

func TestClientCloseIsIdempotent(t *testing.T) {
	_, base := newTestCoord(t, "pw", false)
	c, err := New(base, "pw", "fp", []string{"split"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("首次 Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("重复 Close 应无副作用: %v", err)
	}
}

// --- 校验 -------------------------------------------------------------------

func TestNewValidationWS(t *testing.T) {
	if _, err := New("", "pw", "fp", nil); err == nil {
		t.Fatal("空 base 应报错")
	}
	if _, err := New("wss://x", "", "fp", nil); err == nil {
		t.Fatal("空口令应报错")
	}
	if _, err := New("https://x", "pw", "fp", nil); err == nil {
		t.Fatal("http scheme 应被拒——传输层只接受 ws/wss")
	}
	if _, err := New("wss://satel.example.com", "pw", "fp", nil); err != nil {
		t.Fatalf("合法 base 应通过: %v", err)
	}
}

func TestTrimScheme(t *testing.T) {
	if got := TrimScheme("wss://satel.example.com/"); got != "satel.example.com" {
		t.Fatalf("TrimScheme = %q", got)
	}
}
