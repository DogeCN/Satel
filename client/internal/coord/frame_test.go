package coord

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	raw := encodeFrame(opData, 0x01020304, payload)
	if len(raw) != frameHeader+len(payload) {
		t.Fatalf("帧长 %d, 期望 %d", len(raw), frameHeader+len(payload))
	}
	f, err := decodeFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.op != opData || f.id != 0x01020304 || !bytes.Equal(f.data, payload) {
		t.Fatalf("解出 %+v", f)
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	f, err := decodeFrame(encodeFrame(opClose, 7, nil))
	if err != nil {
		t.Fatal(err)
	}
	if f.op != opClose || f.id != 7 || len(f.data) != 0 {
		t.Fatalf("解出 %+v", f)
	}
}

func TestFrameTooShort(t *testing.T) {
	for n := 0; n < frameHeader; n++ {
		if _, err := decodeFrame(make([]byte, n)); err == nil {
			t.Fatalf("长度 %d 应被拒绝", n)
		}
	}
}

func TestHelloRoundTrip(t *testing.T) {
	ts := int64(1780000000)
	auth := strings.Repeat("a", authLen)
	caps := []string{"split", "tlsrf", "oob"}
	ts2, a2, fp2, caps2, err := decodeHello(encodeHello(ts, auth, "windows-amd64-1", caps))
	if err != nil {
		t.Fatal(err)
	}
	if ts2 != ts || a2 != auth || fp2 != "windows-amd64-1" {
		t.Fatalf("解出 ts=%d auth=%.8s fp=%q", ts2, a2, fp2)
	}
	if len(caps2) != 3 || caps2[0] != "split" || caps2[2] != "oob" {
		t.Fatalf("caps = %v", caps2)
	}

	// 空 caps：不应因为 Split("",",") 产生一个空元素
	_, _, _, caps3, err := decodeHello(encodeHello(ts, auth, "fp", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(caps3) != 0 {
		t.Fatalf("空 caps 应解出空切片，得到 %v", caps3)
	}
}

func TestBundleRoundTrip(t *testing.T) {
	p, n, err := decodeBundle(encodeBundle("tls", 8))
	if err != nil {
		t.Fatal(err)
	}
	if p != "tls" || n != 8 {
		t.Fatalf("解出 proto=%q n=%d", p, n)
	}
}

func TestBundleRespRoundTrip(t *testing.T) {
	in := []bundleEntry{
		{id: "15c0e805", spec: "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)"},
		{id: "78c3d41b", spec: "tls|tlsrf(chunk=8,delay_ms=8,limit=400)"},
	}
	b, err := encodeBundleResp(42, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, out, _, err := decodeBundleResp(b)
	if err != nil {
		t.Fatal(err)
	}
	if v != 42 || len(out) != 2 {
		t.Fatalf("解出 version=%d 共 %d 条", v, len(out))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Fatalf("第 %d 条: %+v != %+v", i, out[i], in[i])
		}
	}
}

func TestBundleRespRejectsBadID(t *testing.T) {
	if _, err := encodeBundleResp(1, []bundleEntry{{id: "short", spec: "x"}}, nil); err == nil {
		t.Fatal("非 8 位 ID 应被拒绝")
	}
}

const bid32 = "0123456789abcdef0123456789abcdef"

func TestReportRoundTrip(t *testing.T) {
	in := []reportEntry{
		{host: "example.com", method: "15c0e805", kind: "ok", ok: true, rtt: 118, ts: 1780000000, proto: "tls"},
		{host: "b.example", method: "@proxyip", kind: "reset", unsup: true, rtt: 0, ts: 1780000001, proto: "http"},
	}
	b, err := encodeReport(bid32, in)
	if err != nil {
		t.Fatal(err)
	}
	// batchID(32) + 2 字节条数 + 每条定长部分 + 四个变长字段的实际字节数。
	want := batchIDLen + 2
	for _, it := range in {
		want += reportEntryFixed + len(it.host) + len(it.method) + len(it.kind) + len(it.proto)
	}
	if len(b) != want {
		t.Fatalf("编码长度 %d, 期望 %d", len(b), want)
	}
	bid, out, err := decodeReport(b)
	if err != nil {
		t.Fatal(err)
	}
	if bid != bid32 {
		t.Fatalf("batchID 未保真: %q", bid)
	}
	if len(out) != 2 {
		t.Fatalf("解出 %d 条", len(out))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Fatalf("第 %d 条: %+v != %+v", i, out[i], in[i])
		}
	}
	// 明文主机名与失败类别都要能原样穿过线上。
	if out[0].host != "example.com" || out[0].kind != "ok" {
		t.Fatalf("明文 host/kind 未保真: %+v", out[0])
	}
	if out[1].method != "@proxyip" || !out[1].unsup || out[1].kind != "reset" {
		t.Fatalf("伪方法与类别未保真: %+v", out[1])
	}
}

// TestReportRejectsOverlong 变长字段各自有上限，超了要在编码侧就拒绝，
// 免得把一个 1 字节长度前缀截断成完全不同的字段。
func TestReportRejectsOverlong(t *testing.T) {
	long := strings.Repeat("a", maxHostName+1)
	if _, err := encodeReport(bid32, []reportEntry{{host: long, method: "@direct", kind: "ok"}}); err == nil {
		t.Fatal("超长主机名应被拒绝")
	}
	if _, err := encodeReport(bid32, []reportEntry{{host: "a", method: strings.Repeat("m", maxMethodLen+1), kind: "ok"}}); err == nil {
		t.Fatal("超长方法名应被拒绝")
	}
	if _, err := encodeReport(bid32, []reportEntry{{host: "a", method: "@direct", kind: strings.Repeat("k", maxKindLen+1)}}); err == nil {
		t.Fatal("超长失败类别应被拒绝")
	}
	if _, err := encodeReport(bid32, []reportEntry{{host: "", method: "@direct", kind: "ok"}}); err == nil {
		t.Fatal("空主机名应被拒绝")
	}
}

func TestReportRejectsTooMany(t *testing.T) {
	many := make([]reportEntry, maxReportN+1)
	if _, err := encodeReport(bid32, many); err == nil {
		t.Fatalf("%d 条应被拒绝", len(many))
	}
}

func TestEvolveRoundTrip(t *testing.T) {
	k, err := decodeEvolve(encodeEvolve("0123456789abcdef"))
	if err != nil || k != "0123456789abcdef" {
		t.Fatalf("解出 key=%q err=%v", k, err)
	}
	g, bo, r, p, err := decodeEvolveResp(encodeEvolveResp(7, 6, 4, 48))
	if err != nil || g != 7 || bo != 6 || r != 4 || p != 48 {
		t.Fatalf("解出 %d/%d/%d/%d err=%v", g, bo, r, p, err)
	}
}

func TestOpenRoundTrip(t *testing.T) {
	b, err := encodeOpen("www.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	h, p, err := decodeOpen(b)
	if err != nil || h != "www.example.com" || p != 443 {
		t.Fatalf("解出 host=%q port=%d err=%v", h, p, err)
	}
}

func TestStatusRoundTrip(t *testing.T) {
	code, msg, err := decodeStatus(encodeStatus(statusAuthFail, "bad ts"))
	if err != nil || code != statusAuthFail || msg != "bad ts" {
		t.Fatalf("解出 code=%d msg=%q err=%v", code, msg, err)
	}
	// 无消息
	code2, msg2, err := decodeStatus(encodeStatus(statusOK, ""))
	if err != nil || code2 != statusOK || msg2 != "" {
		t.Fatalf("解出 code=%d msg=%q err=%v", code2, msg2, err)
	}
}

// TestDecodeTruncatedNeverPanics 是最关键的一条：对每种 payload 逐字节截断，
// decode 只能返回错误，不能 panic —— 输入来自网络。
func TestDecodeTruncatedNeverPanics(t *testing.T) {
	payloads := map[string][]byte{
		"hello":  encodeHello(1780000000, strings.Repeat("a", authLen), "fp-1", []string{"split", "tlsrf"}),
		"bundle": encodeBundle("tls", 8),
		"evolve": encodeEvolve("admin-key-0123456789"),
		"status": encodeStatus(statusAuthFail, "some message"),
	}
	br, _ := encodeBundleResp(3, []bundleEntry{{id: "15c0e805", spec: "tls|split(at=sni)"}}, nil)
	payloads["bundleresp"] = br
	rp, _ := encodeReport(bid32, []reportEntry{{host: "x.com", method: "15c0e805", kind: "ok", ok: true, rtt: 5, ts: 1, proto: "tls"}})
	payloads["report"] = rp
	ob, _ := encodeOpen("a.example.com", 8443)
	payloads["open"] = ob
	payloads["evolveresp"] = encodeEvolveResp(1, 2, 3, 4)

	decoders := map[string]func([]byte) error{
		"hello":      func(b []byte) error { _, _, _, _, e := decodeHello(b); return e },
		"bundle":     func(b []byte) error { _, _, e := decodeBundle(b); return e },
		"bundleresp": func(b []byte) error { _, _, _, e := decodeBundleResp(b); return e },
		"report":     func(b []byte) error { _, _, e := decodeReport(b); return e },
		"evolve":     func(b []byte) error { _, e := decodeEvolve(b); return e },
		"evolveresp": func(b []byte) error { _, _, _, _, e := decodeEvolveResp(b); return e },
		"open":       func(b []byte) error { _, _, e := decodeOpen(b); return e },
		"status":     func(b []byte) error { _, _, e := decodeStatus(b); return e },
	}
	for name, dec := range decoders {
		p := payloads[name]
		for n := 0; n < len(p); n++ {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s 在截断长度 %d 时 panic: %v", name, n, r)
					}
				}()
				_ = dec(p[:n]) // 允许成功或失败，只要求不 panic
			}()
		}
	}
}

// TestDecodeTrailingGarbageRejected 确认"多出来的字节"会被发现，而不是被忽略。
func TestDecodeTrailingGarbageRejected(t *testing.T) {
	cases := map[string]func([]byte) error{
		"hello":  func(b []byte) error { _, _, _, _, e := decodeHello(b); return e },
		"bundle": func(b []byte) error { _, _, e := decodeBundle(b); return e },
		"evolve": func(b []byte) error { _, e := decodeEvolve(b); return e },
		"open":   func(b []byte) error { _, _, e := decodeOpen(b); return e },
	}
	bodies := map[string][]byte{
		"hello":  encodeHello(1, strings.Repeat("a", authLen), "f", nil),
		"bundle": encodeBundle("tls", 8),
		"evolve": encodeEvolve("k"),
		"open":   func() []byte { b, _ := encodeOpen("h", 1); return b }(),
	}
	for name, dec := range cases {
		with := append(append([]byte{}, bodies[name]...), 0xAA, 0xBB)
		if err := dec(with); err == nil {
			t.Fatalf("%s 应拒绝尾随垃圾数据", name)
		}
	}
}

// TestCrossLanguageGolden 与 server/src/frame.js 生成的字节必须逐字节一致。
// 任何一侧改了编码，这个测试会立刻炸——这是两侧唯一的机械契约。
// 字面量直接取自两侧实现的实际输出，不要手工拼接：抄错会伪装成"不一致"。
func TestCrossLanguageGolden(t *testing.T) {
	hello := encodeFrame(opHello, 0, encodeHello(1780000000, strings.Repeat("a", authLen), "fp", []string{"split", "tlsrf"}))
	rep, err := encodeReport(bid32, []reportEntry{
		{host: "www.example.com", method: "15c0e805", kind: "ok", ok: true, rtt: 118, ts: 1780000000, proto: "tls"},
	})
	if err != nil {
		t.Fatal(err)
	}
	report := encodeFrame(opReport, 7, rep)

	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"HELLO", hello, "0100000000000000006a18a50061616161616161616161616161616161616161616161616161616161616161610266700b73706c69742c746c73726602"},
		{"REPORT", report, "0500000007303132333435363738396162636465663031323334353637383961626364656600010f7777772e6578616d706c652e636f6d0831356330653830350100000076000000006a18a500026f6b03746c73"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(c.got); got != c.want {
			t.Errorf("%s 跨语言字节不一致: got %s want %s", c.name, got, c.want)
		}
	}
}
