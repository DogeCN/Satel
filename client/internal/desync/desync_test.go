package desync

import (
	"bytes"
	"testing"

	"satel/internal/flight"
	"satel/internal/strategy"
)

// buildClientHello 造一个最小但结构合法的 ClientHello record，SNI 可控。
// 复用 flight 包的实现，避免两处维护同一份字节布局。
func buildClientHello(sni string) []byte { return flight.SyntheticClientHello(sni) }

func concat(segs []seg) []byte {
	var out []byte
	for _, s := range segs {
		out = append(out, s.data...)
	}
	return out
}

func mustParse(t *testing.T, canon string) *strategy.Spec {
	t.Helper()
	s, err := strategy.Parse(canon)
	if err != nil {
		t.Fatalf("Parse(%q): %v", canon, err)
	}
	return s
}

func TestSNIRange(t *testing.T) {
	ch := buildClientHello("example.com")
	start, end, ok := flight.SNIRange(ch)
	if !ok {
		t.Fatal("未找到 SNI")
	}
	if got := string(ch[start:end]); got != "example.com" {
		t.Fatalf("SNI = %q, want example.com", got)
	}
}

func TestSplitPreservesStream(t *testing.T) {
	ch := buildClientHello("www.example.com")
	spec := mustParse(t, "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)")
	p := buildPlan(spec, ch, Options{})
	if len(p.segs) < 2 {
		t.Fatalf("应切成多段，得到 %d", len(p.segs))
	}
	if !bytes.Equal(concat(p.segs), ch) {
		t.Fatal("split 改变了字节流（应当原样保留）")
	}
	// 第一刀必须落在 SNI 内部
	s, _, _ := flight.SNIRange(ch)
	if len(p.segs[0].data) <= s {
		t.Fatalf("切点 %d 未进入 SNI（SNI 起于 %d）", len(p.segs[0].data), s)
	}
}

func TestSplitCountAndLen(t *testing.T) {
	ch := buildClientHello("averylongexamplehostname.test")
	spec := mustParse(t, "tls|split(at=sni,count=4,delay_ms=24,len=1,pos=0)")
	p := buildPlan(spec, ch, Options{})
	// head + 最多 count 片
	if len(p.segs) < 3 || len(p.segs) > 5 {
		t.Fatalf("分段数 %d 超出预期", len(p.segs))
	}
	if !bytes.Equal(concat(p.segs), ch) {
		t.Fatal("字节流被改变")
	}
	// 第 2..n-1 片长度应为 len=1
	for i := 1; i < len(p.segs)-1; i++ {
		if len(p.segs[i].data) != 1 {
			t.Fatalf("第 %d 片长度 %d, want 1", i, len(p.segs[i].data))
		}
	}
}

func TestTLSRFReassembles(t *testing.T) {
	ch := buildClientHello("fragment.example.com")
	spec := mustParse(t, "tls|tlsrf(chunk=8,delay_ms=8,limit=400)")
	p := buildPlan(spec, ch, Options{})
	if len(p.segs) < 2 {
		t.Fatal("tlsrf 未产生多个 record")
	}
	// 每个分段都是一个合法 TLS record，负载拼起来等于原负载
	origPayload := ch[5:]
	var got []byte
	for i, s := range p.segs {
		if len(s.data) < 5 || s.data[0] != 0x16 {
			t.Fatalf("第 %d 段不是握手 record: % x", i, s.data[:min(5, len(s.data))])
		}
		rl := int(s.data[3])<<8 | int(s.data[4])
		if rl != len(s.data)-5 {
			t.Fatalf("第 %d 段长度字段 %d 与实际 %d 不符", i, rl, len(s.data)-5)
		}
		got = append(got, s.data[5:]...)
	}
	if !bytes.Equal(got, origPayload) {
		t.Fatal("tlsrf 后负载与原始负载不一致")
	}
}

func TestTLSRFLimit(t *testing.T) {
	ch := buildClientHello("fragment.example.com")
	spec := mustParse(t, "tls|tlsrf(chunk=8,delay_ms=0,limit=16)")
	p := buildPlan(spec, ch, Options{})
	// 前 16 字节切成 2 个 record，剩余作为最后一个 record
	if len(p.segs) != 3 {
		t.Fatalf("分段数 %d, want 3", len(p.segs))
	}
	if len(p.segs[0].data) != 13 || len(p.segs[1].data) != 13 {
		t.Fatalf("前两段负载应为 8 字节（record 总长 13），得到 %d/%d",
			len(p.segs[0].data), len(p.segs[1].data))
	}
}

func TestHostSplit(t *testing.T) {
	head := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n")
	spec := mustParse(t, "http|hostsplit(gap=1)")
	p := buildPlan(spec, head, Options{})
	if len(p.segs) != 2 {
		t.Fatalf("hostsplit 应切一刀，得到 %d 段", len(p.segs))
	}
	joined := concat(p.segs)
	if !bytes.Contains(joined, []byte("Host:  example.com")) {
		t.Fatalf("未插入空格: %q", joined)
	}
	// 切点落在主机名中间
	s, e, ok := flight.HostRange(joined)
	if !ok {
		t.Fatal("改写后找不到 Host")
	}
	cut := len(p.segs[0].data)
	if cut <= s || cut >= e {
		t.Fatalf("切点 %d 不在 Host 值区间 [%d,%d)", cut, s, e)
	}
}

func TestCasePreservesLengthAndValues(t *testing.T) {
	head := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl\r\n\r\n")
	spec := mustParse(t, "http|case(seed=1234)")
	p := buildPlan(spec, head, Options{})
	out := p.segs[0].data
	if len(out) != len(head) {
		t.Fatalf("长度变了: %d -> %d", len(head), len(out))
	}
	// Host 值必须原样
	s, e, ok := flight.HostRange(out)
	if !ok || string(out[s:e]) != "example.com" {
		t.Fatalf("Host 值被改动: %q", out[s:e])
	}
	// 请求行不动
	if !bytes.HasPrefix(out, []byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("请求行被改动")
	}
	// 头名大小写确实变了（种子固定，应与原串不同）
	if bytes.Equal(out, head) {
		t.Fatal("case 未产生任何变化")
	}
}

func TestCaseDeterministic(t *testing.T) {
	head := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nX-A: 1\r\n\r\n")
	a := buildPlan(mustParse(t, "http|case(seed=7)"), head, Options{}).segs[0].data
	b := buildPlan(mustParse(t, "http|case(seed=7)"), head, Options{}).segs[0].data
	if !bytes.Equal(a, b) {
		t.Fatal("同种子结果不一致")
	}
}

func TestPrivilegedOpsUnsupported(t *testing.T) {
	for _, canon := range []string{
		"tls|fake(count=1,ttl=3)",
		"tls|disorder()",
		"tls|dup(count=1)",
	} {
		spec := mustParse(t, canon)
		p := buildPlan(spec, buildClientHello("example.com"), Options{Raw: nil})
		if len(p.unsup) != 1 {
			t.Fatalf("%s: 应记为 1 条不支持，得到 %v", canon, p.unsup)
		}
		// 且不应改变分段（除 oob 外无其他副作用）
		if len(p.segs) != 1 {
			t.Fatalf("%s: 不应改变分段", canon)
		}
	}
}

func TestOOBFlag(t *testing.T) {
	spec := mustParse(t, "tls|split(at=sni,count=2)|oob(byte=42)")
	p := buildPlan(spec, buildClientHello("example.com"), Options{})
	if !p.segs[0].oob {
		t.Fatal("第一段未标记 OOB")
	}
	if p.oobByte != 42 {
		t.Fatalf("紧急字节 = %d, want 42", p.oobByte)
	}
}

func TestCombinedSplitThenTLSRF(t *testing.T) {
	ch := buildClientHello("combined.example.com")
	spec := mustParse(t, "tls|split(at=sni,count=2,delay_ms=4,len=1,pos=1)|tlsrf(chunk=8,delay_ms=4,limit=400)")
	p := buildPlan(spec, ch, Options{})
	if len(p.segs) < 3 {
		t.Fatalf("组合策略分段太少: %d", len(p.segs))
	}
}
