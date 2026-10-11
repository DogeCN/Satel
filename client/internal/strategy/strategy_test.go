package strategy

import "testing"

// golden 是跨实现约定值：JS 侧（Worker）独立算出的 ID 必须与这里一致。
// 计算方式：printf '%s' '<canonical>' | sha256sum | cut -c1-8
var golden = map[string]string{
	"tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)":             "15c0e805",
	"tls|tlsrf(chunk=8,delay_ms=8,limit=400)":                      "78c3d41b",
	"tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)|oob(byte=0)": "b98c567b",
	"tls|split(at=sni,count=4,delay_ms=24,len=1,pos=0)":            "0352f73e",
	"http|hostsplit(gap=1)":                                        "393db486",
	"http|case(seed=0)|hostsplit(gap=1)":                           "a50096b8",
	"http|hostsplit(gap=1)|case(seed=1234)":                        "713ce104",
}

func TestGoldenIDs(t *testing.T) {
	for canon, want := range golden {
		s, err := Parse(canon)
		if err != nil {
			t.Fatalf("Parse(%q): %v", canon, err)
		}
		if s.Canonical() != canon {
			t.Errorf("Canonical 往返不一致:\n got %q\nwant %q", s.Canonical(), canon)
		}
		if s.ID() != want {
			t.Errorf("ID(%q) = %s, want %s", canon, s.ID(), want)
		}
	}
}

func TestDefaultsFilled(t *testing.T) {
	s, err := Parse("tls|split")
	if err != nil {
		t.Fatal(err)
	}
	want := "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)"
	if s.Canonical() != want {
		t.Fatalf("got %q, want %q", s.Canonical(), want)
	}
	op, ok := s.Get("split")
	if !ok {
		t.Fatal("split 丢失")
	}
	if op.Str("at", "") != "sni" || op.Int("count", 0) != 2 {
		t.Fatalf("默认值未补齐: %+v", op.Params)
	}
}

func TestParseOrderInsensitiveWithinOp(t *testing.T) {
	// 参数书写顺序不应影响 canonical（参数按名排序）。
	a, err := Parse("tls|split(pos=3,at=mid,count=4)")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse("tls|split(count=4,at=mid,pos=3)")
	if err != nil {
		t.Fatal(err)
	}
	if a.Canonical() != b.Canonical() || a.ID() != b.ID() {
		t.Fatalf("参数顺序影响了规范化:\n%s\n%s", a.Canonical(), b.Canonical())
	}
}

func TestOpOrderMatters(t *testing.T) {
	a, _ := Parse("http|hostsplit(gap=1)|case(seed=0)")
	b, _ := Parse("http|case(seed=0)|hostsplit(gap=1)")
	if a.ID() == b.ID() {
		t.Fatal("招法顺序不同却得到相同 ID")
	}
}

func TestRejectUnknownOp(t *testing.T) {
	if _, err := Parse("tls|bogus()"); err == nil {
		t.Fatal("未知招法应被拒绝")
	}
}

func TestRejectUnknownParam(t *testing.T) {
	if _, err := Parse("tls|split(nope=1)"); err == nil {
		t.Fatal("未知参数应被拒绝")
	}
}

func TestRejectWrongType(t *testing.T) {
	if _, err := Parse("tls|split(count=x)"); err == nil {
		t.Fatal("非整数应被拒绝")
	}
	if _, err := Parse("tls|oob(byte=true)"); err == nil {
		t.Fatal("布尔冒充整数应被拒绝")
	}
	if _, err := Parse("tls|fake(badsum=7)"); err == nil {
		t.Fatal("非法布尔应被拒绝")
	}
}

func TestRejectBadProto(t *testing.T) {
	if _, err := Parse("quic|oob()"); err == nil {
		t.Fatal("未知 proto 应被拒绝")
	}
}

func TestBoolFormatting(t *testing.T) {
	s, err := Parse("tls|fake(badsum=1,badseq=0)")
	if err != nil {
		t.Fatal(err)
	}
	want := "tls|fake(badseq=0,badsum=1,count=1,delay_ms=0,len=64,ttl=3)"
	if s.Canonical() != want {
		t.Fatalf("got %q, want %q", s.Canonical(), want)
	}
}

func TestBuiltinsValid(t *testing.T) {
	bs := Builtins()
	if len(bs) != len(builtinCanonicals) {
		t.Fatalf("内置数量 %d, want %d", len(bs), len(builtinCanonicals))
	}
	for _, s := range bs {
		if s.ID() == "" {
			t.Fatalf("内置策略无 ID: %s", s.Canonical())
		}
	}
	tls := BuiltinFor("tls")
	if len(tls) != 4 {
		t.Fatalf("tls 内置 %d 条, want 4", len(tls))
	}
	http := BuiltinFor("http")
	if len(http) != 2 {
		t.Fatalf("http 内置 %d 条, want 2", len(http))
	}
}
