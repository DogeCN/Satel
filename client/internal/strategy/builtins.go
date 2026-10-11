package strategy

// builtinCanonicals 是离线可用的内置策略库，顺序即降级尝试顺序。
// 与 docs/protocol.md §2.4 一一对应；改动这里必须同步改协议文档。
//
// 顺序按 2026-10-11 的实测排（同 IP 换 SNI 对照，确认是无状态 SNI 封锁）：
// tlsrf 与 split+oob 能完成握手，单纯的 split 不能——所以能赢的排前面，
// 省掉注定失败的探测窗口。详见 docs/findings.md §7。
var builtinCanonicals = []string{
	"tls|tlsrf(chunk=8,delay_ms=8,limit=400)",
	"tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)|oob(byte=0)",
	"tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)",
	"tls|split(at=sni,count=4,delay_ms=24,len=1,pos=0)",
	"http|hostsplit(gap=1)",
	"http|case(seed=0)|hostsplit(gap=1)",
}

// Builtins 返回内置策略库。解析失败视为编程错误，直接 panic——内置串是常量。
func Builtins() []*Spec {
	out := make([]*Spec, 0, len(builtinCanonicals))
	for _, c := range builtinCanonicals {
		s, err := Parse(c)
		if err != nil {
			panic("strategy: 内置策略非法: " + c + ": " + err.Error())
		}
		out = append(out, s)
	}
	return out
}

// BuiltinFor 返回某 proto 的内置策略（保持降级顺序）。
func BuiltinFor(proto string) []*Spec {
	var out []*Spec
	for _, s := range Builtins() {
		if s.Proto == proto {
			out = append(out, s)
		}
	}
	return out
}
