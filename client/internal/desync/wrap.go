package desync

import (
	"net"

	"satel/internal/strategy"
)

// WrapConn 返回一个 net.Conn，把**第一次 Write**（TLS 场景即 ClientHello）按 spec
// 分片发出，之后的 Write 原样透传。
//
// 用途：让工具自己的控制通道（客户端 → 协调端）也走自己的招法。调用方（如
// crypto/tls）自己写 ClientHello，我们碰不到那些字节，只能在底层连接上包一层，
// 让它写出的首段经过分片逻辑。spec 为 nil 时原样返回 c。
func WrapConn(c net.Conn, spec *strategy.Spec, proto string, opt Options) net.Conn {
	if spec == nil {
		return c
	}
	return &wrapConn{Conn: c, spec: spec, proto: proto, opt: opt}
}

type wrapConn struct {
	net.Conn
	spec  *strategy.Spec
	proto string
	opt   Options
	done  bool
}

func (w *wrapConn) Write(p []byte) (int, error) {
	if w.done {
		return w.Conn.Write(p)
	}
	w.done = true
	if _, err := Apply(w.Conn, w.spec, p, nil, w.opt); err != nil {
		return 0, err
	}
	// Write 的契约是"吃掉了多少入参字节"。tlsrf 会额外插入 record 头，写出的
	// 字节数多于 len(p)，但对调用方而言入参已全部落地，故返回 len(p)。
	return len(p), nil
}
