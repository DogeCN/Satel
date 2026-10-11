// Package failkind 把一次尝试的失败归类成**机器可读**的枚举，供路由记忆当证据用。
//
// 为什么不复用 probe.Kind：它的值是中文展示串（"被复位 RST"），当机器键会把展示层
// 漏进路由层。这里是纯代码值，展示串留到打印时才映射（见 Label）。
package failkind

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
)

// Kind 是失败的类别。None 表示成功。
type Kind int

// 顺序不重要，但每种失败对路由的**含义**不同：DNS/拨号类说明"这条路根本到不了"
// （换任何报文招法都没用），读写类才轮到分片与 TLS 终止层。
const (
	None        Kind = iota
	DialTimeout      // 拨号超时：IP 黑洞。包级改写没有赢面，TCP 都没建立
	DialRefused      // 拨号被拒：端口/地址不可达
	Reset            // 连接被复位：TCP 建了但被主动 RST
	ReadTimeout      // 读超时：连接在、字节没回来（静默丢弃的典型形态）
	TLSAlert         // 上游回了 TLS 告警：握手被拒，不是有字节就等于通了
	Write            // 写失败
	Apply            // 改写阶段本身失败（发首段就断）
	Canceled         // 被上层取消（浏览器关闭连接等），不算证据
	Other
)

// Label 返回中文展示串——只在打印时用，不参与任何判等或作为 map 键。
func (k Kind) Label() string {
	switch k {
	case None:
		return "成功"
	case DialTimeout:
		return "拨号超时"
	case DialRefused:
		return "拨号被拒"
	case Reset:
		return "被复位"
	case ReadTimeout:
		return "读超时"
	case TLSAlert:
		return "TLS 告警"
	case Write:
		return "写失败"
	case Apply:
		return "改写失败"
	case Canceled:
		return "已取消"
	default:
		return "其它"
	}
}

// Key 返回**稳定的机器键**——可以安全地用作 map 键、持久化值、分组标识。
//
// 与 Label 的分工是硬约定：Label 是给人看的文案，改它不该影响任何行为；Key 是
// 给机器用的，改它才是协议变更（记忆里的分组就是用 Key 拼的）。
func (k Kind) Key() string {
	switch k {
	case None:
		return "ok"
	case DialTimeout:
		return "dialtimeout"
	case DialRefused:
		return "dialrefused"
	case Reset:
		return "reset"
	case ReadTimeout:
		return "readtimeout"
	case TLSAlert:
		return "tlsalert"
	case Write:
		return "write"
	case Apply:
		return "apply"
	case Canceled:
		return "canceled"
	default:
		return "other"
	}
}

func (k Kind) String() string { return k.Label() }

// Reachable 返回 true 表示连接已经建立过（TCP 通了）。DialTimeout/DialRefused 为
// false——此时任何报文级改写都无从谈起。
func (k Kind) Reachable() bool {
	switch k {
	case Reset, ReadTimeout, TLSAlert, Write, Apply:
		return true
	default:
		return false
	}
}

// IsEvidence 返回 true 表示这次失败值得计入记忆。Canceled 与 None 不算——前者是
// 客户端主动放弃，后者不是失败。
func (k Kind) IsEvidence() bool {
	return k != None && k != Canceled
}

// Classify 把错误归类。nil → None。
func Classify(err error) Kind {
	if err == nil {
		return None
	}
	// 上层取消优先判：它可能包装了别的错误，但语义上不算证据。
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return Reset
	}
	// TLS 告警：握手收到了对方的 alert，不是"有回包=通"。
	var alert *tlsAlertErr
	if errors.As(err, &alert) {
		return TLSAlert
	}

	// 拨号 vs 读写：用 net.OpError 的 Op 区分。
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			if isTimeoutErr(opErr.Err) {
				return DialTimeout
			}
			return DialRefused
		}
		// Op 是 read/write 的
		if isTimeoutErr(opErr.Err) {
			return ReadTimeout
		}
		if errors.Is(opErr.Err, syscall.ECONNRESET) {
			return Reset
		}
	}

	if errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "forcibly closed") {
		return Reset
	}
	if isTimeoutErr(err) {
		// 顶层 timeout（没包在 OpError 里）按读超时处理——拨号超时一定带 Op=="dial"。
		return ReadTimeout
	}
	return Other
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// tlsAlertErr 供调用方在握手失败时标注"这是 TLS 告警"，
// 让 Classify 能把它和普通 Reset/Other 区分开（前者是"内容被拒"，语义不同）。
type tlsAlertErr struct{ msg string }

func (e *tlsAlertErr) Error() string { return e.msg }

// MarkTLSAlert 包装一个 TLS 握手告警错误，使 Classify 返回 TLSAlert。
func MarkTLSAlert(err error) error {
	if err == nil {
		return nil
	}
	return &tlsAlertErr{msg: "tls alert: " + err.Error()}
}
