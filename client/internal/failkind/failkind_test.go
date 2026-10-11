package failkind

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestClassifyNilIsNone(t *testing.T) {
	if got := Classify(nil); got != None {
		t.Fatalf("nil → %v, want None", got)
	}
	if None.Reachable() || None.IsEvidence() {
		t.Fatal("None 不该算可达/证据")
	}
}

func TestClassifyDialTimeout(t *testing.T) {
	inner := &net.OpError{Op: "dial", Err: timeoutErr{}}
	if got := Classify(inner); got != DialTimeout {
		t.Fatalf("dial 超时 → %v, want DialTimeout", got)
	}
	if DialTimeout.Reachable() {
		t.Fatal("拨号超时说明 TCP 没建立，不该算可达")
	}
	if !DialTimeout.IsEvidence() {
		t.Fatal("拨号超时是有效证据（它就是 IP 黑洞的信号）")
	}
}

func TestClassifyDialRefused(t *testing.T) {
	inner := &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	if got := Classify(inner); got != DialRefused {
		t.Fatalf("dial 被拒 → %v, want DialRefused", got)
	}
	if DialRefused.Reachable() {
		t.Fatal("拨号被拒不该算可达")
	}
}

func TestClassifyReset(t *testing.T) {
	for _, err := range []error{
		syscall.ECONNRESET,
		&net.OpError{Op: "read", Err: syscall.ECONNRESET},
		fmt.Errorf("wsarecv: An existing connection was forcibly closed by the remote host"),
		io.EOF,
		io.ErrUnexpectedEOF,
	} {
		if got := Classify(err); got != Reset {
			t.Errorf("Classify(%v) = %v, want Reset", err, got)
		}
	}
	if !Reset.Reachable() {
		t.Fatal("RST 说明 TCP 建过，应算可达")
	}
}

func TestClassifyReadTimeout(t *testing.T) {
	inner := &net.OpError{Op: "read", Err: timeoutErr{}}
	if got := Classify(inner); got != ReadTimeout {
		t.Fatalf("read 超时 → %v, want ReadTimeout", got)
	}
	if !ReadTimeout.Reachable() {
		t.Fatal("读超时说明连接在，应算可达")
	}
}

func TestClassifyCanceled(t *testing.T) {
	if got := Classify(context.Canceled); got != Canceled {
		t.Fatalf("context.Canceled → %v", got)
	}
	if got := Classify(fmt.Errorf("打开隧道: %w", context.Canceled)); got != Canceled {
		t.Fatalf("包装的 Canceled → %v", got)
	}
	if Canceled.IsEvidence() {
		t.Fatal("客户端主动取消不该计入记忆（否则浏览器关页面会污染统计）")
	}
}

func TestClassifyTLSAlert(t *testing.T) {
	base := errors.New("remote error: tls: unrecognized name")
	if got := Classify(MarkTLSAlert(base)); got != TLSAlert {
		t.Fatalf("TLS 告警 → %v, want TLSAlert", got)
	}
	if !TLSAlert.Reachable() {
		t.Fatal("TLS 告警说明 TCP 建过，应算可达")
	}
	if MarkTLSAlert(nil) != nil {
		t.Fatal("MarkTLSAlert(nil) 应为 nil")
	}
}

func TestReachablePartition(t *testing.T) {
	// 拨号类失败：报文级改写不可能奏效
	for _, k := range []Kind{DialTimeout, DialRefused, Canceled, Other, None} {
		if k.Reachable() {
			t.Errorf("%v 不该算可达", k)
		}
	}
	// 连接建立过的失败：才轮到分片 / TLS 终止层
	for _, k := range []Kind{Reset, ReadTimeout, TLSAlert, Write, Apply} {
		if !k.Reachable() {
			t.Errorf("%v 应算可达", k)
		}
	}
}

func TestLabelIsDisplayOnly(t *testing.T) {
	// Label 只用于打印；判等走 Kind 本身。
	if DialTimeout.Label() != "拨号超时" {
		t.Fatalf("Label = %q", DialTimeout.Label())
	}
	if Kind(0) != None {
		t.Fatal("零值必须是 None")
	}
	// 类别要能稳定映射到同值（能当 map 键/group 证据用）
	m := map[Kind]int{None: 1, DialTimeout: 2, Reset: 3}
	if m[DialTimeout] != 2 {
		t.Fatal("Kind 不能稳定当 map 键")
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}
var _ = time.Second
