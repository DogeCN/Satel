package flight

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestDetect(t *testing.T) {
	if got := Detect([]byte{0x16, 0x03, 0x01, 0x00}); got != "tls" {
		t.Fatalf("Detect(tls) = %q", got)
	}
	if got := Detect([]byte("GET / HTTP/1.1")); got != "http" {
		t.Fatalf("Detect(http) = %q", got)
	}
	if got := Detect([]byte("CONNECT x:443 HTTP/1.1")); got != "http" {
		t.Fatalf("Detect(connect) = %q", got)
	}
	if got := Detect([]byte{0x00, 0x01}); got != "" {
		t.Fatalf("Detect(unknown) = %q", got)
	}
}

func TestHostRange(t *testing.T) {
	head := []byte("GET / HTTP/1.1\r\nhOsT:   example.com:8080  \r\nAccept: */*\r\n\r\n")
	s, e, ok := HostRange(head)
	if !ok {
		t.Fatal("未找到 Host")
	}
	if got := string(head[s:e]); got != "example.com:8080" {
		t.Fatalf("Host = %q", got)
	}
}

func TestHostRangeMissing(t *testing.T) {
	if _, _, ok := HostRange([]byte("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n")); ok {
		t.Fatal("无 Host 却返回 ok")
	}
}

func TestDecoySameLength(t *testing.T) {
	ch := buildCH("example.com")
	start, end, ok := SNIRange(ch)
	if !ok {
		t.Fatal("未找到 SNI")
	}
	d, ok := Decoy(ch, 0)
	if !ok {
		t.Fatal("Decoy 失败")
	}
	if len(d) != len(ch) {
		t.Fatalf("Decoy 长度变了: %d -> %d", len(ch), len(d))
	}
	ds, de, _ := SNIRange(d)
	if de-ds != end-start {
		t.Fatalf("Decoy SNI 长度变了: %d -> %d", end-start, de-ds)
	}
	if bytes.Equal(d[ds:de], ch[start:end]) {
		t.Fatal("Decoy 未替换 SNI")
	}
	// 除 SNI 区间外其余字节必须一致
	if !bytes.Equal(d[:start], ch[:start]) || !bytes.Equal(d[end:], ch[end:]) {
		t.Fatal("Decoy 改动了 SNI 之外的字节")
	}
}

func TestCaptureTLS(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ch := buildCH("capture.example.com")
	go func() {
		// 一次写入：首段与尾段在同一 Read 里返回，才能验证 tail 切分。
		b.Write(append(append([]byte{}, ch...), []byte("EXTRA")...))
	}()
	fl, tail, err := Capture(a, "tls", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fl, ch) {
		t.Fatalf("首段不是完整 ClientHello: %d vs %d 字节", len(fl), len(ch))
	}
	if string(tail) != "EXTRA" {
		t.Fatalf("尾段 = %q", tail)
	}
}

func TestCaptureHTTP(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	head := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY")
	go func() { b.Write(head) }()
	fl, tail, err := Capture(a, "http", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(fl) != "GET / HTTP/1.1\r\nHost: x\r\n\r\n" {
		t.Fatalf("首段 = %q", fl)
	}
	if string(tail) != "BODY" {
		t.Fatalf("尾段 = %q", tail)
	}
}

func TestCaptureEmpty(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() { b.Close() }()
	if _, _, err := Capture(a, "tls", 200*time.Millisecond); err == nil {
		t.Fatal("对端未发字节应返回错误")
	}
}

// buildCH 造一个最小 ClientHello；委托给被测实现，测试本身不重复字节布局。
func buildCH(sni string) []byte { return SyntheticClientHello(sni) }
