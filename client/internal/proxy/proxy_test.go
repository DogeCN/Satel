package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"satel/internal/engine"
)

func selfSigned(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{host},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSServer 起一个只做"读 5 字节、回 PONG!"的 TLS 服务器。
func startTLSServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t, "test.local")}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 5)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				_, _ = c.Write([]byte("PONG!"))
			}(c)
		}
	}()
	return ln
}

func startProxy(t *testing.T) (*Server, net.Listener, *engine.Engine) {
	t.Helper()
	eng := engine.New(nil)
	srv := New(eng)
	srv.ProbeWait = 3 * time.Second
	srv.CaptureWait = 5 * time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	return srv, ln, eng
}

// socks5Connect 走一遍 SOCKS5 握手并返回已连通的原始连接。
func socks5Connect(t *testing.T, proxyAddr, host string, port int) net.Conn {
	t.Helper()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(raw, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("SOCKS5 方法协商失败: % x", resp)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, net.ParseIP(host).To4()...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := raw.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(raw, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT 被拒: % x", rep)
	}
	return raw
}

// TestProxyTLSRoundTrip 是最关键的端到端：真实 ClientHello 经分片后仍能完成握手。
func TestProxyTLSRoundTrip(t *testing.T) {
	tlsLn := startTLSServer(t)
	defer tlsLn.Close()
	_, pln, eng := startProxy(t)
	defer pln.Close()

	_, portStr, _ := net.SplitHostPort(tlsLn.Addr().String())
	port, _ := strconv.Atoi(portStr)

	raw := socks5Connect(t, pln.Addr().String(), "127.0.0.1", port)
	defer raw.Close()

	tc := tls.Client(raw, &tls.Config{ServerName: "test.local", InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("经分片代理的 TLS 握手失败: %v", err)
	}
	if _, err := tc.Write([]byte("PING!")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(tc, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "PONG!" {
		t.Fatalf("回显 = %q, want PONG!", got)
	}

	// 引擎应记住这个主机用过某个可行方法
	hosts, _ := eng.Stats()
	if hosts < 1 {
		t.Fatalf("引擎未建立记忆条目: hosts=%d", hosts)
	}
	if eng.TopMethodFor("127.0.0.1") == "" {
		t.Fatal("引擎未记住任何可行方法")
	}
}

// TestProxyFreshHostTriesDirectFirst 验证新 host 的默认顺序里直接直连排在最前。
func TestProxyFreshHostTriesDirectFirst(t *testing.T) {
	tlsLn := startTLSServer(t)
	defer tlsLn.Close()
	_, pln, eng := startProxy(t)
	defer pln.Close()

	_, portStr, _ := net.SplitHostPort(tlsLn.Addr().String())
	port, _ := strconv.Atoi(portStr)

	raw := socks5Connect(t, pln.Addr().String(), "127.0.0.1", port)
	defer raw.Close()

	tc := tls.Client(raw, &tls.Config{ServerName: "test.local", InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("明文直连路径握手失败: %v", err)
	}
	hosts, _ := eng.Stats()
	if hosts < 1 {
		t.Fatalf("引擎未建立记忆条目: hosts=%d", hosts)
	}
	if got := eng.TopMethodFor("127.0.0.1"); got != engine.MethodDirect {
		t.Fatalf("明文直连路径应记住 direct, got %q", got)
	}
}

// TestProxyHTTPConnect 验证 HTTP CONNECT 入口与纯 TCP 转发。
func TestProxyHTTPConnect(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()

	_, pln, _ := startProxy(t)
	defer pln.Close()

	raw, err := net.Dial("tcp", pln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_, echoPort, _ := net.SplitHostPort(echo.Addr().String())
	if _, err := raw.Write([]byte("CONNECT 127.0.0.1:" + echoPort + " HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 39)
	if _, err := io.ReadFull(raw, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf[:12]) != "HTTP/1.1 200" {
		t.Fatalf("CONNECT 应答 = %q", buf[:12])
	}
	// 回显
	if _, err := raw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(raw, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("回显 = %q", got)
	}
}

// TestProxyUnreachableTargetFails 验证目标不可达时优雅失败（不 panic、不挂死）。
func TestProxyUnreachableTargetFails(t *testing.T) {
	// 关掉的端口：先占再放
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(tmp.Addr().String())
	tmp.Close()
	port, _ := strconv.Atoi(portStr)

	_, pln, _ := startProxy(t)
	defer pln.Close()

	raw := socks5Connect(t, pln.Addr().String(), "127.0.0.1", port)
	defer raw.Close()
	_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := raw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := raw.Read(buf); err == nil {
		t.Fatal("目标不可达时不应有数据返回")
	}
}

func TestIsTLSAlert(t *testing.T) {
	alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}
	if !isTLSAlert(alert) {
		t.Fatal("TLS 告警记录未被识别")
	}
	if isTLSAlert([]byte{0x16, 0x03, 0x01, 0x00, 0x05}) {
		t.Fatal("握手记录被误判为告警")
	}
	if isTLSAlert([]byte("HTTP/1.1 200 OK\r\n")) {
		t.Fatal("明文 HTTP 被误判为告警")
	}
	if isTLSAlert(nil) || isTLSAlert([]byte{0x15}) {
		t.Fatal("过短的输入被误判")
	}
}
