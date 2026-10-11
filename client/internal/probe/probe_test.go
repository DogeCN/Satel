package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// tlsEcho 起一个读 5 字节回 PONG! 的 TLS 服务器。
func tlsEcho(t *testing.T) net.Listener {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"test.local"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
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

// fakeSocks5 起一个最小 SOCKS5 代理：只支持无认证 + CONNECT IPv4，随后裸转发。
func fakeSocks5(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				greet := make([]byte, 2)
				if _, err := io.ReadFull(c, greet); err != nil {
					return
				}
				if _, err := io.ReadFull(c, make([]byte, int(greet[1]))); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				head := make([]byte, 4)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				if head[3] != 0x01 {
					_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				addr := make([]byte, 6)
				if _, err := io.ReadFull(c, addr); err != nil {
					return
				}
				target := net.JoinHostPort(net.IP(addr[:4]).String(), itoa(int(binary.BigEndian.Uint16(addr[4:]))))
				up, err := net.DialTimeout("tcp", target, 3*time.Second)
				if err != nil {
					_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
				<-done
			}(c)
		}
	}()
	return ln
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestHandshakeThroughSocks5(t *testing.T) {
	echo := tlsEcho(t)
	defer echo.Close()
	socks := fakeSocks5(t)
	defer socks.Close()

	_, portStr, _ := net.SplitHostPort(echo.Addr().String())
	port := PortOf(portStr, 443)

	res := Run(context.Background(), "test.local", port, nil, Options{
		Timeout:   4 * time.Second,
		IP:        "127.0.0.1",
		Handshake: true,
		Socks5:    socks.Addr().String(),
	})
	if len(res) == 0 {
		t.Fatal("无结果")
	}
	if !res[0].OK {
		t.Fatalf("经 SOCKS5 的基线握手应成功: %v", res[0].Err)
	}
}

func TestDialSocks5Rejected(t *testing.T) {
	// 一个只会拒绝 CONNECT 的假代理
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.ReadFull(c, make([]byte, 3))
		c.Write([]byte{0x05, 0x00})
		io.ReadFull(c, make([]byte, 10))
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()
	if _, err := dialSocks5(context.Background(), ln.Addr().String(), "127.0.0.1", 443, time.Second); err == nil {
		t.Fatal("被拒的 CONNECT 应返回错误")
	}
}

func TestDialSocks5RejectsIPv6(t *testing.T) {
	if _, err := dialSocks5(context.Background(), "127.0.0.1:1", "::1", 443, time.Second); err == nil {
		t.Fatal("IPv6 目标应被拒绝")
	}
}

func TestPortOf(t *testing.T) {
	if PortOf("8443", 443) != 8443 {
		t.Fatal("合法端口解析失败")
	}
	if PortOf("x", 443) != 443 || PortOf("0", 443) != 443 || PortOf("99999", 443) != 443 {
		t.Fatal("非法端口应返回默认值")
	}
}

func TestRunSyntheticBaseline(t *testing.T) {
	echo := tlsEcho(t)
	defer echo.Close()
	_, portStr, _ := net.SplitHostPort(echo.Addr().String())
	port := PortOf(portStr, 443)
	// 合成 ClientHello 模式下，TLS 服务器会回一条 alert，算"有回包"
	res := Run(context.Background(), "test.local", port, nil, Options{
		Timeout: 3 * time.Second,
		IP:      "127.0.0.1",
	})
	if len(res) == 0 || !res[0].OK {
		t.Fatalf("合成模式基线应有回包: %+v", res)
	}
}
