package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"
)

func TestNewCA(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	c := ca.Cert()
	if !c.IsCA {
		t.Fatal("生成的证书不是 CA")
	}
	if c.Subject.CommonName != CAName {
		t.Fatalf("CN = %q, want %q", c.Subject.CommonName, CAName)
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CA 缺少签发权限")
	}
	if len(ca.der) == 0 {
		t.Fatal("DER 为空（装进信任区用的就是它）")
	}
	if c.SerialNumber.Sign() == 0 {
		t.Fatal("序列号为空")
	}
	// 每次生成的 CA 必须不同
	ca2, _ := NewCA()
	if ca2.Cert().SerialNumber.Cmp(c.SerialNumber) == 0 {
		t.Fatal("两次生成的 CA 序列号相同")
	}
}

func TestLeafForHost(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	lc, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if lc.Leaf == nil {
		t.Fatal("未解析叶证书")
	}
	if err := lc.Leaf.VerifyHostname("example.com"); err != nil {
		t.Fatalf("叶证书名字不符: %v", err)
	}
	// 链必须由本 CA 签发
	if err := lc.Leaf.CheckSignatureFrom(ca.Cert()); err != nil {
		t.Fatalf("叶证书不是本 CA 签发: %v", err)
	}
	// 缓存：同一 host 应返回同一个对象
	lc2, _ := ca.Leaf("example.com")
	if lc2 != lc {
		t.Fatal("叶证书未走缓存")
	}
	// 不同 host 必须是不同证书
	lc3, _ := ca.Leaf("other.com")
	if lc3.Leaf.SerialNumber.Cmp(lc.Leaf.SerialNumber) == 0 {
		t.Fatal("不同 host 复用了同一证书")
	}
}

// TestMITMRoundTrip 是最关键的测试：CA 终止客户端 TLS，客户端用本 CA 做根校验证书。
func TestMITMRoundTrip(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()

	go func() {
		defer server.Close()
		tc, err := ca.Terminate(server, nil)
		if err != nil {
			return
		}
		defer tc.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(tc, buf); err != nil {
			return
		}
		_, _ = tc.Write([]byte("PONG"))
	}()

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	cc := tls.Client(client, &tls.Config{ServerName: "example.com", RootCAs: pool})
	_ = cc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := cc.Handshake(); err != nil {
		t.Fatalf("客户端握手失败（证书未被信任？）: %v", err)
	}
	if got := cc.ConnectionState().PeerCertificates[0].Subject.CommonName; got != "example.com" {
		t.Fatalf("叶证书 CN = %q", got)
	}
	if _, err := cc.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(cc, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "PONG" {
		t.Fatalf("回显 = %q", got)
	}
}

// TestTerminateReplaysPre 验证 pre 里的字节被原样喂回 TLS 栈：
// 客户端先写 ClientHello，服务端在握手前已经"抄"走了它，再交给 Terminate。
func TestTerminateReplaysPre(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()

	// 客户端先发 ClientHello
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	cc := tls.Client(client, &tls.Config{ServerName: "replay.test", RootCAs: pool})
	go func() { _ = cc.Handshake() }()

	// 服务端先读走一段（模拟透明路径的 Capture）
	pre := make([]byte, 512)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := server.Read(pre)
	if err != nil || n == 0 {
		t.Fatalf("预读 ClientHello 失败: %v", err)
	}
	_ = server.SetReadDeadline(time.Time{})

	// 把抄到的字节喂回 Terminate
	tc, err := ca.Terminate(server, pre[:n])
	if err != nil {
		t.Fatalf("重放 ClientHello 后握手失败: %v", err)
	}
	defer tc.Close()
	if tc.ConnectionState().ServerName != "replay.test" {
		t.Fatalf("SNI = %q", tc.ConnectionState().ServerName)
	}
}
