package proxyip

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// 这一文件用**真实的本地 TLS/TCP 服务端**验证握手路径（区别于 bounded_test.go
// 的注入式调度测试）。dialOne 现在校验证书，所以服务端证书必须由测试信任根签发、
// 且 SAN 覆盖目标主机名——否则握手失败本身就是断言失败。

// TestRaceIsConcurrent 竞速而不是串行：全员挂起时总耗时约等于**一个**超时
// 加上错开量，而不是 N 个超时。
func TestRaceIsConcurrent(t *testing.T) {
	var addrs []string
	for i := 0; i < maxRaceBatch; i++ {
		a, stop := startHangServer(t)
		defer stop()
		addrs = append(addrs, a)
	}
	p := NewPool(addrs, nil)

	const timeout = 700 * time.Millisecond
	start := time.Now()
	if _, err := p.Dial(context.Background(), "example.com", 443, timeout); err == nil {
		t.Fatal("全部挂起，应失败")
	}
	el := time.Since(start)
	// 串行 = N×700ms；竞速 = 700ms + (N-1)×250ms 错开。
	serial := time.Duration(maxRaceBatch) * timeout
	if el > serial {
		t.Fatalf("疑似仍是串行：%d 条 × %v 耗时 %v", maxRaceBatch, timeout, el)
	}
}

// TestRaceLoserNotPenalised 竞速里被我们取消的落败者**不记失败**：它可能完全健康，
// 只是没跑赢。惩罚它会让排序被"谁起跑早"污染，坏中继反而排到好中继前面。
func TestRaceLoserNotPenalised(t *testing.T) {
	ca := newTestCA(t)
	winner, stopW := startTLSServer(t, ca)
	defer stopW()
	loser, stopL := startHangServer(t)
	defer stopL()

	p := NewPool([]string{winner, loser}, nil)
	p.SetTrust(ca.pool)
	conn, err := p.Dial(context.Background(), "example.com", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("有一条能握手成功，不该失败: %v", err)
	}
	conn.Close()

	if got := p.Order()[0]; got != winner {
		t.Fatalf("胜者应置顶, order=%v", p.Order())
	}
	if st := p.Stats()[loser]; st[1] != 0 {
		t.Fatalf("竞速落败者不该被记失败: %v", st)
	}
}

// TestRaceGenuineFailureCounted 与上一条相对：**真的连不上**的候选要记失败。
func TestRaceGenuineFailureCounted(t *testing.T) {
	ca := newTestCA(t)
	winner, stopW := startTLSServer(t, ca)
	defer stopW()

	p := NewPool([]string{"127.0.0.1:1", winner}, nil)
	p.SetTrust(ca.pool)
	conn, err := p.Dial(context.Background(), "example.com", 443, 2*time.Second)
	if err != nil {
		t.Fatalf("后位的中继应胜出: %v", err)
	}
	conn.Close()

	if st := p.Stats()["127.0.0.1:1"]; st[1] != 1 {
		t.Fatalf("连接被拒应记一次失败: %v", st)
	}
	if got := p.Order()[0]; got != winner {
		t.Fatalf("胜者应置顶, order=%v", p.Order())
	}
}

// TestDialVerifiesTargetCertificate 证书**必须校验**：这个握手就是到目标的
// 端到端 TLS（调用方在这条连接上直接转发已解密的客户端流量）。换上不被信任的
// 证书必须握手失败——这正是要防的中间人降级。
func TestDialVerifiesTargetCertificate(t *testing.T) {
	good := newTestCA(t)
	rogue := newTestCA(t)
	addr, stop := startTLSServer(t, rogue)
	defer stop()

	p := NewPool([]string{addr}, nil)
	p.SetTrust(good.pool) // 只信任 good，而服务端用的是 rogue 签的证书
	if _, err := p.Dial(context.Background(), "example.com", 443, 2*time.Second); err == nil {
		t.Fatal("不受信任的证书应握手失败")
	}
	if st := p.Stats()[addr]; st[1] != 1 {
		t.Fatalf("证书失败是真实失败，应记一次: %v", st)
	}
}

// TestDialRejectsWrongHostname SNI 填的是目标域名，证书也必须对得上目标域名。
func TestDialRejectsWrongHostname(t *testing.T) {
	ca := newTestCA(t)
	addr, stop := startTLSServer(t, ca)
	defer stop()

	p := NewPool([]string{addr}, nil)
	p.SetTrust(ca.pool)
	if _, err := p.Dial(context.Background(), "other.example", 443, 2*time.Second); err == nil {
		t.Fatal("主机名不匹配应握手失败")
	}
}

// testCA 是一把测试用的签发钥匙：签出一张覆盖 example.com 的服务端证书，
// 并把根装进信任池。
type testCA struct {
	cert tls.Certificate
	pool *x509.CertPool
	der  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "proxyip-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	// 服务端证书：SAN 覆盖 example.com，与拨号时用的 SNI 一致。
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"example.com"},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, leaf, &srvKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{
		cert: tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey},
		pool: pool,
		der:  srvDER,
	}
}

// startTLSServer 起一个本地 TLS 服务端：握手一定成功，之后吞掉字节。
func startTLSServer(t *testing.T, ca *testCA) (addr string, stop func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ca.cert}})
	if err != nil {
		t.Fatalf("起 TLS 服务端失败: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					if tc.Handshake() != nil {
						return
					}
				}
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// startHangServer 起一个只 accept、永不握手的 TCP 服务端：让 dialOne 卡到超时。
func startHangServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起挂起服务端失败: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				<-done
			}(c)
		}
	}()
	return ln.Addr().String(), func() { close(done); ln.Close() }
}
