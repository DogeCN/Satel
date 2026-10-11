// Package mitm 实现 Satel 的 TLS 终止层：启动时生成并安装本地 CA，关闭时移除，
// 运行期按 SNI 即时签发叶证书。
//
// 为什么必须有这一层：本网络里唯一有效的两类技巧——ECH（隐藏 SNI）与域名前置
// （换一个允许的 SNI）——都必须由**自己发起 TLS 握手**才能做到。透明包改写
// 架构原理上做不到。实测见 docs/findings.md 第四轮。
package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CAName 是根证书的 CN，也是从系统信任区移除时的依据。
const CAName = "Satel Local CA"

// leafTTL 是叶证书有效期。短一点，少留痕。
const leafTTL = 24 * time.Hour

// CA 是内存中的本地根证书 + 即时签发的叶证书缓存。
//
// 私钥只在内存里，从不落盘：CA 每次启动重新生成、退出即删，所以没有需要保护的
// 磁盘产物（对比 SniShaper 把 ca.key 明文放在 %APPDATA%）。
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte // 根证书 DER，用于装进信任区

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
	id    string // 装进信任区后的标识（Windows 上是指纹），用于精确移除
}

// NewCA 生成一个 ECDSA P-256 根证书。全部在内存里，不落盘。
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mitm: 生成 CA 私钥失败: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: CAName, Organization: []string{"Satel"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("mitm: 自签 CA 失败: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, der: der, leafs: map[string]*tls.Certificate{}}, nil
}

// Cert 返回根证书（测试与调用方校验用）。
func (c *CA) Cert() *x509.Certificate { return c.cert }

// ServerConfig 返回 MITM 服务端用的 tls.Config：按客户端 SNI 即时签发叶证书。
func (c *CA) ServerConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				return nil, fmt.Errorf("mitm: ClientHello 无 SNI")
			}
			return c.Leaf(host)
		},
	}
}

// Leaf 返回（并缓存）host 的叶证书，由本 CA 签发。
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	if lc, ok := c.leafs[host]; ok {
		c.mu.Unlock()
		return lc, nil
	}
	c.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// 目标是 IP 字面量时（CONNECT 里直接给 IP 的场景）必须写进 IPAddresses，
	// 写 DNSNames 的话校验会失败。
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("mitm: 签发 %s 的叶证书失败: %w", host, err)
	}
	lc := &tls.Certificate{Certificate: [][]byte{der, c.der}, PrivateKey: key}
	// 附带解析后的叶证书，便于调用方读取（例如校验名字）。
	if leaf, err := x509.ParseCertificate(der); err == nil {
		lc.Leaf = leaf
	}

	c.mu.Lock()
	c.leafs[host] = lc
	c.mu.Unlock()
	return lc, nil
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("mitm: 生成序列号失败: %w", err)
	}
	return n, nil
}

// --- 开发通道：CA 落盘复用 -----------------------------------------------------
//
// Windows 对"装根证书"会弹一个确认对话框——每次启动都要人点一下，反复重启受不了。
// 所以提供一条**可选**的落盘复用通道：`--ca-file <path>` 把 CA 存进文件，下次直接
// 复用，只在第一次装。不给这个 flag 就是严格零落盘（每次装、退出即删），这也是默认。

// Save 把 CA 的证书与私钥写入 path。父目录不存在时自动建。
func (c *CA) Save(path string) error {
	keyDER, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return fmt.Errorf("mitm: 序列化 CA 私钥失败: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mitm: 建 CA 目录失败: %w", err)
		}
	}
	buf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return fmt.Errorf("mitm: 写 CA 文件失败: %w", err)
	}
	return nil
}

// DefaultPath 是 `remove-ca` 在没给 --ca-file 时清理的位置：项目内的 .lab/
// （已 gitignore）。serve 默认**不**用它——默认零落盘。
func DefaultPath() string {
	return filepath.Join(".lab", "dev-ca.pem")
}

// LoadOrCreate 从 path 载入 CA；文件不存在时新建并写回。
// created 为真表示这是新生成的，调用方需要把它装进信任区。
func LoadOrCreate(path string) (ca *CA, created bool, err error) {
	data, rerr := os.ReadFile(path)
	if rerr == nil {
		certBlock, rest := pem.Decode(data)
		keyBlock, _ := pem.Decode(rest)
		if certBlock == nil || keyBlock == nil {
			return nil, false, fmt.Errorf("mitm: CA 文件格式不对: %s", path)
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, false, fmt.Errorf("mitm: 解析 CA 证书失败: %w", err)
		}
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, false, fmt.Errorf("mitm: 解析 CA 私钥失败: %w", err)
		}
		return &CA{cert: cert, key: key, der: certBlock.Bytes, leafs: map[string]*tls.Certificate{}}, false, nil
	}
	if !os.IsNotExist(rerr) {
		return nil, false, fmt.Errorf("mitm: 读 CA 文件失败: %w", rerr)
	}
	fresh, err := NewCA()
	if err != nil {
		return nil, false, err
	}
	if err := fresh.Save(path); err != nil {
		return nil, false, err
	}
	return fresh, true, nil
}
