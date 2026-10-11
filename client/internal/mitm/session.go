package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// Terminate 用本地 CA 与客户端完成 TLS 握手，返回已解密的连接。
//
// pre 是此前已从客户端读到的字节（就是那个 ClientHello）——透明路径先抄了一份，
// 决定改走 MITM 时必须原样喂回 TLS 栈，否则握手会缺掉开头。
func (c *CA) Terminate(client net.Conn, pre []byte) (*tls.Conn, error) {
	rc := &replayConn{Conn: client, pre: pre}
	tc := tls.Server(rc, c.ServerConfig())
	if err := tc.Handshake(); err != nil {
		return nil, fmt.Errorf("mitm: 与客户端握手失败: %w", err)
	}
	return tc, nil
}

// replayConn 先吐 pre 里的字节，再转发底层连接。
type replayConn struct {
	net.Conn
	pre []byte
}

func (r *replayConn) Read(p []byte) (int, error) {
	if len(r.pre) > 0 {
		n := copy(p, r.pre)
		r.pre = r.pre[n:]
		return n, nil
	}
	return r.Conn.Read(p)
}

// DialECH 用 ECH 连到真实目标：拨 ip（一个可达的 Cloudflare 边缘），
// 内层 SNI 是 host，外层只露出 cloudflare-ech.com。
//
// 服务端拒绝 ECH 时（ECHRejectionError 带 RetryConfigList）用新配置重试一次。
func DialECH(ctx context.Context, ip, host string, echCfg []byte, timeout time.Duration) (*tls.Conn, error) {
	conn, err := DialECHOnce(ctx, ip, host, echCfg, timeout)
	if err == nil {
		return conn, nil
	}
	var rej *tls.ECHRejectionError
	if errors.As(err, &rej) && len(rej.RetryConfigList) > 0 {
		return DialECHOnce(ctx, ip, host, rej.RetryConfigList, timeout)
	}
	return nil, err
}

// Handshake 在一条已建立的连接上做 TLS 握手（echCfg 非空时启用 ECH）。
//
// 隧道与中继这两条路都需要它：通道另一端只是把字节转给目标的 443，TLS 得由
// 我们来说——把明文 HTTP 塞过去，对面只会回一个 400 或直接断开。
func Handshake(ctx context.Context, conn net.Conn, sni string, echCfg []byte, timeout time.Duration) (*tls.Conn, error) {
	cfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
	}
	if len(echCfg) > 0 {
		cfg.MinVersion = tls.VersionTLS13 // 用 ECH 时必须是 1.3
		cfg.EncryptedClientHelloConfigList = echCfg
	}
	tc := tls.Client(conn, cfg)
	if timeout > 0 {
		_ = tc.SetDeadline(time.Now().Add(timeout))
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	return tc, nil
}

// DialECHOnce 是 DialECH 的单次尝试。
func DialECHOnce(ctx context.Context, ip, host string, echCfg []byte, timeout time.Duration) (*tls.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, fmt.Errorf("mitm: 连边缘 %s 失败: %w", ip, err)
	}
	tc, err := Handshake(ctx, conn, host, echCfg, timeout)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("mitm: 上游握手失败(%s via %s): %w", host, ip, err)
	}
	return tc, nil
}
