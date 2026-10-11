//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || windows)

package desync

import "net"

// writeOOB 在其余平台上不可用；调用方收到 errOOBNotSupported 后退回普通写。
func writeOOB(conn net.Conn, data []byte, urgent byte) error {
	return errOOBNotSupported
}
