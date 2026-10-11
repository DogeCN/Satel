package desync

import (
	"net"
	"syscall"
)

// syscallConn 取出连接的 syscall.RawConn；拿不到（类型不支持或系统调用失败）时
// 返回 errOOBNotSupported，调用方退回普通写。
func syscallConn(c net.Conn) (syscall.RawConn, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil, errOOBNotSupported
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil, errOOBNotSupported
	}
	return rc, nil
}
