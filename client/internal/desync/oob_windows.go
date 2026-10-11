//go:build windows

package desync

import (
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// writeOOB 用 WSASend(MSG_OOB) 把 data 连同紧急字节一次发出。Winsock 的语义与
// BSD 一致：紧急字节附加在 data 之后。
func writeOOB(conn net.Conn, data []byte, urgent byte) error {
	rc, err := syscallConn(conn)
	if err != nil {
		return err
	}
	buf := make([]byte, len(data)+1)
	copy(buf, data)
	buf[len(data)] = urgent
	wsabuf := windows.WSABuf{Len: uint32(len(buf)), Buf: &buf[0]}

	var inner error
	cerr := rc.Write(func(fd uintptr) bool {
		var n uint32
		inner = windows.WSASend(windows.Handle(fd), &wsabuf, 1, &n, windows.MSG_OOB, nil, nil)
		return inner != windows.WSAEWOULDBLOCK
	})
	if cerr != nil {
		return cerr
	}
	if inner != nil {
		if e, ok := inner.(syscall.Errno); ok && e == 0 {
			return nil
		}
		return inner
	}
	return nil
}
