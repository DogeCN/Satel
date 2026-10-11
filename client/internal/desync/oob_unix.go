//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris

package desync

import (
	"net"

	"golang.org/x/sys/unix"
)

// writeOOB 用 send(MSG_OOB) 把 data 连同紧急字节一次发出。紧急字节是否进入对端
// 字节流取决于对端是否开了 SO_OOBINLINE——因此 oob 招法默认不出现在内置策略里。
func writeOOB(conn net.Conn, data []byte, urgent byte) error {
	rc, err := syscallConn(conn)
	if err != nil {
		return err
	}
	buf := make([]byte, len(data)+1)
	copy(buf, data)
	buf[len(data)] = urgent

	var inner error
	cerr := rc.Write(func(fd uintptr) bool {
		inner = unix.Send(int(fd), buf, unix.MSG_OOB)
		return inner != unix.EAGAIN && inner != unix.EWOULDBLOCK
	})
	if cerr != nil {
		return cerr
	}
	return inner
}
