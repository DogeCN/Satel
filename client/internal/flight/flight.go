// Package flight 负责两件事：从客户端连接里"抄下"首个飞行段，以及在这个飞行段
// 里定位 SNI / HTTP Host 的字节区间。所有偏移都是相对飞行段自身的，因为后面
// 我们原样发送这些字节，偏移不变。
package flight

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"time"
)

// ErrEmpty 表示对端在给出任何字节之前就断了。
var ErrEmpty = errors.New("flight: 对端未发送任何字节")

// maxFlight 是首段的上限。ClientHello 正常 200~2000 字节，HTTP 头更小；
// 超过这个量说明对端把大块数据当首段发了（例如明文大请求），不再等待。
const maxFlight = 16 * 1024

// Capture 读下首段：TLS 读到第一个完整 record，HTTP 读到空行。
// proto 为空时按内容自动判定（判不出则视为 raw，不做任何改写）。
// 返回 (首段, 尾段)；尾段是已经读到但不属于首段的字节，必须原样跟在后面发出。
// 超时或对端先关时，把已读到的全部当首段返回（尽力而为）。
func Capture(c net.Conn, proto string, timeout time.Duration) (flight, tail []byte, err error) {
	if timeout > 0 {
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		defer c.SetReadDeadline(time.Time{})
	}
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 4096)
	for {
		n, rerr := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if proto == "" {
				if p := Detect(buf); p != "" {
					proto = p
				} else if len(buf) >= 8 {
					proto = "raw" // 判不出协议：不做改写，直接转发
				}
			}
			if size, ok := flightSize(buf, proto); ok {
				return buf[:size], buf[size:], nil
			}
			if len(buf) >= maxFlight {
				return buf, nil, nil
			}
		}
		if rerr != nil {
			if len(buf) > 0 {
				return buf, nil, nil
			}
			return nil, nil, ErrEmpty
		}
	}
}

// flightSize 判断缓冲区里是否已有完整首段；有则返回其长度。
func flightSize(buf []byte, proto string) (int, bool) {
	switch proto {
	case "tls":
		if len(buf) < 5 {
			return 0, false
		}
		if buf[0] != 0x16 {
			// 不是握手记录（可能对端先发了别的），别无限等：整段当首段。
			return len(buf), true
		}
		recLen := int(buf[3])<<8 | int(buf[4])
		if recLen <= 0 || recLen > maxFlight {
			return len(buf), true
		}
		if len(buf) >= 5+recLen {
			return 5 + recLen, true
		}
		return 0, false
	case "http":
		if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
			return i + 4, true
		}
		if i := bytes.Index(buf, []byte("\n\n")); i >= 0 {
			return i + 2, true
		}
		return 0, false
	case "":
		return 0, false
	default:
		return len(buf), true
	}
}

// Detect 从已读到的前缀判断协议类型；判不出返回 ""。
func Detect(prefix []byte) string {
	if len(prefix) >= 3 && prefix[0] == 0x16 && prefix[1] == 0x03 {
		return "tls"
	}
	up := strings.ToUpper(string(prefix))
	for _, m := range []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ", "TRACE "} {
		if strings.HasPrefix(up, m) {
			return "http"
		}
	}
	return ""
}

// SNIRange 返回 ClientHello 里 SNI 主机名字节的 [start,end) 偏移；找不到返回 ok=false。
// 入参是完整的 TLS record（含 5 字节记录头）。
func SNIRange(record []byte) (int, int, bool) {
	if len(record) < 5+4 || record[0] != 0x16 {
		return 0, 0, false
	}
	recLen := int(record[3])<<8 | int(record[4])
	payload := record[5:]
	if recLen < len(payload) {
		payload = payload[:recLen]
	}
	// 握手头：type(1) + length(3)
	if len(payload) < 4 || payload[0] != 0x01 {
		return 0, 0, false
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	body := payload[4:]
	if hsLen < len(body) {
		body = body[:hsLen]
	}
	// 相对整个 record 的基准偏移
	base := 5 + 4
	// client_version(2) + random(32)
	p := 34
	if p >= len(body) {
		return 0, 0, false
	}
	// session_id
	sidLen := int(body[p])
	p += 1 + sidLen
	if p+2 > len(body) {
		return 0, 0, false
	}
	csLen := int(body[p])<<8 | int(body[p+1])
	p += 2 + csLen
	if p+1 > len(body) {
		return 0, 0, false
	}
	compLen := int(body[p])
	p += 1 + compLen
	if p+2 > len(body) {
		return 0, 0, false
	}
	extLen := int(body[p])<<8 | int(body[p+1])
	p += 2
	if p+extLen > len(body) {
		extLen = len(body) - p
	}
	exts := body[p : p+extLen]
	q := 0
	for q+4 <= len(exts) {
		etype := int(exts[q])<<8 | int(exts[q+1])
		elen := int(exts[q+2])<<8 | int(exts[q+3])
		q += 4
		if q+elen > len(exts) {
			break
		}
		if etype == 0x0000 { // server_name
			d := exts[q : q+elen]
			if len(d) < 5 {
				break
			}
			// list_len(2) name_type(1) name_len(2) name
			nameLen := int(d[3])<<8 | int(d[4])
			if 5+nameLen > len(d) {
				break
			}
			start := base + p + q + 5
			return start, start + nameLen, true
		}
		q += elen
	}
	return 0, 0, false
}

// HostRange 返回 HTTP 请求头里 Host 值的 [start,end) 偏移（已去掉首尾空白）；
// 找不到返回 ok=false。
func HostRange(head []byte) (int, int, bool) {
	lines := bytes.Split(head, []byte("\n"))
	off := 0
	for _, line := range lines {
		lineStart := off
		off += len(line) + 1
		trimmed := bytes.TrimRight(line, "\r")
		colon := bytes.IndexByte(trimmed, ':')
		if colon < 0 {
			continue
		}
		if !bytes.EqualFold(bytes.TrimSpace(trimmed[:colon]), []byte("host")) {
			continue
		}
		valStart := lineStart + colon + 1
		// 跳过冒号后的空白
		for valStart < lineStart+len(trimmed) && (head[valStart] == ' ' || head[valStart] == '\t') {
			valStart++
		}
		valEnd := lineStart + len(trimmed)
		for valEnd > valStart && (head[valEnd-1] == ' ' || head[valEnd-1] == '\t') {
			valEnd--
		}
		if valEnd <= valStart {
			return 0, 0, false
		}
		return valStart, valEnd, true
	}
	return 0, 0, false
}

// SyntheticClientHello 造一个最小但结构合法的 ClientHello record（SNI 可控）。
// 供 probe 自检与测试使用——它不是一个能真正完成握手的 ClientHello，但长度字段、
// 扩展布局都合法，足以让 SNI 解析器与分片逻辑按真实路径走一遍。
func SyntheticClientHello(sni string) []byte {
	name := []byte(sni)
	body := make([]byte, 0, 5+len(name))
	body = append(body, byte((len(name)+3)>>8), byte(len(name)+3)) // list_len
	body = append(body, 0x00)                                      // name_type
	body = append(body, byte(len(name)>>8), byte(len(name)))       // name_len
	body = append(body, name...)
	ext := []byte{0x00, 0x00, byte(len(body) >> 8), byte(len(body))}
	ext = append(ext, body...)

	hb := []byte{0x03, 0x03} // client_version
	hb = append(hb, bytes.Repeat([]byte{0xAB}, 32)...)
	hb = append(hb, 0x00)       // session_id_len
	hb = append(hb, 0x00, 0x02) // cipher_suites_len
	hb = append(hb, 0x13, 0x01)
	hb = append(hb, 0x01, 0x00) // compression
	hb = append(hb, byte(len(ext)>>8), byte(len(ext)))
	hb = append(hb, ext...)

	hs := []byte{0x01, byte(len(hb) >> 16), byte(len(hb) >> 8), byte(len(hb))}
	hs = append(hs, hb...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// decoyPool 是伪造段用的"无害 SNI"池。长度匹配靠截断/填充，因此取的都是常见短域名。
var decoyPool = []string{
	"www.bing.com",
	"www.apple.com",
	"www.amazon.com",
	"www.microsoft.com",
	"cdn.jsdelivr.net",
	"www.wikipedia.org",
}

// Decoy 复制 record 并把 SNI 换成一个等长的无害域名，用于 fake 招法。
// 长度必须一致，否则 ClientHello 的长度字段会失真——因此按原长度截断或补齐。
func Decoy(record []byte, seed int) ([]byte, bool) {
	start, end, ok := SNIRange(record)
	if !ok {
		return nil, false
	}
	n := end - start
	if n <= 0 {
		return nil, false
	}
	src := decoyPool[seed%len(decoyPool)]
	out := make([]byte, n)
	for i := range out {
		if i < len(src) {
			out[i] = src[i]
		} else {
			out[i] = 'a'
		}
	}
	cp := make([]byte, len(record))
	copy(cp, record)
	copy(cp[start:end], out)
	return cp, true
}
