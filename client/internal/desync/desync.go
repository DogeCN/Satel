// Package desync 是策略执行器（"策略 VM"）：把一条 strategy.Spec 编译成一串
// 待发送的分段，然后按序（带间隔）写出去。
//
// 核心约束：**普通套接字上写出的字节会推进 TCP 序列号**。因此只有那些"不改变
// 字节流语义"的招法能在用户态后端实现——重分片（split/tlsrf）、带外字节（oob）、
// 以及内容等价改写（hostsplit/case）。dup / fake / disorder 必须在同一序列号上
// 注入报文，只有原始套接字或驱动后端才成立，用户态后端遇到它们会标记为不支持。
package desync

import (
	"errors"
	"fmt"
	"net"
	"time"

	"satel/internal/strategy"
)

// Raw 是特权后端的扩展点。为 nil 时 dup / fake / disorder 一律记为不支持。
// 本构建不附带实现——没有原始套接字就拿不到对端序列号，硬做只会写坏字节流。
type Raw interface {
	// Inject 在同一序列号上注入一段报文（伪造段或乱序段）。
	Inject(conn net.Conn, payload []byte, ttl int, gap time.Duration) error
}

// SupportedOps 返回用户态后端真正能执行的招法名，用于向 Worker 声明能力（caps）。
func SupportedOps() []string {
	return []string{"split", "tlsrf", "oob", "hostsplit", "case"}
}

// Options 控制执行。
type Options struct {
	Raw   Raw
	Sleep func(time.Duration) // 便于测试；nil 用 time.Sleep
}

// Result 是一次执行的账。
type Result struct {
	Bytes       int      // 实际写出的字节数
	Segments    int      // 实际写出的分段数
	Unsupported []string // 因后端能力缺失被跳过的招法
}

// errOOBNotSupported 由平台实现返回：该平台/连接无法发 MSG_OOB。
var errOOBNotSupported = errors.New("desync: MSG_OOB unsupported")

// seg 是一个待发送分段。
type seg struct {
	data  []byte
	delay time.Duration // 发送本段之前等待
	oob   bool          // 本段用 MSG_OOB 发出（仅第一段有意义）
}

// plan 是编译结果。
type plan struct {
	segs    []seg
	unsup   []string
	oobByte byte
}

// Apply 把 spec 作用在首段上并写出，随后原样写出尾段。
func Apply(conn net.Conn, spec *strategy.Spec, flight, tail []byte, opt Options) (Result, error) {
	p := buildPlan(spec, flight, opt)
	res := Result{Unsupported: p.unsup}
	sleep := opt.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	for i, s := range p.segs {
		if s.delay > 0 {
			sleep(s.delay)
		}
		var err error
		if s.oob && i == 0 {
			err = writeOOB(conn, s.data, p.oobByte)
			if errors.Is(err, errOOBNotSupported) {
				err = writeAll(conn, s.data)
			}
		} else {
			err = writeAll(conn, s.data)
		}
		if err != nil {
			return res, fmt.Errorf("desync: 写第 %d 段: %w", i, err)
		}
		res.Bytes += len(s.data)
		res.Segments++
	}
	if len(tail) > 0 {
		if err := writeAll(conn, tail); err != nil {
			return res, fmt.Errorf("desync: 写尾段: %w", err)
		}
		res.Bytes += len(tail)
	}
	return res, nil
}

// buildPlan 按 ops 顺序编译。导出为包内函数以便单测直接检查分段结果。
func buildPlan(spec *strategy.Spec, flight []byte, opt Options) *plan {
	p := &plan{}
	if len(flight) > 0 {
		// 复制一份，后续改写（hostsplit/case）不污染调用方缓冲。
		first := make([]byte, len(flight))
		copy(first, flight)
		p.segs = []seg{{data: first}}
	}
	for _, op := range spec.Ops {
		switch op.Name {
		case "split":
			p.doSplit(op, spec.Proto)
		case "tlsrf":
			p.doTLSRF(op)
		case "oob":
			p.doOOB(op)
		case "hostsplit":
			p.doHostSplit(op)
		case "case":
			p.doCase(op)
		case "dup", "fake", "disorder":
			// 特权招法：用户态后端无法在不推进序列号的前提下注入。
			if opt.Raw == nil {
				p.unsup = append(p.unsup, op.Name)
			}
		default:
			p.unsup = append(p.unsup, op.Name)
		}
	}
	return p
}

func (p *plan) doOOB(op strategy.Op) {
	if len(p.segs) == 0 {
		return
	}
	p.segs[0].oob = true
	p.oobByte = byte(op.Int("byte", 0))
}

// doSplit 把第一段在锚点处切开，再按 len/count 细分后半部分。
func (p *plan) doSplit(op strategy.Op, proto string) {
	if len(p.segs) == 0 {
		return
	}
	first := p.segs[0].data
	cut := cutPoint(first, op.Str("at", "sni"), int(op.Int("pos", 1)), proto)
	if cut <= 0 || cut >= len(first) {
		return
	}
	pieceLen := int(op.Int("len", 1))
	if pieceLen < 1 {
		pieceLen = 1
	}
	count := int(op.Int("count", 2))
	if count < 1 {
		count = 1
	}
	delay := ms(op.Int("delay_ms", 8))

	head := first[:cut]
	rest := first[cut:]
	out := []seg{{data: head, delay: p.segs[0].delay, oob: p.segs[0].oob}}
	for i := 0; i < count && len(rest) > 0; i++ {
		n := len(rest)
		if i < count-1 && n > pieceLen {
			n = pieceLen
		}
		out = append(out, seg{data: rest[:n], delay: delay})
		rest = rest[n:]
	}
	p.segs = append(out, p.segs[1:]...)
}

// doTLSRF 把第一段（一个 TLS record）的负载重新切成 chunk 字节的多个 record。
// 这在 TLS 层是合法的：一个握手消息允许跨多个 record。
func (p *plan) doTLSRF(op strategy.Op) {
	if len(p.segs) == 0 {
		return
	}
	first := p.segs[0].data
	if len(first) < 5 || first[0] != 0x16 {
		return
	}
	recLen := int(first[3])<<8 | int(first[4])
	if recLen <= 0 || 5+recLen > len(first) {
		recLen = len(first) - 5
	}
	if recLen <= 0 {
		return
	}
	payload := first[5 : 5+recLen]
	ver := first[1:3]

	chunk := int(op.Int("chunk", 8))
	if chunk < 1 {
		chunk = 1
	}
	limit := int(op.Int("limit", 400))
	if limit <= 0 || limit > len(payload) {
		limit = len(payload)
	}
	delay := ms(op.Int("delay_ms", 8))

	head := payload[:limit]
	rest := payload[limit:]

	var out []seg
	for i := 0; i < len(head); i += chunk {
		end := i + chunk
		if end > len(head) {
			end = len(head)
		}
		d := time.Duration(0)
		if len(out) > 0 {
			d = delay
		}
		out = append(out, seg{data: makeRecord(ver, head[i:end]), delay: d})
	}
	if len(rest) > 0 {
		out = append(out, seg{data: makeRecord(ver, rest), delay: delay})
	}
	if len(out) == 0 {
		return
	}
	out[0].oob = p.segs[0].oob
	p.segs = append(out, p.segs[1:]...)
}

func makeRecord(ver []byte, payload []byte) []byte {
	rec := make([]byte, 5+len(payload))
	rec[0] = 0x16
	rec[1] = ver[0]
	rec[2] = ver[1]
	rec[3] = byte(len(payload) >> 8)
	rec[4] = byte(len(payload))
	copy(rec[5:], payload)
	return rec
}

func ms(n int64) time.Duration {
	if n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Millisecond
}

func writeAll(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("desync: 写入 0 字节")
		}
		b = b[n:]
	}
	return nil
}
