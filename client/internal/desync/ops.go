package desync

import (
	"bytes"

	"satel/internal/flight"
	"satel/internal/strategy"
)

// cutPoint 计算 split 的切点（相对首段起点）。锚点找不到时退回段中点，再夹到
// [1, len-1] 内——两端都必须至少留 1 字节，否则这条策略退化成"没分片"。
func cutPoint(seg []byte, at string, pos int, proto string) int {
	if len(seg) < 2 {
		return 0
	}
	var base int
	switch at {
	case "sni":
		if s, _, ok := flight.SNIRange(seg); ok {
			base = s
		} else {
			base = len(seg) / 2
		}
	case "host":
		if s, _, ok := flight.HostRange(seg); ok {
			base = s
		} else {
			base = len(seg) / 2
		}
	case "mid":
		base = len(seg) / 2
	case "head":
		base = 0
	case "rand":
		base = pseudoRand(len(seg)) % len(seg)
	default:
		base = len(seg) / 2
	}
	cut := base + pos
	if cut < 1 {
		cut = 1
	}
	if cut > len(seg)-1 {
		cut = len(seg) - 1
	}
	return cut
}

// pseudoRand 用段长度做一个确定性的伪随机数，保证同输入同输出（便于测试与复现）。
func pseudoRand(n int) int {
	x := uint32(n)*2654435761 + 1
	x ^= x << 13
	x ^= x >> 17
	x ^= x << 5
	return int(x)
}

// doHostSplit 在 Host 值前插入 gap 个空格（服务端会 trim，无害），再强制在值的
// 中点切一刀，让阻断设备在单包里只看到半个主机名。
func (p *plan) doHostSplit(op strategy.Op) {
	if len(p.segs) == 0 {
		return
	}
	first := p.segs[0].data
	s, e, ok := flight.HostRange(first)
	if !ok {
		return
	}
	gap := int(op.Int("gap", 1))
	if gap < 0 {
		gap = 0
	}
	if gap > 0 {
		spaces := bytes.Repeat([]byte{' '}, gap)
		nf := make([]byte, 0, len(first)+gap)
		nf = append(nf, first[:s]...)
		nf = append(nf, spaces...)
		nf = append(nf, first[s:]...)
		first = nf
		p.segs[0].data = nf
		s += gap
		e += gap
	}
	mid := s + (e-s)/2
	if mid <= 0 || mid >= len(first) {
		return
	}
	head := first[:mid]
	rest := first[mid:]
	p.segs = append([]seg{
		{data: head, delay: p.segs[0].delay, oob: p.segs[0].oob},
		{data: rest},
	}, p.segs[1:]...)
}

// doCase 随机化 HTTP 头字段名的字母大小写（HTTP 头名大小写不敏感，语义不变），
// 让基于精确字节匹配的规则失效。请求行与头值不动。
func (p *plan) doCase(op strategy.Op) {
	if len(p.segs) == 0 {
		return
	}
	data := p.segs[0].data
	out := make([]byte, len(data))
	copy(out, data)
	rng := uint32(op.Int("seed", 0)) | 1
	for i := 0; i < len(out); {
		end := len(out)
		if nl := bytes.IndexByte(out[i:], '\n'); nl >= 0 {
			end = i + nl + 1
		}
		colon := -1
		for j := i; j < end; j++ {
			c := out[j]
			if c == ':' {
				colon = j
				break
			}
			if c == ' ' || c == '\t' || c == '\r' {
				break
			}
		}
		if colon > i {
			for j := i; j < colon; j++ {
				rng ^= rng << 13
				rng ^= rng >> 17
				rng ^= rng << 5
				if rng&1 == 1 {
					out[j] = upper(out[j])
				} else {
					out[j] = lower(out[j])
				}
			}
		}
		i = end
	}
	p.segs[0].data = out
}

func upper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 32
	}
	return c
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}
