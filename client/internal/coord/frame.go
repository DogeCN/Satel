// Package coord 的帧层：客户端与协调端之间唯一的线格式。
//
//	frame = [ opcode:1 ][ id:4 BE ][ payload ]
//
// payload 是 WS 消息的剩余全部字节——WS 是消息导向的，长度由 WS 层给出，
// 所以帧里不需要 magic、不需要 version、不需要 length。
//
// 本文件只有纯函数：编解码与常量。两侧（Go 客户端与 Worker）必须逐字节一致。
package coord

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// opcode 取值。控制面用 reqID，隧道面用 streamID——两者共用 4 字节空间，
// 但按 opcode 分派到不同的表（pending vs streams），因此不会冲突。
type opcode byte

const (
	opHello      opcode = 1  // C→S  id=0
	opStatus     opcode = 2  // S→C  id=reqID
	opBundle     opcode = 3  // C→S  id=reqID
	opBundleResp opcode = 4  // S→C  id=reqID
	opReport     opcode = 5  // C→S  id=reqID
	opReportResp opcode = 6  // S→C  id=reqID
	opEvolve     opcode = 7  // C→S  id=reqID
	opEvolveResp opcode = 8  // S→C  id=reqID
	opOpen       opcode = 9  // C→S  id=streamID
	opOpened     opcode = 10 // S→C  id=streamID
	opData       opcode = 11 // 双向 id=streamID
	opClose      opcode = 12 // 双向 id=streamID
)

// STATUS.code 取值。
const (
	statusOK       byte = 0
	statusAuthFail byte = 1
	statusBadParam byte = 2
	statusUpstream byte = 3
	statusDenied   byte = 4
)

// OPENED.code：0 成功，非 0 失败。
const (
	openOK   byte = 0
	openFail byte = 1
)

// 协议上限。两侧共用这些常量，改动必须同步。
const (
	maxFP       = 255   // fp_len 是 1 字节
	maxCaps     = 255   // caps_len 是 1 字节
	maxHostLen  = 65535 // host_len 是 2 字节
	maxSpecLen  = 65535 // spec_len 是 2 字节
	maxReportN  = 256   // 与 Worker 的 MAX_REPORT_ITEMS 一致
	maxBundleN  = 32    // 与 Worker 的 n 上限一致
	sidLen      = 8     // 策略 ID：hex(sha256(canonical))[:8]
	authLen     = 32    // HMAC-SHA256 前 32 个 hex 字符
	frameHeader = 5     // opcode(1) + id(4)

	// REPORT 条目里三个变长字段的上限（长度前缀都是 1 字节）。
	maxHostName  = 253 // DNS 名上限
	maxMethodLen = 32  // "@proxyip" 或 8 位策略 ID
	maxKindLen   = 16  // failkind.Key() 最长是 "dialtimeout"(12)
	maxProtoLen  = 8   // "tls" / "http"
	batchIDLen   = 32  // 幂等键：16 字节 hex
	maxHintN     = 128 // BUNDLE_RESP 里后缀经验的上限，与服务端一致

	// protocolVersion 是 HELLO 尾部的版本字节：v2 起带 method 级回报与 hints。
	// 缺失或不等 = 旧/错版本客户端，明确拒绝而不是静默按旧语义解。
	protocolVersion = 2
)

var errShort = errors.New("coord: 帧长度不足")

// frame 是一条解出的帧。
type frame struct {
	op   opcode
	id   uint32
	data []byte
}

// encodeFrame 拼一条帧。
func encodeFrame(op opcode, id uint32, payload []byte) []byte {
	out := make([]byte, frameHeader+len(payload))
	out[0] = byte(op)
	binary.BigEndian.PutUint32(out[1:5], id)
	copy(out[frameHeader:], payload)
	return out
}

// decodeFrame 拆一条帧。payload 是原缓冲的切片，调用方不要再改它。
func decodeFrame(b []byte) (frame, error) {
	if len(b) < frameHeader {
		return frame{}, errShort
	}
	return frame{
		op:   opcode(b[0]),
		id:   binary.BigEndian.Uint32(b[1:5]),
		data: b[frameHeader:],
	}, nil
}

// --- 小工具 ---------------------------------------------------------------

// cursor 是带边界检查的读游标。所有 decode 都走它，保证不 panic。
type cursor struct{ b []byte }

func (c *cursor) u8() (byte, error) {
	if len(c.b) < 1 {
		return 0, errShort
	}
	v := c.b[0]
	c.b = c.b[1:]
	return v, nil
}

func (c *cursor) u16() (uint16, error) {
	if len(c.b) < 2 {
		return 0, errShort
	}
	v := binary.BigEndian.Uint16(c.b)
	c.b = c.b[2:]
	return v, nil
}

func (c *cursor) u32() (uint32, error) {
	if len(c.b) < 4 {
		return 0, errShort
	}
	v := binary.BigEndian.Uint32(c.b)
	c.b = c.b[4:]
	return v, nil
}

func (c *cursor) u64() (uint64, error) {
	if len(c.b) < 8 {
		return 0, errShort
	}
	v := binary.BigEndian.Uint64(c.b)
	c.b = c.b[8:]
	return v, nil
}

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || len(c.b) < n {
		return nil, errShort
	}
	v := c.b[:n]
	c.b = c.b[n:]
	return v, nil
}

// lenBytes 读一个 1 字节长度前缀再读对应字节，返回字符串。
func (c *cursor) lenBytes1() (string, error) {
	n, err := c.u8()
	if err != nil {
		return "", err
	}
	b, err := c.take(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// lenBytes2 读一个 2 字节长度前缀再读对应字节，返回字符串。
func (c *cursor) lenBytes2() (string, error) {
	n, err := c.u16()
	if err != nil {
		return "", err
	}
	b, err := c.take(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// str1 读一个 1 字节长度前缀的字符串，并限制最大长度（长度前缀本身只有 1 字节，
// 所以这里防的是"字段比预期长"，不是防越界——越界由 take 挡）。
func (c *cursor) str1(max int) (string, error) {
	s, err := c.lenBytes1()
	if err != nil {
		return "", err
	}
	if len(s) > max {
		return "", fmt.Errorf("coord: 字段长度 %d 超过上限 %d", len(s), max)
	}
	return s, nil
}

// rest 返回剩余全部字节（不拷贝）。
func (c *cursor) rest() []byte { return c.b }

// --- HELLO (1) ------------------------------------------------------------

// helloPayload = ts(8) + auth(32) + fp_len(1)+fp + caps_len(1)+caps
func encodeHello(ts int64, auth, fp string, caps []string) []byte {
	capsStr := strings.Join(caps, ",")
	out := make([]byte, 0, 8+authLen+1+len(fp)+1+len(capsStr)+1)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(ts))
	out = append(out, buf[:]...)
	out = append(out, auth...)
	out = append(out, byte(len(fp)))
	out = append(out, fp...)
	out = append(out, byte(len(capsStr)))
	out = append(out, capsStr...)
	// 尾字节 = 协议版本。这是**刻意**的版本探针：只此一个方向（HELLO 只有 C→S），
	// 但足够——老客户端连新服务端会被这个字节的存在本身拒绝，新客户端连老服务端
	// 则老服务端因下面的 expectEnd 拒绝。宁可明确失败，不要静默语义漂移。
	out = append(out, protocolVersion)
	return out
}

func decodeHello(b []byte) (ts int64, auth, fp string, caps []string, err error) {
	c := &cursor{b}
	u, err := c.u64()
	if err != nil {
		return 0, "", "", nil, err
	}
	a, err := c.take(authLen)
	if err != nil {
		return 0, "", "", nil, err
	}
	f, err := c.lenBytes1()
	if err != nil {
		return 0, "", "", nil, err
	}
	cs, err := c.lenBytes1()
	if err != nil {
		return 0, "", "", nil, err
	}
	// 尾字节必须是协议版本。缺失 = 老客户端，明确拒绝。
	v, err := c.u8()
	if err != nil {
		return 0, "", "", nil, fmt.Errorf("coord: HELLO 缺少协议版本字节: %w", err)
	}
	if v != protocolVersion {
		return 0, "", "", nil, fmt.Errorf("coord: HELLO 协议版本 %d, 期望 %d", v, protocolVersion)
	}
	if len(c.rest()) != 0 {
		return 0, "", "", nil, fmt.Errorf("coord: HELLO 有 %d 字节尾随数据", len(c.rest()))
	}
	if cs != "" {
		caps = strings.Split(cs, ",")
	}
	return int64(u), string(a), f, caps, nil
}

// --- BUNDLE (3) / BUNDLE_RESP (4) ----------------------------------------

// bundlePayload = proto_len(1)+proto + n(1)
func encodeBundle(proto string, n int) []byte {
	out := make([]byte, 0, 2+len(proto))
	out = append(out, byte(len(proto)))
	out = append(out, proto...)
	out = append(out, byte(n))
	return out
}

func decodeBundle(b []byte) (proto string, n int, err error) {
	c := &cursor{b}
	p, err := c.lenBytes1()
	if err != nil {
		return "", 0, err
	}
	nn, err := c.u8()
	if err != nil {
		return "", 0, err
	}
	if len(c.rest()) != 0 {
		return "", 0, fmt.Errorf("coord: BUNDLE 有 %d 字节尾随数据", len(c.rest()))
	}
	return p, int(nn), nil
}

// bundleEntry 是下发的一条策略。
type bundleEntry struct {
	id   string // 8 hex
	spec string
}

// hintEntry 是 BUNDLE_RESP 末尾的一条后缀经验。见 engine.Memory.SetHints。
type hintEntry struct {
	suffix  string
	method  string
	ok      uint32
	fail    uint32
	hosts   uint32
	expires uint64
}

// bundleRespPayload = version(4) + count(1) + 重复{ id(8) + spec_len(2)+spec }
func encodeBundleResp(version int, items []bundleEntry, hints []hintEntry) ([]byte, error) {
	if len(items) > 255 {
		return nil, fmt.Errorf("coord: bundle 条目 %d 超过 255", len(items))
	}
	if len(hints) > maxHintN {
		return nil, fmt.Errorf("coord: 后缀经验 %d 超过 %d", len(hints), maxHintN)
	}
	out := make([]byte, 0, 5)
	var vb [4]byte
	binary.BigEndian.PutUint32(vb[:], uint32(version))
	out = append(out, vb[:]...)
	out = append(out, byte(len(items)))
	for _, it := range items {
		if len(it.id) != sidLen {
			return nil, fmt.Errorf("coord: 策略 ID %q 不是 %d 位", it.id, sidLen)
		}
		if len(it.spec) > maxSpecLen {
			return nil, fmt.Errorf("coord: spec 过长 (%d)", len(it.spec))
		}
		out = append(out, it.id...)
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(it.spec)))
		out = append(out, lb[:]...)
		out = append(out, it.spec...)
	}
	var hn [2]byte
	binary.BigEndian.PutUint16(hn[:], uint16(len(hints)))
	out = append(out, hn[:]...)
	for _, h := range hints {
		if h.suffix == "" || len(h.suffix) > maxHostName {
			return nil, fmt.Errorf("coord: 后缀 %q 长度非法", h.suffix)
		}
		if h.method == "" || len(h.method) > maxMethodLen {
			return nil, fmt.Errorf("coord: 方法 %q 长度非法", h.method)
		}
		out = append(out, byte(len(h.suffix)))
		out = append(out, h.suffix...)
		out = append(out, byte(len(h.method)))
		out = append(out, h.method...)
		var n4 [4]byte
		binary.BigEndian.PutUint32(n4[:], h.ok)
		out = append(out, n4[:]...)
		binary.BigEndian.PutUint32(n4[:], h.fail)
		out = append(out, n4[:]...)
		binary.BigEndian.PutUint32(n4[:], h.hosts)
		out = append(out, n4[:]...)
		var n8 [8]byte
		binary.BigEndian.PutUint64(n8[:], h.expires)
		out = append(out, n8[:]...)
	}
	return out, nil
}

func decodeBundleResp(b []byte) (version int, items []bundleEntry, hints []hintEntry, err error) {
	c := &cursor{b}
	v, err := c.u32()
	if err != nil {
		return 0, nil, nil, err
	}
	n, err := c.u8()
	if err != nil {
		return 0, nil, nil, err
	}
	items = make([]bundleEntry, 0, n)
	for i := 0; i < int(n); i++ {
		id, err := c.take(sidLen)
		if err != nil {
			return 0, nil, nil, err
		}
		spec, err := c.lenBytes2()
		if err != nil {
			return 0, nil, nil, err
		}
		items = append(items, bundleEntry{id: string(id), spec: spec})
	}
	// hints 是**可选尾巴**：老服务端不下发时这里就是帧尾，一个字都不剩。
	// 所以"没有 hints"必须是合法状态，不能当成截断错误。
	if len(c.rest()) == 0 {
		return int(v), items, nil, nil
	}
	hn, err := c.u16()
	if err != nil {
		return 0, nil, nil, err
	}
	if int(hn) > maxHintN {
		return 0, nil, nil, fmt.Errorf("coord: 后缀经验 %d 超过 %d", hn, maxHintN)
	}
	hints = make([]hintEntry, 0, hn)
	for i := 0; i < int(hn); i++ {
		suffix, err := c.str1(maxHostName)
		if err != nil {
			return 0, nil, nil, err
		}
		method, err := c.str1(maxMethodLen)
		if err != nil {
			return 0, nil, nil, err
		}
		ok, err := c.u32()
		if err != nil {
			return 0, nil, nil, err
		}
		fail, err := c.u32()
		if err != nil {
			return 0, nil, nil, err
		}
		hosts, err := c.u32()
		if err != nil {
			return 0, nil, nil, err
		}
		expires, err := c.u64()
		if err != nil {
			return 0, nil, nil, err
		}
		if suffix == "" || method == "" {
			return 0, nil, nil, fmt.Errorf("coord: 后缀经验字段为空")
		}
		hints = append(hints, hintEntry{
			suffix: suffix, method: method,
			ok: ok, fail: fail, hosts: hosts, expires: expires,
		})
	}
	if len(c.rest()) != 0 {
		return 0, nil, nil, fmt.Errorf("coord: BUNDLE_RESP 有 %d 字节尾随数据", len(c.rest()))
	}
	return int(v), items, hints, nil
}

// --- REPORT (5) / REPORT_RESP (6) ----------------------------------------

// reportEntry 是一条**方法级**效果回报。
//
// host 是**明文主机名**——用户明确要求直传。原先的 host_hash 挡不住反查（对已知
// 域名表逐个 sha256 就能反查明文），只是让人误以为有隐私，所以去掉了。
//
// method 是伪方法 ID（@direct/@ech/@tunnel/@proxyip）或 8 位策略 ID；kind 是失败
// 类别（failkind.Key()，成功为 "ok"）——它让协调端能区分"直连被复位"和"直连黑洞"，
// 这正是"把 GFW 黑名单长出来"所依赖的信号。
type reportEntry struct {
	host   string
	method string
	ok     bool
	unsup  bool
	rtt    uint32
	ts     uint64
	kind   string
	proto  string
}

// reportPayload = batchID(32) + count(2) + 重复{
//
//	host_len(1)+host + method_len(1)+method + flags(1) + rtt(4) + ts(8) + kind_len(1)+kind }
//
// flags：bit0 = ok，bit1 = unsup（未支持的策略）。
// reportEntryFixed 是条目里**定长**部分的字节数：host_len(1) + method_len(1) +
// flags(1) + rtt(4) + ts(8) + kind_len(1) + proto_len(1)。变长的是四个字段本体，
// 由调用方按实际长度另加。
const reportEntryFixed = 1 + 1 + 1 + 4 + 8 + 1 + 1

// encodeReport 把一批回报编码成帧载荷。batchID 是幂等键（32 字符）：客户端重连时
// 会重发同一批（protocol.md §3.4 的"请求类帧自动重发一次"），连接级去重覆盖不到
// 跨连接重发，没有它服务端无法分辨"同一批重发"与"新一批"，计数会双计。
func encodeReport(batchID string, items []reportEntry) ([]byte, error) {
	if len(batchID) != batchIDLen {
		return nil, fmt.Errorf("coord: batchID 必须是 %d 字符", batchIDLen)
	}
	if len(items) > maxReportN {
		return nil, fmt.Errorf("coord: 回报条目 %d 超过 %d", len(items), maxReportN)
	}
	out := make([]byte, 0, batchIDLen+2+len(items)*reportEntryFixed)
	out = append(out, batchID...)
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(len(items)))
	out = append(out, cnt[:]...)
	for _, it := range items {
		if it.host == "" || len(it.host) > maxHostName {
			return nil, fmt.Errorf("coord: 主机名长度非法: %q", it.host)
		}
		if it.method == "" || len(it.method) > maxMethodLen {
			return nil, fmt.Errorf("coord: 方法名长度非法: %q", it.method)
		}
		if it.kind == "" || len(it.kind) > maxKindLen {
			return nil, fmt.Errorf("coord: 失败类别长度非法: %q", it.kind)
		}
		if len(it.proto) > maxProtoLen {
			return nil, fmt.Errorf("coord: proto 长度非法: %q", it.proto)
		}
		var flags byte
		if it.ok {
			flags |= 1
		}
		if it.unsup {
			flags |= 2
		}
		out = append(out, byte(len(it.host)))
		out = append(out, it.host...)
		out = append(out, byte(len(it.method)))
		out = append(out, it.method...)
		out = append(out, flags)
		var r [4]byte
		binary.BigEndian.PutUint32(r[:], it.rtt)
		out = append(out, r[:]...)
		var t [8]byte
		binary.BigEndian.PutUint64(t[:], it.ts)
		out = append(out, t[:]...)
		out = append(out, byte(len(it.kind)))
		out = append(out, it.kind...)
		out = append(out, byte(len(it.proto)))
		out = append(out, it.proto...)
	}
	return out, nil
}

func decodeReport(b []byte) (string, []reportEntry, error) {
	c := &cursor{b}
	bid, err := c.take(batchIDLen)
	if err != nil {
		return "", nil, err
	}
	batchID := string(bid)
	n, err := c.u16()
	if err != nil {
		return "", nil, err
	}
	if int(n) > maxReportN {
		return "", nil, fmt.Errorf("coord: 回报条目 %d 超过 %d", n, maxReportN)
	}
	items := make([]reportEntry, 0, n)
	for i := 0; i < int(n); i++ {
		host, err := c.str1(maxHostName)
		if err != nil {
			return "", nil, err
		}
		method, err := c.str1(maxMethodLen)
		if err != nil {
			return "", nil, err
		}
		flags, err := c.u8()
		if err != nil {
			return "", nil, err
		}
		rtt, err := c.u32()
		if err != nil {
			return "", nil, err
		}
		ts, err := c.u64()
		if err != nil {
			return "", nil, err
		}
		kind, err := c.str1(maxKindLen)
		if err != nil {
			return "", nil, err
		}
		proto, err := c.str1(maxProtoLen)
		if err != nil {
			return "", nil, err
		}
		if host == "" || method == "" || kind == "" {
			return "", nil, fmt.Errorf("coord: 回报条目字段为空")
		}
		items = append(items, reportEntry{
			host: host, method: method,
			ok: flags&1 != 0, unsup: flags&2 != 0,
			rtt: rtt, ts: ts, kind: kind, proto: proto,
		})
	}
	if len(c.rest()) != 0 {
		return "", nil, fmt.Errorf("coord: REPORT 有 %d 字节尾随数据", len(c.rest()))
	}
	return batchID, items, nil
}

// --- EVOLVE (7) / EVOLVE_RESP (8) ----------------------------------------

// evolvePayload = key_len(1)+key
func encodeEvolve(key string) []byte {
	out := make([]byte, 0, 1+len(key))
	out = append(out, byte(len(key)))
	out = append(out, key...)
	return out
}

func decodeEvolve(b []byte) (string, error) {
	c := &cursor{b}
	k, err := c.lenBytes1()
	if err != nil {
		return "", err
	}
	if len(c.rest()) != 0 {
		return "", fmt.Errorf("coord: EVOLVE 有 %d 字节尾随数据", len(c.rest()))
	}
	return k, nil
}

// evolveRespPayload = generation(4)+born(4)+retired(4)+pool(4)
func encodeEvolveResp(generation, born, retired, pool int) []byte {
	out := make([]byte, 16)
	binary.BigEndian.PutUint32(out[0:], uint32(generation))
	binary.BigEndian.PutUint32(out[4:], uint32(born))
	binary.BigEndian.PutUint32(out[8:], uint32(retired))
	binary.BigEndian.PutUint32(out[12:], uint32(pool))
	return out
}

func decodeEvolveResp(b []byte) (generation, born, retired, pool int, err error) {
	c := &cursor{b}
	g, err := c.u32()
	if err != nil {
		return 0, 0, 0, 0, err
	}
	bo, err := c.u32()
	if err != nil {
		return 0, 0, 0, 0, err
	}
	r, err := c.u32()
	if err != nil {
		return 0, 0, 0, 0, err
	}
	p, err := c.u32()
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return int(g), int(bo), int(r), int(p), nil
}

// --- OPEN (9) / OPENED (10) ----------------------------------------------

// openPayload = host_len(2)+host + port(2)
func encodeOpen(host string, port int) ([]byte, error) {
	if len(host) > maxHostLen {
		return nil, fmt.Errorf("coord: host 过长 (%d)", len(host))
	}
	out := make([]byte, 0, 2+len(host)+2)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(host)))
	out = append(out, lb[:]...)
	out = append(out, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	out = append(out, pb[:]...)
	return out, nil
}

func decodeOpen(b []byte) (host string, port int, err error) {
	c := &cursor{b}
	h, err := c.lenBytes2()
	if err != nil {
		return "", 0, err
	}
	p, err := c.u16()
	if err != nil {
		return "", 0, err
	}
	if len(c.rest()) != 0 {
		return "", 0, fmt.Errorf("coord: OPEN 有 %d 字节尾随数据", len(c.rest()))
	}
	return h, int(p), nil
}

// --- STATUS (2) -----------------------------------------------------------

// statusPayload = code(1) [+ msg]
func encodeStatus(code byte, msg string) []byte {
	out := make([]byte, 0, 1+len(msg))
	out = append(out, code)
	out = append(out, msg...)
	return out
}

func decodeStatus(b []byte) (byte, string, error) {
	c := &cursor{b}
	code, err := c.u8()
	if err != nil {
		return 0, "", err
	}
	return code, string(c.rest()), nil
}

// signHello 算 HELLO 的 auth 字段：hex(HMAC-SHA256(key, String(ts)))[:32]。
// 与 server/src/auth.js 的 verifyHello 严格对应——签名串只有 ts 一个字段。
func signHello(key []byte, ts int64) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	return hex.EncodeToString(mac.Sum(nil))[:authLen]
}

// reportRespPayload = accepted(4)
func encodeReportResp(accepted int) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(accepted))
	return out
}

// openedPayload = code(1)
func encodeOpened(code byte) []byte { return []byte{code} }

// batchIDFor 按批内容派生幂等键（16 字节 hex）。同一批条目（顺序、字段）重发得到
// 同一 ID；内容一变就是新的一批。用于调用方没显式给 Batch 的场合。
func batchIDFor(items []reportEntry) string {
	h := sha256.New()
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(items)))
	h.Write(l[:])
	for _, it := range items {
		l0 := byte(len(it.host))
		h.Write([]byte{l0})
		h.Write([]byte(it.host))
		l1 := byte(len(it.method))
		h.Write([]byte{l1})
		h.Write([]byte(it.method))
		flags := byte(0)
		if it.ok {
			flags |= 1
		}
		if it.unsup {
			flags |= 2
		}
		h.Write([]byte{flags})
		var r [4]byte
		binary.BigEndian.PutUint32(r[:], it.rtt)
		h.Write(r[:])
		var t [8]byte
		binary.BigEndian.PutUint64(t[:], it.ts)
		h.Write(t[:])
		lk := byte(len(it.kind))
		h.Write([]byte{lk})
		h.Write([]byte(it.kind))
		lp := byte(len(it.proto))
		h.Write([]byte{lp})
		h.Write([]byte(it.proto))
	}
	return hex.EncodeToString(h.Sum(nil))[:batchIDLen]
}
