// Satel 帧编解码（协议 v1 传输层）。与 client/internal/coord/frame.go 一一对应，
// 两侧必须逐字节一致。
//
//	frame = [ opcode:1 ][ id:4 BE ][ payload ]
//
// WS 是消息导向的，长度由 WS 层给出，所以帧里没有 magic / version / length。

/** opcode 取值。控制面用 reqID，隧道面用 streamID —— 共用 4 字节空间，
 *  但按 opcode 分派到不同的表，不会冲突。 */
export const OP = {
  HELLO: 1, STATUS: 2, BUNDLE: 3, BUNDLE_RESP: 4, REPORT: 5, REPORT_RESP: 6,
  EVOLVE: 7, EVOLVE_RESP: 8, OPEN: 9, OPENED: 10, DATA: 11, CLOSE: 12,
};

/** STATUS.code */
export const STATUS = { OK: 0, AUTH_FAIL: 1, BAD_PARAM: 2, UPSTREAM: 3, DENIED: 4 };

/** OPENED.code */
export const OPEN = { OK: 0, FAIL: 1 };

export const FRAME_HEADER = 5;
export const SID_LEN = 8;
export const AUTH_LEN = 32;
/** REPORT 条目里三个变长字段的上限（长度前缀都是 1 字节）。 */
export const MAX_HOST_NAME = 253;
export const MAX_METHOD_LEN = 32;
export const MAX_KIND_LEN = 16;
export const MAX_REPORT_ITEMS = 256;
export const MAX_BUNDLE_N = 32;
export const DEFAULT_BUNDLE_N = 8;
export const BUNDLE_SCAN_LIMIT = 256;
export const TTL_SECONDS = 3600;

/**
 * **传输层协议版本**，写在 HELLO 的尾字节上。
 *
 * 0 = 传输层重写之前（HTTP 端点时代的遗留握手，已不存在）；
 * 1 = 首版 WS 握手：`ts(8)+auth(32)+fp str1+caps str1`；
 * 2 = 本轮：同一个 HELLO 尾巴上多这一个字节，而 REPORT 的条目多了 `proto`
 *      字段、并整体前移了 32 字节 batchID；BUNDLE_RESP 尾部多了 hints。
 *
 * 老客户端对 HELLO 跑 expectEnd()，看见这个字节会**拒绝**——这正是要的：
 * 宁可响亮失败，也不要"连上了但按错的语义跑"（protocol.md §6）。新服务端
 * 同样拒绝没有这个字节的 HELLO，双向都不降级。
 */
export const PROTOCOL_VERSION = 2;

/** batchID 的字节长度：32 个小写十六进制 ASCII，等价 16 字节随机数的 hex。 */
export const BATCH_ID_LEN = 32;

/** BUNDLE_RESP 尾部 hint 的条数上限。 */
export const MAX_HINTS = 128;

/** socket→ws 的排队上限，超过就停止读，给 TCP 施加背压。 */
export const STREAM_BUFFER_LIMIT = 1 << 20;

const enc = new TextEncoder();

export function encodeFrame(op, id, payload) {
  const p = payload ?? new Uint8Array(0);
  const out = new Uint8Array(FRAME_HEADER + p.length);
  out[0] = op;
  new DataView(out.buffer).setUint32(1, id >>> 0, false);
  out.set(p, FRAME_HEADER);
  return out;
}

export function decodeFrame(bytes) {
  if (bytes.length < FRAME_HEADER) throw new Error("帧长度不足");
  return {
    op: bytes[0],
    id: new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(1, false),
    data: bytes.subarray(FRAME_HEADER),
  };
}

/** 带边界检查的读游标 —— 输入来自网络，不能让它抛未捕获的异常。 */
export class Cursor {
  constructor(b) {
    this.b = b;
    this.i = 0;
  }
  take(n) {
    if (n < 0 || this.i + n > this.b.length) throw new Error("读取越界");
    const v = this.b.subarray(this.i, this.i + n);
    this.i += n;
    return v;
  }
  u8() { return this.take(1)[0]; }
  u16() {
    const v = new DataView(this.b.buffer, this.b.byteOffset, this.b.byteLength)
      .getUint16(this.i, false);
    this.i += 2;
    return v;
  }
  u32() {
    const v = new DataView(this.b.buffer, this.b.byteOffset, this.b.byteLength)
      .getUint32(this.i, false);
    this.i += 4;
    return v;
  }
  /** 8 字节大端。超出 Number.MAX_SAFE_INTEGER 的时间戳不现实，这里用 hi*2^32+lo。 */
  u64() {
    const hi = this.u32(), lo = this.u32();
    return hi * 4294967296 + lo;
  }
  len1(max) {
    const n = this.u8();
    if (max != null && n > max) throw new Error("字段过长");
    return String.fromCharCode(...this.take(n));
  }
  len2() { const n = this.u16(); return String.fromCharCode(...this.take(n)); }
  rest() { return this.b.subarray(this.i); }
  expectEnd() { if (this.i !== this.b.length) throw new Error("存在尾随数据"); }
}

// 长度前缀取**编码后的字节数**：取字符数在遇到非 ASCII 时会与 enc.encode 的
// 长度脱节，把整条帧往后错。主机名/方法/类别都是 ASCII，但别依赖这一点。
function str1(s) {
  const b = enc.encode(s);
  if (b.length > 255) throw new Error("str1 字段超长");
  const out = new Uint8Array(1 + b.length);
  out[0] = b.length;
  out.set(b, 1);
  return out;
}
function str2(s) {
  const b = enc.encode(s);
  const out = new Uint8Array(2 + b.length);
  new DataView(out.buffer).setUint16(0, b.length, false);
  out.set(b, 2);
  return out;
}
function cat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
function u64be(v) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setUint32(0, Math.floor(v / 4294967296), false);
  new DataView(out.buffer).setUint32(4, v >>> 0, false);
  return out;
}

// --- HELLO (1) ------------------------------------------------------------

/**
 * helloPayload = ts(8) + auth(32) + fp_len(1)+fp + caps_len(1)+caps + proto_ver(1)
 *
 * 尾部这个字节是**传输层版本探针**：旧客户端的 decodeHello 跑 expectEnd() 会看见
 * 尾随数据并拒绝连接（旧服务端同样拒收没有它的 HELLO）。刻意做成响亮失败而不是
 * 静默降级——"连上了但按错的语义跑"比连不上更难排查（protocol.md §6）。
 */
export function encodeHello(ts, auth, fp, caps) {
  return cat(
    u64be(ts),
    enc.encode(auth),
    str1(fp),
    str1((caps ?? []).join(",")),
    new Uint8Array([PROTOCOL_VERSION]),
  );
}

export function decodeHello(data) {
  const c = new Cursor(data);
  const ts = c.u64();
  const auth = String.fromCharCode(...c.take(AUTH_LEN));
  const fp = c.len1();
  const caps = c.len1();
  const ver = c.u8();
  // 缺失的尾字节在这里表现为"读取越界"——刻意不设默认值：没有版本字节就是旧客户端。
  if (ver !== PROTOCOL_VERSION) {
    throw new Error(`传输层协议版本不被支持: ${ver}`);
  }
  c.expectEnd();
  return { ts, auth, fp, caps: caps ? caps.split(",") : [] };
}

// --- STATUS (2) -----------------------------------------------------------

export function encodeStatus(code, msg = "") {
  return cat(new Uint8Array([code]), enc.encode(msg));
}

export function decodeStatus(data) {
  const c = new Cursor(data);
  const code = c.u8();
  return { code, msg: String.fromCharCode(...c.rest()) };
}

// --- BUNDLE (3) / BUNDLE_RESP (4) ----------------------------------------

export function encodeBundle(proto, n) {
  return cat(str1(proto), new Uint8Array([n]));
}

export function decodeBundle(data) {
  const c = new Cursor(data);
  const proto = c.len1();
  const n = c.u8();
  c.expectEnd();
  return { proto, n };
}

/**
 * bundleRespPayload =
 *   version(4) + count(1) + 重复{ id(8) + spec_len(2)+spec }
 *   + hintCount(u16) + 重复{ suffix str1 + method str1 + ok(4) + fail(4) + hosts(4) + expires(8) }
 *
 * hints 是**后缀级**的经验先验：客户端在新主机上还没打第一枪之前，就能按
 * "同后缀的其它主机上哪个方法赢得多"排阶梯。它把"每个主机都要各自付一遍学费"
 * 变成"同后缀只付一次"。
 *
 * `hints` 省略即空——老调用方（以及将来只想下发策略的场景）不用改。
 */
export function encodeBundleResp(version, items, hints = []) {
  if (hints.length > MAX_HINTS) throw new Error("hint 条数超过上限");
  for (const h of hints) {
    if (h.suffix === "" || h.method === "") throw new Error("hint 字段为空");
  }
  const specs = items.map((it) => enc.encode(it.spec));
  let size = 5 + 2;
  for (const b of specs) size += SID_LEN + 2 + b.length;
  for (const h of hints) {
    size += 1 + enc.encode(h.suffix).length + 1 + enc.encode(h.method).length + 4 + 4 + 4 + 8;
  }
  const out = new Uint8Array(size);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, version >>> 0, false);
  out[4] = items.length;
  let off = 5;
  for (let i = 0; i < items.length; i++) {
    out.set(enc.encode(items[i].id), off); off += SID_LEN;
    dv.setUint16(off, specs[i].length, false); off += 2;
    out.set(specs[i], off); off += specs[i].length;
  }
  dv.setUint16(off, hints.length, false); off += 2;
  for (const h of hints) {
    const s = enc.encode(h.suffix);
    const m = enc.encode(h.method);
    out[off] = s.length; off += 1;
    out.set(s, off); off += s.length;
    out[off] = m.length; off += 1;
    out.set(m, off); off += m.length;
    dv.setUint32(off, h.ok >>> 0, false); off += 4;
    dv.setUint32(off, h.fail >>> 0, false); off += 4;
    dv.setUint32(off, h.hosts >>> 0, false); off += 4;
    const exp = Math.floor(h.expires);
    dv.setUint32(off, Math.floor(exp / 4294967296), false); off += 4;
    dv.setUint32(off, exp >>> 0, false); off += 4;
  }
  return out;
}

/**
 * 解码 BUNDLE_RESP。
 *
 * `hints` 缺失时返回空数组：**旧服务端发的响应里没有这个尾部**，把它当错误会让
 * 混合版本的车队一上线就全挂。服务端只会发带尾部的响应，但客户端版本更新必然
 * 慢于服务端，容忍缺省是纯收益。
 */
export function decodeBundleResp(data) {
  const c = new Cursor(data);
  const version = c.u32();
  const n = c.u8();
  const items = [];
  for (let i = 0; i < n; i++) {
    const id = String.fromCharCode(...c.take(SID_LEN));
    const spec = c.len2();
    items.push({ id, spec });
  }
  const hints = [];
  // 头部只声明了 count(1)，尾部 hint 数量是额外的 u16。读之前先确认还有字节。
  if (c.i < c.b.length) {
    const hn = c.u16();
    if (hn > MAX_HINTS) throw new Error("hint 条数超过上限");
    for (let i = 0; i < hn; i++) {
      const suffix = c.len1(MAX_HOST_NAME);
      const method = c.len1(MAX_METHOD_LEN);
      const ok = c.u32();
      const fail = c.u32();
      const hosts = c.u32();
      const expires = c.u64();
      if (suffix === "" || method === "") throw new Error("hint 字段为空");
      hints.push({ suffix, method, ok, fail, hosts, expires });
    }
  }
  c.expectEnd();
  return { version, items, hints };
}

// --- REPORT (5) / REPORT_RESP (6) ----------------------------------------
//
// reportPayload = batchID(32 ASCII 小写 hex) + count(u16) + 重复{
//   host str1 + method str1 + flags(1) + rtt(4) + ts(8) + kind str1 + proto str1 }
//
// flags：bit0 = ok，bit1 = unsup。**bit2..bit7 保留**，置位即拒绝——保留位是给未来
// 的条目级标记留的，让未知位静默通过等于允许客户端用服务端不认识的方式表达语义。
//
// host 是**明文主机名**，method 是伪方法（@direct/@ech/@tunnel/@proxyip）或 8 位策略
// ID；kind 是失败类别（成功为 "ok"）。明文主机名是用户明确的选择：host_hash 对已知
// 域名表逐个 sha256 即可反查，挡不住反查却让人误以为有隐私。
//
// proto 在 kind **之后**（条目末尾）。不放 flags 里：flags 只剩 6 个保留位，
// 新增协议会一直挤占它，而 str1 只多一个字节。
//
// batchID 在 payload 最前面。它是**幂等键**，不是载荷：客户端重连时会重发同一批
// （protocol.md §3.4 的"请求类帧自动重发一次"），连接级去重覆盖不到跨连接重发。
// 不发这个 id，服务端就无法分辨"同一批重发"与"新一批"，method_stat 的 ok/fail 会
// 双计、策略的 trials/wins 双计，Beta 后验直接偏向这个批次。幂等键只能由产生这批
// 数据的一方（客户端）生成。

/** flags 未定义的高位——置位即拒。 */
const REPORT_FLAGS_MASK = 0x03;

export function encodeReport(batchID, items) {
  if (typeof batchID !== "string" || batchID.length !== BATCH_ID_LEN) {
    throw new Error("batchID 必须是 32 个字符");
  }
  const bid = enc.encode(batchID);
  const body = [];
  for (const it of items) {
    const rtt = new Uint8Array(4);
    new DataView(rtt.buffer).setUint32(0, it.rtt_ms >>> 0, false);
    let flags = 0;
    if (it.ok) flags |= 1;
    if (it.unsup) flags |= 2;
    body.push(cat(
      str1(it.host), str1(it.method),
      new Uint8Array([flags]), rtt, u64be(it.ts), str1(it.kind),
      str1(it.proto),
    ));
  }
  const count = new Uint8Array(2);
  new DataView(count.buffer).setUint16(0, items.length, false);
  return cat(bid, count, ...body);
}

export function decodeReport(data) {
  const c = new Cursor(data);
  const batchID = String.fromCharCode(...c.take(BATCH_ID_LEN));
  const n = c.u16();
  if (n > MAX_REPORT_ITEMS) throw new Error("回报条目过多");
  const items = [];
  for (let i = 0; i < n; i++) {
    const host = c.len1(MAX_HOST_NAME);
    const method = c.len1(MAX_METHOD_LEN);
    const flags = c.u8();
    const rtt_ms = c.u32();
    const ts = c.u64();
    const kind = c.len1(MAX_KIND_LEN);
    const proto = c.len1();
    if ((flags & ~REPORT_FLAGS_MASK) !== 0) throw new Error("回报 flags 含未定义位");
    if (host === "" || method === "" || kind === "" || proto === "") {
      throw new Error("回报条目字段为空");
    }
    if (proto !== "tls" && proto !== "http") throw new Error("回报 proto 非法");
    items.push({
      host, method, proto,
      ok: (flags & 1) !== 0, unsup: (flags & 2) !== 0,
      rtt_ms, ts, kind,
    });
  }
  c.expectEnd();
  return { batchID, items };
}

// --- EVOLVE (7) / EVOLVE_RESP (8) ----------------------------------------

export function encodeEvolve(key) {
  return str1(key);
}

export function decodeEvolve(data) {
  const c = new Cursor(data);
  const key = c.len1();
  c.expectEnd();
  return key;
}

export function encodeU32s(a, b, c, d) {
  const out = new Uint8Array(16);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, a >>> 0, false);
  dv.setUint32(4, b >>> 0, false);
  dv.setUint32(8, c >>> 0, false);
  dv.setUint32(12, d >>> 0, false);
  return out;
}

export function decodeU32s(data) {
  const c = new Cursor(data);
  return { a: c.u32(), b: c.u32(), c: c.u32(), d: c.u32() };
}

// --- OPEN (9) / OPENED (10) ----------------------------------------------

export function encodeOpen(host, port) {
  const p = new Uint8Array(2);
  new DataView(p.buffer).setUint16(0, port, false);
  return cat(str2(host), p);
}

export function decodeOpen(data) {
  const c = new Cursor(data);
  const host = c.len2();
  const port = c.u16();
  c.expectEnd();
  return { host, port };
}

export function encodeOpened(code) {
  return new Uint8Array([code]);
}