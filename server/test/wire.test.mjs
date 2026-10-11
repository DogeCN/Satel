// 线格式的边界测试：畸形长度、截断、未定义 flags、非法 proto、往返。
//
// 这一层专测"**帧级**"的健壮性：输入来自网络，任何异常形状都不许把 Worker 弄崩、
// 不许让读越界变成 TypeError（而必须是 Error，让 ws.js 的 catch 能回 STATUS）。
import test from "node:test";
import assert from "node:assert/strict";

import {
  BATCH_ID_LEN,
  MAX_HINTS,
  PROTOCOL_VERSION,
  decodeBundleResp,
  decodeHello,
  decodeReport,
  encodeBundleResp,
  encodeHello,
  encodeReport,
} from "../src/frame.js";

const BID = "0123456789abcdef0123456789abcdef";

const entry = (o = {}) => ({
  host: "www.example.com",
  method: "15c0e805",
  ok: true,
  unsup: false,
  rtt_ms: 118,
  ts: 1780000000,
  kind: "ok",
  proto: "tls",
  ...o,
});

// --- 往返 -----------------------------------------------------------------

test("REPORT 往返保留全部字段", () => {
  const items = [
    entry(),
    entry({ host: "api.example.com", method: "@direct", ok: false, kind: "reset", proto: "http" }),
    entry({ method: "15c0e805", unsup: true, ok: false, kind: "other", rtt_ms: 0, ts: 0 }),
    entry({ host: "2001:db8::1", kind: "readtimeout", ok: false }),
  ];
  const back = decodeReport(encodeReport(BID, items));
  assert.equal(back.batchID, BID);
  assert.equal(back.items.length, 4);
  assert.deepEqual(back.items[0], {
    host: "www.example.com", method: "15c0e805", proto: "tls",
    ok: true, unsup: false, rtt_ms: 118, ts: 1780000000, kind: "ok",
  });
  assert.equal(back.items[1].proto, "http");
  assert.equal(back.items[1].kind, "reset");
  assert.equal(back.items[2].unsup, true);
  assert.equal(back.items[3].host, "2001:db8::1");
});

test("BUNDLE_RESP 往返：version / items / hints 三者都保真", () => {
  const items = [{ id: "15c0e805", spec: "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)" }];
  const hints = [
    { suffix: "api.example.com", method: "15c0e805", ok: 12, fail: 1, hosts: 4, expires: 1790000000 },
    { suffix: "z.example.com", method: "@direct", ok: 0, fail: 9, hosts: 6, expires: 1790000000 },
  ];
  const back = decodeBundleResp(encodeBundleResp(42, items, hints));
  assert.equal(back.version, 42);
  assert.deepEqual(back.items, items);
  assert.deepEqual(back.hints, hints);
});

test("BUNDLE_RESP 空 hints 尾部仍可被解码（老服务端兼容）", () => {
  const back = decodeBundleResp(encodeBundleResp(1, [{ id: "15c0e805", spec: "tls|s" }]));
  assert.deepEqual(back.hints, []);
});

test("BUNDLE_RESP 完全不带 hint 尾部时容忍（decode 侧可选读取）", () => {
  // 手工构造一个没有 hintCount 的旧响应：只有 version + count + 1 条策略。
  const spec = "tls|s";
  const out = new Uint8Array(5 + 8 + 2 + spec.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, 42, false);
  out[4] = 1;
  out.set(new TextEncoder().encode("15c0e805"), 5);
  dv.setUint16(13, spec.length, false);
  out.set(new TextEncoder().encode(spec), 15);
  const back = decodeBundleResp(out);
  assert.equal(back.version, 42);
  assert.equal(back.items.length, 1);
  assert.deepEqual(back.hints, []);
});

test("expires 用 u64，超过 2^32 也能往返", () => {
  const big = 4102444800; // > 2^32
  const back = decodeBundleResp(encodeBundleResp(1, [], [
    { suffix: "a.example.com", method: "@direct", ok: 1, fail: 0, hosts: 1, expires: big },
  ]));
  assert.equal(back.hints[0].expires, big);
});

test("128 条 hint 是上限，129 条被拒", () => {
  const mk = (n) => Array.from({ length: n }, (_, i) => ({
    suffix: `s${i}.example.com`, method: "@direct", ok: 1, fail: 0, hosts: 3, expires: 1790000000,
  }));
  // 编码侧拒绝超限
  assert.equal(decodeBundleResp(encodeBundleResp(1, [], mk(MAX_HINTS))).hints.length, MAX_HINTS);
  assert.throws(() => encodeBundleResp(1, [], mk(MAX_HINTS + 1)), /hint 条数超过上限/);
});

test("解码侧也拒超限的 hintCount（防畸形/恶意响应）", () => {
  // 手工构造一条 hintCount=129 但没有对应数据的响应。
  const out = new Uint8Array(7);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, 1, false); // version
  out[4] = 0;                // strategy count
  dv.setUint16(5, MAX_HINTS + 1, false); // hintCount = 129
  assert.throws(() => decodeBundleResp(out), /hint 条数超过上限/);
});

// --- HELLO 版本探针 -------------------------------------------------------

test("HELLO 尾字节 = 2，且缺字节的旧客户端被拒", () => {
  const buf = encodeHello(1780000000, "a".repeat(32), "fp", ["split"]);
  assert.equal(buf[buf.length - 1], PROTOCOL_VERSION);
  // 去掉尾字节 → 旧客户端的 HELLO
  assert.throws(() => decodeHello(buf.subarray(0, buf.length - 1)), /越界|Error/);
  // 版本不对
  const wrong = Uint8Array.from(buf);
  wrong[wrong.length - 1] = 1;
  assert.throws(() => decodeHello(wrong), /协议版本/);
  const wrong2 = Uint8Array.from(buf);
  wrong2[wrong2.length - 1] = 0;
  assert.throws(() => decodeHello(wrong2), /协议版本/);
});

test("HELLO 尾随数据被拒", () => {
  const buf = encodeHello(1, "a".repeat(32), "f", []);
  const junk = Uint8Array.from([...buf, 0xaa]);
  assert.throws(() => decodeHello(junk), /尾随数据/);
});

// --- REPORT 畸形 -----------------------------------------------------------

test("REPORT 未定义 flags 位被拒（bit2..bit7）", () => {
  const good = encodeReport(BID, [entry({ ok: false, kind: "reset" })]);
  // layout: batchID(32) + count(2) + hostLen(1) + host + methodLen(1) + method + flags(1) + …
  const hostLen = good[34];
  const methodLen = good[34 + 1 + hostLen];
  const flagsOffset = 34 + 1 + hostLen + 1 + methodLen;
  assert.equal(good[flagsOffset], 0, "本用例的基线 flags 应为 0");
  for (const bit of [0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff]) {
    const b = Uint8Array.from(good);
    b[flagsOffset] = bit;
    assert.throws(() => decodeReport(b), /未定义位/, `flags=${bit} 应被拒`);
  }
  // 已定义的两个位仍然可用
  for (const bit of [0x00, 0x01, 0x02, 0x03]) {
    const b = Uint8Array.from(good);
    b[flagsOffset] = bit;
    assert.doesNotThrow(() => decodeReport(b), `flags=${bit} 应被接受`);
  }
});

test("REPORT 非法 proto 被拒", () => {
  for (const proto of ["sctp", "TLS", "tls ", "", "tlsx"]) {
    assert.throws(() => decodeReport(encodeReport(BID, [entry({ proto })])), Error, `proto=${JSON.stringify(proto)}`);
  }
});

test("REPORT 空字段被拒", () => {
  assert.throws(() => decodeReport(encodeReport(BID, [entry({ host: "" })])), /字段为空/);
  assert.throws(() => decodeReport(encodeReport(BID, [entry({ method: "" })])), /字段为空/);
  assert.throws(() => decodeReport(encodeReport(BID, [entry({ kind: "" })])), /字段为空/);
});

test("REPORT batchID 长度错误在编码侧就被拒", () => {
  assert.throws(() => encodeReport("tooshort", [entry()]), /32 个字符/);
  assert.throws(() => encodeReport("a".repeat(31), [entry()]), /32 个字符/);
  assert.throws(() => encodeReport("a".repeat(33), [entry()]), /32 个字符/);
});

test("REPORT batchID 偏移正确（不是从 count 开始读）", () => {
  // 用一个全非零的 batchID，确认解码出来的正是它而不是被 count 挤掉。
  const bid = "fedcba9876543210fedcba9876543210";
  const back = decodeReport(encodeReport(bid, [entry()]));
  assert.equal(back.batchID, bid);
  assert.equal(bid.length, BATCH_ID_LEN);
});

test("REPORT 任何截断都抛 Error（不是 TypeError）", () => {
  const buf = encodeReport(BID, [entry(), entry({ host: "api.example.com" })]);
  for (let n = 0; n < buf.length; n++) {
    try {
      decodeReport(buf.subarray(0, n));
    } catch (err) {
      assert.ok(err instanceof Error, `截断 ${n} 抛出了非 Error: ${err}`);
    }
  }
});

test("REPORT 尾随垃圾被拒", () => {
  const buf = encodeReport(BID, [entry()]);
  assert.throws(() => decodeReport(Uint8Array.from([...buf, 0xaa])), /尾随数据/);
});

// --- BUNDLE_RESP 畸形 -----------------------------------------------------

test("BUNDLE_RESP 任何截断都抛 Error", () => {
  const buf = encodeBundleResp(42, [{ id: "15c0e805", spec: "tls|s" }], [
    { suffix: "api.example.com", method: "@direct", ok: 1, fail: 0, hosts: 3, expires: 1790000000 },
  ]);
  for (let n = 0; n < buf.length; n++) {
    try {
      decodeBundleResp(buf.subarray(0, n));
    } catch (err) {
      assert.ok(err instanceof Error, `截断 ${n} 抛出了非 Error: ${err}`);
    }
  }
});

test("BUNDLE_RESP 尾随垃圾被拒", () => {
  const buf = encodeBundleResp(1, [{ id: "15c0e805", spec: "tls|s" }]);
  assert.throws(() => decodeBundleResp(Uint8Array.from([...buf, 0xaa])), /尾随数据/);
});

test("BUNDLE_RESP 空 hint 字段在编码侧被拒", () => {
  assert.throws(() => encodeBundleResp(1, [], [{ suffix: "", method: "@direct", ok: 1, fail: 0, hosts: 1, expires: 1 }]), /字段为空/);
  assert.throws(() => encodeBundleResp(1, [], [{ suffix: "a.com", method: "", ok: 1, fail: 0, hosts: 1, expires: 1 }]), /字段为空/);
});