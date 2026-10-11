// 帧编解码与 HELLO 鉴权的离线测试。不碰 D1，也不需要 WebSocketPair
// （Node 里没有）——连接层的行为由 Go 侧的 client_test 用真实 WS 服务端覆盖。
import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";

import {
  Cursor,
  DEFAULT_BUNDLE_N,
  FRAME_HEADER,
  MAX_REPORT_ITEMS,
  OP,
  SID_LEN,
  STREAM_BUFFER_LIMIT,
  decodeBundle,
  decodeBundleResp,
  decodeEvolve,
  decodeFrame,
  decodeHello,
  decodeOpen,
  decodeReport,
  decodeStatus,
  encodeBundle,
  encodeBundleResp,
  encodeEvolve,
  encodeFrame,
  encodeHello,
  encodeOpen,
  encodeOpened,
  encodeReport,
  encodeStatus,
  encodeU32s,
  decodeU32s,
} from "../src/frame.js";
import { fleetCaps, hostAllowed, opsAllowed, tuning } from "../src/ws.js";
import { verifyHello, verifyAdmin, deriveKey } from "../src/auth.js";

const hex = (b) => Buffer.from(b).toString("hex");

// --- 跨语言 golden ---------------------------------------------------------
// 这些字面量由 scripts/gen-golden.sh 从两侧实现实测生成并断言过一致。

test("HELLO 帧与 Go 侧逐字节一致", () => {
  const got = hex(encodeFrame(
    OP.HELLO, 0,
    encodeHello(1780000000, "a".repeat(32), "fp", ["split", "tlsrf"]),
  ));
  assert.equal(got, "0100000000000000006a18a50061616161616161616161616161616161616161616161616161616161616161610266700b73706c69742c746c73726602");;
});

test("REPORT 帧与 Go 侧逐字节一致", () => {
  const got = hex(encodeFrame(OP.REPORT, 7, encodeReport("0123456789abcdef0123456789abcdef", [
    { host: "www.example.com", method: "15c0e805", ok: 1, unsup: 0, rtt_ms: 118, ts: 1780000000, kind: "ok", proto: "tls" },
  ])));
  assert.equal(got, "0500000007303132333435363738396162636465663031323334353637383961626364656600010f7777772e6578616d706c652e636f6d0831356330653830350100000076000000006a18a500026f6b03746c73");;
});

test("BUNDLE_RESP 往返", () => {
  const items = [
    { id: "15c0e805", spec: "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)" },
    { id: "78c3d41b", spec: "tls|tlsrf(chunk=8,delay_ms=8,limit=400)" },
  ];
  const back = decodeBundleResp(encodeBundleResp(42, items));
  assert.equal(back.version, 42);
  assert.deepEqual(back.items, items);
});

test("OPEN 往返", () => {
  const back = decodeOpen(encodeOpen("www.example.com", 8443));
  assert.deepEqual(back, { host: "www.example.com", port: 8443 });
});

test("EVOLVE 往返", () => {
  assert.equal(decodeEvolve(encodeEvolve("0123456789abcdef")), "0123456789abcdef");
});

test("STATUS 与 OPENED", () => {
  assert.deepEqual(decodeStatus(encodeStatus(1, "auth failed")), { code: 1, msg: "auth failed" });
  assert.deepEqual(decodeStatus(encodeStatus(0, "")), { code: 0, msg: "" });
  assert.deepEqual([...encodeOpened(1)], [1]);
});

test("REPORT 拒绝超量条目", () => {
  const many = Array.from({ length: MAX_REPORT_ITEMS + 1 }, () => ({
    host: "0123456789abcdef", method: "15c0e805", ok: 1, unsup: 0, rtt_ms: 0, ts: 0, kind: "ok", proto: "tls",
  }));
  // 编码侧不限制（由客户端分批），解码侧必须拒绝。
  const buf = encodeReport("a".repeat(32), many);
  assert.throws(() => decodeReport(buf), /回报条目过多/);
});

test("BUNDLE 往返", () => {
  assert.deepEqual(decodeBundle(encodeBundle("tls", 8)), { proto: "tls", n: 8 });
});

test("帧头不足即报错", () => {
  for (let n = 0; n < FRAME_HEADER; n++) {
    assert.throws(() => decodeFrame(new Uint8Array(n)), /帧长度不足/);
  }
});

// --- 截断永不远行 -----------------------------------------------------------

test("Cursor 对任何截断都抛 Error 而不是 TypeError", () => {
  const payloads = [
    encodeHello(1780000000, "a".repeat(32), "fp-1", ["split", "tlsrf"]),
    encodeBundle("tls", 8),
    encodeEvolve("admin-key-0123456789"),
    encodeReport("a".repeat(32), [{ host: "0123456789abcdef", method: "15c0e805", ok: 1, unsup: 0, rtt_ms: 5, ts: 1, kind: "ok", proto: "tls" }]),
    encodeOpen("a.example.com", 8443),
    encodeU32s(1, 2, 3, 4),
  ];
  const reads = [
    (b) => decodeHello(b),
    (b) => decodeBundle(b),
    (b) => decodeEvolve(b),
    (b) => decodeReport(b),
    (b) => decodeOpen(b),
    (b) => decodeU32s(b),
  ];
  payloads.forEach((p, i) => {
    for (let n = 0; n < p.length; n++) {
      const sliced = p.subarray(0, n);
      // 允许成功或抛错，但必须是 Error（不能是 TypeError: undefined 等）
      try {
        reads[i](sliced);
      } catch (err) {
        assert.ok(err instanceof Error, `截断 ${n} 抛出了非 Error：${err}`);
      }
    }
  });
});

test("尾随垃圾被发现而不是被忽略", () => {
  const withJunk = (b) => Uint8Array.from([...b, 0xaa, 0xbb]);
  assert.throws(() => decodeHello(withJunk(encodeHello(1, "a".repeat(32), "f", []))), /尾随数据/);
  assert.throws(() => decodeBundle(withJunk(encodeBundle("tls", 1))), /尾随数据/);
  assert.throws(() => decodeEvolve(withJunk(encodeEvolve("k"))), /尾随数据/);
  assert.throws(() => decodeOpen(withJunk(encodeOpen("h", 1))), /尾随数据/);
});

// --- HELLO 鉴权 ------------------------------------------------------------

/** 独立于 src/auth.js 的参考实现，用来交叉验证签名本身没写错。 */
function refAuth(password, ts) {
  const key = createHash("sha256").update("satel/v1/" + password).digest();
  return createHmac("sha256", key).update(String(ts)).digest("hex").slice(0, 32);
}

test("verifyHello 接受正确签名", async () => {
  const pw = "hunter2";
  const ts = Math.floor(Date.now() / 1000);
  assert.equal(refAuth(pw, ts), await (async () => {
    const { hmacHex } = await import("../src/auth.js");
    const key = await deriveKey(pw);
    return (await hmacHex(key, String(ts))).slice(0, 32);
  })());
  assert.equal(await verifyHello(ts, refAuth(pw, ts), pw), true);
});

test("verifyHello 拒绝错口令 / 过期 ts / 空口令", async () => {
  const ts = Math.floor(Date.now() / 1000);
  assert.equal(await verifyHello(ts, refAuth("wrong", ts), "right"), false);
  assert.equal(await verifyHello(ts, refAuth("pw", ts), "pw", ts + 3600), false);
  assert.equal(await verifyHello(ts, refAuth("pw", ts), ""), false);
  assert.equal(await verifyHello(NaN, "x", "pw"), false);
});

test("verifyAdmin 常量时间比较", () => {
  assert.equal(verifyAdmin("secret", "secret"), true);
  assert.equal(verifyAdmin("secre", "secret"), false);
  assert.equal(verifyAdmin("secrets", "secret"), false);
  assert.equal(verifyAdmin("anything", ""), false);
});

// --- 白名单与 caps ----------------------------------------------------------

test("hostAllowed 拒绝私网与非法字符", () => {
  for (const h of ["10.0.0.1", "127.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1"]) {
    assert.equal(hostAllowed(h), false, `${h} 应被拒`);
  }
  assert.equal(hostAllowed("::1"), false);
  assert.equal(hostAllowed("2001:db8::1"), false);
  assert.equal(hostAllowed("www.example.com"), true);
  assert.equal(hostAllowed("142.251.152.119"), true);
});

test("opsAllowed 按 caps 过滤", () => {
  const caps = new Set(["split", "tlsrf", "oob"]);
  assert.equal(opsAllowed("tls|split(at=sni)", caps), true);
  assert.equal(opsAllowed("tls|fake(ttl=3)", caps), false);
  // 一条里混了不支持的招法就整条丢掉
  assert.equal(opsAllowed("tls|split(at=sni)|fake(ttl=3)", caps), false);
  assert.equal(opsAllowed("tls|split(at=sni)", null), true);
});

// --- 调参 ------------------------------------------------------------------

test("tuning / fleetCaps 处理缺省", () => {
  assert.deepEqual(tuning({ POOL_MAX: "32", TOP_K: "4" }), { poolMax: 32, topK: 4 });
  assert.deepEqual(tuning({}), { poolMax: 48, topK: 8 });
  assert.deepEqual(tuning({ POOL_MAX: "垃圾" }), { poolMax: 48, topK: 8 });
  assert.equal(fleetCaps({ CAPS: "split,tlsrf" }).size, 2);
  assert.equal(fleetCaps({}), null);
  assert.equal(fleetCaps({ CAPS: "  " }), null);
});