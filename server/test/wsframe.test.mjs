// ws.js 帧分派的端到端测试：REPORT 幂等 + BUNDLE 带 hint 下发。
//
// 用一个**假的 WebSocket**（只实现 addEventListener/send/close/bufferedAmount）
// 直接调 handleFrame——Node 里没有 WebSocketPair，而 Go 侧 client_test 已用真实
// WS 服务端覆盖了传输层，这里只测分派逻辑与数据层的接线。
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, createHmac } from "node:crypto";

import { makeD1 } from "./helpers/d1adapter.mjs";
import { OP, decodeFrame, encodeFrame, encodeHello } from "../src/frame.js";
import { handleFrame } from "../src/ws.js";
import { validateItem } from "../src/validate.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA = readFileSync(join(ROOT, "schema.sql"), "utf8");
const NOW = 1780000000;

/** 收集 send 出来的帧。 */
function fakeWS() {
  const sent = [];
  return {
    sent,
    bufferedAmount: 0,
    send(bytes) { sent.push(Uint8Array.from(bytes)); },
    close() {},
  };
}

/** 取最后一帧并解码。 */
function last(ws) {
  const raw = ws.sent[ws.sent.length - 1];
  return decodeFrame(raw);
}

/** 从帧 payload 的第 offset 字节起读 u32。 */
function u32(f, offset = 0) {
  return new DataView(f.data.buffer, f.data.byteOffset, f.data.byteLength).getUint32(offset);
}

/** ctx.now 注入固定时间基准，让 hint 的 expires 与测试里的 NOW 可比。 */
function ctxFor(db) {
  return {
    env: { DB: db },
    fp: "fp1",
    caps: null,
    streams: new Map(),
    hello: true,
    chain: Promise.resolve(),
    now: () => NOW * 1000,
  };
}

function freshDB() {
  const d = makeD1(":memory:");
  d.raw.exec(SCHEMA);
  return d;
}

const item = (o) => {
  const v = validateItem({ proto: "tls", rtt_ms: 0, ts: NOW, ...o });
  return { ...v, ok: v.ok ? 1 : 0, fail: v.train && !v.ok ? 1 : 0 };
};

// --- REPORT ----------------------------------------------------------------

test("REPORT：accepted 回显接受数，重复 batchID 返回同一个 accepted", async () => {
  const db = freshDB();
  const { encodeReport } = await import("../src/frame.js");
  const items = [item({ host: "www.example.com", method: "15c0e805", kind: "ok", ok: true })];
  const bid = "0123456789abcdef0123456789abcdef";
  const payload = encodeReport(bid, items);

  const ws1 = fakeWS();
  await handleFrame(ws1, ctxFor(db), encodeFrame(OP.REPORT, 7, payload));
  const r1 = last(ws1);
  assert.equal(r1.op, OP.REPORT_RESP);
  const a1 = u32(r1, 0);
  assert.equal(a1, 1);

  // 同一批次重放
  const ws2 = fakeWS();
  await handleFrame(ws2, ctxFor(db), encodeFrame(OP.REPORT, 7, payload));
  const r2 = last(ws2);
  assert.equal(r2.op, OP.REPORT_RESP);
  const a2 = u32(r2, 0);
  assert.equal(a2, 1, "重放的 accepted 必须与首次相同");
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM outcome").get().c, 1);
});

test("REPORT：ok 与 kind 不一致 → STATUS.BAD_PARAM，且不落库", async () => {
  const db = freshDB();
  const { encodeReport } = await import("../src/frame.js");
  // 手工构造 ok=1 但 kind="reset" 的条目（encode 不做语义校验，那是 validateItem 的事）
  const bad = encodeReport("0123456789abcdef0123456789abcdef", [
    { host: "www.example.com", method: "15c0e805", ok: true, unsup: false, rtt_ms: 0, ts: NOW, kind: "reset", proto: "tls" },
  ]);
  const ws = fakeWS();
  await handleFrame(ws, ctxFor(db), encodeFrame(OP.REPORT, 7, bad));
  const f = last(ws);
  assert.equal(f.op, OP.STATUS);
  const code = f.data[0];
  assert.equal(code, 2, "应为 BAD_PARAM");
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM outcome").get().c, 0);
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM report_batch").get().c, 0, "拒绝的批次不该留下收据");
});

test("REPORT：非法主机名（控制字符）→ STATUS.BAD_PARAM", async () => {
  const db = freshDB();
  const { encodeReport } = await import("../src/frame.js");
  const bad = encodeReport("0123456789abcdef0123456789abcdef", [
    { host: "evil.com\nX", method: "15c0e805", ok: true, unsup: false, rtt_ms: 0, ts: NOW, kind: "ok", proto: "tls" },
  ]);
  const ws = fakeWS();
  await handleFrame(ws, ctxFor(db), encodeFrame(OP.REPORT, 7, bad));
  assert.equal(last(ws).op, OP.STATUS);
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM outcome").get().c, 0);
});

test("REPORT：canceled 记账但不训练方法置信", async () => {
  const db = freshDB();
  const { encodeReport } = await import("../src/frame.js");
  const payload = encodeReport("0123456789abcdef0123456789abcdef", [
    { host: "www.example.com", method: "@direct", ok: false, unsup: false, rtt_ms: 0, ts: NOW, kind: "canceled", proto: "tls" },
  ]);
  const ws = fakeWS();
  await handleFrame(ws, ctxFor(db), encodeFrame(OP.REPORT, 7, payload));
  assert.equal(last(ws).op, OP.REPORT_RESP);
  // method_stat 里不该有这一条（canceled 不产生负证据）
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM method_stat").get().c, 0);
  // 但 outcome 流水仍然记（可审计）
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM outcome").get().c, 1);
});

// --- BUNDLE ----------------------------------------------------------------

test("BUNDLE：hints 按 proto 下发，跨 proto 不串", async () => {
  const db = freshDB();
  const { encodeBundle, decodeBundleResp } = await import("../src/frame.js");
  // 直接塞 hint（跳过挖掘，只测下发路径）
  db.raw.exec(`INSERT INTO hint VALUES ('api.example.com','tls','15c0e805',12,1,4,${NOW + 1200},${NOW})`);
  db.raw.exec(`INSERT INTO hint VALUES ('api.example.org','http','@direct',3,0,3,${NOW + 1200},${NOW})`);

  const ws = fakeWS();
  await handleFrame(ws, ctxFor(db), encodeFrame(OP.BUNDLE, 3, encodeBundle("tls", 8)));
  const f = last(ws);
  assert.equal(f.op, OP.BUNDLE_RESP);
  const back = decodeBundleResp(f.data);
  assert.equal(back.hints.length, 1);
  assert.equal(back.hints[0].suffix, "api.example.com");
  assert.equal(back.hints[0].method, "15c0e805");

  // http 拿自己的那套
  const ws2 = fakeWS();
  await handleFrame(ws2, ctxFor(db), encodeFrame(OP.BUNDLE, 4, encodeBundle("http", 8)));
  const back2 = decodeBundleResp(last(ws2).data);
  assert.equal(back2.hints.length, 1);
  assert.equal(back2.hints[0].suffix, "api.example.org");
});

test("BUNDLE：过期 hint 不下发", async () => {
  const db = freshDB();
  const { encodeBundle, decodeBundleResp } = await import("../src/frame.js");
  db.raw.exec(`INSERT INTO hint VALUES ('old.example.com','tls','@direct',9,0,3,1,${NOW})`);
  const ws = fakeWS();
  await handleFrame(ws, ctxFor(db), encodeFrame(OP.BUNDLE, 3, encodeBundle("tls", 8)));
  assert.deepEqual(decodeBundleResp(last(ws).data).hints, []);
});

// --- 端到端：REPORT 之后 BUNDLE 能拿到刚挖出来的 hint -----------------------

test("端到端：回报积累到足够证据 → BUNDLE 下发新挖出的 hint", async () => {
  const db = freshDB();
  const { encodeReport, encodeBundle, decodeBundleResp } = await import("../src/frame.js");

  // 6 个主机，每个 3 次 15c0e805 成功 → 越过 MIN_HOSTS/MIN_OBSERVATIONS
  const items = [];
  for (let i = 0; i < 6; i++) {
    for (let k = 0; k < 3; k++) {
      items.push(item({ host: `h${i}.z.example.com`, method: "15c0e805", kind: "ok", ok: true }));
    }
  }
  const payload = encodeReport("0123456789abcdef0123456789abcdef", items);
  const ws = fakeWS();
  await handleFrame(ws, ctxFor(db), encodeFrame(OP.REPORT, 7, payload));
  assert.equal(last(ws).op, OP.REPORT_RESP);
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM hint").get().c, 1, "回报后应自动挖出 hint");

  const ws2 = fakeWS();
  await handleFrame(ws2, ctxFor(db), encodeFrame(OP.BUNDLE, 8, encodeBundle("tls", 8)));
  const hints = decodeBundleResp(last(ws2).data).hints;
  assert.equal(hints.length, 1);
  assert.equal(hints[0].suffix, "z.example.com");
  assert.equal(hints[0].method, "15c0e805");
});