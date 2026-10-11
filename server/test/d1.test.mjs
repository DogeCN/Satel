// recordReport 的 exactly-once 语义 + 三种 schema 形态下的行为。
//
// 全部跑**真实 SQLite**（node:sqlite），不是 SQL 文本快照：幂等性、ON CONFLICT
// 累加、事务原子性都是引擎行为，只有真跑才知道。
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { makeD1 } from "./helpers/d1adapter.mjs";
import { migrate } from "../src/migrate.js";
import { recordReport, listHints, replaceHints, pruneHints } from "../src/d1.js";
import { validateItem } from "../src/validate.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA = readFileSync(join(ROOT, "schema.sql"), "utf8");

const LEGACY_SCHEMA = `
CREATE TABLE strategy (id TEXT PRIMARY KEY, spec TEXT NOT NULL, proto TEXT NOT NULL, score REAL NOT NULL DEFAULT 0, trials INTEGER NOT NULL DEFAULT 0, wins INTEGER NOT NULL DEFAULT 0, unsup INTEGER NOT NULL DEFAULT 0, gen INTEGER NOT NULL DEFAULT 0, parent TEXT, created_at INTEGER NOT NULL, retired INTEGER NOT NULL DEFAULT 0);
CREATE TABLE outcome (id INTEGER PRIMARY KEY AUTOINCREMENT, host_hash TEXT NOT NULL, sid TEXT NOT NULL, ok INTEGER NOT NULL, rtt_ms INTEGER, fp TEXT, unsup INTEGER NOT NULL DEFAULT 0, ts INTEGER NOT NULL);
CREATE TABLE host_stat (host_hash TEXT NOT NULL, sid TEXT NOT NULL, ok INTEGER NOT NULL DEFAULT 0, fail INTEGER NOT NULL DEFAULT 0, last_ts INTEGER NOT NULL, PRIMARY KEY (host_hash, sid));
`;

const NOW = 1780000000;

/** 全新库：schema.sql。 */
function freshDB() {
  const d = makeD1(":memory:");
  d.raw.exec(SCHEMA);
  return d;
}

/** 迁移库：旧三表 + 历史行，再 migrate()。 */
function migratedDB() {
  const d = makeD1(":memory:");
  d.raw.exec(LEGACY_SCHEMA);
  d.raw.exec("INSERT INTO strategy VALUES ('15c0e805','tls|split(at=sni)','tls',0.75,100,60,2,4,'aaa',1700000000,0)");
  d.raw.exec("INSERT INTO outcome (host_hash,sid,ok,rtt_ms,fp,unsup,ts) VALUES ('www.example.com','15c0e805',1,118,'fp1',0,1780000000)");
  migrate(d.raw);
  return d;
}

const item = (o) => {
  const base = validateItem({ proto: "tls", rtt_ms: 0, ts: NOW, ...o });
  // 落库 SQL 直接读 JSON 里的 ok/fail，所以要显式带上（validateItem 返回的是
  // 语义字段，derive 出 ok/fail 的**计数增量**：ok=1 或 fail=1，不会两个同时为 1）。
  return { ...base, ok: base.ok ? 1 : 0, fail: base.train && !base.ok ? 1 : 0 };
};

/** 三个主机、共 8 条正证据 + 2 条负证据，足以在 tls 下挖出 hint。 */
function evidenceItems() {
  return [
    item({ host: "www.example.com", method: "15c0e805", kind: "ok", ok: true }),
    item({ host: "www.example.com", method: "15c0e805", kind: "ok", ok: true }),
    item({ host: "api.example.com", method: "15c0e805", kind: "ok", ok: true }),
    item({ host: "cdn.example.com", method: "15c0e805", kind: "ok", ok: true }),
    item({ host: "www.example.com", method: "@direct", kind: "reset", ok: false }),
    item({ host: "api.example.com", method: "@direct", kind: "reset", ok: false }),
  ];
}

// --- exactly-once ---------------------------------------------------------

test("首次投递：method_stat / outcome / strategy / host_stat 全部落库", async () => {
  const db = freshDB();
  const items = evidenceItems();
  const r = await recordReport(db, items, "a".repeat(32), "fp1", NOW);

  assert.deepEqual(r, { accepted: items.length, duplicate: false });
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM outcome").get().c, items.length);
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM report_batch").get().c, 1);
  // method_stat 按 (host, proto, method) 聚合
  const ms = db.raw
    .prepare("SELECT host, method, ok, fail FROM method_stat ORDER BY host, method")
    .all()
    .map((r) => ({ ...r }));
  assert.deepEqual(ms, [
    { host: "api.example.com", method: "15c0e805", ok: 1, fail: 0 },
    { host: "api.example.com", method: "@direct", ok: 0, fail: 1 },
    { host: "cdn.example.com", method: "15c0e805", ok: 1, fail: 0 },
    { host: "www.example.com", method: "15c0e805", ok: 2, fail: 0 },
    { host: "www.example.com", method: "@direct", ok: 0, fail: 1 },
  ]);
});

test("**重复投递幂等**：同一个 batchID 第二次一个字都不写，返回原 accepted", async () => {
  const db = freshDB();
  const items = evidenceItems();
  const bid = "b".repeat(32);
  const first = await recordReport(db, items, bid, "fp1", NOW);
  const before = snapshot(db);

  const second = await recordReport(db, items, bid, "fp1", NOW + 5);

  assert.deepEqual(second, { accepted: first.accepted, duplicate: true });
  assert.deepEqual(snapshot(db), before, "重放改动了任何一行");
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM outcome").get().c, items.length);
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM report_batch").get().c, 1);
});

test("重放 3 次仍然 exactly-once", async () => {
  const db = freshDB();
  const items = evidenceItems();
  const bid = "c".repeat(32);
  await recordReport(db, items, bid, "fp1", NOW);
  const before = snapshot(db);
  for (let i = 0; i < 3; i++) {
    const r = await recordReport(db, items, bid, "fp1", NOW);
    assert.equal(r.duplicate, true);
  }
  assert.deepEqual(snapshot(db), before);
});

test("不同 batchID 是不同批次，正常累加", async () => {
  const db = freshDB();
  const items = evidenceItems();
  await recordReport(db, items, "d".repeat(32), "fp1", NOW);
  await recordReport(db, items, "e".repeat(32), "fp1", NOW + 1);
  // 每批 2 个 www.example.com/15c0e805 的 ok → 两批共 4
  const row = db.raw
    .prepare("SELECT ok FROM method_stat WHERE host=? AND method=?")
    .get("www.example.com", "15c0e805");
  assert.equal(row.ok, 4);
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM outcome").get().c, items.length * 2);
});

test("策略统计：unsup 计 trials 绝不计 win；canceled 两样都不计", async () => {
  const db = freshDB();
  db.raw.exec("INSERT INTO strategy VALUES ('15c0e805','tls|split','tls',0.5,10,5,0,3,NULL,1,0)");

  await recordReport(db, [
    item({ host: "www.example.com", method: "15c0e805", kind: "ok", ok: true }),
    item({ host: "www.example.com", method: "15c0e805", kind: "other", ok: false, unsup: true }),
  ], "f".repeat(32), "fp1", NOW);

  const s = db.raw.prepare("SELECT trials, wins, unsup FROM strategy").get();
  // 1 次真 ok → wins+1；1 次 unsup → trials+1, unsup+1，win 不动
  assert.equal(s.wins, 6);
  assert.equal(s.unsup, 1);
  assert.equal(s.trials, 12);

  await recordReport(db, [
    item({ host: "www.example.com", method: "15c0e805", kind: "canceled", ok: false }),
  ], "0".repeat(32), "fp1", NOW);

  const s2 = db.raw.prepare("SELECT trials, wins, unsup FROM strategy").get();
  assert.deepEqual(s2, s, "canceled 被计入了策略统计");
  // canceled 也不该进 method_stat
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM method_stat").get().c, 1);
});

test("策略统计：伪方法不污染 strategy 表", async () => {
  const db = freshDB();
  db.raw.exec("INSERT INTO strategy VALUES ('15c0e805','tls|split','tls',0.5,10,5,0,3,NULL,1,0)");
  await recordReport(db, [
    item({ host: "www.example.com", method: "@direct", kind: "ok", ok: true }),
    item({ host: "www.example.com", method: "@tunnel", kind: "ok", ok: true }),
    item({ host: "www.example.com", method: "@ech", kind: "ok", ok: true }),
  ], "1".repeat(32), "fp1", NOW);
  const s = db.raw.prepare("SELECT trials, wins, unsup FROM strategy").get();
  assert.deepEqual({ ...s }, { trials: 10, wins: 5, unsup: 0 }, "伪方法动了 strategy");
  // 但 method_stat 要记它们——伪方法的方法置信是真信号
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM method_stat").get().c, 3);
});

test("空批次也落收据（客户端重连反复发空批时不空转）", async () => {
  const db = freshDB();
  const r = await recordReport(db, [], "2".repeat(32), "fp1", NOW);
  assert.deepEqual(r, { accepted: 0, duplicate: false });
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM report_batch").get().c, 1);
  const r2 = await recordReport(db, [], "2".repeat(32), "fp1", NOW);
  assert.deepEqual(r2, { accepted: 0, duplicate: true });
});

test("迁移库同样 exactly-once（outcome 旧列仍被写，历史行不被覆盖）", async () => {
  const db = migratedDB();
  const items = evidenceItems();
  await recordReport(db, items, "3".repeat(32), "fp1", NOW);
  const before = snapshot(db);
  const r = await recordReport(db, items, "3".repeat(32), "fp1", NOW);
  assert.equal(r.duplicate, true);
  assert.deepEqual(snapshot(db), before);
  // 旧列 host_hash/sid 有值（历史查询不丢），新列 host/method 也有值
  const o = db.raw
    .prepare("SELECT host_hash, sid, host, method, kind, proto, batch_id FROM outcome WHERE batch_id IS NOT NULL LIMIT 1")
    .get();
  assert.equal(o.host_hash, o.host);
  assert.equal(o.sid, o.method);
  assert.equal(o.proto, "tls");
  assert.equal(o.batch_id, "3".repeat(32));
  assert.equal(o.kind, "ok");
  // 历史行原样保留：kind / batch_id 为 NULL 就是"这条是旧格式"的标记
  const legacyRow = db.raw.prepare("SELECT kind, batch_id FROM outcome WHERE batch_id IS NULL").get();
  assert.equal(legacyRow.kind, null);
  assert.equal(legacyRow.batch_id, null);
});

test("事务原子性：最后一条失败 → 前面的写入全部回滚", async () => {
  const db = freshDB();
  const items = evidenceItems();
  // 用一个非法的 batchID 长度让收据插入失败，前面的守卫语句必须一起回滚。
  await assert.rejects(
    () => recordReport(db, items, "tooshort", "fp1", NOW),
    /batch_id|NOT NULL|constraint/i,
  );
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM outcome").get().c, 0,
    "回滚后 outcome 仍有数据");
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM method_stat").get().c, 0,
    "回滚后 method_stat 仍有数据");
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM report_batch").get().c, 0,
    "回滚后 report_batch 仍有数据");
});

// --- hint 读写 -----------------------------------------------------------

test("hint 按 proto 取，过期的不返回", async () => {
  const db = freshDB();
  await replaceHints(db, "tls", [
    { suffix: "example.com", method: "15c0e805", ok: 5, fail: 1, hosts: 3, expires: NOW + 1200 },
    { suffix: "expired.com", method: "@direct", ok: 1, fail: 9, hosts: 3, expires: NOW - 1 },
  ], NOW);
  const live = await listHints(db, "tls", 128, NOW);
  assert.equal(live.length, 1);
  assert.equal(live[0].suffix, "example.com");
  // http 是空的
  assert.equal((await listHints(db, "http", 128, NOW)).length, 0);
  // 过期清理
  await pruneHints(db, NOW);
  assert.equal(db.raw.prepare("SELECT COUNT(*) AS c FROM hint").get().c, 1);
});

test("replaceHints 是替换不是累加", async () => {
  const db = freshDB();
  await replaceHints(db, "tls", [
    { suffix: "a.com", method: "@direct", ok: 5, fail: 0, hosts: 3, expires: NOW + 1200 },
  ], NOW);
  await replaceHints(db, "tls", [
    { suffix: "b.com", method: "@direct", ok: 9, fail: 1, hosts: 4, expires: NOW + 1200 },
  ], NOW + 1);
  const rows = db.raw.prepare("SELECT suffix, ok FROM hint ORDER BY suffix").all().map((r) => ({ ...r }));
  assert.deepEqual(rows, [{ suffix: "b.com", ok: 9 }], "旧行没被替换掉");
});

// --- 结伴断言用的快照 -----------------------------------------------------

function snapshot(db) {
  const q = (sql) => db.raw.prepare(sql).all().map((r) => ({ ...r }));
  return JSON.stringify({
    outcome: q("SELECT * FROM outcome ORDER BY id"),
    method_stat: q("SELECT * FROM method_stat ORDER BY host, proto, method"),
    strategy: q("SELECT * FROM strategy ORDER BY id"),
    host_stat: q("SELECT * FROM host_stat ORDER BY host_hash, sid"),
    report_batch: q("SELECT * FROM report_batch ORDER BY batch_id"),
    hint: q("SELECT * FROM hint ORDER BY suffix, proto, method"),
  }, (k, v) => (v === undefined ? null : v));
}
