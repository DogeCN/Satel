// schema.sql / migrations 的验证：全新库 + 迁移旧库 + 幂等性。
//
// 用 node:sqlite（Node 24 内置，不需要任何依赖）跑真实 SQL——不是 SQL 文本快照。
// 断言的重点是"**不破坏既有数据**"：迁移前后 strategy / outcome / host_stat 的
// 每一行必须逐字节相同，否则这次升级就是有损的。
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

import { migrate, missingOutcomeColumns } from "../src/migrate.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA = readFileSync(join(ROOT, "schema.sql"), "utf8");
const MIGRATION = readFileSync(join(ROOT, "migrations/0002_method_stats_hints.sql"), "utf8");

const LEGACY_SCHEMA = `
CREATE TABLE strategy (
  id TEXT PRIMARY KEY, spec TEXT NOT NULL, proto TEXT NOT NULL,
  score REAL NOT NULL DEFAULT 0, trials INTEGER NOT NULL DEFAULT 0,
  wins INTEGER NOT NULL DEFAULT 0, unsup INTEGER NOT NULL DEFAULT 0,
  gen INTEGER NOT NULL DEFAULT 0, parent TEXT, created_at INTEGER NOT NULL,
  retired INTEGER NOT NULL DEFAULT 0);
CREATE TABLE outcome (
  id INTEGER PRIMARY KEY AUTOINCREMENT, host_hash TEXT NOT NULL, sid TEXT NOT NULL,
  ok INTEGER NOT NULL, rtt_ms INTEGER, fp TEXT,
  unsup INTEGER NOT NULL DEFAULT 0, ts INTEGER NOT NULL);
CREATE TABLE host_stat (
  host_hash TEXT NOT NULL, sid TEXT NOT NULL, ok INTEGER NOT NULL DEFAULT 0,
  fail INTEGER NOT NULL DEFAULT 0, last_ts INTEGER NOT NULL, PRIMARY KEY (host_hash, sid));
CREATE INDEX idx_outcome_sid_ts ON outcome(sid, ts);
CREATE INDEX idx_outcome_host_ts ON outcome(host_hash, ts);
CREATE INDEX idx_strategy_proto_score ON strategy(proto, retired, score DESC);
`;

const LEGACY_ROWS = [
  `INSERT INTO strategy VALUES ('15c0e805','tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)','tls',0.75,100,60,2,4,'aaa',1700000000,0)`,
  `INSERT INTO strategy VALUES ('78c3d41b','tls|tlsrf(chunk=8,delay_ms=8,limit=400)','tls',0.5,40,10,0,3,NULL,1700000001,1)`,
  `INSERT INTO outcome (host_hash, sid, ok, rtt_ms, fp, unsup, ts) VALUES
     ('www.example.com','15c0e805',1,118,'fp1',0,1780000000),
     ('www.example.com','@direct',0,0,'fp1',0,1780000001),
     ('a.example.com','15c0e805',1,90,'fp2',0,1780000002)`,
  `INSERT INTO host_stat VALUES ('www.example.com','15c0e805',5,1,1780000000)`,
  `INSERT INTO host_stat VALUES ('a.example.com','@direct',2,3,1780000002)`,
];

/** 造一个"迁移前的旧库"：旧三表 + 真实历史行。 */
function legacyDB() {
  const db = new DatabaseSync(":memory:");
  db.exec(LEGACY_SCHEMA);
  for (const sql of LEGACY_ROWS) db.exec(sql);
  return db;
}

function snapshot(db) {
  return JSON.stringify({
    strategy: db.prepare("SELECT * FROM strategy ORDER BY id").all(),
    outcome: db.prepare("SELECT * FROM outcome ORDER BY id").all(),
    host_stat: db.prepare("SELECT * FROM host_stat ORDER BY host_hash, sid").all(),
  });
}

function tables(db) {
  return db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    .all()
    .map((r) => r.name);
}

function cols(db, table) {
  return db.prepare(`SELECT name FROM pragma_table_info('${table}')`).all().map((r) => r.name);
}

/** node:sqlite 的 .all() 返回 null-prototype 对象，assert.deepEqual 对它们敏感。 */
function rows(db, sql, ...args) {
  return db.prepare(sql).all(...args).map((r) => ({ ...r }));
}

// --- 全新库 ---------------------------------------------------------------

test("schema.sql 建出全部表与索引", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(SCHEMA);
  for (const t of ["strategy", "outcome", "host_stat", "method_stat", "report_batch", "hint"]) {
    assert.ok(tables(db).includes(t), `缺表 ${t}`);
  }
  for (const i of ["idx_method_stat_proto_ts", "idx_hint_proto_expires", "idx_report_batch_ts"]) {
    const idx = db.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name = ?").get(i);
    assert.ok(idx, `缺索引 ${i}`);
  }
  assert.deepEqual(cols(db, "method_stat"), ["host", "proto", "method", "ok", "fail", "last_kind", "last_ts"]);
  assert.deepEqual(cols(db, "report_batch"), ["batch_id", "accepted", "fp", "ts"]);
  assert.deepEqual(cols(db, "hint"), ["suffix", "proto", "method", "ok", "fail", "hosts", "expires", "updated"]);
});

test("迁移建出 idx_outcome_batch（schema.sql 故意不建它——见那里的注释）", () => {
  const fresh = new DatabaseSync(":memory:");
  fresh.exec(SCHEMA);
  // 全新库上 schema.sql 单独执行不该失败，但也没有 batch_id 索引（列由 CREATE TABLE 建出，
  // 索引留给 migration；全新库跑一次 migration 是空操作但会补上索引）。
  const legacy = legacyDB();
  migrate(legacy);
  const idx = legacy.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name = 'idx_outcome_batch'").get();
  assert.ok(idx, "迁移后应有 idx_outcome_batch");
});

test("schema.sql 可反复执行（无 ALTER，天然幂等）", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(SCHEMA);
  db.exec(SCHEMA);
  db.exec(SCHEMA);
  // 表没有翻倍、行没有丢
  assert.equal(tables(db).filter((t) => t === "method_stat").length, 1);
  db.exec("INSERT INTO method_stat (host,proto,method) VALUES ('a.com','tls','@direct')");
  db.exec(SCHEMA);
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM method_stat").get().c, 1);
});

// --- 迁移旧库 -------------------------------------------------------------

test("迁移后 outcome 补上五列", () => {
  const db = legacyDB();
  assert.deepEqual(missingOutcomeColumns(db), ["host", "method", "kind", "proto", "batch_id"]);
  migrate(db);
  for (const c of ["host", "method", "kind", "proto", "batch_id"]) {
    assert.ok(cols(db, "outcome").includes(c), `迁移后仍缺列 ${c}`);
  }
  assert.equal(missingOutcomeColumns(db).length, 0);
});

test("迁移**不破坏**既有数据", () => {
  const db = legacyDB();
  const before = snapshot(db);
  migrate(db);
  const after = snapshot(db);
  // 逐表逐字段比对：新增列在 outcome 里出现（回填所致），但旧列一个值都不能变。
  const b = JSON.parse(before);
  const a = JSON.parse(after);
  assert.deepEqual(a.strategy, b.strategy, "strategy 被改了");
  assert.deepEqual(a.host_stat, b.host_stat, "host_stat 被改了");
  assert.equal(a.outcome.length, b.outcome.length, "outcome 行数变了");
  for (let i = 0; i < b.outcome.length; i++) {
    for (const k of ["id", "host_hash", "sid", "ok", "rtt_ms", "fp", "unsup", "ts"]) {
      assert.deepEqual(a.outcome[i][k], b.outcome[i][k], `outcome[${i}].${k} 被改了`);
    }
  }
});

test("历史行回填 host/method/proto（kind 留 NULL = 未知）", () => {
  const db = legacyDB();
  migrate(db);
  const r = rows(db, "SELECT id, host, method, kind, proto FROM outcome ORDER BY id");
  assert.deepEqual(r[0], { id: 1, host: "www.example.com", method: "15c0e805", kind: null, proto: "tls" });
  assert.deepEqual(r[1], { id: 2, host: "www.example.com", method: "@direct", kind: null, proto: "tls" });
  assert.deepEqual(r[2], { id: 3, host: "a.example.com", method: "15c0e805", kind: null, proto: "tls" });
});

test("迁移建出三张新表", () => {
  const db = legacyDB();
  migrate(db);
  for (const t of ["method_stat", "report_batch", "hint"]) {
    assert.ok(tables(db).includes(t), `迁移后缺表 ${t}`);
  }
});

test("迁移本身可重复执行（靠 PRAGMA 判断，不是靠 SQL 层的 IF NOT EXISTS）", () => {
  const db = legacyDB();
  migrate(db);
  migrate(db);
  migrate(db);
  // 第二次迁移没有新增列、没有重复执行 ALTER，所以不会 duplicate column。
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM outcome").get().c, 3);
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM strategy").get().c, 2);
  // 回填只在第一次发生，不会反复覆盖
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM outcome WHERE host = 'www.example.com'").get().c, 2);
});

test("迁移后 schema.sql 也能安全应用（两遍）", () => {
  const db = legacyDB();
  migrate(db);
  db.exec(SCHEMA);
  db.exec(SCHEMA);
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM outcome").get().c, 3);
});

// --- 原始 SQL 文件路径（CLI 文档里写的顺序）--------------------------------

test("文档顺序：schema.sql → migrations/0002 在有历史行的旧库上成立", () => {
  const db = legacyDB();
  db.exec(SCHEMA);
  // schema.sql 不含 ALTER，所以这一步只建缺的表；outcome 的明文字段仍缺。
  assert.equal(missingOutcomeColumns(db).length, 5);
  db.exec(MIGRATION);
  assert.equal(missingOutcomeColumns(db).length, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM outcome").get().c, 3);
});

test("migrations/0002 单独执行时不能重复（文档已说明，这里锁住该行为）", () => {
  const db = legacyDB();
  db.exec(MIGRATION);
  // SQLite 的 ADD COLUMN 没有 IF NOT EXISTS，第二次必然 duplicate column。
  assert.throws(() => db.exec(MIGRATION), /duplicate column name/);
});
