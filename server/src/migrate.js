// 迁移：把 schema.sql / migrations/*.sql 按正确的顺序、以幂等的方式应用。
//
// 为什么需要这个而不是直接 `wrangler d1 execute --file=`：
// SQLite 的 `ALTER TABLE ADD COLUMN` 没有 `IF NOT EXISTS`，所以 migrations 里的
// 迁移**不能**重复执行（第二次会 "duplicate column name" 失败）。而"是否已迁移过"
// 只有数据库自己知道——所以这里先查 PRAGMA table_info，缺列才 ALTER，有列就跳过。
// 这样同一个迁移文件可以安全地反复跑。
//
// 用法（离线，本地 D1 或任意 node:sqlite 文件）：
//     node src/migrate.js --db <path-or-:memory:> [--dry-run]
//
// 线上（D1）不能用本 CLI 直连——凭据在 wrangler 里，请用 wrangler：
//     npx wrangler d1 execute satel --remote --file=./schema.sql
//     npx wrangler d1 execute satel --remote --file=./migrations/0002_method_stats_hints.sql
// 但有 `--dry-run` 可以先核对：它会打印将要执行什么，不做任何修改。

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER_ROOT = join(HERE, "..");

/** 每个迁移要 ADD 的列名（与 0002_method_stats_hints.sql 中的 ALTER 一一对应）。 */
const OUTCOME_COLUMNS = ["host", "method", "kind", "proto", "batch_id"];

/**
 * outcome 表缺少哪些列。
 *
 * 表不存在时返回全部列名（语义等价于"全缺"——反正 CREATE TABLE IF NOT EXISTS 会建）。
 */
export function missingOutcomeColumns(db) {
  const cols = db
    .prepare("SELECT name FROM pragma_table_info('outcome')")
    .all()
    .map((r) => r.name);
  if (cols.length === 0) return OUTCOME_COLUMNS.slice();
  return OUTCOME_COLUMNS.filter((c) => !cols.includes(c));
}

/**
 * 应用 schema.sql（全新库形态）与 migrations/ 下的迁移。
 *
 * @param {import('node:sqlite').DatabaseSync} db  本地 SQLite 连接
 * @param {{dryRun?: boolean}} [opts]
 * @returns {{applied: string[], skipped: string[]}}
 */
export function migrate(db, opts = {}) {
  const dryRun = !!opts.dryRun;
  const applied = [];
  const skipped = [];

  // 1. schema.sql —— 全部 CREATE ... IF NOT EXISTS，可以无条件反复执行。
  //    它不带 ALTER，所以重复跑是安全的（ADD COLUMN 在 migrations 里）。
  const schema = readFileSync(join(SERVER_ROOT, "schema.sql"), "utf8");
  if (!dryRun) db.exec(schema);
  applied.push("schema.sql");

  // 2. migrations/*.sql —— 按文件名排序执行。
  //    对每个迁移，先按它声明的列名集合判断"是否已应用"；只 ALTER 缺的列。
  //    ⚠ 只支持"ADD COLUMN 型"迁移：别的迁移（建新表/建索引）本身就是幂等的，
  //    直接 exec 即可，不需要判断。
  const dir = join(SERVER_ROOT, "migrations");
  let files = [];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
  } catch {
    // 没有 migrations 目录不算错误——全新库里 schema.sql 就够了。
  }

  for (const f of files) {
    const sql = readFileSync(join(dir, f), "utf8");
    // 本迁移只处理 outcome 的 ADD COLUMN；且只在有列缺失时才真正 ALTER。
    const need = missingOutcomeColumns(db);
    if (need.length === 0) {
      skipped.push(f);
      continue;
    }
    if (!dryRun) {
      // 1. 先把**所有**缺列补上，再执行迁移文件里其余部分。
      //    顺序要紧：迁移文件里的回填 UPDATE 会引用这些新列（
      //    `UPDATE outcome SET host = host_hash`），列没加全就执行会
      //    "no such column"。逐列 ALTER 之间不能夹其它语句。
      for (const col of need) {
        // ADD COLUMN 不支持 IF NOT EXISTS，所以逐列查过才加。
        db.exec(`ALTER TABLE outcome ADD COLUMN ${col} TEXT;`);
      }
      // 2. 迁移文件里的非 ALTER 部分（建表/建索引/回填）幂等，照常执行。
      const nonAlter = sql
        .split("\n")
        .filter((line) => !/^\s*ALTER\s+TABLE\s+outcome\s+ADD\s+COLUMN/i.test(line))
        .join("\n");
      db.exec(nonAlter);
    }
    applied.push(f);
  }

  return { applied, skipped };
}

// --- CLI -------------------------------------------------------------------

function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const dbIdx = args.indexOf("--db");
  const path = dbIdx >= 0 ? args[dbIdx + 1] : ":memory:";

  const db = new DatabaseSync(path);
  try {
    const missing = missingOutcomeColumns(db);
    if (dryRun) {
      console.log(`[dry-run] ${path}`);
      console.log(`[dry-run] outcome 缺少的列: ${missing.join(", ") || "（无）"}`);
      console.log("[dry-run] 不会做任何修改");
      return;
    }
    const { applied, skipped } = migrate(db);
    console.log(`已应用: ${applied.join(", ") || "（无）"}`);
    console.log(`已跳过: ${skipped.join(", ") || "（无）"}`);
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all()
      .map((r) => r.name);
    console.log(`表: ${tables.join(", ")}`);
    const cols = db
      .prepare("SELECT name FROM pragma_table_info('outcome')")
      .all()
      .map((r) => r.name);
    console.log(`outcome 列: ${cols.join(", ")}`);
  } finally {
    db.close();
  }
}

// 直接执行（不作为模块被 import）时才跑 CLI。
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    main();
  } catch (err) {
    console.error(`迁移失败: ${err.message}`);
    process.exit(1);
  }
}