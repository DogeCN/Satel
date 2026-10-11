// test/ 用的本地 D1 兼容适配器。
//
// 为什么不用 D1：离线测试不能碰 Cloudflare，而"假适配器只捕获 SQL"验不了**结果**——
// 幂等性、ON CONFLICT 累加、事务原子性这些全是 SQL 引擎的行为，只有真跑才知道。
// Node 24 自带 node:sqlite（真 SQLite），API 与 D1 的 prepare/bind/batch 对齐，
// 补一层薄适配即可。
//
// 这个适配器**故意只实现被测路径用到的方法**：prepare/bind/all/first/run/batch。
// 不是 D1 的替代品，是它的"本地替身"。
import { DatabaseSync } from "node:sqlite";

/**
 * @param {string|':memory:'|DatabaseSync} pathOrDb
 * @returns {{db: DatabaseSync, prepare: Function}} 带 D1 风格 prepare 的对象
 */
export function makeD1(pathOrDb = ":memory:") {
  const raw = typeof pathOrDb === "string" ? new DatabaseSync(pathOrDb) : pathOrDb;
  // 与 D1 一样把外键与递归触发器留着（迁移脚本里没有用到，但保持行为一致）。
  raw.exec("PRAGMA foreign_keys = ON;");

  return {
    raw,
    prepare(sql) {
      const stmt = raw.prepare(sql);
      // D1 的 D1PreparedStatement 上**直接**就有 all/first/run（无参版本），
      // bind() 返回另一个同样带这三个方法的 D1PreparedStatement。node:sqlite 的
      // stmt.get/all 需要至少一个参数（否则抛 "Too few parameter values"），
      // 所以无参调用要用真值来判断而不是靠参数个数。
      const withParams = (params) => ({
        async all() {
          try {
            const rows = params.length ? stmt.all(...params) : stmt.all();
            return { results: rows.map(norm) };
          } catch (e) {
            if (e && /no rows|no such table/i.test(e.message)) return { results: [] };
            throw e;
          }
        },
        async first() {
          const r = params.length ? stmt.get(...params) : stmt.get();
          return r == null ? null : norm(r);
        },
        async run() {
          const info = params.length ? stmt.run(...params) : stmt.run();
          return { success: true, meta: { changes: info.changes } };
        },
      });
      // 无参版本（D1: db.prepare(sql).first()）
      const bare = withParams([]);
      return {
        bind(...params) { return withParams(params); },
        all: bare.all,
        first: bare.first,
        run: bare.run,
      };
    },
    /**
     * D1 的 batch 是**事务**：任一条失败整体回滚。
     * node:sqlite 的 run() 是自动提交的，所以要显式 BEGIN/COMMIT 才等价。
     */
    async batch(stmts) {
      raw.exec("BEGIN");
      try {
        const out = [];
        for (const s of stmts) {
          // D1PreparedStatement 在本适配器里是 {sql, params} 的形状；但 ws.js/d1.js
          // 传的是 bind() 之后的对象。这里兼容两种：优先走对象的 run()。
          if (typeof s.run === "function") {
            const r = await s.run();
            out.push(r);
          } else if (typeof s.all === "function") {
            const r = await s.all();
            out.push(r);
          } else {
            throw new Error("batch 里有不可执行的语句");
          }
        }
        raw.exec("COMMIT");
        return out;
      } catch (e) {
        raw.exec("ROLLBACK");
        throw e;
      }
    },
  };
}

/** node:sqlite 返回 null-prototype 对象，转成普通对象便于断言。 */
function norm(r) {
  return r == null ? r : { ...r };
}
