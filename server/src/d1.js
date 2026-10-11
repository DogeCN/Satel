// Thin data-access helpers over the Cloudflare D1 binding (`env.DB`).
//
// Nothing here is importable without a real D1 binding, so this module is kept
// free of top-level side effects and is not exercised by the offline tests.
//
// 本模块的三条核心保证：
//
//   1. **exactly-once**：recordReport 的所有写入都在**一个** db.batch() 事务里，
//      每条语句都被 `NOT EXISTS (SELECT 1 FROM report_batch WHERE batch_id = ?)`
//      守着，而收据行是批次里**最后**一条。重复投递 → 收据已存在 → 全部写入
//      一条不执行 → 返回原 accepted。D1 的 batch 是事务（任一条失败整体回滚），
//      所以不存在"写了一半"的中间态。
//   2. **不碰旧路径**：outcome 仍写 host_hash/sid（旧列，NOT NULL），只是同时
//      把明文写进 host/method/kind/proto。host_stat 仍按旧键维护。
//   3. **策略统计只认真策略**：只有 8 位 hex 方法 ID 才 UPDATE strategy 表；
//      伪方法（@direct/@ech/…）在 strategy 里没有行，命中 0 行是设计如此。

/** Columns returned for a strategy row. */
const STRATEGY_COLUMNS =
  "id, spec, proto, score, trials, wins, unsup, gen, parent, created_at, retired";

/**
 * Top strategies for a bundle: non-retired, matching proto, highest score first.
 */
export async function listPool(db, { proto, limit }) {
  const { results } = await db
    .prepare(
      `SELECT ${STRATEGY_COLUMNS} FROM strategy
       WHERE retired = 0 AND proto = ?
       ORDER BY score DESC, trials DESC, id ASC
       LIMIT ?`,
    )
    .bind(proto, limit)
    .all();
  return results ?? [];
}

/** Every strategy row (retired included) — used by the evolution loop. */
export async function listAllStrategies(db) {
  const { results } = await db
    .prepare(`SELECT ${STRATEGY_COLUMNS} FROM strategy`)
    .all();
  return results ?? [];
}

/** max(gen) across the whole strategy table; 0 when empty. */
export async function maxGeneration(db) {
  const row = await db.prepare("SELECT COALESCE(MAX(gen), 0) AS g FROM strategy").first();
  return row && row.g != null ? row.g : 0;
}

/** Number of non-retired strategies (optionally filtered by proto). */
export async function countActive(db, proto) {
  const stmt = proto
    ? db.prepare("SELECT COUNT(*) AS c FROM strategy WHERE retired = 0 AND proto = ?").bind(proto)
    : db.prepare("SELECT COUNT(*) AS c FROM strategy WHERE retired = 0");
  const row = await stmt.first();
  return row && row.c != null ? row.c : 0;
}

/** Insert new strategy rows. Returns the number of rows written. */
export async function insertStrategies(db, rows) {
  if (!rows || rows.length === 0) return 0;
  const stmt = db.prepare(
    `INSERT OR IGNORE INTO strategy
       (id, spec, proto, score, trials, wins, unsup, gen, parent, created_at, retired)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const batch = rows.map((r) =>
    stmt.bind(
      r.id,
      r.spec,
      r.proto,
      r.score ?? 0,
      r.trials ?? 0,
      r.wins ?? 0,
      r.unsup ?? 0,
      r.gen ?? 0,
      r.parent ?? null,
      r.created_at ?? Date.now(),
      r.retired ?? 0,
    ),
  );
  await db.batch(batch);
  return rows.length;
}

/** Mark strategies retired (rows are kept for history). */
export async function retireStrategies(db, ids) {
  if (!ids || ids.length === 0) return 0;
  const stmt = db.prepare("UPDATE strategy SET retired = 1 WHERE id = ?");
  await db.batch(ids.map((id) => stmt.bind(id)));
  return ids.length;
}

// --- 回报落库（exactly-once）---------------------------------------------
//
// 用 json1 把整批当作**一条** SQL 语句发出去，而不是"每项三条语句"。
//
// 为什么必须这样：D1 的 batch 单条 SQL 有 100 个绑定参数上限、100 KB 语句长度上限。
// 每项 9 个字段的逐项绑定，64 项就要 576 个参数——超限。而整批序列化成 JSON 后
// 只需要 2 个参数（JSON 串 + batchID），64 项也只有约 7 KB，远在限制之内。
//
// 三个写目标（method_stat / outcome / strategy）**各自**一条语句，都带同一个
// `NOT EXISTS (... report_batch ...)` 守卫；收据行在批次里最后插。db.batch() 是
// 事务，所以要么全部生效、要么全部不生效，不存在中间态。

const NOT_APPLIED = `NOT EXISTS (SELECT 1 FROM report_batch WHERE batch_id = ?)`;

/**
 * method_stat 的幂等累加（含 last_kind/last_ts 的最新值覆盖）。
 *
 * ok/fail 读的是 **ok_inc / fail_inc**（互斥的整数增量，由 validateItem 派生），
 * 不是布尔 ok——布尔进 CAST 会变成 0/1 也还行，但缺 fail 时 JSON 里没有这个键，
 * `->>'fail'` 返回 NULL，直接违反 NOT NULL。显式的两个整数字段把这条歧义消掉了。
 *
 * `WHERE train = 1`：**canceled 与 unsup 两类不进 method_stat**。它们没有产生任何
 * 观测（取消是用户行为、unsup 是策略没跑起来），插一行 0/0 只会让"某主机试过这个
 * 方法"的查询把它误认成一条战绩。它们的流水仍在 outcome 里可审计。
 */
const UPSERT_METHOD_STAT = `
INSERT INTO method_stat (host, proto, method, ok, fail, last_kind, last_ts)
SELECT j.value->>'host',
       j.value->>'proto',
       j.value->>'method',
       CAST(j.value->>'ok_inc'   AS INTEGER),
       CAST(j.value->>'fail_inc' AS INTEGER),
       j.value->>'kind',
       CAST(j.value->>'ts'       AS INTEGER)
  FROM json_each(?) AS j
 WHERE ${NOT_APPLIED}
   AND CAST(j.value->>'train' AS INTEGER) = 1
ON CONFLICT (host, proto, method) DO UPDATE SET
  ok       = ok + excluded.ok,
  fail     = fail + excluded.fail,
  last_kind = excluded.last_kind,
  last_ts   = MAX(last_ts, excluded.last_ts)`;

/**
 * strategy 的聚合更新。
 *
 * `UPDATE ... FROM (SELECT ...)` 把整批按 method 聚合成一行，一条语句更新多个策略；
 * 逐条 UPDATE 会让 64 项发 64 条语句。unsup 计 trials+unsup 但**绝不计 win**；
 * canceled 两样都不计（它连一次完整尝试都不是）。
 *
 * `s.proto = u.proto` 是**协议隔离**的保证：同一条策略 ID 出现在两个 proto 下时
 * （evolution 的 `proto` 变异会翻它），两边的计数绝不串门。
 */
const UPDATE_STRATEGY = `
UPDATE strategy AS s
   SET trials = s.trials + u.trials,
       wins   = s.wins   + u.wins,
       unsup  = s.unsup  + u.unsup,
       score  = (s.wins + u.wins + 1.0) / (s.trials + u.trials + 1 + 2)
  FROM (SELECT j.value->>'method' AS method,
               j.value->>'proto'  AS proto,
               SUM(CASE WHEN CAST(j.value->>'countsAsTrial' AS INTEGER) = 1 THEN 1 ELSE 0 END) AS trials,
               SUM(CASE WHEN CAST(j.value->>'countsAsWin'   AS INTEGER) = 1 THEN 1 ELSE 0 END) AS wins,
               SUM(CASE WHEN CAST(j.value->>'countsAsUnsup' AS INTEGER) = 1 THEN 1 ELSE 0 END) AS unsup
          FROM json_each(?) AS j
         WHERE ${NOT_APPLIED}
         GROUP BY j.value->>'method', j.value->>'proto') AS u
 WHERE s.id = u.method AND s.proto = u.proto`;

/**
 * outcome 流水（保留旧列 + 新列）。
 *
 * host_hash / sid 继续写，保持历史查询与既有报表可用；host/method/kind/proto/batch_id
 * 是新列，让"方法级"查询不必再依赖 host_hash 的旧语义。
 */
const INSERT_OUTCOME = `
INSERT INTO outcome (host_hash, sid, ok, rtt_ms, fp, unsup, ts, host, method, kind, proto, batch_id)
SELECT j.value->>'host',
       j.value->>'method',
       CAST(j.value->>'ok'    AS INTEGER),
       CAST(j.value->>'rtt_ms' AS INTEGER),
       ?,
       CAST(j.value->>'unsup' AS INTEGER),
       CAST(j.value->>'ts'    AS INTEGER),
       j.value->>'host',
       j.value->>'method',
       j.value->>'kind',
       j.value->>'proto',
       ?
  FROM json_each(?) AS j
 WHERE ${NOT_APPLIED}`;

/** host_stat（旧路径，按 (host_hash, sid) 维护）。同样读 ok_inc / fail_inc。 */
const UPSERT_HOST_STAT = `
INSERT INTO host_stat (host_hash, sid, ok, fail, last_ts)
SELECT j.value->>'host',
       j.value->>'method',
       CAST(j.value->>'ok_inc'   AS INTEGER),
       CAST(j.value->>'fail_inc' AS INTEGER),
       CAST(j.value->>'ts'       AS INTEGER)
  FROM json_each(?) AS j
 WHERE ${NOT_APPLIED}
ON CONFLICT (host_hash, sid) DO UPDATE SET
  ok      = ok + excluded.ok,
  fail    = fail + excluded.fail,
  last_ts = MAX(last_ts, excluded.last_ts)`;

/**
 * 落一批回报。**幂等**：同一个 batchID 重复投递只生效一次。
 *
 * 三步：
 *   1. 先查收据——命中就返回原 accepted，一个字都不写（这是最常见的重复路径）；
 *   2. 一个 db.batch() 事务里四条写语句，各带 `NOT EXISTS (... report_batch ...)`
 *      守卫，收据行**最后**插（且是裸 INSERT，不用 OR IGNORE——原因见下）；
 *   3. 事务后再读一次收据，以它的 accepted 为准返回。
 *
 * 为什么收据用裸 INSERT 而不是 `INSERT OR IGNORE`：OR IGNORE 会把**约束违例**
 * 也静默吞掉（SQLite 的 OR IGNORE 跳过所有约束失败的行，包括 CHECK）。真出这种事
 * 时，四条写语句已经生效而收据没插——事务照样 COMMIT，于是"批次已入账"的凭据永久
 * 缺失，下一次重放会双计。裸 INSERT 让约束违例真的抛错，整个事务回滚，客户端重试
 * 即可（D1 写是串行的，重试时第 1 步就命中收据，直接返回原 accepted）。
 *
 * @param {object} db        D1 binding
 * @param {object[]} items   已通过 validateItem 的条目（含 train/countsAs* 派生字段）
 * @param {string} batchID   32 位小写 hex，客户端的幂等键
 * @param {string|null} fp  客户端指纹（HELLO 里带的）
 * @param {number} now      unix 秒，用于收据的 ts
 * @returns {Promise<{accepted:number, duplicate:boolean}>}
 */
export async function recordReport(db, items, batchID, fp, now) {
  // 1. 收据已在 → 直接返回，不写任何东西。
  const existing = await db
    .prepare("SELECT accepted FROM report_batch WHERE batch_id = ?")
    .bind(batchID)
    .first();
  if (existing) {
    return { accepted: existing.accepted, duplicate: true };
  }

  if (!items || items.length === 0) {
    // 空批也要落收据：否则客户端反复发空批（重连时确实会发生）每次都白跑一次事务。
    await db.batch([
      db
        .prepare("INSERT INTO report_batch (batch_id, accepted, fp, ts) VALUES (?, ?, ?, ?)")
        .bind(batchID, 0, fp ?? null, now),
    ]);
    return { accepted: 0, duplicate: false };
  }

  const payload = JSON.stringify(items);

  try {
    await db.batch([
      db.prepare(UPSERT_METHOD_STAT).bind(payload, batchID),
      db.prepare(UPSERT_HOST_STAT).bind(payload, batchID),
      db.prepare(INSERT_OUTCOME).bind(fp ?? null, batchID, payload, batchID),
      db.prepare(UPDATE_STRATEGY).bind(payload, batchID),
      // **收据最后插**：前面四条都被它守着，它一存在，整个批次就再也写不动。
      // 裸 INSERT（无 OR IGNORE）——见上面的说明。
      db
        .prepare("INSERT INTO report_batch (batch_id, accepted, fp, ts) VALUES (?, ?, ?, ?)")
        .bind(batchID, items.length, fp ?? null, now),
    ]);
  } catch (err) {
    // 并发撞车：两个 Worker 同时看到一个"不存在"的收据，都进了事务。D1 写是串行的，
    // 后一个在这里撞主键。此时前一个已经提交，重读收据即可拿到它的 accepted——
    // 这正是"重复批次返回原始 accepted"在竞态下的正确表现。
    const raced = await db
      .prepare("SELECT accepted FROM report_batch WHERE batch_id = ?")
      .bind(batchID)
      .first();
    if (raced) return { accepted: raced.accepted, duplicate: true };
    throw err;
  }

  // 3. 以库里存的 accepted 为准（而不是我们以为的 items.length）——万一共识与我们
  //    的预期不同，也要如实报告。
  const stored = await db
    .prepare("SELECT accepted FROM report_batch WHERE batch_id = ?")
    .bind(batchID)
    .first();
  return { accepted: stored ? stored.accepted : items.length, duplicate: false };
}

/**
 * Prune old rows (protocol.md section 6.5): outcomes 7 days, host_stat 30 days.
 *
 * report_batch 的收据保留 7 天——正好和 outcome 同期：客户端重连重发的最长窗口
 * 远小于 7 天（重发只发生在连接重建时），而收据的用途就是挡住那次重发。到期后
 * 客户端若再发同一个 batchID（极端情况：离线 8 天后上线重发），会被当成新批次
 * 处理——这是可接受的，因为 7 天前的回报对现在的决策已无价值。
 */
export async function prune(db, now) {
  const DAY = 86400;
  await db.batch([
    db.prepare("DELETE FROM outcome WHERE ts < ?").bind(now - 7 * DAY),
    db.prepare("DELETE FROM host_stat WHERE last_ts < ?").bind(now - 30 * DAY),
    db.prepare("DELETE FROM report_batch WHERE ts < ?").bind(now - 7 * DAY),
  ]);
}

// --- hint（后缀级经验先验）------------------------------------------------

/**
 * 取某 proto 未过期的 hint，按置信度排序。
 *
 * `now` 显式传入而不是内部取 Date.now()：调用方（cron 与 BUNDLE）用的是同一个
 * 时间基准，而测试要能注入固定的"现在"。
 *
 * 排序：先按支撑主机数（hosts）降序——那才是"这个结论有多普适"的直接度量；
 * 同数再按 Beta(1,1) 后验降序；最后按 suffix/method 字典序保证确定性。
 */
export async function listHints(db, proto, limit, now = Math.floor(Date.now() / 1000)) {
  const { results } = await db
    .prepare(
      `SELECT suffix, method, ok, fail, hosts, expires FROM hint
       WHERE proto = ? AND expires > ?
       ORDER BY hosts DESC, (ok * 1.0 / (ok + fail + 2)) DESC, suffix ASC, method ASC
       LIMIT ?`,
    )
    .bind(proto, now, limit)
    .all();
  return results ?? [];
}

/**
 * 用挖出来的 hint **整批替换**该 proto 下的旧行。
 *
 * 替换而不是累加：挖出来的是"当前最近窗口的全量结论"，与旧行累加会把已经过期的
 * 观测反复计入。先删后插在同一事务里，中间态不可见。
 */
export async function replaceHints(db, proto, rows, now) {
  if (!rows || rows.length === 0) {
    await db.batch([db.prepare("DELETE FROM hint WHERE proto = ?").bind(proto)]);
    return 0;
  }
  const stmt = db.prepare(
    `INSERT INTO hint (suffix, proto, method, ok, fail, hosts, expires, updated)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (suffix, proto, method) DO UPDATE SET
       ok      = excluded.ok,
       fail    = excluded.fail,
       hosts   = excluded.hosts,
       expires = excluded.expires,
       updated = excluded.updated`,
  );
  await db.batch([
    db.prepare("DELETE FROM hint WHERE proto = ?").bind(proto),
    ...rows.map((r) =>
      stmt.bind(r.suffix, proto, r.method, r.ok, r.fail, r.hosts, r.expires, now),
    ),
  ]);
  return rows.length;
}

/** 删除已过期的 hint（cron 用）。 */
export async function pruneHints(db, now) {
  await db.batch([db.prepare("DELETE FROM hint WHERE expires < ?").bind(now)]);
}
