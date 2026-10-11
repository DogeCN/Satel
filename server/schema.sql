-- Satel coordination service — D1 schema (protocol v1).
--
-- Apply with:  wrangler d1 execute satel --remote --file=./schema.sql
--          or:  wrangler d1 execute satel --local  --file=./schema.sql
--
-- 本文件是**全新库**的完整形态，可以在已有库上反复执行（全部语句都是
-- CREATE ... IF NOT EXISTS，天然幂等）。
--
-- ⚠ 它**不含** ALTER TABLE ADD COLUMN：SQLite 的 ADD COLUMN 没有
-- `IF NOT EXISTS`，把它放进这个反复执行的文件里，第二次跑就会以
-- "duplicate column name" 失败。因此：
--
--   全新库        直接执行本文件（outcome 已带 host/method/kind/proto/batch_id）
--   已有库        先执行 migrations/0002_method_stats_hints.sql，再执行本文件
--
-- 完整迁移路径与验证见 server/README.md「升级已有数据库」。

CREATE TABLE IF NOT EXISTS strategy (
  id TEXT PRIMARY KEY,
  spec TEXT NOT NULL,
  proto TEXT NOT NULL,
  score REAL NOT NULL DEFAULT 0,
  trials INTEGER NOT NULL DEFAULT 0,
  wins INTEGER NOT NULL DEFAULT 0,
  unsup INTEGER NOT NULL DEFAULT 0,
  gen INTEGER NOT NULL DEFAULT 0,
  parent TEXT,
  created_at INTEGER NOT NULL,
  retired INTEGER NOT NULL DEFAULT 0
);

-- 逐条回报流水。
--
-- host_hash / sid 是**旧格式的列**，保留 NOT NULL 是为了不动历史行与既有写入路径。
-- 新写入一律把明文主机名放进 host_hash、方法放进 sid（见 src/d1.js 的 recordReport），
-- 同时把明文写进 host / method / kind / proto —— 冗余但兼容：旧的分析查询继续可用，
-- 新的方法统计不再依赖它。
--
-- 这四列 + batch_id 声明为 nullable：ALTER TABLE ADD COLUMN 无法给已有行提供值，
-- 而"历史行的明文字段为空"与"新行的明文字段为空"必须能区分。recordReport 保证
-- 新行必然写全这五列，读侧（挖 hint）因此只查 method_stat，不读 outcome。
CREATE TABLE IF NOT EXISTS outcome (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_hash TEXT NOT NULL,
  sid TEXT NOT NULL,
  ok INTEGER NOT NULL,
  rtt_ms INTEGER,
  fp TEXT,
  unsup INTEGER NOT NULL DEFAULT 0,
  ts INTEGER NOT NULL,
  host TEXT,
  method TEXT,
  kind TEXT,
  proto TEXT,
  batch_id TEXT
);

CREATE TABLE IF NOT EXISTS host_stat (
  host_hash TEXT NOT NULL,
  sid TEXT NOT NULL,
  ok INTEGER NOT NULL DEFAULT 0,
  fail INTEGER NOT NULL DEFAULT 0,
  last_ts INTEGER NOT NULL,
  PRIMARY KEY (host_hash, sid)
);

-- **方法级统计**：本轮的核心新表。PK(host, proto, method)。
--
-- proto 进主键是硬要求：同一条策略可以以 tls 或 http 两种形态下发
-- （evolution.js 的 `proto` 变异会翻它），而客户端对同一主机两种 proto 都可能试过。
-- 混在一行，ok/fail 就分不清是哪个协议下的表现，hint 挖掘会拿 tls 的证据去给
-- http 的建议背书——这比没有 hint 更糟。
--
-- last_kind / last_ts 让挖 hint 时能看"最近一次是什么失败"，而不只有计数。
CREATE TABLE IF NOT EXISTS method_stat (
  host TEXT NOT NULL,
  proto TEXT NOT NULL,
  method TEXT NOT NULL,
  ok INTEGER NOT NULL DEFAULT 0,
  fail INTEGER NOT NULL DEFAULT 0,
  last_kind TEXT,
  last_ts INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (host, proto, method)
);

-- **幂等收据**：一条 batchID 一行。这是 "duplicate batch must return original
-- accepted" 的落点——事务里最后一条语句插它；重放时所有写入都被它挡住，
-- 直接返回它存的 accepted，一个字都不写。
--
-- accepted 存的是**原始批次**被接受时的条目数，所以重放与首次在客户端看来完全一样。
--
-- CHECK(length(batch_id)=32) 是**故意加的最后防线**：长度本该在 frame.js 的
-- decodeReport 和 validate.js 的 normalizeBatchID 两处挡住，但如果漏到库里，
-- "写语句生效但收据没插成"会造成永久双计（见 src/d1.js 里 recordReport 的注释）。
-- 用裸 INSERT（不是 OR IGNORE）配这条 CHECK，漏过来时事务整体回滚、客户端重试。
CREATE TABLE IF NOT EXISTS report_batch (
  batch_id TEXT PRIMARY KEY CHECK(length(batch_id) = 32),
  accepted INTEGER NOT NULL,
  fp TEXT,
  ts INTEGER NOT NULL
);

-- **后缀级经验先验**：hint 的持久形态。PK(suffix, proto, method)。
--
-- suffix 是"最小可聚合后缀"（>=3 标签，且不是公共后缀本身——规则见 src/hints.js）。
-- 它是**弱先验**：TTL 短（20 分钟）、一次反例即降级。客户端只拿它排初始阶梯，
-- 绝不替代本主机自己的观测。
CREATE TABLE IF NOT EXISTS hint (
  suffix TEXT NOT NULL,
  proto TEXT NOT NULL,
  method TEXT NOT NULL,
  ok INTEGER NOT NULL DEFAULT 0,
  fail INTEGER NOT NULL DEFAULT 0,
  hosts INTEGER NOT NULL DEFAULT 0,
  expires INTEGER NOT NULL,
  updated INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (suffix, proto, method)
);

CREATE INDEX IF NOT EXISTS idx_outcome_sid_ts ON outcome(sid, ts);
CREATE INDEX IF NOT EXISTS idx_outcome_host_ts ON outcome(host_hash, ts);
-- ⚠ idx_outcome_batch 引用 batch_id 列。SQLite 的 `IF NOT EXISTS` 只判断**索引名**
-- 是否已存在，不判断列是否已存在——所以在缺列的旧库上，这条 CREATE INDEX 会以
-- "no such column: batch_id" 失败。故把它从本文件移到 migrations/0002 里（那里先
-- ADD COLUMN 再建索引，顺序正确）。全新库则由 CREATE TABLE 建出该列，索引在
-- migrations 里补也一样生效。
CREATE INDEX IF NOT EXISTS idx_strategy_proto_score ON strategy(proto, retired, score DESC);
-- 挖 hint 的主查询路径：按协议取最近的方法统计。
CREATE INDEX IF NOT EXISTS idx_method_stat_proto_ts ON method_stat(proto, last_ts);
-- BUNDLE 取 hint 的主查询路径：按协议取未过期的。
CREATE INDEX IF NOT EXISTS idx_hint_proto_expires ON hint(proto, expires);
-- report_batch 的剪枝：按 ts 删过期收据。
CREATE INDEX IF NOT EXISTS idx_report_batch_ts ON report_batch(ts);