-- 0002 — durable method statistics + idempotent report batches + mined suffix hints
--
-- **只在已有数据库上执行**（全新库请用 schema.sql，它已含这些形态）：
--
--     npx wrangler d1 execute satel --remote --file=./migrations/0002_method_stats_hints.sql
--
-- 幂等性：SQLite 的 `ALTER TABLE ADD COLUMN` **没有** `IF NOT EXISTS`，所以本文件
-- **不能**重复执行——第二次会以 "duplicate column name" 失败。要重复执行是安全的
-- 情况只有"列已存在"，所以本文件把 ADD COLUMN 收敛在文件末尾、并配一条回滚说明。
--
-- 非破坏性：只 ADD COLUMN 与 CREATE TABLE IF NOT EXISTS，不动任何已有列与已有行。
-- outcome 的历史行在迁移后 host/method/kind/proto 为 NULL，由下面的 UPDATE 回填
-- （旧格式的 host_hash 里存的就是明文主机名，回填是无损的）。

-- 1. outcome 补上明文字段与批次 ID。
--    nullable 是必须的：ADD COLUMN 无法给已有行提供值，而"历史行字段为空"与
--    "新行字段为空"必须可区分。
ALTER TABLE outcome ADD COLUMN host TEXT;
ALTER TABLE outcome ADD COLUMN method TEXT;
ALTER TABLE outcome ADD COLUMN kind TEXT;
ALTER TABLE outcome ADD COLUMN proto TEXT;
ALTER TABLE outcome ADD COLUMN batch_id TEXT;

-- 2. 历史行回填（只填 NULL，不动已有值）。
--    host_hash 在旧客户端里就存明文主机名，所以这个回填是有据的、不是猜的。
--    sid 同理（旧格式就是明文方法 ID）。proto 只能猜——旧格式根本没带协议，
--    而 tls 是二者中更常见的一个，所以默认 tls；kind 无法回填（旧格式没有），
--    留 NULL 表示"未知"，挖 hint 时不读 outcome，所以不影响任何统计。
UPDATE outcome SET host = host_hash WHERE host IS NULL AND host_hash IS NOT NULL;
UPDATE outcome SET method = sid WHERE method IS NULL AND sid IS NOT NULL;
UPDATE outcome SET proto = 'tls' WHERE proto IS NULL;

-- 3. 新表：方法统计 / 幂等收据 / 后缀先验。定义与 schema.sql 中一致。
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

CREATE TABLE IF NOT EXISTS report_batch (
  batch_id TEXT PRIMARY KEY CHECK(length(batch_id) = 32),
  accepted INTEGER NOT NULL,
  fp TEXT,
  ts INTEGER NOT NULL
);

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

-- 4. 新索引。旧库没有它们，补上让新查询路径有索引可用。
CREATE INDEX IF NOT EXISTS idx_outcome_batch ON outcome(batch_id);
CREATE INDEX IF NOT EXISTS idx_method_stat_proto_ts ON method_stat(proto, last_ts);
CREATE INDEX IF NOT EXISTS idx_hint_proto_expires ON hint(proto, expires);
CREATE INDEX IF NOT EXISTS idx_report_batch_ts ON report_batch(ts);

-- 回滚说明（手工，D1 不支持 DROP COLUMN 的批量回滚）：
--   ALTER TABLE outcome DROP COLUMN host;   -- 需要 SQLite 3.35+，D1 支持
--   ALTER TABLE outcome DROP COLUMN method;
--   ALTER TABLE outcome DROP COLUMN kind;
--   ALTER TABLE outcome DROP COLUMN proto;
--   ALTER TABLE outcome DROP COLUMN batch_id;
--   DROP TABLE hint; DROP TABLE report_batch; DROP TABLE method_stat;
-- 三张新表只在本轮写入，删除不破坏任何既有功能；outcome 的明文字段删掉后
-- 旧的 host_hash/sid 两列仍在，写回退到迁移前的可读状态。
