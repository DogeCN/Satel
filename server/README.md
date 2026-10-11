# Satel — coordination server (Cloudflare Worker + D1)

Server side of the Satel DPI-bypass coordination service. The client is a
separate Go program. The authoritative wire spec is `../docs/protocol.md`;
anything in this README is subordinate to that file.

> **传输层是单条 WebSocket，不是 HTTP 端点。** 本文件下半部分残留的
> `GET /v1/bundle` / `POST /v1/report` 章节是 HTTP 时代的旧文档，**已过时**——
> 端点只有 `GET /`，其余路径一律 404 空 body。帧格式见 `src/frame.js` 的注释
> 与 `docs/protocol.md` §3。

The Worker does four things:

1. hands out a strategy pool (`BUNDLE` → `BUNDLE_RESP`),
2. records outcome reports idempotently (`REPORT` → `REPORT_RESP`),
3. mines suffix hints from those reports (durable method statistics),
4. evolves the strategy pool (evolution loop + cron).

## Layout

```
server/
  schema.sql            D1 schema（全新库形态，可反复执行）
  migrations/
    0002_method_stats_hints.sql   已有库升级（方法统计 + 幂等收据 + hint）
  src/frame.js          线格式编解码（与 Go 侧逐字节一致）
  src/validate.js       主机名规范化 / 方法形态 / 失败类别枚举 / canceled 与 unsup 的语义
  src/d1.js             data-access + recordReport 的 exactly-once 事务
  src/hints.js          后缀 hint 的挖掘（公共后缀列表、主机权重、阈值）
  src/migrate.js        幂等迁移 CLI（本地 SQLite）
  src/canonical.js      canonicalizer + strategy id + param defaults/domains
  src/auth.js           HMAC-SHA256 request auth (WebCrypto)
  src/evolution.js      the evolution algorithm (pure, injectable rand)
  src/index.js          fetch + scheduled handlers
  test/*.test.mjs       offline unit tests (node --test)
```

## Canonical form and strategy ids

A strategy is `proto` + an ordered list of ops. Its canonical string is what is
hashed to produce the id; the client recomputes and verifies it, so the two
implementations must match byte-for-byte.

```
canonical = proto "|" op1 "|" op2 "|" ...          # ops in order, NOT sorted
op        = name "(" k1 "=" v1 "," k2 "=" v2 ")"    # params sorted by key, ASCII asc
int       = decimal, no leading zeros, non-negative
bool      = "1" | "0"
str       = as-is, must not contain , ( ) = |
id        = lowercase hex(sha256(canonical))[0:8]
```

Defaults are filled for every missing param **before** hashing, so the canonical
string always carries all params. `src/canonical.js` holds the per-op table
(`OPS`): type, default and value domain. An unknown op name, an unknown param,
or a value whose type does not match the default is rejected (`CanonicalError`).

Golden ids pinned by both sides (see `test/canonical.test.mjs`):

| canonical | id |
|---|---|
| `tls\|split(at=sni,count=2,delay_ms=8,len=1,pos=1)` | `15c0e805` |
| `tls\|tlsrf(chunk=8,delay_ms=8,limit=400)` | `78c3d41b` |
| `tls\|split(at=sni,count=2,delay_ms=8,len=1,pos=1)\|oob(byte=0)` | `b98c567b` |
| `tls\|split(at=sni,count=4,delay_ms=24,len=1,pos=0)` | `0352f73e` |
| `http\|hostsplit(gap=1)` | `393db486` |
| `http\|case(seed=0)\|hostsplit(gap=1)` | `a50096b8` |
| `http\|hostsplit(gap=1)\|case(seed=1234)` | `713ce104` |

`dup`, `fake` and `disorder` are *privileged* ops (raw-socket / driver
backends). They remain valid canonical op names; portable clients simply omit
them from the `caps` list (see below) and mark such attempts `unsup=1`.

## Auth (protocol.md section 3)

```
key            = sha256("satel/v1/" + PASSWORD)              # 32 raw bytes
signing_string = ts "\n" METHOD "\n" PATH "\n" sha256_hex(body)
X-Satel-Auth   = hex(HMAC-SHA256(key, signing_string))[0:32]
X-Satel-Ts     = unix seconds
```

`PATH` excludes the query string; an empty body hashes as `sha256_hex("")`. The
timestamp must be within ±300 s. Comparisons are constant-time. `/v1/bundle`
and `/v1/report` use `PASSWORD`; `/v1/evolve` uses the independent `ADMIN_KEY`
via the `X-Satel-Admin` header.

## Endpoints

### `GET /v1/bundle`

Query: `fp` (client fingerprint), `proto` (`tls`|`http`, default `tls`), `n`
(1..32, default 8), and `caps`.

`caps` is a comma-separated list of op names the client's backend supports, e.g.
`caps=split,tlsrf,oob,hostsplit,case`. When present, only strategies whose
**every** op is in the set are returned; absent/blank means "all ops supported".
The whole pool is scanned before slicing to `n`, so filtering never
under-fills the response.

Response 200:

```json
{ "version": 42, "ttl": 3600,
  "strategies": [ { "id": "8f3a1c02", "spec": "tls|split(...)", "score": 0.71, "trials": 1280 } ] }
```

`strategies` is ordered by `score` descending, non-retired, matching `proto`,
at most `n`. `version` is `max(gen)` over the strategy table (0 when empty). An
empty table returns `strategies: []` (the client has built-in fallbacks).

### `POST /v1/report`

```json
{ "fp": "windows-amd64-1",
  "items": [ { "host": "a1b2c3d4e5f60718", "sid": "8f3a1c02", "ok": 1,
               "rtt_ms": 118, "err": "", "unsup": 0, "ts": 1699999999 } ] }
```

`host` must be 16 lowercase hex chars, `sid` 8 lowercase hex chars, `ok`/`unsup`
`0|1`. Invalid items are skipped (they do not count toward `accepted`). `items`
not being an array is 400; more than 256 items is 413. Response 200:
`{"accepted": N}`.

Each item inserts into `outcome`, upserts `host_stat` (ok/fail counters) and
updates the strategy's aggregate counters. `unsup=1` increments `trials` and
`unsup` only — it never raises `wins` (protocol.md section 6).

### `POST /v1/evolve`

Requires `X-Satel-Admin: <ADMIN_KEY>` (constant-time compare; otherwise 403).
Runs one generation and returns
`{"generation":G,"born":K,"retired":M,"pool":P}`. If the strategy table is
empty it seeds the 6 built-ins instead and reports `born: 6`, `generation: 0`.

Everything else returns 404 with an empty body and no extra headers.

## The evolution loop (protocol.md section 6)

`evolve({ strategies, now, rand, poolMax, topK })` is pure (no I/O) and returns
`{ born, retired, generation }`; `rand` is injectable for deterministic tests.
Per generation:

1. **Score** — `score = (wins + 1) / (trials + 2)` (Beta(1,1) posterior mean).
2. **Select** — UCB1 `score + sqrt(2·ln(N) / max(trials,1))`, take top `topK`.
3. **Mutate** — each child picks 1–2 operators (uniform), one child per parent:
   - `param`: nudge one numeric param inside its domain (clamped);
   - `toggle`: add a random absent op, or remove one if >1 op;
   - `crossover`: splice a contiguous run of ops from another parent;
   - `proto`: flip `tls`↔`http` (low probability, ~0.1).
   Children are re-canonicalized and re-hashed; a child whose id already exists
   is skipped.
4. **Cap** — if active strategies exceed `POOL_MAX` (48), the lowest-score ones
   are retired (`retired=1`; rows are kept for history).
5. **Prune** — the cron handler deletes `outcome` older than 7 days and
   `host_stat` older than 30 days.

The `scheduled` cron handler (`17 */6 * * *`) runs the same generation routine
and discards the result.

## 升级已有数据库（非破坏性）

本轮新增了**方法级统计**与**后缀 hint**。它们需要三张新表，以及 `outcome` 的五个
新列。两条路径，按你的库是新的还是旧的选一条。

> ⚠ **先读这一条**：`schema.sql` 故意**不含** `ALTER TABLE ADD COLUMN`。SQLite 的
> ADD COLUMN 没有 `IF NOT EXISTS`，把它放进这个要反复执行的建表文件里，第二次跑
> 就会以 `duplicate column name` 失败。所以有历史数据的库必须走 `migrations/`。

### 全新库

```bash
npx wrangler d1 execute satel --remote --file=./schema.sql
```

`schema.sql` 里 `outcome` 已直接包含 `host/method/kind/proto/batch_id` 五列。
可以反复执行（全是 `CREATE ... IF NOT EXISTS`），用作自检。

### 已有库

```bash
npx wrangler d1 execute satel --remote --file=./migrations/0002_method_stats_hints.sql
npx wrangler d1 execute satel --remote --file=./schema.sql          # 建剩下的表/索引
```

迁移做了这些事，**不动任何已有列与已有行**：

| 动作 | 说明 |
|---|---|
| `outcome` + 5 列 | `host` / `method` / `kind` / `proto` / `batch_id`，全部 nullable |
| 回填历史行 | `host = host_hash`、`method = sid`（旧格式里存的就是明文，有据不猜）；`proto = 'tls'`；`kind` 留 NULL 表示"未知" |
| 新表 | `method_stat` / `report_batch` / `hint` |
| 新索引 | `idx_outcome_batch` / `idx_method_stat_proto_ts` / `idx_hint_proto_expires` / `idx_report_batch_ts` |

**为什么 outcome 的明文列是 nullable 而不是 NOT NULL**：`ALTER TABLE ADD COLUMN`
没法给已有行提供值，而"历史行的明文字段为空"与"新行的明文字段为空"必须能区分
（前者不参与方法统计，后者参与）。`recordReport` 保证新行必然写全五列。

**回滚**：迁移文件末尾有 `DROP COLUMN` / `DROP TABLE` 的手工步骤。三张新表只在本轮
写入，删除不影响任何既有功能；`outcome` 的明文列删掉后旧列仍在。

### 离线核对（不碰线上库）

```bash
node src/migrate.js --db <path-to-sqlite.db> --dry-run   # 只看将要做什么
node src/migrate.js --db <path-to-sqlite.db>             # 真跑（可重复执行）
```

这个 CLI 靠 `PRAGMA table_info` 判断缺哪些列再逐列 ALTER，所以**同一个迁移可以安全
重复执行**——这是直接 `wrangler d1 execute --file` 做不到的（SQLite 没有
`ADD COLUMN IF NOT EXISTS`）。

## 方法级统计与后缀 hint

### report_batch：exactly-once 的收据

客户端重连时会重发同一批回报（protocol.md §3.4 的"请求类帧自动重发一次"）。
**连接级去重覆盖不到跨连接重发**，所以批次 ID 必须在线上：它是一个 32 位小写 hex
字符串，由客户端生成，作为 `report_batch` 的主键。

`recordReport` 的保证：

1. 先查收据，命中就直接返回**原** accepted，一个字都不写；
2. 否则一个 `db.batch()` 事务（D1 文档：*"Batched statements are SQL transactions"*，
   任一条失败整体回滚）里跑四条写语句，**每条**都带
   `NOT EXISTS (SELECT 1 FROM report_batch WHERE batch_id = ?)` 守卫，
   **收据行最后插**；
3. 返回库里存的 accepted。

重复投递 → 收据已存在 → 四条写入全部命中守卫、一条都不执行。

### method_stat：按 (host, proto, method) 聚合

`proto` 进主键是硬要求：同一条策略可以以 `tls` 或 `http` 两种形态下发
（`evolution.js` 的 `proto` 变异会翻它），混在一行会让 hint 拿 tls 的证据给 http 背书。

两条不训练方法置信的规则：

- **`canceled`**：用户主动放弃（关标签页、切走、ctx 取消）。它与真正的封锁长得
  一模一样（都是 `ok=0`），算作失败等于让**用户行为**训练封锁模型——随机关几个
  页面就能把某后缀的 `@direct` 成功率压到底。仍然进 `outcome` 流水（可审计），不进
  `method_stat`，也不计策略的 trials。
- **`unsup`**：策略根本没跑起来。只进策略的 `trials`/`unsup` 记账，**绝不**进
  `method_stat`。

### hint 挖掘

`rebuildHintsFor` 在**整批回报入账后调用一次**（不是每条一次），按本批涉及的 proto
分别重挖。三条红线：

1. **只读 `method_stat`，绝不读 `hint`**（`MINE_SQL` 里没有 `hint` 字样，测试锁住
   了这点）。把上轮 hint 喂回下一轮会让它自我强化，客户端的一次反例拉不下来。
2. **后缀必须过公共后缀列表**，且必须严格长于 PSL 公共后缀、严格短于主机名。
   启用 `tldts` 的**私有段**，否则 `github.io` / `blogspot.com` / `herokuapp.com`
   这些共享托管平台会被当成普通可注册域——`user.github.io` 能挖出 `github.io` 当
   后缀，而它下面全是互不相干的用户页面。
   - `www.api.example.com` → `api.example.com`（聚合键）
   - `api.example.com` → 不取（没有"更长一层"）
   - `user.github.io` / `x.blogspot.com` → 拒绝（共享托管）
   - `1.2.3.4` / `::1` → 拒绝（IP 没有后缀）
3. **每个 host 权重封顶**：成功率必须落在 >=0.8 或 <=0.2 的极端区才投票（中间地带
   不投票——那是"时好时坏"，多半是抖动），且最多 3 票。一个被访问几百次的 host 不该
   独自决定整个后缀的结论。

阈值：`MIN_HOSTS = 3`、`MIN_OBSERVATIONS = 6`、`TTL = 20 分钟`（与客户端
`inheritedTTL` 对齐）、每 proto 最多 128 条。

### 为什么用 json1 而不是逐项绑定

D1 单条 SQL 有 **100 个绑定参数**上限和 **100 KB** 语句长度上限。逐项绑定时
64 个条目 × 9 个字段 = 576 个参数，必然超限。所以整批序列化成 JSON，用一条
`json_each(?)` 语句展开——只需 2 个参数，64 个条目也只有约 7 KB。

## Configuration

`wrangler.toml` binds:

- `[vars] POOL_MAX = "48"`, `TOP_K = "8"`
- `[[d1_databases]] binding = "DB"` with a **placeholder** `database_id` that
  deployment must replace (see below)
- `[triggers] crons = ["17 */6 * * *"]`

Secrets (`PASSWORD`, `ADMIN_KEY`) are never stored in `wrangler.toml`; set them
with `wrangler secret put` (below).

## Deploying

```bash
cd server

# 1. Create the D1 database. This prints a database_id and rewrites wrangler.toml.
npx wrangler d1 create satel
#    ...or paste the printed id over the placeholder in wrangler.toml.

# 2. Apply the schema. 全新库直接用 schema.sql；已有库先跑迁移（见上一节）。
npx wrangler d1 execute satel --local  --file=./schema.sql
npx wrangler d1 execute satel --remote --file=./schema.sql
#    已有库：先 migrations/0002_method_stats_hints.sql，再 schema.sql

# 3. Set the two secrets (prompted; not committed anywhere).
npx wrangler secret put PASSWORD      # shared with the Go client
npx wrangler secret put ADMIN_KEY     # for /v1/evolve only

# 4. Deploy.
npx wrangler deploy
```

> Deployment requires a Cloudflare account and network access; it is out of
> scope for offline development.

## Testing (offline, no network, no D1)

```bash
cd server
npm test          # == node --test
```

111 tests,全部离线。分五组：

| 文件 | 覆盖 |
|---|---|
| `test/canonical.test.mjs` | golden ids、默认补齐、参数排序、拒绝未知 op/参数/类型不符、往返稳定、`caps` 过滤 |
| `test/evolution.test.mjs` | 空池播种、评分公式、确定性演化、池上限、`unsup` 绝不抬 `wins` |
| `test/ws.test.mjs` | 帧编解码与 Go 侧逐字节一致、HELLO 鉴权、目标白名单、caps、调参 |
| `test/wire.test.mjs` | 线格式边界：往返、**任何截断都抛 Error 而非 TypeError**、未定义 flags 位、非法 proto、空字段、128 条 hint 上限、HELLO 版本探针、尾随垃圾 |
| `test/d1.test.mjs` | exactly-once：重放 3 次仍字节级不变、事务原子性（最后一条失败 → 整体回滚）、unsup/canceled 不进 `method_stat`、伪方法不污染 `strategy`、迁移库同样幂等 |
| `test/schema.test.mjs` | 全新库建表、**迁移前后既有数据逐字段相同**、回填、迁移可重复执行 |
| `test/hints.test.mjs` | 公共后缀规则（含 `github.io`/`blogspot.com` 拒绝）、hostWeight 封顶、四道阈值、proto 隔离、`MINE_SQL` 不引用 hint |
| `test/wsframe.test.mjs` | 分派端到端：REPORT 幂等回显、非法条目回 STATUS 且不落库、BUNDLE 带 hint 下发、回报→挖 hint→下发全链路 |

`test/helpers/d1adapter.mjs` 把 `node:sqlite`（Node 24 内置）包成 D1 的
`prepare/bind/all/first/run/batch` 形状，并在 `batch` 里显式 `BEGIN`/`COMMIT`——
D1 的 batch 是事务，node:sqlite 默认自动提交，不显式包就没有等价语义，
"exactly-once" 也就测不出来。

## Security note

Do not commit real credentials. Keep `.env` (if used) out of version control and
prefer `wrangler secret put`. Rotate any token that has ever been written to a
plaintext file in the repository.
