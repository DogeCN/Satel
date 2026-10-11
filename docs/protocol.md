# Satel 协议规范 v1

本文是客户端（Go）与协调端（Cloudflare Worker + D1）之间的**唯一事实来源**。
两侧实现必须逐字节一致；任何不一致都表现为"策略 ID 对不上"或"认证失败"。

## 1. 角色

- **客户端**：严格单文件可执行程序。零配置文件、零磁盘状态——口令来自 flag/环境
  变量，策略库与记忆全部驻留内存，退出即消失。
- **Worker**：无状态边缘函数 + 一个 D1 数据库。职责只有三件：下发策略库、接收
  效果回报、按回报演化策略库。

客户端**不信任** Worker 的排序：策略 ID 由客户端本地从 spec 重算并校验，不匹配
即丢弃该条。

## 2. 策略（Strategy）

一条策略 = 一个 `proto` + 一个有序的 `ops` 列表。`ops` 按顺序作用在连接的
**首个飞行段**（TLS 场景即 ClientHello，HTTP 场景即请求头）上。

### 2.1 参数默认值表

规范化之前，所有缺省参数先按本表补齐。**规范化输出总是携带全部参数**（含默认
值），因此不存在"两种写法指同一条策略"。

| op | 参数 | 类型 | 默认 | 取值域 |
|---|---|---|---|---|
| `split` | `at` | str | `sni` | `sni` `host` `mid` `head` `rand` |
| | `pos` | int | `1` | `0..32`（`sni`/`host` 时相对命中点偏移） |
| | `len` | int | `1` | `1..64`（每片字节数） |
| | `count` | int | `2` | `2..8`（片数上限） |
| | `delay_ms` | int | `8` | `0..200` |
| `tlsrf` | `chunk` | int | `8` | `1..64`（每个 TLS record 的负载字节） |
| | `limit` | int | `400` | `32..2048`（只重写前 N 字节） |
| | `delay_ms` | int | `8` | `0..200` |
| `oob` | `byte` | int | `0` | `0..255`（紧急字节值） |
| `dup` | `count` | int | `1` | `1..4` |
| | `delay_ms` | int | `0` | `0..200` |
| `hostsplit` | `gap` | int | `1` | `1..8`（Host 值中间插入的空格数） |
| `case` | `seed` | int | `0` | `0..65535`（header 名大小写随机种子） |
| `fake` † | `count` | int | `1` | `1..4` |
| | `ttl` | int | `3` | `1..64` |
| | `badsum` | bool | `1` | `0` `1` |
| | `badseq` | bool | `1` | `0` `1` |
| | `len` | int | `64` | `0..1500`（伪造段负载长度，0=复用首段前 N 字节） |
| | `delay_ms` | int | `0` | `0..200` |
| `disorder` † | `gap_ms` | int | `0` | `0..50` |

† `fake` / `disorder` / `dup` 是**特权招法**：它们必须在同一序列号上注入报文，普通
套接字写会推进 TCP 序列号、把字节流写坏，只有原始套接字或驱动后端才成立。纯用户态
后端遇到它们时按"不支持"跳过（不报错、不中断策略），并在回报里带 `unsup=1`。

客户端在 `GET /v1/bundle` 里用 `caps` 声明自己支持哪些招法，Worker 据此约束变异范围，
不必靠 `unsup` 回报慢慢淘汰（见 §4.1）。

### 2.2 规范化（canonical）

```
canonical = proto "|" op1 "|" op2 "|" ...
op        = name "(" k1 "=" v1 "," k2 "=" v2 ... ")"     # 参数名按 ASCII 升序
v(int)    = 十进制，无前导零
v(bool)   = "1" | "0"
v(str)    = 原样，不含 , ( ) = |
```

示例：

```
tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)|oob(byte=0)
http|hostsplit(gap=1)|case(seed=1234)
```

### 2.3 策略 ID

```
id = hex( sha256( canonical ) )[0:8]      # 8 个小写十六进制字符
```

客户端与 Worker 各自独立计算。客户端收到 bundle 后**重算并校验** `id`，不符即丢。

### 2.4 内置策略库（离线可用）

客户端内置以下 6 条，**顺序即降级尝试顺序**，按 2026-10-11 实测效能排（能赢的在前，
省掉注定失败的探测窗口；实测见 `docs/findings.md`）：

| # | canonical | 说明 |
|---|---|---|
| 1 | `tls\|tlsrf(chunk=8,delay_ms=8,limit=400)` | 实测能破无状态 SNI 封锁 |
| 2 | `tls\|split(at=sni,count=2,delay_ms=8,len=1,pos=1)\|oob(byte=0)` | 实测能破，且最快 |
| 3 | `tls\|split(at=sni,count=2,delay_ms=8,len=1,pos=1)` | 基线；实测对无状态封锁无效，保留作对照 |
| 4 | `tls\|split(at=sni,count=4,delay_ms=24,len=1,pos=0)` | 更细更慢的分片 |
| 5 | `http\|hostsplit(gap=1)` | HTTP Host 拆分 |
| 6 | `http\|case(seed=0)\|hostsplit(gap=1)` | HTTP 大小写 + Host 拆分 |


## 3. 传输层：单条 WebSocket

客户端与协调端之间只有**一条** WebSocket（端点 `GET /`）。控制面（BUNDLE/REPORT/
EVOLVE）与隧道面（OPEN/DATA/CLOSE）复用它——40 条浏览器连接也只对应一次 TLS+ECH
握手。没有别的端点：其余路径一律 404 空 body，既没有指纹可抓，也让旧客户端立刻失败
而不是静默语义漂移。

### 3.1 帧格式

```
frame = [ opcode:1 ][ id:4 BE ][ payload ]
```

**没有 magic、没有 version、没有 length。** WebSocket 是消息导向的，一条消息就是一帧，
长度由 WS 层给出。

`id` 的语义按 opcode 决定：控制面是 `reqID`，隧道面是 `streamID`。两者共用同一个 4
字节空间，但因为按 opcode 分派到不同的表（客户端 `pending` vs `streams`），不会冲突。
`HELLO` 固定 `id=0`。

### 3.2 opcode 表

| 值 | 名称 | 方向 | id 语义 | payload |
|---|---|---|---|---|
| 1 | HELLO | C→S | 0 | `ts(8 BE) + auth(32) + fp_len(1)+fp + caps_len(1)+caps + version(1)` |
| 2 | STATUS | S→C | reqID | `code(1) [+msg]` |
| 3 | BUNDLE | C→S | reqID | `proto_len(1)+proto + n(1)` |
| 4 | BUNDLE_RESP | S→C | reqID | `version(4) + count(1) + 重复{ id(8)+spec_len(2)+spec } + hints` |
| 5 | REPORT | C→S | reqID | `batch(32) + count(2) + 重复{ entry }` |
| 6 | REPORT_RESP | S→C | reqID | `accepted(4)` |
| 7 | EVOLVE | C→S | reqID | `key_len(1)+key` |
| 8 | EVOLVE_RESP | S→C | reqID | `generation(4)+born(4)+retired(4)+pool(4)` |
| 9 | OPEN | C→S | streamID | `host_len(2)+host + port(2)` |
| 10 | OPENED | S→C | streamID | `code(1)` |
| 11 | DATA | 双向 | streamID | 原始字节，无封装 |
| 12 | CLOSE | 双向 | streamID | 空 |

REPORT 的 `batch` 是 32 个 ASCII 小写 hex 字符（一次上报的幂等标识），
`entry` 为：

```
entry = host_len(1)+host + method_len(1)+method + flags(1) + rtt(4) + ts(8) + kind_len(1)+kind + proto_len(1)+proto
flags: bit0 = ok，bit1 = unsup
```

- `host` 是**明文主机名**（≤253）。用户明确要求直传；原先的 16 位 `host_hash`
  挡不住反查（拿公开域名表逐个 sha256 即可反查明文），只是让人误以为有隐私。
- `method`（≤32）是伪方法 `@direct`/`@ech`/`@tunnel`/`@proxyip`，或 8 位策略 ID。
- `kind`（≤16）是失败类别，取 `failkind.Key()`：`ok` `dialtimeout` `dialrefused`
  `reset` `readtimeout` `tlsalert` `write` `apply` `canceled` `other`。
  它让协调端能区分"直连被复位"与"直连黑洞"——**这才是把 GFW 黑名单长出来所依赖的信号**。
- `proto`（≤8）只能是 `tls` 或 `http`，空值拒收：给默认值会让"客户端没想清楚"
  与"客户端故意说 tls"不可分辨。
- `ok` 位与 `kind=="ok"` 必须一致，不一致的条目**整条拒收**——那是编码 bug 的
  信号，放它过去等于让坏数据进 Beta 后验。

`batch` 必须是产生这批数据的一方生成的：客户端重连时会重发同一个批次（§3.4），
而 WS 连接级去重只覆盖"同一条连接内"的重发。连接一断，重发的批次就是一条全新
payload，服务端若认不出是重发，`method_stat` 的 ok/fail 与策略的 trials/wins 都会
**双计**，Beta 后验直接偏向这一批。

BUNDLE_RESP 末尾的 `hints` 是协调端从全体客户端回报里挖出来的后缀经验：

```
hints = count(2) + 重复{ suffix_len(1)+suffix + method_len(1)+method + ok(4) + fail(4) + hosts(4) + expires(8) }
```

`count=0` 必须被当作合法（老服务端不下发这个尾巴），不能当截断错误。客户端把它
当**tier3 弱先验**用：只在组里没有证据时顶上组先验的位置，本机观测永远压得住它。

`id` 与策略 `sid` 仍是 **ASCII 十六进制字符串**（`sid` 8 位），不是原始字节。

`STATUS.code`：`0` ok / `1` 鉴权失败 / `2` 参数非法 / `3` 上游失败 / `4` 目标禁连。
`OPENED.code`：`0` 成功，非 0 失败。

上限：`proto`/`fp`/`caps`/`host`/`method`/`kind` 长度前缀 1 字节，`spec` 2 字节，
`REPORT` 至多 256 条（与 D1 侧一致），`BUNDLE` 至多 32 条，`hints` 至多 128 条。

### 3.3 版本探针

`HELLO` 的 payload 最末是 1 字节版本号，当前 `2`（带 method 级回报与 hints 的那一版）。

这是**刻意**的响亮失败，只此一个方向（HELLO 只有 C→S）：

- 老客户端连新服务端 → 新服务端读到版本字节不等于 2，`close(1008)`；
- 新客户端连老服务端 → 老服务端 `decodeHello` 的尾随数据检查失败，同样拒绝。

宁可明确失败，也不要"看起来连上了但语义不同"。

### 3.3 认证：建连一次

```
key  = sha256("satel/v1/" + PASSWORD)                    # 32 字节，口令从不上网
auth = hex( HMAC-SHA256(key, String(ts)) )[0:32]
```

签名串**只有 ts 一个字段**——路径与方法不再参与签名，因为帧走 WebSocket 且只有一个端点。

- 首帧必须是 HELLO；校验 ts 窗口（±300s）与 HMAC，失败 `close(1008)`。
- **之后帧不再签名。** 连接本身在 TLS(ECH) 之内，能拿到明文帧的人本就能终止 TLS。
- `PASSWORD` 为空时一律拒绝——否则未配置的协调端会变成谁都能连的开放中继。

`EVOLVE` 用另一把密钥 `ADMIN_KEY`，放在 payload 里（不再用 `X-Satel-Admin` 头）。

### 3.4 重连与重放

- ECH 被拒 → 服务端在 `ECHRejectionError.RetryConfigList` 里带回新配置，装上重连一次。
- 连接中断 → 下次使用时重建 TLS+WS、重发 HELLO，**请求类帧自动重发一次**。
- 隧道流不可重放：连接一断就向本地 `Close`，由浏览器自行重试（与旧行为一致）。
- 每流缓冲上限 1 MiB：满了就不再从协调端读，让 TCP 窗口自然收缩（背压）。

### 3.5 目标解析不再走协调端

`/v1/dns` 已删除。客户端直接用 DoH：主端点是 Cloudflare Gateway（干净但慢，
0.5–2.5s），备端点 `doh.pub`（快但对封锁域名经常给污染答案），最后系统 DNS。
延迟由客户端缓存吸收（TTL 10 分钟）。理由与实测见 `docs/findings.md` 第五节。

## 4. D1 表结构

见 `server/schema.sql`。三张表：`strategy` / `outcome` / `host_stat`。

## 5. 演化算法（协调端侧）

见 `server/src/evolution.js`。要点：

1. **评分**：`score = (wins + 1) / (trials + 2)`（Beta(1,1) 后验均值）。
2. **选择**：UCB1 `score + sqrt(2·ln(N)/trials)` 取前 `TOP_K` 个作父本。
3. **变异**：`param` / `toggle` / `crossover` / `proto`，每条子代随机取 1–2 个。
4. **caps 约束**：`CAPS`（`wrangler.toml`）声明客户端群能跑的招法，变异只在此集合内
   取值，避免池里塞满没有客户端跑得动的策略。
5. **落库**：子代入库（`gen+1`，记录 `parent`）；非退休数超过 `POOL_MAX` 时按 score
   淘汰最低者（`retired=1`，保留历史行）。

调度：`[triggers] crons = ["17 */6 * * *"]`，每 6 小时一代；也可随时用
`satel admin evolve` 手动触发。

## 6. 版本

本文件描述的是**协议 v1 的帧格式**。传输层在本轮做了破坏性重写（5 个 HTTP 端点 → 1 个
WS 端点），路径前缀未变（仍是 `/`），但旧客户端的请求形式已不被接受——它们会收到 404
而非被静默接受。这是刻意的：宁可明确失败，也不要"看起来连上了但语义不同"。
