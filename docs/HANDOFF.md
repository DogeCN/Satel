# 交接文档

写给下一个会话。读完这一份应该就能接着干，不用重读全部对话。

**最后更新：2026-10-12（第二轮复核）　｜　A（传输层）与 B（记忆层）均已完成、真机验证。复核轮修掉三个让功能整块失效的 bug，见 §4。**

---

## 0. 一句话状态

Satel = 本地 DPI 绕过客户端（严格单文件、零配置）+ Cloudflare 协调端（D1 演化）。
传输层已是"1 条 WebSocket"；记忆层已从"每主机单个赢家 + blocked 标志"换成
"**有序方法列表 + 分层经验贝叶斯**"，阶梯形状不再硬编码，且**每打完一枪就重排**
（§4.5）——同组新域名与重复访问都能跳过已证伪的方法。

---

## 1. 仓库与部署状态

| 项 | 值 |
|---|---|
| 路径 | `D:\Develop\Satel`（**不是 git 仓库**，没有提交历史） |
| 规模 | 50 个源文件 / 10723 行 |
| Worker | `wss://satel.0xa.cc.cd`（自定义域名，由用户在控制台绑定） |
| D1 | 数据库名 `satel`，id `c1fc4b04-804a-4bcc-b272-aad7015607d5`，region WNAM |
| 密钥 | 仓库根 `.env`：`PASSWORD` / `ADMIN_KEY` / CF 三个凭据。**已被 .gitignore 排除** |
| 部署 | `cd server && set -a && . ../.env && set +a && npx wrangler@4 deploy` |
| 客户端 | `cd client && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o satel.exe ./cmd/satel` |

`wrangler.toml` 里没有 `[[routes]]`：管理 zone 路由需要 zone 级 token 权限，当前 token
没有（`No access to the specified resource`），域名是用户在控制台绑的，不要动这块。

## 2. 文档地图

| 文件 | 内容 |
|---|---|
| `docs/HANDOFF.md` | 本文件 |
| `docs/protocol.md` | 协议规范：策略模型（§2）+ **帧格式/12 个 opcode/认证/重连重放（§3）** |
| `docs/findings.md` | 实测记录，46 节。**结论类内容以它为准**，本文只做索引 |
| `README.md` | 上手、部署、段位自评 |
| `scripts/gen-golden.sh` | 跨语言帧契约的生成与自检 |
| `scripts/deploy.sh` | 一键部署 |

## 3. 传输层重写（A 阶段，已完成）

### 架构

```
浏览器 → satel（本地 SOCKS5 + HTTP CONNECT，同一端口）
          ├─ ① 抄首飞行段  ② DoH 解析  ③ 探测阶梯（包级改写）
          ├─ ④ 全败 → TLS 终止 + ECH 直连 CF 边缘
          └─ 非 CF 承载 → 控制 WS 上的 streamID 隧道（走协调端）
                                  ↓
              一条 wss 长连接：控制面(reqID) + 隧道面(streamID) 共用
                                  ↓
              Worker (wss://satel.0xa.cc.cd) ── D1
```

### 关键决定（都已实现，改动前先读 reasons）

1. **端点只有 `GET /`**，其余路径 404 空 body。**路径不带版本前缀**——原计划写 `/v2`，
   我评估后改成 `/`：旧 HTTP 客户端在 WS-only 服务端必然 404，失败是响亮的；且新签名串
   只有 `ts`，路径根本不参与签名。理由写在 `docs/protocol.md` §6。
2. **帧无 magic/version/length**，靠 WS 消息边界。`id` 4 字节，控制面与隧道面共用，
   但按 opcode 分派到 `pending` / `streams` 两张表，不冲突。
3. **`id`/`host` 是 ASCII 十六进制字符串**（`sid` 8 位、`host_hash` 16 位），不是原始
   字节——这样服务端 `d1.js` 与 `normalizeItem` 完全不用动。原计划的 `sid(4)` 是笔误。
4. **建连鉴权一次**：HELLO 里 `auth = hex(HMAC-SHA256(sha256("satel/v1/"+PASSWORD), String(ts)))[:32]`，
   ±300s 窗口。之后帧不再签名（连接在 TLS/ECH 之内）。
5. **重放只覆盖请求类帧**：ECH 被拒 → 装 `RetryConfigList` 重连；连接断 → 请求重发一次；
   **隧道流不重放**，直接 Close 让浏览器重试。
6. **`/v1/dns` 删除**：目标解析不再绕协调端。见 §5.1。

### 已验证清单（命令 + 实际输出）

```bash
cd client && gofmt -l . && go vet ./... && GOOS=linux go vet ./... && go test ./...
#   gofmt 空；vet 两侧干净；12 个包全绿

cd server && node --check src/*.js && node --test
#   47/47 通过

cd client && for t in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
  os=${t%/*}; arch=${t#*/}
  GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o /tmp/satel-dist/satel-$os-$arch ./cmd/satel
done   # 6/6 成功

bash scripts/gen-golden.sh
#   OK HELLO / BUNDLE_RESP / REPORT / OPEN / EVOLVE_RESP —— 两侧逐字节一致
```

**真机**（`satel.0xa.cc.cd` 已部署当前版本）：

```
$ satel admin evolve --worker wss://satel.0xa.cc.cd …
[ech] 控制通道 SNI 已隐藏
演化完成: map[born:8 generation:5 pool:42 retired:0]

$ satel serve --worker wss://satel.0xa.cc.cd … -v
[mitm] 本地 CA 已装入用户信任区（退出时移除）
[ech] 控制通道 SNI 已隐藏
[sync] tls 策略库 v5: 8 条可用（丢弃 0 条）     ← 跨语言 ID 契约在真实演化数据上成立
[sync] http 策略库 v5: 8 条可用（丢弃 0 条）
[sync] 回报 1/1 条
```

隧道隔离验证（当时用临时程序 `client/cmd/ttest`，已在清理阶段删除）：

| 目标 | 结果 |
|---|---|
| `www.wikipedia.org:80` | ✅ 真实 `HTTP/1.1 301`（HAProxy，`x-cache: cp4041`） |
| `github.com:80` | ✅ 真实 `HTTP/1.1 301` |
| `example.com` / `cloudflare.com` / `medium.com` | ❌ `Stream was cancelled.` |

后三个**全部由 Cloudflare 承载**——Workers 拨不了 Cloudflare 自有网段，平台限制，
客户端应退到本机 ProxyIP（`proxyip` 包已在）。

## 4. 复核轮（2026-10-12 第二轮）：三个真 bug 已修

复核 B 阶段实现时抓到三个 bug，其中两个让功能整块失效。**上一版 §4.1 的结论
（"google 是目标侧问题"）是错的**，那是流式 API bug 造成的假象。详见
`docs/findings.md` §47–51。

### 4.1 google 走隧道：**是通的**（已订正）

| 目标 | 修前 | 修后 |
|---|---|---|
| `www.google.com:443` | `bad record MAC` / 上游关闭 | ✅ **200 OK 501ms** |
| `www.wikipedia.org:443` | `bad record MAC` | ✅ **200 OK 486ms** |
| `www.bing.com:443` | `bad record MAC` | ✅ 200 OK 515ms |
| `www.baidu.com:443` | record 版本不符 | ✅ 200 OK 1812ms |

真机全链路（`satel serve -v` + curl）：

```
baidu 200 [direct]   discord 200 [ech]   bing 302 [direct]
wikipedia 200 [tunnel]   google 200 [tunnel]
```

### 4.2 三个 bug（都已修 + 回归测试）

1. **`SetBundle` 不刷新候选全集** → 下载的策略永不进入 `Plan`，Worker 演化**完全空转**。
   修：`SetBundle` 里同步 `mem.SetKnown(...)`。测试 `TestBundleStrategiesEnterPlan`。
2. **分组键的 `firstDirectSignal` 恒为 `none`** —— proxy 在任何尝试之前就算 group。
   修：`Record` 改收 `isCF bool`，只在失败且类别可用时拼组键。测试
   `TestGroupOnlyOnEvidence`、`TestGroupKeyUsesStableToken`（后者顺带锁住
   "展示串不得当 map 键"）。
3. **三个上游方法各自 `MITM.Terminate`** —— 终止是一次性的，第一个失败就把连接毁了。
   修：终止一次拿到 `clientSession`，三个上游在同一会话里依次试
   （`openSession` + `tryTerminating`）。

### 4.3 最隐蔽的一个：拿流式 API 做消息型协议

隧道里跑 TLS 一直 `bad record MAC`，而同一隧道发明文 HTTP (:80) 正常——差别是往返
次数。根因是客户端用了 `x/net/websocket` 的 **`Conn.Read`/`Conn.Write`（流式 API）**，
部分读时下一次 Read 继续同一帧，被按"一次 Read = 一帧"解析后全错位。

**已改用消息型 API `websocket.Message.Send/Receive`。** 协议"一条消息就是一帧"的
假设必须用消息型 API 兑现——这是本轮最贵的一课。

### 4.4 剩余（非阻断）

- `@ech` 失败时日志只有"其它"：裸 TLS 错误（如 `unrecognized name`）归入
  `failkind.Other`，原因不可见。隧道那条已带原因（CLOSE 帧 payload），ECH 这条还没。
- `probe.Step` 现在 `Kind` 与 `OK` 并用——`Kind` 不再是"成败"，读代码时注意。

### 4.5 第三轮复核：记忆层真正生效的两处（2026-10-12）

前两轮让记忆层**建起来了**，但真机上它**没在起作用**。两处都是"看起来有数据、
排序却不变"的症状，详见 `docs/findings.md` §52/§53。

1. **伪计数没有下限** → 未观测的方法得 `rate=0.0`，比"试过且失败"（有组先验，>0）
   还低，于是阶梯只重放已知失败的方法。修法：`a` 下限 1（未观测 ≈ 先验 ≈ 0.5）。
   回归测试 `TestUntriedBeatsFailed`。
2. **阶梯在循环前一次性物化** → "新 host 先打 direct 拿信号"这一枪本身才产出分组
   特征，等组建好阶梯早已排完，组先验只对访问过的 host 有效。修法：`tunnel()`
   改成每打完一枪 `plan = nil` 重排，并显式规定 `sess != nil` 后跳过包级方法
   （原先靠"终止类排在末尾"这个不变量隐式保证，重排会打破它）。

真机数据（同一进程）：

| 请求 | miss 数 | 耗时 |
|---|---|---|
| zh.wikipedia.org（首个 host） | 15 | 57.0s |
| en.wikipedia.org（同组、从未访问） | 1 | 4.0s |
| zh.wikipedia.org（重复访问） | 0 | 0.69s |

这正是规格要的"同组后续站直接命中正确方法"。附带效果：`@ech` 对非 CF 域名的
白烧探测自然消失（组里它的后验低于 `@tunnel`，重排后轮不到它）。

**注意并发**：这轮有第二个 agent 同时在改 `internal/engine` 与 `internal/proxy`，
其测试脚本用 `taskkill /F /IM satel.exe` 清场，会连你的进程一起杀（症状：阶梯走到
一半进程消失、退出码 1、无 panic 文本）。自己跑真机验证时先改名隔离，例如
改名成另一个文件名再起一份即可隔离两个进程（进程名冲突时排查用）。

### 4.6 黑名单覆盖实验（2026-10-12，另一路）

拿社区黑名单抽样（`Loyalsoldier/clash-rules` 的 `gfw.txt`，4430 条→抽 30）逐个真实
HTTPS 请求，跑两轮看**覆盖**与**记忆是否自己长出来**。原始数据见 `docs/findings.md`
§51–55。三条结论：

1. **记忆确实自己长出来了。** 同一进程两轮，`google.com` 第一轮 25s 超时（被 curl
   打断），第二轮 **859ms 的 301**——日志里第二轮只有一行 `[tunnel] google.com`，
   零 miss、零策略尝试。第一轮它把 direct + 12 条策略 + @ech + @proxyip 全试了一遍。
2. **第一轮 10 条小样本通过 5/10**，且 5 个失败都不是"无路可走"——日志显示它们
   最后都建立了 `[tunnel]`，只是 `@proxyip` 先跑了 9 条公共中继、耗掉 20 秒才轮到。
3. 因此修了两个 bug：**`[skip]` 只打日志不真跳过**（方法列表重构时丢了原来的 `break`
   语义，IP 黑洞站上白烧 4×5 秒）→ `trySimple` 返回 `(ok, tcpDown)`；
   **`@proxyip` 因字母序排在 `@tunnel` 前**（三者原本同成本）→ `methodCost` 改成
   成本递增且互不相同（@ech 2 / @tunnel 3 / @proxyip 4）。

未做完的部分：30 条大样本的两轮因为并发 `taskkill` 中断了几次，只拿到 10 条小样本的
完整两轮。要复跑就在没有并发实验者的窗口做，见 §54 的改名建议。

### 4.7 方法级上报（2026-10-12 第四轮）：REPORT 从"策略 ID"扩到"主机×方法×类别"

用户要求"把逐主机结论也传 D1，而且不管泄漏，直传主机名"。做了三件事：

**1. 回报节流解耦（真机抓到的一个静默 bug）。** `syncLoop` 原来只在 ticker 上
flushReports，而 ticker 第一次触发要等满 `--sync-interval`（默认 15 分钟）——启动时
那次 flush 排在浏览器连接之前，队列还是空的。真机现象是：`reportLocked` 确实入队、
Worker 侧 `outcome` 表却一条没有，且**没有任何错误日志**。修法：回报单独一个短周期
（45s），与策略库拉取解耦。教训：**"没有错误"不等于"在工作"**，要看落库那一侧。

**2. REPORT 条目扩容**（`docs/protocol.md` §3.2 已同步）：

```
entry = host_len(1)+host + method_len(1)+method + flags(1) + rtt(4) + ts(8) + kind_len(1)+kind
```

- `host` 明文（≤253）。`HostHash`/`HostHashOf`/`hostHashLen` **已从 Go 侧删除**，
  连同它的测试——留着会有人把哈希主机名这条老路重新捡起来。
- `method` 是伪方法或 8 位策略 ID；`kind` 是 `failkind.Key()`。
  **`kind` 是关键**：协调端从此能区分"直连被复位"和"直连黑洞"，这才是把 GFW
  黑名单长出来所依赖的信号，以前回报里只有一个 bool。
- 回报点只有两处：策略走 `RecordAttempt`（那里有 rtt/unsup），伪方法（`spec==nil`）
  走 `Record`。两边都记会重复上报。

**3. 跨语言 golden 扩到 JS 侧。** `scripts/gen-golden.sh` 原先只回填 Go 测试的
golden，JS 测试里那份是手抄的——改完线格式后它静默过期，直到 `node --test` 报错才
发现。现在脚本两侧都回填（幂等，回填不到会打警告）。

**当前状态**：客户端能发出 REPORT，线上 Worker 仍回
`STATUS(code=2 D1_TYPE_ERROR: Type 'undefined' not supported for value 'undefined')`
——部署的 `d1.js` 还是按 `sid`/`host_hash` 写的。迁移 + `recordReport` 改写 +
`method_stat`/`hint` 表由另一路在做，做完才谈得上真机验证。

## 5. 硬约束与已验证的结论

这些是实测得出的，改代码前必须知道，否则会重复走我踩过的弯路。原始数据见
`docs/findings.md` 对应节。

### 5.1 DNS：只有 Cloudflare Gateway 端点可靠

污染是**竞速的**——同一端点会在几分钟内从全干净翻成全污染、或反过来。
**连打 N 次测的是错误的方差**；污染是网络状态属性，不是每查询随机。

| 端点 | `www.google.com` 真 IP | type=65(HTTPS RR) |
|---|---|---|
| `xwfpeb16ii.cloudflare-gateway.com` | **8/8 干净**（跨 2.5 分钟） | ✅ 支持 |
| `doh.pub` / `1.12.12.12` | 0~3/10，跨分钟翻转 | ❌ `UrlParameterError` |
| `223.5.5.5` | **0/10** | ✅ 支持 |

对 CF 承载的被墙站：`doh.pub` 只对 2/4（medium、chatgpt 对；discord、notion 错）。
**Gateway 端点是唯一可靠的**，代价是延迟 0.5–2.5s，由客户端 10 分钟缓存吸收。
它的 A 记录与 HTTPS RR **可以共用一条解析链**（都已实测支持）。

当前实现：`resolver.NewDoH("")` → `defaultEndpoints = [Gateway, doh.pub]`，
再兜系统 DNS。`--doh` 可覆盖（逗号分隔表示优先级）。

### 5.2 封锁分类（决定了什么有用什么没用）

| 类别 | 域名 | 本地绕过 |
|---|---|---|
| 无封锁 | baidu、github、x.com、openai、deepl、protonmail | 直连 |
| **无状态 SNI** | `satel.0xa.cc.cd` | ✅ `tlsrf` / `split+oob` |
| 状态化 SNI + CF 承载 | discord、medium、chatgpt、signal、pixiv | ✅ **MITM + ECH** |
| 状态化 SNI + 非 CF | dropbox | ❌ |
| IP 黑洞 | google、youtube、t.me | ❌ 需隧道 |
| CF 自有网段 | 任何 CF 承载的域名走 Worker 隧道 | ❌ 需本机 ProxyIP |

**关键结论：决定胜负的不是包级招法，是有没有 TLS 终止层。** ECH 与域名前置都必须自己
发起 TLS，所以透明改写架构原理上做不到——这在动手前我判断错过。

### 5.3 我实测否掉的两个错误结论（别再走回头路）

- **不需要 `fake`/`disorder` 原始套接字后端**：ciadpi（黄金级、含全套）对 `medium.com`
  重复测量 **0/5**。加了也没用。
- **不是"所有国内 DoH 都污染"**（第一轮结论），也不是"doh.pub 干净"（第二轮结论）。
  见 §5.1。

## 6. B 阶段规格（**已实现**；下面是设计记录）

**目标**：把 `engine` 从"每主机单个赢家 + blocked 标志"换成"有序方法列表 + 计数器 +
两层记忆"，归纳用分层经验贝叶斯。不动 wire、不动 D1（"本机先行"）。

### B1 `internal/failkind`（新包）

```
Kind: None | DialTimeout | DialRefused | Reset | ReadTimeout | TLSAlert | Write | Apply | Other
```

**不复用 `probe.Kind`**——它的值是中文展示串（"被复位 RST"），当机器键会把展示层漏进
路由层。新建后把 `probe.Classify` 改成返回本类型，展示串留到打印时映射。

现状（已探明）：失败类别在 `proxy.go` 的 `RecordAttempt(..., err == nil, ...)` 与
`RecordOutcome(..., ok bool)` 两处被压成 bool；`RecordOutcome` 的 `proto` 参数收了
不用；`memory.wins/fails` **只写不读**；`e.mem` **完全没有容量上限**。

### B2 统一方法 ID

伪方法用 `@` 前缀（不与 8 位 hex 策略 ID 冲突）：`@direct @tunnel @ech @proxyip` + 策略 ID。

现在四种真实方法塌缩进 3 个 verdict，且隧道与 MITM 的成功都记成 `VerdictDirect` +
`sid==""`——`sid==""` 是隐式哨兵，没有具名常量。

### B3 两层记忆 + 分层经验贝叶斯

```go
type hostStat struct {            // tier1 工作集，LRU 上限约 512
    methods map[string]*stat      // methodID -> {ok, fail; inherited bool}
    group   string
    last    time.Time
}
type groupStat struct {           // tier2 归档，只接受 observed 证据
    methods map[string]*stat
    hosts   int
}
```

**Group 键必须是"知道答案之前就能算出来"的特征**，否则循环论证：

```
group = isCF + ":" + firstDirectSignal
```

`isCF` 来自解析结果（`ech.AnyCloudflare`，已在用）；`firstDirectSignal` 是**第一次
direct 尝试的失败类别**——这一枪必然要打、成本一个探测窗口、产出的是观测不是预测。
所以第一个 host 就能归类，不需要访问过兄弟域名。

于是 **GFW 黑名单不需要任何导入**：访问过几个 CF 承载的被墙站后，`group=1:reset` 里
`direct` 的后验自然掉下去，新来的同组 host 直接继承"别先试 direct"。

**排序**：

```
prior_rate(m) = (ok_g(m) + 1) / (ok_g(m) + fail_g(m) + 2)
a             = min(A_MAX, ok_g(m) + fail_g(m))          // A_MAX ≈ 8
rate_h(m)     = (ok_h(m) + a·prior_rate(m)) / (n_h(m) + a)
```

按 `rate_h` 降序；同分按固定成本序（direct < 策略 < ech/tunnel/proxyip）。

**继承结果绝不回灌组证据**：`inherited=true` 只用来决定"先试什么"，永不进
`ok_g/fail_g`。否则错误模式自证循环、永不证伪。配套：继承条目先验弱、TTL 短，
**一次反例即降级**。

**淘汰即折叠**：LRU 挤出 tier1 时不丢弃，把 observed 计数折进 tier2；另加周期折叠兜底。

**Plan 形态**：返回单一有序方法列表，取代 `TryDirectFirst`/`KnownBlocked`/`Strategies`。
阶梯形状不再硬编码；唯一的固定策略是"新 host 先打 direct 拿信号"——那是探测，不是决策。

### B4 `internal/proxy` 接线

- `attempt` 的错误不再丢弃：`failkind.Classify` 分类后一路带到 `RecordOutcome`
- `RecordOutcome` 签名改为带 `Method` 与 `Kind`
- `escalate` 的 `isCF` 分支与 `isBlockedStatus`（硬编码 `" 403"`/`" 451"`）改为
  **按方法列表驱动**；`isCF` 降级为 group 特征
- `proxyip` / `tunnel` / `ech` 各自成为可记忆的方法

### B5 测试

**必然要改**：`engine_test.go` 有 4 个测试硬编码条目数（pool 恰好 4、合并后恰好 5）与
verdict 语义；`proxy_test.go` 的 `TestProxyTLSRoundTrip`/`TestProxyDirectFirst` 断言
`Stats()` 计数。

**新增**：折叠（LRU 挤出 → 组计数增加）、继承不回灌、收缩（组证据弱时不过度拉动）、
一次反例降级、LRU 上限生效。

**顺带补零覆盖**：`escalate` 尾部、`isBlockedStatus`、`attempt` 错误类别、
`KnownBlocked` 交互。

## 7. 踩过的坑（给下一个人省时间）

1. **手抄长 hex 必错。** 我连续抄错 3 次，一度以为协议漂移。修法是
   `scripts/gen-golden.sh`：两端各自跑出载荷 → 断言相同 → 自动回填测试文件。
   **任何跨语言字面量都不要手打。**
2. **`wrangler tail` 用 `npx` 后台化不可靠**（报"Successfully created tail"但收不到日志，
   过期时间还是上一次的）。诊断服务端行为请改用别的手段——见第 3 条。
3. **让服务端把错误带回客户端**：`CLOSE` 帧 payload 带 reason，客户端 `Read` 返回它。
   否则隧道失败在客户端只是没有线索的 EOF。
4. **Git Bash 的 `/tmp` 路径 Go/Node 解析不了**（会被当成盘符相对路径）。要用绝对路径，
   混合风格用 `pwd -W` 转换。
5. **Node 脚本替换源码容易毁文件**（正则含中文、转义层级、`$1` 被 shell 吃掉）。
   多次之后改用 `node -e` 时优先匹配 ASCII 结构、替换前先 `grep` 确认命中数。
6. **测试服务端不能并发 `ws.Read`**——`x/net/websocket` 的 Conn 是 io.Reader，两个读
   循环会互相抢帧。`client_test.go` 里是单读循环 + streams 表。
7. **`x/net/websocket` 的 Conn 没有 `Send`/`Receive`**，是 `Read`/`Write`；且默认发 text
   帧，**必须设 `ws.PayloadType = websocket.BinaryFrame`**，否则对端只收二进制、每个
   字节都被丢掉（症状是"连上了但立刻空回复"）。
8. **换 DoH 端点前先测 type=65。** 不支持的话 ECH 配置静默拿不到，MITM 分支整条失效。
9. **`--doh` 空值要统一走 `resolver.NewDoH("").Primary()`**。直接传空串给
   `ech.Fetch` 会报"DoH 端点为空"——这是本轮真实踩到的一个 bug。
10. **测试目标的选择比改代码更能定位问题。** 隧道失败时我先试了
    `example.com:80` 和一个 IP，误以为"域名解析有问题"；实际是 example.com 与
    cloudflare.com 都挂在 Cloudflare 上（Workers 拨不了），换成 wikipedia/github
    就一路通了。

## 8. 操作手册

```bash
# 全量自检（改完协议必跑）
cd client && gofmt -l . && go vet ./... && GOOS=linux go vet ./... && go test ./...
cd server && node --check src/*.js && node --test
cd .. && bash scripts/gen-golden.sh

# 构建 / 部署
cd client && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o satel.exe ./cmd/satel
cd ../server && set -a && . ../.env && set +a && npx wrangler@4 deploy

# 运维
satel admin evolve --worker wss://satel.0xa.cc.cd --password … --admin-key …

# 诊断
satel probe --handshake --fetch www.example.com      # 某站现在能不能用
satel diag www.example.com                            # 封锁判据对照实验
satel diag --shared-ip --bad-sni www.example.com      # 同 IP 换 SNI（无混淆变量）

# CA 生命周期
#   默认：严格零落盘——启动装一张临时 CA，退出即删，不写任何文件；
#         代价是 Windows 每次启动弹一次根证书确认框
#   开发通道：--ca-file <path> 让 CA 落盘复用，只在第一次装（之后只查不装）
satel remove-ca                                       # 清信任区（+ 删开发通道的落盘私钥）
satel serve --ca-ephemeral                            # 回到"每次装、退出删"（会弹框）
certutil -store -user Root | grep -c "CN=Satel Local CA"   # 残留检查，正常应为 0
```

## 9. 不要做的事

- 不要把 `ProxyIP` 放进 Worker——用户的明确要求，且 `tunnel.js` 的注释里已把这条边界
  写成设计的一部分。
- 不要为 `fake`/`disorder` 去实现原始套接字后端（§5.3 已实测否掉）。
- 不要引入域名黑名单/规则集导入——黑名单应当以"group=CF/reset 的 direct 后验低"的
  形式**长出来**。
- 不要把逐主机结论上 D1（`host_hash` 对已知域名表是可逆的：拿到公开黑名单逐个 sha256
  就能反查明文域名；"本机先行"就是为此）。用户已表示"不管泄漏"但那是针对**阶段**的
  决定，实施前值得再确认一次。