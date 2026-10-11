# 实测记录

环境：本机（Windows，`192.168.1.13`）、2026-10-11、账号 `Edge`、zone `0xa.cc.cd`、
Worker `satel.0xa.cc.cd`、D1 `c1fc4b04-804a-4bcc-b272-aad7015607d5`（WNAM）。

本文件只记原始观测，不下结论——结论在 [README](../README.md#限制与实测)。

## 1. 可达性

| 目标 | 结果 |
|---|---|
| `satel.edge-tunnel.workers.dev` | 4 次请求全部 20s 超时（curl exit 28） |
| `satel.0xa.cc.cd`（明文 SNI） | 同样超时 |
| `satel.0xa.cc.cd`（ECH） | 成功 |

`.workers.dev` 被 SNI 阻断；`.cc.cd` 的明文 SNI 也被阻断；只有 ECH 能过。

## 2. DNS

| 解析器 | `www.google.com` 的 A | 结果 |
|---|---|---|
| 223.5.5.5（AliDNS DoH） | `69.171.235.22` | 污染（Facebook 的 IP） |
| 1.1.1.1（DoH） | — | 15s 超时（被墙） |
| dns.google（DoH） | — | 15s 超时（被墙） |
| 本机系统解析 | `2001::1` / `185.45.5.35` | 污染 |
| Worker `/v1/dns` | `142.251.152.119` | **正确**（Google 自有网段） |

同一域名两次不同的污染结果（`69.171.235.22`、`157.240.7.20`，都是 Facebook 网段）。

`satel.0xa.cc.cd` 的 HTTPS RR（223.5.5.5）：

```
1 . alpn="h3,h2" ipv4hint="104.21.75.248,172.67.184.15"
    ech="AEX+DQBBvgAgACBweY36Jk+IMXpd7bfdo77EYDdLEQeJCuEjWOlbqBv3XwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="
    ipv6hint="2606:4700:3033::ac43:b80f,2606:4700:3035::6815:4bf8"
```

ECHConfigList 前 4 字节 `00 45 fe 0d`：总长 0x45，条目版本 0xfe0d。

## 3. 控制通道与数据平面

```
[ech] 控制通道 SNI 已隐藏
satel 0.1.0 监听 127.0.0.1:18080 | 协调端 https://satel.0xa.cc.cd | 招法 split,tlsrf,oob,hostsplit,case
[sync] tls 策略库 v0: 4 条可用（丢弃 0 条）
[sync] http 策略库 v0: 2 条可用（丢弃 0 条）
```

「丢弃 0 条」= 客户端用 Go 侧规范化重算的 ID 与服务端 JS 侧算出的 ID 全部一致。

`satel admin evolve` → `map[born:6 generation:0 pool:6 retired:0]`。

D1 落库：

```
outcomes=8  host_stats=8  strategies=6  active=6

2t/0w/0u score=0.25  tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)
2t/0w/0u score=0.25  tls|tlsrf(chunk=8,delay_ms=8,limit=400)
2t/0w/0u score=0.25  tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)|oob(byte=0)
2t/0w/0u score=0.25  tls|split(at=sni,count=4,delay_ms=24,len=1,pos=0)
0t/0w/0u score=0.5   http|hostsplit(gap=1)
0t/0w/0u score=0.5   http|case(seed=0)|hostsplit(gap=1)
```

score = `(wins+1)/(trials+2)`：2 次尝试 0 胜 → 1/4 = 0.25；未试过 → 1/2 = 0.5。

## 4. 目标可达性（`satel probe`，窗口 5–6s）

| 主机 | 解析到的 IP | 明文直连 | 四条 TLS 策略 |
|---|---|---|---|
| `www.baidu.com` | — | **通（200）** | — |
| `www.google.com` | `142.251.152.119`（DoH 修正后） | `dial` 超时 | 全部 `dial` 超时 |
| `www.google.com` | `69.171.235.22`（污染） | `dial` 超时 | 同上 |
| `www.wikipedia.org` | `198.35.26.224` | `read` 超时 | 全部 `read` 超时 |
| `en.wikipedia.org` | `198.35.26.224` | `read` 超时 | 全部 `read` 超时 |
| `www.reddit.com` | `151.101.193.140` | `read` 超时 | 全部 `read` 超时 |
| `duckduckgo.com` | `52.250.42.157` | RST（`wsarecv: forcibly closed`） | 全部 RST |

`dial` 超时 = TCP 握手就没成（IP 黑洞）。`read` 超时 / RST = TCP 通了、数据被丢或复位。

## 5. 判定分片是否可能奏效的关键一组

对 `duckduckgo.com` 用不同参数单测（窗口 6s）：

| 策略 | 结果 |
|---|---|
| `split(at=sni,count=2,delay_ms=200,len=1,pos=1)` | RST |
| `split(at=sni,count=2,delay_ms=0,len=1,pos=1)` | RST |
| `tlsrf(chunk=1,delay_ms=200,limit=100)` | 第 0 段（**6 字节**）写出后，第 1 段写失败（RST） |

第三行是决定性的：第一段内容为 `16 03 01 00 01 xx`——一个声明长度为 1 的 TLS record
头加 1 字节，**不含 SNI，也不含完整 record**。DPI 仍在此后 200ms 内复位连接。
所以这里的封锁判据不是 SNI 特征，分片类技巧在原理上无法命中。

（`tlsrf(chunk=1)` 的第一段之所以是 6 字节而不是 5：`makeRecord` 会为每片重写 record 头，
chunk=1 即 5 字节头 + 1 字节负载。）

## 6. 复现命令

```bash
# 控制通道 + 播种
./client/satel admin evolve --worker https://satel.0xa.cc.cd \
  --password "$PASSWORD" --admin-key "$ADMIN_KEY"

# 逐条策略探测
./client/satel probe --worker https://satel.0xa.cc.cd --password "$PASSWORD" \
  --timeout 5s www.wikipedia.org

# 单条策略
./client/satel probe --worker https://satel.0xa.cc.cd --password "$PASSWORD" \
  --timeout 6s --strategy 'tls|tlsrf(chunk=1,delay_ms=200,limit=100)' duckduckgo.com

# 经代理跑真实流量
./client/satel serve --worker https://satel.0xa.cc.cd --password "$PASSWORD" \
  --listen 127.0.0.1:18080 --sync-interval 6s -v
curl -s -o /dev/null -w '%{http_code}\n' -x socks5h://127.0.0.1:18080 https://www.baidu.com/

# 查 D1
cd server && npx wrangler d1 execute satel --remote --json \
  --command "SELECT id, spec, trials, wins, unsup, score FROM strategy ORDER BY trials DESC;"
```

---

# 第二轮：封锁分类与第三方对照（2026-10-11 同日）

目的：回答"哪些站能本地绕过"，并判断"我的引擎是不是短板"。

## 7. 判定判据：同 IP 换 SNI（无混淆变量）

Cloudflare 边缘同时承载被墙域名与正常域名，所以**同一个 IP 上只换 SNI** 是唯一没有
混淆变量的对照。

```
$ satel diag --shared-ip --worker https://satel.0xa.cc.cd --password … --timeout 5s
  有回包        共享 IP 104.16.124.96                     对照基准
  成功         正常 SNI www.cloudflare.com               336ms
  失败         被墙 SNI satel.0xa.cc.cd                  (RST)
```

**结论：这是 SNI 特征封锁**——判据只能是 ClientHello 里的明文域名。

（第一轮把结论写成"IP/流级封锁"是被混淆变量骗了：那时测的站要么 IP 被黑洞，
要么"无害 SNI"根本不在那个 IP 上。）

## 8. 用真实 TLS 握手打策略矩阵（同 IP `162.159.152.4`）

第一轮用的是合成 ClientHello，只能问"有没有字节回来"。改成**真实 TLS 握手**后，
同一个 IP 上三个 SNI 分化得非常清楚：

| 该 IP 上的 SNI | 明文 | `tlsrf(chunk=8)` | `split+oob` | `split(at=sni)` | `split(count=4)` |
|---|---|---|---|---|---|
| `www.cloudflare.com` | 通 | 通 | 通 | 通 | 通 |
| `satel.0xa.cc.cd` | 断 | **通 753ms** | **通 349ms** | 断 | 断 |
| `medium.com` | 断 | 断 | 断 | 断 | 断 |

所以**可移植技巧确实能破 SNI 封锁**——但只对 `satel.0xa.cc.cd` 这类**无状态**封锁。
据此把内置策略阶梯按实测重排：能赢的 `tlsrf` / `split+oob` 放最前。

顺带一个副作用验证：把控制通道的 ECH 关掉（`--ech=false`），只靠自举分片，
`satel admin evolve` 依然成功——**工具用自己的招法破了自己的封锁**。

## 9. `medium.com` 是另一种封锁：状态化重组

同一个 IP 上 `medium.com` 全败。加大间隔也没用：

| 策略 | 结果 |
|---|---|
| `tlsrf(chunk=8,delay_ms=8,limit=400)` | 第 **17** 段（约 128 字节负载）才被复位 |
| `tlsrf(chunk=64,delay_ms=1500,limit=128)` | 断 |
| `split(at=sni,count=2,delay_ms=1500,len=1,pos=1)` | 断 |
| `split(at=sni,count=2,delay_ms=400,len=1,pos=1)` | 断 |

"撑到第 17 段"说明它**把分片重组了**；1500ms 的间隔也拦不住，说明它的重组窗口不是
"等一小会儿就放弃"，而是**攒够能判断为止**。这类完整状态化重组，靠"让关键字跨包"
是原理上无解的——必须让 SNI **根本不按序出现**（乱序/伪造注入），或者根本不出现（ECH）。

## 10. 与 ciadpi（ByeDPI v0.17.3）逐招对照

同一台测量仪，经 ciadpi 的 SOCKS5 测它的**基线**（即 ciadpi 自己的效果）。
每招重复多次，报通过率——单次采样会骗人（`--fake` 曾出现一次 1/1，复测 0/5）。

目标 `medium.com`，各 5 次：

| ciadpi 招法 | 通过率 |
|---|---|
| `--split 1+s` | 0/5 |
| `--disorder 3+s` | 0/5 |
| `--oob 1+s` | 0/5 |
| `--disoob 1+s` | 0/5 |
| `--tlsrec 1+s` | 0/5 |
| `--fake 1+s` | 0/5 |
| `--fake 1+s --ttl 4` | 0/5 |
| `--split 1 --disorder 3+s --tlsrec 1+s` | 0/5 |

其它站（`--fake 1+s`）：`www.notion.so` **2/4**、`discord.com` 0/4。

对照之下，ciadpi 对无状态封锁站 `satel.0xa.cc.cd` 是**通**的（1483ms），
说明测量链路本身没问题。

**结论：ciadpi 在这个网络上并不比 Satel 强。** 它多出来的 `disorder` / `fake` /
`fake-sni` / `disoob` 在状态化封锁面前同样无效。**我的短板不在招法集。**

## 11. 逐站分类（真实握手，各站基线）

| 域名 | 解析到的 IP | 明文 | 失败模式 | 本地绕过 |
|---|---|---|---|---|
| www.baidu.com | — | 通 | — | 无需 |
| x.com | — | 通 | — | 无需 |
| github.com | — | 通 | — | 无需 |
| openai.com | — | 通 | — | 无需 |
| protonmail.com | — | 通 | — | 无需 |
| www.deepl.com | — | 通 | — | 无需 |
| **satel.0xa.cc.cd** | CF 边缘 | 断 | RST | ✅ **可**（tlsrf / split+oob） |
| www.notion.so | CF | 断 | RST | ⚠️ 部分（fake，约 50%） |
| medium.com | 162.159.152.4 | 断 | RST | ❌ |
| discord.com | CF | 断 | RST | ❌ |
| chatgpt.com | CF | 断 | RST | ❌ |
| www.dropbox.com | CF | 断 | RST | ❌ |
| signal.org | CF | 断 | RST | ❌ |
| www.pixiv.net | CF | 断 | RST | ❌ |
| r.jina.ai | CF | 断 | RST | ❌ |
| www.nytimes.com | — | 断 | 静默丢弃 | ❌ |
| www.wikipedia.org / en. | 198.35.26.224 | 断 | 静默丢弃 | ❌ |
| www.reddit.com | 151.101.1.140 | 断 | 静默丢弃 | ❌ |
| www.bbc.com | 151.101.128.81 | 断 | 静默丢弃 | ❌ |
| www.twitch.tv | 151.101.194.214 | 断 | 静默丢弃 | ❌ |
| duckduckgo.com | 52.250.42.157 | 断 | RST | ❌ |
| www.google.com | 142.251.x.x | 断 | **dial 超时** | ❌ IP 黑洞 |
| www.youtube.com | — | 断 | dial 超时 | ❌ IP 黑洞 |
| t.me | 149.154.167.99 | 断 | dial 超时 | ❌ IP 黑洞 |

三类封锁：**IP 黑洞**（连 TCP 都握不上手）、**无状态 SNI**（可绕）、
**状态化 SNI**（不可绕）。

## 12. ECH 救不了它们

被墙且状态化封锁的站，HTTPS RR 里**一个都没有发布 ECH 配置**：

```
medium.com / discord.com / www.notion.so / chatgpt.com / www.dropbox.com /
signal.org / www.pixiv.net / www.nytimes.com   →  均无 ech=
```

没有 ECH 配置，客户端就无从加密 SNI。所以对这些站，本地侧没有任何出路。

## 13. 本轮的可执行结论

1. **可移植招法够用**，只是要用对：`tlsrf` 与 `split+oob` 能破无状态 SNI 封锁
   （已据此重排内置阶梯）。特权招法 `fake`/`disorder` 在实测网络里**不解决问题**，
   继续留在"已建模未实现"状态是合理的，优先级应下调。
2. **状态化封锁是本地侧的硬边界**。对这类站，工具该做的是**尽快判定并放弃**，
   把连接交给隧道——而不是白付探测窗口。这对应引擎里 `KnownBlocked` 记忆的价值。
3. 判别方法已固化进 `satel diag`（`--shared-ip` 是无混淆对照），可复用来给任意
   域名分类。

## 14. 环境与工具

- ciadpi（ByeDPI）v0.17.3，`byedpi-17.3-x86_64-w64.zip`，取自
  `hufrea/byedpi` GitHub Releases，落在 `.lab/`（已 gitignore）。
- **当前 shell 非管理员**，因此依赖 WinDivert 驱动的 GoodbyeDPI 与 zapret-win
  无法安装；Geneva 是 Linux 专用。这三者在本次实测中缺席。
- 测量仪：`satel probe --handshake [--ip] [--sni] [--socks5]`，
  对照实验：`satel diag` / `satel diag --shared-ip`。

---

# 第三轮：SniShaper 实测（2026-10-11 同日）

用户在自己的环境里启用了 SniShaper（系统代理指向 `127.0.0.1:8080`）。
测量仪：`satel probe --http-proxy 127.0.0.1:8080 --handshake --fetch`
（`--fetch` 会真发一个带随机 query 的 GET 并读状态行/响应头/正文，
这是唯一能穿透 MITM 假象的判据——握手级测量在 MITM 面前完全失效）。

## 15. 它是怎么工作的：MITM + 远端中继，不是本地绕过

**证据一：直连不通的站，经它却拿到真实响应。**

```
直连：      dial tcp 142.251.157.119:443: i/o timeout     ← google 的 IP 被黑洞
经 SniShaper：HTTP/1.1 200 OK  Server: gws  Date: 实时推进  body 400B+  294ms
```

`Server: gws` 是 Google 真实的 web 服务器标识。TCP 都握不上手的 IP，
不可能凭空拿到实时响应——**除非它没走本机出口**。

**证据二：它的出站连接是一整个中继池。** 5 次请求期间抓到 **72 个不同的远端
endpoint**：

| 归属 | 例子 |
|---|---|
| Cloudflare | `104.20.23.243:443`、`162.159.36.5:443`、`172.67.206.138:443` |
| Google Cloud | `34.107.243.93:443`、`34.54.185.247:443` |
| Fastly | `151.101.1.91:443` |
| 中国 ISP（非标端口） | `120.232.219.129:443`、`171.43.247.44:8082`、`36.150.102.180:7826` |

**证据三：延迟形态。** 所有被墙站统一 ~640ms（一跳中继的特征）；
可达站 `www.baidu.com` 不走 MITM、用真证书（`GlobalSign`）、~100ms。

**证据四：有缓存。** `www.reddit.com` **2ms** 返回 `HTTP/1.1 200 OK`、
`Server: snooserv`、`Via: 1.1 varnish`、`Content-Length: 8397`——
物理上没有网络往返能做到 2ms，这是本地缓存的历史响应。

## 16. 逐站结果

| 域名 | 结果 | 证书 | 判读 |
|---|---|---|---|
| www.baidu.com | 200 OK 100ms | `baidu.com ← GlobalSign`（真） | 直连，未 MITM |
| satel.0xa.cc.cd | 200 OK 334ms | `0xa.cc.cd ← WE1`（真） | 未 MITM，通了 |
| medium.com | **403** 642ms | `medium.com ← SniShaper CA` | MITM + 中继，Cloudflare 真实 CF-RAY |
| discord.com | 200 OK 636ms | `SniShaper CA` | MITM + 中继 |
| www.google.com | 200 OK 294ms | `SniShaper CA` | MITM + 中继 |
| www.wikipedia.org | 301 780ms | `SniShaper CA` | MITM + 中继 |
| www.reddit.com | 200 OK **2ms** | `SniShaper CA` | MITM + **本地缓存** |
| chatgpt.com | 502 Bad Gateway | — | 上游失败 |

## 17. 安全观察（实测，非推测）

1. **它自己终止你的 TLS。** `CN=SniShaper CA, O=SniShaper` 装在**用户根证书区**
   （有效期 2026-09-25 → 2036-09-22，十年）。装了它，凡信任系统根证书的软件
   （浏览器、curl、部分桌面应用）对**所有**域名的 HTTPS 都可被它读改。
2. **CA 私钥明文落盘**：`%APPDATA%\snishaper\cert\ca.key`（1675 字节，无口令、
   无加密），与 `ca.crt` 同目录。任何能读这个文件的进程/用户/备份，都能用这个
   CA 伪造任意域名的证书——而该 CA 就在根证书区里。
3. **流量出本机到第三方中继池**：google / medium / discord / wikipedia 的请求
   （含 Cookie）经它的中继转发。中继的运营者、位置、日志策略从外部不可知。
4. 会破坏证书固定：对固定证书的 App，MITM 会直接导致连接失败。

## 18. 结论：它赢在换赛道，不是招法更强

| | 本地绕过（Satel / zapret / ciadpi） | SniShaper |
|---|---|---|
| 无状态 SNI 站 | ✅ `tlsrf` / `split+oob` | ✅（走中继） |
| 状态化 SNI（medium/discord） | ❌ 实测全败 | ✅（走中继） |
| IP 黑洞（google/reddit） | ❌ 实测 `dial` 超时 | ✅（走中继） |
| 流量是否出本机 | **否** | **是**（第三方中继池） |
| 能否看到你的明文 | **否** | **能**（本地 CA MITM） |
| 需要装根证书 | **否** | **是** |

这正好印证了第二轮的结论：**状态化封锁与 IP 黑洞只有隧道能过**。SniShaper 是那个
结论的一个现成实现——它没有比 zapret/ciadpi 更强的本地招法，而是**放弃了本地绕过**，
改用 MITM + 远端中继。

所以按段位表，它不该和 zapret / GoodbyeDPI 同栏，它属于**代理平台**那一栏
（与 NetMaster、Xray 同类），只是把中继藏在了 MITM 后面。

---

# 第四轮：更正——SniShaper 不走中继（2026-10-11）

**第三轮我判断错了，这里更正。** 用户指出"它没走中继"，我读了它的代码、配置、日志，
并用一行命令复现了它的机制。**用户是对的。**

## 19. 关键更正：出口就是本机

用 Cloudflare 的 trace 端点测**被墙且 CF 承载**的站（第三轮我用的是 cloudflare.com，
它不在 GFWList，走直连，所以测不出）：

```
直连  https://medium.com/cdn-cgi/trace              → 空（被墙）
经 SniShaper 同一端点                                → ip=120.229.120.133 colo=LHR loc=CN
```

`120.229.120.133` 就是**本机自己的出口 IP**。Cloudflare 边缘看到的就是本机，
**没有第三方中继**。第三轮"72 个远端 endpoint"是它的**优选池健康检查**加上
正常浏览流量（日志里能看到 bilibili / msn / qq / mozilla push 等 `mode=direct` 记录）。

## 20. 它的真实机制（来自它自己的日志与 `rules/config.json`）

自动路由 `auto_routing.mode=default`，对 GFWList 域名分两支：

**A. 被墙 + Cloudflare 承载** → `mode=mitm` + **ECH** + `use_cf_pool`

```
[Connect] target=discord.com:443 mode=mitm->mitm upstream=DIRECT
[Connect] Using candidates [162.159.128.233:443 162.159.135.232:443 …]
```

拨 Cloudflare 边缘 IP（`settings.json` 里 `cloudflare_config.preferred_ips` 20 个，
全是真 CF 网段：104.17.x / 104.16.x / 172.66.x / 172.67.x / 104.18.x），
靠 **Cloudflare anycast + ECH 隐藏 SNI** 直连。**不是中继。**

**B. 被墙 + 非 Cloudflare** → **域名前置表**（`rules/config.json` 的 `site_groups`）

| 域名 | upstream（可达 IP） | sni_fake |
|---|---|---|
| www.google.com | `47.102.115.14` | `g.cn` |
| cdn1.cdn-telegram.org | `151.101.65.229:443` | `g.cn` |
| api.github.com | `140.82.112.26` | `api-github-com.mapped` |
| api.bbc.com | `13.35.186.119:443` | （tls-rf 模式） |

日志原文：

```
[Connect] target=www.google.com:443 mode=mitm->mitm upstream=47.102.115.14 sni_fake=g.cn
[MITM] Handling www.google.com with SNI: g.cn
```

**一行命令复现：**

```bash
printf 'GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n' \
  | openssl s_client -quiet -connect 47.102.115.14:443 -servername g.cn
# → HTTP/1.1 200 OK   Server: gws
# 证书: subject=CN=*.google.cn  issuer=C=US, O=Google Trust Services, CN=WR2
```

`47.102.115.14` 是**真正的 Google 服务器**（证书由 Google Trust Services 签发）。
用允许的 SNI `g.cn` 骗过 DPI，HTTP Host 仍是 `www.google.com`——
**域名前置（domain fronting），全程从本机出去。**

## 21. 为什么它必须 MITM

**ECH 与 SNI 伪造都需要自己发起 TLS 握手**——要改 SNI、要注入 ECH 配置，
就必须终止浏览器的 TLS 再重新起一条。所以本地 CA 不是"顺手做的 MITM"，
而是这两个技巧的**必要前提**。

这也解释了为什么它是唯一能在本网络打通 medium / discord / google 的工具：
它用的两类技巧（ECH、域名前置）**都不是包级改写**。

## 22. zapret-win 实测（Flowseal/zapret-discord-youtube 1.10.3，UAC 提权）

UAC 提权后 `winws.exe` 运行、`windivert` 内核驱动 `RUNNING`，确认生效。

| 目标 | 是否在它的 hostlist | 结果 |
|---|---|---|
| discord.com | ✅ 在 | **断（2/2）** |
| www.youtube.com | ✅ 在 | 断（`dial` 超时，IP 黑洞） |
| www.google.com | ✗ 不在 | 断（`dial` 超时，IP 黑洞） |
| medium.com | ✗ 不在 | 断 |
| www.wikipedia.org | ✗ 不在 | 断 |

**对照实验**：把无状态封锁站 `satel.0xa.cc.cd` 加进它的用户列表
（`load_user_lists` 只建文件不改内容，`general.bat` 直接引用该文件，确认已加载），
在**同一台机器、同一时刻**：

| 处理 | 结果 |
|---|---|
| 明文直连 | 断（RST） |
| zapret 的 `multisplit --split-seqovl=568 --split-pos=1` | 断（3/3） |
| **我的 `tls|tlsrf(chunk=8)`** | **通** |
| **我的 `tls|split(at=sni)|oob`** | **通** |

即：**zapret 的 multisplit+序列号重叠在这个站上打不穿，而我的 tlsrf/oob 能**。
（两者同时生效时叠加，所以严格归因有限；但"无 zapret 时 tlsrf 单独也能通"已在第二轮验证。）

## 23. 更正后的结论：真正的短板是架构，不是招法

| | 我的 Satel | zapret / ciadpi | SniShaper |
|---|---|---|---|
| 架构 | 透明包改写（本地代理） | 透明包改写（驱动/代理） | **TLS 终止（MITM）** |
| 无状态 SNI 站 | ✅ tlsrf / oob | ⚠️ 本次未打通 | ✅ |
| 状态化 SNI（discord/medium） | ❌ | ❌ | ✅ **ECH** |
| IP 黑洞（google/youtube） | ❌ | ❌ | ✅ **域名前置** |
| 需要 MITM | 否 | 否 | **是（ECH/前置的前提）** |
| 装根证书 | 否 | 否 | 是 |

**结论**：本网络里唯一有效的两类技巧——**ECH 隐藏 SNI** 与 **域名前置**——
都必须终止 TLS，因此**透明包改写架构原理上做不到**。这不是"缺一个原始套接字后端"，
是架构选择带来的能力边界。SniShaper 用 MITM 换来了这两类能力。

要补这个短板，方向不是 `fake`/`disorder`，而是给 Satel 加一个**可选 TLS 终止层**
（本地 CA + 按域名决定是否 MITM），在 MITM 分支里实现 ECH 与前置表。
代价与 SniShaper 相同：明文可见 + 需装根证书 + 破坏证书固定。

---

# 第五轮：把结论做进代码——TLS 终止层（2026-10-11）

第四轮的结论是"真正的短板是架构"。这一轮把它落地了：`internal/mitm`。

## 24. 先验证核心假设（spike）

在动架构之前先确认 ECH 能**通用**打穿，不依赖目标自己发布配置：

```
目标            自身发布 ECH    用 crypto.cloudflare.com 的共享配置 + CF 边缘 IP
medium.com      ✗               ✅ 握手成功 ECHAccepted=true → 403
discord.com     ✗               ✅ ECHAccepted=true → 200
chatgpt.com     ✗               ✅ ECHAccepted=true → 403
www.notion.so   ✗               ✅ ECHAccepted=true → 307
www.dropbox.com ✗               ✗ tls: unrecognized name（不在这个 CF 边缘上）
```

对照组（同一 IP、明文 SNI）全部 RST。所以**不需要按域名的表**：取一次
`crypto.cloudflare.com` 的 ECH 配置，拨一个可达 CF 边缘，内层 SNI 填真域名即可。
Go 1.26 的 `crypto/tls` 原生支持（`EncryptedClientHelloConfigList`），不用 uTLS。

## 25. 实现

- `internal/mitm/ca.go`：内存里生成 ECDSA P-256 根证书，按 SNI 即时签发叶证书（缓存）。
- `internal/mitm/store_windows.go`：`certutil -addstore -user Root` 装、`-delstore <序列号>` 删；
  `Install` 先按名字清同名残留（上次被强杀时 defer 没跑到）。
- `internal/mitm/session.go`：`Terminate` 用 `replayConn` 把透明路径已经抄走的
  ClientHello 喂回 TLS 栈；`DialECH` 经 CF 边缘用 ECH 连真实目标，处理
  `ECHRejectionError.RetryConfigList` 重试。
- `internal/ech/cfnet.go`：Cloudflare 网段判定（决定哪些域名走 MITM 分支）。
- `internal/proxy`：透明阶梯**全败之后**且目标是 CF 承载 → 升级 MITM + ECH。
- `internal/ech`：`Cloudflare()` 取共享配置 + 边缘 IP，1 小时缓存。

## 26. 实测（真机）

```
[mitm] 本地 CA 已装入用户信任区（退出时移除）
[mitm] discord.com <- ECH via 162.159.135.79
[mitm] medium.com  <- ECH via 162.159.135.79
[mitm] signal.org  <- ECH via 162.159.135.79

curl -k -x http://127.0.0.1:18090 https://discord.com/  → 200
curl -k -x http://127.0.0.1:18090 https://signal.org/   → 200
curl -k -x http://127.0.0.1:18090 https://medium.com/   → 403（Cloudflare 真实 bot 拦截）
curl -k -x http://127.0.0.1:18090 https://chatgpt.com/  → 403（同上）
```

这几个站在透明阶梯下是**全败**的。403 不是失败：那是 Cloudflare 对非浏览器 UA 的
拦截，浏览器能过。

**顺带修掉一个真 bug**：透明阶梯原来把"收到 TLS 告警（记录类型 0x15）"当成成功，
于是把一个死连接交给客户端，用户看到莫名的安全错误。现在告警按失败处理，
会继续往下试并升级到 MITM。见 `isTLSAlert`。

## 27. CA 生命周期

```
装之前: 0    装之后: 1    再装一次(模拟残留): 1    移除后: 0
```

可选集成测试：`SATEL_CATEST=1 go test ./internal/mitm/ -run TestCAStoreLifecycle -v`
（默认跳过——它会真的改系统信任区）。

## 28. 仍然无解的

| 类别 | 现在 |
|---|---|
| 无状态 SNI | ✅ 包级改写（tlsrf / split+oob） |
| 状态化 SNI + CF 承载（discord/medium/chatgpt/signal） | ✅ **MITM + ECH** |
| 状态化 SNI + 非 CF（dropbox） | ❌ 共享 ECH 配置对它无效 |
| IP 黑洞 + 非 CF（google/youtube/telegram） | ❌ 需要域名前置表，本实现没有 |

最后一行是 SniShaper 靠人工维护 `site_groups`（`upstream` + `sni_fake`）覆盖的部分。
要覆盖它就得建一张表——那是数据工作，不是技术工作。

---

# 第五轮：CA 安装弹窗（2026-10-11）

MITM 层要在启动时装一张本地 CA、退出时删掉。装进**用户**根证书区不需要管理员
（实测 `certutil -user -addstore Root` 以普通用户身份成功、无 UAC），但
**crypt32 会弹一次"安全警告"对话框**（"你即将安装来自以下认证机构的证书…"）。
这一轮把所有绕开它的路子都试了。

## 24. 试过什么

| 做法 | 结果 |
|---|---|
| `CERT_STORE_PROV_SYSTEM` + `CertAddEncodedCertificateToStore` 写 Root | ❌ 弹警告 |
| `CERT_STORE_PROV_SYSTEM_REGISTRY` 写 Root | ❌ **同样弹**——警告是 crypt32 对"目标是 Root"本身的检查，与 provider 无关 |
| 直写注册表 + `CertSerializeCertificateStoreElement` 的产物 | ❌ 与注册表里的字节**长度相同但内容不同**，certutil 认不出 |
| 直写注册表 + crypt32 为 CA 存储写出的最小格式 | ❌ 放进 Root 后 certutil 仍认不出 |
| 装进 **CA** 存储 | ❌ 不是信任锚点：`x509: certificate signed by unknown authority` |

## 25. 注册表 Blob 的真实格式

SniShaper 的 CA 是唯一能对照的样本——实测它**只**存在于
`HKCU\Software\Microsoft\SystemCertificates\Root\Certificates\<指纹>`，子键名就是
**SHA-1 正序**十六进制（与 PowerShell 的 Thumbprint 一致，与 `CERT_HASH_PROP_ID`
的字节序一致）。

它的 `Blob`（999 字节）布局：

```
[0]  DWORD cbCertInfo          = 92
[4]  DWORD dwCertEncodingType  = 1
[8..207]  属性记录 + 一段由 crypt32 计算的哈希属性
            @28  16 字节（MD5）
            @56  32 字节
            @100 20 字节（SHA-1，= 指纹）
            @132 20 字节（key identifier）
            @164 32 字节
[196] DWORD 32 / [200] DWORD 1
[204] DWORD cbCertEncoded      = 791
[208] DER（791 字节）
```

而 crypt32 为 **CA** 存储写出的最小格式只有 454 字节、结构完全不同：

```
[0] DWORD 3 / [4] DWORD 1 / [8] DWORD 20 / [12] 20 字节 SHA-1
[32] DWORD 32 / [36] DWORD 1 / [40] DWORD cbCertEncoded / DER
```

两者**不通用**：把最小格式写进 Root，certutil 看不到。Root 要求那段带哈希属性的
前缀，而记录封装（`[A][1][cbData][data]` 里 `A` 的含义）没能定死，所以拼不出来。
**结论：直写注册表这条路放弃。**

## 26. 最终选择

用 crypt32 API 直装（不写临时文件、不起子进程），接受每次启动弹一次警告。
"关闭即删"这条要求与"零弹窗"在当前实现下无法同时满足。

---

# 第六轮：分流——非 CF 走协调端，CF 锁国区走本机中继（2026-10-11）

用户的判断是对的：**"后两行以及主动锁国区的站点走 Worker 配合应该能完美解决；
CF 承载又主动锁国区就直接在本机走 ProxyIP（参考 NetMaster），但不要把 ProxyIP
放进 Worker"**。这一轮实现并验证了它。

## 29. 最终分流

| 目标性质 | 路径 | 实测 |
|---|---|---|
| 无封锁 | 明文直连 | baidu ✅ |
| 无状态 SNI | 包级改写（tlsrf / split+oob） | — |
| 状态化 SNI + CF 承载 | **MITM + ECH 直连 CF 边缘** | discord 200 / signal 200 |
| 状态化 SNI + CF + **锁国区** | **本机 ProxyIP 中继**（退路） | 中继此刻对 medium/chatgpt 不可用 |
| 非 CF 被墙（google/youtube/telegram/dropbox） | **协调端隧道** | google 200 / youtube 200 / t.me 302 / dropbox 200 |

**为什么不把 ProxyIP 放进 Worker**：Workers 的 `connect()` 拨不了 CF 自己的网段，
而锁国区的站恰恰都在 CF 上——放进 Worker 绕不开这条平台限制，还多烧一跳子请求
配额。放本机就没这个问题，而且本机到中继这一段是自己的连接。

## 30. 实现

- `server/src/tunnel.js`：`/v1/tunnel`，WebSocket 之上的原始字节通道，
  `cloudflare:sockets` 直连。**只做直连**（CF 网段连不上就报错，交给客户端走本机
  中继），私网/保留网段一律拒绝，禁 25 端口。
- `client/internal/coord/tunnel.go`：复用控制通道的链路（ECH + 优选边缘 IP +
  自举分片）开隧道。
- `client/internal/proxyip`：本机中继池。

## 31. 三个真 bug（都是实测抓出来的）

1. **WS 帧类型**：x/net 默认发 text 帧，Worker 侧丢弃 text —— 隧道"连上了但立刻
   空回复"。必须设 `ws.PayloadType = websocket.BinaryFrame`。
2. **隧道/中继内没做 TLS**：通道另一端只转发字节，TLS 得我们说。把明文 HTTP 塞给
   目标 443，`t.me` 回了 400 —— 正是这个症状暴露的。
3. **中继是 SNI 路由型，不是 CONNECT 代理**：最初我发 `CONNECT`，9 条全部
   `handshake failure`。NetMaster 的注释里写得很明白："公共 CMLiussss 中继不是
   HTTP CONNECT 代理，实测对 CONNECT 回 400。它读 ClientHello 里的 SNI 并据此
   转发"。正确做法：把**目标域名**当作 SNI 直接跟中继握手。

## 32. ProxyIP 改成内存可用性池（用户提议）

公共中继时好时坏，静态顺序每次从头试很浪费。改成 `Pool`：

- **顺序尝试**，成功的置顶、失败的置底；
- 连续失败 `maxFails=3` 次进入 **2 分钟冷却**，冷却中的排到最后（但不会直接跳过，
  全在冷却时仍有机会尝试，好过直接失败）；
- 冷却过期后**位置不自动回前**——"失败置底"是独立一维，要上升只能靠成功；
- 全部在内存，不落盘（零配置）；并发安全；
- `SATEL_PROXYIP` 可指定自建中继（公共的不可靠）。

## 33. 实测

```
[tunnel] www.google.com   <- 协调端      → 200
[tunnel] www.youtube.com  <- 协调端      → 200
[tunnel] t.me             <- 协调端      → 302
[mitm]   discord.com      <- ECH via 162.159.135.79   → 200
[mitm]   signal.org       <- ECH via 162.159.135.79   → 200
[tunnel] www.dropbox.com  <- 协调端      → 200
[direct] www.baidu.com                   → 200
[fail]   medium.com / chatgpt.com
```

**medium/chatgpt 仍未解决，原因不是代码**：openssl 直连验证，9 条中继里只有 1 条
（DigitalOcean）能给出 Cloudflare 真证书；KR 那条对所有 CF 站都 `write:errno=10054`。
而直连 CF 边缘是通的。所以是**公共中继此刻被拉黑**，不是机制问题——
NetMaster 也记录过"公共中继的出口 IP 被 Cloudflare 系站点拉黑是常态"。
换自建中继（`SATEL_PROXYIP`）即可。

## 34. 开发通道（证书确认框）

Windows 装根证书会弹确认框，每次启动都要人点一下——这就是前几轮 `serve` 卡住
不监听的原因。加了 `SATEL_CA_FILE`：CA 落盘复用，装一次就够（用 `contains` 判断
是否已装，查询不弹框、只有安装才弹）。不设它就是生产行为（装完即用、退出即删）。

---

# 第七轮：社区公益 ProxyIP 实测（2026-10-12）

## 35. 测了什么

两份社区列表：`Zakkaland/CF-ProxyIP`（372 条裸 IP）、
`CB-X2-Jun/cf-proxyip-lists`（277 条，带国家与端口）。用 `relayprobe` 按 SNI 路由
的方式批量探测（SNI 填目标域名 + 真发 HTTP 请求）。

## 36. 结果：对客户域名 0 可用，对 CF 自有域名 163/277 可用

| 目标域名 | 可用 / 总数 |
|---|---|
| discord.com | 0–1 / 277（且不可复现） |
| medium.com | 0 / 277 |
| chatgpt.com | 0 / 277 |
| **www.cloudflare.com** | **163 / 277** |
| **crypto.cloudflare.com** | **164 / 277** |

失败原因分布（discord.com，并发 8）：`tls: handshake failure` 175、`dial` 101。

## 37. 为什么：它们按 SNI 白名单转发，只看 SNI 不看 Host

openssl 验证（中继 `94.20.154.66`）：

```
SNI=www.cloudflare.com  Host=medium.com          → www.cloudflare.com 的真证书 + 200
SNI=medium.com                                    → handshake failure
```

即：**中继连的是 SNI 指定的那个域名，Host 头被完全忽略**。所以"SNI 写 CF 域名、
Host 写目标"这种思路不成立——你拿到的只是 Cloudflare 官网的页面。

这不是缺陷，是设计用途：这些公益 ProxyIP 是给 **CF Workers / Pages 反代**用的，
转发目标本来就是 Cloudflare 自有域名。它们从来不是给客户域名（discord / medium）
做出口的。CMLiussss 那一型（NetMaster 在用的）才是为转发任意 CF 客户域名准备的
——这一型实测此刻基本被拉黑。

## 38. 附带发现：批量探测的"可用"不可复现

批量跑（并发 8）每次都能"抓到 1 条可用"，但**立刻单独复测同一条，0/2 通**，
且每轮换的是不同的 IP。所以那些"1/277"是随机偶发，不是稳定可用——
任何基于单次探测的中继优选都会被它骗到。这印证了 NetMaster 记录过的
"薛定谔中继"现象。

## 39. 结论

1. **社区公益 ProxyIP 救不了 CF 客户域名**（discord / medium / chatgpt），
   原因是机制性的（SNI 白名单），不是列表过期。
2. 它们数量大、对 CF 自有域名可用率高（59%）——**适合做控制通道的备用出口**，
   不适合做目标中继。
3. 要覆盖"CF 承载 + 锁国区"这一类，现实的解法是**自建中继**（`SATEL_PROXYIP`），
   而不是指望公共列表。

---

# 第九轮：DNS 结论的更正与解析端点选型（2026-10-12）

传输层重写顺带要回答一个问题：**删掉 `/v1/dns`（让协调端代解析）安全吗？**
结论是安全的，而且必须删——但过程中推翻了自己两次写进文档的结论。

## 40. 更正：不是"所有国内 DoH 都污染"，也不是"doh.pub 干净"

第一轮我写过"所有可达的本地解析器对 `www.google.com` 都返回污染结果"，当时标注为
"单次偶发"存疑。本轮做了 n=10 的重复测量，发现**污染是竞速的**——同一端点会在几分钟
内从全干净翻成全污染、或者反过来。

**教训：连打 N 次测的是错误的方差。** 污染是网络状态属性，不是每查询随机；两个 n=10
的结论可以都对，只是描述的是不同时刻。真正要测得跨时间采样。

## 41. 各端点实测（2026-10-12）

对 `www.google.com` 的 A 记录，各打 10 次：

| 端点 | 真 Google | 备注 |
|---|---|---|
| `doh.pub` / `1.12.12.12` | **0/10 ~ 3/10** | 污染，且跨分钟翻转 |
| `120.53.53.53` | 5/10 | 随机翻转 |
| `223.5.5.5` | **0/10** | 稳定返回 `174.132.167.252` |
| `xwfpeb16ii.cloudflare-gateway.com` | **8/8 干净**（跨 2.5 分钟） | 延迟 0.5–2.5s |

对 **Cloudflare 承载的被墙站**（这一类才决定 `isCF` 判断对不对）：

| 域名 | `doh.pub` | `223.5.5.5` | 正确 |
|---|---|---|---|
| medium.com | `162.159.153.4` ✓CF | `108.160.163.106` ✗ | doh.pub 对 |
| chatgpt.com | `172.64.155.209` ✓CF | `31.13.70.9` ✗ | doh.pub 对 |
| **discord.com** | `162.125.8.1` ✗（Dropbox 网段） | `128.242.240.59` ✗ | **两个都错** |

结论：**客户端 DoH 对封锁域名不可靠**，`/v1/dns` 删不得——但删法不对，正确的删法是
换一个干净的端点。

## 42. Cloudflare Gateway 端点可用，且支持 HTTPS RR

用户提供的 `xwfpeb16ii.cloudflare-gateway.com` 实测：

- 对 `medium / chatgpt / discord / wikipedia / google` 解析**全部正确且稳定**
- **支持 type=65（HTTPS RR）**，`crypto.cloudflare.com` 与 `satel.0xa.cc.cd` 都能取到
  `ech=`——所以 A 记录与 ECH 配置**可以共用同一条解析链**，不必拆成两个角色
- 代价是延迟 0.5–2.5s（首个请求最慢，之后 0.5–0.8s），由客户端 10 分钟缓存吸收
- 它自己的域名系统 DNS 能正确解析（162.159.36.5/36.20，未被污染），所以引导没问题

## 43. 因此：`/v1/dns` 删除，端点改为两级降级链

```
A/AAAA 与 HTTPS RR   →  Cloudflare Gateway（正确性优先）
                     →  doh.pub（主端点不可达时的兜底，快但对封锁域名不可靠）
                     →  系统 DNS
```

不需要再经协调端解析：Gateway 端点自身不被 SNI 拦，值得为此多绕一跳控制连接。

## 44. 附带发现：HTTPS RR 的引号格式不统一

不同 DoH 对展示格式里参数值的引号处理**不一致**：

```
AliDNS:      ech="AEX+DQBB...",      ipv4hint="162.159.135.79,162.159.136.79"
Cloudflare:  ech=AEX+DQBB...,        ipv4hint=162.159.135.79,162.159.136.79
```

原解析器只认带引号的形式。换成 Gateway 后会**静默地**拿不到 ECH 配置，MITM 分支整条
失效（表现为"discord 忽然全断"）。已修：`echRe/hintRe` 改成"带引号 / 不带引号"二选一
的交替匹配，并加了锁住 Gateway 格式的用例。

这是本轮最容易踩且最难查的坑——它不会报错，只会让你以为策略失效了。

---

# 第七轮：真实浏览器实测（2026-10-11）

用 Playwright 的 chromium headless shell `--dump-dom` 走代理加载真实复杂页面。
每页 20s 虚拟时间预算，统计 DOM 大小与页面内引用的资源域名数（粗略反映子资源并发面）。

## 35. 直连基线

| 页面 | 耗时 | DOM |
|---|---|---|
| www.baidu.com | 3.5s | 837 KB |
| discord.com | 21.6s | **41 字节（超时）** |
| www.google.com | 21.6s | **41 字节（超时）** |

`41 字节` 就是被墙后的空壳。基线干净：三个里两个不可达。

## 36. 经代理加载

| 页面 | 耗时 | DOM | 资源域名 | 走的路 |
|---|---|---|---|---|
| baidu | 4.4s | 835 KB | 40 | `[direct]` |
| discord | 32.2s | **229 KB** | 24 | `[mitm]` ECH |
| signal | 6.3s | 21.8 KB | 10 | `[mitm]` ECH |
| google | 73.5s | **261 KB** | 19 | `[tunnel]` 协调端 |
| youtube | 128.7s | **1.15 MB** | 19 | `[tunnel]` 协调端 |
| t.me | — | 302 | — | `[tunnel]` 协调端 |
| dropbox | — | 200 | — | `[tunnel]` 协调端 |

**复杂页面全部真实加载**（youtube 的 1.15MB DOM 意味着 JS 初始化的页面结构都拿到了），
子资源也逐个走了对应路径：`cdn.discordapp.com` 6 次全走 `[mitm]` ECH，
`www.gstatic.com` / `fonts.gstatic.com` 等 20+ 次走 `[tunnel]`。

## 37. 并发下暴露的真 bug：MITM 成功被误记成"直连可行"

路由日志里 discord 出现 **4 条成功 + 3 条失败**的混合。根因在记账：

```go
if s.MITM != nil && port == 443 && s.escalate(c, host, fl, tail) {
    s.Engine.RecordOutcome(host, proto, nil, true)   // ← nil 表示"明文直连成立"
    return
}
```

`RecordOutcome(..., nil, true)` 的语义是"**明文直连可行**"，于是引擎记成
`VerdictDirect`，之后每条新连接都会直接赌明文——而明文恰恰是行不通的那条路。

**这在浏览器并发下放大**：首屏几十条连接打同一个站，每条都重试一遍阶梯，
就是几十次无谓的探测窗口（每条 3~8s）。

修法：新增 `VerdictMitm` 记忆态。

- `RecordMitm(host)` —— 走 TLS 终止层成功后调用；
- `Plan` 返回 `KnownMitm` —— 为真时 `Strategies` 置空，代理**跳过整条阶梯**直接升级；
- `ForgetMitm(host)` —— 升级也失败时清掉，让下条连接重新完整探测。

修完复测：discord 的阶梯重试**降为 0**（日志里 `[mitm]` 6 次、`[ok]`/`[direct]`/`[skip]` 各 0 次），
残留失败 3→2，且那 2 条已证明是浏览器行为（见下）。

## 38. 残留 `[fail]` 里混着浏览器自己的行为

逐条查了剩下的 `[fail]`，其中两条是：

```
01:20:34 [idle] discord.com 客户端未发请求即断开
01:20:47 [idle] cdn.discordapp.com 客户端未发请求即断开
```

浏览器开了连接却**没发请求就关掉**（speculative / preconnect / 导航取消）。
原代码把它静默算成 `[fail]`，既污染统计也误导排查。加了 `[idle]` 单独记一条。

## 39. 剩余未通过的，原因都清楚

| 页面 | 原因 |
|---|---|
| wikipedia | 非 CF 承载（Wikimedia 网段），需协调端隧道；离线模式下无隧道 |
| google / youtube / ajax.googleapis | IP 黑洞，需协调端隧道；同上 |
| medium | ECH 直连被 403 拦下 → 退本机中继 → 9 条公共中继此刻全不可用（需自建） |

## 40. 一处并发改动导致的既有限制

测试中发现 `coord.New` 的 scheme 校验被改成了要求 `ws/wss`（正在把控制面从 HTTP
端点迁到 WebSocket 传输），而线上 Worker 仍是 HTTP 端点。因此本轮**隧道路径无法
实测**，只能用离线模式覆盖直连与 MITM+ECH 两路。隧道路径的结论沿用第六轮实测。

---

# 第十轮：隧道（OPEN/DATA/CLOSE）真机验证（2026-10-12）

传输层重写把隧道从"独立 HTTP 端点"改成了"控制 WS 上的 streamID"，这条路径此前
**从未真机验证过**。用一个隔离测试程序（不进 proxy 逻辑，直接用 `coord.Tunnel`）验：

| 目标 | 结果 |
|---|---|
| `www.wikipedia.org:80` | ✅ 收到真实 `HTTP/1.1 301`（Wikipedia，HAProxy，`x-cache: cp4041`） |
| `github.com:80` | ✅ 收到真实 `HTTP/1.1 301`（GitHub） |
| `example.com:80` | ❌ `Stream was cancelled.` |
| `cloudflare.com:80` | ❌ `Stream was cancelled.` |
| `medium.com:443` | ❌ `Stream was cancelled.` |

## 45. "Stream was cancelled" 是设计边界，不是 bug

三个失败的域名**全部由 Cloudflare 承载**。这是 Workers 的平台限制：`connect()` 拨不了
Cloudflare 自有网段。代码里本来就有这条注释，删掉 `/v1/tunnel` 时一并搬进了 `ws.js`。
客户端遇到这种情况应退到**本机 ProxyIP**——出口不在国内，地区封锁不成立。

顺带把失败原因从服务端带回了客户端：`CLOSE` 帧的 payload 现在带 reason，客户端
`Read` 直接返回它。否则隧道失败在客户端只表现为一个**没有线索的 EOF**——
排查时最费时间的就是这种。

## 46. 一个测试方法论上的坑

隔离测试一开始连 `example.com:80` 和 `140.82.112.26:80`，现象是"主机名 EOF / IP 超时"，
很容易误判成"域名解析有问题"。实际原因只是：**example.com 与 cloudflare.com 都挂在
Cloudflare 上**，而 140.82.112.26 不挂。换成 wikipedia/github 就一路通了。

换目标比改代码更能定位问题——记一笔，免得下次又沿着错误方向查半天。

---

# 第八轮：§4.1 收尾 + 交接（2026-10-12）

## 46. §4.1 定论：google 走隧道失败**不是隧道的问题**

用 `ttest`（`client/cmd/ttest`）在隧道内做**真实 TLS 握手**打目标，重新验了 handoff
里最高优先级的那一条。对照数据：

| 目标 | 结果 |
|---|---|
| `www.google.com:443` | TLS 握手阶段"上游关闭"（Worker `connect()` 后即断） |
| `www.google.com:80` | ✅ 200 OK，1.7s |
| `www.wikipedia.org:80` | ✅ 301，225ms |
| `github.com:80` | ✅ 301，213ms |
| `neverssl.com:443` | 超时 |
| `example.com:443` | "Stream was cancelled"（CF 自有网段） |

**判读**：隧道本身完全正常——80 端口一字排开、毫秒级。google:443 是**目标侧**：
Worker 出站到 Google 的 443 握手就被关（`neverssl.com` 同理）。**隧道解决的是
"本机 IP 黑洞"，解决不了"Worker 到目标的 443 也被拦"**。这不推翻 handoff §5.2
的分类，只是给"IP 黑洞类需隧道"加了个边界：对 google/youtube 这类，隧道也不是
银弹，可能仍需更强的出口或不同路径。

## 47. ttest 的用法（§8 操作手册补一条）

```bash
cd client && go build -o /tmp/ttest.exe ./cmd/ttest
/tmp/ttest.exe -worker wss://satel.0xa.cc.cd -password "$PASSWORD" host:port...
```
- 443 走真实 TLS 握手、80 走明文，打印状态行与耗时。
- **不要用"先读一下看看"判断隧道通不通**——目标在 443 等 ClientHello、80 等请求，
  那种写法会把测试和目标的正常行为混在一起（本轮一开始就栽在这）。
- `EnableECH` 的 DoH 端点要显式 `resolver.NewDoH("").Primary()`，传空串会报
  "DoH 端点为空"（§7.9）。

---

# 第九轮：B 阶段记忆层落地（2026-10-12）

把路由记忆从"每主机单个赢家 + blocked 标志"换成"有序方法列表 + 分层经验贝叶斯"。
不动 wire、不动 D1（帧契约重跑 gen-golden 仍两侧一致）。

## 48. 真机行为：记忆层按后验驱动

首次访问 discord / signal：
```
[miss] discord.com direct: 被复位
[miss] discord.com 0352f73e: 被复位        ← 4 条包级策略全被复位
[miss] discord.com 15c0e805: 被复位
[miss] discord.com 78c3d41b: 被复位
[miss] discord.com b98c567b: 被复位
[ech]  discord.com                            ← TLS 终止层赢
```
baidu 直接 `[direct]` 过。

**第二次访问**：
```
[ech] discord.com      ← 零 miss，跳过所有已知失败的方法
[ech] signal.org
```
这正是 B3 的目的：浏览器首屏几十条连接打同一站，记忆让它们共享一次探测的结果。

## 49. 实现中发现的两个真 bug（都不是测试写错）

1. **`failkind` 的 NaN 传染**：无观测方法算后验时 `n_h=0, a=0` → 分母 0 → NaN。
   一旦某方法是 NaN，所有候选 rate 相等，排序退化成不确定，direct 不再保证优先。
   修法：`den = max(n_h + a, 1)`——既防除零，也给未观测方法统一弱先验。
2. **成功的观测被 `IsEvidence` 门挡住**：`Observe` 入口按 `!kind.IsEvidence() return`，
   而成功时 `kind=kind.None`（`IsEvidence` 为 false）——**成功是最强证据却最先被丢**，
   导致"某方法成功 N 次"永远不入记忆、group 证据为空。修法：只对**失败**判
   `IsEvidence`（成功永远记录）。

这两个都是"证据方向搞反"的同类错误，值得记一笔。

## 50. 沉淀的坑（补进 §7）

- **重构成方法列表后，旧 verdict 状态的影子会残留**：`RecordOutcome` 被换成 `Record`
  后，proxy 里残留的调用点、`Stats()` 返回值、`moveFront`/`isDialError` 孤立函数
  都要清。逐个编译错误推进比一次大改快。
- **改 `Stats()` 等被测试断言的返回值签名，`go build` 通过但 `go test` 失败**——
  测试编译错误才暴露所有旧调用点。

---

# 第十一轮：B 阶段验收——三个真 bug（2026-10-12）

复核主会话的 B 阶段实现时抓到三个 bug，其中一个**让 Worker 演化完全空转**，
另一个**让整条隧道数据错位**。都已修并加了回归测试。

## 47. `SetBundle` 不刷新候选方法全集 → 下载的策略永不进入 Plan

`Memory.known` 在 `New()` 时算一次就再也不更新，而 `SetBundle` 换了池子却没通知它。
判别测试的输出：

```
下发前候选 8 个: [@direct 0352f73e 15c0e805 78c3d41b @ech @proxyip @tunnel]
下发后池 5 个（含新策略 5a989f27）
下发后候选 8 个: [@direct 0352f73e 15c0e805 78c3d41b @ech @proxyip @tunnel]   ← 完全没变
```

后果：A 阶段的 bundle 下发、演化、跨语言 ID 契约在路由上**全部空转**——客户端只试
启动时那 4 条内置策略。修法是 `SetBundle` 里同步 `mem.SetKnown(...)`。

## 48. 分组键的信号维度是死的

`proxy` 在**任何尝试之前**就算 group，传的是 `failkind.None`：

```go
group := engine.GroupKey(ech.AnyCloudflare(...), failkind.None)
```

于是 group 恒为 `"1:none"` / `"0:none"`，规格里 `isCF:firstDirectSignal` 的后半维
从未生效；`Memory.Observe` 那条按 kind 推导 group 的路径在生产环境从不走。

修法：`Record` 改收 `isCF bool`，只在**失败且类别可用**时才拼组键——那正是规格里
"第一次 direct 尝试的失败类别"的落点。顺带修掉一个副作用：只记成功的 host 会攒出
一个键为 `""` 的垃圾桶分组。

## 49. 三个上游方法不能各自独立尝试

`@ech`/`@proxyip`/`@tunnel` 都要先 `MITM.Terminate` 客户端，而**终止是一次性的**：
第一次终止就消费掉了 ClientHello，随后的 `ctls.Close()` 还会关掉底层连接。旧的
实现按方法逐个 `Terminate`，于是**第一个方法一失败就把连接毁了**，后两个必然立刻
以"客户端握手失败: use of closed network connection"收场。

真机轨迹（修前）：

```
[miss] @ech: 其它
[mitm] 客户端握手失败: use of closed network connection   ← @proxyip
[miss] @proxyip: 其它
[mitm] 客户端握手失败: use of closed network connection   ← @tunnel
[miss] @tunnel: 其它
```

修后：终止一次拿到会话，三个上游在**同一会话**里依次试，各自跑完（12s / 10s / 24s）：

```
[miss] @ech: 其它  →  [miss] @proxyip: 被复位  →  [miss] @tunnel: 读超时
```

## 50. 最隐蔽的一个：拿流式 API 做消息型协议

隧道里跑 TLS 一直报 `bad record MAC` / `received record with version 17 when expecting
version 303`，而同一隧道发明文 HTTP (:80) 完全正常。差别是**往返次数**：一次往返看不出，
多轮握手必现。

根因是客户端用了 `x/net/websocket` 的 **`Conn.Read`/`Conn.Write`——那是流式 API**：
`hybiFrameReader.Read` 在缓冲区不够时会部分读，下一次 Read 继续同一帧；而我按
"一次 Read = 一帧"解析，于是后续字节全被切错位。

同一库有**消息型 API**：`websocket.Message.Send/Receive` —— `Receive` 内部用
`io.ReadAll(frame)` 取整帧，`marshal` 对 `[]byte` 自动选 BinaryFrame。换掉之后：

```
www.bing.com:443      515ms  "HTTP/1.1 200 OK"
www.baidu.com:443    1812ms  "HTTP/1.1 200 OK"
www.wikipedia.org:443 486ms  "HTTP/1.1 200 OK"
```

**教训**：协议"一条消息就是一帧"的假设，必须用库的消息型 API 兑现；流式 API 只在
连续字节流（长度由协议自己界定）上成立。

## 51. 复验与遗留

修完四项后真机全链路：

```
https://www.baidu.com/      -> 200   [direct]
https://discord.com/        -> 200   [ech]
https://www.wikipedia.org/  -> 200   [tunnel]
https://www.google.com/     -> 200   [tunnel]
https://www.bing.com/       -> 302   [direct]
```

**google 与 wikipedia 首次经 Satel 可用。** 附带确认：`www.google.com` 的 direct
现在正确分类为 `拨号超时`（IP 黑洞），failkind 起作用了。

遗留（非阻断）：
- `@ech` 失败时日志仍只显示"其它"——`failkind.Classify` 对裸 TLS 错误（如
  "unrecognized name"）归为 Other，原因不可见。隧道那条已经带原因了（CLOSE 帧），
  ECH 这条还没。
- `probe` 的 `Kind` 已改用 failkind，但展示层仍靠 `Label()`；`Step.OK` 与 `Kind`
  并用，语义上 `Kind` 不再是"成败"，读代码时要注意。
- `client/cmd/ttest` 是隧道诊断工具（`-plain` 走明文、否则隧道内做真实 TLS），
  留着有用，但还没写进文档。

## 52. 未观测的方法被排在"试过且失败"之后 → 探索饿死

**症状**：discord 第 1 轮打 13 枪才通，第 2 轮**仍然从 `@direct` 开始**、重放一遍
已知失败的策略，而从未试过的 `@ech` 排在最后。记忆明明有数据（`hosts=1 groups=1`），
排序却像没用上。

**根因**在分层收缩的伪计数：

```
a         = min(A_MAX, n_g(m))          # 组里对该方法的观测数
rate_h(m) = (ok_h + a·prior) / (max(1, n_h + a))
```

组里**没有**该方法证据时 `n_g=0 → a=0`，于是未观测方法算出 `(0 + 0·0.5)/1 = 0.0`。
而已失败方法有组先验（`prior>0`）撑腰，得 `0.167`。两者一比，**"从没试过"成了最差
选项**——阶梯只会一遍遍重放已知失败的方法，新方法永远轮不到。分母下限 1 原本的注释
说"给未观测方法一个统一弱先验"，但 `0/1 = 0` 是**悲观**先验，不是弱先验。

**修法**：给 `a` 加下限 1。这样未观测方法的 rate ≈ prior ≈ 0.5（"不确定"），排在
已知失败之前：

```go
if a < 1 {
    a = 1
}
```

**真机验证**（discord，同一进程连续三轮）：

| 轮次 | miss 数 | 首个命中方法 |
|---|---|---|
| 1 | 13 | `@ech` |
| 2 | 1 | `@ech`（试了一条没试过的策略，随即直达） |
| 3 | **0** | `@ech` 排第一 |

回归测试 `TestUntriedBeatsFailed` 钉住"未观测 rate 必须高于已失败"。

## 53. 阶梯必须在每次探测之后重排，否则组先验白学

**症状**：en.wikipedia.org（从没访问过）访问时，把 11 条策略挨个烧完才轮到 `@tunnel`，
与首次访问 zh.wikipedia.org 一样慢（~57s）。分组机制看起来没生效。

**根因**：`tunnel()` 在循环前调一次 `Engine.Methods()` 就把整个阶梯**物化**了。
而"新 host 先打 `direct` 拿信号"这一枪**本身**才产出分组特征——组是在那一枪失败
之后才建立的。等组建好，阶梯早已排完，列表不会再看记忆第二眼。于是组先验只对
**已经访问过**的 host 有效，"同组的新域名直接继承"这条规格落空。

**修法**：把 `for range 固定列表` 换成"每打完一枪就 `plan = nil` 重排"的循环
（`tried` 集合防重复）。顺带显式化一条边界：`openSession` 一旦消费掉 ClientHello，
包级方法就再无机会，所以 `sess != nil` 时必须跳过它们——原先靠"终止类方法都排在
末尾"这个不变量隐式保证，重排会打破它。

**真机验证**（同一进程，先 zh.wikipedia 再 en.wikipedia）：

| 请求 | miss 数 | 耗时 | 命中 |
|---|---|---|---|
| zh.wikipedia.org（首个 host） | 15 | 57.0s | `[tunnel]` |
| en.wikipedia.org（同组新域名） | **1** | **4.0s** | `[tunnel]` |
| zh.wikipedia.org（重复访问） | **0** | 0.69s | `[tunnel]` |

第 2 行就是规格要的"同组后续站直接命中正确方法"：`direct` 探测一枪（探测，不是决策）
之后**跳过全部 11 条策略**直达 `@tunnel`，快了 14 倍。

**顺带**：这条改动也让 `@ech` 对非 CF 域名的白烧探测自然消失——组里 `@ech` 的后验
低于 `@tunnel`，重排后根本不会轮到它（实测 en.wikipedia 只打了一枪 direct）。

## 54. 并发编辑期间的一条运维教训

同一仓库有第二个 agent 在改 `internal/engine` 与 `internal/proxy`，并且它的测试脚本
用 `taskkill /F /IM satel.exe` 清场——这会**连我的进程一起杀**，症状是阶梯走到一半
进程消失、退出码 1、日志戛然而止、没有任何 panic 文本。

排查时先别怀疑自己的代码：改名跑（`cp satel.exe zverify.exe`）就能把两个进程隔离开。
`退出码 1 + 无栈回溯`基本可以判定为**外部终止**而不是 Go panic（panic 是退出码 2）。

---

# 第十轮：黑名单覆盖实验（2026-10-12）

拿社区黑名单（Loyalsoldier/clash-rules `gfw.txt` 的 release 分支，4430 条）抽样，
经代理逐个真实 HTTPS 请求，两轮。目的是回答两件事：**覆盖多少**、**记忆是否自己长出来**。

## 51. 样本与方法

30 条样本 = 15 条已知最难的（google / youtube / wikipedia / reddit / medium / discord /
chatgpt / signal / t.me / x / facebook / instagram / bbc / nytimes / dropbox）
+ 15 条从社区列表随机抽（`chaos.social`、`dougscripts.com`、`gate.io`、`hket.com` …）。

每条：`curl -x http://127.0.0.1:<port> https://<domain>/`，`--max-time 45`。
两轮用同一个客户端进程，**中间不重启**——否则记忆会被清零，测不出"长出来"。

## 52. 第一轮（记忆从零）

拿到的有效数据（10 条小样本，因为大样本中途被并发进程杀掉了，见 §54）：

| 域名 | 结果 | 耗时 | 备注 |
|---|---|---|---|
| discord.com | **200** | 5.0s | 走 @ech |
| chaos.social | **200** | 4.3s | 走 @ech |
| dougscripts.com | **200** | 1.0s | |
| gate.io | **301** | 0.6s | |
| hket.com | **301** | 3.2s | 末段 @tunnel |
| google.com | 000 | 25s（被 curl 打断） | @proxyip 先吃了 20 秒 |
| youtube.com | 000 | 25s | 同上 |
| www.wikipedia.org | 000 | 25s | 同上 |
| reddit.com | 000 | 25s | 同上 |
| medium.com | 000 | 20.6s | |

**5/10 通过。** 全部 5 个失败都不是"没路可走"，而是**在 curl 的窗口内没走到那条路**——
日志显示它们最后都成功建立了 `[tunnel]`，只是 `@proxyip` 先跑了 9 条公共中继、
耗掉 20 秒才轮到 @tunnel。

## 53. 第二轮（记忆已热）：`google.com` 25s → **859ms**

同一个客户端进程，同一批域名再来一遍：

```
PASS1  google.com  000  25144ms
PASS2  google.com  301    859ms     ← 记忆直接把它送到 @tunnel
```

日志里第二轮 google 只有一行 `[tunnel] google.com`——**零 miss、零策略尝试**。
这是"记忆自己长出来"最干净的一个证据：第一轮它把 direct + 12 条策略 + @ech + @proxyip
全试了一遍（81 条 miss），第二轮一次命中。

## 54. 两个真 bug（都已改）

1. **`[skip]` 只打日志、不真跳过。** 方法列表重构时把原来 `break` 的语义丢了，
   改成只 `s.logf("[skip] …")`。后果：IP 黑洞站（拨号就超时）上照样把每条包级策略
   挨个试满——实测 4 条 × 5 秒 = **白烧 20 秒**。
   修：`trySimple` 返回 `(ok, tcpDown)`，`tunnel` 收到 `tcpDown` 后跳过后续包级方法
   （终止层方法不受影响——它们走 CF 边缘/协调端/中继，与本机到目标的可达性无关）。

2. **`@proxyip` 因为字母序排在 `@tunnel` 前面。** 三个终止层方法原本同成本、靠 ID
   字典序破平，而 `"@proxyip" < "@tunnel"`。后果就是 §52 那 20 秒白烧——@proxyip 对
   IP 黑洞站完全无用（它只为"CF 承载 + 锁国区"存在），却排在真正管用的 @tunnel 之前。
   修：`methodCost` 给三者**成本递增且互不相同**（@ech 2 / @tunnel 3 / @proxyip 4）。

顺带补了 `memory.go` 缺的 `fmt` import（并行改动加了 `DebugTopRates` 用 `fmt` 但漏了 import，
整包编译不过）。

## 55. 一个必须记下来的环境坑

这一轮有多次"代理静默死亡"（日志停在中途、无 panic、Windows 事件日志无 WER 记录、
`taskkill` 显示进程已不在）。一度以为是代码崩溃，查了 Go panic、访问违例、`os.Exit`
路径、instlock、看门狗——**全不是**。

**真相：有并发改动者在跑 `taskkill /F /IM satel.exe`**（他自己的测试脚本），把别人的
代理一起杀了。特征是"存活状态 Y/N 来回跳"——因为杀的是一个进程、而检查时又可能有
另一个 satel 实例（包括几小时前遗留的僵尸进程）。

教训：**在这台机器上做长跑实验，要么确认没有并发实验者，要么给进程起唯一名字**
（`satel-<tag>.exe`），否则 `taskkill /IM` 会互相误伤。这个坑不写下来，下一个人会
重复把时间花在"找不存在的崩溃"上。

---

# 第十一轮：改名隔离后的大样本两轮（2026-10-12）

前两轮（§52、§54）因为并发实验者 `taskkill /IM satel.exe` 被反复打断，只拿到
10 条小样本。这一轮按 §54 的建议改名隔离（`cp satel.exe zverify.exe`），再用
302 端口跑完整 30 条 × 2 轮——**同一进程、中间不重启**，记忆连续。

## 56. 结果：28/30 拿到 HTTP 响应，两轮一致

| | PASS1（记忆空） | PASS2（记忆热） |
|---|---|---|
| 拿到响应 | **28/30** | **28/30** |
| `[miss]` 探测次数 | **50** | **6** |
| 最终走的路 | 7 direct / 3 ech / 17 tunnel | 7 direct / 3 ech / 17 tunnel |

**同一个进程、同一批域名，第二轮用 6 次探测代替 50 次**——这就是记忆"自己长出来"
最直接的证据。路由分布完全不变（7/3/17），只是第二次**直奔**正确的那条。

## 57. 提速幅度

平均 **6.2×**，最大的几个：

| 域名 | PASS1 | PASS2 | 提速 |
|---|---|---|---|
| www.wikipedia.org | 12628ms | 841ms | **15.0×** |
| google.com | 6578ms | 783ms | 8.4× |
| t.me | 5961ms | 784ms | 7.6× |
| www.facebook.com | 7366ms | 1165ms | 6.3× |
| youtube.com | 5959ms | 963ms | 6.2× |

## 58. 三条"没提速"的，原因各不相同——都不是 bug

1. **medium.com / chatgpt.com**：两条都失败。日志明确：
   ```
   [miss] chatgpt.com @ech: 其它 (ECH 直连被上游以 4xx 拒绝)
   [miss] chatgpt.com @tunnel: 其它 [Stream was cancelled.]     ← 服务端 reason
   [miss] chatgpt.com @proxyip: 被复位 (9 条公共中继全部失败)
   ```
   两条路都被正确排除，且**服务端通过 CLOSE 帧把 "Stream was cancelled." 带了回来**
   （Workers 拨不了 CF 自有网段）——这是上一轮 `reasonSuffix` 那个改动的实际收益，
   否则这里只会是"其它"。剩下唯一一条路是本机 ProxyIP，而 9 条公共中继此刻全灭
   （Vultr/KR/… 全部握手失败）。**结论：这两条是"确实无路可走"，需要自建中继。**
2. **`Stream was cancelled.` 能带回来**，证明 §4.3 那个"拿流式 API 做消息型协议"的
   修复是对的——原因字段能穿透 WS 到客户端日志。

## 59. ~~三条"慢但通了"~~ —— 其中一条是**假连通**，本节已更正

**更正（2026-10-12 当天，用户要求浏览器实测后发现）**：

- **`x.com` 是假连通。** 用真实浏览器 UA + 完整正文复测：
  ```
  curl -H "User-Agent: Mozilla/5.0 … Chrome/120.0.0.0 Safari/537.36" \
       -m 60 -x http://127.0.0.1:<port> https://x.com/
  → code=000  time=60.0s  size=0        （0 字节正文）
  ```
  而**同一代理、同一 curl** 下 `discord.com` 是 `200 / 170382 字节 /
  title="Discord - Group Chat That's All Fun & Games"`。差别只在域名，所以不是链路问题。
- 当时的完整轨迹也说明了它**根本不该算通**：
  ```
  [miss] x.com direct: 读超时
  [miss] x.com 0352f73e: 读超时            ← 10 条包级策略全部读超时
  [miss] x.com @ech: 其它 (tls: internal error)
  [miss] x.com @tunnel: 其它 [Stream was cancelled.]
  ```
  一条都没成功，最终 `[fail]`。
- **我为什么会记错**：那一轮跑的是**旧二进制**——我改了 `methodCost` 之后没有重新
  `go build`，`zverify.exe` 还是改动前的。旧二进制里 direct 那一枪确实拿到了
  `HTTP/1.1 200 OK` 响应头（`Server: cloudflare envoy`、`x-server: x-web`、
  真实 `x-transaction-id`、`Transfer-Encoding: chunked`），于是 `waitFirst` 判"通"。
  **但正文一个字节都没到**——X 的登录墙对非浏览器客户端就是这个行为。
- **教训两条**：
  1. `waitFirst` 判"通"只看首字节，**响应头到了不等于内容到了**。对
     `Transfer-Encoding: chunked` + 0 字节正文的站点，这是系统性盲区。
  2. 改完代码必须重新构建再测。用旧产物得出的结论比没有结论更坏——它会写进文档。

仍然成立的两条：

- `itshidden.com` 20.3s → 20.4s（**522**）——Cloudflare 往源站连超时，源站自己的问题。
- `www.nytimes.com` 3.0s → 841ms（**403**）——站点按出口 IP 的地区策略。

`niu.moe` 同理 403。**这几类属于目标站自己的门槛，本地侧无解。**

## 60. 覆盖率的诚实口径

```
28/30 有响应 → 25 条是真通的（2xx/3xx）
             →  nytimes.com 403 / niu.moe 403 ：目标站按地区拒绝
    blogspot.com.mt 404                          ：站点本身没有该路径
    itshidden.com    522                         ：目标源站挂
    medium / chatgpt.com                        ：CF+锁国区，唯一出口是自建中继

更正：x.com **不是**"慢但通了"——它是假连通（200 响应头 + 0 字节正文），
      见 §59。所以"真通"应扣掉它一条，正确口径是 **24/30**。
```

"能不能全覆盖 200 连通"的答案是：**在不自建中继、只用公共资源的前提下，
24/30 是真通的；剩下 6 条里 3 条是目标站自己的门槛（403/404/522）、
1 条是假连通（x.com，响应头到了但内容到不了）、
2 条（medium / chatgpt）需要补一块自建 ProxyIP 才能拿下。**

## 61. 本轮的运行方式（可复现）

```bash
cd client && go build -trimpath -ldflags "-s -w" -o zverify.exe ./cmd/satel   # 改名隔离
cd ../.lab/blacklist && bash exp3.sh        # 端口 18260、两轮、同一进程
```

关键：**两轮之间不能重启进程**，否则记忆清零、测不出"长出来"。
另一轮教训见 §55——并发实验者的 taskkill 会误伤无名进程。

## 55. 回报永远不发：syncLoop 的 ticker 排在连接之前

**症状**：真机跑完，`reportLocked` 明明入队了（DIAG 打出
`DIAG reportLocked clientNil=false item=www.baidu.com @direct`），Worker 侧
`outcome` 表却**一条都没有**，而且**没有任何错误日志**。

**根因**：`syncLoop` 里 `flushReports` 只挂在 ticker 上，第一次触发要等满
`--sync-interval`（默认 15 分钟）。而 syncLoop 启动时那次 flush 排在浏览器连接之前
——那时队列是空的，于是它 drain 了个 0 就回去睡 15 分钟。时间线（同一进程）：

```
04:31:09 DIAG flush items= 0          ← 启动时 flush，队列还空着
04:31:09 [sync] tls 策略库 v2 …
04:31:10 DIAG enq www.baidu.com @direct   ← 浏览器这时才连上，入队
```

**修法**：回报与拉取拆成两个 ticker，回报用短周期（45s）。15 分钟拉一次策略库够，
但方法级结论要跟上浏览速度，否则协调端看到的永远是半小时前的世界。

**教训**：这条 bug 最阴的地方是**静默**。没有报错、没有超时、日志看着一切正常，
只是数据永远不到。排查靠的是在 `Drain()` 前后打点看队列长度——"没有错误"和
"在工作"是两件事，尤其是"周期性任务"这类路径。

## 56. D1 库被外部删掉了（重建）

真机回报时报 `D1_ERROR: D1 database c1fc4b04-804a-4bcc-b272-aad7015607d5 has been
deleted.`。`wrangler d1 list --json` 返回 `[]`——库里**一行都不剩**（20 条策略、
历史 outcome、host_stat 全没）。用 `.env` 里的凭据 `wrangler d1 create satel` 重建，
新 id `a442d347-a5eb-43ac-8f0b-8a7b957b4af2`，跑 schema.sql 建表、重新部署，
`admin evolve` 与客户端 sync 随即恢复（gen 2，pool 20）。

**留给下一个人的**：`server/wrangler.toml` 里的 `database_id` 是硬编码的，库一重建
就必须同步改，否则 Worker 起来就是这个报错。已在 toml 顶部注释写明。

## 57. 三处踩坑：回报链路上"看起来都对了"却一行都没落库

方法级上报打通的过程里，**连续三次**都是"代码写完、测试全绿、真机一行没进去"。
每一次的失败点都不一样，值得记下来：

### 57.1 回报静默：ticker 排在连接之前

`flushReports` 只挂在 15 分钟的 ticker 上，而第一次 flush 发生在 `syncLoop` 启动时
——那会儿浏览器还没连上，队列是空的。症状是**没有任何错误日志**。
详见 §55。修法：回报单独一个 45s 短周期。

### 57.2 `proto` 没人填

`Item` 加了 `Proto` 字段，线格式也要求了，但 engine 的两个回报点都没填它
（`RecordAttempt` 与 `Record`）。服务端按协议拒收：`STATUS(code=2 回报条目字段为空)`。

**"字段存在"不等于"字段有值"。** 一个必填字段要串过 5 层（proxy → engine → coord →
frame → 服务端校验），漏掉任何一层的症状都是同一条笼统的拒绝信息。

### 57.3 schema 是 `CREATE TABLE IF NOT EXISTS`，所以它**不会**改已存在的表

线上库先前就有 `outcome` 表（老 schema）。跑 `schema.sql` 全部"成功"——因为
`IF NOT EXISTS` 让每条 CREATE 都是 no-op。新表建好了，`outcome` 却还是老样子。
真机症状：`D1_ERROR: table outcome has no column named host`。

必须跑 `migrations/0002_*.sql`（或幂等 CLI `node src/migrate.js`，它用
`PRAGMA table_info` 判断缺哪列）。**建表脚本对已有库是无效的**，这条要写进部署步骤。

顺带：`schema.sql` 里故意不放 `ALTER TABLE`——SQLite 的 `ADD COLUMN` 没有
`IF NOT EXISTS`，放进去会让脚本第二次执行直接失败。

### 57.4 golden 脚本自己坏了（而且坏了很久）

`scripts/gen-golden.sh` 里那段 Go 是用**未加引号的 heredoc**（`<< GOEOF`）嵌入的，
里面的 `"$GOLD_ABS"` 被 **shell** 当变量展开成了当时的路径字面量——一个带反斜杠的
Windows 路径，被 Go 字符串当作转义序列，文件写到了一个诡异的文件名。脚本却以为成功。

后果是它一直报"两侧一致"（因为它读的是上一次遗留的文件），而我抄给你 hex 时是**从
终端复制的**，被截断了——你据此发现 224 vs 228 的长度不符，是对的。
现在改成 `os.Getenv("GOLD_ABS")`（让 Go 自己去环境变量里取，绕开 shell 展开），
并且重跑后长度变成 122 / 228 / 168 / 38 / 32。

**教训**：跨语言 golden 的价值全在"两边真的各跑了一遍"。一旦这一步变成 no-op，
它就退化成"两份手工抄的 hex 比对"，比没有更危险——它会一直给你绿灯。

## 58. 真机验收（方法级上报全链路）

```
05:36:51 [sync] tls 策略库 v2: 8 条可用（丢弃 0 条）        ← HELLO v2 被受理
05:39:40 [sync] 回报 3/3 条                                   ← REPORT 被受理
05:43:38 [sync] 后缀经验 1 条                                 ← hints 下发并装载
```

D1 侧对账（3 次真实访问）：

```
host             method     kind  proto  ok  batch_id
www.baidu.com    @direct    ok    tls    1   418c9651d06ba27ff0afd2e629ae8459
discord.com      @direct    ok    tls    1   418c9651d06ba27ff0afd2e629ae8459
www.bing.com     @direct    ok    tls    1   418c9651d06ba27ff0afd2e629ae8459
```

幂等性对账：`outcome` 总数 5 == `report_batch` 的 `SUM(accepted)` 5，两个 batchID 各
只出现一次——重放没有双计。

hints 回环：手工种一条 `m.wikipedia.org / @tunnel`（15 胜 0 负 / 5 主机），
客户端 `[sync] 后缀经验 1 条` 后首次访问 `en.m.wikipedia.org`：
**1.53s 直接 `[tunnel]`，零浪费探测**（没有 hint 时要 57s）。

挖 hint 的规则经合成数据验证：同后缀 ≥3 主机、≥6 次观测才挖；共享托管空间
（`user.github.io` / `foo.blogspot.com` / `my.herokuapp.com`）**一律拒绝**——
把一个用户的结论推给所有用户是最坏情况。可注册域本身（`wikipedia.org`，没有子域）
也拒绝，因为没有可聚合的维度。
