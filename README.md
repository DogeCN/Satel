<div align="center">

<img src="docs/icon.svg" alt="Satel" width="128" height="128">

# Satel

**A local DPI-circumvention client that keeps its secrets.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange.svg)](https://developers.cloudflare.com/workers/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#支持平台)
[![Stars](https://img.shields.io/github/stars/DogeCN/Satel?style=social)](https://github.com/DogeCN/Satel/stargazers)
[![Forks](https://img.shields.io/github/forks/DogeCN/Satel?style=social)](https://github.com/DogeCN/Satel/network/members)

</div>

---

Satel 是一个**严格单文件、零落盘**的本地 DPI 绕过客户端，配一个可选的 Cloudflare
Worker 协调端。它不修改系统网络栈：所有改写都发生在自己进程内的一个 SOCKS5 /
HTTP CONNECT 代理里——不装驱动、不装服务、不需要管理员权限。

```
浏览器 / 任意 TCP 应用
     │  SOCKS5 与 HTTP CONNECT 共用同一端口
     ▼
  satel（单文件，状态全在内存）
     │  ① 抄下首飞行段            ④ 全败 → TLS 终止 + ECH
     │  ② DoH 解析（绕 DNS 污染）    或协调端隧道 / 本机中继
     │  ③ 按记忆层的方法列表逐个试
     ▼
  Cloudflare Worker ── D1（策略库演化 + 后缀经验）
```

## 为什么需要 TLS 终止层

这是 Satel 与 zapret / GoodbyeDPI / ciadpi 一类工具的根本差别。

在本网络里实测（原始数据见 [`docs/findings.md`](docs/findings.md)）：包级改写——分片、
TLS-RF、紧急字节——能打穿**无状态** SNI 封锁，但面对**状态化**重组和 **IP 黑洞**
原理上无解。真正奏效的是 ECH（加密 SNI）与域名前置，而这两者都必须由自己发起 TLS
握手才能做到，透明改写架构做不到。所以 Satel 加了 TLS 终止层。

代价是明确的，也是这个技巧的固有代价：本地 CA 装在**用户**信任区期间，它能看到并
改写所有信任系统根证书的软件的明文。Satel 默认**严格零落盘**——启动装一张临时 CA，
退出即删。

## 特性

- **单文件**：`CGO_ENABLED=0` 静态编译，6 个平台（Windows / Linux / macOS ×
  amd64 / arm64），无运行时依赖。
- **零落盘**：不读不写任何配置文件；策略库与记忆全在内存，退出即消失。
- **自适应路由**：三层记忆（逐主机 → 同类站点组 → 协调端后缀经验）+ 分层经验贝叶斯
  排序。阶梯形状不硬编码——每条连接按后验决定先试什么。
- **加密控制面**：到协调端的控制通道走 ECH，底层再套一层自举分片。
- **跨语言帧契约**：客户端与 Worker 的线上格式由脚本生成 golden 并逐字节断言。
- **在线演化**：协调端用 UCB1 + 变异演化策略库，后缀经验回流成第三层记忆。

## 安装

从 [Releases](https://github.com/DogeCN/Satel/releases) 下载对应平台的单文件，或自行构建：

```bash
cd client
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o satel ./cmd/satel
```

## 使用

```bash
# 起代理。系统代理指向 127.0.0.1:18080 即可
satel serve --worker wss://satel.example.com --password "$PASSWORD"

# 离线模式：只用内置策略库，不需要协调端
satel serve --listen 127.0.0.1:18080

# 自检：某站现在能不能用（--fetch 穿透 MITM 假象）
satel probe --handshake --fetch www.example.com

# 判定封锁判据：同 IP 换 SNI 的无混淆对照
satel diag --shared-ip --bad-sni www.example.com

# 触发一代策略演化
satel admin evolve --worker wss://… --password … --admin-key …
```

### 关键 flag

| flag | 默认 | 说明 |
|---|---|---|
| `--listen` | `127.0.0.1:18080` | 监听地址；`:0` 自动选端口 |
| `--worker` | 空 | 协调端；留空 = 离线 |
| `--password` | `$SATEL_PASSWORD` | 与协调端共享，**从不上网** |
| `--ech` | `true` | 用 ECH 隐藏控制通道 SNI |
| `--ca-file` | 空 | 开发通道：CA 落盘复用。**空 = 严格零落盘** |
| `--probe-wait` | `3s` | 每个候选等首字节的窗口 |
| `-v` | `false` | 详细日志（`[direct]` / `[miss]` / `[ech]` …） |

### CA 生命周期

| 模式 | 行为 | 代价 |
|---|---|---|
| 默认（不给 `--ca-file`） | 启动装一张临时 CA，退出即删，**不写任何文件** | Windows 每次启动弹一次根证书确认框 |
| `--ca-file <path>` | CA 落盘复用，只在第一次装（之后只查不装） | 私钥留在磁盘上、这张 CA 长期可信 |

`satel remove-ca` 随时把信任区清干净（进程被强杀、defer 没跑到时的退路）。

## 部署协调端

需要一个 Cloudflare 账号和一个托管在 Cloudflare 的域名。**必须绑自定义域名**——
`*.workers.dev` 在大陆被 SNI 阻断，客户端连不上。

```bash
cd server
export CLOUDFLARE_API_TOKEN=… CLOUDFLARE_ACCOUNT_ID=…
npx wrangler d1 create satel              # 把输出的 id 填进 wrangler.toml
npx wrangler d1 execute satel --remote --file=schema.sql
npx wrangler d1 migrations apply satel --remote
npx wrangler deploy
npx wrangler secret put PASSWORD
npx wrangler secret put ADMIN_KEY
```

然后在控制台把 `satel.<你的域名>` 绑成该 Worker 的自定义域名。

或用一键脚本：`scripts/deploy.sh`（支持 `--dry-run`）。

## 支持平台

Windows / Linux / macOS，amd64 与 arm64。**信任区安装目前只在 Windows 实现**——
其它平台 MITM 路径不启用，其余功能（包级改写、协调端隧道）照常工作。

## 文档

| 文件 | 内容 |
|---|---|
| [`docs/protocol.md`](docs/protocol.md) | 协议规范：策略模型、帧格式、opcode、认证、重连重放 |
| [`docs/findings.md`](docs/findings.md) | 实测记录：封锁分类、与第三方实现的逐招对照、结论的原始数据 |
| [`docs/HANDOFF.md`](docs/HANDOFF.md) | 工程交接笔记：架构决定、硬约束、踩过的坑 |

## 边界与已知限制

- 系统代理不转发 UDP：QUIC 不会被代理，建议在浏览器里禁用 QUIC。
- **IP 黑洞类目标（google / youtube / telegram）需要协调端隧道**；而隧道解决的是
  "本机出口被封"，解决不了"协调端到目标的 443 也被拦"——这一类可能仍无解。
- **TLS 终止层只对 Cloudflare 承载的域名生效**（共享 ECH 配置只对 CF 边缘有效）。
- MITM 分支不协商 ALPN，浏览器会退回 HTTP/1.1。
- 装了本地 CA 意味着 HTTPS 对 Satel 透明。这是 ECH / 域名前置的固有代价。
- **不实现 `fake` / `disorder` 原始套接字后端**：实测 ciadpi（含全套招法）对状态化封锁
  重复测量 0/5，加了也不解决问题。

## 合规

在 Cloudflare Workers 上运行协调服务、以及在受限网络中使用这类工具，都可能触碰
服务条款或当地法规。请**个人使用、低流量**，用**小号部署**并做账号隔离。本项目仅供
技术学习与研究。

## 致谢

- [zapret](https://github.com/bol-van/zapret) —— 包级改写的完整工具箱，本项目的底层
  招法（split / tlsrf / oob）思路源自此。
- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) —— Windows 上的经典方案。
- [ciadpi / ByeDPI](https://github.com/hufrea/byedpi) —— 跨平台 desync 实现，是本项目
  实测阶段的主要对照。
- [Geneva](https://github.com/kard/geneva) —— 用遗传算法自动搜索报文改写策略的思路。

## 许可证

[AGPL-3.0-or-later](LICENSE)　© 2026 DogeCN　详见 [NOTICE](NOTICE)。
