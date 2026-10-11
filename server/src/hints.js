// 后缀 hint 的挖掘：把 method_stat（**每主机**的方法成败）聚合成**每后缀**的弱先验。
//
// 目标：让客户端在一个**从未访问过**的新主机上，在打第一枪之前就知道
// "同后缀的其它主机上哪个方法赢得多"。这把"每个主机各自付一遍学费"变成
// "同后缀只付一次"。
//
// 三条设计红线（每条都对应一类真实误伤）：
//
//   1. **只挖 method_stat，绝不读 hint。** 如果把上一轮挖出来的 hint 当输入喂给
//      下一轮，hint 会自我强化：一个偶然的强后缀结论会永远自己证明自己，
//      客户端的一次反例无法把它拉下来。这是必须防的自我循环。
//   2. **后缀必须通过公共后缀列表。** "co.uk" 底下有 10^6 个互不相干的站点，
//      "github.io" 底下全是互不相干用户的页面。用它们当"后缀"就是把噪声
//      当先验推给所有人——比没有 hint 更糟。见 candidateSuffix 的规则。
//   3. **每个 host 权重封顶。** 见 hostWeight 的说明：单个 noisy host 不该
//      决定一个后缀的结论。

import { getDomain, getPublicSuffix, getSubdomain } from "tldts";

import { isIPLiteral } from "./validate.js";

/**
 * PSL 查询选项：**启用私有段**（PRIVATE_DOMAINS）。
 *
 * 只用 ICANN 段的话，`github.io` / `blogspot.com` / `appspot.com` 这些**共享托管
 * 平台**会被当成普通可注册域（domain=github.io, publicSuffix=io），于是
 * "user.github.io" 能挖出 "github.io" 当后缀——而这正是要防的：它下面每个用户
 * 的页面互不相干。
 *
 * 私有段把这些平台明确列为公共后缀（github.io 本身就是一条 PSL 规则
 * `*.github.io`），启用后 publicSuffix 变成 "github.io"，registrable 也变成
 * "github.io" —— 二者相等，candidateSuffix 就能识别并拒绝它。
 *
 * 代价：私有段里有些条目其实是可注册的（如某些 blog 平台），把它们当公共后缀会
 * 让"真正的多主机站点"挖不出 hint。取**保守的一侧**：宁可漏一个 hint（少一个
 * 先验），也不要给所有用户推一个错的先验。
 */
const PSL_OPTS = { allowPrivateDomains: true };

// --- 阈值 ------------------------------------------------------------------

/** 一次挖掘最多看多少行 method_stat。防单次 cron 读爆内存。 */
export const MINE_ROW_LIMIT = 20000;

/** 观测时间窗（秒）。再旧的数据不进这一轮结论。 */
export const MINE_MAX_AGE_SECONDS = 7 * 24 * 3600;

/** 一个后缀至少要有多少个**不同主机**支撑。低于此数不挖。 */
export const MIN_HOSTS = 3;

/** 一个后缀至少要有多少次**真实观测**。低于此数不挖。 */
export const MIN_OBSERVATIONS = 6;

/**
 * 单个 host 在一个 (后缀, 方法) 上的权重上限。
 *
 * 3 次全赢 = 1.0，10 次全赢还是 1.0。不封顶的话，某个被访问了几百次的 host 会
 * 独自决定整个后缀的结论——而它可能只是恰好适合这一个站。
 */
export const MAX_HOST_WEIGHT = 3;

/** 成功率的**极性阈值**：>= 0.8 算强成功，<= 0.2 算强失败，中间不算证据。 */
export const STRONG_OK_RATE = 0.8;
export const STRONG_FAIL_RATE = 0.2;

/** hint 的存活时间（秒）。与客户端的 inheritedTTL（20 分钟）对齐。 */
export const HINT_TTL_SECONDS = 20 * 60;

/** 每轮每个 proto 最多产出多少条 hint。 */
export const MAX_HINTS_PER_PROTO = 128;

// --- 后缀选取 --------------------------------------------------------------

/**
 * 从主机名算出一个**可聚合的后缀**，或返回 null（不可聚合）。
 *
 * 聚合键取"可注册域 + 最左一级子域"（`www.api.example.com` → `www.example.com`），
 * 它天然有 3 个标签，是 PSL 之下**严格长于公共后缀、严格短于主机名**的一层。
 *
 * 为什么不取更长的后缀（如 `api.example.com` 给 `a.b.api.example.com`）：
 * 那需要按标签数枚举多个候选，会把同一个站拆进多个 hint 组，组数随深度指数增长。
 * 单层拼接是幂等的——同一个主机永远映射到同一个后缀，聚合不会漏也不会裂。
 *
 * 为什么不取更短的（即裸的可注册域 `example.com`）：只有 2 个标签，覆盖整站，
 * 而 `example.com` 的结论会直接套到该域下**每一个**主机上，包括那些行为完全
 * 不同的（CDN 节点 vs API 端点）。>= 3 标签是这条防线的形式化。
 *
 * 公共后缀列表（PSL）在这里的职责：`github.io` / `blogspot.com` / `co.uk` 这类
 * **共享托管后缀**下面全是互不相干的站。若允许把它们当后缀，就会把"某个用户的
 * github.io 页面需要 @tunnel"推给"所有用户的 github.io 页面"——比没有 hint
 * 危险得多。
 *
 * 例子（用 tldts 的 PSL）：
 *   www.api.example.com  → api.example.com
 *   api.example.com      → null            （就是可注册域，没有更长一层）
 *   www.example.com      → null            （同上）
 *   a.b.co.uk            → null            （b.co.uk 是可注册域，无更长一层）
 *   user.github.io       → null            （PSL：github.io 是公共后缀 → 共享托管）
 *   x.blogspot.com       → null            （同上）
 *   a.b.c.example.co.uk  → example.co.uk
 *   1.2.3.4 / ::1        → null            （IP 没有后缀）
 */
export function candidateSuffix(host) {
  if (isIPLiteral(host)) return null;
  if (host.split(".").length < 3) return null;

  // 可注册域 = PSL 之下的第一个域（example.com）。
  const registrable = getDomain(host, PSL_OPTS);
  if (!registrable) return null;
  // 公共后缀 = PSL 条目本身（com / co.uk / github.io）。
  const publicSuffix = getPublicSuffix(host, PSL_OPTS);
  if (!publicSuffix) return null;

  // 子域部分（可能是多级：www.api.example.com 的子域是 "www.api"）。
  const sub = getSubdomain(host, PSL_OPTS);
  if (!sub) return null; // 无子域 = 就是可注册域本身，没有"更长一层"可取
  // **只取最右一级**子域标签，拼到可注册域前面：
  //   www.api.example.com → sub="www.api" → 标签 "api" → api.example.com
  //   api.example.com     → sub="api"    → 标签 "api" → api.example.com
  // 两个主机名映射到同一个后缀，这是聚合成立的前提。
  const leftLabel = sub.slice(sub.lastIndexOf(".") + 1);
  if (!leftLabel) return null;

  const suffix = `${leftLabel}.${registrable}`;

  // 必须严格短于主机名：否则退化成了"逐主机存储"，那就该用 method_stat。
  if (suffix.length >= host.length) return null;

  // 必须严格长于公共后缀（com / io 之下的一层总是满足）。
  if (suffix.length <= publicSuffix.length) return null;

  // **拒绝共享托管空间**：可注册域本身就是一条 PSL 公共后缀规则时，说明这块
  // 空间归属一个平台而非注册者（github.io / blogspot.com / herokuapp.com），
  // 底下每个用户/站点互不相干。把它们当聚合键，等于把一个用户的结论推给所有用户。
  if (registrable === publicSuffix) return null;

  return suffix;
}

/**
 * 单个 host 对某个 (后缀, 方法) 的权重：0 或 [1, MAX_HOST_WEIGHT]。
 *
 * 两步：
 *   1. **够极端才投票**：该 host 上这个方法的成功率必须在 >=0.8 或 <=0.2 的一个
 *      极端区里。中间地带（0.2~0.8）不投票——它多半意味着"时好时坏"，可能是网络
 *      抖动或目标站自己在变，把它当证据只会给结论掺噪声。
 *   2. **票数饱和**：一票算一次观测，最多 MAX_HOST_WEIGHT 票。一个被访问了
 *      几百次的 host 不该独自决定整个后缀的结论，所以 3 次之后不再加权。
 *
 * 返回值同时编码方向（>0 = 该 host 认为此方法好；调用方按 ok>fail 判定方向），
 * 这里是纯量，方向在 mineHints 里按该 host 的 ok/fail 判。
 */
export function hostWeight(ok, fail) {
  const n = ok + fail;
  if (n === 0) return 0;
  const rate = ok / n;
  const extreme = rate >= STRONG_OK_RATE || rate <= STRONG_FAIL_RATE;
  if (!extreme) return 0;
  return Math.min(n, MAX_HOST_WEIGHT);
}

// --- 挖掘 ------------------------------------------------------------------

/**
 * 把 method_stat 的行聚合成 hint 结论。**纯函数**，不做 I/O——便于用构造好的行
 * 直接测试边界（边界条件很多，注入真实 DB 会让测试又慢又脆）。
 *
 * @param {object[]} rows  method_stat 的行：{host, proto, method, ok, fail, last_kind, last_ts}
 * @param {object}   opts
 * @param {number}   opts.now        unix 秒
 * @param {number}  [opts.proto]     只挖这个 proto；不给则挖所有
 * @returns {{suffix, proto, method, ok, fail, hosts, expires}[]}
 */
export function mineHints(rows, { now, proto = null }) {
  const cutoff = now - MINE_MAX_AGE_SECONDS;

  // 第一遍：按 (host, proto, method) 聚合该 host 的总量。
  // 必须先按 host 收敛——同一 host 在 method_stat 里通常有多行（按 host 存），
  // 但同一个主机也可能因 proto/method 组合出现多行。按 host 收敛后，
  // hostWeight 拿到的就是这个 host 的完整战绩，而不是其中一行。
  const byHost = new Map();
  for (const r of rows) {
    if ((r.last_ts ?? 0) < cutoff) continue;
    if (proto && r.proto !== proto) continue;
    const hkey = `${r.proto}|${r.method}|${r.host}`;
    let h = byHost.get(hkey);
    if (!h) {
      h = { host: r.host, proto: r.proto, method: r.method, ok: r.ok ?? 0, fail: r.fail ?? 0 };
      byHost.set(hkey, h);
    }
  }

  // 第二遍：按后缀聚合**每台 host 的一票**。
  const groups = new Map();
  for (const h of byHost.values()) {
    const suffix = candidateSuffix(h.host);
    if (!suffix) continue;

    const weight = hostWeight(h.ok, h.fail);
    if (weight <= 0) continue;

    const key = `${suffix}|${h.proto}|${h.method}`;
    let g = groups.get(key);
    if (!g) {
      g = { suffix, proto: h.proto, method: h.method, ok: 0, fail: 0, hosts: new Set() };
      groups.set(key, g);
    }
    g.hosts.add(h.host);
    if (h.ok > h.fail) g.ok += weight;
    else g.fail += weight;
  }

  // 只保留证据足够的：hosts >= MIN_HOSTS，总观测 >= MIN_OBSERVATIONS。
  const out = [];
  for (const g of groups.values()) {
    const hosts = g.hosts.size;
    const obs = g.ok + g.fail;
    if (hosts < MIN_HOSTS || obs < MIN_OBSERVATIONS) continue;
    out.push({
      suffix: g.suffix,
      proto: g.proto,
      method: g.method,
      ok: Math.round(g.ok),
      fail: Math.round(g.fail),
      hosts,
      expires: now + HINT_TTL_SECONDS,
    });
  }

  // 排序后截断：同一个后缀下每个方法一条 hint，所以每个后缀会有 ~4 个方法。
  // 按支撑强度排序，保证截断后留下的最强。
  out.sort((a, b) =>
    b.hosts - a.hosts ||
    (b.ok + b.fail) - (a.ok + a.fail) ||
    (b.ok / (b.ok + b.fail + 2)) - (a.ok / (a.ok + a.fail + 2)) ||
    a.suffix.localeCompare(b.suffix) ||
    a.method.localeCompare(b.method),
  );
  return out.slice(0, MAX_HINTS_PER_PROTO);
}

/**
 * 查询 method_stat 中待挖的行（供 DB 层调用）。
 *
 * 有意**只读 method_stat**，绝不 JOIN hint——见文件头红线 1。
 */
export const MINE_SQL = `
SELECT host, proto, method, ok, fail, last_kind, last_ts
  FROM method_stat
 WHERE last_ts >= ?
 ORDER BY last_ts DESC
 LIMIT ?`;