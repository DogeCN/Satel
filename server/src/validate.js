// 回报条目的**语义**校验：主机名规范化、方法名、失败类别、协议名。
//
// 与 frame.js 的分工：frame.js 只管字节（长度前缀、上限、截断），这里是业务规则。
// 两者都要有——frame.js 防的是畸形帧，这里防的是"格式对但内容有害"的主机名。
//
// 主机名规范化（normalizeHost）是整个后缀挖掘的地基：method_stat 按 host 聚合，
// 大小写或尾点不同就会裂成两行，"某后缀在 5 个主机上赢过"就永远凑不齐 3 个。

/** 协议名。与 canonical.js 的 PROTOCOLS 一致。 */
export const PROTOCOLS = ["tls", "http"];

/**
 * 稳定的失败类别枚举。与 Go 侧 failkind.Key() 的 Key() 方法逐个对应。
 *
 * 这里是**协议契约**，不是展示文案：kind 会进 method_stat.last_kind、被挖 hint 时
 * 按类别过滤，改字面量就是改历史数据的可比性。展示文案在别处映射。
 */
export const KINDS = [
  "ok",
  "dialtimeout",
  "dialrefused",
  "reset",
  "readtimeout",
  "tlsalert",
  "write",
  "apply",
  "canceled",
  "other",
];

/** ok 为真时 kind 必须恰好是这个值——两者不一致说明客户端编码有 bug，不是数据。 */
export const KIND_OK = "ok";

/**
 * canceled 不产生负证据。
 *
 * 浏览器关标签页、用户切走、上层 ctx 取消——这些情况下"没连上"与封锁毫无关系，
 * 却和真正的复位/黑洞长得一模一样（都是 ok=0）。把它算作失败，等于让**用户行为**
 * 训练封锁模型：随机关几个页面就能把某个后缀的 @direct 成功率压到底，然后所有新
 * 主机都跳过直连——而真相只是用户手快。
 *
 * 与 failkind.Kind.IsEvidence() 严格对应（k != None && k != Canceled）。
 */
export function kindIsEvidence(kind) {
  return kind !== KIND_OK && kind !== "canceled";
}

/** 只有真正的观测（成功 + 非 canceled 的失败）才训练方法置信度。 */
export function kindTrains(kind) {
  return kind !== "canceled";
}

export class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
  }
}

function bad(msg) {
  throw new ValidationError(msg);
}

// --- 主机名 ----------------------------------------------------------------

/** DNS 标签：字母数字连字符，不以连字符开头/结尾。允许下划线（部分 SRV 名在用）。 */
const DNS_LABEL = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/;

/** IPv4：四段十进制，禁止前导零（"010" 会被某些栈当八进制，是真实的解析歧义源）。 */
const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** IPv6：整体文法。含 "::" 压缩与内嵌 IPv4 两种形式。 */
const V6 = /^(([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|([0-9a-f]{1,4}:){1,4}:(([0-9a-f]{1,4}:){0,1}[0-9a-f]{1,4}|:[0-9a-f]{1,4})|:((:[0-9a-f]{1,4}){0,1}[0-9a-f]{1,4}|:))$/;

/**
 * 判断字符串是否"可能含控制字符 / 空白 / 非 ASCII"。
 *
 * 主机名最终会进 D1 的 TEXT 列并被回下发到客户端，任何控制字符都是提示注入与
 * 日志伪造的原料（换行能把一条 outcome 伪装成两条）。DNS 名按定义就是 ASCII，
 * 所以非 ASCII 一律拒——不做 IDNA 转写，转写会让"看起来一样"的两个名字在不同
 * 路径下归一到不同键，破坏聚合。
 */
function hasForbiddenChars(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f || c > 0x7e) return true;
  }
  return false;
}

function isIPv4(s) {
  const m = V4.exec(s);
  if (!m) return false;
  for (let i = 1; i <= 4; i++) {
    const part = m[i];
    if (part.length > 1 && part[0] === "0") return false;
    const n = Number(part);
    if (n > 255) return false;
  }
  return true;
}

/**
 * 规范化主机名：小写、去尾点、校验形态。
 *
 * 接受 DNS 名、IPv4 字面量、IPv6 字面量。**IP 字面量照收不误**——它们进
 * method_stat 是合法的（"这个 IP 上 @direct 总是超时"是真结论），只是不参与
 * 后缀挖掘：IP 没有后缀，硬凑会造出 "0.1" 这种荒谬的"后缀"。
 *
 * @param {string} raw
 * @returns {string} 规范化后的主机名
 * @throws {ValidationError}
 */
export function normalizeHost(raw) {
  if (typeof raw !== "string") bad("主机名必须是字符串");
  if (raw === "") bad("主机名为空");
  if (hasForbiddenChars(raw)) bad("主机名含控制字符、空白或非 ASCII");
  if (raw.length > 254) bad("主机名过长");

  // 尾点（FQDN 的写法差异）必须去掉，否则 "a.com." 与 "a.com" 会裂成两行统计。
  let h = raw.toLowerCase();
  while (h.endsWith(".")) h = h.slice(0, -1);
  if (h === "") bad("主机名只有尾点");
  if (h.length > 253) bad("主机名过长");

  if (h.includes(":")) {
    // 只可能是 IPv6 字面量：上面已拒掉控制字符/空白，这里再确认文法。
    if (!V6.test(h)) bad("IPv6 字面量非法");
    if (h.length > 45) bad("IPv6 字面量过长");
    return h;
  }

  if (V4.test(h)) {
    if (!isIPv4(h)) bad("IPv4 字面量非法");
    return h;
  }

  const labels = h.split(".");
  if (labels.length < 2) bad("主机名不是完整域名");
  for (const label of labels) {
    if (label.length === 0) bad("主机名含空标签");
    if (label.length > 63) bad("DNS 标签超过 63 字节");
    if (!DNS_LABEL.test(label)) bad(`DNS 标签非法: ${JSON.stringify(label)}`);
  }
  // 纯数字 TLD 会和 IPv4 混淆（"1.2.3"），且不是合法公网命名。
  if (/^\d+$/.test(labels[labels.length - 1])) bad("顶级标签不能是纯数字");
  return h;
}

/** 主机名是不是 IP 字面量（不参与后缀挖掘）。 */
export function isIPLiteral(host) {
  return host.includes(":") || isIPv4(host);
}

// --- 方法名 ----------------------------------------------------------------

/**
 * 方法 ID：8 位小写十六进制策略 ID，或 "@" 前缀的伪方法。
 *
 * **只校验形态，不校验语义**——这不是白名单。目的是挡掉畸形与注入（控制字符、
 * 超长、非 ASCII），而不是限制客户端能报什么：客户端的候选池由本地 bundle 决定，
 * 协调端无权替它决定该有哪些方法。净化在上游 D1 写入时另做。
 */
const SID = /^[0-9a-f]{8}$/;
const PSEUDO = /^@[a-z0-9_]{1,31}$/;

export function normalizeMethod(raw) {
  if (typeof raw !== "string") bad("方法名必须是字符串");
  if (raw === "") bad("方法名为空");
  if (raw.length > 32) bad("方法名超过 32 字节");
  if (hasForbiddenChars(raw)) bad("方法名含控制字符、空白或非 ASCII");
  if (!SID.test(raw) && !PSEUDO.test(raw)) {
    bad(`方法名既不是 8 位 hex 策略 ID 也不是 @伪方法: ${JSON.stringify(raw)}`);
  }
  return raw;
}

/**
 * 策略方法（8 位 hex）还是伪方法。
 *
 * 演化器只更新策略的聚合计数器；伪方法（@direct/@ech/…）在 strategy 表里没有行，
 * 所以对它们执行 UPDATE 命中 0 行——这是设计，不是 bug：伪方法不参与策略演化。
 */
export function isStrategyMethod(method) {
  return SID.test(method);
}

// --- 协议 ------------------------------------------------------------------

export function normalizeProto(raw) {
  if (typeof raw !== "string") bad("协议名必须是字符串");
  if (!PROTOCOLS.includes(raw)) bad(`协议名非法: ${JSON.stringify(raw)}`);
  return raw;
}

export function normalizeKind(raw) {
  if (typeof raw !== "string") bad("失败类别必须是字符串");
  if (!KINDS.includes(raw)) bad(`失败类别不在稳定枚举内: ${JSON.stringify(raw)}`);
  return raw;
}

/** batchID：32 个小写十六进制 ASCII（客户端生成的幂等键）。 */
const BATCH_ID = /^[0-9a-f]{32}$/;

export function normalizeBatchID(raw) {
  if (typeof raw !== "string" || !BATCH_ID.test(raw)) {
    bad(`批次 ID 必须是 32 位小写 hex: ${JSON.stringify(raw)}`);
  }
  return raw;
}

/**
 * 校验并规范化一条回报条目。
 *
 * 一致性检查（ok 与 kind=="ok" 必须吻合）在这里做，因为它是**编码 bug 的信号**：
 * 两处表达同一件事，允许它们分歧就等于允许静默的错误数据进统计。一旦分歧，
 * 整批应当被拒，而不是猜一个。
 *
 * @returns {{host, method, proto, kind, ok, unsup, rtt_ms, ts,
 *            train:boolean, countsAsTrial:boolean, countsAsWin:boolean,
 *            countsAsUnsup:boolean}}
 */
export function validateItem(it) {
  const host = normalizeHost(it.host);
  const method = normalizeMethod(it.method);
  const proto = normalizeProto(it.proto);
  const kind = normalizeKind(it.kind);

  const ok = !!it.ok;
  if (ok !== (kind === KIND_OK)) {
    bad(`ok(${ok}) 与 kind(${JSON.stringify(kind)}) 不一致`);
  }
  const unsup = !!it.unsup;
  const rtt = Number(it.rtt_ms ?? 0);
  if (!Number.isInteger(rtt) || rtt < 0 || rtt > 0xffffffff) bad("rtt 非法");
  const ts = Number(it.ts ?? 0);
  if (!Number.isInteger(ts) || ts < 0) bad("ts 非法");

  // 训练集 = 真观测。canceled 不训练（见 kindIsEvidence 的说明）；unsup 表示这条
  // 策略根本没跑起来，同样不是观测——它只进策略的 trials/unsup 记账。
  const train = kindTrains(kind) && !unsup;
  return {
    host,
    method,
    proto,
    kind,
    ok,
    unsup,
    rtt_ms: rtt,
    ts,
    train,
    // **落库的计数增量**：整数，且 ok 与 fail 互斥（一次观测要么成要么败）。
    // 注意 ok 是布尔（进 JSON/frame），而 ok_inc/fail_inc 才是给 SQL 的整数增量——
    // 两者不是一回事，早先只给布尔时 SQL 会把 JSON 里的 ok 当布尔读，
    // method_stat.fail 直接 NOT NULL 违约。
    ok_inc: train && ok ? 1 : 0,
    fail_inc: train && !ok ? 1 : 0,
    // 策略记账：unsup 计入 trials 但绝不计 win；canceled 两样都不计——它连
    // 一次完整的尝试都不是，不该消耗策略的试验预算。
    countsAsTrial: unsup || train,
    countsAsWin: train && ok,
    countsAsUnsup: unsup,
  };
}