// / —— 协调端唯一的 WebSocket 端点。
//
// 建连鉴权一次：首帧必须是 HELLO，校验 ts 窗口与 HMAC，通过后受理后续帧。
// 后续帧不再签名——连接本身在 TLS(ECH) 之内，能拿到明文帧的人本就能终止 TLS。
//
// 控制面（BUNDLE/REPORT/EVOLVE）与隧道面（OPEN/DATA/CLOSE）共用这一条 WS：
// 前者按 reqID 查 pending，后者按 streamID 查 sockets。
import { verifyAdmin, verifyHello } from "./auth.js";
import {
  BUNDLE_SCAN_LIMIT,
  DEFAULT_BUNDLE_N,
  MAX_BUNDLE_N,
  MAX_HINTS,
  OP,
  OPEN,
  STATUS,
  STREAM_BUFFER_LIMIT,
  decodeBundle,
  decodeEvolve,
  decodeFrame,
  decodeHello,
  decodeOpen,
  decodeReport,
  encodeBundleResp,
  encodeFrame,
  encodeOpened,
  encodeStatus,
  encodeU32s,
} from "./frame.js";
import {
  countActive,
  insertStrategies,
  listAllStrategies,
  listHints,
  listPool,
  maxGeneration,
  prune,
  pruneHints,
  recordReport,
  replaceHints,
  retireStrategies,
} from "./d1.js";
import { evolve } from "./evolution.js";
import {
  MINE_MAX_AGE_SECONDS,
  MINE_ROW_LIMIT,
  MINE_SQL,
  MAX_HINTS_PER_PROTO,
  mineHints,
} from "./hints.js";
import { ValidationError, validateItem } from "./validate.js";

// --- 目标白名单 ------------------------------------------------------------

const HOST_RE = /^[A-Za-z0-9._-]{1,253}$/;
const BLOCKED_V4 = [
  /^10\./, /^127\./, /^169\.254\./, /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./, /^0\./, /^22[4-9]\./, /^2[3-5][0-9]\./,
];

export function hostAllowed(host) {
  if (host.includes(":")) return false; // IPv6 字面量不走这条
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    return !BLOCKED_V4.some((re) => re.test(host));
  }
  return HOST_RE.test(host);
}

/**
 * 策略用到的 op 是否全在 caps 内。供下发过滤与演化共用。
 * 直接扫 canonical 字符串——过滤不需要把每条策略都 parse 一遍。
 */
export function opsAllowed(spec, caps) {
  if (!caps) return true;
  try {
    const s = String(spec);
    if (!s.includes("|")) return true;
    for (const tok of s.split("|").slice(1)) {
      const i = tok.indexOf("(");
      const name = (i < 0 ? tok : tok.slice(0, i)).trim();
      if (!caps.has(name)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

// --- 演化（EVOLVE 帧与 cron 共用）----------------------------------------

export function tuning(env) {
  const int = (v, d) => (Number.isInteger(v) ? v : d);
  return {
    poolMax: int(Number.parseInt(env.POOL_MAX, 10), 48),
    topK: int(Number.parseInt(env.TOP_K, 10), 8),
  };
}

/** 参与演化的客户端群支持哪些招法。缺失 = 不限制。 */
export function fleetCaps(env) {
  if (typeof env.CAPS !== "string" || env.CAPS.trim() === "") return null;
  const set = new Set(env.CAPS.split(",").map((s) => s.trim()).filter(Boolean));
  return set.size === 0 ? null : set;
}

export async function runGeneration(env) {
  const { poolMax, topK } = tuning(env);
  const rows = await listAllStrategies(env.DB);
  const result = await evolve({
    strategies: rows,
    now: Date.now(),
    rand: Math.random,
    poolMax,
    topK,
    caps: fleetCaps(env),
  });
  await insertStrategies(env.DB, result.born);
  await retireStrategies(env.DB, result.retired);
  return {
    generation: result.generation,
    born: result.born.length,
    retired: result.retired.length,
    pool: await countActive(env.DB),
  };
}

// --- 隧道 -----------------------------------------------------------------

/** streams 的值是 { sock, writer }。writer 只能取一次，所以要缓存起来复用。 */
async function openStream(ws, streamID, host, port) {
  if (!hostAllowed(host) || port < 1 || port > 65535 || port === 25) {
    ws.send(encodeFrame(OP.OPENED, streamID, encodeOpened(OPEN.FAIL)));
    return null;
  }
  let sock = null;
  try {
    const { connect } = await import("cloudflare:sockets");
    sock = connect({ hostname: host, port });
  } catch (e) {
    sock = null;
  }
  if (!sock) {
    ws.send(encodeFrame(OP.OPENED, streamID, encodeOpened(OPEN.FAIL)));
    return null;
  }
  ws.send(encodeFrame(OP.OPENED, streamID, encodeOpened(OPEN.OK)));
  // 必须在 connect() 的同一时刻就锁定 readable：Workers 的 socket 若稍后才被读取
  // 会被平台关闭，表现是客户端立刻收到 CLOSE / EOF。
  return { sock, writer: sock.writable.getWriter(), reader: sock.readable.getReader() };
}

async function pumpToClient(ws, streamID, entry) {
  const reader = entry.reader;
  let reason = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) { reason = reason || "上游关闭"; break; }
      // 背压：积压过多就停止读 socket，等客户端把数据取走再继续
      let waited = 0;
      while (ws.bufferedAmount > STREAM_BUFFER_LIMIT && waited < 5000) {
        await new Promise((r) => setTimeout(r, 5));
        waited += 5;
      }
      ws.send(encodeFrame(OP.DATA, streamID, new Uint8Array(value)));
    }
  } catch (e) {
    reason = String(e && e.message ? e.message : e);
  }
  try { reader.releaseLock(); } catch { /* 已释放 */ }
  // CLOSE 帧的 payload 带失败原因，客户端据此报错——隧道失败在服务端可见，
  // 否则客户端只看到一个没有线索的 EOF。
  const body = new TextEncoder().encode(reason);
  try { ws.send(encodeFrame(OP.CLOSE, streamID, body)); } catch { /* 已关 */ }
}

// --- 帧分派 ---------------------------------------------------------------

function sendFrame(ws, op, id, payload) {
  try {
    ws.send(encodeFrame(op, id, payload));
  } catch {
    // 发送失败通常意味着连接已关，交给 close 清理。
  }
}

/**
 * 重挖 hint 并写库。**在整批回报入账后调用一次**，不是每一条调用一次。
 *
 * 为什么必须批量：挖掘要扫 method_stat 再聚合成后缀结论，按条触发等于每条回报
 * 都付一次全表扫描；而"刚收到的那一条"通常也不足以把某个后缀顶过 MIN_HOSTS，
 * 挖出来也是空。合并到批次边界上，扫描次数从 N 降到 1。
 *
 * proto 列表由本批回报的条目决定——没出现过的 proto 不值得为它扫一遍。
 */
async function rebuildHintsFor(db, items, now) {
  const protos = new Set(items.map((it) => it.proto));
  for (const proto of protos) {
    const rows = await db
      .prepare(MINE_SQL)
      .bind(now - MINE_MAX_AGE_SECONDS, MINE_ROW_LIMIT)
      .all();
    const mined = mineHints(rows.results ?? rows ?? [], { now, proto });
    await replaceHints(db, proto, mined.slice(0, MAX_HINTS_PER_PROTO), now);
  }
}

/**
 * 当前 unix 秒。`ctx.now` 是一个返回 unix **毫秒** 的函数（与 Date.now 同单位），
 * 这里统一折算成秒；不注入时用真实墙钟。注入它是为了让 hint 的 expires 判定在离线
 * 测试里可复现——测试的固定时间基准与真实墙钟差好几个月，不折算的话 expires
 * 比较永远走不到预期分支。
 */
function nowOf(ctx) {
  return ctx && typeof ctx.now === "function"
    ? Math.floor(ctx.now() / 1000)
    : Math.floor(Date.now() / 1000);
}

/**
 * 分派一条已解码的帧。
 *
 * 导出是为了离线测试：连接层需要 WebSocketPair（Node 里没有），但分派逻辑本身
 * 与传输无关，可以用一个只实现 send/close 的假 WS 直接喂帧。Go 侧 client_test
 * 用真实 WS 服务端覆盖传输层，两边合起来覆盖完整链路。
 */
export async function handleFrame(ws, ctx, raw) {
  let f;
  try {
    f = decodeFrame(raw);
  } catch {
    return;
  }
  const { env } = ctx;
  try {
    switch (f.op) {
      case OP.BUNDLE: {
        const { proto, n } = decodeBundle(f.data);
        if (proto !== "tls" && proto !== "http") {
          sendFrame(ws, OP.STATUS, f.id, encodeStatus(STATUS.BAD_PARAM, "proto"));
          return;
        }
        const want = Math.min(MAX_BUNDLE_N, Math.max(1, n || DEFAULT_BUNDLE_N));
        const version = await maxGeneration(env.DB);
        const rows = await listPool(env.DB, { proto, limit: BUNDLE_SCAN_LIMIT });
        const caps = ctx.caps ?? fleetCaps(env);
        const items = (caps ? rows.filter((r) => opsAllowed(r.spec, caps)) : rows)
          .slice(0, want)
          .map((r) => ({ id: r.id, spec: r.spec }));
        // hint 跟着同一个 proto 一起下发：客户端在新主机上还没有任何观测时，
        // 这份后缀级先验就是它排初始阶梯的唯一依据。
        const hints = await listHints(env.DB, proto, MAX_HINTS, nowOf(ctx));
        sendFrame(ws, OP.BUNDLE_RESP, f.id, encodeBundleResp(version, items, hints));
        return;
      }
      case OP.REPORT: {
        const { batchID, items: raw } = decodeReport(f.data);
        const now = nowOf(ctx);
        // 语义校验：一条不过就整批拒。宁可让客户端重试，也不让"格式对但内容有害"
        // 的主机名/方法名/类别进统计——掺进去的坏数据会一直在 Beta 后验里，
        // 而且它会污染同 (host, proto, method) 的所有后续累加，事后无法分辨。
        const items = raw.map((e) =>
          validateItem({
            host: e.host,
            method: e.method,
            proto: e.proto,
            kind: e.kind,
            ok: e.ok,
            unsup: e.unsup,
            rtt_ms: e.rtt_ms,
            ts: e.ts || now,
          }),
        );
        const r = await recordReport(env.DB, items, batchID, ctx.fp, now);
        // 重放的批次不再挖 hint：observations 早已在上次入账，再挖只会把同一批
        // 证据反复塞进同一个 TTL 窗口。
        if (!r.duplicate) await rebuildHintsFor(env.DB, items, now);
        sendFrame(ws, OP.REPORT_RESP, f.id, encodeU32s(r.accepted, 0, 0, 0));
        return;
      }
      case OP.EVOLVE: {
        const key = decodeEvolve(f.data);
        if (!verifyAdmin(key, env.ADMIN_KEY)) {
          sendFrame(ws, OP.STATUS, f.id, encodeStatus(STATUS.AUTH_FAIL, "admin"));
          return;
        }
        const r = await runGeneration(env);
        sendFrame(ws, OP.EVOLVE_RESP, f.id, encodeU32s(r.generation, r.born, r.retired, r.pool));
        return;
      }
      case OP.OPEN: {
        const { host, port } = decodeOpen(f.data);
        const entry = await openStream(ws, f.id, host, port);
        if (entry) {
          ctx.streams.set(f.id, entry);
          pumpToClient(ws, f.id, entry);
        }
        return;
      }
      case OP.DATA: {
        const entry = ctx.streams.get(f.id);
        if (!entry) return;
        await entry.writer.write(f.data);
        return;
      }
      case OP.CLOSE: {
        const entry = ctx.streams.get(f.id);
        if (entry) {
          ctx.streams.delete(f.id);
          try { await entry.writer.close(); } catch { /* 已关 */ }
        }
        return;
      }
      default:
        return;
    }
  } catch (err) {
    // 帧解码失败或后端异常：回一个 STATUS，让客户端知道这次调用没成。静默丢帧
    // 会让上层永远等在 pending 上。
    if (f.op !== OP.DATA && f.op !== OP.CLOSE) {
      const msg = String(err?.message ?? "bad frame").slice(0, 120);
      sendFrame(ws, OP.STATUS, f.id, encodeStatus(STATUS.BAD_PARAM, msg));
    }
  }
}

// --- 连接 -----------------------------------------------------------------

export async function handleWebSocket(request, env) {
  if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
    return new Response(null, { status: 400 });
  }
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();

  const ctx = { env, fp: null, caps: null, streams: new Map(), hello: false };

  const cleanup = () => {
    for (const [id, entry] of ctx.streams) {
      ctx.streams.delete(id);
      try { entry.writer.close(); } catch { /* 已关 */ }
    }
  };
  server.addEventListener("close", cleanup);
  server.addEventListener("error", cleanup);

  // **按连接串行处理帧**。Workers 为每条 message 事件各起一个异步回调，若直接
  // await 处理，多个 DATA 帧会被并发处理并可能乱序写入 socket——隧道里跑 TLS 时
  // 表现为 record 错位 / bad record MAC（:80 一次性请求看不出，:443 多轮握手必现）。
  ctx.chain = Promise.resolve();
  server.addEventListener("message", (ev) => {
    if (typeof ev.data === "string") return; // 只要二进制帧
    const raw = new Uint8Array(ev.data);
    ctx.chain = ctx.chain.then(() => (async () => {
      if (ctx.hello) {
        await handleFrame(server, ctx, raw);
        return;
      }
      let hello;
      try {
        const f = decodeFrame(raw);
        if (f.op !== OP.HELLO) throw new Error("首帧不是 HELLO");
        hello = decodeHello(f.data);
      } catch {
        try { server.close(1008, "hello required"); } catch { /* 已关 */ }
        return;
      }
      if (!(await verifyHello(hello.ts, hello.auth, env.PASSWORD))) {
        try { server.close(1008, "auth failed"); } catch { /* 已关 */ }
        return;
      }
      ctx.hello = true;
      ctx.fp = hello.fp;
      ctx.caps = hello.caps && hello.caps.length ? new Set(hello.caps) : null;
      sendFrame(server, OP.STATUS, 0, encodeStatus(STATUS.OK));
    })().catch(() => { /* 已在内部处理 */ }));
  });

  return new Response(null, { status: 101, webSocket: client });
}

/** cron：演化一代 + 剪枝。 */
export async function scheduled(env) {
  await runGeneration(env);
  await prune(env.DB, Math.floor(Date.now() / 1000));
}