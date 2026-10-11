// 鉴权。传输层重写后只剩两处需要鉴权：
//
//	1. 建连时的 HELLO —— 校验 ts 窗口 + HMAC。签名串只有 ts 一个字段：
//	   auth = hex(HMAC-SHA256(sha256("satel/v1/"+PASSWORD), String(ts)))[0:32]
//	   路径不参与签名：帧走 WebSocket，端点只有一个，没有多版本要区分。
//	2. EVOLVE 帧里的管理员密钥 —— 与口令独立的共享密钥。
//
// 后续帧不再签名：连接本身在 TLS(ECH) 之内，能拿到明文帧的人本就能终止 TLS。

import { sha256Bytes, toHex } from "./canonical.js";

const textEncoder = new TextEncoder();

/** ts 允许的偏移，单位秒。防重放，成本为零。 */
export const MAX_SKEW_SECONDS = 300;

/** 口令派生密钥。与 Go 侧 coord.New 的 key 派生保持一致。 */
export async function deriveKey(password) {
  return sha256Bytes("satel/v1/" + String(password));
}

/** 全小写 hex 的 HMAC-SHA256。 */
export async function hmacHex(key, message) {
  const k = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", k, textEncoder.encode(message));
  return toHex(new Uint8Array(sig));
}

/** 常量时间比较，长度不同直接失败。 */
export function constantTimeEqual(a, b) {
  const ab = typeof a === "string" ? textEncoder.encode(a) : a;
  const bb = typeof b === "string" ? textEncoder.encode(b) : b;
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

/**
 * 校验 HELLO：ts 在窗口内，且 HMAC 与客户端送来的 auth 一致。
 * 口令为空时一律拒绝——否则未配置的协调端会变成谁都能连的开放中继。
 * `now` 是 unix 秒（测试可注入）。
 */
export async function verifyHello(ts, auth, password, now) {
  if (!password) return false;
  if (typeof ts !== "number" || !Number.isFinite(ts)) return false;
  const nowSec = now === undefined ? Math.floor(Date.now() / 1000) : now;
  if (Math.abs(nowSec - ts) > MAX_SKEW_SECONDS) return false;

  const key = await deriveKey(password);
  const expected = (await hmacHex(key, String(ts))).slice(0, 32);
  return constantTimeEqual(expected, String(auth ?? ""));
}

/** 管理员密钥常量时间比较（EVOLVE 帧用）。 */
export function verifyAdmin(provided, adminKey) {
  if (!adminKey || typeof provided !== "string") return false;
  return constantTimeEqual(provided.trim(), String(adminKey));
}