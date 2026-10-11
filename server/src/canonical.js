// Satel protocol v1 — strategy canonicalization and id derivation.
//
// This file is the JS mirror of the Go client's canonicalizer (protocol.md
// sections 2.1–2.4). The two implementations are written independently and
// MUST agree byte-for-byte, because the strategy id is recomputed and verified
// on the client: any divergence shows up as "strategy id mismatch".
//
//   canonical = proto "|" op1 "|" op2 "|" ...          // ops in order, NOT sorted
//   op        = name "(" k1 "=" v1 "," k2 "=" v2 ")"    // params sorted by key, ASCII asc
//   int       = decimal, no leading zeros, non-negative
//   bool      = "1" | "0"
//   str       = as-is, must not contain , ( ) = |
//   id        = lowercase hex of sha256(canonical), first 8 chars
//
// Defaults are applied to every missing param BEFORE canonicalizing, so the
// canonical output always carries ALL params (including defaults) and there is
// never "two spellings of the same strategy".

const textEncoder = new TextEncoder();

/** Accepted protocol names. */
export const PROTOCOLS = ["tls", "http"];

/**
 * Per-op parameter table: type, default and (for the evolution loop) domain.
 *
 * `type`   — "int" | "bool" | "str" (the type the canonical form encodes).
 * `default`— value used when the param is absent.
 * `min`/`max` — inclusive domain for numeric params (protocol.md section 2.1).
 * `enum`   — allowed values for enum-like string params.
 *
 * NOTE: the canonicalizer itself only enforces TYPE and NAME validity (see the
 * task spec: "Param value types must match the default's type ... or it is an
 * error"). The min/max/enum metadata is consumed by src/evolution.js to keep
 * mutations inside the protocol's declared value domain.
 */
export const OPS = {
  split: {
    at: { type: "str", default: "sni", enum: ["sni", "host", "mid", "head", "rand"] },
    pos: { type: "int", default: 1, min: 0, max: 32 },
    len: { type: "int", default: 1, min: 1, max: 64 },
    count: { type: "int", default: 2, min: 2, max: 8 },
    delay_ms: { type: "int", default: 8, min: 0, max: 200 },
  },
  tlsrf: {
    chunk: { type: "int", default: 8, min: 1, max: 64 },
    limit: { type: "int", default: 400, min: 32, max: 2048 },
    delay_ms: { type: "int", default: 8, min: 0, max: 200 },
  },
  oob: {
    byte: { type: "int", default: 0, min: 0, max: 255 },
  },
  dup: {
    count: { type: "int", default: 1, min: 1, max: 4 },
    delay_ms: { type: "int", default: 0, min: 0, max: 200 },
  },
  hostsplit: {
    gap: { type: "int", default: 1, min: 1, max: 8 },
  },
  case: {
    seed: { type: "int", default: 0, min: 0, max: 65535 },
  },
  // `fake` / `disorder` are privileged (raw socket / driver backends). They are
  // still first-class in the canonical form.
  fake: {
    count: { type: "int", default: 1, min: 1, max: 4 },
    ttl: { type: "int", default: 3, min: 1, max: 64 },
    badsum: { type: "bool", default: true },
    badseq: { type: "bool", default: true },
    len: { type: "int", default: 64, min: 0, max: 1500 },
    delay_ms: { type: "int", default: 0, min: 0, max: 200 },
  },
  disorder: {
    gap_ms: { type: "int", default: 0, min: 0, max: 50 },
  },
};

/** Known op names, in table order. */
export const OP_NAMES = Object.keys(OPS);

/** Characters forbidden inside string param values. */
const FORBIDDEN_STR = /[,()=|]/;

/** Strict decimal integer: "0" or no leading zero, non-negative. */
const INT_RE = /^(0|[1-9][0-9]*)$/;

/** Op token: `name` or `name(params)`. */
const OP_TOKEN_RE = /^([A-Za-z0-9_]+)\s*(?:\(([\s\S]*)\))?$/;

export class CanonicalError extends Error {
  constructor(message) {
    super(message);
    this.name = "CanonicalError";
  }
}

function fail(msg) {
  throw new CanonicalError(msg);
}

function assertProto(proto) {
  if (typeof proto !== "string" || !PROTOCOLS.includes(proto)) {
    fail(`invalid proto: ${JSON.stringify(proto)}`);
  }
  return proto;
}

/**
 * Coerce and validate a single param value against its declared type.
 * Accepts already-typed values (object form) or strings (parsed spec form).
 */
function coerceValue(opName, key, raw) {
  const def = OPS[opName][key];
  if (!def) fail(`unknown param ${opName}.${key}`);

  switch (def.type) {
    case "int": {
      if (typeof raw === "number") {
        if (!Number.isInteger(raw)) fail(`${opName}.${key}: not an integer: ${raw}`);
        if (raw < 0) fail(`${opName}.${key}: negative not allowed: ${raw}`);
        return raw;
      }
      if (typeof raw === "string") {
        if (!INT_RE.test(raw)) fail(`${opName}.${key}: bad int literal: ${JSON.stringify(raw)}`);
        return Number(raw);
      }
      fail(`${opName}.${key}: expected int, got ${typeof raw}`);
      break;
    }
    case "bool": {
      if (typeof raw === "boolean") return raw;
      if (raw === 1 || raw === "1" || raw === "true") return true;
      if (raw === 0 || raw === "0" || raw === "false") return false;
      fail(`${opName}.${key}: expected bool (1|0), got ${JSON.stringify(raw)}`);
      break;
    }
    case "str": {
      if (typeof raw !== "string") fail(`${opName}.${key}: expected str, got ${typeof raw}`);
      if (FORBIDDEN_STR.test(raw)) fail(`${opName}.${key}: str contains forbidden char: ${raw}`);
      return raw;
    }
    default:
      fail(`${opName}.${key}: unknown param type ${def.type}`);
  }
  // unreachable
  return undefined;
}

/** Parse one op token (`name` or `name(k=v,...)`) from a canonical string. */
function parseOpToken(token) {
  const m = OP_TOKEN_RE.exec(token);
  if (!m) fail(`malformed op token: ${JSON.stringify(token)}`);
  const name = m[1];
  if (!OPS[name]) fail(`unknown op: ${name}`);

  const params = {};
  const body = m[2];
  if (body !== undefined && body !== "") {
    for (const pair of body.split(",")) {
      const eq = pair.indexOf("=");
      if (eq <= 0) fail(`malformed param in ${name}: ${JSON.stringify(pair)}`);
      const k = pair.slice(0, eq);
      const v = pair.slice(eq + 1);
      params[k] = coerceValue(name, k, v);
    }
  }
  return { op: name, params };
}

/**
 * Parse a canonical (or partial) spec string into `{proto, ops:[{op,params}]}`.
 * Missing params are NOT filled here — canonicalize() does that.
 */
export function parseSpecString(spec) {
  if (typeof spec !== "string") fail("spec must be a string");
  const parts = spec.split("|");
  const proto = assertProto(parts[0].trim());
  const ops = [];
  for (let i = 1; i < parts.length; i++) {
    const tok = parts[i].trim();
    if (tok === "") fail("empty op in spec");
    ops.push(parseOpToken(tok));
  }
  if (ops.length === 0) fail("strategy has no ops");
  return { proto, ops };
}

/**
 * Parse the object form `{proto, ops:[{op:"split", pos:2, ...}]}` into the same
 * internal shape. Any key besides `op` is treated as a param.
 */
export function parseSpecObject(obj) {
  if (!obj || typeof obj !== "object") fail("spec object required");
  const proto = assertProto(obj.proto);
  const rawOps = obj.ops === undefined ? [] : obj.ops;
  if (!Array.isArray(rawOps)) fail("ops must be an array");
  const ops = rawOps.map((o) => {
    if (!o || typeof o !== "object") fail("op entry must be an object");
    const { op, ...rest } = o;
    if (typeof op !== "string" || !OPS[op]) fail(`unknown op: ${JSON.stringify(op)}`);

    // Accept the internal shape `{op, params:{...}}` (produced by parseStrategy
    // and used by the evolution loop) in addition to the flat `{op, k:v}` form.
    let flat = rest;
    const keys = Object.keys(rest);
    if (keys.length === 1 && keys[0] === "params" && rest.params && typeof rest.params === "object") {
      flat = rest.params;
    }

    const params = {};
    for (const [k, v] of Object.entries(flat)) params[k] = coerceValue(op, k, v);
    return { op, params };
  });
  if (ops.length === 0) fail("strategy has no ops");
  return { proto, ops };
}

/** Fill every missing param with its default, returning a new strategy. */
export function fillDefaults(strategy) {
  const ops = strategy.ops.map(({ op, params }) => {
    const filled = {};
    for (const key of Object.keys(OPS[op])) {
      filled[key] = Object.prototype.hasOwnProperty.call(params, key)
        ? params[key]
        : OPS[op][key].default;
    }
    return { op, params: filled };
  });
  return { proto: strategy.proto, ops };
}

function formatValue(opName, key, value) {
  const def = OPS[opName][key];
  if (def.type === "bool") return value ? "1" : "0";
  if (def.type === "int") return String(value);
  return value;
}

/** Serialize a filled strategy to its canonical string. */
export function serialize(strategy) {
  const chunks = [strategy.proto];
  for (const { op, params } of strategy.ops) {
    const keys = Object.keys(params).sort(); // ASCII ascending
    const kv = keys.map((k) => `${k}=${formatValue(op, k, params[k])}`).join(",");
    chunks.push(`${op}(${kv})`);
  }
  return chunks.join("|");
}

/**
 * Canonicalize a spec given as a canonical string OR an object
 * `{proto, ops:[{op, ...params}]}`. Fills defaults, sorts params, validates.
 * Throws CanonicalError on unknown ops/params or type mismatches.
 */
export function canonicalize(input) {
  const parsed = typeof input === "string" ? parseSpecString(input) : parseSpecObject(input);
  return serialize(fillDefaults(parsed));
}

/** Parse (and default-fill) any accepted input into the internal strategy shape. */
export function parseStrategy(input) {
  const parsed = typeof input === "string" ? parseSpecString(input) : parseSpecObject(input);
  return fillDefaults(parsed);
}

// ---------------------------------------------------------------------------
// Hashing helpers (WebCrypto; available in Workers and Node >= 18).
// ---------------------------------------------------------------------------

export function toHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

/** SHA-256 of a string's UTF-8 bytes (or raw bytes) → Uint8Array(32). */
export async function sha256Bytes(data) {
  const bytes = typeof data === "string" ? textEncoder.encode(data) : data;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

/** Lowercase hex SHA-256 of a string's UTF-8 bytes. */
export async function sha256Hex(data) {
  return toHex(await sha256Bytes(data));
}

/** Strategy id = first 8 lowercase hex chars of sha256(canonical). */
export async function strategyId(input) {
  const canonical = canonicalize(input);
  const hex = await sha256Hex(canonical);
  return hex.slice(0, 8);
}

// ---------------------------------------------------------------------------
// Capability filtering for GET /v1/bundle.
//
// The client may advertise which ops its backend actually supports, e.g.
// `caps=split,tlsrf,oob,hostsplit,case`. Privileged ops (fake, disorder, dup)
// are omitted by portable clients. A strategy is returned only if EVERY one of
// its ops is in the advertised set. Absent (or empty) caps = all ops supported.
// ---------------------------------------------------------------------------

/** Op names present in a spec, in order. */
export function opsOf(input) {
  return parseStrategy(input).ops.map((o) => o.op);
}

/**
 * Parse the raw `caps` query value into a Set of op names.
 * Returns null when absent/blank (meaning "no restriction").
 */
export function parseCaps(raw) {
  if (raw === null || raw === undefined) return null;
  const set = new Set();
  for (const part of String(raw).split(",")) {
    const token = part.trim();
    if (token) set.add(token);
  }
  return set.size === 0 ? null : set;
}

/** True if a spec uses only ops contained in `caps` (null caps = allow all). */
export function specAllowed(spec, caps) {
  if (!caps) return true;
  return opsOf(spec).every((name) => caps.has(name));
}

/** Filter strategy rows (`{spec,...}`) by an advertised capability set. */
export function filterByCaps(strategies, caps) {
  if (!caps) return strategies;
  return strategies.filter((s) => specAllowed(s.spec, caps));
}
