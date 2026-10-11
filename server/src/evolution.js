// Satel protocol v1 — strategy evolution (protocol.md section 6).
//
// The core routine is a pure-ish async function:
//
//   evolve({ strategies, now, rand, poolMax, topK }) ->
//       { born: [strategyRow], retired: [id], generation }
//
// It takes the current strategy rows as input and returns the new rows to
// insert plus the ids to retire. It performs NO I/O, so it is fully unit
// testable with an injected deterministic `rand`.
//
// Only `strategyId()` needs async (WebCrypto sha256), hence the async signature.
//
// Scoring (spec 6.1):   score = (wins + 1) / (trials + 2)   [Beta(1,1) mean]
// Selection (spec 6.2): UCB1 = score + sqrt(2·ln(N) / max(trials,1)), top K
// unsup reports increment `trials` (and `unsup`) but never `wins`.

import { OPS, OP_NAMES, canonicalize, parseStrategy, strategyId } from "./canonical.js";

/** The 6 built-in strategies (protocol.md section 2.4), in fallback order. */
export const SEED_SPECS = [
  "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)",
  "tls|tlsrf(chunk=8,delay_ms=8,limit=400)",
  "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)|oob(byte=0)",
  "tls|split(at=sni,count=4,delay_ms=24,len=1,pos=0)",
  "http|hostsplit(gap=1)",
  "http|case(seed=0)|hostsplit(gap=1)",
];

/** Beta(1,1) posterior mean used as the strategy score. */
export function scoreOf(wins, trials) {
  return (wins + 1) / (trials + 2);
}

/** UCB1 exploration term; `n` is the size of the active pool. */
export function ucb1(score, trials, n) {
  return score + Math.sqrt((2 * Math.log(Math.max(n, 1))) / Math.max(trials, 1));
}

/**
 * Apply one report item to a strategy's counters (pure).
 * unsup items bump trials+unsup only; wins is never raised by them.
 */
export function applyReport(strategy, item) {
  const s = { ...strategy };
  s.trials = (s.trials ?? 0) + 1;
  if (item.unsup) {
    s.unsup = (s.unsup ?? 0) + 1;
  } else if (item.ok) {
    s.wins = (s.wins ?? 0) + 1;
  }
  s.score = scoreOf(s.wins ?? 0, s.trials ?? 0);
  return s;
}

/** Build a default-filled op entry for a given op name. */
function defaultOp(name) {
  const params = {};
  for (const [k, def] of Object.entries(OPS[name])) params[k] = def.default;
  return { op: name, params };
}

/** True if `name` is within the advertised capability set (null = everything). */
function opAllowed(name, allowed) {
  return !allowed || allowed.has(name);
}

/** Normalize a caps argument (array | Set | null) into a Set or null. */
function normalizeCaps(caps) {
  if (!caps) return null;
  const set = caps instanceof Set ? caps : new Set(caps);
  return set.size === 0 ? null : set;
}

function pickIndex(rand, n) {
  return Math.min(n - 1, Math.floor(rand() * n));
}

/** `param` mutation: nudge one random numeric param inside its domain. */
function mutateParam(strategy, rand) {
  const slots = [];
  strategy.ops.forEach((o, oi) => {
    for (const [k, def] of Object.entries(OPS[o.op])) {
      if (def.type === "int") slots.push({ oi, k, def });
    }
  });
  if (slots.length === 0) return false;
  const { oi, k, def } = slots[pickIndex(rand, slots.length)];
  const cur = strategy.ops[oi].params[k];
  const span = def.max - def.min;
  const maxDelta = Math.max(1, Math.ceil(span / 2));
  let delta = Math.round((rand() * 2 - 1) * maxDelta);
  if (delta === 0) delta = rand() < 0.5 ? 1 : -1;
  let next = cur + delta;
  if (next < def.min || next > def.max) {
    next = cur - delta; // bounce off the boundary
  }
  if (next < def.min) next = def.min;
  if (next > def.max) next = def.max;
  if (next === cur) return false;
  strategy.ops[oi].params[k] = next;
  return true;
}

/** `toggle` mutation: add a random absent op, or remove one if >1 op. */
function mutateToggle(strategy, rand, allowed) {
  const present = new Set(strategy.ops.map((o) => o.op));
  const absent = OP_NAMES.filter((n) => !present.has(n) && opAllowed(n, allowed));
  const canRemove = strategy.ops.length > 1;
  const doRemove = canRemove && (absent.length === 0 || rand() < 0.5);
  if (doRemove) {
    strategy.ops.splice(pickIndex(rand, strategy.ops.length), 1);
    return true;
  }
  if (absent.length === 0) return false;
  strategy.ops.push(defaultOp(absent[pickIndex(rand, absent.length)]));
  return true;
}

/** `crossover` mutation: splice a contiguous run of a donor parent's ops in. */
function mutateCrossover(strategy, parents, rand, allowed) {
  if (!parents || parents.length === 0) return false;
  const donor = parents[pickIndex(rand, parents.length)];
  let donorOps;
  try {
    donorOps = parseStrategy(donor.spec).ops;
  } catch {
    return false;
  }
  if (donorOps.length === 0) return false;
  const start = pickIndex(rand, donorOps.length);
  const maxLen = donorOps.length - start;
  const len = 1 + pickIndex(rand, maxLen);
  const slice = donorOps
    .slice(start, start + len)
    .filter((o) => opAllowed(o.op, allowed))
    .map((o) => ({ op: o.op, params: { ...o.params } }));
  if (slice.length === 0) return false;
  const at = Math.floor(rand() * (strategy.ops.length + 1));
  strategy.ops.splice(at, 0, ...slice);
  return true;
}

/** `proto` mutation: flip tls <-> http. */
function mutateProto(strategy) {
  strategy.proto = strategy.proto === "tls" ? "http" : "tls";
  return true;
}

/** Pick 1–2 distinct operators; `proto` is low-probability (~0.1). */
function chooseOperators(rand) {
  const base = ["param", "toggle", "crossover"];
  const count = rand() < 0.5 ? 1 : 2;
  const chosen = new Set();
  for (let i = 0; i < count; i++) {
    if (rand() < 0.1) chosen.add("proto");
    else chosen.add(base[pickIndex(rand, base.length)]);
  }
  if (chosen.size === 0) chosen.add("param");
  return [...chosen];
}

/**
 * Seed rows for an empty database: the 6 built-ins at gen 0.
 * `poolMax` is accepted for symmetry with evolve() and caps the returned set.
 */
export async function seed(poolMax = 48, now = Date.now()) {
  const rows = [];
  for (const spec of SEED_SPECS.slice(0, Math.max(0, poolMax))) {
    const canonical = canonicalize(spec);
    const id = await strategyId(canonical);
    rows.push({
      id,
      spec: canonical,
      proto: canonical.split("|")[0],
      score: scoreOf(0, 0),
      trials: 0,
      wins: 0,
      unsup: 0,
      gen: 0,
      parent: null,
      created_at: now,
      retired: 0,
    });
  }
  return rows;
}

/**
 * Run one generation. See file header for the contract.
 *
 * @param {object}   opts
 * @param {object[]} opts.strategies  current rows (retired included)
 * @param {number}   [opts.now]       unix ms for created_at
 * @param {function} [opts.rand]      RNG in [0,1)
 * @param {number}   [opts.poolMax]   max non-retired strategies
 * @param {number}   [opts.topK]      number of parents
 * @param {Iterable} [opts.caps]      ops the fleet supports; mutations stay inside
 *                                    it so the pool is not filled with strategies
 *                                    that can never be delivered (null = all ops)
 */
export async function evolve({
  strategies = [],
  now = Date.now(),
  rand = Math.random,
  poolMax = 48,
  topK = 8,
  caps = null,
} = {}) {
  const allowed = normalizeCaps(caps);

  // Empty pool: bootstrap with the built-ins instead of evolving.
  if (!strategies || strategies.length === 0) {
    const born = await seed(poolMax, now);
    return { born, retired: [], generation: 0 };
  }

  const all = strategies.map((s) => ({ ...s }));
  const active = all.filter((s) => !s.retired);

  const maxGen = all.reduce((m, s) => Math.max(m, s.gen ?? 0), 0);
  const generation = maxGen + 1;

  // 1. Score every strategy from its counters.
  for (const s of all) s.score = scoreOf(s.wins ?? 0, s.trials ?? 0);

  const candidates = active.length > 0 ? active : all;
  const n = candidates.length;

  // 2. UCB1 selection, top K.
  const parents = candidates
    .map((s) => ({ s, ucb: ucb1(s.score, s.trials ?? 0, n) }))
    .sort((a, b) => b.ucb - a.ucb)
    .slice(0, Math.max(1, topK))
    .map((r) => r.s);

  // 3. Mutations -> children (one child per parent).
  const existingIds = new Set(all.map((s) => s.id));
  const born = [];
  for (const parent of parents) {
    let child;
    try {
      child = parseStrategy(parent.spec);
    } catch {
      continue;
    }
    for (const opName of chooseOperators(rand)) {
      try {
        if (opName === "param") mutateParam(child, rand);
        else if (opName === "toggle") mutateToggle(child, rand, allowed);
        else if (opName === "crossover") mutateCrossover(child, parents, rand, allowed);
        else if (opName === "proto") mutateProto(child);
      } catch {
        // A failed operator leaves the child as-is; still a valid strategy.
      }
    }

    let spec;
    let id;
    try {
      spec = canonicalize(child);
      id = await strategyId(spec);
    } catch {
      continue;
    }
    if (existingIds.has(id)) continue; // dedupe against the whole pool
    existingIds.add(id);
    born.push({
      id,
      spec,
      proto: child.proto,
      score: scoreOf(0, 0),
      trials: 0,
      wins: 0,
      unsup: 0,
      gen: generation,
      parent: parent.id,
      created_at: now,
      retired: 0,
    });
  }

  // 4. Pool cap: retire the lowest-score active strategies down to poolMax.
  const retired = [];
  const activeAfter = [...all, ...born].filter((s) => !s.retired);
  if (activeAfter.length > poolMax) {
    activeAfter.sort((a, b) => (a.score ?? 0) - (b.score ?? 0));
    const excess = activeAfter.length - poolMax;
    for (let i = 0; i < excess; i++) retired.push(activeAfter[i].id);
  }

  return { born, retired, generation };
}
