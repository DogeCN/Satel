// Evolution algorithm tests. Offline only: no network, no D1.
import test from "node:test";
import assert from "node:assert/strict";

import { canonicalize, strategyId } from "../src/canonical.js";
import { SEED_SPECS, applyReport, evolve, scoreOf, seed, ucb1 } from "../src/evolution.js";

/** Small deterministic PRNG (mulberry32) for injected `rand`. */
function mulberry32(a) {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

async function assertValidRow(row, { gen, parents }) {
  assert.match(row.id, /^[0-9a-f]{8}$/);
  assert.equal(canonicalize(row.spec), row.spec, "born spec must be canonical");
  assert.equal(await strategyId(row.spec), row.id, "born id must match spec");
  assert.ok(row.proto === "tls" || row.proto === "http");
  assert.equal(row.gen, gen);
  assert.equal(row.retired, 0);
  assert.equal(row.trials, 0);
  assert.equal(row.wins, 0);
  if (parents) assert.ok(parents.has(row.parent), `parent ${row.parent} not in pool`);
}

// (a) empty pool seeds the 6 built-ins -------------------------------------

test("empty pool seeds 6 built-ins at gen 0", async () => {
  const res = await evolve({ strategies: [], poolMax: 48, topK: 8, rand: mulberry32(1) });

  assert.equal(res.generation, 0);
  assert.deepEqual(res.retired, []);
  assert.equal(res.born.length, 6);
  assert.deepEqual(
    res.born.map((r) => r.spec),
    SEED_SPECS,
  );

  const ids = new Set();
  for (const row of res.born) {
    await assertValidRow(row, { gen: 0, parents: null });
    assert.equal(row.parent, null);
    assert.ok(!ids.has(row.id), "seed ids must be unique");
    ids.add(row.id);
  }
});

test("built-in #4 is the corrected spec", async () => {
  assert.equal(SEED_SPECS[3], "tls|split(at=sni,count=4,delay_ms=24,len=1,pos=0)");
  const rows = await seed(48, 0);
  assert.equal(rows[3].id, "0352f73e");
  assert.equal(rows[0].id, "15c0e805");
  assert.equal(rows[2].id, "b98c567b");
});

test("seed() respects poolMax", async () => {
  const rows = await seed(3, 0);
  assert.equal(rows.length, 3);
});

// (b) scoring formula -------------------------------------------------------

test("score is the Beta(1,1) posterior mean", () => {
  assert.equal(scoreOf(0, 0), 0.5);
  assert.equal(scoreOf(3, 7), 4 / 9);
  assert.equal(scoreOf(0, 100), 1 / 102);
  assert.equal(scoreOf(10, 10), 11 / 12);
});

test("UCB1 adds an exploration bonus that shrinks with trials", () => {
  const n = 10;
  assert.ok(ucb1(0.5, 0, n) > ucb1(0.5, 100, n));
  assert.ok(ucb1(0.5, 5, n) > 0.5);
});

// (c) a deterministic generation -------------------------------------------

test("a generation produces valid canonical children with unique ids", async () => {
  const base = await seed(48, 1000);
  const strategies = base.map((r, i) => ({ ...r, trials: (i + 1) * 10, wins: i }));
  const parentIds = new Set(strategies.map((s) => s.id));

  const res = await evolve({ strategies, now: 2000, rand: mulberry32(12345), poolMax: 48, topK: 8 });

  assert.equal(res.generation, 1, "generation = maxGen + 1");
  assert.ok(res.born.length > 0, "at least one child");

  const bornIds = new Set();
  for (const row of res.born) {
    await assertValidRow(row, { gen: 1, parents: parentIds });
    assert.equal(row.created_at, 2000);
    assert.ok(!bornIds.has(row.id), "child ids unique within the batch");
    assert.ok(!parentIds.has(row.id), "child id must not already exist");
    bornIds.add(row.id);
  }

  // Input is not mutated.
  assert.ok(strategies.every((s) => s.retired === 0));
});

test("deterministic rand => deterministic output", async () => {
  const base = await seed(48, 5);
  const strategies = base.map((r, i) => ({ ...r, trials: 20, wins: i % 3 }));
  const a = await evolve({ strategies, now: 7, rand: mulberry32(99), poolMax: 48, topK: 6 });
  const b = await evolve({ strategies, now: 7, rand: mulberry32(99), poolMax: 48, topK: 6 });
  assert.deepEqual(a.born.map((r) => r.id), b.born.map((r) => r.id));
  assert.deepEqual(a.retired, b.retired);
});

// (d) pool cap --------------------------------------------------------------

test("pool cap retires the lowest-score strategies", async () => {
  const poolMax = 4;
  const base = await seed(48, 1); // 6 seeds
  // Distinct, known scores: wins = i, trials = 100  ->  ascending with i.
  const strategies = base.map((r, i) => ({ ...r, trials: 100, wins: i, gen: 0 }));

  const res = await evolve({ strategies, now: 2, rand: mulberry32(7), poolMax, topK: 2 });

  const totalActive = strategies.length + res.born.length;
  assert.ok(totalActive > poolMax, "precondition: pool exceeds the cap");

  const expectedRetired = [...strategies]
    .sort((a, b) => scoreOf(a.wins, a.trials) - scoreOf(b.wins, b.trials))
    .slice(0, totalActive - poolMax)
    .map((s) => s.id);

  assert.deepEqual(new Set(res.retired), new Set(expectedRetired));
  // The worst existing strategy (wins=0) is always retired here.
  assert.ok(res.retired.includes(strategies[0].id));

  // Non-retired count after applying the generation is exactly poolMax.
  const activeAfter =
    strategies.filter((s) => !s.retired).length - res.retired.length + res.born.length;
  assert.equal(activeAfter, poolMax);
});

test("no retirement when the pool stays under the cap", async () => {
  const base = await seed(48, 1);
  const strategies = base.map((r) => ({ ...r, trials: 1, wins: 1 }));
  const res = await evolve({ strategies, now: 1, rand: mulberry32(3), poolMax: 48, topK: 8 });
  assert.deepEqual(res.retired, []);
});

// (e) unsup reports never raise wins ---------------------------------------

test("unsup reports bump trials but never wins", () => {
  let s = { wins: 0, trials: 0, unsup: 0 };
  for (let i = 0; i < 50; i++) s = applyReport(s, { ok: 0, unsup: 1 });

  assert.equal(s.wins, 0);
  assert.equal(s.trials, 50);
  assert.equal(s.unsup, 50);
  assert.equal(s.score, scoreOf(0, 50));
  assert.ok(s.score < 0.5, "posterior mean stays below the prior");

  // A genuine success does raise wins.
  s = applyReport(s, { ok: 1, unsup: 0 });
  assert.equal(s.wins, 1);
  assert.equal(s.trials, 51);
  assert.equal(s.unsup, 50);

  // A plain failure raises trials only.
  s = applyReport(s, { ok: 0, unsup: 0 });
  assert.equal(s.wins, 1);
  assert.equal(s.trials, 52);
});

test("evolve recomputes score from wins/trials (stored score ignored)", async () => {
  const base = await seed(48, 1);
  const [rA, rB, rC] = base;
  const strategies = [
    { ...rA, score: 999, trials: 100, wins: 0 }, // real score ~0.01
    { ...rB, score: 0, trials: 50, wins: 50 }, // real score ~0.98
    { ...rC, score: 0, trials: 0, wins: 0 }, // real score 0.5
  ];

  const res = await evolve({ strategies, now: 1, rand: mulberry32(11), poolMax: 1, topK: 1 });

  assert.equal(res.retired.length, strategies.length + res.born.length - 1);
  assert.ok(res.retired.includes(rA.id), "low real scorer retired despite stored score 999");
  assert.ok(!res.retired.includes(rB.id), "high real scorer kept despite stored score 0");
});

test("caps keeps mutations inside the advertised op set", async () => {
  const caps = new Set(["split", "tlsrf", "oob", "hostsplit", "case"]);
  const base = await seed(48, 1);
  const strategies = base.map((r) => ({ ...r, trials: 20, wins: 10 }));

  // Many generations with a fresh RNG each time: privileged ops (fake, dup,
  // disorder) must never appear in a born spec when they are outside caps.
  for (let g = 0; g < 40; g++) {
    const res = await evolve({
      strategies,
      now: 1 + g,
      rand: mulberry32(100 + g),
      poolMax: 48,
      topK: 8,
      caps,
    });
    for (const row of res.born) {
      const ops = row.spec.split("|").slice(1).map((t) => t.slice(0, t.indexOf("(")));
      for (const op of ops) {
        assert.ok(caps.has(op), `born spec escaped caps: ${op} in ${row.spec}`);
      }
    }
  }
});

test("caps null still allows privileged ops to be discovered", async () => {
  const base = await seed(48, 1);
  let sawPrivileged = false;
  for (let g = 0; g < 60 && !sawPrivileged; g++) {
    const res = await evolve({
      strategies: base.map((r) => ({ ...r, trials: 5, wins: 2 })),
      now: 1,
      rand: mulberry32(500 + g),
      poolMax: 48,
      topK: 8,
    });
    for (const row of res.born) {
      if (/\|(fake|dup|disorder)\(/.test(row.spec)) sawPrivileged = true;
    }
  }
  assert.ok(sawPrivileged, "unrestricted evolution should be able to introduce privileged ops");
});
