// Canonicalization + id tests. Offline only: no network, no D1.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  CanonicalError,
  OPS,
  canonicalize,
  filterByCaps,
  opsOf,
  parseCaps,
  parseSpecString,
  parseStrategy,
  sha256Hex,
  strategyId,
} from "../src/canonical.js";

/** Independent reference id, computed with node:crypto. */
function refId(spec) {
  return createHash("sha256").update(spec, "utf8").digest("hex").slice(0, 8);
}

// Golden ids supplied by the Go client implementation — the two sides MUST
// agree on these byte-for-byte.
const GOLDEN = [
  ["tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)", "15c0e805"],
  ["tls|tlsrf(chunk=8,delay_ms=8,limit=400)", "78c3d41b"],
  ["tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)|oob(byte=0)", "b98c567b"],
  ["tls|split(at=sni,count=4,delay_ms=24,len=1,pos=0)", "0352f73e"],
  ["http|hostsplit(gap=1)", "393db486"],
  ["http|case(seed=0)|hostsplit(gap=1)", "a50096b8"],
  ["http|hostsplit(gap=1)|case(seed=1234)", "713ce104"],
];

test("golden ids match the Go client (and node:crypto)", async () => {
  for (const [spec, id] of GOLDEN) {
    assert.equal(refId(spec), id, `node sha256 sanity: ${spec}`);
    assert.equal(await strategyId(spec), id, `worker id: ${spec}`);
  }
});

test("sha256 is over UTF-8 bytes, no trailing newline", async () => {
  assert.equal(
    await sha256Hex(""),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
  assert.equal(await sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("canonical examples are already canonical", () => {
  for (const [spec] of GOLDEN) assert.equal(canonicalize(spec), spec);
});

test("object form fills defaults", () => {
  assert.equal(
    canonicalize({ proto: "tls", ops: [{ op: "split" }, { op: "oob" }] }),
    "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)|oob(byte=0)",
  );
  // Partial params are completed with defaults too; op order follows the input.
  assert.equal(
    canonicalize({ proto: "http", ops: [{ op: "case", seed: 1234 }, { op: "hostsplit" }] }),
    "http|case(seed=1234)|hostsplit(gap=1)",
  );
});

test("params are sorted by key (ASCII ascending), ops are NOT sorted", () => {
  // unsorted params get sorted
  assert.equal(
    canonicalize("tls|split(pos=1,at=sni)"),
    "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)",
  );
  // op order is preserved
  assert.equal(
    canonicalize("tls|oob(byte=0)|split(at=sni,count=2,delay_ms=8,len=1,pos=1)"),
    "tls|oob(byte=0)|split(at=sni,count=2,delay_ms=8,len=1,pos=1)",
  );
});

test("fake params sort badseq before badsum (ASCII)", () => {
  assert.equal(
    canonicalize({ proto: "tls", ops: [{ op: "fake" }] }),
    "tls|fake(badseq=1,badsum=1,count=1,delay_ms=0,len=64,ttl=3)",
  );
});

test("bool params render as 1/0", () => {
  assert.equal(
    canonicalize({ proto: "tls", ops: [{ op: "fake", badsum: false, badseq: true }] }),
    "tls|fake(badseq=1,badsum=0,count=1,delay_ms=0,len=64,ttl=3)",
  );
  // The Go client also accepts true/false literals; canonical output is still 1/0.
  assert.equal(
    canonicalize("tls|fake(badsum=true,badseq=false)"),
    "tls|fake(badseq=0,badsum=1,count=1,delay_ms=0,len=64,ttl=3)",
  );
});

test("id stability: same spec -> same id, different spec -> different id", async () => {
  const a1 = await strategyId("tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)");
  const a2 = await strategyId({ proto: "tls", ops: [{ op: "split" }] }); // default-filled
  assert.equal(a1, a2);

  const b = await strategyId("tls|split(at=sni,count=2,delay_ms=8,len=1,pos=2)");
  assert.notEqual(a1, b);

  // op order matters for the id
  const c1 = await strategyId("tls|oob(byte=0)|split(at=sni,count=2,delay_ms=8,len=1,pos=1)");
  const c2 = await strategyId("tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)|oob(byte=0)");
  assert.notEqual(c1, c2);

  assert.match(a1, /^[0-9a-f]{8}$/);
});

test("unknown ops are rejected", () => {
  assert.throws(() => canonicalize("tls|bogus(x=1)"), CanonicalError);
  assert.throws(() => canonicalize({ proto: "tls", ops: [{ op: "nope" }] }), CanonicalError);
  assert.throws(() => parseSpecString("tls|split(at=sni)|bogus"), CanonicalError);
});

test("unknown params are rejected", () => {
  assert.throws(() => canonicalize("tls|split(wat=1)"), CanonicalError);
  assert.throws(() => canonicalize({ proto: "tls", ops: [{ op: "oob", nope: 1 }] }), CanonicalError);
});

test("wrong param types are rejected", () => {
  // int
  assert.throws(() => canonicalize("tls|split(pos=abc)"), CanonicalError);
  assert.throws(() => canonicalize("tls|split(pos=-1)"), CanonicalError);
  assert.throws(() => canonicalize("tls|split(pos=01)"), CanonicalError); // leading zero
  assert.throws(() => canonicalize("tls|split(pos=1.5)"), CanonicalError);
  assert.throws(() => canonicalize({ proto: "tls", ops: [{ op: "split", pos: 1.5 }] }), CanonicalError);
  // bool
  assert.throws(() => canonicalize("tls|fake(badsum=yes)"), CanonicalError);
  assert.throws(() => canonicalize("tls|fake(badsum=2)"), CanonicalError);
  assert.throws(() => canonicalize({ proto: "tls", ops: [{ op: "fake", badsum: 2 }] }), CanonicalError);
  // str must be a string and must not contain , ( ) = |
  assert.throws(() => canonicalize({ proto: "tls", ops: [{ op: "split", at: 5 }] }), CanonicalError);
  assert.throws(() => canonicalize({ proto: "tls", ops: [{ op: "split", at: "a|b" }] }), CanonicalError);
  assert.throws(() => canonicalize({ proto: "tls", ops: [{ op: "split", at: "a,b" }] }), CanonicalError);
});

test("invalid proto / malformed specs are rejected", () => {
  assert.throws(() => canonicalize("quic|split"), CanonicalError);
  assert.throws(() => canonicalize({ proto: "ftp", ops: [{ op: "split" }] }), CanonicalError);
  assert.throws(() => canonicalize("tls|"), CanonicalError);
  assert.throws(() => canonicalize({ proto: "tls", ops: "nope" }), CanonicalError);
  // The Go client rejects a strategy with no ops; match it.
  assert.throws(() => canonicalize("tls"), CanonicalError);
  assert.throws(() => canonicalize({ proto: "tls", ops: [] }), CanonicalError);
});

test("round-trip parse -> canonical -> parse is stable", () => {
  const inputs = [
    "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)",
    "tls|tlsrf(chunk=8,delay_ms=8,limit=400)",
    "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)|oob(byte=0)",
    "tls|split(at=sni,count=4,delay_ms=24,len=1,pos=0)",
    "http|hostsplit(gap=1)|case(seed=1234)",
    "tls|fake(badseq=1,badsum=1,count=1,delay_ms=0,len=64,ttl=3)",
    "tls|tlsrf(chunk=4,delay_ms=12,limit=200)|dup(count=1,delay_ms=0)",
    "http|disorder(gap_ms=0)|split(at=rand,count=8,delay_ms=200,len=64,pos=32)",
  ];
  for (const spec of inputs) {
    const c1 = canonicalize(spec);
    const parsed = parseSpecString(c1);
    const c2 = canonicalize(parsed);
    assert.equal(c2, c1, spec);
    // internal strategy shape survives a second round-trip
    assert.deepEqual(parseStrategy(c2), parseStrategy(c1));
  }
});

test("opsOf lists op names in order", () => {
  assert.deepEqual(opsOf("http|case(seed=0)|hostsplit(gap=1)"), ["case", "hostsplit"]);
  assert.deepEqual(opsOf("tls|fake(badseq=1,badsum=1,count=1,delay_ms=0,len=64,ttl=3)"), ["fake"]);
});

test("parseCaps: absent/blank -> null, otherwise a Set", () => {
  assert.equal(parseCaps(null), null);
  assert.equal(parseCaps(undefined), null);
  assert.equal(parseCaps(""), null);
  assert.deepEqual([...parseCaps("split,tlsrf,oob,hostsplit,case")], [
    "split",
    "tlsrf",
    "oob",
    "hostsplit",
    "case",
  ]);
  // whitespace and empty tokens tolerated
  assert.deepEqual([...parseCaps(" split , , tlsrf ")], ["split", "tlsrf"]);
});

test("filterByCaps drops strategies using unsupported (privileged) ops", () => {
  const rows = [
    { id: "a", spec: "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)" },
    { id: "b", spec: "tls|fake(badseq=1,badsum=1,count=1,delay_ms=0,len=64,ttl=3)" },
    { id: "c", spec: "tls|tlsrf(chunk=8,delay_ms=8,limit=400)" },
    { id: "d", spec: "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)|oob(byte=0)" },
  ];

  // absent caps -> everything
  assert.equal(filterByCaps(rows, null).length, 4);

  // portable client without fake/disorder/dup
  const caps = parseCaps("split,tlsrf,oob,hostsplit,case");
  const out = filterByCaps(rows, caps);
  assert.deepEqual(out.map((r) => r.id), ["a", "c", "d"]);

  // a strategy mixing a supported and an unsupported op is dropped entirely
  const mixed = [{ id: "m", spec: "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)|fake(badseq=1,badsum=1,count=1,delay_ms=0,len=64,ttl=3)" }];
  assert.equal(filterByCaps(mixed, caps).length, 0);
});

test("default table is intact for privileged ops", () => {
  // dup/fake/disorder stay valid op names (they are privileged, not removed).
  for (const name of ["dup", "fake", "disorder"]) assert.ok(OPS[name], name);
  assert.equal(OPS.fake.badsum.type, "bool");
  assert.equal(OPS.disorder.gap_ms.max, 50);
});
