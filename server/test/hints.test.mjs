// 后缀 hint 挖掘的纯逻辑测试（不碰 DB）+ 与真实 method_stat 的集成测试。
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { makeD1 } from "./helpers/d1adapter.mjs";
import {
  MINE_MAX_AGE_SECONDS,
  MINE_ROW_LIMIT,
  MINE_SQL,
  MIN_HOSTS,
  MIN_OBSERVATIONS,
  MAX_HOST_WEIGHT,
  HINT_TTL_SECONDS,
  candidateSuffix,
  hostWeight,
  mineHints,
} from "../src/hints.js";
import { recordReport, replaceHints, listHints } from "../src/d1.js";
import { validateItem } from "../src/validate.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA = readFileSync(join(ROOT, "schema.sql"), "utf8");
const NOW = 1780000000;

// --- 后缀选取 --------------------------------------------------------------

test("candidateSuffix：只取 PSL 之下的一层，拒绝共享托管后缀", () => {
  // 可取
  assert.equal(candidateSuffix("www.api.example.com"), "api.example.com");
  assert.equal(candidateSuffix("a.b.c.example.co.uk"), "c.example.co.uk");
  assert.equal(candidateSuffix("deep.sub.t.co.uk"), "sub.t.co.uk");
  assert.equal(candidateSuffix("x.y.z.example.com"), "z.example.com");
  // 只有 2 标签 / 无可注册域之下的更长一层
  assert.equal(candidateSuffix("www.example.com"), null);
  assert.equal(candidateSuffix("api.example.com"), null);
  assert.equal(candidateSuffix("test.org.uk"), null);
  assert.equal(candidateSuffix("a.b.co.uk"), null);
  assert.equal(candidateSuffix("zh.wikipedia.org"), null);
  // **共享托管后缀必须拒**（PSL 私有段把它们列为公共后缀）
  assert.equal(candidateSuffix("user.github.io"), null);
  assert.equal(candidateSuffix("foo.bar.github.io"), null);
  assert.equal(candidateSuffix("x.blogspot.com"), null);
  assert.equal(candidateSuffix("sub.weebly.com"), null);
  assert.equal(candidateSuffix("a.b.appspot.com"), null);
  assert.equal(candidateSuffix("a.herokuapp.com"), null);
  // IP 没有后缀
  assert.equal(candidateSuffix("1.2.3.4"), null);
  assert.equal(candidateSuffix("2001:db8::1"), null);
  // 畸形输入不炸
  assert.equal(candidateSuffix("badhost..com"), null);
  assert.equal(candidateSuffix(""), null);
});

test("candidateSuffix 幂等：同一主机永远映射到同一后缀", () => {
  // 同一个 API 主机的不同写法（大小写/尾点已由 normalizeHost 处理）不裂行
  for (const h of ["www.api.example.com", "www.API.example.com"]) {
    assert.equal(candidateSuffix(h.toLowerCase().replace(/\.$/, "")), "api.example.com");
  }
});

// --- 主机权重 --------------------------------------------------------------

test("hostWeight：中间地带不投票，极端区才投票且票数封顶", () => {
  assert.equal(hostWeight(0, 0), 0);
  // 中间地带（0.2~0.8）→ 0 票
  assert.equal(hostWeight(1, 1), 0);
  assert.equal(hostWeight(5, 5), 0);
  assert.equal(hostWeight(4, 6), 0); // rate = 0.4
  assert.equal(hostWeight(3, 2), 0); // rate = 0.6
  // 强成功（>=0.8）：min(n, MAX_HOST_WEIGHT) 票
  assert.equal(hostWeight(1, 0), 1);
  assert.equal(hostWeight(4, 1), 3);   // rate = 0.8，n=5 → 封顶
  assert.equal(hostWeight(5, 0), MAX_HOST_WEIGHT);
  assert.equal(hostWeight(100, 0), MAX_HOST_WEIGHT); // 封顶
  // 强失败（<=0.2）：同样投票（方向由调用方按 ok>fail 判）
  assert.equal(hostWeight(0, 1), 1);
  assert.equal(hostWeight(1, 4), MAX_HOST_WEIGHT); // rate = 0.2，n=5 → 封顶
  assert.equal(hostWeight(0, 100), MAX_HOST_WEIGHT);
  // 单次观测且恰好极端 → 1 票（最弱）
  assert.equal(hostWeight(1, 0), 1);
  assert.equal(hostWeight(0, 1), 1);
});

// --- 挖掘阈值 --------------------------------------------------------------

const row = (o) => ({ proto: "tls", ok: 0, fail: 0, last_kind: "ok", last_ts: NOW, ...o });

/** n 个主机，每个都强成功。 */
function strongHosts(n, prefix = "z.example.com") {
  return Array.from({ length: n }, (_, i) => row({
    host: `h${i}.${prefix}`, method: "15c0e805", ok: 3, fail: 0,
  }));
}

test("挖掘：主机数不足 MIN_HOSTS 不产出", () => {
  const rows = strongHosts(MIN_HOSTS - 1);
  assert.deepEqual(mineHints(rows, { now: NOW, proto: "tls" }), []);
});

test("挖掘：观测数不足 MIN_OBSERVATIONS 不产出", () => {
  // 3 个主机（够 MIN_HOSTS），每台只 1 票 → 总票 3 < MIN_OBSERVATIONS(6)。
  const rows = Array.from({ length: MIN_HOSTS }, (_, i) => row({
    host: `h${i}.z.example.com`, method: "15c0e805", ok: 1, fail: 0,
  }));
  assert.deepEqual(mineHints(rows, { now: NOW, proto: "tls" }), []);
  // 6 个主机各 1 票 → 总票 6，恰好达到下限，产出
  const enough = Array.from({ length: MIN_OBSERVATIONS }, (_, i) => row({
    host: `h${i}.z.example.com`, method: "15c0e805", ok: 1, fail: 0,
  }));
  assert.equal(mineHints(enough, { now: NOW, proto: "tls" }).length, 1);
});

test("挖掘：正常产出，按主机累加权重", () => {
  const rows = strongHosts(6);
  const out = mineHints(rows, { now: NOW, proto: "tls" });
  assert.equal(out.length, 1);
  assert.deepEqual(out[0], {
    suffix: "z.example.com", proto: "tls", method: "15c0e805",
    ok: 18, fail: 0, hosts: 6, expires: NOW + HINT_TTL_SECONDS,
  });
});

test("挖掘：时间窗外的行被忽略", () => {
  const rows = strongHosts(6).map((r) => ({ ...r, last_ts: NOW - MINE_MAX_AGE_SECONDS - 1 }));
  assert.deepEqual(mineHints(rows, { now: NOW, proto: "tls" }), []);
  // 窗口内（边界值）保留
  const inside = strongHosts(6).map((r) => ({ ...r, last_ts: NOW - MINE_MAX_AGE_SECONDS + 1 }));
  assert.equal(mineHints(inside, { now: NOW, proto: "tls" }).length, 1);
});

test("挖掘：proto 过滤生效，跨协议不串", () => {
  const rows = [
    ...strongHosts(6).map((r) => ({ ...r, proto: "tls" })),
    ...strongHosts(6, "h.example.com").map((r) => ({ ...r, proto: "http" })),
  ];
  const tls = mineHints(rows, { now: NOW, proto: "tls" });
  const http = mineHints(rows, { now: NOW, proto: "http" });
  const all = mineHints(rows, { now: NOW });
  assert.equal(tls.length, 1);
  assert.equal(tls[0].suffix, "z.example.com");
  assert.equal(http.length, 1);
  assert.equal(http[0].suffix, "h.example.com");
  assert.equal(all.length, 2);
});

test("挖掘：中间地带的 host 不投票（噪声不进结论）", () => {
  // 6 个主机全是 rate=0.5 → 全部不投票 → 空
  const rows = Array.from({ length: 6 }, (_, i) => row({
    host: `h${i}.z.example.com`, method: "15c0e805", ok: 2, fail: 2,
  }));
  assert.deepEqual(mineHints(rows, { now: NOW, proto: "tls" }), []);
});

test("挖掘：github.io / blogspot.com 这类共享托管后缀被拒", () => {
  const gh = Array.from({ length: 6 }, (_, i) => row({
    host: `u${i}.github.io`, method: "15c0e805", ok: 3, fail: 0,
  }));
  assert.deepEqual(mineHints(gh, { now: NOW, proto: "tls" }), []);
});

test("挖掘：IP 字面量被拒（没有后缀可言）", () => {
  const ips = Array.from({ length: 6 }, (_, i) => row({
    host: `10.0.0.${i}`, method: "15c0e805", ok: 3, fail: 0,
  }));
  assert.deepEqual(mineHints(ips, { now: NOW, proto: "tls" }), []);
});

test("挖掘：单个 noisy host 不能单独决定结论（主机数与票数两道闸）", () => {
  // 1 个 host 赢到天荒地老（100 票，封顶 3）+ 2 个 host 全败 → 主机数 3 达标，
  // 但总票 = 3 + 3 + 3 = 9 达标…… 所以换个更强的例子：让赢的票不足以压过输的。
  // 实际上封顶后 1 台赢 = 3 票，2 台输 = 6 票，结论会是"输"——但**主机数只有 3**
  // 时仍会产出。要证明封顶生效，看 ok 计数：1 台赢 100 次只有 3 票，不是 100 票。
  const rows = [
    row({ host: "a.z.example.com", method: "15c0e805", ok: 100, fail: 0 }),
    row({ host: "b.z.example.com", method: "15c0e805", ok: 100, fail: 0 }),
    row({ host: "c.z.example.com", method: "15c0e805", ok: 100, fail: 0 }),
  ];
  const out = mineHints(rows, { now: NOW, proto: "tls" });
  assert.equal(out.length, 1);
  // 3 台 × 3 票 = 9 票，而不是 300 票——这才是"封顶"的含义。
  assert.equal(out[0].ok, 9);
  assert.equal(out[0].hosts, 3);
});

test("挖掘：同一主机的多行先合并，不会一个 host 被数成多个", () => {
  // 同一 host 两行（proto/method 相同）——应合并成一台 host 的战绩。
  // 这里构造 3 个真实主机，每个 2 行，确保 hosts 数是 3 而不是 6。
  const rows = [];
  for (let i = 0; i < MIN_HOSTS; i++) {
    for (let k = 0; k < 2; k++) {
      rows.push(row({ host: `h${i}.z.example.com`, method: "15c0e805", ok: 2, fail: 0 }));
    }
  }
  const out = mineHints(rows, { now: NOW, proto: "tls" });
  assert.equal(out.length, 1);
  assert.equal(out[0].hosts, MIN_HOSTS);
});

// --- 集成：真实 method_stat 上挖 -------------------------------------------

function freshDB() {
  const d = makeD1(":memory:");
  d.raw.exec(SCHEMA);
  return d;
}

const item = (o) => {
  const v = validateItem({ proto: "tls", rtt_ms: 0, ts: NOW, ...o });
  return { ...v, ok: v.ok ? 1 : 0, fail: v.train && !v.ok ? 1 : 0 };
};

test("集成：recordReport → method_stat → 挖出 hint → 落库 → 下发", async () => {
  const db = freshDB();
  // 6 个 z.example.com 主机，@direct 全败、15c0e805 全胜（每台各 3 次观测，
  // 足够越过 MIN_OBSERVATIONS 与票数封顶）。
  const items = [];
  for (let i = 0; i < MIN_HOSTS + 3; i++) {
    for (let k = 0; k < 3; k++) {
      items.push(item({ host: `h${i}.z.example.com`, method: "15c0e805", kind: "ok", ok: true }));
      items.push(item({ host: `h${i}.z.example.com`, method: "@direct", kind: "reset", ok: false }));
    }
  }
  await recordReport(db, items, "a".repeat(32), "fp1", NOW);

  // 按 MINE_SQL 读 method_stat（与生产路径同一条查询）
  const rows = db.raw.prepare(MINE_SQL).all(NOW - MINE_MAX_AGE_SECONDS, MINE_ROW_LIMIT).map((r) => ({ ...r }));
  const hints = mineHints(rows, { now: NOW, proto: "tls" });
  assert.equal(hints.length, 2);
  const win = hints.find((h) => h.method === "15c0e805");
  const lose = hints.find((h) => h.method === "@direct");
  assert.ok(win.ok > 0 && win.fail === 0, `15c0e805 应全胜: ${JSON.stringify(win)}`);
  assert.ok(lose.fail > 0 && lose.ok === 0, `@direct 应全败: ${JSON.stringify(lose)}`);
  assert.ok(win.hosts >= MIN_HOSTS);
  assert.equal(win.expires, NOW + HINT_TTL_SECONDS);

  // 落库 + 按 proto 下发
  await replaceHints(db, "tls", hints, NOW);
  const live = await listHints(db, "tls", 128, NOW);
  assert.equal(live.length, 2);
  assert.equal((await listHints(db, "http", 128, NOW)).length, 0, "http 不该拿到 tls 的 hint");
});

test("MINE_SQL 只读 method_stat（绝不 JOIN hint）", () => {
  assert.ok(/FROM method_stat/i.test(MINE_SQL), "MINE_SQL 不从 method_stat 读");
  assert.ok(!/hint/i.test(MINE_SQL), "MINE_SQL 不得引用 hint 表");
  // 且带行数上限与时间下限
  assert.ok(/LIMIT \?/i.test(MINE_SQL));
  assert.ok(/last_ts >=/i.test(MINE_SQL));
});
