#!/usr/bin/env bash
# 生成并校验跨语言帧契约。
#
# 帧编解码在 Go（client/internal/coord/frame.go）与 JS（server/src/frame.js）各有一份，
# 两侧必须逐字节一致。肉眼比对长 hex 一定会抄错，所以这个脚本：
#
#   1. 让两侧各自跑出同一组载荷的 hex
#   2. 断言两侧相同（不同 = 协议不一致，立刻失败）
#   3. 把实测值自动回填进 Go 测试与 JS 测试的 golden
#
# 改了任何一侧的编码后重跑本脚本。
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
GOLD="$ROOT/.lab/golden"
mkdir -p "$GOLD"
# Go 与 Node 需要绝对路径。MSYS/Git Bash 下 /d/... 它们解析不了，要转成
# Windows 风格；其它平台直接用 pwd 的结果。
if ABS="$(cd "$GOLD" && pwd -W 2>/dev/null)"; then
  GOLD_ABS="$ABS"
else
  GOLD_ABS="$(cd "$GOLD" && pwd)"
fi
export GOPROXY=off GOFLAGS="${GOFLAGS:--mod=mod}"

cleanup() { rm -f "$ROOT/client/internal/coord/zz_dump_test.go"; }
trap cleanup EXIT

# --- 1. Go 侧 --------------------------------------------------------------
cat > "$ROOT/client/internal/coord/zz_dump_test.go" << GOEOF
package coord

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestDumpGolden(t *testing.T) {
	h := encodeFrame(opHello, 0, encodeHello(1780000000, strings.Repeat("a", authLen), "fp", []string{"split", "tlsrf"}))
	b, err := encodeBundleResp(42, []bundleEntry{
		{id: "15c0e805", spec: "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)"},
		{id: "78c3d41b", spec: "tls|tlsrf(chunk=8,delay_ms=8,limit=400)"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := encodeReport("0123456789abcdef0123456789abcdef", []reportEntry{
		{host: "www.example.com", method: "15c0e805", kind: "ok", ok: true, rtt: 118, ts: 1780000000, proto: "tls"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ob, err := encodeOpen("www.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{
		hex.EncodeToString(h),
		hex.EncodeToString(b),
		hex.EncodeToString(encodeFrame(opReport, 7, r)),
		hex.EncodeToString(ob),
		hex.EncodeToString(encodeEvolveResp(7, 6, 4, 48)),
	}
	if err := os.WriteFile(os.Getenv("GOLD_ABS")+"/go.txt", []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
GOEOF
( cd "$ROOT/client" && go test ./internal/coord/ -run TestDumpGolden >/dev/null )

# --- 2. JS 侧 --------------------------------------------------------------
( cd "$ROOT/server" && GOLD_ABS="$GOLD_ABS" node -e '
const fs = require("fs");
import("./src/frame.js").then((m) => {
  const enc = (b) => Buffer.from(b).toString("hex");
  const lines = [
    enc(m.encodeFrame(m.OP.HELLO, 0, m.encodeHello(1780000000, "a".repeat(32), "fp", ["split", "tlsrf"]))),
    enc(m.encodeBundleResp(42, [
      { id: "15c0e805", spec: "tls|split(at=sni,count=2,delay_ms=8,len=1,pos=1)" },
      { id: "78c3d41b", spec: "tls|tlsrf(chunk=8,delay_ms=8,limit=400)" },
    ])),
    enc(m.encodeFrame(m.OP.REPORT, 7, m.encodeReport("0123456789abcdef0123456789abcdef", [
      { host: "www.example.com", method: "15c0e805", ok: 1, unsup: 0, rtt_ms: 118, ts: 1780000000, kind: "ok", proto: "tls" },
    ]))),
    enc(m.encodeOpen("www.example.com", 443)),
    enc(m.encodeU32s(7, 6, 4, 48)),
  ];
  fs.writeFileSync(process.env.GOLD_ABS + "/js.txt", lines.join("\n") + "\n");
}).catch((e) => { console.error(e); process.exit(1); });
')

# --- 3. 断言 + 回填 ---------------------------------------------------------
GOLD_ABS="$GOLD_ABS" ROOT="$ROOT" node -e '
const fs = require("fs");
const names = ["HELLO", "BUNDLE_RESP", "REPORT", "OPEN", "EVOLVE_RESP"];
const go = fs.readFileSync(process.env.GOLD_ABS + "/go.txt", "utf8").trim().split("\n");
const js = fs.readFileSync(process.env.GOLD_ABS + "/js.txt", "utf8").trim().split("\n");
let bad = 0;
names.forEach((n, i) => {
  const same = go[i] === js[i];
  if (!same) bad++;
  console.log(`${same ? "OK  " : "FAIL"} ${n.padEnd(13)} len=${go[i].length}`);
  if (!same) console.log("  go=" + go[i] + "\n  js=" + js[i]);
});
if (bad) { console.error(`\n${bad} 项跨语言不一致 —— 协议已漂移`); process.exit(1); }

const gp = process.env.ROOT + "/client/internal/coord/frame_test.go";
let s = fs.readFileSync(gp, "utf8");
const replace = (re, v) => { s = s.replace(re, (m, a) => a + v + m.slice(m.lastIndexOf("\")")) ); };
s = s.replace(/(\{"HELLO", hello, ")[0-9a-f]+("\})/, "$1" + go[0] + "$2");
s = s.replace(/(\{"REPORT", report, ")[0-9a-f]+("\})/, "$1" + go[2] + "$2");
fs.writeFileSync(gp, s);

// JS 侧也一起回填。曾经只回填 Go，两边各有一份硬编码 golden，改了线格式后 JS 那份
// 静默过期，直到测试报错才发现——这正是本脚本要消灭的手工同步。
const jp = process.env.ROOT + "/server/test/ws.test.mjs";
let j = fs.readFileSync(jp, "utf8");
const jb = j;
// 只回填 REPORT 那条（它的上下文里有 OP.REPORT, 7），其余 golden 不参与本脚本。
j = j.replace(/(assert\.equal\(got, ")[0-9a-f]+("\);;)/g, (m, a, b, off, all) =>
  all.lastIndexOf("OP.REPORT, 7", off) > off - 200 ? a + go[2] + b : m);
// 幂等：值本来就正确时 replace 不改动任何东西，所以用"文件里有没有这个值"判成功。
if (!j.includes(go[2])) console.error("警告: 未能在 server/test/ws.test.mjs 回填 REPORT golden");
fs.writeFileSync(jp, j);

console.log("\n已把实测值回填进 Go/JS 测试 golden");
'
cleanup

echo
echo "完成。两侧一致。"