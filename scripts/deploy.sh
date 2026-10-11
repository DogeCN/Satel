#!/usr/bin/env bash
# 一键部署 Satel 协调端：建 D1 → 建表 → 部署 Worker → 写密钥。
#
# 需要（可用仓库根的 .env）：
#   CLOUDFLARE_API_TOKEN   有 Workers 编辑权限
#   CLOUDFLARE_ACCOUNT_ID
#   PASSWORD               客户端与 Worker 共享的口令
# 可选：
#   ADMIN_KEY              /v1/evolve 用；不设则自动生成并写回 .env
#
# 用法：
#   scripts/deploy.sh --dry-run    只打印要执行什么
#   scripts/deploy.sh
#
# 注意：脚本不会替你绑自定义域名——那需要 zone 级权限，得在控制台做
# （Workers → Settings → Domains & Routes）。没有自定义域名，大陆客户端连不上。
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
ENV_FILE="$ROOT/.env"

DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

: "${CLOUDFLARE_API_TOKEN:?需要 CLOUDFLARE_API_TOKEN}"
: "${CLOUDFLARE_ACCOUNT_ID:?需要 CLOUDFLARE_ACCOUNT_ID}"
: "${PASSWORD:?需要 PASSWORD}"

DB_NAME="${DB_NAME:-satel}"
WORKER_NAME="${WORKER_NAME:-satel}"

run() {
  if [[ $DRY == 1 ]]; then
    echo "  [dry-run] $*"
  else
    echo "  + $*"
    "$@"
  fi
}

echo "== 1/5 准备依赖 =="
if [[ ! -d "$ROOT/server/node_modules" ]]; then
  run npm --prefix "$ROOT/server" ci
fi

echo "== 2/5 建 D1（已存在会报错，可忽略） =="
if [[ $DRY == 1 ]]; then
  echo "  [dry-run] wrangler d1 create $DB_NAME"
else
  ( cd "$ROOT/server" && npx --yes wrangler@4 d1 create "$DB_NAME" ) || \
    echo "  (D1 可能已存在，继续)"
fi

DB_ID="$(cd "$ROOT/server" && npx --yes wrangler@4 d1 list --json 2>/dev/null \
  | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{const i=s.indexOf('[');const j=JSON.parse(s.slice(i));const m=j.find(x=>x.name===process.argv[1]);if(m)console.log(m.uuid)}catch{}})" "$DB_NAME" || true)"

if [[ -n "${DB_ID:-}" ]]; then
  echo "  database_id = $DB_ID"
  if [[ $DRY == 0 ]]; then
    node -e '
      const fs=require("fs");
      const p=process.argv[1], id=process.argv[2];
      let s=fs.readFileSync(p,"utf8");
      s=s.replace(/database_id\s*=\s*"[^"]*"/, `database_id = "${id}"`);
      fs.writeFileSync(p,s);
    ' "$ROOT/server/wrangler.toml" "$DB_ID"
  fi
else
  echo "  警告: 未解析到 D1 id，请手动填 server/wrangler.toml 的 database_id"
fi

echo "== 3/5 建表 =="
run bash -c "cd '$ROOT/server' && npx --yes wrangler@4 d1 execute $DB_NAME --remote --file=schema.sql -y"

echo "== 4/5 部署 =="
run bash -c "cd '$ROOT/server' && npx --yes wrangler@4 deploy"

echo "== 5/5 写密钥 =="
if [[ $DRY == 1 ]]; then
  echo "  [dry-run] wrangler secret put PASSWORD / ADMIN_KEY"
else
  ( cd "$ROOT/server" && printf '%s' "$PASSWORD" | npx --yes wrangler@4 secret put PASSWORD )
  if [[ -z "${ADMIN_KEY:-}" ]]; then
    ADMIN_KEY="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    printf 'ADMIN_KEY=%s\n' "$ADMIN_KEY" >> "$ENV_FILE"
    echo "  已生成 ADMIN_KEY 并写入 .env"
  fi
  ( cd "$ROOT/server" && printf '%s' "$ADMIN_KEY" | npx --yes wrangler@4 secret put ADMIN_KEY )
fi

cat <<EOF

完成。还差最后一步（需要 zone 级权限，控制台做）：
  把 satel.<你的域名> 绑成 Worker "$WORKER_NAME" 的自定义域名。
  Workers → 选该 Worker → Settings → Domains & Routes → Add custom domain。

绑好后播种策略库：
  ./client/satel admin evolve --worker https://satel.<你的域名> \\
    --password "\$PASSWORD" --admin-key "\$ADMIN_KEY"
EOF
