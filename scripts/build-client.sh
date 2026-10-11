#!/usr/bin/env bash
# 构建客户端：严格单文件静态可执行程序。
#
# 用法：scripts/build-client.sh [输出目录]
set -euo pipefail

cd "$(dirname "$0")/../client"
OUT_DIR="${1:-.}"
mkdir -p "$OUT_DIR"

export CGO_ENABLED=0
export GOFLAGS="${GOFLAGS:--mod=mod}"

echo "== 检查 =="
gofmt -l . | tee /tmp/satel-fmt.txt
[[ ! -s /tmp/satel-fmt.txt ]] || { echo "以上文件未格式化（gofmt -w）"; exit 1; }
go vet ./...
go test ./...

echo "== 构建（6 个目标平台） =="
build() {
  local os="$1" arch="$2" ext=""
  [[ "$os" == "windows" ]] && ext=".exe"
  echo "  $os/$arch"
  GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "-s -w" \
    -o "$OUT_DIR/satel-$os-$arch$ext" ./cmd/satel
}

build linux   amd64
build linux   arm64
build windows amd64
build windows arm64
build darwin  amd64
build darwin  arm64

echo "== 产物 =="
ls -la "$OUT_DIR"/satel-*
