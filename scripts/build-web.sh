#!/usr/bin/env bash
# Build the browser verifier into web/: verify.wasm, the wasm_exec.js of the
# Go that built it, and Externalize's browser package.
set -euo pipefail
cd "$(dirname "$0")/.."
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o web/verify.wasm ./cmd/wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/
scripts/vendor-externalize.sh
