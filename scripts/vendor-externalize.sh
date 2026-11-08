#!/usr/bin/env bash
# Fetch Externalize's browser package into web/vendor/externalize, checked
# against a pinned SHA-256. Its binaries aren't committed.
set -euo pipefail
VERSION=v0.2.0
SHA256=6390413f5b3bd1759a3471ad27892b68af97861ba998babb434d71bd593d9023
NAME=externalize-wasm-$VERSION-web
DIR=$(cd "$(dirname "$0")/.." && pwd)/web/vendor/externalize
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/pkg.tar.gz" "https://github.com/Externalize-Labs/externalize/releases/download/$VERSION/$NAME.tar.gz"
echo "$SHA256  $TMP/pkg.tar.gz" | sha256sum -c --quiet
tar -xzf "$TMP/pkg.tar.gz" -C "$TMP"
cp "$TMP/$NAME/externalize_wasm.js" "$TMP/$NAME/externalize_wasm_bg.wasm" "$TMP/$NAME/LICENSE" "$DIR/"
