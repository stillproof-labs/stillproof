#!/usr/bin/env bash
# Fetch Externalize's browser package into web/vendor/externalize, checked
# against a pinned SHA-256. Its binaries aren't committed.
#
# Until the v0.3.0 release is published (SHA256 empty), it is built from the
# pinned commit instead, as Externalize's release workflow builds it. That
# needs cargo with the wasm32-unknown-unknown target.
set -euo pipefail
VERSION=v0.3.0
SHA256=2445ec5eb7b276bd8a69648b7e2456f3f27ce2b1b74f51df04cbc8be83d852ff
COMMIT=3b1c322ed39bf7e89ed78281911fe77591d3338c # main at "chore: release 0.3.0"
NAME=externalize-wasm-$VERSION-web
DIR=$(cd "$(dirname "$0")/.." && pwd)/web/vendor/externalize
TMP=$(mktemp -d)
if command -v cygpath >/dev/null; then TMP=$(cygpath -m "$TMP"); fi # for cargo on Windows
trap 'rm -rf "$TMP"' EXIT
if [ -n "$SHA256" ]; then
  curl -fsSL -o "$TMP/pkg.tar.gz" "https://github.com/Externalize-Labs/externalize/releases/download/$VERSION/$NAME.tar.gz"
  echo "$SHA256  $TMP/pkg.tar.gz" | sha256sum -c --quiet
  tar -xzf "$TMP/pkg.tar.gz" -C "$TMP"
else
  git -C "$TMP" init -q src
  git -C "$TMP/src" fetch -q --depth 1 https://github.com/Externalize-Labs/externalize "$COMMIT"
  git -C "$TMP/src" checkout -q FETCH_HEAD
  (
    cd "$TMP/src"
    cargo build -q -p externalize-wasm --target wasm32-unknown-unknown --profile wasm --locked
    bindgen=$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"$/\1/p')
    [ -n "$bindgen" ] || { echo "no wasm-bindgen version in Cargo.lock" >&2; exit 1; }
    cargo install -q wasm-bindgen-cli --version "$bindgen" --locked --root "$TMP/tools"
    "$TMP/tools/bin/wasm-bindgen" --target web --out-dir "$TMP/$NAME" target/wasm32-unknown-unknown/wasm/externalize_wasm.wasm
    cp LICENSE "$TMP/$NAME/"
  )
fi
cp "$TMP/$NAME/externalize_wasm.js" "$TMP/$NAME/externalize_wasm_bg.wasm" "$TMP/$NAME/LICENSE" "$DIR/"
