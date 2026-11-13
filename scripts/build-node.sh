#!/usr/bin/env bash
# Build the Node-API `.node` binary for every `*-node` crate (or the ones named
# as arguments) and place it next to that crate's `index.js`, which loads it by
# the fixed name `<napi.name>.node`. That file name is the contract between a
# release tarball and the consumer shells that package it, so it never
# carries a platform token; the tarball name does.
#
# Usage: scripts/build-node.sh [crate ...]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

case "$(uname -s)" in
  Darwin) dylib_prefix="lib"; dylib_ext="dylib" ;;
  Linux)  dylib_prefix="lib"; dylib_ext="so" ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT) dylib_prefix=""; dylib_ext="dll" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

TARGET_DIR="${CARGO_TARGET_DIR:-target}"

CRATES=("$@")
if [ "${#CRATES[@]}" -eq 0 ]; then
  for d in *-node; do
    [ -f "$d/Cargo.toml" ] && CRATES+=("$d")
  done
fi

BUILD_ARGS=()
for crate in "${CRATES[@]}"; do BUILD_ARGS+=(-p "$crate"); done
cargo build --release --locked "${BUILD_ARGS[@]}"

for crate in "${CRATES[@]}"; do
  napi_name="$(node -e 'console.log(require("./" + process.argv[1]).napi.name)' "$crate/package.json")"
  src="$TARGET_DIR/release/${dylib_prefix}${napi_name}.${dylib_ext}"
  test -f "$src" || { echo "missing $src" >&2; exit 1; }
  cp -f "$src" "$crate/${napi_name}.node"
  echo "ok $crate -> $crate/${napi_name}.node"
done
