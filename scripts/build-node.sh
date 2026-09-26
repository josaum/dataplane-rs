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
  Darwin) DYLIB_EXT="dylib" ;;
  Linux)  DYLIB_EXT="so" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

TARGET_DIR="$(cargo metadata --locked --no-deps --format-version 1 \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')"

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
  napi_name="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["napi"]["name"])' "$crate/package.json")"
  src="$TARGET_DIR/release/lib${napi_name}.${DYLIB_EXT}"
  test -f "$src" || { echo "missing $src" >&2; exit 1; }
  cp -f "$src" "$crate/${napi_name}.node"
  echo "ok $crate -> $crate/${napi_name}.node"
done
