#!/usr/bin/env bash
# Build the wasm package and run the JS interop client against it.
#
# Regenerates `tests/fixtures/js_snapshot.loro`, which the native test
# `js_produced_fixture_decodes_to_canonical_content` asserts against.
set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
repo_root="$(cd "$crate_dir/../.." && pwd)"

# roam-sync builds OOM under parallelism; keep the wasm build single-job too and
# hold cargo's scratch inside target/ so it lands on the big volume.
export CARGO_BUILD_JOBS=1
export TMPDIR="$repo_root/target/tmp"
mkdir -p "$TMPDIR"

# --target nodejs: CommonJS glue that `node` can require directly, no bundler.
# --dev: skip wasm-opt; this is a correctness harness, not a size benchmark.
# --features test-relay: exports the MemoryBackend-backed relay that sync.mjs
#   serves over HTTP. Off in a shipped build (see Cargo.toml).
#
# NOTE --out-dir is resolved relative to the crate dir by wasm-pack, so it must
# be a bare name here, not an absolute path.
wasm-pack build "$crate_dir" --target nodejs --dev --out-dir pkg --features test-relay

node "$crate_dir/tests/js/interop.mjs"
node "$crate_dir/tests/js/sync.mjs"
