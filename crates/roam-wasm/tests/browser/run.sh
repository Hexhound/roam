#!/usr/bin/env bash
# Run the OPFS storage checks in a real headless browser.
#
# The node harness (`tests/js/run.sh`) covers M1 interop and M3 transport and
# structurally cannot cover storage: node has no OPFS. Nor could a page — the
# sync access handle API exists only inside a dedicated worker. So this is the
# one test path that needs a browser, and it exists only for the ~5 methods of
# `roam_storage::vfs_opfs` that delegate to it. Everything else about the pool is
# covered natively by roam-storage.
set -euo pipefail

harness_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate_dir="$(cd "$harness_dir/../.." && pwd)"
repo_root="$(cd "$crate_dir/../.." && pwd)"

export CARGO_BUILD_JOBS=1
export TMPDIR="$repo_root/target/tmp"
mkdir -p "$TMPDIR"

# --target web: ESM glue a module worker can `import` directly, unlike the
# nodejs (CommonJS) target the other harness builds.
# --dev: skip wasm-opt; this checks correctness, not size.
wasm-pack build "$crate_dir" --target web --dev \
  --out-dir "tests/browser/pkg" --features browser-test

profile="$(mktemp -d)"
trap 'rm -rf "$profile"' EXIT

node "$harness_dir/serve.mjs" &
server=$!
# Report the checks' verdict, not the browser's: chromium exits non-zero for its
# own reasons and would mask a passing run either way.
trap 'kill $server 2>/dev/null || true; rm -rf "$profile"' EXIT

sleep 1
# A FRESH profile per run, deliberately. OPFS is durable, so a leftover profile
# would carry the previous run's pool — and "survives a remount" would then pass
# against stale slots even if this build never wrote anything.
chromium --headless=new --no-sandbox --disable-gpu \
  --user-data-dir="$profile" \
  "http://127.0.0.1:${PORT:-8732}/" >/dev/null 2>&1 &
browser=$!

wait $server
status=$?
kill $browser 2>/dev/null || true
exit $status
