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

# Single-job by default because this workspace OOMs under parallelism on a
# smaller machine, but overridable: that limit is a property of the machine, not
# of the harness, and hard-coding it makes a 16-core box build at the speed of a
# laptop. TMPDIR stays inside target/ so cargo's scratch lands on the big volume.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export TMPDIR="$repo_root/target/tmp"
mkdir -p "$TMPDIR"

# --target web: ESM glue a module worker can `import` directly, unlike the
# nodejs (CommonJS) target the other harness builds.
# --dev: skip wasm-opt; this checks correctness, not size.
wasm-pack build "$crate_dir" --target web --dev \
  --out-dir "tests/browser/pkg" --features browser-test

profile="$(mktemp -d)"
browser=""
server=""

# Kill both children and WAIT for them before removing the profile. `kill` only
# signals: chromium keeps writing into its user-data-dir for a moment after, and
# an `rm -rf` racing that fails with "Directory not empty" and leaves the profile
# behind. Profiles are hundreds of MB, and this repo has already filled its disk
# once, so a cleanup that silently loses the race is not a cosmetic problem.
#
# `set +e` first, and it is load-bearing: this runs under `set -e`, and by the
# time the trap fires the server has usually already exited, so `kill` and `wait`
# return non-zero and would abort the function BEFORE the `rm`. That is not
# hypothetical — it is why the first version of this script left a 23 MB profile
# behind on every single run while looking like it cleaned up.
cleanup() {
  set +e
  [ -n "$browser" ] && kill "$browser" 2>/dev/null
  [ -n "$server" ] && kill "$server" 2>/dev/null
  # Reap before removing: chromium keeps writing into its user-data-dir for a
  # moment after the signal, and an `rm -rf` racing that fails with "Directory
  # not empty".
  wait "$browser" "$server" 2>/dev/null
  rm -rf "$profile"
}
trap cleanup EXIT

node "$harness_dir/serve.mjs" &
server=$!

sleep 1
# A FRESH profile per run, deliberately. OPFS is durable, so a leftover profile
# would carry the previous run's pool — and "survives a remount" would then pass
# against stale slots even if this build never wrote anything.
chromium --headless=new --no-sandbox --disable-gpu \
  --user-data-dir="$profile" \
  "http://127.0.0.1:${PORT:-8732}/" >/dev/null 2>&1 &
browser=$!

# Report the CHECKS' verdict, not the browser's: chromium exits non-zero for its
# own reasons and would mask a passing run either way. The server exits with the
# verdict it was handed by the page.
wait $server
exit $?
