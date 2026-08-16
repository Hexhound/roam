#!/usr/bin/env bash
# Run the browser-only checks in a real headless browser: OPFS storage, and the
# worker that hosts roam.
#
# The node harness (`tests/js/run.sh`) covers M1 interop and M3 transport and
# structurally cannot cover either of these: node has no OPFS. Nor could a page —
# the sync access handle API exists only inside a dedicated worker. So this is
# the one test path that needs a browser, and it is kept to what only a browser
# can prove: the ~5 methods of `roam_storage::vfs_opfs` that delegate to a sync
# access handle, and that the shipped `worker/roam-worker.js` loads and survives
# being terminated. The pool's logic is covered natively by roam-storage, and the
# command protocol by `roam-wasm`'s `tests/session.rs`.
set -euo pipefail

harness_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate_dir="$(cd "$harness_dir/../.." && pwd)"
repo_root="$(cd "$crate_dir/../.." && pwd)"

# Single-job by default because this workspace OOMs under parallelism on a
# smaller machine, but overridable: that limit is a property of the machine, not
# of the harness, and hard-coding it makes a 16-core box build at the speed of a
# laptop. TMPDIR stays inside target/ so cargo's scratch lands on the big volume.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

# One scratch directory per run, holding EVERYTHING this run creates: the
# chromium profile, and — the part that is easy to miss — the
# `org.chromium.Chromium.XXXXXX` directory chromium drops in TMPDIR for its
# singleton socket. Removing just the profile leaves that behind, and a unix
# socket inside the repo is not merely litter: `nix develop .` copies the
# working tree as a path input and fails outright with "has an unsupported
# type", so the next run cannot even enter the shell.
export TMPDIR="$repo_root/target/tmp"
mkdir -p "$TMPDIR"
scratch="$(mktemp -d)"
export TMPDIR="$scratch"

# --target web: ESM glue a module worker can `import` directly, unlike the
# nodejs (CommonJS) target the other harness builds.
# --dev: skip wasm-opt; this checks correctness, not size.
wasm-pack build "$crate_dir" --target web --dev \
  --out-dir "tests/browser/pkg" --features browser-test

profile="$scratch/profile"
browser=""
server=""

# Leaving anything behind is not cosmetic here. This repo has already filled its
# disk once, and worse, a chromium socket left inside the tree makes `nix
# develop .` fail outright with "has an unsupported type" — so a leaked file
# breaks the NEXT run before it starts.
#
# Three separate things had to be right, each found by watching a run leak:
#
#   1. `set +e`. The trap runs under `set -e`, and by the time it fires the
#      server has usually already exited, so `kill`/`wait` return non-zero and
#      abort the function BEFORE the `rm`. The first version of this script left
#      a 23 MB profile behind on every run while looking like it cleaned up.
#   2. Kill the process GROUP, not the process. chromium forks children that are
#      not children of this shell, so `wait` never reaps them and they keep
#      writing into the profile while `rm -rf` walks it — which fails with
#      "Directory not empty". `setsid` below is what makes the group killable.
#   3. Retry the removal. Even after SIGTERM to the group, unlinking races the
#      last writes; a few short retries settle it, and SIGKILL ends the argument.
cleanup() {
  set +e
  [ -n "$browser" ] && kill -- -"$browser" 2>/dev/null
  [ -n "$server" ] && kill "$server" 2>/dev/null
  wait "$browser" "$server" 2>/dev/null

  for _ in 1 2 3 4 5; do
    rm -rf "$scratch" 2>/dev/null && break
    [ -n "$browser" ] && kill -9 -- -"$browser" 2>/dev/null
    sleep 0.3
  done
  # Say so rather than leaking silently: the next `nix develop` would fail with
  # an error that points nowhere near this script.
  if [ -e "$scratch" ]; then
    echo "WARNING: could not remove $scratch — remove it before the next run" >&2
  fi
}
trap cleanup EXIT

node "$harness_dir/serve.mjs" &
server=$!

sleep 1
# A FRESH profile per run, deliberately. OPFS is durable, so a leftover profile
# would carry the previous run's pool — and "survives a remount" would then pass
# against stale slots even if this build never wrote anything.
# `setsid`: chromium's forked children must land in their own process group so
# cleanup can kill all of them at once. Without it they outlive the signal and
# keep writing into the profile being removed.
setsid chromium --headless=new --no-sandbox --disable-gpu \
  --user-data-dir="$profile" \
  "http://127.0.0.1:${PORT:-8732}/" >/dev/null 2>&1 &
browser=$!

# Report the CHECKS' verdict, not the browser's: chromium exits non-zero for its
# own reasons and would mask a passing run either way. The server exits with the
# verdict it was handed by the page.
wait $server
exit $?
