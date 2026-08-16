# Browser storage: an OPFS `VaultFs`

The durable half of the browser client. M2 extracted `VaultFs` and left the
browser backend as "still to come"; M3 shipped transport on `MemFs`, so a
browser vault currently dies with the tab. This is the design that fixes it,
and the evidence it rests on.

Read `wasm_localsend_handoff.md` first for M1–M3.

## The problem in one paragraph

`VaultFs` is **synchronous** — deliberately, because making it async would push
`async fn` through every persistence call and up through `Store` for what is an
IO detail (M2, "two decisions worth not re-litigating"). OPFS is *mostly*
asynchronous: `getDirectory`, `getDirectoryHandle`, `getFileHandle`,
`createSyncAccessHandle` and `removeEntry` all return promises. Only the
operations **on an already-open sync access handle** — `read`, `write`,
`truncate`, `getSize`, `flush`, `close` — are synchronous. So a synchronous
`read(path)` cannot navigate to its file; it can only act on a handle something
already opened.

## Measured facts, not assumptions

Probed in Chromium 150.0.7871.186, headless, over `http://127.0.0.1` (OPFS needs
a secure context with a real storage key — `file://` is an opaque origin and
will not do). Probe lived in `target/opfs-probe/`, deliberately scratch.

| question | answer |
|---|---|
| `createSyncAccessHandle` on the main thread | **does not exist** — the property is `undefined`, so it is not a permissions failure you can prompt past |
| …in a dedicated worker | works, byte roundtrip verified |
| do the two contexts share one OPFS namespace | yes — the worker listed the file the main thread created |
| 64 sync access handles held open at once | works |
| a second handle on a file that already has one | rejected, `NoModificationAllowedError` |
| `truncate(1024)` then `write(at: 900)` | works, size stays 1024 |
| `removeEntry` | exists, but is **async** |

Two of these decide the design:

1. **Main-thread OPFS sync handles are absent, not merely restricted.** M2's
   consequence stands unchanged: *the browser client cannot run roam on the main
   thread.* Flutter web must talk to roam in a dedicated worker.
2. **Exclusivity is enforced.** Open-on-demand is therefore not just slow, it is
   incorrect: two concurrent operations touching the same file would collide.

## The design: a pre-opened handle pool

The same shape `sqlite3.wasm`'s `opfs-sahpool` VFS uses, for the same reason.

At mount — which **is** async, and is the only async step — open a fixed number
of opaque backing files (`.roam-pool/0`, `.roam-pool/1`, …) and keep a sync
access handle on each for the lifetime of the worker. A name map associates a
vault path with a slot. After that, every `VaultFs` method is a synchronous
operation on a handle that is already open.

```
OpfsFs::mount(root, capacity).await     // the only await
  ├── .roam-pool/0  ─── handle ─── "ops/1234.log"
  ├── .roam-pool/1  ─── handle ─── "roster/roster.log"
  ├── .roam-pool/2  ─── handle ─── (free)
  └── ...
```

How each trait method falls out:

| `VaultFs` | pool implementation |
|---|---|
| `read` / `read_range` | `handle.read(buf, {at})` |
| `write` | `truncate(0)` then `write(buf, {at: 0})` |
| `append` | `write(buf, {at: getSize()})` |
| `append_sync` | the same, then `flush()` — a real distinct guarantee, which is why M2 made it a separate method |
| `create_sized` | `truncate(len)` — the probe confirms sparse-ish behaviour and a write past 900 into a 1024 file |
| `write_range` | `write(buf, {at: offset})`, length unchanged |
| `create_dir_all` | nothing on disk; directories are implied by the name map |
| `read_dir` / `is_dir` | prefix scan of the name map |
| `rename` | **rename the key in the map.** The bytes never move, and the mode flag rides on the entry — so the `MemFs` bug (permissions must follow a file across `rename`, or the identity secret is published world-readable) cannot occur here by construction |
| `remove_file` | drop the name, `truncate(0)`, return the slot to the free list. The OPFS file is **recycled, never deleted** — which is what makes this synchronous despite `removeEntry` being async |
| `set_owner_only` | no-op; the origin is the isolation boundary, as the trait doc already says |

### Capacity, the one genuinely open edge

A slot claim is synchronous, so the pool can be exhausted by a sequence of
synchronous calls with no chance to `await` a refill. `assets/` (content-addressed
blobs) is the part that can grow without bound.

The seam that solves it is the worker's own message loop: it is async, and it
sits between roam API calls. Before dispatching a command it can
`ensure_capacity(n).await`, topping the pool up off the critical path. Exhaustion
mid-command then means the pool was under-provisioned for a single operation,
which is a bug to surface loudly rather than a condition to recover from.

Do **not** try to grow the pool from inside a `VaultFs` method. There is no way
to await there, and the alternatives (`Atomics.wait` on a `SharedArrayBuffer`
with a proxy worker) require cross-origin isolation — COOP/COEP headers that
would also break embedding third-party resources, which CareMate does.

### Durability

`flush()` on a sync access handle is the durability primitive, and `append_sync`
is the only caller that needs it. Everything else may stay in the browser's
buffer. This preserves M2's guarantee that an acknowledged op-log append survives
a crash, which is the invariant `op-log-is-truth` rests on.

## `VaultFs: Send + Sync` versus JS values

A sync access handle is a `JsValue`, which is neither `Send` nor `Sync`. Two
options, and `Backend` has already set the precedent: it cfg's its `Send` bound
rather than removing it, keeping the full guarantee on native and relaxing it
only on wasm32. Doing the same for `VaultFs` is sound for the same reason —
wasm32 has no threads — and is honest in a way a blanket `unsafe impl Send`
wrapper is not.

The one thing to check before choosing: `Backend`'s relaxation is only sound
because it is always used as `B: Backend` and never as `dyn Backend`. `VaultFs`
is the opposite — `Store` holds `Arc<dyn VaultFs>` — so the auto-trait bound is
part of the object type and a cfg'd supertrait will not elaborate onto it. That
means the wrapper route is the workable one here, and its `unsafe impl` must be
justified in a comment by the no-threads argument, not waved at.

## What was built

- `roam-storage/src/vfs_pool.rs` — `SlotPool<S>`, the whole design above, over a
  five-method `Slot` trait. Plain Rust: no JS, no browser, no wasm.
- `roam-storage/src/vfs_opfs.rs` — wasm32-only. `OpfsSlot` (the five
  delegations), `mount()` (the one async step), `OpfsPool::ensure_free()`.
- `roam-wasm/src/opfs_checks.rs` + `roam-wasm/tests/browser/` — the harness.

The split is the point: because `Slot` excludes everything OPFS makes async,
essentially all the behaviour is natively testable, and the browser-only surface
is five one-line methods.

## Validation

Three layers, each covering what the one below cannot.

**Native, `roam-storage`.** `vfs::conformance()` — the one suite every backend
passes, now reachable outside `cfg(test)` behind the `conformance` feature — runs
against the pool alongside `NativeFs` and `MemFs`. Plus unit tests for slot
recycling, exhaustion, growth, rename-onto-existing, over-long paths, and a
duplicate-claim mount.

**Native, `tests/vault_on_slot_pool.rs`.** A real `Store` lifecycle that survives
a **remount**: a brand-new `SlotPool` rebuilds the path map from slot bytes
alone. `MemFs` structurally cannot test this — it dies with the process, so
"reopen the store" only re-reads a map that never went away. A pool holding its
map in memory passes every test in `vault_on_memfs.rs` and loses the whole vault
on tab close. Mutation-checked: dropping header recovery fails the two remount
tests and leaves the third passing.

**Real browser, `crates/roam-wasm/tests/browser/run.sh`.** Four checks in a
dedicated worker in headless Chromium, covering only what the browser itself has
to honour: the conformance suite against real OPFS; a vault surviving every
handle being closed and the pool remounted; `truncate` upward actually
zero-filling (`create_sized` pre-sizes a blob, and slots are *recycled*, so a
non-zeroed gap would disclose a previous tenant's bytes); and growing a pool
after mount. Mutation-checked by making the `Slot` impl ignore the offset.

Two things the harness needs that are easy to get wrong:

- **A fresh browser profile per run.** OPFS is durable, so a leftover profile
  carries the previous run's pool and "survives a remount" would pass against
  stale slots even if the build under test wrote nothing.
- **Panic text has to be forwarded as it happens.** wasm32 panics are aborts: a
  failed assertion inside `conformance` kills the worker outright, so the
  `try/catch` around each check never runs and anything merely accumulated in the
  worker dies with it. The worker posts each `console.error` to the page
  immediately; without that, a real failure reads only as
  `RuntimeError: unreachable`.

## Still open

- **Nothing calls `mount` in anger yet.** `Vault::in_memory` is still `MemFs`;
  wiring OPFS in belongs with the worker that hosts it.
- **The worker itself.** Message loop, command dispatch, and the
  `ensure_free` top-up between commands.
- **Capacity policy.** How many slots to open at mount, and how far ahead to keep
  the free list, are both unmeasured. `free_slots()` and `capacity()` are exposed
  for whatever policy the worker settles on.
