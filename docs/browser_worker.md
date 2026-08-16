# The browser worker: hosting roam off the main thread

M4. The other half of `browser_storage_opfs.md`: that doc built durable storage
and ended with "nothing calls `mount` in anger yet". This is what calls it.

Read `browser_storage_opfs.md` first — the constraint below comes from there.

## The constraint, restated

OPFS sync access handles **do not exist** on a document's main thread. Not
restricted, not permission-gated: the property is `undefined` (measured, Chromium
150 and 151). `VaultFs` is synchronous, so roam's storage needs those handles, so
**roam cannot run on the main thread.**

Everything below follows from that one fact. A worker means a `postMessage`
boundary; a boundary means a protocol; a protocol means somewhere to put the
top-up that keeps the slot pool from running dry.

## The layering, and why the JS file is empty of decisions

```
page  ──postMessage──▶  worker/roam-worker.js  ──▶  Session (Rust)  ──▶  Vault ──▶ SlotPool ──▶ OPFS
        JSON objects      transport only            the protocol
```

`roam_wasm::session` is plain Rust and holds every decision about what a command
means. `worker/roam-worker.js` parses, forwards, serializes, replies. This is the
same split as `Doc`/`bindings`, for the same reason: **anything implemented in
the worker could only ever be tested in a browser.** `tests/session.rs` runs the
whole protocol — including a two-device sync — under an ordinary `cargo test`.

The JS keeps exactly two behaviours, and both are transport concerns:

- **A request queue.** Commands run one at a time. Not for throughput:
  `Session.handle` tops the pool up before dispatching, and the top-up reads the
  pool's capacity and *then* awaits `createSyncAccessHandle`. Two overlapping
  calls would both observe the same capacity and both open the same slot index —
  and OPFS enforces exclusivity, so the second fails with
  `NoModificationAllowedError`. `Session::handle` documents that it is not
  re-entrant.
- **Immediate panic forwarding.** wasm32 panics are aborts. A panic kills the
  worker, taking every in-flight reply with it, so anything merely accumulated
  there dies too. The Rust panic hook writes to `console.error` in the one moment
  the message exists; the worker posts it to the page right then.

The panic hook moved out of the test-only module in this slice. A shipped build
needs it for the same reason a test one does — without it the page sees
`RuntimeError: unreachable` and nothing else.

## The protocol

One JSON object per request, tagged by `command`, replying with exactly one of
`ok` / `error` and the caller's `id` echoed:

```json
{ "id": 7, "command": "setEntry", "container": "meta", "key": "title", "value": "Hi" }
{ "id": 7, "ok": null }
```

Three encoding rules, each of which is a bug avoided rather than a preference:

| rule | why |
|---|---|
| peer ids cross as **strings** | a peer id is a `u64`; JSON numbers are doubles. Above 2^53 it would arrive silently rounded, and a rounded peer id is not an approximate device, it is a different device |
| keys cross as **base64url, unpadded** | matches how roam already encodes entry and blob ids |
| a text container is `textId`, never `id` | the envelope owns `id`. JSON does not reject a duplicated key — parsers keep one of them — so the collision would not have been an error, it would have edited a container named `"7"` |

`handle` is infallible: malformed JSON, an unknown command and a failed vault
operation all produce an envelope. A worker that stays silent leaves the page
holding a promise that never settles, which is strictly worse than an error —
there is nothing to show a user and nothing to log.

## Opening: the pool directory is derived, not chosen

`Session.openOnOpfs(vaultKey, relayUrl)` mounts `.roam-<bucketId>`, where the
bucket id is already derived from the vault key. Three things fall out for free:

- reopening is automatic — the same key finds the same files;
- two vaults in one origin cannot collide, which would not be a merge but a
  `NoModificationAllowedError` at mount, since the first pool still holds every
  handle;
- nothing new is disclosed: the bucket id is the vault's opaque public name at
  the relay already.

## Durability changed what `open` has to mean

Against `MemFs` every open *is* a first open, so `Vault::open` could generate an
identity and declare a founder unconditionally. Against OPFS both are wrong on
the second open, and neither fails quietly:

- a fresh identity per reload makes the device a stranger to its own op log;
- `declare_founder` returns `"vault founder already pinned"`, so **reopening
  simply fails** — the second visit to the site could not open the vault at all.

So the identity is now persisted through the same `VaultFs` as everything else
(inside the origin's private filesystem, never `localStorage`), and founding is
conditional on there being no founder. `tests/durable_vault.rs` covers this over
a remounted slot pool, because `MemFs` structurally cannot.

Mutation-checked both ways: making `declare_founder` unconditional, and
regenerating the identity, each fail those tests.

**Known gap.** A device that *joins* an existing vault must not found one of its
own, and nothing can yet tell the two cases apart — browser pairing does not
exist. When it does, joining has to supply the roster out of band and take the
"already founded" path.

## Capacity policy

`MOUNT_CAPACITY = 64`, `KEEP_FREE = 16`. Starting values, not measured ones. The
floor is that a vault's fixed files (identity, founder pin, roster and key logs,
this device's op log, the snapshot) are on the order of ten, and everything above
that is one slot per blob chunk. The ceiling is that each slot is one
`createSyncAccessHandle`, so mount cost is linear in `MOUNT_CAPACITY`.

`KEEP_FREE` exists because a single command must never be able to exhaust the
pool: there is nowhere to await a refill inside a synchronous `VaultFs` call, so
exhaustion mid-command is a provisioning bug, not a recoverable condition.

## Validation

**Native** (`cargo test -p roam-wasm`) — `tests/session.rs` covers the protocol,
including two sessions vouching for each other over commands alone and
converging through a relay, and that no input produces silence.
`tests/durable_vault.rs` covers reopening, over a remounted slot pool.

**Real browser** (`crates/roam-wasm/tests/browser/run.sh`) — five checks that
drive the *shipped* worker file from a page, alongside the four OPFS checks. The
harness serves `worker/roam-worker.js` from its source rather than copying it in,
so the checks cannot pass against a worker nobody ships. They cover only what
needs a browser:

- the worker loads, initialises wasm, and mounts OPFS at all;
- a **terminated** worker releases its sync access handles. `terminate()` does
  not run Rust's `Drop`, so nothing calls `close()` — the browser has to release
  them when it tears the agent down. If it did not, closing a tab would leave the
  vault locked by `NoModificationAllowedError`;
- a vault opened by a later worker is the same vault, seen by the same device;
- 24 commands fired without awaiting all land, which is the queue doing its job;
- a failing command rejects without killing the session.

Each check uses its own vault key, and that is not tidiness. Sharing one key made
the checks share a vault — every check inserted text at position 0, and their
writes interleaved into one string. Durability couples tests to each other; that
is exactly the failure mode `MemFs` never exhibits.

## Still open

- **Flutter web ↔ roam-wasm.** The named spike, and the real unknown.
  `flutter_rust_bridge` 2.11.1 runs Rust on the main thread by default on web,
  which the probe rules out. Either frb has a worker mode that fits, or the web
  client talks to `roam-worker.js` over `dart:js_interop` and skips frb entirely.
- **Pairing a browser session.** Relay leaf only — no iroh, no LAN. Until it
  exists, `openOnOpfs` always founds a new vault.
- **Blobs over the protocol.** No command carries binary yet; attachments will
  need transferables rather than JSON.
- **Key handling.** `vaultKey` arrives from the page, so it is XSS-exposed. It
  must be derived per session and never persisted in the clear — see the security
  notes on `WasmVault`.
