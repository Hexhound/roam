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

### Binary rides beside the envelope

Attachments are megabytes. Base64 inside the JSON would cost a third more bytes
and, worse, push the whole payload through a parser twice on each side for data
that is opaque anyway. So `putBlob` and `getBlob` carry their bytes *alongside*
the envelope — `Session::handle` takes and returns an `Option<Vec<u8>>`, and the
worker moves it as a **transferable**, so the buffer changes owner rather than
being copied.

Blobs are the only thing this carries, which is exactly the right boundary: blob
bytes already live outside the CRDT, with only a hash-reference on the op log.

Two details that are easy to get wrong, and are pinned by tests:

- **A zero-length blob is present.** `getBlob` answers `{ "len": 0 }` with an
  empty payload; a *missing* blob answers a bare `null`. Collapse the two and a
  caller re-fetches an attachment it already holds, forever.
- **`putBlob` with no payload is an error**, not an empty blob — writing zero
  bytes under a hash nobody asked for is silent corruption of the reference.

`wasm_bindgen` cannot return two values, so the binding splits into
`handleWithBytes` and `takeReplyBytes`. Stashing the bytes on the session
between those two calls is safe for the same reason the queue exists: one
command at a time. `takeReplyBytes` *takes*, so a large attachment is not held
alive after the page has read it.

### Changes ride on the reply, and there is no push channel

An embedder projecting a vault into its own database has to be told what moved.
The obvious design is an unsolicited worker→page channel — and it turns out to
be unnecessary, because **nothing changes a vault except a command.** A local
edit is a command; pulling a peer's ops is `sync`, also a command. So each reply
carries the map delta its own command produced, under `changes`, omitted when
empty.

That is strictly better than a side channel, not merely simpler: ordering is
correct by construction, since a caller cannot observe a change before the reply
that caused it.

`changes` is key-level over *maps* (`Store::map_delta`), so text containers are
not in it — a caller projecting text re-reads it after a `sync`. A `null` value
is a deletion, which is why the array carries values rather than just names;
this protocol has no delete command yet, so the encoding is ahead of its use.

### The two ids `open` hands back

`open` replies with `{ bucketId, peerId }` rather than `null`. Both are fixed for
the life of a session, and `bucketId` in particular is a **synchronous** getter
on CareMate's Dart port — it cannot become a `Future` merely because one platform
computes it in another agent. So it is fetched once and cached.

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

**Closed.** A device that *joins* an existing vault must not found one of its
own. The two cases cannot be told apart from the arguments, so they are separate
constructors rather than a flag: `Vault::open` founds, `Vault::join` adopts a
pairing accept and does not. A joiner that founded would pin *itself* as founder
of a vault it did not create, and the host's roster — anchored on the real
founder — could never fold over it; the failure is silent, just two vaults that
never converge. `tests/join.rs` covers it, and all three of its checks fail if
the founding is put back.

### Joining runs before storage exists

`Session.joinOnOpfs(invite, code)` finishes the whole handshake *before* it
mounts anything. That is forced rather than chosen: the OPFS pool directory is
named after the bucket id, the bucket id is derived from the vault key, and the
vault key arrives inside the accept. It is safe because the joiner's store is
untouched until the accept is adopted — everything before that is network and
cryptography — and it has a useful consequence: a failed join leaves nothing
behind, no pool and no identity.

The reply carries `vaultKey`, which `open` does not, because the direction is
reversed. A founder passes the key in; a joiner does not have it until the
handshake succeeds, and without it the next page load could not reopen the vault
it just joined. It is transferred rather than copied, so the worker is not left
holding a second reachable copy of the whole vault.

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
converging through a relay, that a pulled change is reported on the `sync` reply
that caused it, that a read reports no changes at all, and that no input produces
silence. `tests/durable_vault.rs` covers reopening, over a remounted slot pool.

Mutation-checked: suppressing `changes` fails two tests, and making a missing
blob answer like an empty one fails a third.

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
- a failing command rejects without killing the session;
- **1 MiB of blob bytes really is transferred, not copied.** The page checks its
  own `Uint8Array` is detached after the send, which is the only observable
  difference between a transfer and a structured clone — and then a *second*
  worker reads the bytes back, so this also proves they reached OPFS rather than
  living in the first session's memory;
- `open` reports a `bucketId` matching the command, and a write reports its own
  `changes`.

Each check uses its own vault key, and that is not tidiness. Sharing one key made
the checks share a vault — every check inserted text at position 0, and their
writes interleaved into one string. Durability couples tests to each other; that
is exactly the failure mode `MemFs` never exhibits.

## Flutter web ↔ roam-wasm: why frb's thread pool cannot host this

The named spike, now run. The question was whether roam's storage could live
inside `flutter_rust_bridge`'s SharedArrayBuffer thread pool instead of a worker
of its own — which would have kept one bridge for all platforms.

It cannot, and the reason is a property of the browser, not of frb. wasm threads
are separate **agents**: they share linear memory but not the JS heap, and a
`JsValue` is an index into a per-agent table. So the question reduces to whether
a sync access handle can cross an agent boundary. Measured, Chromium 151:

| attempt | result |
|---|---|
| `structuredClone(handle)` in the same agent | `DataCloneError` — cannot be cloned |
| `postMessage(handle)` to the page | `DataCloneError` |
| `postMessage(handle)` to another worker | `DataCloneError` |
| `postMessage(handle, [handle])` as a transferable | `DataCloneError` — "does not have a transferable type" |
| another agent opening the same file while the first holds it | `NoModificationAllowedError` |

The last row is what closes the door. A handle can neither be *moved* to another
thread nor *re-opened* there, so whichever thread opens the pool must be the only
thread that ever touches it — for the life of the pool. frb's default pool is
[four threads](https://github.com/fzyzcjy/flutter_rust_bridge/discussions/1007)
with no affinity guarantee, so this is unsound rather than slow: the failure is a
`NoModificationAllowedError` on whichever call happens to land elsewhere.

This is also the measurement behind the `unsafe impl Send + Sync for OpfsSlot` in
`vfs_opfs.rs`. Its justification — "exactly one thread per agent on wasm32" — is
true only while roam owns its worker. Enabling wasm threading would falsify it,
and nothing in the type system would notice.

frb is not *strictly* ruled out: a custom `BaseThreadPool` with a single thread
would restore affinity. But that gives up frb's concurrency entirely, still
requires COOP/COEP and a separate Safari build (Safari cannot spawn nested
workers), and leans on an undocumented invariant — while buying nothing over a
worker roam already owns.

**So: the web client talks to `roam-worker.js` directly.** CareMate already has
the seam for it — `lib/data/sync/vault_port.dart` is a 22-method abstraction with
one implementation today (`roam_vault_port.dart`, frb-backed); web adds a second,
and nothing above the port changes. frb stays for Android and iOS.

Three things that implementation needed, all three now built on the roam side —
though one of them turned out not to need what this doc first said it did:

- **Binary.** `putBlob`/`getBlob` are `List<int>` on the port. Now carried
  beside the envelope as transferables; see above.
- **`Stream<VaultChange> get changes`.** Predicted here as needing an
  unsolicited push channel. It does not: nothing changes a vault except a
  command, so the delta rides on the causing command's own reply and the Dart
  side pumps it into a `StreamController`. No second channel exists.
- **`String get bucketId`.** Returned by `open` and cached, since it is the
  port's one synchronous getter.

The standing cost of this route is that the protocol is a hand-written contract
in three places (Rust enum ↔ JSON ↔ Dart), where frb's codegen would have kept
two of them in step automatically. `tests/session.rs` guards the Rust half; the
Dart half will need its own.

## Still open
- **The Dart `web_vault_port.dart` itself.** The roam side of the contract is
  complete; the second implementation of the 22-method port is not written.
- **Hosting an invite from a browser.** `joinOnOpfs` lets a browser *join*; there
  is no binding for the other side, so a browser member cannot yet invite a
  third device. Nothing structural blocks it — `roam_pairing::host_via_mailbox`
  is the same wasm-portable code — it is simply not wired.
- **`joinOnOpfs` inside a real browser.** The join logic is covered natively
  (`roam-pairing`'s suite, and `roam-wasm/tests/join.rs` for the browser-shaped
  wiring on `MemFs`), and the CLI pairs end-to-end through a live Phoenix relay.
  What has NOT been run is `joinOnOpfs` in Chromium against a relay: the headless
  harness has no host process to pair with. The untested part is the mount
  ordering, not the protocol.
- **Key handling.** `vaultKey` arrives from the page, so it is XSS-exposed. It
  must be derived per session and never persisted in the clear — see the security
  notes on `WasmVault`.
- **Blob transfer between devices.** `putBlob`/`getBlob` are local; a browser
  that syncs an op-log referencing a blob it does not hold still has no way to
  fetch the bytes.
