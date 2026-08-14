---
name: roam-wasm-browser
description: Run a roam vault in the browser via roam-wasm — the Doc and Vault JS classes, syncing through the zero-knowledge relay with fetch, why a web client is a relay leaf and can never be a P2P peer, OPFS vs in-memory durability, wasm32 pitfalls (SystemTime traps, peer-id collisions), and where the vault key may and may not be kept. Use when adding roam sync to a web app, PWA, browser extension or Electron renderer, building the JS/TS side of a roam client, compiling roam to wasm with wasm-pack, or debugging a browser client that will not converge with a native device. Read roam-sync-overview first if it is not yet clear that roam fits.
---

# roam in the browser

`crates/roam-wasm` is the browser façade. It is deliberately split in two:

- `Doc` / `Vault` in `src/doc.rs` and `src/vault.rs` — **plain Rust**, no
  `wasm_bindgen`, exercised by ordinary native tests.
- `src/bindings.rs` — the `#[wasm_bindgen]` shim, wasm32-only, **pure
  delegation**.

That split is load-bearing: nothing interesting should be testable only through
a browser. If you add logic, add it to `Doc`/`Vault` and let `bindings` forward.

## The one architectural fact

**A browser can never be a P2P peer.** It cannot open raw UDP/QUIC, so it cannot
be an iroh endpoint. A web client syncs *exclusively* through the backend relay.

This is not a weakening of the threat model — the `Backend` trait moves
already-encrypted bytes and never encrypts or decrypts, so the relay sees the
same ciphertext and opaque ids either way. But it does mean:

> **The web client always requires a running backend.** There is no
> browser-to-browser and no browser-to-desktop direct path. Do not promise
> offline peer sync in a web app.

## The JS surface

Built with `wasm-pack`. Two classes and one free function.

### `Vault` — a whole vault

```js
import init, { Vault, bucketId } from "./pkg/roam_wasm.js";
await init();

const vault = new Vault(vaultKey);          // vaultKey: 32 bytes (Uint8Array)

await vault.peerId();                       // bigint
await vault.verifyingKey();                 // Uint8Array(32)
await vault.addPeer(peerId, verifyingKey);  // vouch for another device

await vault.setEntry(container, key, value);
await vault.getEntry(container, key);       // string | undefined
await vault.editText(id, at, text);
await vault.text(id);                       // string

await vault.writeSnapshot();
await vault.sync(baseUrl);                  // one full push+pull against the relay

bucketId(vaultKey);                         // the relay bucket these bytes address
```

`sync` is **one reconcile pass**, not a subscription. Drive it yourself: on an
interval, on visibility change, and after local edits. Everything crossing the
wire is ciphertext.

The constructor **founds the vault as Admin** — a device's own vouch must fold
before its local writes are permitted. Two browsers constructed with the same
key each found independently and then reconcile through the relay; they must
still `addPeer` each other for their ops to be accepted.

### `Doc` — the CRDT alone

```js
const doc = new Doc(peerId);
doc.insertText(id, pos, s);   doc.text(id);
doc.setEntry(mapId, k, v);    doc.getEntry(mapId, k);
doc.commit();
const bytes = doc.snapshot(); doc.import(bytes);
```

Use this when you want Loro semantics with no vault, keys, roster or relay — a
collaborative editor whose transport you already own, for instance.

## Durability: the thing to get right first

`Vault::in_memory` runs on `MemFs`. It is real and correct and **not durable** —
closing the tab loses the vault entirely. The current `bindings` constructor uses
it.

The durable browser backend is an **OPFS implementation of `VaultFs`**, which is
deliberately still to come. Storage is a constructor argument precisely so that
swap is a one-line change:

```rust
Vault::open(fs: Arc<dyn VaultFs>, vault_key: [u8; 32])
```

So: if you are building anything a user would be upset to lose, implementing
OPFS `VaultFs` is the first task, not an optimisation. Do not ship
`in_memory` behind a UI that implies persistence.

## Where the vault key may live

**The vault key is the whole vault.** It derives the content keys and the bucket
id.

- **Never** in `localStorage` or `sessionStorage`.
- **Never** in a URL fragment.
- **Never** in a log line, error report or analytics event.

Deriving it from a passphrase in-session, or holding it only in memory for the
tab's lifetime, are the honest options. Anything that survives a tab close
without a user secret is storing the vault in the clear.

## wasm32 pitfalls that have actually bitten

- **`SystemTime::now()` traps on wasm32** — it does not return a wrong answer, it
  aborts. Use `roam_storage::wallclock`. `writeSnapshot` is the vault operation
  that reads the clock (it stamps a history marker), which is why it is worth
  exercising in the browser specifically.
- **Peer ids must be unique.** A browser session must use an id distinct from
  every other peer in the vault, or their op logs collide. Do not derive one
  from something stable-but-shared like a user id.
- **`Vault` is `Clone` and cloning shares, not copies** — the store is behind an
  `Arc`. The async binding methods need an owned handle to move into the returned
  future; that is the only reason.

## Testing

Three layers, and they are complementary — none replaces another:

1. **Native tests** against `MemoryBackend` (`crates/roam-wasm/tests/`) — cover
   all the logic, because `Doc`/`Vault` are plain Rust.
2. **The node acceptance harness** — proves the client half, the encryption, the
   RBSR protocol, `fetch`, and real HTTP over a real socket. It uses the
   `TestRelay` export (behind the `test-relay` cargo feature, so it can never be
   in a shipped artifact), which wraps `MemoryBackend` rather than
   reimplementing set reconciliation in JavaScript.
3. **`roam-backend-client/tests/e2e_backend.rs`** — runs the real Phoenix server,
   and is the only thing that proves the production backend agrees.

`TestRelay` maps onto the real HTTP routes: `put` returns true for created /
false for already-present, which the harness turns into 201 vs 409; `get`
returning `undefined` becomes a 404.

## When the browser will not converge with a native device

Check in this order:

1. **Same vault key?** Different keys mean different buckets. Compare
   `bucketId(vaultKey)` on both sides — that is the cheapest decisive test.
2. **Same relay URL**, and is the relay actually reachable (CORS, mixed content)?
3. **Has each side vouched for the other?** Unvouched ops are silently rejected
   on import; that is by design and looks exactly like "sync is broken".
4. **Distinct peer ids?**
5. Is `sync` actually being called, or was it assumed to be a subscription?
