---
name: roam-embed-rust
description: Embed roam-sync as a Rust library in a native app — open a Store, wire the Engine over the iroh QUIC transport, mirror a real folder with FolderBridge, add the zero-knowledge backend as an offline fallback, pair a second device, manage roster roles and epoch rotation, and store data on something other than a filesystem via the VaultFs seam. Use when writing Rust that calls roam-storage / roam-sync-core / roam-files / roam-transport-iroh / roam-backend-client, adding sync to an existing Rust app, choosing between the CRDT text API and the file-folder API, or debugging convergence, roster rejection or blocked-peer hangs. Read roam-sync-overview first if it is not yet clear that roam fits.
---

# Embedding roam-sync in a Rust app

The `roam` CLI is the reference host app. When in doubt about wiring, read
`crates/roam-cli/src/main.rs` — `setup_engine` (~L849), `sync_folder` (~L994) and
`spawn_backend_sync` (~L789) are the three functions that show the whole shape.

## Pick your level

There are three, and choosing the wrong one causes most of the pain:

| Level | Use when | Entry point |
|---|---|---|
| **Folder** | Your app's data *is* files on disk | `roam_files::FolderBridge` |
| **Document** | Your app has its own model and just wants replicated text/maps | `Store::edit_text` / `Store::set_entry` |
| **CRDT only** | You want Loro semantics with no vault, keys or roster | `roam_crdt::Document` |

Do not mix the folder level and the document level over the same containers.
`FolderBridge` owns the mapping from path → container id; hand-editing those
containers behind its back desynchronises the sidecars.

## Level 1: the Store

```rust
use roam_storage::{Identity, Store, Role};

let identity = Identity::load(identity_path)?;      // or Identity::generate()
let mut store = Store::open(vault_dir, identity.clone())?;
store.declare_founder(Role::Admin)?;                // FOUNDER ONLY — see below
```

`declare_founder` is for the device that *creates* the vault. A device that will
**join** an existing vault must not call it — its vault and roster arrive from
the host during pairing. Getting this wrong produces two vaults that will never
converge, and the symptom (ops silently rejected) does not point at the cause.

A device's own vouch must fold in before its local writes are permitted. Check
with `store.may_write()` rather than assuming.

Useful surface (`crates/roam-storage/src/store.rs`):

```rust
store.set_entry(map_id, key, value)?;   store.get_entry(map_id, key);
store.edit_text(id, pos, text)?;        store.text(id);
store.delete_text(id, pos, len)?;
store.roster();                         store.role_of(peer_id);
store.add_peer(peer_id, key, role)?;    store.revoke_peer(peer_id, key)?;
store.self_role();                      store.may_write();
store.write_snapshot()?;                store.data_size()?;
store.text_history(container)?;         store.revert_text(container, &frontier)?;
store.checkpoint_dry_run(before_ts)?;   store.checkpoint(before_ts)?;
store.rotate_epoch(..)?;                store.recover_with_paper(..)?;
```

## Level 2: the Engine and a transport

```rust
use roam_sync_core::engine::Engine;
use roam_transport_iroh::transport::IrohTransport;

// Routes: peer_id -> verifying key, from the ACTIVE roster, minus yourself.
let routes: HashMap<u64, [u8; 32]> = store.roster().into_iter()
    .filter(|p| p.status == PeerStatus::Active && p.peer_id != identity.peer_id())
    .map(|p| (p.peer_id, p.verifying_key))
    .collect();

let transport = Arc::new(IrohTransport::spawn(&identity, routes).await?);
let engine = Arc::new(Engine::new(identity, vault_id, store, transport.clone(), vault_key));
tokio::spawn(engine.clone().run());
```

Two things that are easy to get wrong:

- **Hold the transport `Arc` yourself.** You need it to call `shutdown()`. See
  *Shutdown* below — this is not optional politeness.
- **Connect in the background.** An unreachable peer's dial blocks for ~15s
  (iroh's own timeout). Doing this on the startup path makes the app look hung.

The `Engine` owns the `Store` behind an `Arc<Mutex<_>>` from then on. Reach it
with `engine.store()` — **do not keep a second `Store` open on the same
directory.** Every writer must serialise on that one lock, which is exactly why
the backend sync task below takes `engine.store()` rather than opening its own.

Signals worth using: `engine.changed()` fires when remote data lands (drive your
UI off it) and `engine.local_flushed()` fires after every local flush (drive
backend push off it, instead of waiting out a poll interval).

## Level 3: mirroring a real folder

```rust
use roam_files::FolderBridge;

// Sidecars and blob markers live under the STORE dir, never in the user's folder.
let bridge = FolderBridge::new(&folder, &store_dir.join("filemeta"));

bridge.scan(&mut store)?;                 // reconcile the whole folder
bridge.import_file(&mut store, &path)?;   // disk  -> CRDT
bridge.project_file(&mut store, &path)?;  // CRDT  -> disk
bridge.delete_file(&mut store, &path)?;
bridge.rename_file(..)?;
bridge.list_deleted(&store);              // what restore could bring back
bridge.restore_all(..)?;  bridge.restore_paths(..)?;  bridge.revert_file(..)?;
```

**Files are classified by content, not extension.** UTF-8 → mergeable text
document; non-UTF-8 → whole-file binary blob, transferred pull-based on demand.
An app that wants a `.json` file to merge as text gets that for free; an app that
wants a UTF-8 file treated as opaque does *not*, and needs to handle that itself.

Create the folder before attaching a filesystem watcher — watching a
non-existent path fails and every scan then walks nothing.

## Adding the zero-knowledge backend

P2P alone requires both devices online at once. The backend is the fallback that
removes that constraint. It stores ciphertext under opaque ids and can decrypt
nothing.

```rust
use roam_backend_client::{crypto::VaultKey, http::HttpBackend, sync::reconcile_once};

let backend = Arc::new(HttpBackend::new(&backend_url));
let key = VaultKey(vault_key);
let store = engine.store();                  // the Engine's own Arc<Mutex<Store>>

reconcile_once(&store, &backend, &key).await?;   // one full push+pull pass
```

Run it on a timer *and* on `engine.local_flushed()`, so local edits push
immediately instead of waiting for the next tick. Register the notify waiter
**before** reconciling — `notify_waiters` stores no permit, so a flush that races
the pass would otherwise be lost.

`VaultKey` derives the bucket id, so every device of a vault must hold the same
32 bytes or they will address different buckets and never converge.

## Pairing a second device

```rust
use roam_transport_iroh::{host_pairing, join_pairing, host_lan_pairing, join_lan_pairing};
```

- **`host_lan_pairing` / `join_lan_pairing`** — six digits, SPAKE2-proved. The
  code never crosses the wire. Three wrong guesses retire it; mint a fresh one
  rather than retrying.
- **`host_pairing` / `join_pairing`** — a full-entropy `PairingToken`, moved out
  of band. Works over the internet.
- `roam_transport_iroh::discovery` browses the LAN over mDNS, passively.

Both flows end with the host vouching for the joiner in the roster and the vault
(including the vault key) crossing the proven channel.

## Storage that is not a filesystem

```rust
use roam_storage::vfs::{VaultFs, MemFs};
let store = Store::open_with_fs(Path::new("/vault"), identity, fs)?;
```

`VaultFs` is the seam that lets the same `Store` run on OPFS in a browser, or on
`MemFs` in tests. Implement it rather than shimming a filesystem underneath.

## Shutdown — read this one

roam's most persistent bug class: **one side blocked on a peer that is never
coming.** QUIC's only "the other end is gone" signals are a CONNECTION_CLOSE
frame or a ~30s idle timeout, and `Drop` cannot send the former because it
cannot await.

So, in any code you add:

- Anything that finishes and drops an endpoint must `endpoint.close().await`
  first — and that call must be **unconditional**, not sitting after a `?` where
  only the success path reaches it.
- Every read from a peer needs a bound. `open_bi` is lazy in QUIC: a peer that
  connects and never writes leaves `accept_bi()` pending forever.
- A signal handler must reach `transport.shutdown().await`.
  `std::process::exit(0)` runs no destructors, so every peer of every session
  keeps a dead connection until timeout.
- Ask a third question too: *who can end this session by any route?* An attempt
  budget, a fatal-error classification and an unflushed close are the same bug
  wearing different clothes.

These never show up in library tests, where both sides live in one process that
stays up. Test them across two real processes, and **assert timing** (the server
exits within N seconds of the client) — a missing close reads as a slow suite,
not a failure.

## Security invariants you must not break

- **Roles are enforced receiver-side**, on import. A peer that ignores its own
  role is caught by its counterparties, not by itself. Never build a flow that
  trusts a peer to police its own writes.
- **Grants bind peer-id ↔ verifying key.** Never key a role off the peer id
  alone.
- **Rotation protects the future, not the past.** `rotate_epoch` excludes
  revoked members from the new epoch; already-written data stays under the old
  one and is *not* re-encrypted.
- **The vault key is the vault.** Never persist it in `localStorage`, a URL
  fragment, a log line or a crash report.
- **Backend bucket routes are unauthenticated by design.** Possession of the key
  is the authorisation. Anything mutable the server holds must be signed.

## Testing

- `MemFs` + `MemoryBackend` give a full vault with no filesystem and no server —
  most behaviour should be provable that way.
- Property-test convergence: random op orderings must reach identical state.
- For anything liveness-related, use two real processes; see above.
- `ROAM_DEBUG=1` enables `[engine]` and `[transport]` stderr traces.
- Build with `CARGO_BUILD_JOBS=1 ... -j1` in this repo; parallel builds exhaust
  memory and disk.
