//! Hermetic end-to-end test: a REAL vault folder syncs between two endpoints
//! over the ACTUAL iroh transport (loopback), driven through the sync engine
//! and the folder bridge.
//!
//! This is the folder-level analogue of
//! `roam-transport-iroh/tests/e2e.rs::two_real_endpoints_catch_up_offline_edits`:
//! it reuses that harness verbatim (two `Identity`s, one shared `VaultId`, two
//! `Store`s with cross `add_peer` roster trust, two `IrohTransport::spawn` wired
//! for loopback via `add_addr`/`endpoint_addr`, two `Engine`s each `run()` in a
//! spawned task, mutual `connect`), and layers a `FolderBridge` per endpoint on
//! top so a disk change on A propagates through the CRDT to B's disk.
//!
//! Placement: `roam-cli` is the only crate that already depends on all three of
//! `roam-files`, `roam-sync-core`, and `roam-transport-iroh` (see its
//! Cargo.toml). `roam-transport-iroh` may NOT depend on `roam-files` (that would
//! cross-link the transport with the disk bridge), so the test lives here where
//! the three can be composed.
//!
//! REAL NETWORKING: these tests use the loopback iroh transport, so they are
//! slightly slower and marginally less deterministic than the pure unit tests.
//! Every wait is a bounded poll with a hard timeout — the test FAILS with a
//! clear message rather than hanging if convergence does not happen.
//!
//! Structure: all three scenarios (create, delete, rename) run as sequential
//! phases inside ONE test function sharing one pair of endpoints. Standing up
//! three independent full-transport endpoint pairs would triple the (real)
//! network setup cost for no added coverage — the phases are independent (they
//! use distinct filenames) and each polls to a fully-converged state before the
//! next begins.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use roam_files::{container_id, EntryStatus, FileEntry, FolderBridge, SyncOutcome, FILESET_MAP_ID};
use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_transport_iroh::IrohTransport;
use tempfile::TempDir;

/// Total time to wait for one scenario to converge across the loopback network
/// before failing. Real networking means a couple of seconds is normal; 10s is
/// a generous ceiling that still fails fast on a genuine stall.
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(10);
/// Poll interval between re-scans while waiting for convergence.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// One endpoint: its vault dir, the bridge over it, and the engine that owns the
/// Store the bridge reconciles against.
struct Endpoint {
    /// Kept alive so the tempdir is not deleted for the test's lifetime.
    _vault_dir: TempDir,
    /// Kept alive so the store's tempdir is not deleted for the test's lifetime.
    _store_dir: TempDir,
    vault: PathBuf,
    bridge: FolderBridge,
    engine: Arc<Engine<IrohTransport>>,
}

/// Drive one endpoint's reconcile against ITS engine's shared store, then gossip
/// any resulting local ops to connected peers.
///
/// Locks the store directly (`lock().await`) — this is a single-threaded test
/// with no competing blocking runtime, so the CLI's `spawn_blocking` +
/// `blocking_lock` dance is unnecessary. The ONE discipline that still matters:
/// drop the store guard BEFORE awaiting `flush_local` (never hold a lock across
/// a transport await).
async fn scan(endpoint: &Endpoint) -> Vec<(PathBuf, SyncOutcome)> {
    let store = endpoint.engine.store();
    let outcomes = {
        let mut guard = store.lock().await;
        endpoint.bridge.scan(&mut guard).expect("scan must succeed")
    }; // guard dropped here, before the flush await.
    endpoint.engine.flush_local().await;
    outcomes
}

/// Repeatedly `scan(endpoint)` (projecting inbound CRDT state to disk and
/// flushing any local delta) until `done()` returns true or the timeout
/// elapses. Panics with `label` on timeout so the test fails loudly instead of
/// hanging.
async fn sync_until(endpoint: &Endpoint, mut done: impl FnMut() -> bool, label: &str) {
    let start = Instant::now();
    loop {
        scan(endpoint).await;
        if done() {
            return;
        }
        if start.elapsed() > CONVERGE_TIMEOUT {
            panic!(
                "timed out after {:?} waiting for: {label}",
                CONVERGE_TIMEOUT
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Blob-aware convergence pump. Blobs are PULL-based: gossip carries only the
/// Blob file-set entry (the blob-ref), not the bytes, so before a fetched blob
/// can be projected to disk the endpoint must request the missing bytes
/// (`request_missing_blobs` → BlobWant → peer replies BlobData). Each round
/// requests any missing blobs, waits briefly for the reply to arrive and fire
/// `changed()`, then scans (which projects a now-local blob to disk). Used on
/// the RECEIVING side of a binary-file scenario.
async fn sync_until_with_blobs(endpoint: &Endpoint, mut done: impl FnMut() -> bool, label: &str) {
    let start = Instant::now();
    loop {
        endpoint.engine.request_missing_blobs().await;
        scan(endpoint).await;
        if done() {
            return;
        }
        if start.elapsed() > CONVERGE_TIMEOUT {
            panic!(
                "timed out after {:?} waiting for: {label}",
                CONVERGE_TIMEOUT
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Read the file-set entry for `file` from `endpoint`'s store, if present.
async fn entry_for(endpoint: &Endpoint, file: &Path) -> Option<FileEntry> {
    let container = container_id(&endpoint.vault, file).expect("container id");
    let store = endpoint.engine.store();
    let guard = store.lock().await;
    guard
        .get_entry(FILESET_MAP_ID, &container)
        .map(|value| FileEntry::from_value(&value).expect("valid file-set entry"))
}

#[tokio::test(flavor = "multi_thread")]
async fn real_folder_create_delete_rename_syncs_over_iroh() {
    // --- Harness: mirror roam-transport-iroh/tests/e2e.rs exactly. ---
    let vault_dir_a = tempfile::tempdir().unwrap();
    let vault_dir_b = tempfile::tempdir().unwrap();
    let store_dir_a = tempfile::tempdir().unwrap();
    let store_dir_b = tempfile::tempdir().unwrap();
    let vault_a = vault_dir_a.path().to_path_buf();
    let vault_b = vault_dir_b.path().to_path_buf();

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();
    let vault_id = VaultId::generate();

    let mut store_a = Store::open(store_dir_a.path(), identity_a.clone()).unwrap();
    let mut store_b = Store::open(store_dir_b.path(), identity_b.clone()).unwrap();
    // Each device founds its own vault as admin so its own `add_peer` vouches fold.
    store_a.declare_founder(Role::Admin).unwrap();
    store_b.declare_founder(Role::Admin).unwrap();
    // Cross-trust: each device vouches for the other in its roster.
    store_a
        .add_peer(
            identity_b.peer_id(),
            identity_b.verifying_key().to_bytes(),
            Role::Admin,
        )
        .unwrap();
    store_b
        .add_peer(
            identity_a.peer_id(),
            identity_a.verifying_key().to_bytes(),
            Role::Admin,
        )
        .unwrap();

    // Transport routes: each transport knows the other peer's key.
    let mut routes_a = HashMap::new();
    routes_a.insert(identity_b.peer_id(), identity_b.verifying_key().to_bytes());
    let mut routes_b = HashMap::new();
    routes_b.insert(identity_a.peer_id(), identity_a.verifying_key().to_bytes());
    let transport_a = IrohTransport::spawn(&identity_a, routes_a).await.unwrap();
    let transport_b = IrohTransport::spawn(&identity_b, routes_b).await.unwrap();
    // Loopback reachability: exchange node addrs.
    transport_a
        .add_addr(identity_b.peer_id(), transport_b.endpoint_addr())
        .await;
    transport_b
        .add_addr(identity_a.peer_id(), transport_a.endpoint_addr())
        .await;

    let engine_a = Arc::new(Engine::new(
        identity_a.clone(),
        vault_id,
        store_a,
        Arc::new(transport_a),
    ));
    let engine_b = Arc::new(Engine::new(
        identity_b.clone(),
        vault_id,
        store_b,
        Arc::new(transport_b),
    ));
    tokio::spawn(engine_a.clone().run());
    tokio::spawn(engine_b.clone().run());

    // Mutual connect so ops flow both ways.
    engine_a.connect(identity_b.peer_id()).await.unwrap();
    engine_b.connect(identity_a.peer_id()).await.unwrap();

    // Metadata dirs live under each device's STORE dir (outside the vault),
    // mirroring the CLI's `<vault>/filemeta`.
    let meta_a = store_dir_a.path().join("filemeta");
    let meta_b = store_dir_b.path().join("filemeta");
    let a = Endpoint {
        _vault_dir: vault_dir_a,
        _store_dir: store_dir_a,
        vault: vault_a.clone(),
        bridge: FolderBridge::new(&vault_a, &meta_a),
        engine: engine_a,
    };
    let b = Endpoint {
        _vault_dir: vault_dir_b,
        _store_dir: store_dir_b,
        vault: vault_b.clone(),
        bridge: FolderBridge::new(&vault_b, &meta_b),
        engine: engine_b,
    };

    // ================================================================
    // Phase 1 — file create propagates A -> B.
    // ================================================================
    let hello_a = vault_a.join("hello.md");
    let hello_b = vault_b.join("hello.md");
    std::fs::write(&hello_a, "hello world\n").unwrap();
    scan(&a).await; // import + gossip.

    sync_until(&b, || hello_b.exists(), "hello.md to appear on B").await;
    assert_eq!(
        std::fs::read(&hello_b).unwrap(),
        b"hello world\n",
        "B's hello.md must hold A's bytes"
    );
    let entry = entry_for(&b, &hello_b)
        .await
        .expect("B must have a file-set entry for hello.md");
    assert_eq!(
        entry.status,
        EntryStatus::Live,
        "hello.md entry on B must be Live"
    );

    // ================================================================
    // Phase 2 — delete propagates A -> B.
    // First establish a synced `doc.md` on both sides.
    // ================================================================
    let doc_a = vault_a.join("doc.md");
    let doc_b = vault_b.join("doc.md");
    std::fs::write(&doc_a, "doc body\n").unwrap();
    scan(&a).await;
    sync_until(&b, || doc_b.exists(), "doc.md to appear on B").await;
    assert_eq!(std::fs::read(&doc_b).unwrap(), b"doc body\n");

    // Now delete doc.md on A and gossip the tombstone.
    {
        let store = a.engine.store();
        {
            let mut guard = store.lock().await;
            a.bridge.delete_file(&mut guard, &doc_a).unwrap();
        } // guard dropped before flush.
        a.engine.flush_local().await;
    }
    assert!(!doc_a.exists(), "doc.md must be gone from A's disk");

    sync_until(&b, || !doc_b.exists(), "doc.md to be removed from B").await;
    let entry = entry_for(&b, &doc_b)
        .await
        .expect("B must retain a tombstone entry for doc.md");
    assert_eq!(
        entry.status,
        EntryStatus::Tombstoned,
        "doc.md entry on B must be Tombstoned"
    );

    // ================================================================
    // Phase 3 — rename propagates A -> B.
    // First establish a synced `old.md` on both sides.
    // ================================================================
    let old_a = vault_a.join("old.md");
    let old_b = vault_b.join("old.md");
    let new_b = vault_b.join("new.md");
    std::fs::write(&old_a, "content\n").unwrap();
    scan(&a).await;
    sync_until(&b, || old_b.exists(), "old.md to appear on B").await;
    assert_eq!(std::fs::read(&old_b).unwrap(), b"content\n");

    // Rename old.md -> new.md on A and gossip.
    let new_a = vault_a.join("new.md");
    {
        let store = a.engine.store();
        {
            let mut guard = store.lock().await;
            a.bridge.rename_file(&mut guard, &old_a, &new_a).unwrap();
        } // guard dropped before flush.
        a.engine.flush_local().await;
    }
    assert!(!old_a.exists(), "old.md must be gone from A's disk");
    assert_eq!(std::fs::read(&new_a).unwrap(), b"content\n");

    sync_until(
        &b,
        || new_b.exists() && !old_b.exists(),
        "new.md to appear and old.md to vanish on B",
    )
    .await;
    assert_eq!(
        std::fs::read(&new_b).unwrap(),
        b"content\n",
        "B's new.md must carry the renamed content"
    );
    assert!(!old_b.exists(), "old.md must be gone from B's disk");

    // ================================================================
    // Phase 4 — BINARY (blob) create then delete propagates A -> B.
    // Exercises the full pull-based blob path over the real transport: the
    // Blob file-set entry gossips, B requests the missing bytes
    // (BlobWant/BlobData), then projects them byte-identically to disk (D5).
    // ================================================================
    let pic_a = vault_a.join("pic.png");
    let pic_b = vault_b.join("pic.png");
    // Non-UTF-8 payload with an asset extension → routes to the blob store.
    let pixels: Vec<u8> = vec![
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0x00, 0x7f,
    ];
    std::fs::write(&pic_a, &pixels).unwrap();
    scan(&a).await; // import_blob (bytes + Live Blob entry + marker) + gossip.

    sync_until_with_blobs(&b, || pic_b.exists(), "pic.png to appear on B").await;
    assert_eq!(
        std::fs::read(&pic_b).unwrap(),
        pixels,
        "B's pic.png must be byte-identical to A's blob"
    );
    let entry = entry_for(&b, &pic_b)
        .await
        .expect("B must have a file-set entry for pic.png");
    assert_eq!(
        entry.status,
        EntryStatus::Live,
        "pic.png entry on B must be Live"
    );

    // Delete the binary on A (raw fs remove → scan detects the local delete via
    // the presence marker and writes a Blob tombstone), gossip it.
    std::fs::remove_file(&pic_a).unwrap();
    scan(&a).await;
    let entry_a = entry_for(&a, &pic_a)
        .await
        .expect("A must retain a tombstone entry for pic.png");
    assert_eq!(
        entry_a.status,
        EntryStatus::Tombstoned,
        "pic.png entry on A must be Tombstoned after local delete"
    );

    sync_until(&b, || !pic_b.exists(), "pic.png to be removed from B").await;
    let entry_b = entry_for(&b, &pic_b)
        .await
        .expect("B must retain a tombstone entry for pic.png");
    assert_eq!(
        entry_b.status,
        EntryStatus::Tombstoned,
        "pic.png entry on B must be Tombstoned",
    );
}
