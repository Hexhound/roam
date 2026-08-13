//! Large (multi-chunk) binary blob transfer over the REAL iroh transport
//! (loopback), through the FolderBridge disk projection.
//!
//! `folder_sync_e2e.rs` proves a *tiny* (11-byte, single-chunk) blob round-trips.
//! This proves the CHUNKED streaming path: a payload several times the 1 MiB
//! `BLOB_CHUNK_SIZE` is pulled as many `Frame::BlobChunk`s (offsets 0, 1 MiB,
//! 2 MiB, …, plus a ragged final remainder), reassembled by content hash on the
//! receiver, and projected to disk byte-for-byte identical to the source. The
//! in-crate `blob_chunking.rs` test covers chunking over an in-memory switchboard;
//! this is the missing intersection — chunking over real iroh + real disk.
//!
//! Blobs are PULL-based: gossip carries only the Blob file-set entry (the
//! blob-ref), never the bytes, so the receiver drives `request_missing_blobs`
//! (BlobWant → BlobChunk…) each round via `sync_until_with_blobs`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use roam_files::{container_id, EntryStatus, FileEntry, FolderBridge, SyncOutcome, FILESET_MAP_ID};
use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_transport_iroh::IrohTransport;
use tempfile::TempDir;

/// Multi-MiB transfers over loopback take longer than the tiny-file cases; give
/// the pull loop generous headroom (the in-memory chunking test uses 120s).
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The 1 MiB chunk size the engine splits on (mirrors the private
/// `roam_sync_core::engine::BLOB_CHUNK_SIZE`, which is not exported).
const BLOB_CHUNK_SIZE: usize = 1024 * 1024;

struct Endpoint {
    _vault_dir: TempDir,
    _store_dir: TempDir,
    vault: PathBuf,
    bridge: FolderBridge,
    engine: Arc<Engine<IrohTransport>>,
}

/// Import a local disk change into the engine's store, then gossip. Lock is
/// dropped before the flush await (never held across a transport await).
async fn scan(endpoint: &Endpoint) -> Vec<(PathBuf, SyncOutcome)> {
    let store = endpoint.engine.store();
    let outcomes = {
        let mut guard = store.lock().await;
        endpoint.bridge.scan(&mut guard).expect("scan must succeed")
    };
    endpoint.engine.flush_local().await;
    outcomes
}

/// Blob-aware convergence pump: request missing blob bytes each round (PULL),
/// then scan to project any now-local blob to disk. Fails loudly on timeout.
async fn sync_until_with_blobs(endpoint: &Endpoint, mut done: impl FnMut() -> bool, label: &str) {
    let start = Instant::now();
    loop {
        endpoint.engine.request_missing_blobs().await;
        scan(endpoint).await;
        if done() {
            return;
        }
        if start.elapsed() > CONVERGE_TIMEOUT {
            panic!("timed out after {CONVERGE_TIMEOUT:?} waiting for: {label}");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The file-set entry (status/kind) a device holds for `file`, if any.
async fn entry_for(endpoint: &Endpoint, file: &Path) -> Option<FileEntry> {
    let container = container_id(&endpoint.vault, file).expect("container id");
    let store = endpoint.engine.store();
    let guard = store.lock().await;
    guard
        .get_entry(FILESET_MAP_ID, &container)
        .map(|value| FileEntry::from_value(&value).expect("valid file-set entry"))
}

/// A deterministic, NON-UTF-8 payload of exactly `len` bytes. Non-UTF-8 is what
/// routes a file to the blob store (vs the mergeable-text path); a simple LCG
/// with a forced invalid lead byte guarantees both determinism and invalidity.
fn blob_payload(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u32 = 0x9E37_79B9;
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 24) as u8);
    }
    // Force non-UTF-8 regardless of the LCG stream: a lone 0xFF is never valid.
    out[0] = 0xFF;
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn a_multi_megabyte_blob_streams_in_chunks_over_iroh() {
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

    // Transport routes + loopback address exchange.
    let mut routes_a = HashMap::new();
    routes_a.insert(identity_b.peer_id(), identity_b.verifying_key().to_bytes());
    let mut routes_b = HashMap::new();
    routes_b.insert(identity_a.peer_id(), identity_a.verifying_key().to_bytes());
    let transport_a = IrohTransport::spawn(&identity_a, routes_a).await.unwrap();
    let transport_b = IrohTransport::spawn(&identity_b, routes_b).await.unwrap();
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
        [0u8; 32],
    ));
    let engine_b = Arc::new(Engine::new(
        identity_b.clone(),
        vault_id,
        store_b,
        Arc::new(transport_b),
        [0u8; 32],
    ));
    tokio::spawn(engine_a.clone().run());
    tokio::spawn(engine_b.clone().run());
    engine_a.connect(identity_b.peer_id()).await.unwrap();
    engine_b.connect(identity_a.peer_id()).await.unwrap();

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

    // A 5 MiB + 123 B payload: 5 full 1 MiB chunks plus a ragged final remainder,
    // so both the full-chunk and the short-final-chunk paths are exercised.
    let size = 5 * BLOB_CHUNK_SIZE + 123;
    let payload = blob_payload(size);
    assert!(
        size > BLOB_CHUNK_SIZE,
        "payload must exceed one chunk to force chunking"
    );

    let big_a = vault_a.join("big.bin");
    let big_b = vault_b.join("big.bin");
    std::fs::write(&big_a, &payload).unwrap();

    // A imports the blob (bytes + Live Blob entry + marker) and gossips the ref.
    scan(&a).await;

    // B pulls the bytes chunk-by-chunk and projects them to disk.
    sync_until_with_blobs(&b, || big_b.exists(), "big.bin to appear on B").await;

    // Byte-for-byte reassembly across many chunks.
    let received = std::fs::read(&big_b).unwrap();
    assert_eq!(received.len(), size, "B's blob must be the full length");
    assert_eq!(
        received, payload,
        "B's blob must be byte-identical to A's after chunked reassembly"
    );

    // And it is a Live blob file-set entry, not some degraded state.
    let entry = entry_for(&b, &big_b)
        .await
        .expect("B must have a file-set entry for big.bin");
    assert_eq!(
        entry.status,
        EntryStatus::Live,
        "big.bin entry on B must be Live"
    );
}
