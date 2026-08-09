//! WS-D4 — pull-based blob BYTE transfer over the transport.
//!
//! A peer that learned a `Blob` entry-ref through the synced file-set map but
//! lacks the bytes fetches them from a peer that has them: `BlobWant` (pull) →
//! `BlobData` (serve). These tests drive real frames over the in-memory
//! transport (hermetic, no network) and assert byte transfer, hash-verification
//! poison-rejection, the read-side revoke gate, idempotence, and absent-serve.

use futures::StreamExt;
use roam_files::{EntryKind, EntryStatus, FileEntry, FILESET_MAP_ID};
use roam_storage::{BlobStore, Identity, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_sync_core::frame::Frame;
use roam_sync_core::memory::MemorySwitchboard;
use roam_sync_core::Transport;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

/// Seed `store`'s roster so it vouches for `peer`.
fn seed(store: &mut Store, peer: &Identity) {
    store
        .add_peer(peer.peer_id(), peer.verifying_key().to_bytes())
        .unwrap();
}

/// A `Live` `Blob` file-set map value referencing `hash`.
fn blob_entry_value(hash: &str) -> String {
    FileEntry {
        kind: EntryKind::Blob,
        status: EntryStatus::Live,
        content_hash: hash.to_string(),
        renamed_from: None,
        tombstoned_at: None,
    }
    .to_value()
}

/// Full pull round-trip: A holds the bytes, both hold a synced `Live` `Blob`
/// entry for the hash, B lacks the bytes → `B.request_missing_blobs()` makes A
/// serve `BlobData` and B store the correct bytes, firing `changed()`.
#[tokio::test]
async fn pull_round_trip_transfers_blob_bytes_and_fires_changed() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let payload = b"the-blob-bytes-only-A-has".to_vec();

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    seed(&mut sa, &ib);
    seed(&mut sb, &ia);

    // A holds the actual blob bytes; B does not.
    let hash = sa.blobs().put(&payload).unwrap();
    assert!(!sb.blobs().has(&hash), "precondition: B lacks the bytes");

    // A records the `Blob` entry-ref in the file-set map (rides the op-log).
    sa.set_entry(FILESET_MAP_ID, "file-1", &blob_entry_value(&hash)).unwrap();

    let ea = Arc::new(Engine::new(ia.clone(), vault, sa, Arc::new(board.endpoint(ia.peer_id()))));
    let eb = Arc::new(Engine::new(ib.clone(), vault, sb, Arc::new(board.endpoint(ib.peer_id()))));
    tokio::spawn(ea.clone().run());
    tokio::spawn(eb.clone().run());

    ea.connect(ib.peer_id()).await.unwrap();
    eb.connect(ia.peer_id()).await.unwrap();
    // Let the handshake carry A's file-set entry to B (map ops sync over Ops).
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        eb.store().lock().await.get_entry(FILESET_MAP_ID, "file-1"),
        Some(blob_entry_value(&hash)),
        "B must have learned the Blob entry-ref via map sync"
    );

    // Register a changed() waiter BEFORE requesting, then pull.
    let changed = eb.changed();
    let notified = changed.notified();
    tokio::pin!(notified);

    eb.request_missing_blobs().await;

    let fired = tokio::time::timeout(Duration::from_millis(1000), &mut notified).await;
    assert!(fired.is_ok(), "changed() did not fire after the blob landed");

    let bb = eb.store().lock().await.blobs().get(&hash).unwrap();
    assert_eq!(bb, Some(payload), "B did not receive the correct blob bytes");
    assert!(eb.store().lock().await.blobs().has(&hash));
}

/// A `BlobData` whose bytes DON'T hash to the claimed hash (a malicious/corrupt
/// peer) must be rejected — the blob store is never poisoned.
#[tokio::test]
async fn corrupt_blob_data_is_rejected_no_poison() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());
    let _ = da;

    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    seed(&mut sb, &ia);
    // B genuinely wants this hash (a Live Blob entry references it).
    let claimed = BlobStore::hash(b"the real bytes");
    sb.set_entry(FILESET_MAP_ID, "file-1", &blob_entry_value(&claimed)).unwrap();

    let eb = Arc::new(Engine::new(ib.clone(), vault, sb, Arc::new(board.endpoint(ib.peer_id()))));

    // A (trusted) sends bytes that DO NOT hash to `claimed`.
    eb.handle(
        ia.peer_id(),
        Frame::BlobData { hash: claimed.clone(), bytes: b"WRONG bytes".to_vec() },
    )
    .await
    .unwrap();

    assert!(
        !eb.store().lock().await.blobs().has(&claimed),
        "corrupt bytes were stored under the claimed hash (poison!)"
    );
}

/// Read-side revoke gate: A must NOT serve `BlobData` to a REVOKED peer that
/// asks for a blob A holds.
#[tokio::test]
async fn a_does_not_serve_a_revoked_peers_blob_want() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let da = tempdir().unwrap();
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    // A trusts then revokes B: B is in the roster, but Revoked.
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes()).unwrap();
    sa.revoke_peer(ib.peer_id(), ib.verifying_key().to_bytes()).unwrap();
    let hash = sa.blobs().put(b"secret blob").unwrap();

    let ea = Arc::new(Engine::new(ia.clone(), vault, sa, Arc::new(board.endpoint(ia.peer_id()))));
    let tb = board.endpoint(ib.peer_id());
    let mut b_in = tb.incoming();

    ea.handle(ib.peer_id(), Frame::BlobWant { hash }).await.unwrap();

    let got = tokio::time::timeout(Duration::from_millis(200), b_in.next()).await;
    assert!(got.is_err(), "A served a blob to a revoked peer: {got:?}");
}

/// Contrast: an Active peer's `BlobWant` for a held blob IS served (the gate is
/// specific to revoked/untrusted peers, not a blanket refusal).
#[tokio::test]
async fn a_serves_an_active_peers_blob_want() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let da = tempdir().unwrap();
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes()).unwrap();
    let payload = b"served blob".to_vec();
    let hash = sa.blobs().put(&payload).unwrap();

    let ea = Arc::new(Engine::new(ia.clone(), vault, sa, Arc::new(board.endpoint(ia.peer_id()))));
    let tb = board.endpoint(ib.peer_id());
    let mut b_in = tb.incoming();

    ea.handle(ib.peer_id(), Frame::BlobWant { hash: hash.clone() }).await.unwrap();

    let got = tokio::time::timeout(Duration::from_millis(200), b_in.next()).await;
    match got {
        Ok(Some((from, Frame::BlobData { hash: h, bytes }))) => {
            assert_eq!(from, ia.peer_id());
            assert_eq!(h, hash);
            assert_eq!(bytes, payload);
        }
        other => panic!("expected BlobData for an active peer, got {other:?}"),
    }
}

/// Absent serve: a `BlobWant` for a hash the server does NOT hold produces no
/// frame and no error.
#[tokio::test]
async fn blob_want_for_absent_blob_serves_nothing() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let da = tempdir().unwrap();
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes()).unwrap();

    let ea = Arc::new(Engine::new(ia.clone(), vault, sa, Arc::new(board.endpoint(ia.peer_id()))));
    let tb = board.endpoint(ib.peer_id());
    let mut b_in = tb.incoming();

    // A valid-shaped hash A does not have.
    let missing = BlobStore::hash(b"A never stored this");
    ea.handle(ib.peer_id(), Frame::BlobWant { hash: missing }).await.unwrap();

    let got = tokio::time::timeout(Duration::from_millis(200), b_in.next()).await;
    assert!(got.is_err(), "A served a blob it does not hold: {got:?}");
}

/// Idempotent receive: `BlobData` for a hash B already holds is a no-op — the
/// bytes stay put and `changed()` does NOT fire.
#[tokio::test]
async fn blob_data_for_already_held_blob_is_a_noop() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let db = tempdir().unwrap();
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let payload = b"already here".to_vec();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    seed(&mut sb, &ia);
    let hash = sb.blobs().put(&payload).unwrap();
    sb.set_entry(FILESET_MAP_ID, "file-1", &blob_entry_value(&hash)).unwrap();

    let eb = Arc::new(Engine::new(ib.clone(), vault, sb, Arc::new(board.endpoint(ib.peer_id()))));

    let changed = eb.changed();
    let notified = changed.notified();
    tokio::pin!(notified);

    eb.handle(
        ia.peer_id(),
        Frame::BlobData { hash: hash.clone(), bytes: payload.clone() },
    )
    .await
    .unwrap();

    // Still present, and no change was signalled (nothing new landed).
    assert_eq!(eb.store().lock().await.blobs().get(&hash).unwrap(), Some(payload));
    let fired = tokio::time::timeout(Duration::from_millis(150), &mut notified).await;
    assert!(fired.is_err(), "changed() fired for an already-held blob");
}

/// `request_missing_blobs` with nothing missing sends NO `BlobWant`.
#[tokio::test]
async fn request_missing_blobs_sends_nothing_when_complete() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let db = tempdir().unwrap();
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    seed(&mut sb, &ia);
    // A Live Blob entry whose bytes B ALREADY holds → nothing is missing.
    let hash = sb.blobs().put(b"complete").unwrap();
    sb.set_entry(FILESET_MAP_ID, "file-1", &blob_entry_value(&hash)).unwrap();

    let eb = Arc::new(Engine::new(ib.clone(), vault, sb, Arc::new(board.endpoint(ib.peer_id()))));
    // Raw observer endpoint for A: no engine, just read what B sends.
    let ta = board.endpoint(ia.peer_id());
    let mut a_in = ta.incoming();

    // Connect so B tracks A as connected, then drain the handshake frames.
    eb.connect(ia.peer_id()).await.unwrap();
    while tokio::time::timeout(Duration::from_millis(80), a_in.next())
        .await
        .is_ok()
    {}

    // Nothing missing → no BlobWant (in fact no frame at all).
    eb.request_missing_blobs().await;
    let got = tokio::time::timeout(Duration::from_millis(200), a_in.next()).await;
    assert!(got.is_err(), "request_missing_blobs sent a frame with nothing missing: {got:?}");
}
