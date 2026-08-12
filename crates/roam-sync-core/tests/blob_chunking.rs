//! Blob chunking — end-to-end integration tests.
//!
//! The Engine now serves a `BlobWant` as a STREAM of `Frame::BlobChunk { hash,
//! offset, total_len, bytes }` frames (`BLOB_CHUNK_SIZE` = 1 MiB), instead of
//! the old single-frame `Frame::BlobData` capped at `MAX_BLOB_BYTES` (60 MiB).
//! The receiver reassembles chunks into `incoming/<hash>.part` (tracking
//! DISTINCT offsets, so duplicate/interleaved streams from multiple serving
//! peers don't corrupt accounting) and finalizes into `BlobStore` once every
//! byte has landed and the hash verifies.
//!
//! These tests reproduce the two-engine harness from `blob_transfer.rs`
//! (construction of identities, shared `VaultId`, `add_peer(Role::Admin)`,
//! the in-memory transport, and `import`-free `set_entry`-based Blob
//! file-set entries) rather than importing test-only helpers across the
//! test-binary boundary, and drive the receiver's pull loop
//! (`request_missing_blobs().await`) under a bounded poll until convergence.

use roam_files::{EntryKind, EntryStatus, FileEntry, FILESET_MAP_ID};
use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_sync_core::memory::MemorySwitchboard;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

/// Deterministic pseudo-random blob bytes. Bytes 0,1 are 0xFF so the file-set
/// classifier treats the content as a Blob (invalid UTF-8), not text.
fn blob_payload(len: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut s = seed | 1;
    for b in out.iter_mut() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (s >> 33) as u8;
    }
    if len >= 2 {
        out[0] = 0xFF;
        out[1] = 0xFF;
    }
    out
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

/// Poll `f` (an async closure returning `bool`) up to `timeout`, sleeping
/// `interval` between attempts. Panics with `msg` on timeout, so a failure
/// reads as a clear assertion rather than a silent hang.
async fn poll_until<F, Fut>(timeout: Duration, interval: Duration, msg: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if f().await {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("{msg}");
        }
        tokio::time::sleep(interval).await;
    }
}

/// Blob larger than the retired 60 MiB `MAX_BLOB_BYTES` single-frame cap
/// transfers end-to-end via chunked `BlobChunk` streaming.
#[tokio::test(flavor = "multi_thread")]
async fn blob_larger_than_the_old_cap_transfers_end_to_end() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let payload = blob_payload(80 * 1024 * 1024, 0xB10B_C0DE); // 80 MiB > old 60 MiB cap

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();

    // A holds the actual blob bytes; B does not.
    let hash = sa.blobs().put(&payload).unwrap();
    assert!(!sb.blobs().has(&hash), "precondition: B lacks the bytes");

    // A records the `Blob` entry-ref in the file-set map (rides the op-log).
    sa.set_entry(FILESET_MAP_ID, "file-1", &blob_entry_value(&hash))
        .unwrap();

    let ea = Arc::new(Engine::new(
        ia.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ia.peer_id())),
        [0u8; 32],
    ));
    let eb = Arc::new(Engine::new(
        ib.clone(),
        vault,
        sb,
        Arc::new(board.endpoint(ib.peer_id())),
        [0u8; 32],
    ));
    tokio::spawn(ea.clone().run());
    tokio::spawn(eb.clone().run());

    ea.connect(ib.peer_id()).await.unwrap();
    eb.connect(ia.peer_id()).await.unwrap();

    // Let the handshake carry A's file-set entry to B (map ops sync over Ops).
    poll_until(
        Duration::from_secs(30),
        Duration::from_millis(20),
        "B never learned the Blob entry-ref via map sync",
        || async {
            eb.store().lock().await.get_entry(FILESET_MAP_ID, "file-1")
                == Some(blob_entry_value(&hash))
        },
    )
    .await;

    // Drive B's pull loop until every chunk has landed and the blob verifies.
    poll_until(
        Duration::from_secs(120),
        Duration::from_millis(20),
        "B never converged on the 80 MiB blob's bytes",
        || {
            let eb = eb.clone();
            let hash = hash.clone();
            async move {
                eb.request_missing_blobs().await;
                eb.store().lock().await.blobs().has(&hash)
            }
        },
    )
    .await;

    let bytes = eb.store().lock().await.blobs().get(&hash).unwrap();
    assert_eq!(
        bytes,
        Some(payload),
        "B's reassembled 80 MiB blob does not match A's bytes"
    );
}

/// A blob smaller than `BLOB_CHUNK_SIZE` (1 MiB) still transfers correctly —
/// it is served as a single `BlobChunk` frame covering the whole payload.
#[tokio::test(flavor = "multi_thread")]
async fn small_blob_still_transfers_as_a_single_chunk() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let payload = blob_payload(500 * 1024, 0x5EED); // < 1 MiB BLOB_CHUNK_SIZE

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();

    let hash = sa.blobs().put(&payload).unwrap();
    assert!(!sb.blobs().has(&hash), "precondition: B lacks the bytes");

    sa.set_entry(FILESET_MAP_ID, "file-1", &blob_entry_value(&hash))
        .unwrap();

    let ea = Arc::new(Engine::new(
        ia.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ia.peer_id())),
        [0u8; 32],
    ));
    let eb = Arc::new(Engine::new(
        ib.clone(),
        vault,
        sb,
        Arc::new(board.endpoint(ib.peer_id())),
        [0u8; 32],
    ));
    tokio::spawn(ea.clone().run());
    tokio::spawn(eb.clone().run());

    ea.connect(ib.peer_id()).await.unwrap();
    eb.connect(ia.peer_id()).await.unwrap();

    poll_until(
        Duration::from_secs(30),
        Duration::from_millis(20),
        "B never learned the Blob entry-ref via map sync",
        || async {
            eb.store().lock().await.get_entry(FILESET_MAP_ID, "file-1")
                == Some(blob_entry_value(&hash))
        },
    )
    .await;

    poll_until(
        Duration::from_secs(30),
        Duration::from_millis(20),
        "B never converged on the small blob's bytes",
        || {
            let eb = eb.clone();
            let hash = hash.clone();
            async move {
                eb.request_missing_blobs().await;
                eb.store().lock().await.blobs().has(&hash)
            }
        },
    )
    .await;

    let bytes = eb.store().lock().await.blobs().get(&hash).unwrap();
    assert_eq!(bytes, Some(payload));
}

/// Two peers (A and C) both hold the identical blob and are both connected to
/// receiver B. `request_missing_blobs` sends a `BlobWant` to EVERY connected
/// Active peer, so B pulls from A and C concurrently — duplicate/interleaved
/// `BlobChunk` streams for the SAME hash arrive at B. This exercises the
/// offset-dedup fix (distinct-offset accounting) directly: a real three-engine
/// setup (not a same-server double-pull workaround), because
/// `request_missing_blobs` fans out to the whole connected+Active roster by
/// construction, which is the simplest way to get genuinely concurrent,
/// independently-driven chunk streams for one hash.
#[tokio::test(flavor = "multi_thread")]
async fn blob_transfers_when_two_peers_serve_it_concurrently() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db, dc) = (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib, ic) = (
        Identity::generate(),
        Identity::generate(),
        Identity::generate(),
    );

    let payload = blob_payload(8 * 1024 * 1024, 0x2222_3333); // 8 MiB -> multiple chunks

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    let mut sc = Store::open(dc.path(), ic.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sc.declare_founder(Role::Admin).unwrap();

    // Full mesh roster: A, B, C all vouch for each other.
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sa.add_peer(ic.peer_id(), ic.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sb.add_peer(ic.peer_id(), ic.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sc.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sc.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();

    // A and C BOTH hold the identical blob bytes; B holds neither.
    let hash_a = sa.blobs().put(&payload).unwrap();
    let hash_c = sc.blobs().put(&payload).unwrap();
    assert_eq!(hash_a, hash_c, "content-addressed hash must match");
    let hash = hash_a;
    assert!(!sb.blobs().has(&hash), "precondition: B lacks the bytes");

    sa.set_entry(FILESET_MAP_ID, "file-1", &blob_entry_value(&hash))
        .unwrap();

    let ea = Arc::new(Engine::new(
        ia.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ia.peer_id())),
        [0u8; 32],
    ));
    let eb = Arc::new(Engine::new(
        ib.clone(),
        vault,
        sb,
        Arc::new(board.endpoint(ib.peer_id())),
        [0u8; 32],
    ));
    let ec = Arc::new(Engine::new(
        ic.clone(),
        vault,
        sc,
        Arc::new(board.endpoint(ic.peer_id())),
        [0u8; 32],
    ));
    tokio::spawn(ea.clone().run());
    tokio::spawn(eb.clone().run());
    tokio::spawn(ec.clone().run());

    // Full mesh of live connections so B's roster + connected set include both A and C.
    ea.connect(ib.peer_id()).await.unwrap();
    eb.connect(ia.peer_id()).await.unwrap();
    ea.connect(ic.peer_id()).await.unwrap();
    ec.connect(ia.peer_id()).await.unwrap();
    eb.connect(ic.peer_id()).await.unwrap();
    ec.connect(ib.peer_id()).await.unwrap();

    // Let the handshake carry A's file-set entry to B and C (map ops sync over Ops).
    poll_until(
        Duration::from_secs(30),
        Duration::from_millis(20),
        "B never learned the Blob entry-ref via map sync",
        || async {
            eb.store().lock().await.get_entry(FILESET_MAP_ID, "file-1")
                == Some(blob_entry_value(&hash))
        },
    )
    .await;

    // Sanity: B sees both A and C as connected before pulling, so the fan-out
    // in `request_missing_blobs` genuinely targets two servers.
    poll_until(
        Duration::from_secs(30),
        Duration::from_millis(20),
        "B never connected to both A and C",
        || async {
            let connected = eb.connected_peers().await;
            connected.contains(&ia.peer_id()) && connected.contains(&ic.peer_id())
        },
    )
    .await;

    // Drive B's pull loop repeatedly: each call fans a BlobWant out to BOTH A
    // and C while the blob remains missing, producing overlapping BlobChunk
    // streams for the same hash from two independent servers.
    poll_until(
        Duration::from_secs(60),
        Duration::from_millis(20),
        "B never converged on the concurrently-served blob's bytes",
        || {
            let eb = eb.clone();
            let hash = hash.clone();
            async move {
                eb.request_missing_blobs().await;
                eb.store().lock().await.blobs().has(&hash)
            }
        },
    )
    .await;

    let bytes = eb.store().lock().await.blobs().get(&hash).unwrap();
    assert_eq!(
        bytes,
        Some(payload),
        "B's reassembled bytes are corrupt after concurrent multi-peer serving"
    );
}
