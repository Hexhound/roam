//! WS-C / C1 — per-peer acked-version tracking in the engine.
//!
//! The causally-stable tombstone GC needs to know, for every trusted peer, the
//! document version that peer has told us it holds. The engine learns this from
//! each inbound [`Frame::Have`] and records it per peer, MONOTONICALLY (a stale
//! Have never regresses a peer's acked version). These tests drive real Have
//! frames over the in-memory transport and assert the recorded versions.

use roam_storage::{version_dominates, Identity, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_sync_core::frame::Frame;
use roam_sync_core::memory::MemorySwitchboard;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

/// Seed `store`'s roster so it vouches for `peer`.
fn seed(store: &mut Store, peer: &Identity) {
    store
        .add_peer(peer.peer_id(), peer.verifying_key().to_bytes())
        .unwrap();
}

/// After B advertises its version via a Have, A records B's acked version, and a
/// newer Have from B advances it (older/stale Have does not regress it).
#[tokio::test]
async fn engine_records_and_advances_peer_acked_version() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    seed(&mut sa, &ib);
    seed(&mut sb, &ia);

    let ea = Arc::new(Engine::new(
        ia.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ia.peer_id())),
    ));
    let eb = Arc::new(Engine::new(
        ib.clone(),
        vault,
        sb,
        Arc::new(board.endpoint(ib.peer_id())),
    ));
    tokio::spawn(ea.clone().run());
    tokio::spawn(eb.clone().run());

    ea.connect(ib.peer_id()).await.unwrap();
    eb.connect(ia.peer_id()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // The handshake already carried a Have both ways: A has recorded B's version.
    let recorded = ea.acked_versions().await;
    let b_v0 = recorded
        .get(&ib.peer_id())
        .expect("A must record B's acked version from the handshake Have")
        .clone();

    // B advances its document, then re-advertises via a fresh Have. A must
    // ADVANCE B's acked version (new version dominates the old one).
    eb.store().lock().await.edit_text("note", 0, "hello").unwrap();
    let b_new = eb.store().lock().await.doc_version_bytes();
    ea.handle(ib.peer_id(), Frame::Have { doc_version: b_new.clone() })
        .await
        .unwrap();
    let after = ea.acked_versions().await;
    let b_v1 = after.get(&ib.peer_id()).unwrap().clone();
    assert!(
        version_dominates(&b_v1, &b_v0),
        "a newer Have must advance B's acked version"
    );
    assert!(version_dominates(&b_v1, &b_new) && version_dominates(&b_new, &b_v1));

    // A STALE Have (B's older version) must NOT regress the recorded version.
    ea.handle(ib.peer_id(), Frame::Have { doc_version: b_v0.clone() })
        .await
        .unwrap();
    let after_stale = ea.acked_versions().await;
    let b_v2 = after_stale.get(&ib.peer_id()).unwrap().clone();
    assert!(
        version_dominates(&b_v2, &b_new),
        "a stale Have must not lower B's acked version"
    );
}

/// A Have from a peer we do NOT trust (not in our roster) must not be recorded —
/// only trusted, non-revoked witnesses count for GC.
#[tokio::test]
async fn engine_ignores_have_from_untrusted_peer() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let da = tempdir().unwrap();
    let ia = Identity::generate();
    let stranger = Identity::generate();

    let sa = Store::open(da.path(), ia.clone()).unwrap();
    // NB: A does NOT vouch for `stranger`.
    let ea = Arc::new(Engine::new(
        ia.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ia.peer_id())),
    ));

    // A bare, well-formed Have from the untrusted stranger.
    let v = Store::open(tempdir().unwrap().path(), stranger.clone())
        .unwrap()
        .doc_version_bytes();
    ea.handle(stranger.peer_id(), Frame::Have { doc_version: v })
        .await
        .unwrap();

    assert!(
        !ea.acked_versions().await.contains_key(&stranger.peer_id()),
        "an untrusted peer's Have must not be recorded"
    );
}
