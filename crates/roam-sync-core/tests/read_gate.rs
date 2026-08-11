//! Read-side revocation gate: the engine must not serve the whole document /
//! roster to a peer it has revoked (spec §9.6 — a revoked peer is rejected
//! mesh-wide, not only on the write path).

use futures::StreamExt;
use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_sync_core::frame::Frame;
use roam_sync_core::memory::MemorySwitchboard;
use roam_sync_core::Transport;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn a_does_not_reply_to_a_revoked_peers_have() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());
    let _ = db;

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    // A trusts then revokes B: B is in the roster, but Revoked.
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sa.revoke_peer(ib.peer_id(), ib.verifying_key().to_bytes())
        .unwrap();
    let version = sa.doc_version_bytes();

    let ea = Arc::new(Engine::new(
        ia.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ia.peer_id())),
    ));
    // B's endpoint, only to observe whether A sends it anything.
    let tb = board.endpoint(ib.peer_id());
    let mut b_in = tb.incoming();

    // A handles a (valid) Have from the revoked peer B directly.
    ea.handle(
        ib.peer_id(),
        Frame::Have {
            doc_version: version,
        },
    )
    .await
    .unwrap();

    // A must send NOTHING back to the revoked peer.
    let got = tokio::time::timeout(Duration::from_millis(200), b_in.next()).await;
    assert!(got.is_err(), "A replied to a revoked peer's Have: {got:?}");
}

#[tokio::test]
async fn a_does_reply_to_an_active_peers_have() {
    // Contrast: an Active peer's Have still gets served (the gate is specific to
    // revoked peers, not a blanket refusal).
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());
    let _ = db;

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    let version = sa.doc_version_bytes();

    let ea = Arc::new(Engine::new(
        ia.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ia.peer_id())),
    ));
    let tb = board.endpoint(ib.peer_id());
    let mut b_in = tb.incoming();

    ea.handle(
        ib.peer_id(),
        Frame::Have {
            doc_version: version,
        },
    )
    .await
    .unwrap();

    let got = tokio::time::timeout(Duration::from_millis(200), b_in.next()).await;
    assert!(
        matches!(got, Ok(Some(_))),
        "A did not serve an active peer's Have: {got:?}"
    );
}
