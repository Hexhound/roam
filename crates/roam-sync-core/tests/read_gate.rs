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
        [0u8; 32],
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
        [0u8; 32],
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

/// Serve side of P2P snapshot bootstrap: a peer whose advertised document
/// version is behind A's gets A's held snapshot ids advertised (`SnapshotHave`),
/// and a follow-up `SnapshotWant` is answered with the exact stored framed bytes
/// (`SnapshotData`).
#[tokio::test]
async fn have_from_behind_peer_gets_snapshot_advert_then_data() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    // A vouches for B as Active (the serve gates require an active peer).
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    // Give A some document state so its doc_version is non-empty. A fresh peer
    // (below) advertises the empty version, which is behind any non-empty doc,
    // so `offer_snapshots` fires.
    sa.set_entry("notes", "k", "v").unwrap();
    // A holds one framed snapshot object to advertise and serve.
    sa.persist_snapshot_object("snap", b"snap-object-bytes")
        .unwrap();

    // A brand-new, unmutated store's version is empty → strictly behind A.
    let sb = Store::open(db.path(), ib.clone()).unwrap();
    let behind_version = sb.doc_version_bytes();
    drop(sb);

    let ea = Arc::new(Engine::new(
        ia.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ia.peer_id())),
        [0u8; 32],
    ));
    let tb = board.endpoint(ib.peer_id());
    let mut b_in = tb.incoming();

    // B (behind) handshakes with a Have carrying its empty version.
    ea.handle(
        ib.peer_id(),
        Frame::Have {
            doc_version: behind_version,
        },
    )
    .await
    .unwrap();

    // Among the frames A sent B (push_logs may also send Ops/Log frames), a
    // SnapshotHave advertising the held id must be present.
    let mut saw_advert = false;
    while let Ok(Some(frame)) =
        tokio::time::timeout(Duration::from_millis(200), b_in.next()).await
    {
        if let (_, Frame::SnapshotHave { ids }) = frame {
            assert_eq!(ids, vec!["snap".to_string()]);
            saw_advert = true;
            break;
        }
    }
    assert!(
        saw_advert,
        "A did not advertise its held snapshot to a behind peer"
    );

    // B asks for the advertised object; A must serve the exact stored bytes.
    ea.handle(ib.peer_id(), Frame::SnapshotWant { id: "snap".into() })
        .await
        .unwrap();

    let mut saw_data = false;
    while let Ok(Some(frame)) =
        tokio::time::timeout(Duration::from_millis(200), b_in.next()).await
    {
        if let (_, Frame::SnapshotData { framed }) = frame {
            assert_eq!(framed, b"snap-object-bytes".to_vec());
            saw_data = true;
            break;
        }
    }
    assert!(saw_data, "A did not serve the snapshot object on Want");
}
