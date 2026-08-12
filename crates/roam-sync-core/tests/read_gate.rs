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

/// Build a VALID Admin-signed framed snapshot object over a vault whose raw key
/// is `vault_key`, authored by `admin`. Content is sealed at epoch 0 (a fresh
/// store's head epoch), so any peer holding the same vault key can open it with
/// no pairing/keylog — the epoch-0 AEAD key derives straight from the vault key.
///
/// Mirrors the backend producer (`maybe_produce_snapshot`): write a head marker,
/// build a shallow snapshot, seal it, then wrap it in a signed manifest + frame.
fn build_admin_framed_snapshot(admin: &Identity, vault_key: &[u8; 32]) -> Vec<u8> {
    use roam_backend_client::crypto::VaultKey;
    use roam_storage::snapshot_msg::{frame, SnapshotManifest};

    let dir = tempdir().unwrap();
    let mut store = Store::open(dir.path(), admin.clone()).unwrap();
    store.declare_founder(Role::Admin).unwrap();
    store.set_entry("notes", "k", "v").unwrap();
    // Pin a head history marker so there is a frontier to snapshot.
    store.write_snapshot().unwrap();
    // `i64::MAX` captures the marker just written (any ts before "now + ε").
    let snap = store
        .build_backend_snapshot(i64::MAX)
        .unwrap()
        .expect("a snapshot at the just-written head marker");

    // Seal at epoch 0 (fresh store head), exactly like the producer's
    // `seal_under_head` fallback: `VaultKey::seal` == the epoch-0 AEAD seal, and
    // `VaultKey` derives its subkeys from the SAME `vault_subkeys` a receiver's
    // keychain uses, so the ciphertext opens under the shared vault key alone.
    let vk = VaultKey(*vault_key);
    let sealed = vk.seal(&snap.bytes);

    let manifest = SnapshotManifest {
        frontier_digest: snap.frontier_digest,
        snapshot_ct_hash: blake3::hash(&sealed).into(),
        subsumed_entry_ids: Vec::new(),
        blob_ref_ids: Vec::new(),
        author: 0,
        sig: String::new(),
    }
    .signed(admin);

    let manifest_json = serde_json::to_vec(&manifest).unwrap();
    frame(&manifest_json, &sealed)
}

/// Adopt side of P2P snapshot bootstrap: a received `SnapshotData` whose framed
/// object is authored by an Active ADMIN and decryptable under our vault key is
/// verified, adopted (its state imported into the doc), and persisted so we can
/// re-serve it. The engine names the object by its own content hash.
#[tokio::test]
async fn snapshot_data_is_verified_and_adopted_and_persisted() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let vault_key = [42u8; 32];

    let (ia, ib) = (Identity::generate(), Identity::generate());
    // Admin A's framed snapshot over the shared vault key.
    let framed = build_admin_framed_snapshot(&ia, &vault_key);

    // B's store lists A as an ACTIVE ADMIN (so the author gate trusts A), and
    // B's engine carries the SAME vault key (so B derives the epoch-0 key to
    // decrypt). No keylog/pairing needed: epoch-0 content opens from the vault
    // key alone.
    let db = tempdir().unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    let before = sb.doc_version_bytes();

    let eb = Arc::new(Engine::new(
        ib.clone(),
        vault,
        sb,
        Arc::new(board.endpoint(ib.peer_id())),
        vault_key,
    ));

    eb.handle(ia.peer_id(), Frame::SnapshotData { framed })
        .await
        .unwrap();

    // B holds the adopted object (non-empty), and its document advanced (the
    // snapshot's state was imported).
    let store = eb.store();
    let g = store.lock().await;
    assert!(
        !g.held_snapshot_ids().unwrap().is_empty(),
        "B did not record the adopted snapshot as held"
    );
    assert_ne!(
        g.doc_version_bytes(),
        before,
        "adopting the snapshot did not advance B's document version"
    );
}

/// The same framed object, but B's roster lists A as a WRITER (not an Admin).
/// The shared receiver-side gate rejects the non-Admin author BEFORE any store
/// mutation, so B holds nothing and its document does not advance.
#[tokio::test]
async fn snapshot_data_from_non_admin_author_is_dropped() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let vault_key = [42u8; 32];

    let (ia, ib) = (Identity::generate(), Identity::generate());
    let framed = build_admin_framed_snapshot(&ia, &vault_key);

    let db = tempdir().unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    // B sees A as a WRITER, not an Admin.
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Writer)
        .unwrap();
    let before = sb.doc_version_bytes();

    let eb = Arc::new(Engine::new(
        ib.clone(),
        vault,
        sb,
        Arc::new(board.endpoint(ib.peer_id())),
        vault_key,
    ));

    eb.handle(ia.peer_id(), Frame::SnapshotData { framed })
        .await
        .unwrap();

    let store = eb.store();
    let g = store.lock().await;
    assert!(
        g.held_snapshot_ids().unwrap().is_empty(),
        "B adopted a snapshot from a non-Admin author"
    );
    assert_eq!(
        g.doc_version_bytes(),
        before,
        "a rejected snapshot must not advance B's document version"
    );
}
