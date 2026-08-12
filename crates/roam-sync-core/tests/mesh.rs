use roam_storage::{Identity, PeerStatus, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_sync_core::memory::MemorySwitchboard;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test]
async fn c_learns_b_transitively_through_a() {
    // A is paired with B and with C. B and C are NOT directly paired. After A
    // gossips its roster, B and C must learn each other and converge.
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db, dc) = (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib, ic) = (
        Identity::generate(),
        Identity::generate(),
        Identity::generate(),
    );

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    let mut sc = Store::open(dc.path(), ic.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sc.declare_founder(Role::Admin).unwrap();
    // A vouches for B and C (as pairing would).
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sa.add_peer(ic.peer_id(), ic.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    // B and C each trust A (learned at their own pairing with A).
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sc.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
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

    eb.connect(ia.peer_id()).await.unwrap();
    ec.connect(ia.peer_id()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // B must now know C via A's signed roster.
    let b_knows_c = eb
        .store()
        .lock()
        .await
        .roster()
        .iter()
        .any(|p| p.peer_id == ic.peer_id() && p.status == PeerStatus::Active);
    assert!(b_knows_c, "B did not learn C transitively");

    // And a B edit reaches C.
    eb.edit_text("note", 0, "B-writes").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ec.store().lock().await.text("note"), "B-writes");
}

#[tokio::test]
async fn transitive_learn_adds_a_dynamic_route_under_strict_routing() {
    // Strict-routing transitive mesh: each endpoint can only reach peers in its
    // seeded `known` set, which grows solely via `add_route`. B is the hub —
    // paired with A and with C — but A and C are NOT directly paired. A and C
    // learn each other only transitively via B's roster gossip. For A to converge
    // with a C edit, A must dial C, which the strict transport permits only if the
    // engine called `add_route(C)` when it learned C (and C likewise for A).
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db, dc) = (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib, ic) = (
        Identity::generate(),
        Identity::generate(),
        Identity::generate(),
    );

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    let mut sc = Store::open(dc.path(), ic.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sc.declare_founder(Role::Admin).unwrap();
    // B (the hub) vouches for A and C; A and C each only know B.
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sb.add_peer(ic.peer_id(), ic.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sc.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();

    // Strict routes: A and C initially reach only B; B reaches A and C. A and C
    // must learn to reach each other dynamically for the C edit to arrive.
    let ta = board.strict_endpoint(ia.peer_id(), &[ib.peer_id()]);
    let tb = board.strict_endpoint(ib.peer_id(), &[ia.peer_id(), ic.peer_id()]);
    let tc = board.strict_endpoint(ic.peer_id(), &[ib.peer_id()]);

    let ea = Arc::new(Engine::new(ia.clone(), vault, sa, Arc::new(ta), [0u8; 32]));
    let eb = Arc::new(Engine::new(ib.clone(), vault, sb, Arc::new(tb), [0u8; 32]));
    let ec = Arc::new(Engine::new(ic.clone(), vault, sc, Arc::new(tc), [0u8; 32]));
    tokio::spawn(ea.clone().run());
    tokio::spawn(eb.clone().run());
    tokio::spawn(ec.clone().run());

    ea.connect(ib.peer_id()).await.unwrap();
    ec.connect(ib.peer_id()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // C writes; the edit must reach A only if A learned a route to C (and C to A).
    ec.edit_text("note", 0, "C-writes").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        ea.store().lock().await.text("note"),
        "C-writes",
        "A never learned a dynamic route to C, so the strict transport refused the dial"
    );
}

#[tokio::test]
async fn revoked_peer_edits_stop_propagating() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());
    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
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
    tokio::time::sleep(Duration::from_millis(150)).await;

    // A revokes B, then B edits: A must not accept B's new op.
    ea.revoke_peer(ib.peer_id(), ib.verifying_key().to_bytes())
        .await
        .unwrap();
    eb.edit_text("note", 0, "after-revoke").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        ea.store().lock().await.text("note"),
        "",
        "revoked peer op leaked in"
    );
}
