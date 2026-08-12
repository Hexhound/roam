//! Engine-wiring slice, Task (b): a reusable local-op gossip method
//! (`flush_local`) and a remote-change `Notify` (`changed`).
//!
//! `flush_local` factors the own-log suffix push out of `edit_text` so a
//! direct/store-bypassing mutation (e.g. `FolderBridge::scan`) can still be
//! gossiped. `changed()` lets a single consumer (the CLI) await inbound applies.

use futures::StreamExt;
use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_sync_core::frame::Frame;
use roam_sync_core::memory::MemorySwitchboard;
use roam_sync_core::Transport;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

/// Seed `store`'s roster so it vouches for `peer` (mirrors convergence tests).
fn seed(store: &mut Store, peer: &Identity) {
    store
        .add_peer(peer.peer_id(), peer.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
}

/// A direct store edit followed by `flush_local` must propagate to a connected,
/// trusted peer — proving scan-style writes that bypass `edit_text` still gossip.
#[tokio::test]
async fn flush_local_gossips_direct_store_edits() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    seed(&mut sa, &ib);
    seed(&mut sb, &ia);

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

    // Mutate A's store DIRECTLY, bypassing Engine::edit_text (no live-push).
    ea.store().lock().await.edit_text("note", 0, "hi").unwrap();
    // The reusable flush must ship the new own-log suffix to B.
    ea.flush_local().await;

    tokio::time::sleep(Duration::from_millis(150)).await;
    let tb = eb.store().lock().await.text("note");
    assert_eq!(
        tb, "hi",
        "flush_local did not propagate a direct store edit"
    );
}

/// `flush_local` is idempotent: with nothing new to send it must transmit no
/// further `Ops`. We observe A through a raw endpoint (no engine) and count the
/// frames it actually sends across two flushes.
#[tokio::test]
async fn flush_local_is_a_safe_noop_when_nothing_new() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());
    let _ = db;

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    seed(&mut sa, &ib);

    let ea = Arc::new(Engine::new(
        ia.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ia.peer_id())),
        [0u8; 32],
    ));
    // Raw observer endpoint for B: no engine, we just read frames A sends.
    let tb = board.endpoint(ib.peer_id());
    let mut b_in = tb.incoming();

    // Connect so A tracks B in sent_offsets/connected, then drain the handshake.
    ea.connect(ib.peer_id()).await.unwrap();
    while tokio::time::timeout(Duration::from_millis(80), b_in.next())
        .await
        .is_ok()
    {}

    // One real change: a direct edit + flush must produce exactly one Ops frame.
    ea.store().lock().await.edit_text("note", 0, "hi").unwrap();
    ea.flush_local().await;
    let first = tokio::time::timeout(Duration::from_millis(150), b_in.next()).await;
    assert!(
        matches!(first, Ok(Some((_, Frame::Ops { .. })))),
        "first flush after an edit should send an Ops frame: {first:?}"
    );

    // Second flush with nothing new must send NOTHING.
    ea.flush_local().await;
    let second = tokio::time::timeout(Duration::from_millis(150), b_in.next()).await;
    assert!(
        second.is_err(),
        "flush_local resent ops with nothing new: {second:?}"
    );
}

/// `reconnect_active` heals a peer that was never connected: A mutates while no
/// peer is connected (so nothing is pushed), then a reconnect re-offers the full
/// log and B catches up. Models the daemon's periodic self-healing reconnect.
#[tokio::test]
async fn reconnect_active_catches_up_an_unconnected_peer() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    seed(&mut sa, &ib);
    seed(&mut sb, &ia);

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

    // A mutates with NO peer connected — flush finds no peers and pushes nothing.
    ea.store().lock().await.edit_text("note", 0, "hi").unwrap();
    ea.flush_local().await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        eb.store().lock().await.text("note"),
        "",
        "B must have nothing before any connection"
    );

    // Self-heal: reconnect dials B and re-offers the full log; B catches up.
    ea.reconnect_active().await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        eb.store().lock().await.text("note"),
        "hi",
        "reconnect_active did not catch the peer up"
    );
}

/// `changed()` resolves after an inbound apply, and is pending before one.
#[tokio::test]
async fn changed_fires_on_inbound_ops() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    seed(&mut sa, &ib);
    seed(&mut sb, &ia);

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

    // Register a waiter AFTER the handshake settles. notify_waiters stores no
    // permit, so any spurious handshake fire before registration is harmless.
    let changed = eb.changed();
    let notified = changed.notified();
    tokio::pin!(notified);

    // Pending before any real inbound change.
    let pending = tokio::time::timeout(Duration::from_millis(120), &mut notified).await;
    assert!(
        pending.is_err(),
        "changed() fired before any inbound change"
    );

    // A edits and live-pushes to B; B applies and must fire changed().
    ea.edit_text("note", 0, "remote!").await.unwrap();

    let fired = tokio::time::timeout(Duration::from_millis(500), &mut notified).await;
    assert!(
        fired.is_ok(),
        "changed() did not fire after an inbound apply"
    );
    assert_eq!(eb.store().lock().await.text("note"), "remote!");
}

/// No-regression: editing twice through `edit_text` (now routed via
/// `flush_local`) must not duplicate ops on the peer — sent_offsets bookkeeping
/// prevents resending already-sent own-log bytes.
#[tokio::test]
async fn repeated_edits_do_not_duplicate_on_peer() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (da, db) = (tempdir().unwrap(), tempdir().unwrap());
    let (ia, ib) = (Identity::generate(), Identity::generate());

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    seed(&mut sa, &ib);
    seed(&mut sb, &ia);

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
    tokio::time::sleep(Duration::from_millis(120)).await;

    ea.edit_text("note", 0, "ab").await.unwrap();
    let end = ea.store().lock().await.text("note").chars().count();
    ea.edit_text("note", end, "cd").await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // B must hold exactly the two edits, in order, with no duplication.
    let tb = eb.store().lock().await.text("note");
    assert_eq!(
        tb, "abcd",
        "repeated edits duplicated or lost on peer: {tb}"
    );
}
