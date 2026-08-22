//! `Engine::with_store`: an embedding app keeps its own `Store` handle.
//!
//! The app opened a store to read and write long before it decided to sync, and
//! sync can be turned off again. `Engine::new` takes the store by value, which
//! would make the engine the sole owner and force every local read through it.
//! `with_store` shares one handle instead — and *one* is the point: two `Store`s
//! over the same directory are two independent op logs that silently diverge.

use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_sync_core::memory::MemorySwitchboard;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::Mutex;

/// A write made through the app's own handle must be visible to the engine, and
/// must gossip to a peer — i.e. it really is the same store, not a copy.
#[tokio::test]
async fn a_write_through_the_apps_handle_reaches_a_peer() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (dir_a, dir_b) = (tempdir().unwrap(), tempdir().unwrap());
    let (id_a, id_b) = (Identity::generate(), Identity::generate());

    let mut store_a = Store::open(dir_a.path(), id_a.clone()).unwrap();
    let mut store_b = Store::open(dir_b.path(), id_b.clone()).unwrap();
    store_a.declare_founder(Role::Admin).unwrap();
    store_b.declare_founder(Role::Admin).unwrap();
    store_a
        .add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    store_b
        .add_peer(id_a.peer_id(), id_a.verifying_key().to_bytes(), Role::Admin)
        .unwrap();

    // The app owns this handle and keeps it after the engine exists.
    let app_store = Arc::new(Mutex::new(store_a));

    let engine_a = Arc::new(Engine::with_store(
        id_a.clone(),
        vault,
        app_store.clone(),
        Arc::new(board.endpoint(id_a.peer_id())),
        [0u8; 32],
    ));
    let engine_b = Arc::new(Engine::new(
        id_b.clone(),
        vault,
        store_b,
        Arc::new(board.endpoint(id_b.peer_id())),
        [0u8; 32],
    ));
    tokio::spawn(engine_a.clone().run());
    tokio::spawn(engine_b.clone().run());

    engine_a.connect(id_b.peer_id()).await.unwrap();
    engine_b.connect(id_a.peer_id()).await.unwrap();

    // Written through the app's handle, never through the engine's.
    app_store
        .lock()
        .await
        .edit_text("note", 0, "app-write")
        .unwrap();
    engine_a.flush_local().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        engine_b.store().lock().await.text("note"),
        "app-write",
        "a write through the app's own handle did not reach the peer"
    );
    assert!(
        Arc::ptr_eq(&engine_a.store(), &app_store),
        "the engine cloned the store instead of sharing the caller's handle"
    );
}
