//! The administrative surface an embedder needs and used to be denied.
//!
//! Every capability here existed as a public `Store` method all along, so what
//! these tests cover is not "can it be done" but the part that was actually
//! missing: the contracts. A mutation that does not persist itself, key material
//! that has to be derived, and — the one with teeth — a change that has to be
//! gossiped or the rest of the mesh never learns of it.
//!
//! Reaching all of this through `Engine::store()` was always possible. It was
//! also how you got it wrong.

use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_sync_core::memory::MemorySwitchboard;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

const VAULT_KEY: [u8; 32] = [11u8; 32];

/// Two engines that have vouched for each other and are running, so anything
/// one broadcasts is observable on the other.
struct Pair {
    a: Arc<Engine<roam_sync_core::memory::MemoryTransport>>,
    b: Arc<Engine<roam_sync_core::memory::MemoryTransport>>,
    b_peer: u64,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

async fn connected_pair() -> Pair {
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

    let a = Arc::new(Engine::new(
        ia.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ia.peer_id())),
        VAULT_KEY,
    ));
    let b = Arc::new(Engine::new(
        ib.clone(),
        vault,
        sb,
        Arc::new(board.endpoint(ib.peer_id())),
        VAULT_KEY,
    ));
    tokio::spawn(a.clone().run());
    tokio::spawn(b.clone().run());
    b.connect(ia.peer_id()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    Pair {
        a,
        b,
        b_peer: ib.peer_id(),
        _dirs: (da, db),
    }
}

/// The one with real teeth. `rotate_epoch` on the raw store appends to the key
/// log and stops; nothing pushes it. Since `seal_under_head` fails CLOSED rather
/// than falling back to epoch 0, every peer that has not received the new key
/// cannot write *at all* — so a rotation that is not gossiped is an outage that
/// lasts until the next reconnect.
#[tokio::test]
async fn rotating_pushes_the_new_epoch_key_to_connected_peers() {
    let pair = connected_pair().await;

    let epoch = pair.a.rotate_epoch(None).await.expect("rotate");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let b_sees = pair
        .b
        .store()
        .lock()
        .await
        .keychain(
            &roam_storage::vault_subkeys(&VAULT_KEY).0,
            &roam_storage::vault_subkeys(&VAULT_KEY).1,
        )
        .expect("build B's keychain")
        .dag_heads();

    assert!(
        b_sees.contains(&epoch),
        "B never learned epoch {epoch:?}; its heads are {b_sees:?}"
    );
}

/// Rotation is Admin-only at the store, and the engine must not paper over that.
#[tokio::test]
async fn a_non_admin_cannot_rotate() {
    let board = MemorySwitchboard::new();
    let dir = tempdir().unwrap();
    let identity = Identity::generate();
    let mut store = Store::open(dir.path(), identity.clone()).unwrap();
    // A vault this device has not been vouched into: no role at all, so the
    // admin gate must refuse.
    let _ = &mut store;

    let engine = Engine::new(
        identity.clone(),
        VaultId::generate(),
        store,
        Arc::new(board.endpoint(identity.peer_id())),
        VAULT_KEY,
    );

    assert!(
        engine.rotate_epoch(None).await.is_err(),
        "a device with no admin role rotated the vault"
    );
}

/// A role change nobody hears about is not a role change. The store call alone
/// only appends to our own roster log.
#[tokio::test]
async fn changing_a_role_reaches_the_other_device() {
    let pair = connected_pair().await;
    let b_store = pair.b.store();
    let b_key = {
        let store = b_store.lock().await;
        store
            .roster()
            .into_iter()
            .find(|p| p.peer_id == pair.b_peer)
            .expect("B knows itself")
            .verifying_key
    };

    pair.a
        .set_role(pair.b_peer, b_key, Role::Reader)
        .await
        .expect("set_role");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let b_role = pair.b.self_role().await;
    assert_eq!(
        b_role,
        Some(Role::Reader),
        "B still believes it is {b_role:?} after A demoted it"
    );
}

/// The name is durable on its own — it is folded from the roster log, which is
/// append-durable, so no snapshot is needed.
///
/// This started as a test that the engine's `write_snapshot` call was
/// load-bearing. Mutation-checking disproved that: removing the call left this
/// passing, because the roster log had already persisted the name. The call was
/// removed and the claim corrected rather than the test weakened.
#[tokio::test]
async fn a_device_name_survives_a_reopen() {
    let board = MemorySwitchboard::new();
    let dir = tempdir().unwrap();
    let identity = Identity::generate();
    let mut store = Store::open(dir.path(), identity.clone()).unwrap();
    store.declare_founder(Role::Admin).unwrap();

    let engine = Engine::new(
        identity.clone(),
        VaultId::generate(),
        store,
        Arc::new(board.endpoint(identity.peer_id())),
        VAULT_KEY,
    );
    engine.set_device_name("laptop").await.expect("set name");
    drop(engine);

    let reopened = Store::open(dir.path(), identity.clone()).unwrap();
    let name = reopened
        .roster()
        .into_iter()
        .find(|p| p.peer_id == identity.peer_id())
        .and_then(|p| p.name);
    assert_eq!(
        name.as_deref(),
        Some("laptop"),
        "the name was not persisted"
    );
}

/// The index, not a `Frontier`, is the version handle — and it is resolved
/// against a freshly read history, so an index that does not exist is an error
/// rather than a revert to the wrong version.
#[tokio::test]
async fn reverting_to_a_version_that_does_not_exist_is_an_error() {
    let board = MemorySwitchboard::new();
    let dir = tempdir().unwrap();
    let identity = Identity::generate();
    let mut store = Store::open(dir.path(), identity.clone()).unwrap();
    store.declare_founder(Role::Admin).unwrap();

    let engine = Engine::new(
        identity.clone(),
        VaultId::generate(),
        store,
        Arc::new(board.endpoint(identity.peer_id())),
        VAULT_KEY,
    );
    engine.edit_text("notes", 0, "hello").await.unwrap();

    let history = engine.text_history("notes").await.expect("history");
    let err = engine
        .revert_text("notes", history.len() + 5)
        .await
        .expect_err("reverting past the end must fail");
    assert!(
        err.to_string().contains("no version"),
        "unhelpful error: {err}"
    );
}

/// Blobs were reachable from wasm and from the CLI but not from the engine,
/// which had only the pull-missing half.
#[tokio::test]
async fn blobs_round_trip_through_the_engine() {
    let board = MemorySwitchboard::new();
    let dir = tempdir().unwrap();
    let identity = Identity::generate();
    let mut store = Store::open(dir.path(), identity.clone()).unwrap();
    store.declare_founder(Role::Admin).unwrap();

    let engine = Engine::new(
        identity.clone(),
        VaultId::generate(),
        store,
        Arc::new(board.endpoint(identity.peer_id())),
        VAULT_KEY,
    );

    let hash = engine.put_blob(b"attachment bytes").await.expect("put");
    assert!(engine.has_blob(&hash).await);
    assert_eq!(
        engine.get_blob(&hash).await.expect("get").as_deref(),
        Some(&b"attachment bytes"[..])
    );
    assert!(
        engine
            .get_blob(&"0".repeat(64))
            .await
            .expect("a missing blob is not an error")
            .is_none(),
        "a blob this device does not hold must read as None, not fail"
    );
}
