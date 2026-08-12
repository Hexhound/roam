use roam_storage::{Identity, Role, Store};
use tempfile::tempdir;

#[test]
fn set_device_name_shows_on_own_peer_record_and_supersedes() {
    let dir = tempdir().unwrap();
    let mut store = Store::open(dir.path(), Identity::generate()).unwrap();
    // A lone `Store::open` is not yet a roster member; self-vouch as founder so
    // the self PeerRecord exists (mirrors text_history.rs).
    store.declare_founder(Role::Admin).unwrap();
    let me = store.self_peer_id();

    store.set_device_name("Sam's laptop").unwrap();
    let rec = store
        .roster()
        .into_iter()
        .find(|p| p.peer_id == me)
        .unwrap();
    assert_eq!(rec.name.as_deref(), Some("Sam's laptop"));

    store.set_device_name("Sam's desktop").unwrap();
    let rec = store
        .roster()
        .into_iter()
        .find(|p| p.peer_id == me)
        .unwrap();
    assert_eq!(rec.name.as_deref(), Some("Sam's desktop"));
}

#[test]
fn set_device_name_rejects_overlong() {
    let dir = tempdir().unwrap();
    let mut store = Store::open(dir.path(), Identity::generate()).unwrap();
    store.declare_founder(Role::Admin).unwrap();
    assert!(store.set_device_name(&"x".repeat(65)).is_err());
}
