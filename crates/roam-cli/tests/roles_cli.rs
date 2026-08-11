//! Role-aware CLI behavior. `main.rs` is a binary crate, so its handlers are not
//! importable from an integration test (matching the existing roam-cli tests,
//! which reconstruct behavior through the storage API rather than calling the
//! `async fn` handlers). These tests exercise the same storage genesis + role
//! transitions the `init`/`grant` handlers drive.
use roam_storage::{Identity, Role, Store};

/// `roam init --role admin` genesis: the founder pins itself and self-vouches
/// with the chosen role, so `self_role()` reports Admin after reopening.
#[test]
fn init_declares_founder_admin() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");

    // Mirror the `init` handler's genesis: open the store and declare_founder.
    let identity = Identity::generate();
    let mut store = Store::open(&vault, identity.clone()).unwrap();
    store.declare_founder(Role::Admin).unwrap();
    drop(store);

    // Reopen with the same identity: the founder role must persist.
    let store = Store::open(&vault, identity).unwrap();
    assert_eq!(store.self_role(), Some(Role::Admin));
}

/// A founder may declare a lesser role (the CLI default is admin, but `--role`
/// lets the creator self-vouch as reader/writer too).
#[test]
fn init_declares_founder_reader() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let identity = Identity::generate();
    let mut store = Store::open(&vault, identity).unwrap();
    store.declare_founder(Role::Reader).unwrap();
    assert_eq!(store.self_role(), Some(Role::Reader));
}
