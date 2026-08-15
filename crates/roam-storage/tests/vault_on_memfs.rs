//! M2 acceptance: a **complete vault lifecycle with no filesystem at all**.
//!
//! Every other test in this crate would still pass if `VaultFs` were a thin
//! wrapper that secretly reached for `std::fs` underneath. This one cannot: it
//! runs against `MemFs` and a root path (`/vault`) that does not exist on any
//! disk. If a single persistence site still called `std::fs` directly, the data
//! would land somewhere this backend cannot see and these assertions would fail.
//!
//! This is the test the browser backend has to pass too — swap `MemFs` for an
//! OPFS implementation and the rest stands unchanged.

use roam_storage::vfs::{MemFs, VaultFs};
use roam_storage::{Identity, Role, Store};
use std::path::Path;
use std::sync::Arc;

const ROOT: &str = "/vault";
const TEXT_ID: &str = "notes/hello.md";

#[test]
fn a_full_vault_lifecycle_runs_entirely_on_a_non_filesystem_backend() {
    let fs: Arc<dyn VaultFs> = Arc::new(MemFs::new());
    let identity = Identity::generate();

    let blob_hash = {
        let mut store = Store::open_with_fs(Path::new(ROOT), identity.clone(), fs.clone())
            .expect("open vault on MemFs");

        store.declare_founder(Role::Admin).expect("declare founder");
        store
            .edit_text(TEXT_ID, 0, "hello from memfs")
            .expect("edit text");
        store
            .set_entry("meta", "title", "Hello")
            .expect("set entry");
        let hash = store.blobs().put(b"blob payload").expect("put blob");
        store.write_snapshot().expect("write snapshot");

        assert_eq!(store.text(TEXT_ID), "hello from memfs");
        assert_eq!(store.self_role(), Some(Role::Admin));
        hash
    };

    // Nothing touched a real disk.
    assert!(
        !Path::new(ROOT).exists(),
        "vault leaked onto the real filesystem"
    );

    // Reopening from the SAME backend must recover everything — this is what
    // proves the bytes were actually persisted through `VaultFs` rather than
    // held in the dropped `Store`.
    let reopened = Store::open_with_fs(Path::new(ROOT), identity.clone(), fs.clone())
        .expect("reopen vault on MemFs");

    assert_eq!(reopened.text(TEXT_ID), "hello from memfs", "text lost");
    assert_eq!(
        reopened.get_entry("meta", "title").as_deref(),
        Some("Hello"),
        "map entry lost"
    );
    assert_eq!(
        reopened.blobs().get(&blob_hash).expect("get blob"),
        Some(b"blob payload".to_vec()),
        "blob lost"
    );
    assert_eq!(
        reopened.founder_pin(),
        Some(identity.peer_id()),
        "founder pin lost"
    );
    assert_eq!(reopened.self_role(), Some(Role::Admin), "role lost");
}

/// The vault writes the layout we expect into the backend — the same paths the
/// native store uses, so a browser backend keyed on them stays interchangeable.
#[test]
fn the_expected_paths_are_written_into_the_backend() {
    let mem = Arc::new(MemFs::new());
    let fs: Arc<dyn VaultFs> = mem.clone();
    let identity = Identity::generate();
    let peer_id = identity.peer_id();

    let mut store =
        Store::open_with_fs(Path::new(ROOT), identity, fs).expect("open vault on MemFs");
    store.declare_founder(Role::Admin).expect("declare founder");
    store.edit_text(TEXT_ID, 0, "hi").expect("edit text");
    store.write_snapshot().expect("write snapshot");

    let written: Vec<String> = mem
        .paths()
        .iter()
        .map(|p| p.to_string_lossy().replace(&peer_id.to_string(), "<PEER>"))
        .collect();

    for expected in [
        "/vault/founder",
        "/vault/ops/ops-<PEER>.jsonl",
        "/vault/roster/roster-<PEER>.jsonl",
        "/vault/snapshots/snapshot.loro",
        "/vault/history/history.jsonl",
    ] {
        assert!(
            written.iter().any(|p| p == expected),
            "expected {expected} in the backend, got {written:?}"
        );
    }

    assert!(
        !written.iter().any(|p| p.ends_with(".tmp")),
        "temporary files left in the backend: {written:?}"
    );
}

/// Two vaults on two independent backends must not see each other, even at the
/// same root path. Guards against any lingering shared global/`std::fs` state.
#[test]
fn separate_backends_are_fully_isolated() {
    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let fs_a: Arc<dyn VaultFs> = Arc::new(MemFs::new());
    let fs_b: Arc<dyn VaultFs> = Arc::new(MemFs::new());

    let mut a = Store::open_with_fs(Path::new(ROOT), identity_a, fs_a).expect("open A");
    a.edit_text(TEXT_ID, 0, "written by A").expect("edit A");
    a.write_snapshot().expect("snapshot A");

    let b = Store::open_with_fs(Path::new(ROOT), identity_b, fs_b).expect("open B");
    assert_eq!(b.text(TEXT_ID), "", "backend B saw backend A's data");
}
