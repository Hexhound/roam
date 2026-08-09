//! Two-device convergence integration tests for the file-set map.
//!
//! These are the end-to-end proof that delete / rename / edit-vs-delete
//! propagate AND converge across two independent devices, riding the exact same
//! signed peer-merge path as text ops (the file-set MAP ops are just more ops in
//! each device's own log). They complement the single-store reconcile unit tests
//! in `src/bridge.rs` and the CRDT-merge test in `roundtrip.rs`.
//!
//! # How "two devices + sync + scan" is driven through the public API
//!
//! Each [`Device`] is a vault + store_root + identity, and — exactly like the
//! `roundtrip.rs` `Fixture` — opens a FRESH [`FolderBridge`] per operation
//! (`Store::open` replays the persisted oplog, so all state lives on disk
//! between operations, no long-lived handle required).
//!
//! A **sync `from` → `to`** is the real signed peer-merge path:
//!   1. Export the sender's own signed log via `bridge.store().export_own_log()`
//!      — a `&self` call, so reachable through the bridge's `&Store`.
//!   2. Open a plain `Store` at the RECEIVER's own `store_root` (with the
//!      receiver's identity — NOT a neutral third store, so the merged ops land
//!      in the store the receiver's bridge itself reopens), ensure mutual roster
//!      trust (`add_peer`), and `apply_peer_ops` the sender's log. `import_peer`
//!      writes `ops/ops-<peer>.jsonl` and merges into the doc, so the merge is
//!      DURABLE.
//!   3. Drop that store; the next `Device::open` replays own + peer logs and thus
//!      sees the merged map + text ops.
//!
//! Because the receiver's bridge reopens the very store the merge was written
//! into, `FolderBridge::scan` runs its reconcile against a store that has
//! received the other device's ops — the whole point of the task. This needs NO
//! widening of the `roam-files` public API: `export_own_log`, `add_peer`,
//! `apply_peer_ops` are all on the public `roam_storage::Store`, reached for the
//! sender via `bridge.store()` and for the receiver by opening its own store
//! root directly (the store root is the value the test itself supplied to
//! `FolderBridge::open`).

use std::path::PathBuf;

use roam_files::{
    container_id, sidecar_path, EntryStatus, FileEntry, FolderBridge, FILESET_MAP_ID,
};
use roam_storage::{Identity, Store};
use tempfile::tempdir;

/// One device: an isolated vault + store_root + stable identity.
struct Device {
    _dir: tempfile::TempDir,
    vault: PathBuf,
    store: PathBuf,
    identity: Identity,
}

impl Device {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let store = dir.path().join("store");
        std::fs::create_dir_all(&vault).unwrap();
        Device {
            _dir: dir,
            vault,
            store,
            identity: Identity::generate(),
        }
    }

    /// Open a fresh bridge over this device's (persisted) vault + store.
    fn open(&self) -> FolderBridge {
        FolderBridge::open(&self.vault, &self.store, self.identity.clone()).unwrap()
    }

    fn vault_file(&self, rel: &str) -> PathBuf {
        self.vault.join(rel)
    }

    /// The file-set entry for `container`, if the map holds one.
    fn entry(&self, container: &str) -> Option<FileEntry> {
        self.open()
            .store()
            .get_entry(FILESET_MAP_ID, container)
            .map(|v| FileEntry::from_value(&v).unwrap())
    }

    /// The container's current CRDT text on this device.
    fn store_text(&self, container: &str) -> String {
        self.open().store().text(container)
    }
}

/// Real signed peer-merge: export `from`'s own log and durably apply it into
/// `to`'s OWN store (so `to`'s next `open()` replays it). Establishes roster
/// trust lazily the first time a given sender is seen.
fn sync(from: &Device, to: &Device) {
    let log = from.open().store().export_own_log().unwrap();

    let mut store = Store::open(&to.store, to.identity.clone()).unwrap();
    let from_key = from.identity.verifying_key();
    if !store
        .roster()
        .iter()
        .any(|p| p.peer_id == from.identity.peer_id())
    {
        store
            .add_peer(from.identity.peer_id(), from_key.to_bytes())
            .unwrap();
    }
    store
        .apply_peer_ops(from.identity.peer_id(), &from_key, &log)
        .unwrap();
    // `store` drops here, releasing `to`'s store_root for the next `open()`.
}

/// One full bidirectional round: sync both ways, then reconcile both devices.
fn round(a: &Device, b: &Device) {
    sync(a, b);
    sync(b, a);
    a.open().scan().unwrap();
    b.open().scan().unwrap();
}

/// Snapshot of a device's observable state for one file, for convergence /
/// stability assertions.
#[derive(Debug, PartialEq, Eq)]
struct FileState {
    disk: Option<Vec<u8>>,
    sidecar_exists: bool,
    status: Option<EntryStatus>,
}

fn state(device: &Device, rel: &str, container: &str) -> FileState {
    let file = device.vault_file(rel);
    FileState {
        disk: std::fs::read(&file).ok(),
        sidecar_exists: sidecar_path(&file).exists(),
        status: device.entry(container).map(|e| e.status),
    }
}

/// Import `text` into `rel` on `device` (writes disk, then imports).
fn import(device: &Device, rel: &str, text: &str) {
    let file = device.vault_file(rel);
    std::fs::write(&file, text).unwrap();
    device.open().import_file(&file).unwrap();
}

fn cid(device: &Device, rel: &str) -> String {
    container_id(&device.vault, &device.vault_file(rel)).unwrap()
}

// ---------------------------------------------------------------------------
// 1. Delete propagates A -> B.
// ---------------------------------------------------------------------------
#[test]
fn delete_propagates_a_to_b() {
    let a = Device::new();
    let b = Device::new();
    let rel = "note.md";
    let container = cid(&a, rel);

    // A creates the file; sync to B; B materializes it on disk.
    import(&a, rel, "hello\n");
    sync(&a, &b);
    b.open().scan().unwrap();
    assert_eq!(std::fs::read(b.vault_file(rel)).unwrap(), b"hello\n");
    assert!(sidecar_path(&b.vault_file(rel)).exists());

    // A deletes the file; sync to B; B applies the tombstone.
    a.open().delete_file(&a.vault_file(rel)).unwrap();
    sync(&a, &b);
    b.open().scan().unwrap();

    // B's disk copy and sidecar are gone, and the entry is a tombstone.
    assert!(
        !b.vault_file(rel).exists(),
        "delete on A must remove the file on B"
    );
    assert!(!sidecar_path(&b.vault_file(rel)).exists());
    assert_eq!(b.entry(&container).map(|e| e.status), Some(EntryStatus::Tombstoned));
}

// ---------------------------------------------------------------------------
// 2. Rename propagates A -> B.
// ---------------------------------------------------------------------------
#[test]
fn rename_propagates_a_to_b() {
    let a = Device::new();
    let b = Device::new();
    let old_container = cid(&a, "old.md");
    let new_container = cid(&a, "new.md");

    import(&a, "old.md", "content\n");
    sync(&a, &b);
    b.open().scan().unwrap();
    assert_eq!(std::fs::read(b.vault_file("old.md")).unwrap(), b"content\n");

    a.open()
        .rename_file(&a.vault_file("old.md"), &a.vault_file("new.md"))
        .unwrap();
    sync(&a, &b);
    b.open().scan().unwrap();

    // On B: old path gone, new path present with the moved content.
    assert!(!b.vault_file("old.md").exists(), "rename must remove old path on B");
    assert_eq!(std::fs::read(b.vault_file("new.md")).unwrap(), b"content\n");
    assert_eq!(
        b.entry(&old_container).map(|e| e.status),
        Some(EntryStatus::Tombstoned)
    );
    assert_eq!(
        b.entry(&new_container).map(|e| e.status),
        Some(EntryStatus::Live)
    );
}

// ---------------------------------------------------------------------------
// 3. Concurrent edit-vs-delete -> EDIT WINS, converges (the critical one).
// ---------------------------------------------------------------------------
#[test]
fn concurrent_edit_vs_delete_edit_wins_and_converges() {
    let a = Device::new();
    let b = Device::new();
    let rel = "x.md";
    let container = cid(&a, rel);

    // Both devices start synced with x.md = "hello\n".
    import(&a, rel, "hello\n");
    sync(&a, &b);
    b.open().scan().unwrap();
    assert_eq!(std::fs::read(b.vault_file(rel)).unwrap(), b"hello\n");

    // CONCURRENTLY (no sync between):
    //  - A deletes x.md (tombstones with the last-synced hash of "hello\n").
    a.open().delete_file(&a.vault_file(rel)).unwrap();
    //  - B edits its disk x.md and imports (container diverges; entry stays Live).
    import(&b, rel, "hello world\n");

    // Drive both directions + reconcile until settled. Edit-wins needs the
    // resurrecting device to re-broadcast its Live flip, so run several rounds.
    for _ in 0..4 {
        round(&a, &b);
    }

    // CONVERGENCE: identical final state on both, and per edit-wins the file is
    // PRESENT with the edited content and the entry is Live on BOTH. Neither
    // device is left with the file deleted.
    let final_a = state(&a, rel, &container);
    let final_b = state(&b, rel, &container);
    assert_eq!(final_a, final_b, "both devices must converge to the same state");
    assert_eq!(
        final_a.disk.as_deref(),
        Some(&b"hello world\n"[..]),
        "edit must win: file present with the edited content"
    );
    assert_eq!(final_a.status, Some(EntryStatus::Live));
    assert_eq!(a.store_text(&container), "hello world\n");
    assert_eq!(b.store_text(&container), "hello world\n");

    // STABILITY: further sync+scan rounds are idempotent (no flip-flop).
    let before = (state(&a, rel, &container), state(&b, rel, &container));
    round(&a, &b);
    round(&a, &b);
    let after = (state(&a, rel, &container), state(&b, rel, &container));
    assert_eq!(before, after, "converged state must be stable across more rounds");
}

// ---------------------------------------------------------------------------
// 4. Delete with NO concurrent edit -> delete wins, converges.
// ---------------------------------------------------------------------------
#[test]
fn delete_without_concurrent_edit_delete_wins_and_converges() {
    let a = Device::new();
    let b = Device::new();
    let rel = "y.md";
    let container = cid(&a, rel);

    import(&a, rel, "yes\n");
    sync(&a, &b);
    b.open().scan().unwrap();
    assert_eq!(std::fs::read(b.vault_file(rel)).unwrap(), b"yes\n");

    // A deletes; NO concurrent edit on B.
    a.open().delete_file(&a.vault_file(rel)).unwrap();

    for _ in 0..3 {
        round(&a, &b);
    }

    // Both converge to ABSENT + Tombstoned.
    let final_a = state(&a, rel, &container);
    let final_b = state(&b, rel, &container);
    assert_eq!(final_a, final_b, "both devices must converge to the same state");
    assert_eq!(final_a.disk, None, "delete must win: file absent");
    assert!(!final_a.sidecar_exists);
    assert_eq!(final_a.status, Some(EntryStatus::Tombstoned));

    // Stable across another round.
    let before = (state(&a, rel, &container), state(&b, rel, &container));
    round(&a, &b);
    let after = (state(&a, rel, &container), state(&b, rel, &container));
    assert_eq!(before, after, "converged delete state must be stable");
}

// ---------------------------------------------------------------------------
// 5. Sync-ordering independence: edit-vs-delete converges to edit-wins whether
//    B->A or A->B is applied first.
// ---------------------------------------------------------------------------
#[test]
fn edit_vs_delete_converges_regardless_of_sync_order() {
    // Helper: run the edit-vs-delete scenario applying the two directions in a
    // caller-chosen order for the FIRST reconciling round, then settle.
    fn run(b_first: bool) -> (Vec<u8>, EntryStatus) {
        let a = Device::new();
        let b = Device::new();
        let rel = "z.md";
        let container = cid(&a, rel);

        import(&a, rel, "hello\n");
        sync(&a, &b);
        b.open().scan().unwrap();

        // Concurrent divergence.
        a.open().delete_file(&a.vault_file(rel)).unwrap();
        import(&b, rel, "hello world\n");

        // First reconciling round with the chosen application order.
        if b_first {
            sync(&b, &a);
            sync(&a, &b);
        } else {
            sync(&a, &b);
            sync(&b, &a);
        }
        a.open().scan().unwrap();
        b.open().scan().unwrap();
        // Settle.
        for _ in 0..3 {
            round(&a, &b);
        }

        let sa = state(&a, rel, &container);
        let sb = state(&b, rel, &container);
        assert_eq!(sa, sb, "devices must converge (b_first={b_first})");
        (sa.disk.unwrap(), sa.status.unwrap())
    }

    let ab = run(false);
    let ba = run(true);
    assert_eq!(ab, ba, "edit-wins convergence must be sync-order independent");
    assert_eq!(ab.0, b"hello world\n");
    assert_eq!(ab.1, EntryStatus::Live);
}
