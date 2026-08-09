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
//! `roundtrip.rs` `Fixture` — opens a FRESH caller-owned `Store` plus a
//! stateless [`FolderBridge`] per operation (`Store::open` replays the persisted
//! oplog, so all state lives on disk between operations, no long-lived handle
//! required).
//!
//! A **sync `from` → `to`** is the real signed peer-merge path:
//!   1. Export the sender's own signed log via the sender's `Store`'s
//!      `export_own_log()`.
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
//! sender via its own caller-owned `Store` and for the receiver by opening its
//! own store root directly (the store root is the value the test itself supplied
//! to the device).

use std::path::{Path, PathBuf};

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

    /// Open a fresh caller-owned store plus a stateless bridge over this
    /// device's (persisted) vault + store.
    fn open(&self) -> (FolderBridge, Store) {
        let bridge = FolderBridge::new(&self.vault);
        let store = Store::open(&self.store, self.identity.clone()).unwrap();
        (bridge, store)
    }

    fn vault_file(&self, rel: &str) -> PathBuf {
        self.vault.join(rel)
    }

    /// Scan (reconcile) this device: open store + bridge for the op and thread
    /// the `&mut Store` into `scan`.
    fn scan(&self) {
        let (bridge, mut store) = self.open();
        bridge.scan(&mut store).unwrap();
    }

    /// Delete `file` on this device via the bridge (open store + bridge per op).
    fn delete_file(&self, file: &Path) {
        let (bridge, mut store) = self.open();
        bridge.delete_file(&mut store, file).unwrap();
    }

    /// Rename `from` → `to` on this device via the bridge (open store + bridge
    /// per op).
    fn rename_file(&self, from: &Path, to: &Path) {
        let (bridge, mut store) = self.open();
        bridge.rename_file(&mut store, from, to).unwrap();
    }

    /// The file-set entry for `container`, if the map holds one.
    fn entry(&self, container: &str) -> Option<FileEntry> {
        let (_bridge, store) = self.open();
        store
            .get_entry(FILESET_MAP_ID, container)
            .map(|v| FileEntry::from_value(&v).unwrap())
    }

    /// The container's current CRDT text on this device.
    fn store_text(&self, container: &str) -> String {
        let (_bridge, store) = self.open();
        store.text(container)
    }
}

/// Real signed peer-merge: export `from`'s own log and durably apply it into
/// `to`'s OWN store (so `to`'s next `open()` replays it). Establishes roster
/// trust lazily the first time a given sender is seen.
fn sync(from: &Device, to: &Device) {
    let (_from_bridge, from_store) = from.open();
    let log = from_store.export_own_log().unwrap();

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
    a.scan();
    b.scan();
}

/// Snapshot of a device's observable state for one file, for convergence /
/// stability assertions.
#[derive(Debug, PartialEq, Eq)]
struct FileState {
    disk: Option<Vec<u8>>,
    sidecar_exists: bool,
    status: Option<EntryStatus>,
    /// The container's CRDT text — included so a container/disk divergence is
    /// caught by the convergence equality, not just disk + status.
    text: String,
}

fn state(device: &Device, rel: &str, container: &str) -> FileState {
    let file = device.vault_file(rel);
    FileState {
        disk: std::fs::read(&file).ok(),
        sidecar_exists: sidecar_path(&file).exists(),
        status: device.entry(container).map(|e| e.status),
        text: device.store_text(container),
    }
}

/// Import `text` into `rel` on `device` (writes disk, then imports).
fn import(device: &Device, rel: &str, text: &str) {
    let file = device.vault_file(rel);
    std::fs::write(&file, text).unwrap();
    let (bridge, mut store) = device.open();
    bridge.import_file(&mut store, &file).unwrap();
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
    b.scan();
    assert_eq!(std::fs::read(b.vault_file(rel)).unwrap(), b"hello\n");
    assert!(sidecar_path(&b.vault_file(rel)).exists());

    // A deletes the file; sync to B; B applies the tombstone.
    a.delete_file(&a.vault_file(rel));
    sync(&a, &b);
    b.scan();

    // B's disk copy and sidecar are gone, and the entry is a tombstone.
    assert!(
        !b.vault_file(rel).exists(),
        "delete on A must remove the file on B"
    );
    assert!(!sidecar_path(&b.vault_file(rel)).exists());
    assert_eq!(
        b.entry(&container).map(|e| e.status),
        Some(EntryStatus::Tombstoned)
    );
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
    b.scan();
    assert_eq!(std::fs::read(b.vault_file("old.md")).unwrap(), b"content\n");

    a.rename_file(&a.vault_file("old.md"), &a.vault_file("new.md"));
    sync(&a, &b);
    b.scan();

    // On B: old path gone, new path present with the moved content.
    assert!(
        !b.vault_file("old.md").exists(),
        "rename must remove old path on B"
    );
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
// 3. Concurrent edit-vs-delete -> EDIT WINS (Lamport-favors-edit case).
//
// Here A's delete is a SINGLE op, so B's edit + Live `set_entry` carry the
// HIGHER Lamport and the file-set map's LWW picks Live outright — convergence
// is reached in the first round with NO resurrection flip required. The harder
// case, where A's tombstone out-Lamports the edit so the map first resolves to
// Tombstoned and the editing device must flip-to-Live + re-broadcast before the
// deleter re-projects, is driven end-to-end by
// `forced_tombstone_wins_resurrection_converges_end_to_end` below.
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
    b.scan();
    assert_eq!(std::fs::read(b.vault_file(rel)).unwrap(), b"hello\n");

    // CONCURRENTLY (no sync between):
    //  - A deletes x.md (tombstones with the last-synced hash of "hello\n").
    a.delete_file(&a.vault_file(rel));
    //  - B edits its disk x.md and imports (container diverges; entry stays Live).
    import(&b, rel, "hello world\n");

    // Drive both directions + reconcile. This case converges in the first
    // round (B's Live out-Lamports A's single-op tombstone), but run a couple
    // to be robust; stability is asserted per-round below.
    for _ in 0..3 {
        round(&a, &b);
    }

    // CONVERGENCE: identical final state on both, and per edit-wins the file is
    // PRESENT with the edited content and the entry is Live on BOTH. Neither
    // device is left with the file deleted.
    let final_a = state(&a, rel, &container);
    let final_b = state(&b, rel, &container);
    assert_eq!(
        final_a, final_b,
        "both devices must converge to the same state"
    );
    assert_eq!(
        final_a.disk.as_deref(),
        Some(&b"hello world\n"[..]),
        "edit must win: file present with the edited content"
    );
    assert_eq!(final_a.status, Some(EntryStatus::Live));
    assert_eq!(a.store_text(&container), "hello world\n");
    assert_eq!(b.store_text(&container), "hello world\n");

    // STABILITY: assert after EACH single round (comparing after two rounds
    // could alias a period-2 oscillation).
    let snapshot = |a: &Device, b: &Device| (state(a, rel, &container), state(b, rel, &container));
    let baseline = snapshot(&a, &b);
    round(&a, &b);
    assert_eq!(
        snapshot(&a, &b),
        baseline,
        "state must be stable after one round"
    );
    round(&a, &b);
    assert_eq!(
        snapshot(&a, &b),
        baseline,
        "state must be stable after a second round"
    );
}

// ---------------------------------------------------------------------------
// 3b. Forced TOMBSTONE-WINS-LWW edit-vs-delete: drives the resurrection
//     flip + re-broadcast path end-to-end (the real edit-wins guarantee under
//     realistic Lamport ordering).
//
// Loro's file-set map is an LWW register keyed by (Lamport, peer_id): the write
// with the HIGHER Lamport wins. Here we deliberately make A's DELETE op carry a
// higher Lamport than B's concurrent edit by having A perform several unrelated
// ops first (import + edit `z.md`), so when the two devices merge, the map for
// `x` resolves to Tombstoned FIRST — NOT Live. Convergence to edit-wins then
// REQUIRES: the editing device (B) sees Tombstoned-but-container-diverged,
// flips the entry back to Live at a fresh (now-highest) Lamport, and
// re-broadcasts it; only after that reaches the deleter (A) — which has no disk
// copy — does A re-project `x.md` via the remote-new branch. This is the path
// test #3 never exercises (there Lamport favors the edit outright).
// ---------------------------------------------------------------------------
#[test]
fn forced_tombstone_wins_resurrection_converges_end_to_end() {
    let a = Device::new();
    let b = Device::new();
    let rel = "x.md";
    let container = cid(&a, rel);

    // Both devices start synced with x.md = "hello\n".
    import(&a, rel, "hello\n");
    sync(&a, &b);
    b.scan();
    assert_eq!(
        a.entry(&container).map(|e| e.status),
        Some(EntryStatus::Live)
    );
    assert_eq!(
        b.entry(&container).map(|e| e.status),
        Some(EntryStatus::Live)
    );

    // CONCURRENTLY (no sync between):
    //  - On A: raise A's Lamport clock ABOVE B's coming edit with unrelated ops
    //    (import + two edits of z.md), THEN delete x.md. A's tombstone-for-x now
    //    carries a higher Lamport than B's Live-for-x.
    import(&a, "z.md", "one\n");
    import(&a, "z.md", "one\ntwo\n");
    import(&a, "z.md", "one\ntwo\nthree\n");
    a.delete_file(&a.vault_file(rel));
    //  - On B: edit x.md and import (Live at a LOWER Lamport).
    import(&b, rel, "hello world\n");

    // First merge BOTH directions but do NOT scan yet: prove the map's LWW
    // actually picked Tombstoned (higher-Lamport delete beats the edit). This is
    // the pre-condition that makes the resurrection path mandatory.
    sync(&a, &b);
    sync(&b, &a);
    assert_eq!(
        a.entry(&container).map(|e| e.status),
        Some(EntryStatus::Tombstoned),
        "forced construction: A's delete must out-Lamport B's edit (Tombstoned wins LWW)"
    );
    assert_eq!(
        b.entry(&container).map(|e| e.status),
        Some(EntryStatus::Tombstoned),
        "both devices agree the map resolved to Tombstoned before any resurrection"
    );

    // Round 1 reconcile (no further sync): B sees Tombstoned + container diverged
    // → resurrection flip to Live locally; A has no disk copy so it does nothing
    // yet. The flip has NOT reached A.
    a.scan();
    b.scan();
    assert_eq!(
        b.entry(&container).map(|e| e.status),
        Some(EntryStatus::Live),
        "editing device must flip the tombstone back to Live (resurrection)"
    );
    assert!(
        !a.vault_file(rel).exists(),
        "deleter must NOT have re-projected yet — the Live flip hasn't propagated"
    );
    assert_eq!(
        a.entry(&container).map(|e| e.status),
        Some(EntryStatus::Tombstoned),
        "deleter still holds the tombstone until B's flip is re-broadcast"
    );

    // Round 2: re-broadcast B's fresh Live to A; A then re-projects x.md via the
    // remote-new branch (Live + absent + no sidecar).
    sync(&a, &b);
    sync(&b, &a);
    assert_eq!(
        a.entry(&container).map(|e| e.status),
        Some(EntryStatus::Live),
        "B's resurrection flip must propagate to the deleter"
    );
    a.scan();
    b.scan();
    assert!(
        a.vault_file(rel).exists(),
        "deleter must RE-PROJECT x.md to disk after receiving B's fresh Live"
    );

    // A couple of bounded settle rounds, then assert full convergence.
    for _ in 0..2 {
        round(&a, &b);
    }
    let final_a = state(&a, rel, &container);
    let final_b = state(&b, rel, &container);
    assert_eq!(
        final_a, final_b,
        "both devices must converge to the same state"
    );
    assert_eq!(
        final_a.disk.as_deref(),
        Some(&b"hello world\n"[..]),
        "edit must win end-to-end: file present with the edited content"
    );
    assert_eq!(final_a.status, Some(EntryStatus::Live));
    assert_eq!(final_a.text, "hello world\n");

    // STABILITY: idempotent after each single round.
    let snapshot = |a: &Device, b: &Device| (state(a, rel, &container), state(b, rel, &container));
    let baseline = snapshot(&a, &b);
    round(&a, &b);
    assert_eq!(
        snapshot(&a, &b),
        baseline,
        "converged state stable after one round"
    );
    round(&a, &b);
    assert_eq!(
        snapshot(&a, &b),
        baseline,
        "converged state stable after a second round"
    );
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
    b.scan();
    assert_eq!(std::fs::read(b.vault_file(rel)).unwrap(), b"yes\n");

    // A deletes; NO concurrent edit on B.
    a.delete_file(&a.vault_file(rel));

    for _ in 0..3 {
        round(&a, &b);
    }

    // Both converge to ABSENT + Tombstoned.
    let final_a = state(&a, rel, &container);
    let final_b = state(&b, rel, &container);
    assert_eq!(
        final_a, final_b,
        "both devices must converge to the same state"
    );
    assert_eq!(final_a.disk, None, "delete must win: file absent");
    assert!(!final_a.sidecar_exists);
    assert_eq!(final_a.status, Some(EntryStatus::Tombstoned));
    // The text container is retained on both (tombstone keeps history); the
    // `FileState` equality above already proves A and B agree on it.

    // Stable after a single round (avoids aliasing a period-2 oscillation).
    let baseline = (state(&a, rel, &container), state(&b, rel, &container));
    round(&a, &b);
    let after = (state(&a, rel, &container), state(&b, rel, &container));
    assert_eq!(baseline, after, "converged delete state must be stable");
}

// ---------------------------------------------------------------------------
// 5. Sync-ordering independence: edit-vs-delete converges to edit-wins whether
//    B->A or A->B is applied first.
// ---------------------------------------------------------------------------
#[test]
fn edit_vs_delete_converges_regardless_of_sync_order() {
    // Helper: run the edit-vs-delete scenario applying the two directions in a
    // caller-chosen order for the FIRST reconciling round, then settle. Returns
    // (disk bytes, entry status, container text) so a container/disk divergence
    // is caught by the order-independence comparison.
    fn run(b_first: bool) -> (Vec<u8>, EntryStatus, String) {
        let a = Device::new();
        let b = Device::new();
        let rel = "z.md";
        let container = cid(&a, rel);

        import(&a, rel, "hello\n");
        sync(&a, &b);
        b.scan();

        // Concurrent divergence.
        a.delete_file(&a.vault_file(rel));
        import(&b, rel, "hello world\n");

        // First reconciling round with the chosen application order.
        if b_first {
            sync(&b, &a);
            sync(&a, &b);
        } else {
            sync(&a, &b);
            sync(&b, &a);
        }
        a.scan();
        b.scan();
        // Settle.
        for _ in 0..3 {
            round(&a, &b);
        }

        let sa = state(&a, rel, &container);
        let sb = state(&b, rel, &container);
        assert_eq!(sa, sb, "devices must converge (b_first={b_first})");
        (sa.disk.unwrap(), sa.status.unwrap(), sa.text)
    }

    let ab = run(false);
    let ba = run(true);
    assert_eq!(
        ab, ba,
        "edit-wins convergence must be sync-order independent"
    );
    assert_eq!(ab.0, b"hello world\n");
    assert_eq!(ab.1, EntryStatus::Live);
    assert_eq!(ab.2, "hello world\n");
}

// ===========================================================================
// WS-F / F1 — THREE-device file-set convergence (A, B, C mutually trusted).
//
// The 2-device `sync`/`round`/`state` harness above generalizes cleanly: a
// `sync` is a directed signed peer-merge for ANY ordered pair (roster trust is
// established lazily per sender), so a fully-connected 3-device round is just
// every ordered pair synced, then all three reconciled. Topology: complete
// mesh A↔B↔C↔A — every device directly syncs every other, the strongest
// convergence obligation.
// ===========================================================================

/// One full round over a complete 3-mesh: sync every ordered pair (so any
/// device's newest ops reach both others directly), then reconcile all three.
/// Bounded and deterministic — the LWW tiebreak is `(Lamport, peer_id)`.
fn round3(a: &Device, b: &Device, c: &Device) {
    sync(a, b);
    sync(a, c);
    sync(b, a);
    sync(b, c);
    sync(c, a);
    sync(c, b);
    a.scan();
    b.scan();
    c.scan();
}

/// Assert all three devices hold an identical `FileState` for `rel`/`container`,
/// and return that shared state for further per-field assertions.
fn converged3(a: &Device, b: &Device, c: &Device, rel: &str, container: &str) -> FileState {
    let sa = state(a, rel, container);
    let sb = state(b, rel, container);
    let sc = state(c, rel, container);
    assert_eq!(sa, sb, "A and B must converge to the same state");
    assert_eq!(sb, sc, "B and C must converge to the same state");
    sa
}

// ---------------------------------------------------------------------------
// F1.1 — create on A propagates to B AND C.
// ---------------------------------------------------------------------------
#[test]
fn create_propagates_a_to_b_and_c() {
    let a = Device::new();
    let b = Device::new();
    let c = Device::new();
    let rel = "note.md";
    let container = cid(&a, rel);

    import(&a, rel, "hello\n");
    for _ in 0..3 {
        round3(&a, &b, &c);
    }

    let final_state = converged3(&a, &b, &c, rel, &container);
    assert_eq!(final_state.disk.as_deref(), Some(&b"hello\n"[..]));
    assert!(final_state.sidecar_exists);
    assert_eq!(final_state.status, Some(EntryStatus::Live));
    assert_eq!(final_state.text, "hello\n");
    // Explicit: the file is present on ALL three, not merely equal.
    assert!(a.vault_file(rel).exists());
    assert!(b.vault_file(rel).exists());
    assert!(c.vault_file(rel).exists());

    // Stability across an extra round.
    let baseline = converged3(&a, &b, &c, rel, &container);
    round3(&a, &b, &c);
    assert_eq!(
        converged3(&a, &b, &c, rel, &container),
        baseline,
        "3-device create must be stable across an extra round"
    );
}

// ---------------------------------------------------------------------------
// F1.2 — delete on A (no concurrent edit) → gone on B and C, Tombstoned on all.
// ---------------------------------------------------------------------------
#[test]
fn delete_propagates_a_to_b_and_c() {
    let a = Device::new();
    let b = Device::new();
    let c = Device::new();
    let rel = "note.md";
    let container = cid(&a, rel);

    import(&a, rel, "hello\n");
    for _ in 0..3 {
        round3(&a, &b, &c);
    }
    assert!(b.vault_file(rel).exists());
    assert!(c.vault_file(rel).exists());

    a.delete_file(&a.vault_file(rel));
    for _ in 0..3 {
        round3(&a, &b, &c);
    }

    let final_state = converged3(&a, &b, &c, rel, &container);
    assert_eq!(final_state.disk, None, "delete must win: file absent");
    assert!(!final_state.sidecar_exists);
    assert_eq!(final_state.status, Some(EntryStatus::Tombstoned));
    // Gone on B and C explicitly.
    assert!(!b.vault_file(rel).exists());
    assert!(!c.vault_file(rel).exists());

    let baseline = converged3(&a, &b, &c, rel, &container);
    round3(&a, &b, &c);
    assert_eq!(
        converged3(&a, &b, &c, rel, &container),
        baseline,
        "3-device delete must be stable across an extra round"
    );
}

// ---------------------------------------------------------------------------
// F1.3 — rename on A → old gone / new present with content on B and C.
// ---------------------------------------------------------------------------
#[test]
fn rename_propagates_a_to_b_and_c() {
    let a = Device::new();
    let b = Device::new();
    let c = Device::new();
    let old_container = cid(&a, "old.md");
    let new_container = cid(&a, "new.md");

    import(&a, "old.md", "content\n");
    for _ in 0..3 {
        round3(&a, &b, &c);
    }
    assert!(b.vault_file("old.md").exists());
    assert!(c.vault_file("old.md").exists());

    a.rename_file(&a.vault_file("old.md"), &a.vault_file("new.md"));
    for _ in 0..3 {
        round3(&a, &b, &c);
    }

    // New path: identical Live state on all three, holding the moved content.
    let new_state = converged3(&a, &b, &c, "new.md", &new_container);
    assert_eq!(new_state.disk.as_deref(), Some(&b"content\n"[..]));
    assert_eq!(new_state.status, Some(EntryStatus::Live));
    // Old path: gone / Tombstoned on all three.
    let old_state = converged3(&a, &b, &c, "old.md", &old_container);
    assert_eq!(old_state.disk, None);
    assert_eq!(old_state.status, Some(EntryStatus::Tombstoned));

    assert!(!b.vault_file("old.md").exists());
    assert!(!c.vault_file("old.md").exists());
    assert!(b.vault_file("new.md").exists());
    assert!(c.vault_file("new.md").exists());

    // Stability for both paths.
    let base_new = converged3(&a, &b, &c, "new.md", &new_container);
    let base_old = converged3(&a, &b, &c, "old.md", &old_container);
    round3(&a, &b, &c);
    assert_eq!(converged3(&a, &b, &c, "new.md", &new_container), base_new);
    assert_eq!(converged3(&a, &b, &c, "old.md", &old_container), base_old);
}

// ---------------------------------------------------------------------------
// F1.4 — concurrent edit-vs-delete across 3 devices → EDIT WINS on all three.
//
// A and B start synced with x.md; then CONCURRENTLY A deletes it while B edits
// it. C is a PASSIVE third party — it was not party to the original file and
// only observes the resolved file-set state as the mesh settles. A's delete is a
// SINGLE op, so B's edit + Live `set_entry` out-Lamport it and the file-set
// map's LWW picks Live — the analogue of the 2-device test #3, now with a third
// device that must also converge to edit-wins.
//
// C is modeled as a fresh observer (no prior local copy) deliberately: the
// bridge's `scan` re-projects a remotely-edited container onto disk only via the
// remote-new path (Live + absent + no sidecar). A device that already holds a
// clean-but-stale disk copy of a remotely-edited file is NOT re-projected by
// `scan` at the bridge layer — a separate, pre-existing reconcile concern
// outside WS-F's file-set convergence scope. Driving C as a passive newcomer
// exercises exactly the 3-device LWW merge (A's tombstone + B's Live both reach
// C; C resolves Live and projects the edit-wins content) that WS-F targets.
// ---------------------------------------------------------------------------
#[test]
fn concurrent_edit_vs_delete_three_device_edit_wins_and_converges() {
    let a = Device::new();
    let b = Device::new();
    let c = Device::new();
    let rel = "x.md";
    let container = cid(&a, rel);

    // A and B start synced with x.md = "hello\n"; C has NOT seen the file yet.
    import(&a, rel, "hello\n");
    sync(&a, &b);
    b.scan();
    assert_eq!(std::fs::read(b.vault_file(rel)).unwrap(), b"hello\n");
    assert!(!c.vault_file(rel).exists(), "C is a fresh passive observer");

    // CONCURRENTLY (no sync between):
    //  - A deletes x.md (single-op tombstone).
    a.delete_file(&a.vault_file(rel));
    //  - B edits + imports (container diverges; entry stays Live).
    //  - C does nothing (passive third party; receives the resolved state below).
    import(&b, rel, "hello world\n");

    for _ in 0..4 {
        round3(&a, &b, &c);
    }

    // CONVERGENCE: identical final state on all three, edit-wins.
    let final_state = converged3(&a, &b, &c, rel, &container);
    assert_eq!(
        final_state.disk.as_deref(),
        Some(&b"hello world\n"[..]),
        "edit must win on all three: file present with the edited content"
    );
    assert_eq!(final_state.status, Some(EntryStatus::Live));
    assert_eq!(final_state.text, "hello world\n");
    assert!(a.vault_file(rel).exists());
    assert!(b.vault_file(rel).exists());
    assert!(c.vault_file(rel).exists());

    // STABILITY across an extra round (asserted after a single round, so a
    // period-2 oscillation can't alias as stable).
    let baseline = converged3(&a, &b, &c, rel, &container);
    round3(&a, &b, &c);
    assert_eq!(
        converged3(&a, &b, &c, rel, &container),
        baseline,
        "3-device edit-wins must be stable across an extra round"
    );
    round3(&a, &b, &c);
    assert_eq!(
        converged3(&a, &b, &c, rel, &container),
        baseline,
        "3-device edit-wins must be stable across a second extra round"
    );
}

// ===========================================================================
// WS-F / F2 — RELAYED peer-log path at the files layer.
//
// Topology: A↔B and B↔C, but NEVER A↔C directly. A's ops reach C ONLY because
// B re-exports A's stored log to C. This mirrors the sync-core mesh test's
// transitive gossip (`c_learns_b_transitively_through_a`) but drives it at the
// Store level and asserts file-set / disk outcomes.
//
// HOW THE RELAY IS DRIVEN: after `sync(A, B)`, B durably holds A's signed log at
// `ops/ops-<A>.jsonl`. `relay(via = B, author = A, to = C)` reads that with
// `export_peer_log(A.peer_id())` — A's ORIGINAL signatures, untouched — and lands
// it in C via `apply_peer_ops(A.peer_id(), &A_key, log)`. C independently trusts A
// (roster `add_peer`, as it would after transitive roster gossip). No
// `export_own_log` on A is ever shipped to C, and A and C never sync directly.
// ===========================================================================

/// `via` re-exports `author`'s stored (third-party) log to `to` — the RELAY
/// path. `to` establishes roster trust in `author` lazily (mirroring transitive
/// roster learning) and applies the relayed ops. Nothing here touches a direct
/// `author`↔`to` channel.
fn relay(via: &Device, author: &Device, to: &Device) {
    let (_via_bridge, via_store) = via.open();
    let log = via_store
        .export_peer_log(author.identity.peer_id())
        .unwrap();
    assert!(
        !log.is_empty(),
        "relay precondition: `via` must already hold `author`'s log"
    );

    let mut store = Store::open(&to.store, to.identity.clone()).unwrap();
    let author_key = author.identity.verifying_key();
    if !store
        .roster()
        .iter()
        .any(|p| p.peer_id == author.identity.peer_id())
    {
        store
            .add_peer(author.identity.peer_id(), author_key.to_bytes())
            .unwrap();
    }
    store
        .apply_peer_ops(author.identity.peer_id(), &author_key, &log)
        .unwrap();
    // `store` drops here, releasing `to`'s store_root for the next `open()`.
}

// ---------------------------------------------------------------------------
// F2.1 — a CREATE on A reaches C only via B's relay (no direct A↔C sync).
// ---------------------------------------------------------------------------
#[test]
fn create_relayed_a_to_c_via_b() {
    let a = Device::new();
    let b = Device::new();
    let c = Device::new();
    let rel = "relayed.md";
    let container = cid(&a, rel);

    // A creates; A→B only.
    import(&a, rel, "relay hello\n");
    sync(&a, &b);
    b.scan();
    assert_eq!(std::fs::read(b.vault_file(rel)).unwrap(), b"relay hello\n");

    // B relays A's log to C. There is NO A↔C sync anywhere.
    relay(&b, &a, &c);
    c.scan();

    // C materialized A's file on disk with a Live entry, purely from the relay.
    assert_eq!(
        std::fs::read(c.vault_file(rel)).unwrap(),
        b"relay hello\n",
        "C must receive A's file via B's relay without a direct A↔C link"
    );
    assert!(sidecar_path(&c.vault_file(rel)).exists());
    assert_eq!(
        c.entry(&container).map(|e| e.status),
        Some(EntryStatus::Live)
    );
    assert_eq!(c.store_text(&container), "relay hello\n");
}

// ---------------------------------------------------------------------------
// F2.2 — a DELETE on A relayed the same way → C removes the file.
// ---------------------------------------------------------------------------
#[test]
fn delete_relayed_a_to_c_via_b() {
    let a = Device::new();
    let b = Device::new();
    let c = Device::new();
    let rel = "relayed.md";
    let container = cid(&a, rel);

    // A creates → relay create to C via B; C now holds the file.
    import(&a, rel, "relay hello\n");
    sync(&a, &b);
    b.scan();
    relay(&b, &a, &c);
    c.scan();
    assert!(c.vault_file(rel).exists());

    // A deletes; A→B carries the tombstone into B's stored A-log.
    a.delete_file(&a.vault_file(rel));
    sync(&a, &b);
    b.scan();
    assert!(!b.vault_file(rel).exists());

    // B relays A's now-extended log to C (full log; apply_peer_ops handles the
    // append-only prefix). C applies the tombstone with no direct A↔C link.
    relay(&b, &a, &c);
    c.scan();

    assert!(
        !c.vault_file(rel).exists(),
        "C must remove the file from A's relayed delete, without a direct A↔C link"
    );
    assert!(!sidecar_path(&c.vault_file(rel)).exists());
    assert_eq!(
        c.entry(&container).map(|e| e.status),
        Some(EntryStatus::Tombstoned)
    );
}
