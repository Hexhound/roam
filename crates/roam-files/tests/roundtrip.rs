//! End-to-end / golden integration tests for the `roam-files` public API.
//!
//! These exercise the whole disk ↔ CRDT bridge over realistic edit sequences,
//! persistence/replay across a cold reopen, byte-stable projection of tricky
//! content, cross-store convergence, and nested path mapping. They intentionally
//! avoid duplicating the in-module unit tests in `src/bridge.rs`, which already
//! cover the single-op happy paths and the sidecar-healing error paths.
//!
//! The tests use the public `roam_files` surface plus `roam_storage` — the
//! latter is unavoidable because the caller owns the `roam_storage::Store` that
//! the stateless `FolderBridge` operates on, and because the convergence test
//! merges the oplogs those `Store` handles expose through the public API.

use std::path::{Path, PathBuf};

use roam_files::{container_id, FolderBridge};
use roam_storage::{Identity, Role, Store};
use tempfile::tempdir;

/// A vault + store pair rooted under one tempdir, mirroring the unit-test
/// `bridge()` helper but returning the paths too so tests can reopen the store.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: PathBuf,
    store: PathBuf,
    identity: Identity,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let store = dir.path().join("store");
        std::fs::create_dir_all(&vault).unwrap();
        let identity = Identity::generate();
        // Under the roles model a roleless store has `may_write() == false`.
        // These fixtures drive the writable import/rename paths, so self-found
        // as Admin once (persisted, replayed on later `open`) to stay writable.
        {
            let mut store = Store::open(&store, identity.clone()).unwrap();
            store.declare_founder(Role::Admin).unwrap();
        }
        Fixture {
            _dir: dir,
            vault,
            store,
            identity,
        }
    }

    /// Open the caller-owned store and a stateless bridge over this fixture's
    /// (persisted) vault + store_root. The caller threads the `Store` into each
    /// bridge operation.
    fn open(&self) -> (FolderBridge, Store) {
        let bridge = FolderBridge::new(&self.vault, &self.store.join("filemeta"));
        let store = Store::open(&self.store, self.identity.clone()).unwrap();
        (bridge, store)
    }

    fn vault_file(&self, rel: &str) -> PathBuf {
        self.vault.join(rel)
    }
}

/// Rewrite `file` on disk, import it, and assert the container now reads back
/// byte-identical to what is on disk — proving the disk→diff→ops→CRDT path.
fn edit_and_assert(
    bridge: &FolderBridge,
    store: &mut Store,
    vault: &Path,
    file: &Path,
    new_text: &str,
) {
    std::fs::write(file, new_text).unwrap();
    bridge.import_file(store, file).unwrap();
    let container = container_id(vault, file).unwrap();
    let on_disk = std::fs::read_to_string(file).unwrap();
    assert_eq!(
        store.text(&container),
        on_disk,
        "store text must equal disk text after importing {new_text:?}"
    );
    assert_eq!(on_disk, new_text);
}

/// Scenario 1: a golden sequence of external edits (front insert, mid insert,
/// run delete, run replace, multi-byte edits) each reconcile so the container
/// exactly equals the on-disk file.
#[test]
fn external_edit_sequence_reconciles_to_disk() {
    let fx = Fixture::new();
    let (bridge, mut store) = fx.open();
    let file = fx.vault_file("note.md");

    let sequence = [
        "the quick brown fox\n",             // seed
        "PREFIX the quick brown fox\n",      // insert at front
        "PREFIX the quick RED brown fox\n",  // insert mid
        "PREFIX the RED brown fox\n",        // delete a run ("quick ")
        "PREFIX the RED brown cat\n",        // replace a run ("fox" -> "cat")
        "PREFIX the RED brown cat — café\n", // multi-byte: em dash + é
        "PREFIX RED cat — café 世界\n",      // delete + CJK insert
        "PREFIX RED cat — café 世界 🚀\n",   // emoji (4-byte, surrogate-free scalar)
        "🚀 café 世界\n",                    // collapse to mostly multi-byte
    ];

    for text in sequence {
        edit_and_assert(&bridge, &mut store, &fx.vault, &file, text);
    }
}

/// Scenario 2: content survives a cold reopen of the store WITHOUT re-importing.
/// The second `FolderBridge::open` over the same store_root (same identity)
/// replays the oplog and reconstructs the container text.
#[test]
fn cold_reopen_replays_oplog() {
    let fx = Fixture::new();
    let file = fx.vault_file("survivor.md");
    let body = "line one\nline two\ncafé 世界\n";

    let container = {
        let (bridge, mut store) = fx.open();
        std::fs::write(&file, body).unwrap();
        bridge.import_file(&mut store, &file).unwrap();
        let container = container_id(&fx.vault, &file).unwrap();
        assert_eq!(store.text(&container), body);
        container
    }; // store dropped: state is on disk only.

    // Reopen the SAME store_root with the SAME identity — no re-import.
    let (_bridge2, store2) = fx.open();
    assert_eq!(
        store2.text(&container),
        body,
        "reopened store must replay the oplog and recover the imported text"
    );
}

/// Scenario 3: byte-stable round-trip over a set of tricky files. For each,
/// import → delete-on-disk → project yields the exact original bytes.
#[test]
fn byte_stable_roundtrip_over_tricky_files() {
    let fx = Fixture::new();
    let (bridge, mut store) = fx.open();

    // (relative path, raw bytes on disk)
    let cases: &[(&str, &[u8])] = &[
        ("empty.md", b""),
        ("no_trailing_newline.md", b"one line no newline"),
        ("crlf.md", b"windows\r\nline\r\nendings\r\n"),
        ("trailing_ws.md", b"trailing spaces   \nand a tab\t\n"),
        (
            "multibyte.md",
            "# café 世界 🚀\nmixed — scripts\n".as_bytes(),
        ),
        ("mixed_newlines.md", b"lf\ncrlf\r\nlf\n"),
    ];

    for (rel, bytes) in cases {
        let file = fx.vault_file(rel);
        std::fs::write(&file, bytes).unwrap();
        bridge.import_file(&mut store, &file).unwrap();

        // Remove from disk, then rebuild from the CRDT.
        std::fs::remove_file(&file).unwrap();
        bridge.project_file(&mut store, &file).unwrap();

        assert_eq!(
            &std::fs::read(&file).unwrap(),
            bytes,
            "projected bytes must be byte-identical for {rel}"
        );
    }
}

/// Scenario 4: two independent stores (two bridges over two store_roots) each
/// import DIFFERENT edits to the SAME container id, then their exported oplogs
/// are merged through the public `Store` API and converge with no data loss.
///
/// Each device's caller-owned `Store` exports its own oplog; both logs are then
/// merged into two neutral `Store`s we own. Importing in both orders and getting
/// identical text that contains BOTH edits proves the real Loro CRDT merge is
/// commutative and lossless — the property the task cares about, via genuine
/// `Store` export/import (not a weaker stand-in).
#[test]
fn two_bridges_converge_via_store_merge() {
    // Both vaults use the same relative path so both map to container "note.md".
    let rel = "note.md";

    let fx_a = Fixture::new();
    let fx_b = Fixture::new();
    let id_a = fx_a.identity.clone();
    let id_b = fx_b.identity.clone();

    let file_a = fx_a.vault_file(rel);
    let file_b = fx_b.vault_file(rel);
    let container = container_id(&fx_a.vault, &file_a).unwrap();
    assert_eq!(container, container_id(&fx_b.vault, &file_b).unwrap());

    let log_a = {
        let (a, mut store_a) = fx_a.open();
        std::fs::write(&file_a, "alpha-edit\n").unwrap();
        a.import_file(&mut store_a, &file_a).unwrap();
        store_a.export_own_log().unwrap()
    };
    let log_b = {
        let (b, mut store_b) = fx_b.open();
        std::fs::write(&file_b, "bravo-edit\n").unwrap();
        b.import_file(&mut store_b, &file_b).unwrap();
        store_b.export_own_log().unwrap()
    };

    // Merge both exported logs into two neutral stores in opposite orders.
    let dir_m1 = tempdir().unwrap();
    let dir_m2 = tempdir().unwrap();
    let mut m1 = Store::open(dir_m1.path(), Identity::generate()).unwrap();
    let mut m2 = Store::open(dir_m2.path(), Identity::generate()).unwrap();

    for m in [&mut m1, &mut m2] {
        // Under the roles model `add_peer` is admin-gated and `import_peer`
        // drops ops authored by a non-Writer, so the neutral merge store
        // self-founds as Admin and vouches A/B as Writers to accept their ops.
        m.declare_founder(Role::Admin).unwrap();
        m.add_peer(id_a.peer_id(), id_a.verifying_key().to_bytes(), Role::Writer)
            .unwrap();
        m.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Writer)
            .unwrap();
    }

    // m1: A then B.
    m1.import_peer(id_a.peer_id(), &id_a.verifying_key(), log_a.clone())
        .unwrap();
    m1.import_peer(id_b.peer_id(), &id_b.verifying_key(), log_b.clone())
        .unwrap();
    // m2: B then A (opposite order).
    m2.import_peer(id_b.peer_id(), &id_b.verifying_key(), log_b)
        .unwrap();
    m2.import_peer(id_a.peer_id(), &id_a.verifying_key(), log_a)
        .unwrap();

    let text1 = m1.text(&container);
    let text2 = m2.text(&container);

    // Commutative: merge order does not change the converged text.
    assert_eq!(text1, text2, "merge must be order-independent");
    // Lossless: both concurrent edits are present.
    assert!(
        text1.contains("alpha-edit") && text1.contains("bravo-edit"),
        "converged text {text1:?} must retain both edits"
    );
}

/// Scenario 5: a nested file `vault/a/b/c.md` maps to container `"a/b/c.md"`,
/// round-trips byte-identically, and is discovered by `scan`.
#[test]
fn nested_path_maps_and_roundtrips() {
    let fx = Fixture::new();
    let (bridge, mut store) = fx.open();

    let nested = fx.vault.join("a").join("b").join("c.md");
    std::fs::create_dir_all(nested.parent().unwrap()).unwrap();
    let body = "nested note\ncafé 世界\n";
    let original = body.as_bytes().to_vec();
    std::fs::write(&nested, &original).unwrap();

    let container = container_id(&fx.vault, &nested).unwrap();
    assert_eq!(
        container, "a/b/c.md",
        "nested path maps with '/' separators"
    );

    // scan discovers the nested file and imports it.
    let outcomes = bridge.scan(&mut store).unwrap();
    assert!(
        outcomes
            .iter()
            .any(|(path, outcome)| path == &nested && outcome.changed),
        "scan must pick up the nested file"
    );
    assert_eq!(store.text(&container), body);

    // Project back to the same path: byte-identical.
    std::fs::remove_file(&nested).unwrap();
    bridge.project_file(&mut store, &nested).unwrap();
    assert_eq!(std::fs::read(&nested).unwrap(), original);
}
