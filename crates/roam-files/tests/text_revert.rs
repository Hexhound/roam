//! `FolderBridge::revert_file` — write-gated, non-destructive TEXT rollback that
//! re-projects the reverted content to disk.
//!
//! These end-to-end tests pin two contracts: (1) reverting a text file to an
//! earlier version (identified by a `Frontier` from `Store::text_history`)
//! rewrites the on-disk bytes to the earlier content while KEEPING full history
//! (the revert is itself a new version, not a truncation); and (2) a read-only
//! (Reader-role) device is refused BEFORE any frontier is used.

use roam_crdt::Frontier;
use roam_files::{container_id, FilesError, FolderBridge};
use roam_storage::{Identity, Role, Store};
use tempfile::tempdir;

/// Revert rewrites disk back to the earlier content and history is retained
/// (Created + BAD-edit + revert == 3 versions afterwards).
#[test]
fn revert_file_rewrites_disk_to_earlier_version_and_keeps_history() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault");
    let store_root = dir.path().join("store");
    std::fs::create_dir_all(&vault).unwrap();

    // Founder (Admin) store so `may_write() == true`.
    let identity = Identity::generate();
    {
        let mut store = Store::open(&store_root, identity.clone()).unwrap();
        store.declare_founder(Role::Admin).unwrap();
    }
    let bridge = FolderBridge::new(&vault, &store_root.join("filemeta"));
    let mut store = Store::open(&store_root, identity.clone()).unwrap();

    let note = vault.join("note.txt");
    let container = container_id(&vault, &note).unwrap();

    // Drive BOTH versions through the distinct-timestamp seam (bypasses the 10s
    // coalescing window) so they are two separate CRDT changes.
    // Version 1 (Created @ t=1000): "alpha".
    store.edit_text_at(&container, 0, "alpha", 1000).unwrap();
    let created = store
        .text_history(&container)
        .unwrap()
        .last()
        .unwrap()
        .frontier
        .clone();

    // Version 2 (Edited @ t=2000): "alpha" + " + BAD" => "alpha + BAD".
    store.edit_text_at(&container, 5, " + BAD", 2000).unwrap();
    assert_eq!(store.text(&container), "alpha + BAD");

    // Materialize the current (BAD) content on disk + establish a sidecar
    // baseline so the later re-projection is a clean stale-file rewrite (not a
    // dirty-file rejection).
    bridge.project_file(&mut store, &note).unwrap();
    assert_eq!(std::fs::read_to_string(&note).unwrap(), "alpha + BAD");

    // Revert to the CREATED version: authors new ops re-shaping the content, then
    // re-projects the file to disk.
    bridge.revert_file(&mut store, &note, &created).unwrap();

    // Disk holds the earlier content again.
    assert_eq!(std::fs::read_to_string(&note).unwrap(), "alpha");
    // History is retained and GREW by the revert: created + bad + revert == 3.
    assert_eq!(store.text_history(&container).unwrap().len(), 3);
}

/// A Reader-role device (`may_write() == false`) is refused, and the gate fires
/// BEFORE the frontier is used (an empty frontier suffices).
#[test]
fn revert_file_refused_for_reader() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault");
    std::fs::create_dir_all(&vault).unwrap();

    // --- Bootstrap: admin founds, seeds `note`, adds a Reader. ---
    let admin = Identity::generate();
    let reader = Identity::generate();

    let admin_root = dir.path().join("admin_store");
    let mut admin_store = Store::open(&admin_root, admin.clone()).unwrap();
    admin_store.declare_founder(Role::Admin).unwrap();
    admin_store.edit_text("note", 0, "canon").unwrap();
    admin_store
        .add_peer(
            reader.peer_id(),
            reader.verifying_key().to_bytes(),
            Role::Reader,
        )
        .unwrap();

    // --- Reader materializes as a Reader (may_write() == false). ---
    let reader_root = dir.path().join("reader_store");
    let mut reader_store = Store::open(&reader_root, reader.clone()).unwrap();
    reader_store.pin_founder(admin.peer_id()).unwrap();
    reader_store
        .import_roster(
            admin.peer_id(),
            &admin.verifying_key(),
            admin_store.export_own_roster().unwrap(),
        )
        .unwrap();
    reader_store
        .import_peer(
            admin.peer_id(),
            &admin.verifying_key(),
            admin_store.export_own_log().unwrap(),
        )
        .unwrap();
    assert_eq!(reader_store.self_role(), Some(Role::Reader));
    assert!(!reader_store.may_write(), "reader device must not write");

    let bridge = FolderBridge::new(&vault, &reader_root.join("filemeta"));
    let note = vault.join("note");

    // The write-gate must fire BEFORE any frontier use, so an empty frontier is
    // a fine stand-in.
    assert!(matches!(
        bridge.revert_file(&mut reader_store, &note, &Frontier::empty()),
        Err(FilesError::ReadOnly)
    ));
}
