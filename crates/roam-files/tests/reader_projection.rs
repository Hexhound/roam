//! A read-only (Reader-role) vault is a PURE PROJECTION.
//!
//! A Reader device has no write role (`Store::may_write() == false`). Its folder
//! must never turn a local file edit into a CRDT op: on the next scan the tamper
//! is DISCARDED and the file is reverted to the vault's authoritative CRDT state.
//! This end-to-end test pins that contract.

use roam_files::{container_id, FolderBridge};
use roam_storage::{Identity, Role, Store};
use tempfile::tempdir;

#[test]
fn reader_scan_reverts_local_tamper_and_authors_no_op() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault");
    std::fs::create_dir_all(&vault).unwrap();

    // --- Bootstrap: admin founds, seeds `note = "canon"`, adds a Reader. ---
    let admin = Identity::generate();
    let reader = Identity::generate();

    let admin_root = dir.path().join("admin_store");
    let mut admin_store = Store::open(&admin_root, admin.clone()).unwrap();
    admin_store.declare_founder(Role::Admin).unwrap();
    // Seed the content the Reader will later project. `container_id` of a
    // (UTF-8) vault file named `note` at the root is exactly `"note"`, so seed
    // that key (routing is by content, not extension).
    admin_store.edit_text("note", 0, "canon").unwrap();
    admin_store
        .add_peer(
            reader.peer_id(),
            reader.verifying_key().to_bytes(),
            Role::Reader,
        )
        .unwrap();

    // --- Reader materializes as a Reader and holds `note == "canon"`. ---
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
    // Admin is not a Reader, so its content ops are accepted by the Reader.
    reader_store
        .import_peer(
            admin.peer_id(),
            &admin.verifying_key(),
            admin_store.export_own_log().unwrap(),
        )
        .unwrap();

    assert_eq!(reader_store.self_role(), Some(Role::Reader));
    assert!(!reader_store.may_write(), "reader device must not write");
    assert_eq!(reader_store.text("note"), "canon");

    // --- Project the Reader's vault so `note` file holds the canonical text. ---
    let bridge = FolderBridge::new(&vault, &reader_root.join("filemeta"));
    let note = vault.join("note");
    assert_eq!(container_id(&vault, &note).unwrap(), "note");
    bridge.project_file(&mut reader_store, &note).unwrap();
    assert_eq!(std::fs::read_to_string(&note).unwrap(), "canon");

    // --- Tamper the on-disk file locally. ---
    std::fs::write(&note, "TAMPERED").unwrap();

    let before = reader_store.text("note").to_string();

    // --- Scan: the Reader must NOT import the tamper; it reverts the file. ---
    bridge.scan(&mut reader_store).unwrap();

    // No op created from the tamper: the CRDT text is unchanged.
    assert_eq!(
        reader_store.text("note"),
        before,
        "reader tamper must not become a CRDT op"
    );
    // The file is reverted to the authoritative projection.
    assert_eq!(
        std::fs::read_to_string(&note).unwrap(),
        before,
        "reader vault file must be reverted to the CRDT projection"
    );
}
