//! End-to-end (no network): create a file, snapshot, delete it, restore it.
use roam_files::FolderBridge;
use roam_storage::{Identity, Role, Store};

/// The CLI's meta-dir convention: internal sidecars/blob-markers live under
/// `<vault>/filemeta`, OUTSIDE the user's synced folder (mirrors the `sync`
/// handler in `main.rs`).
fn bridge_for(folder: &std::path::Path, vault: &std::path::Path) -> FolderBridge {
    FolderBridge::new(folder, &vault.join("filemeta"))
}

#[test]
fn delete_then_restore_recovers_content() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let folder = dir.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();

    let mut store = Store::open(&vault, Identity::generate()).unwrap();
    // Found the vault as admin so local writes (import) are permitted (not ReadOnly).
    store.declare_founder(Role::Admin).unwrap();
    let bridge = bridge_for(&folder, &vault);

    let file = folder.join("secret.txt");
    std::fs::write(&file, "do not lose me").unwrap();
    bridge.import_file(&mut store, &file).unwrap();
    store.write_snapshot().unwrap();

    std::fs::remove_file(&file).unwrap();
    bridge.delete_file(&mut store, &file).unwrap();
    assert!(!file.exists());

    bridge.restore_all(&mut store).unwrap();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "do not lose me");
}

#[test]
fn checkpoint_to_latest_preserves_state_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let folder = dir.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    let id_path = dir.path().join("id.key");

    // Persist an identity so we can reopen with the SAME one (mirrors how `init`
    // writes the keyfile and `status` loads it back).
    let identity = Identity::generate();
    identity.save(&id_path).unwrap();

    let file = folder.join("keep.txt");
    {
        let mut store = Store::open(&vault, Identity::load(&id_path).unwrap()).unwrap();
        // Found the vault as admin so local writes (import) are permitted.
        store.declare_founder(Role::Admin).unwrap();
        let bridge = bridge_for(&folder, &vault);
        std::fs::write(&file, "kept").unwrap();
        bridge.import_file(&mut store, &file).unwrap();
        store.write_snapshot().unwrap();
        store.checkpoint(i64::MAX).unwrap();
    }
    // Reopen with the same identity: current content still recoverable/projectable.
    let mut store = Store::open(&vault, Identity::load(&id_path).unwrap()).unwrap();
    let bridge = bridge_for(&folder, &vault);
    std::fs::remove_file(&file).unwrap();
    bridge.project_file(&mut store, &file).unwrap(); // re-materialize from CRDT
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "kept");
}
