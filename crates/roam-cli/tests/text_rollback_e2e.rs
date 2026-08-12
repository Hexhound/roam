//! End-to-end (no network): drive the `text-history` and `revert` subcommands
//! against the real built binary.
//!
//! Two rapid real-time edits COALESCE within the change-merge window, so we seed
//! TWO DISTINCT versions using the `edit_text_at` timestamp seam (a Created
//! version via the normal bridge import, then an Edited version committed far in
//! the future). Disk + sidecar are kept consistent so `revert`'s `project_file`
//! dirty-file guard passes (on-disk == last projected/sidecar baseline).

use std::process::Command;

use roam_files::FolderBridge;
use roam_storage::{Identity, Role, Store};

/// The CLI's meta-dir convention: sidecars live under `<vault>/filemeta`.
fn bridge_for(folder: &std::path::Path, vault: &std::path::Path) -> FolderBridge {
    FolderBridge::new(folder, &vault.join("filemeta"))
}

/// Run the `roam` binary with the given args; return (stdout, success).
fn run_roam(args: &[&str]) -> (String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_roam"))
        .args(args)
        .output()
        .expect("spawn roam binary");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        eprintln!(
            "roam {args:?} failed:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    (stdout, out.status.success())
}

#[test]
fn text_history_lists_versions_and_revert_restores_by_index() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let folder = dir.path().join("folder");
    std::fs::create_dir_all(&folder).unwrap();
    let id_path = dir.path().join("id.key");

    // Persist an identity so the CLI reopens the SAME founder (mirrors `init`).
    let identity = Identity::generate();
    identity.save(&id_path).unwrap();

    // The note is NOT pre-written to disk: an absent file is not "dirty", so the
    // first `project_file` is free to materialize it and seed the sidecar.
    let note = folder.join("note.txt");

    // Seed two distinct versions + a clean disk/sidecar, then persist durably so
    // the CLI (a fresh process) sees them on reopen.
    //
    // Both versions are committed in the PAST (ts 1000s and 2000s) via the
    // `edit_text_at` seam. Loro clamps a peer's change timestamps to be
    // non-decreasing, so a later `revert` at real wall-clock time lands FAR after
    // 2000s (well past the change-merge window) and forms a DISTINCT third change
    // rather than coalescing into the seeded edit. (Seeding in the future would
    // clamp the revert UP into that edit's merge window and merge them.)
    let container = {
        let mut store = Store::open(&vault, identity.clone()).unwrap();
        // Found as admin so local writes (edit/revert) are permitted.
        store.declare_founder(Role::Admin).unwrap();
        let bridge = bridge_for(&folder, &vault);
        let container = roam_files::container_id(&folder, &note).unwrap();

        // Created version "one" at ts 1000s.
        store.edit_text_at(&container, 0, "one", 1000).unwrap();
        // Distinct Edited version "one two" at ts 2000s (>> merge window later).
        store.edit_text_at(&container, 3, " two", 2000).unwrap();
        // Project "one two" to disk + seed the sidecar baseline (disk clean).
        bridge.project_file(&mut store, &note).unwrap();
        store.write_snapshot().unwrap();
        container
    };
    // "one two" is on disk, sidecar baseline == "one two", two versions in store.
    assert_eq!(std::fs::read_to_string(&note).unwrap(), "one two");
    let _ = &container; // kept for clarity of the setup narrative.

    let vault_s = vault.to_str().unwrap();
    let id_s = id_path.to_str().unwrap();
    let folder_s = folder.to_str().unwrap();
    let note_s = note.to_str().unwrap();

    // `text-history note.txt` → two rows, indices 0 (newest, the " two" edit) and 1.
    let (hist, ok) = run_roam(&[
        "text-history",
        "--vault",
        vault_s,
        "--identity",
        id_s,
        "--folder",
        folder_s,
        note_s,
    ]);
    assert!(ok, "text-history should succeed");
    let rows: Vec<&str> = hist.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(rows.len(), 2, "expected 2 version rows, got:\n{hist}");
    assert!(rows[0].starts_with("0\t"), "row 0 index: {}", rows[0]);
    assert!(rows[1].starts_with("1\t"), "row 1 index: {}", rows[1]);
    // Newest (index 0) is the Edited " two" insertion (4 inserted chars).
    assert!(
        rows[0].contains("+4 -0"),
        "row 0 should summarize the ' two' insert (+4 -0): {}",
        rows[0]
    );
    assert!(
        rows[0].contains("Edited"),
        "row 0 should be the Edited version: {}",
        rows[0]
    );
    assert!(
        rows[1].contains("Created"),
        "row 1 should be the Created version: {}",
        rows[1]
    );

    // `revert note.txt --to 1` → back to the Created "one" content on disk.
    let (_out, ok) = run_roam(&[
        "revert",
        "--vault",
        vault_s,
        "--identity",
        id_s,
        "--folder",
        folder_s,
        note_s,
        "--to",
        "1",
    ]);
    assert!(ok, "revert should succeed");
    assert_eq!(std::fs::read_to_string(&note).unwrap(), "one");

    // `text-history` again → three rows (the revert appended a new version).
    let (hist2, ok) = run_roam(&[
        "text-history",
        "--vault",
        vault_s,
        "--identity",
        id_s,
        "--folder",
        folder_s,
        note_s,
    ]);
    assert!(ok, "second text-history should succeed");
    let rows2 = hist2.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(
        rows2, 3,
        "expected 3 version rows after revert, got:\n{hist2}"
    );
}
