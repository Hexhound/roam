//! M2 safety net: pins roam-storage's **on-disk contract** before the `VaultFs`
//! extraction begins.
//!
//! The ~150 existing tests all go through the `Store` API, so they would stay
//! green even if the refactor quietly moved a file, dropped `0600` off the
//! secret key, or replaced an atomic tmp+rename with a plain write. Those are
//! exactly the mistakes an IO-layer refactor makes, so they get their own tests
//! here — asserted against the filesystem directly, not through the API.
//!
//! Regenerate the layout golden with `ROAM_REGEN_GOLDEN=1`.

use roam_storage::{Identity, Role, Store};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Every file under `root`, as relative-path -> bytes.
fn walk(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn recurse(dir: &Path, base: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
            .map(|e| e.expect("dir entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                recurse(&path, base, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .expect("under base")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, std::fs::read(&path).expect("read file"));
            }
        }
    }
    let mut out = BTreeMap::new();
    recurse(root, root, &mut out);
    out
}

/// Peer ids are derived from a random keypair, so they differ every run and
/// would make any golden useless. Replace them with a stable token.
fn normalize(paths: impl Iterator<Item = String>, peer_id: u64) -> Vec<String> {
    let needle = peer_id.to_string();
    let mut out: Vec<String> = paths.map(|p| p.replace(&needle, "<PEER>")).collect();
    out.sort();
    out
}

/// Exercise every persistence site the `VaultFs` extraction has to cover:
/// founder pin, op-log, roster log, local history index, content-addressed
/// blob, and the fast-load snapshot.
fn build_representative_vault(root: &Path, identity: Identity) -> Store {
    let mut store = Store::open(root, identity).expect("open vault");
    store.declare_founder(Role::Admin).expect("declare founder");
    store
        .edit_text("notes/hello.md", 0, "hello characterization")
        .expect("edit text");
    store.set_entry("meta", "title", "Hello").expect("set entry");
    store.blobs().put(b"blob payload").expect("put blob");
    store.write_snapshot().expect("write snapshot");
    store
}

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/vault_layout.txt")
}

/// The set of paths a vault creates is the contract every `VaultFs` backend has
/// to reproduce. A browser backend keying IndexedDB by these same paths stays
/// interchangeable with the native one; one that invents its own keys does not.
#[test]
fn vault_layout_matches_golden() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = Identity::generate();
    let peer_id = identity.peer_id();
    let _store = build_representative_vault(dir.path(), identity);

    let actual = normalize(walk(dir.path()).into_keys(), peer_id).join("\n");

    let path = golden_path();
    if std::env::var_os("ROAM_REGEN_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).expect("create golden dir");
        std::fs::write(&path, format!("{actual}\n")).expect("write golden");
    }

    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("golden {} unreadable ({e}); ROAM_REGEN_GOLDEN=1", path.display()));

    assert_eq!(
        actual.trim(),
        expected.trim(),
        "on-disk layout changed; if intentional, regenerate with ROAM_REGEN_GOLDEN=1"
    );
}

/// Nine sites publish via write-tmp-then-rename. If the refactor drops the
/// rename (or fails to clean up), stray `.tmp`/`.part` files are the symptom —
/// and they also mean a reader can observe a half-written file.
#[test]
fn no_temporary_files_survive_a_clean_vault_build() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = Identity::generate();
    let _store = build_representative_vault(dir.path(), identity);

    let strays: Vec<String> = walk(dir.path())
        .into_keys()
        .filter(|p| p.ends_with(".tmp") || p.ends_with(".part"))
        .collect();

    assert!(
        strays.is_empty(),
        "temporary files left behind (atomic publish broken?): {strays:?}"
    );
}

/// The identity secret is the whole vault's root of trust. `save()` chmods it to
/// `0600`; a refactor that routes the write through a trait without carrying the
/// permission call would leave it world-readable and no other test would notice.
#[cfg(unix)]
#[test]
fn identity_secret_key_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("identity.json");
    Identity::generate().save(&path).expect("save identity");

    let mode = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "identity secret must be owner-read/write only");
}

/// Op-logs are append-only and readers rely on a byte-prefix / no-shrink
/// invariant. Reopening a vault and writing more must EXTEND each log, never
/// rewrite its existing bytes.
#[test]
fn reopening_a_vault_only_appends_to_existing_logs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let id_path = root.join("identity.json");

    let identity = Identity::generate();
    identity.save(&id_path).expect("save identity");
    let before = {
        let _store = build_representative_vault(root, Identity::load(&id_path).expect("load"));
        walk(root)
    };

    {
        let mut store = Store::open(root, Identity::load(&id_path).expect("load")).expect("reopen");
        store.edit_text("notes/hello.md", 0, "more ").expect("edit");
        store.write_snapshot().expect("snapshot");
    }
    let after = walk(root);

    for (path, old_bytes) in &before {
        // Rebuildable derived state is allowed to be rewritten wholesale; the
        // append-only logs are not.
        let is_log = path.starts_with("ops/") || path.starts_with("roster/") || path.contains("history");
        if !is_log {
            continue;
        }
        let new_bytes = after
            .get(path)
            .unwrap_or_else(|| panic!("log {path} disappeared on reopen"));
        assert!(
            new_bytes.starts_with(old_bytes),
            "log {path} was rewritten, not appended (prefix invariant broken)"
        );
    }
}
