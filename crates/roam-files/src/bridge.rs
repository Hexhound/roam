//! Bridge between on-disk vault files and the CRDT [`Store`].
//!
//! A [`FolderBridge`] owns a [`Store`] (which persists the CRDT state) and the
//! vault root where the user's text files live. [`FolderBridge::import_file`]
//! reconciles a single file's on-disk text into its container, using the
//! sidecar's last-synced text as the baseline so only the minimal delta is
//! applied to the CRDT.

use std::path::{Path, PathBuf};

use roam_storage::{Identity, Store};

use crate::error::FilesError;
use crate::path::container_id;
use crate::sidecar::{text_hash, Sidecar};
use crate::textdiff::{diff_to_ops, TextOp};

/// Current sidecar format version written by [`FolderBridge::import_file`].
const SIDECAR_VERSION: u32 = 1;

/// The result of reconciling a single file into the CRDT store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Number of edit ops applied to the container.
    pub ops_applied: usize,
    /// Whether anything changed (ops applied + sidecar rewritten).
    pub changed: bool,
}

/// Bridges a vault folder of text files into a CRDT [`Store`].
pub struct FolderBridge {
    store: Store,
    vault_root: PathBuf,
}

impl FolderBridge {
    /// Open the bridge: open the CRDT store at `store_root` for `identity`, and
    /// remember `vault_root` (where the user's files live).
    pub fn open(
        vault_root: &Path,
        store_root: &Path,
        identity: Identity,
    ) -> Result<Self, FilesError> {
        let store = Store::open(store_root, identity)?;
        Ok(Self {
            store,
            vault_root: vault_root.to_path_buf(),
        })
    }

    /// Reconcile `file`'s on-disk text into its container (disk → CRDT).
    ///
    /// Computes the minimal delta between the sidecar's last-synced text and
    /// the current file text, applies it to the container, verifies the store
    /// now matches the file, and records the new sidecar. A file with no
    /// changes since the last sync is a no-op that leaves the sidecar untouched.
    pub fn import_file(&mut self, file: &Path) -> Result<SyncOutcome, FilesError> {
        let container = container_id(&self.vault_root, file)?;

        // Read bytes then decode so a non-UTF-8 file is a distinct error from
        // an IO failure.
        let bytes = std::fs::read(file)?;
        let file_text = String::from_utf8(bytes)
            .map_err(|_| FilesError::NotText(file.to_path_buf()))?;

        let sidecar = Sidecar::load(file)?;
        let baseline = sidecar
            .as_ref()
            .map(|s| s.last_synced_text.as_str())
            .unwrap_or("");

        let ops = diff_to_ops(baseline, &file_text);
        if ops.is_empty() {
            return Ok(SyncOutcome {
                ops_applied: 0,
                changed: false,
            });
        }

        for op in &ops {
            match op {
                TextOp::Insert { pos, s } => self.store.edit_text(&container, *pos, s)?,
                TextOp::Delete { pos, len } => self.store.delete_text(&container, *pos, *len)?,
            }
        }

        // Sanity: the applied ops must reproduce the file text exactly. A
        // mismatch signals an offset/diff bug and must fail loudly.
        let stored = self.store.text(&container);
        if stored != file_text {
            return Err(FilesError::Desync(format!(
                "container {container}: store text diverged from file text after import"
            )));
        }

        Sidecar {
            version: SIDECAR_VERSION,
            doc_id: container.clone(),
            last_synced_hash: text_hash(&file_text),
            last_synced_text: file_text.clone(),
        }
        .store(file)?;

        Ok(SyncOutcome {
            ops_applied: ops.len(),
            changed: true,
        })
    }

    /// Borrow the underlying [`Store`] (escape hatch for tests / engine wiring).
    pub fn store(&self) -> &Store {
        &self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Build a bridge over a `vault/` and `store/` subdir of one tempdir.
    fn bridge(root: &Path) -> FolderBridge {
        let vault = root.join("vault");
        let store = root.join("store");
        std::fs::create_dir_all(&vault).unwrap();
        FolderBridge::open(&vault, &store, Identity::generate()).unwrap()
    }

    #[test]
    fn new_file_import_seeds_container_and_sidecar() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();

        let outcome = b.import_file(&file).unwrap();
        assert!(outcome.ops_applied > 0);
        assert!(outcome.changed);

        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(b.store().text(&container), "hello\n");

        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "hello\n");
        assert_eq!(sidecar.last_synced_hash, text_hash("hello\n"));
        assert_eq!(sidecar.doc_id, container);
    }

    #[test]
    fn second_import_with_no_change_is_a_no_op() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();

        b.import_file(&file).unwrap();
        let sidecar_before = Sidecar::load(&file).unwrap().unwrap();

        let outcome = b.import_file(&file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(!outcome.changed);

        let sidecar_after = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar_before, sidecar_after);
    }

    #[test]
    fn incremental_edit_applies_a_minimal_delta() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&file).unwrap();

        // "hello\n" -> "hello world\n": a single insert of " world".
        std::fs::write(&file, "hello world\n").unwrap();
        let outcome = b.import_file(&file).unwrap();
        assert!(outcome.changed);
        // Minimal delta: exactly one insert op, not a full re-insert.
        assert_eq!(outcome.ops_applied, 1);

        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(b.store().text(&container), "hello world\n");
    }

    #[test]
    fn multibyte_incremental_reconciles_via_char_offsets() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("cafe.md");
        std::fs::write(&file, "café\n").unwrap();
        b.import_file(&file).unwrap();

        std::fs::write(&file, "cafés\n").unwrap();
        let outcome = b.import_file(&file).unwrap();
        assert!(outcome.changed);

        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(b.store().text(&container), "cafés\n");
    }

    #[test]
    fn non_utf8_file_is_not_text() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("binary.md");
        std::fs::write(&file, [0xff, 0xfe]).unwrap();

        assert!(matches!(
            b.import_file(&file),
            Err(FilesError::NotText(_))
        ));
    }

    #[test]
    fn two_files_map_to_independent_containers() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let vault = dir.path().join("vault");
        let a = vault.join("a.md");
        let c = vault.join("c.md");
        std::fs::write(&a, "aaa").unwrap();
        std::fs::write(&c, "ccc").unwrap();

        b.import_file(&a).unwrap();
        b.import_file(&c).unwrap();

        let ca = container_id(&vault, &a).unwrap();
        let cc = container_id(&vault, &c).unwrap();
        assert_ne!(ca, cc);
        assert_eq!(b.store().text(&ca), "aaa");
        assert_eq!(b.store().text(&cc), "ccc");

        // Editing one must not disturb the other.
        std::fs::write(&a, "aaaZ").unwrap();
        b.import_file(&a).unwrap();
        assert_eq!(b.store().text(&ca), "aaaZ");
        assert_eq!(b.store().text(&cc), "ccc");
    }
}
