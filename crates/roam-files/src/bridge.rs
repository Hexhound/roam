//! Bridge between on-disk vault files and the CRDT [`Store`].
//!
//! A [`FolderBridge`] owns a [`Store`] (which persists the CRDT state) and the
//! vault root where the user's text files live. [`FolderBridge::import_file`]
//! reconciles a single file's on-disk text into its container, using the
//! sidecar's last-synced text as the baseline so only the minimal delta is
//! applied to the CRDT.
//!
//! # LIMITATIONS
//!
//! ## #1 — Concurrent remote merges: handled via OT rebase (resolved)
//!
//! [`FolderBridge::import_file`] computes the local delta as char offsets
//! relative to the sidecar baseline `A` (`last_synced_text`, the disk text at
//! the last sync). Those offsets are only valid against the store while
//! `store.text() == A` — i.e. while this device is the sole writer. Once the
//! sync engine merges a remote peer's edits into the same container the store
//! reads `R != A`, and the raw `A`-space offsets would land mid-remote-content
//! or out of bounds, producing desync and persisted corruption.
//!
//! `import_file` now **rebases** the local delta into the store's coordinates
//! (see [`crate::rebase`]). When `R == A` it keeps the fast path (`A -> L`
//! offsets applied directly). When `R != A` it re-expresses the local delta
//! (`A -> L`) in `R`-space and layers it on top of the remote edits — a
//! **lossless** 3-way merge that keeps both the remote and local edits — then
//! derives the store op sequence from `diff_to_ops(R, merged)`. The desync
//! guard compares the store's post-apply text against the independently
//! computed merged text (not against `L`, since the store legitimately carries
//! remote edits). On success the sidecar baseline is set to the disk text `L`;
//! a later [`FolderBridge::project_file`] writes the merged store text to disk
//! and advances the baseline to it, converging to `disk == store == baseline`.
//!
//! ## #4 — No delete/rename propagation
//!
//! [`FolderBridge::scan`] only discovers **existing** `*.md`/`*.org` files. A
//! file removed or renamed on disk leaves its container populated, and
//! [`FolderBridge::project_file`] would happily **recreate the deleted file**
//! from that container on the next projection. There is no tombstone and no
//! path→container map to notice the removal.
//!
//! Delete/rename sync needs the deferred **file-set-map CRDT**
//! (`path → (kind, content-ref)`, a separate slice — see the architecture
//! spec). Delete-sync is **out of scope** for this crate.

use std::path::{Path, PathBuf};

use roam_storage::{Identity, Store};

use crate::error::FilesError;
use crate::path::container_id;
use crate::rebase::merge_local_onto_remote;
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

        // Baseline (`A`) for the diff: the sidecar's last-synced text when
        // present, otherwise the store's CURRENT text (NOT ""). Re-seeding
        // against "" when the container is already populated (cold-reopen oplog
        // replay, or a deleted/unsynced `.roammeta`) would make an unchanged
        // file diff as a full insert at pos 0 — DOUBLING the container.
        let sidecar = Sidecar::load(file)?;
        let baseline = match &sidecar {
            Some(s) => s.last_synced_text.clone(),
            None => self.store.text(&container),
        };

        // The store's CURRENT text (`R`). It equals `baseline` (`A`) only while
        // this device is the sole writer; once the sync engine merges a remote
        // peer's edits into the container, `R != A` (LIMITATION #1).
        let remote_text = self.store.text(&container);

        // `expected` is the merged text the store must hold after this import.
        //
        // - Fast path (`R == A`, no concurrent remote edits): the local delta's
        //   `A`-space offsets are already valid against the store, so the merged
        //   text is simply the disk text `L`.
        // - Rebase path (`R != A`): re-express the local delta (`A -> L`) in the
        //   store's `R`-coordinates via OT rebase and layer it on top of the
        //   remote edits — LOSSLESS, keeping both sides.
        let expected = if remote_text == baseline {
            file_text.clone()
        } else {
            merge_local_onto_remote(&baseline, &file_text, &remote_text)
        };

        // Ops that carry the store from its CURRENT text to the merged text.
        // Deriving them from `R -> expected` (rather than the raw `A -> L`
        // offsets) is what makes the offsets correct regardless of remote merges.
        let ops = diff_to_ops(&remote_text, &expected);
        if ops.is_empty() {
            return Ok(SyncOutcome {
                ops_applied: 0,
                changed: false,
            });
        }

        // Apply ops in order, but DON'T early-return on a storage error:
        // `Store::edit_text`/`delete_text` mutate the in-memory doc before
        // persisting, so a mid-sequence failure can leave the container
        // half-mutated. We capture the first error, stop, and then heal the
        // sidecar to the store's ACTUAL state so a retry diffs against reality
        // (converging) instead of re-applying the same diff (escalating).
        let mut apply_err: Option<FilesError> = None;
        for op in &ops {
            let result = match op {
                TextOp::Insert { pos, s } => self.store.edit_text(&container, *pos, s),
                TextOp::Delete { pos, len } => self.store.delete_text(&container, *pos, *len),
            };
            if let Err(err) = result {
                apply_err = Some(err.into());
                break;
            }
        }

        let actual = self.store.text(&container);
        reconcile_sidecar(
            file,
            &container,
            &file_text,
            &expected,
            &actual,
            ops.len(),
            apply_err,
        )
    }

    /// Project the container's current CRDT text onto disk (CRDT → disk).
    ///
    /// Writes the container's text to `file` atomically (byte-for-byte, no
    /// normalization or added trailing newline) and records a sidecar so a
    /// subsequent [`import_file`](Self::import_file) sees no change. When the
    /// file already holds exactly that text AND the sidecar already records it
    /// as synced, this is a no-op that leaves disk untouched.
    ///
    /// `changed` reflects whether disk was written; `ops_applied` is always 0
    /// because projection never mutates the CRDT.
    pub fn project_file(&mut self, file: &Path) -> Result<SyncOutcome, FilesError> {
        let container = container_id(&self.vault_root, file)?;
        let text = self.store.text(&container);

        // Read the current on-disk text, if any. A missing file is "absent";
        // a non-UTF-8 file simply won't compare equal, so we fall through to a
        // fresh write rather than erroring.
        let on_disk = match std::fs::read(file) {
            Ok(bytes) => String::from_utf8(bytes).ok(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(FilesError::Io(err)),
        };

        // A sidecar parse error is intentionally surfaced rather than treated
        // as "unsynced" — a corrupt sidecar is worth reporting.
        let sidecar = Sidecar::load(file)?;

        if on_disk.as_deref() == Some(text.as_str()) {
            if let Some(sidecar) = &sidecar {
                if sidecar.last_synced_text == text {
                    return Ok(SyncOutcome {
                        ops_applied: 0,
                        changed: false,
                    });
                }
            }
        }

        // Dirty-file guard (data-loss protection): refuse to clobber a file
        // that carries local edits the user hasn't imported yet. The file is
        // dirty when it exists, is valid UTF-8, differs from the store text (so
        // an overwrite WOULD change it), AND differs from the last-synced
        // baseline (so it was edited on disk since the last sync). A file that
        // is absent, or already equals the baseline (clean, merely stale vs the
        // store), is safe to project. When no sidecar exists we have no proof
        // the file is clean, so an existing differing file is treated as dirty
        // rather than silently overwritten.
        if let Some(disk) = on_disk.as_deref() {
            if disk != text {
                let edited_since_sync = match &sidecar {
                    Some(sidecar) => disk != sidecar.last_synced_text,
                    None => true,
                };
                if edited_since_sync {
                    return Err(FilesError::DirtyFile(file.to_path_buf()));
                }
            }
        }

        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        atomic_write(file, text.as_bytes())?;

        Sidecar {
            version: SIDECAR_VERSION,
            doc_id: container,
            last_synced_hash: text_hash(&text),
            last_synced_text: text,
        }
        .store(file)?;

        Ok(SyncOutcome {
            ops_applied: 0,
            changed: true,
        })
    }

    /// Reconcile the whole vault: recursively import every `*.md`/`*.org` file
    /// under `vault_root`, returning each file's [`SyncOutcome`].
    ///
    /// Sidecar (`.roammeta`) files are skipped. A file that fails as
    /// [`FilesError::NotText`] is skipped rather than aborting the whole scan;
    /// any other error propagates.
    pub fn scan(&mut self) -> Result<Vec<(PathBuf, SyncOutcome)>, FilesError> {
        let mut files = Vec::new();
        collect_vault_files(&self.vault_root, &mut files)?;
        files.sort();

        let mut outcomes = Vec::with_capacity(files.len());
        for file in files {
            match self.import_file(&file) {
                Ok(outcome) => outcomes.push((file, outcome)),
                Err(FilesError::NotText(_)) => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(outcomes)
    }

    /// Borrow the underlying [`Store`] (escape hatch for tests / engine wiring).
    pub fn store(&self) -> &Store {
        &self.store
    }
}

/// Atomically write `bytes` to `path` by writing a sibling temp file and
/// renaming it over `path` (same directory, so the rename stays on one
/// filesystem and is atomic). Mirrors [`Sidecar::store`]'s strategy.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), FilesError> {
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);

    if let Err(err) = std::fs::write(&temp, bytes) {
        // Best-effort cleanup so a partial/failed write leaves no debris.
        let _ = std::fs::remove_file(&temp);
        return Err(FilesError::Io(err));
    }
    match std::fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(err) => {
            // Best-effort cleanup so a failed rename leaves no debris.
            let _ = std::fs::remove_file(&temp);
            Err(FilesError::Io(err))
        }
    }
}

/// Recursively collect `*.md`/`*.org` files under `dir` into `out`, skipping
/// sidecar files (any other extension, including `.roammeta`). A missing
/// directory yields no files rather than an error.
///
/// Symlinks are skipped entirely (neither descended into nor imported): a
/// symlinked directory that points at an ancestor (e.g. `vault/loop -> vault`)
/// would otherwise send the walk into an infinite loop. `DirEntry::file_type`
/// reports the link itself (it does not traverse), so `is_symlink()` catches
/// these without a follow.
fn collect_vault_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), FilesError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(FilesError::Io(err)),
    };

    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect_vault_files(&path, out)?;
        } else if is_vault_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

/// Whether `path` has a vault text extension (`md` or `org`, case-insensitive).
fn is_vault_file(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => {
            let ext = ext.to_ascii_lowercase();
            ext == "md" || ext == "org"
        }
        None => false,
    }
}

/// Reconcile the sidecar after applying the import ops, then decide the result.
///
/// The baseline written to the sidecar depends on the outcome, because the
/// sidecar tracks the **disk sync-point / merge ancestor** the next import will
/// diff against:
///
/// - **Success** (no apply error, and the store's `actual` text matches the
///   `expected` merged text): record `last_synced_text = file_text` — the
///   current DISK text `L`. Under a concurrent remote merge the store also
///   carries remote edits (`actual == expected != L`), so recording `actual`
///   would wrongly mark the disk as dirty and re-diff on the next import.
///   Recording `L` keeps `baseline == disk`, which the dirty-check and the next
///   diff depend on. A later [`FolderBridge::project_file`] then writes the
///   merged store text to disk and advances the baseline to it, so the cycle
///   converges to `disk == store == baseline`.
/// - **Error / desync** (an op failed mid-sequence, or `actual != expected`):
///   heal `last_synced_text = actual` (the store's REAL text) so a retry diffs
///   `actual -> file_text` (only the remaining delta) and CONVERGES instead of
///   re-applying an already-partially-applied diff and escalating corruption.
///   A mid-sequence storage error is propagated after healing; otherwise the
///   mismatch is reported as [`FilesError::Desync`].
///
/// `expected` is the in-memory merged text derived by the OT rebase (or `L` on
/// the fast path); comparing the store's `actual` against it — rather than
/// against `L` — is the post-rebase desync invariant (the store legitimately
/// carries remote edits, so `actual == L` no longer holds).
#[allow(clippy::too_many_arguments)]
fn reconcile_sidecar(
    file: &Path,
    container: &str,
    file_text: &str,
    expected: &str,
    actual: &str,
    ops_applied: usize,
    apply_err: Option<FilesError>,
) -> Result<SyncOutcome, FilesError> {
    // SUCCESS: baseline tracks the disk text `L`, not the (possibly
    // remote-merged) store text.
    if apply_err.is_none() && actual == expected {
        Sidecar {
            version: SIDECAR_VERSION,
            doc_id: container.to_string(),
            last_synced_hash: text_hash(file_text),
            last_synced_text: file_text.to_string(),
        }
        .store(file)?;
        return Ok(SyncOutcome {
            ops_applied,
            changed: true,
        });
    }

    // ERROR / DESYNC: heal to the store's actual state so a retry converges.
    // Heal FIRST so the real state is recorded even when we're about to return
    // an error — convergence-to-disk beats preserving a rare remote edit.
    Sidecar {
        version: SIDECAR_VERSION,
        doc_id: container.to_string(),
        last_synced_hash: text_hash(actual),
        last_synced_text: actual.to_string(),
    }
    .store(file)?;

    if let Some(err) = apply_err {
        return Err(err);
    }
    Err(FilesError::Desync(format!(
        "container {container}: store text diverged from expected merge after import"
    )))
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
    fn missing_sidecar_reseeds_baseline_from_store_not_empty() {
        // Regression (#2): a populated container + an absent sidecar + an
        // UNCHANGED file must NOT double the container. The baseline defaults
        // to the store's current text (not ""), so an unchanged file is a
        // no-op rather than a full re-insert at pos 0.
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&file).unwrap();

        // Delete the sidecar off disk (simulates a deleted/unsynced
        // `.roammeta` or a cold-reopen oplog replay with no sidecar yet).
        std::fs::remove_file(crate::sidecar::sidecar_path(&file)).unwrap();

        // Re-import the SAME unchanged file: must be a no-op, not a double.
        let outcome = b.import_file(&file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(!outcome.changed);

        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(b.store().text(&container), "hello\n");
    }

    #[test]
    fn missing_sidecar_diffs_only_delta_against_store() {
        // Regression (#2): absent sidecar + a container already holding
        // "hello\n" + a disk file "hello world\n" must diff only the delta
        // against the store's current text, ending at "hello world\n" (not
        // doubled, not re-seeded from empty).
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&file).unwrap();

        std::fs::remove_file(crate::sidecar::sidecar_path(&file)).unwrap();
        std::fs::write(&file, "hello world\n").unwrap();

        let outcome = b.import_file(&file).unwrap();
        assert!(outcome.changed);
        // Minimal delta against the store: one insert, not a full re-seed.
        assert_eq!(outcome.ops_applied, 1);

        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(b.store().text(&container), "hello world\n");
    }

    #[test]
    fn project_file_refuses_to_clobber_dirty_local_edits() {
        // Regression (#3): the on-disk file has local edits the user hasn't
        // imported yet. Projecting must NOT overwrite them; it returns
        // Err(DirtyFile) and leaves the file bytes untouched.
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&file).unwrap();

        // Edit disk WITHOUT importing: now disk != baseline and disk != store.
        std::fs::write(&file, "local edit\n").unwrap();

        let result = b.project_file(&file);
        assert!(matches!(result, Err(FilesError::DirtyFile(_))));
        // The user's local edit survives untouched.
        assert_eq!(std::fs::read(&file).unwrap(), b"local edit\n");
    }

    #[test]
    fn project_file_projects_when_disk_is_clean_but_stale() {
        // The clean case still projects: the on-disk file equals the sidecar
        // baseline (no un-imported local edit) but the store has advanced, so
        // overwriting disk with store text is safe.
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&file).unwrap();

        // Advance the store only (disk stays at the baseline "hello\n").
        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        b.store.edit_text(&container, 5, " world").unwrap();
        assert_eq!(b.store().text(&container), "hello world\n");

        let outcome = b.project_file(&file).unwrap();
        assert!(outcome.changed);
        assert_eq!(std::fs::read(&file).unwrap(), b"hello world\n");
    }

    #[test]
    fn concurrent_remote_merge_import_rebases_local_edit() {
        // LIMITATION #1 reproduction (fail-first before the OT-rebase fix):
        // a remote peer's edit has already been merged into the container, so
        // `store.text() != baseline`. The baseline-relative local diff must be
        // rebased into the store's coordinates or it lands at the wrong offset
        // and corrupts/desyncs.
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&file).unwrap();

        let container = container_id(&vault, &file).unwrap();
        assert_eq!(b.store().text(&container), "hello world\n");

        // Simulate a REMOTE merge: a peer inserted "XYZ " at the front of the
        // container. Inject it directly through the store (the same private
        // access `project_file_projects_when_disk_is_clean_but_stale` uses),
        // WITHOUT touching the sidecar — exactly what the sync engine does when
        // it merges a peer's ops into a container this device also syncs.
        b.store.edit_text(&container, 0, "XYZ ").unwrap();
        assert_eq!(b.store().text(&container), "XYZ hello world\n");

        // Local disk edit: insert " END" before the trailing newline.
        std::fs::write(&file, "hello world END\n").unwrap();
        let outcome = b.import_file(&file).unwrap();
        assert!(outcome.changed);
        assert!(outcome.ops_applied > 0);

        // The 3-way merge keeps BOTH the remote "XYZ " prefix AND the local
        // " END" suffix.
        assert_eq!(b.store().text(&container), "XYZ hello world END\n");

        // Sidecar baseline tracks the DISK text (L), not the merged store text.
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "hello world END\n");
    }

    #[test]
    fn concurrent_remote_delete_local_insert_merges_both() {
        // Test #2: remote deleted a region the local edit didn't touch; the
        // merge keeps the remote deletion AND the local insertion.
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remote deletes "world" → store reads "hello \n".
        b.store.delete_text(&container, 6, 5).unwrap();
        assert_eq!(b.store().text(&container), "hello \n");

        // Local inserts " END" before the newline (untouched region).
        std::fs::write(&file, "hello world END\n").unwrap();
        b.import_file(&file).unwrap();

        assert_eq!(b.store().text(&container), "hello  END\n");
    }

    #[test]
    fn local_delete_of_partially_remote_deleted_region() {
        // Test #3: local deletes a run remote already partially removed — only
        // the still-present chars are deleted; no out-of-bounds, no error.
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remote deletes "wor" (chars 6..9) → store reads "hello ld\n".
        b.store.delete_text(&container, 6, 3).unwrap();
        assert_eq!(b.store().text(&container), "hello ld\n");

        // Local deletes the whole "world" run → disk "hello \n".
        std::fs::write(&file, "hello \n").unwrap();
        let outcome = b.import_file(&file).unwrap();
        assert!(outcome.changed);

        // Only the still-present "ld" is removed; result converges cleanly.
        assert_eq!(b.store().text(&container), "hello \n");
    }

    #[test]
    fn multibyte_rebase_stays_char_correct() {
        // Test #4: remote inserts a multi-byte (CJK + emoji) prefix, local edits
        // after it — offsets stay char-correct through the rebase.
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("cafe.md");
        std::fs::write(&file, "café\n").unwrap();
        b.import_file(&file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remote inserts "世界🚀 " at the front (4 chars).
        b.store.edit_text(&container, 0, "世界🚀 ").unwrap();
        assert_eq!(b.store().text(&container), "世界🚀 café\n");

        // Local appends " latte" before the newline.
        std::fs::write(&file, "café latte\n").unwrap();
        b.import_file(&file).unwrap();

        assert_eq!(b.store().text(&container), "世界🚀 café latte\n");
    }

    #[test]
    fn concurrent_merge_import_then_project_converges_to_fast_path() {
        // Test #6: a concurrent-merge import, then project_file, then a second
        // import must reach the R == A fast path — stable, byte-stable disk, no
        // drift or re-corruption.
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Concurrent remote merge + local edit, then import (rebase path).
        b.store.edit_text(&container, 0, "XYZ ").unwrap();
        std::fs::write(&file, "hello world END\n").unwrap();
        b.import_file(&file).unwrap();
        assert_eq!(b.store().text(&container), "XYZ hello world END\n");

        // After import the baseline tracks disk (L), not the merged store text.
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "hello world END\n");

        // Project the merged store text to disk: now disk == store == baseline.
        let projected = b.project_file(&file).unwrap();
        assert!(projected.changed);
        assert_eq!(std::fs::read(&file).unwrap(), b"XYZ hello world END\n");
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "XYZ hello world END\n");

        // A second import now hits the fast path (R == A): a stable no-op.
        let outcome = b.import_file(&file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(!outcome.changed);
        assert_eq!(b.store().text(&container), "XYZ hello world END\n");

        // Disk is byte-stable across the whole cycle.
        assert_eq!(std::fs::read(&file).unwrap(), b"XYZ hello world END\n");
    }

    #[test]
    fn concurrent_merge_baseline_tracks_disk_then_project_advances_it() {
        // Test #7: after a concurrent-merge import, the sidecar baseline equals
        // the DISK text L (not the merged store text); a subsequent project_file
        // then advances the baseline to the store text, and the dirty-check
        // still works throughout.
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        b.store.edit_text(&container, 0, "XYZ ").unwrap();
        std::fs::write(&file, "hello world END\n").unwrap();
        b.import_file(&file).unwrap();

        // Baseline == disk text L, NOT the merged store text.
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "hello world END\n");
        assert_ne!(sidecar.last_synced_text, b.store().text(&container));

        // Dirty-check still works: disk == baseline, so projection is allowed
        // (not treated as dirty) and advances the baseline to the store text.
        b.project_file(&file).unwrap();
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, b.store().text(&container));
        assert_eq!(sidecar.last_synced_text, "XYZ hello world END\n");
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
    fn reconcile_heals_sidecar_to_actual_on_desync() {
        // Fabricate a mismatch: the store actually holds "partial" but the file
        // wanted "hello world". The sidecar must record the ACTUAL store text so
        // the next import diffs "partial" -> "hello world" (the remaining delta),
        // never re-applying the stale baseline diff.
        let dir = tempdir().unwrap();
        let file = dir.path().join("note.md");

        // expected == file_text here (a non-rebase desync): the store diverged
        // from what we intended, so it heals to the actual "partial".
        let result =
            reconcile_sidecar(&file, "note.md", "hello world", "hello world", "partial", 1, None);
        assert!(matches!(result, Err(FilesError::Desync(_))));

        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "partial");
        assert_eq!(sidecar.last_synced_hash, text_hash("partial"));
    }

    #[test]
    fn reconcile_heals_sidecar_then_propagates_apply_error() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("note.md");

        // A simulated storage failure captured mid-sequence must still heal the
        // sidecar to the store's actual state before propagating.
        let err = FilesError::Sidecar("simulated storage failure".into());
        let result = reconcile_sidecar(
            &file,
            "note.md",
            "hello world",
            "hello world",
            "partial",
            1,
            Some(err),
        );
        assert!(result.is_err());

        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "partial");
    }

    #[test]
    fn reconcile_success_records_file_text_and_reports_change() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("note.md");

        let outcome = reconcile_sidecar(&file, "note.md", "same", "same", "same", 2, None).unwrap();
        assert_eq!(
            outcome,
            SyncOutcome {
                ops_applied: 2,
                changed: true
            }
        );
        assert_eq!(
            Sidecar::load(&file).unwrap().unwrap().last_synced_text,
            "same"
        );
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

    #[test]
    fn project_file_is_byte_stable_round_trip() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("a.md");
        // Multi-byte content with NO trailing newline.
        let original = "# Title\ncafé — 世界";
        std::fs::write(&file, original).unwrap();
        let original_bytes = std::fs::read(&file).unwrap();

        b.import_file(&file).unwrap();
        std::fs::remove_file(&file).unwrap();

        let outcome = b.project_file(&file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(outcome.changed);

        // Byte-for-byte identical to the original file.
        assert_eq!(std::fs::read(&file).unwrap(), original_bytes);
    }

    #[test]
    fn project_then_import_is_a_no_op() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();

        b.import_file(&file).unwrap();
        // Disk already matches the store and the sidecar records it: a no-op.
        let projected = b.project_file(&file).unwrap();
        assert!(!projected.changed);

        let outcome = b.import_file(&file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(!outcome.changed);
    }

    #[test]
    fn project_file_writes_store_text_when_disk_missing() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let file = dir.path().join("vault").join("x.md");
        std::fs::write(&file, "hello").unwrap();
        b.import_file(&file).unwrap();

        std::fs::remove_file(&file).unwrap();
        let outcome = b.project_file(&file).unwrap();
        assert!(outcome.changed);
        assert_eq!(std::fs::read(&file).unwrap(), b"hello");
    }

    #[test]
    fn project_file_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let deep = dir
            .path()
            .join("vault")
            .join("sub")
            .join("dir")
            .join("deep.md");

        let outcome = b.project_file(&deep).unwrap();
        assert!(outcome.changed);
        assert!(deep.exists());
        // Empty container projects an empty file (byte-stable, no newline).
        assert_eq!(std::fs::read(&deep).unwrap(), b"");
    }

    #[test]
    fn scan_imports_md_and_org_ignoring_others() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let vault = dir.path().join("vault");
        let one = vault.join("one.md");
        let two = vault.join("nested").join("two.org");
        std::fs::create_dir_all(vault.join("nested")).unwrap();
        std::fs::write(&one, "one body").unwrap();
        std::fs::write(&two, "two body").unwrap();
        std::fs::write(vault.join("ignore.txt"), "ignore me").unwrap();
        // A stray but valid sidecar sitting beside one.md — scan must not treat
        // it as an importable file.
        Sidecar {
            version: SIDECAR_VERSION,
            doc_id: "one.md".to_string(),
            last_synced_hash: text_hash(""),
            last_synced_text: String::new(),
        }
        .store(&one)
        .unwrap();

        let outcomes = b.scan().unwrap();
        assert_eq!(outcomes.len(), 2);
        for (path, outcome) in &outcomes {
            assert!(outcome.changed);
            assert!(path == &one || path == &two);
            let container = container_id(&vault, path).unwrap();
            let expected = std::fs::read_to_string(path).unwrap();
            assert_eq!(b.store().text(&container), expected);
        }
    }

    #[test]
    fn scan_skips_non_utf8_md_without_aborting() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let vault = dir.path().join("vault");
        let good = vault.join("good.md");
        std::fs::write(&good, "good").unwrap();
        std::fs::write(vault.join("bad.md"), [0xff, 0xff]).unwrap();

        let outcomes = b.scan().unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].0, good);
        let container = container_id(&vault, &good).unwrap();
        assert_eq!(b.store().text(&container), "good");
    }

    #[cfg(unix)]
    #[test]
    fn scan_does_not_recurse_into_symlink_cycle() {
        let dir = tempdir().unwrap();
        let mut b = bridge(dir.path());
        let vault = dir.path().join("vault");
        let real = vault.join("real.md");
        std::fs::write(&real, "real body").unwrap();
        // A directory symlink pointing back at the vault: descending it would
        // loop forever. scan must terminate.
        std::os::unix::fs::symlink(&vault, vault.join("loop")).unwrap();

        let outcomes = b.scan().unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].0, real);
        let container = container_id(&vault, &real).unwrap();
        assert_eq!(b.store().text(&container), "real body");
    }
}
