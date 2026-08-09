//! Bridge between on-disk vault files and the CRDT [`Store`].
//!
//! A [`FolderBridge`] remembers the vault root where the user's text files live
//! and takes the caller-owned [`Store`] (which persists the CRDT state) on every
//! operation. [`FolderBridge::import_file`] reconciles a single file's on-disk
//! text into its container, using the sidecar's last-synced text as the baseline
//! so only the minimal delta is applied to the CRDT.
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
//! ## #4 — Delete/rename propagation: resolved via the file-set map
//!
//! [`FolderBridge::scan`] is a full **reconcile** between the vault directory
//! and the file-set map (`path → (kind, status, content-hash)`). It flushes
//! local disk edits into the CRDT, tombstones files deleted locally, projects
//! remote-new files onto disk, and applies remote tombstones (with a
//! resurrection guard so a concurrent edit merged after the delete wins over
//! the tombstone). Renames ride this as a delete of the old path plus a
//! create of the new one.
//!
//! Remaining scope: tombstones are retained forever (**no garbage
//! collection**), and only [`EntryKind::Text`] is handled — **binary/blob
//! content is still deferred** to a later slice.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use roam_storage::Store;

use crate::error::FilesError;
use crate::fileset::{EntryKind, EntryStatus, FileEntry, FILESET_MAP_ID};
use crate::path::container_id;
use crate::rebase::merge_local_onto_remote;
use crate::sidecar::{sidecar_path, text_hash, Sidecar};
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
///
/// The bridge is STATELESS w.r.t. the store: it holds only the `vault_root` and
/// takes the [`Store`] explicitly on every operation. This lets the caller (the
/// sync engine) own a single `Store` instance and share it with the bridge,
/// instead of the bridge owning a second, separate store handle.
///
/// `Clone` is cheap (a single `PathBuf`) and lets a caller hand an owned copy to
/// a `spawn_blocking` closure — the CLI folder-sync loop does exactly this so the
/// blocking disk+store work runs off the async runtime workers.
#[derive(Clone)]
pub struct FolderBridge {
    vault_root: PathBuf,
}

impl FolderBridge {
    /// Create a bridge over a vault directory. Does NOT open a Store — the caller
    /// owns the Store and passes it into each operation (so the engine and the
    /// bridge can share one Store instance).
    pub fn new(vault_root: &Path) -> Self {
        Self {
            vault_root: vault_root.to_path_buf(),
        }
    }

    /// Reconcile `file`'s on-disk text into its container (disk → CRDT).
    ///
    /// Computes the minimal delta between the sidecar's last-synced text and
    /// the current file text, applies it to the container, verifies the store
    /// now matches the file, and records the new sidecar. A file with no
    /// changes since the last sync is a no-op that leaves the sidecar untouched.
    pub fn import_file(&self, store: &mut Store, file: &Path) -> Result<SyncOutcome, FilesError> {
        let container = container_id(&self.vault_root, file)?;

        // Read bytes then decode so a non-UTF-8 file is a distinct error from
        // an IO failure.
        let bytes = std::fs::read(file)?;
        let file_text =
            String::from_utf8(bytes).map_err(|_| FilesError::NotText(file.to_path_buf()))?;

        // Baseline (`A`) for the diff: the sidecar's last-synced text when
        // present, otherwise the store's CURRENT text (NOT ""). Re-seeding
        // against "" when the container is already populated (cold-reopen oplog
        // replay, or a deleted/unsynced `.roammeta`) would make an unchanged
        // file diff as a full insert at pos 0 — DOUBLING the container.
        let sidecar = Sidecar::load(file)?;
        let baseline = match &sidecar {
            Some(s) => s.last_synced_text.clone(),
            None => store.text(&container),
        };

        // The store's CURRENT text (`R`). It equals `baseline` (`A`) only while
        // this device is the sole writer; once the sync engine merges a remote
        // peer's edits into the container, `R != A` (LIMITATION #1).
        let remote_text = store.text(&container);

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
                TextOp::Insert { pos, s } => store.edit_text(&container, *pos, s),
                TextOp::Delete { pos, len } => store.delete_text(&container, *pos, *len),
            };
            if let Err(err) = result {
                apply_err = Some(err.into());
                break;
            }
        }

        let actual = store.text(&container);
        // `reconcile_sidecar` returns `Ok` ONLY on the success path (no apply
        // error and `actual == expected`); every error/desync/DirtyFile path
        // returns `Err` and short-circuits the `?` below, so the file-set entry
        // upsert runs on success only.
        let outcome = reconcile_sidecar(
            file,
            &container,
            &file_text,
            &expected,
            &actual,
            ops.len(),
            apply_err,
        )?;

        // Upsert the Live file-set entry. The hash is over the disk text `L`
        // (`file_text`), which is exactly the sidecar baseline recorded on
        // success — keeping the entry hash and the sidecar consistent.
        store.set_entry(
            FILESET_MAP_ID,
            &container,
            &FileEntry {
                kind: EntryKind::Text,
                status: EntryStatus::Live,
                content_hash: text_hash(&file_text),
            }
            .to_value(),
        )?;

        Ok(outcome)
    }

    /// Tombstone a file in the file-set map and remove it from disk.
    ///
    /// The text container is intentionally left intact (history / resurrection):
    /// only the file-set entry is flipped to [`EntryStatus::Tombstoned`], and the
    /// on-disk file and its sidecar are removed. The tombstone records the hash
    /// of the container's CURRENT store text so a later resurrection guard can
    /// tell whether the content changed after the delete.
    pub fn delete_file(&self, store: &mut Store, file: &Path) -> Result<SyncOutcome, FilesError> {
        let container = container_id(&self.vault_root, file)?;

        // Tombstone hash = the content THIS DEVICE last synced (the sidecar's
        // last_synced_hash), NOT the current store text. A remote edit may have
        // already merged into the container before this delete; hashing the
        // current (post-merge) text would defeat the resurrection guard and
        // silently delete the peer's concurrent edit. Fall back to the current
        // store text only when no sidecar exists (file already gone / never
        // synced), a degraded best-effort.
        let hash = match Sidecar::load(file)? {
            Some(sidecar) => sidecar.last_synced_hash,
            None => text_hash(&store.text(&container)),
        };

        store.set_entry(
            FILESET_MAP_ID,
            &container,
            &FileEntry {
                kind: EntryKind::Text,
                status: EntryStatus::Tombstoned,
                content_hash: hash,
            }
            .to_value(),
        )?;

        // Remove the disk file; already-gone is fine, other IO errors propagate.
        remove_if_present(file)?;
        // Drop the sidecar too so a later remote re-create reads as remote-new.
        remove_if_present(&sidecar_path(file))?;

        Ok(SyncOutcome {
            ops_applied: 0,
            changed: true,
        })
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
    pub fn project_file(&self, store: &mut Store, file: &Path) -> Result<SyncOutcome, FilesError> {
        let container = container_id(&self.vault_root, file)?;
        let text = store.text(&container);

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

    /// Reconcile the whole vault against the file-set map (disk ↔ CRDT).
    ///
    /// This is the reconcile entry point. It runs three ordered, single-pass
    /// steps over snapshots of the file-set map — never looping until stable —
    /// and is itself idempotent: a second `scan` with no external change makes
    /// no further mutations.
    ///
    /// **Step 1 — flush local disk → CRDT.** Recursively import every
    /// `*.md`/`*.org` file under `vault_root` ([`import_file`](Self::import_file),
    /// which upserts a [`EntryStatus::Live`] entry and writes a sidecar). Sidecar
    /// (`.roammeta`) files are skipped; a [`FilesError::NotText`] file is skipped
    /// rather than aborting the scan. The set of container ids present on disk is
    /// remembered for the later steps.
    ///
    /// **Step 2 — detect local deletions.** For each `Live` entry whose file is
    /// absent from disk BUT whose sidecar still exists (proof this device once
    /// had the file), flip the entry to [`EntryStatus::Tombstoned`] (hashing the
    /// container's current text) and drop the stale sidecar. A `Live` entry that
    /// is absent WITH no sidecar is a remote-new file this device has never seen,
    /// handled in Step 3 — not a local delete.
    ///
    /// **Step 3 — apply remote state (CRDT → disk).** Re-read the (now updated)
    /// entries and:
    /// - `Live` + absent + no sidecar → **remote-new**: project the container to
    ///   disk (creates file + sidecar).
    /// - `Tombstoned` + present → **resurrection guard**: if the container's
    ///   current hash equals the tombstone's hash the delete wins (remove file +
    ///   sidecar); if it differs, a concurrent edit merged in after the delete,
    ///   so the edit wins — flip back to `Live` (current hash) and project.
    /// - all other combinations are already reconciled and skipped.
    ///
    /// Only [`EntryKind::Text`] entries participate; the map holds no other kind
    /// this slice.
    pub fn scan(&self, store: &mut Store) -> Result<Vec<(PathBuf, SyncOutcome)>, FilesError> {
        // --- Step 1: flush local disk edits into the CRDT. ---
        let mut files = Vec::new();
        collect_vault_files(&self.vault_root, &mut files)?;
        files.sort();

        // Container ids that exist on disk (all discovered vault files, even a
        // NotText one that import will skip — it still "exists" for Step 2/3).
        let mut present: HashSet<String> = HashSet::new();
        for file in &files {
            present.insert(container_id(&self.vault_root, file)?);
        }

        let mut outcomes = Vec::new();
        for file in files {
            match self.import_file(store, &file) {
                Ok(outcome) => outcomes.push((file, outcome)),
                Err(FilesError::NotText(_)) => continue,
                Err(err) => return Err(err),
            }
        }

        // --- Step 1b: heal present files with NO file-set entry at all. ---
        // `import_file` writes its Live entry AFTER the `ops.is_empty()` early
        // return, so an unchanged present file that has no entry (pre-file-set
        // migration, or a lost entry op) would stay entry-less forever and never
        // propagate to peers. Heal ONLY a totally-absent entry: a `Tombstoned`
        // entry is owned by Step 3 (delete-wins/resurrection) and a `Live` one
        // is already fine — this must not disturb the "no-op import keeps a
        // remote Tombstoned entry" behavior. Require a sidecar so a raw NotText
        // file skipped in Step 1 (empty container) is never force-entried.
        for key in &present {
            if store.get_entry(FILESET_MAP_ID, key).is_some() {
                continue;
            }
            if !sidecar_path(&self.vault_root.join(key)).exists() {
                continue;
            }
            store.set_entry(
                FILESET_MAP_ID,
                key,
                &FileEntry {
                    kind: EntryKind::Text,
                    status: EntryStatus::Live,
                    content_hash: text_hash(&store.text(key)),
                }
                .to_value(),
            )?;
        }

        // --- Step 2: tombstone locally-deleted files. ---
        // Snapshot the entries so this is a single pass (import above may have
        // mutated them). An unchanged import in Step 1 is a no-op that does NOT
        // rewrite its entry, so a remote tombstone on a present-but-unchanged
        // file survives Step 1 to be handled in Step 3.
        for (key, value) in store.entries(FILESET_MAP_ID) {
            let entry = FileEntry::from_value(&value)?;
            if entry.status != EntryStatus::Live || present.contains(&key) {
                continue;
            }
            // `vault_root.join(key)` inverts container_id → absolute path. The
            // key is a `/`-separated vault-relative path, so this is correct on
            // unix; on Windows the `/` separators would need translating to `\`
            // (out of scope — this crate targets unix vaults).
            let file = self.vault_root.join(&key);
            let sidecar = sidecar_path(&file);
            if !sidecar.exists() {
                // Absent file with no sidecar: a remote-new entry this device
                // never had — leave it for Step 3, do NOT tombstone.
                continue;
            }
            // Locally deleted: this device knew the file (sidecar present) and
            // it is now gone. The tombstone hash must be the content THIS DEVICE
            // last synced (the sidecar's last_synced_hash), NOT the current
            // store text — a remote edit may have merged in already, and hashing
            // the post-merge text would defeat the resurrection guard (the
            // concurrent edit would be silently deleted). Degrade to the current
            // store text only if the sidecar is unreadable.
            let content_hash = match Sidecar::load(&file) {
                Ok(Some(sidecar)) => sidecar.last_synced_hash,
                _ => text_hash(&store.text(&key)),
            };
            store.set_entry(
                FILESET_MAP_ID,
                &key,
                &FileEntry {
                    kind: entry.kind,
                    status: EntryStatus::Tombstoned,
                    content_hash,
                }
                .to_value(),
            )?;
            remove_if_present(&sidecar)?;
            outcomes.push((
                file,
                SyncOutcome {
                    ops_applied: 0,
                    changed: true,
                },
            ));
        }

        // --- Step 3: apply remote state onto disk. ---
        for (key, value) in store.entries(FILESET_MAP_ID) {
            let entry = FileEntry::from_value(&value)?;
            let file = self.vault_root.join(&key);
            let file_present = present.contains(&key);
            match entry.status {
                EntryStatus::Live => {
                    if !file_present && !sidecar_path(&file).exists() {
                        // Remote-new: Live entry with no local file and no
                        // sidecar (never seen here). Absent-with-sidecar became
                        // a tombstone in Step 2.
                        let outcome = self.project_file(store, &file)?;
                        outcomes.push((file, outcome));
                    } else if file_present {
                        // Live + present: reconcile the CRDT -> disk direction.
                        // Step 1 already imported (and OT-rebased) any local disk
                        // edits, so for a present text file the disk equals the
                        // sidecar baseline (clean) — meaning if a remote edit has
                        // advanced the container past disk, `project_file` writes
                        // the merged text and advances the baseline WITHOUT
                        // tripping the dirty guard. Its internal no-op guard skips
                        // unchanged files, keeping this idempotent (after a
                        // projection disk == container == baseline, so a second
                        // scan is a no-op and there is no project<->import
                        // oscillation).
                        match self.project_file(store, &file) {
                            // Only report an ACTUAL reprojection; the steady-state
                            // no-op (guard skips, `changed: false`) must not add a
                            // duplicate outcome alongside Step 1's import.
                            Ok(outcome) if outcome.changed => {
                                outcomes.push((file, outcome))
                            }
                            Ok(_) => {}
                            // Residual safety: if some path left disk dirty (e.g.
                            // Step 1's import was skipped), the disk carries
                            // un-imported local edits. Keep it as-is rather than
                            // clobber — mirror the resurrection branch's handling.
                            Err(FilesError::DirtyFile(_)) => {}
                            Err(err) => return Err(err),
                        }
                    }
                }
                EntryStatus::Tombstoned => {
                    if !file_present {
                        // An absent tombstone is reconciled EXCEPT for a leaked
                        // sidecar: a remote tombstone can arrive for a file whose
                        // local disk copy is already gone but whose sidecar
                        // lingers. That orphan sidecar makes the Step-3 remote-new
                        // gate (`Live + absent + !sidecar`) false forever, so the
                        // path could never be re-materialized. Clean it here.
                        remove_if_present(&sidecar_path(&file))?;
                        continue;
                    }
                    let current_hash = text_hash(&store.text(&key));
                    if current_hash == entry.content_hash {
                        // Delete wins: no edit landed after the tombstone.
                        remove_if_present(&file)?;
                        remove_if_present(&sidecar_path(&file))?;
                        outcomes.push((
                            file,
                            SyncOutcome {
                                ops_applied: 0,
                                changed: true,
                            },
                        ));
                    } else {
                        // Edit wins / resurrection: the container diverged from
                        // the tombstone hash, so a concurrent edit merged in
                        // after the delete. Flip back to Live at the CURRENT
                        // container hash (so a later reconcile sees Live+matching
                        // and is stable), keep the file, and project so disk
                        // matches the edited container.
                        store.set_entry(
                            FILESET_MAP_ID,
                            &key,
                            &FileEntry {
                                kind: entry.kind,
                                status: EntryStatus::Live,
                                content_hash: current_hash,
                            }
                            .to_value(),
                        )?;
                        match self.project_file(store, &file) {
                            Ok(outcome) => outcomes.push((file, outcome)),
                            // A dirty disk file carries un-imported local edits —
                            // which ARE the edits the resurrection preserves. Keep
                            // the file as-is (do not clobber) and still report a
                            // change; the entry is already Live.
                            Err(FilesError::DirtyFile(_)) => outcomes.push((
                                file,
                                SyncOutcome {
                                    ops_applied: 0,
                                    changed: true,
                                },
                            )),
                            Err(err) => return Err(err),
                        }
                    }
                }
            }
        }

        Ok(outcomes)
    }

    /// Rename a file within the vault: move its content to the new path's
    /// container, mark the new path Live and the old path Tombstoned in the
    /// file-set map, and move the file + sidecar on disk.
    ///
    /// Modeled as tombstone-old + a new-entry-carrying-content (Loro has no
    /// re-key-with-content op), so the rename does NOT preserve the old
    /// container's edit history — the new container starts from the old
    /// container's CURRENT text. `from == to` is a no-op (returns
    /// `changed: false`), never touching disk or the store. This handles a
    /// single file only; directory renames are out of scope.
    ///
    /// Ordering is data-loss-safe: flush `from`'s pending disk edits → seed the
    /// `to` container → set the map entries → project `to` to disk → only THEN
    /// remove the `from` file + sidecar. A failure before `to` is written on
    /// disk therefore leaves the `from` file intact.
    pub fn rename_file(
        &self,
        store: &mut Store,
        from: &Path,
        to: &Path,
    ) -> Result<SyncOutcome, FilesError> {
        let from_container = container_id(&self.vault_root, from)?;
        let to_container = container_id(&self.vault_root, to)?;

        // No-op: same path/container. Nothing to move; leave all data untouched.
        if from_container == to_container {
            return Ok(SyncOutcome {
                ops_applied: 0,
                changed: false,
            });
        }

        // Flush any pending local disk edits on `from` first, so the container
        // reflects the LATEST disk content before we copy it. A missing `from`
        // file has nothing to flush; a NotText file propagates its error.
        if from.exists() {
            self.import_file(store, from)?;
        }

        // Copy the current container text into the (assumed fresh/empty) `to`
        // container. Seeding at pos 0 is correct for a new destination; an
        // empty source is a no-op insert we skip.
        let text = store.text(&from_container);
        if !text.is_empty() {
            store.edit_text(&to_container, 0, &text)?;
        }
        let hash = text_hash(&text);

        // File-set map: new path Live, old path Tombstoned. The tombstone hash
        // is the MOVED content's hash — consistent with the resurrection guard:
        // absent a concurrent edit to `from` after the rename, the old container
        // still hashes to this and stays deleted.
        store.set_entry(
            FILESET_MAP_ID,
            &to_container,
            &FileEntry {
                kind: EntryKind::Text,
                status: EntryStatus::Live,
                content_hash: hash.clone(),
            }
            .to_value(),
        )?;
        store.set_entry(
            FILESET_MAP_ID,
            &from_container,
            &FileEntry {
                kind: EntryKind::Text,
                status: EntryStatus::Tombstoned,
                content_hash: hash,
            }
            .to_value(),
        )?;

        // Disk: write the destination FIRST (creates `to` file + sidecar,
        // byte-stable), then remove the source. Removing `from` only after `to`
        // is on disk means a failure partway never loses the content.
        self.project_file(store, to)?;
        remove_if_present(from)?;
        remove_if_present(&sidecar_path(from))?;

        Ok(SyncOutcome {
            ops_applied: 0,
            changed: true,
        })
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

/// Remove `path` if it exists, treating a `NotFound` as success (already gone)
/// and propagating any other IO error as [`FilesError::Io`].
fn remove_if_present(path: &Path) -> Result<(), FilesError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(FilesError::Io(err)),
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
    use roam_storage::Identity;
    use tempfile::tempdir;

    /// Build a bridge over a `vault/` subdir plus a separately-opened store
    /// rooted at a `store/` subdir of one tempdir. The bridge is stateless; the
    /// caller owns the returned `Store` and threads it into each operation.
    fn bridge(root: &Path) -> (FolderBridge, Store) {
        let vault = root.join("vault");
        let store_root = root.join("store");
        std::fs::create_dir_all(&vault).unwrap();
        let bridge = FolderBridge::new(&vault);
        let store = Store::open(&store_root, Identity::generate()).unwrap();
        (bridge, store)
    }

    #[test]
    fn new_file_import_seeds_container_and_sidecar() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();

        let outcome = b.import_file(&mut store, &file).unwrap();
        assert!(outcome.ops_applied > 0);
        assert!(outcome.changed);

        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(store.text(&container), "hello\n");

        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "hello\n");
        assert_eq!(sidecar.last_synced_hash, text_hash("hello\n"));
        assert_eq!(sidecar.doc_id, container);
    }

    #[test]
    fn second_import_with_no_change_is_a_no_op() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();

        b.import_file(&mut store, &file).unwrap();
        let sidecar_before = Sidecar::load(&file).unwrap().unwrap();

        let outcome = b.import_file(&mut store, &file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(!outcome.changed);

        let sidecar_after = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar_before, sidecar_after);
    }

    #[test]
    fn incremental_edit_applies_a_minimal_delta() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        // "hello\n" -> "hello world\n": a single insert of " world".
        std::fs::write(&file, "hello world\n").unwrap();
        let outcome = b.import_file(&mut store, &file).unwrap();
        assert!(outcome.changed);
        // Minimal delta: exactly one insert op, not a full re-insert.
        assert_eq!(outcome.ops_applied, 1);

        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(store.text(&container), "hello world\n");
    }

    #[test]
    fn multibyte_incremental_reconciles_via_char_offsets() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("cafe.md");
        std::fs::write(&file, "café\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        std::fs::write(&file, "cafés\n").unwrap();
        let outcome = b.import_file(&mut store, &file).unwrap();
        assert!(outcome.changed);

        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(store.text(&container), "cafés\n");
    }

    #[test]
    fn missing_sidecar_reseeds_baseline_from_store_not_empty() {
        // Regression (#2): a populated container + an absent sidecar + an
        // UNCHANGED file must NOT double the container. The baseline defaults
        // to the store's current text (not ""), so an unchanged file is a
        // no-op rather than a full re-insert at pos 0.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        // Delete the sidecar off disk (simulates a deleted/unsynced
        // `.roammeta` or a cold-reopen oplog replay with no sidecar yet).
        std::fs::remove_file(crate::sidecar::sidecar_path(&file)).unwrap();

        // Re-import the SAME unchanged file: must be a no-op, not a double.
        let outcome = b.import_file(&mut store, &file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(!outcome.changed);

        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(store.text(&container), "hello\n");
    }

    #[test]
    fn missing_sidecar_diffs_only_delta_against_store() {
        // Regression (#2): absent sidecar + a container already holding
        // "hello\n" + a disk file "hello world\n" must diff only the delta
        // against the store's current text, ending at "hello world\n" (not
        // doubled, not re-seeded from empty).
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        std::fs::remove_file(crate::sidecar::sidecar_path(&file)).unwrap();
        std::fs::write(&file, "hello world\n").unwrap();

        let outcome = b.import_file(&mut store, &file).unwrap();
        assert!(outcome.changed);
        // Minimal delta against the store: one insert, not a full re-seed.
        assert_eq!(outcome.ops_applied, 1);

        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(store.text(&container), "hello world\n");
    }

    #[test]
    fn project_file_refuses_to_clobber_dirty_local_edits() {
        // Regression (#3): the on-disk file has local edits the user hasn't
        // imported yet. Projecting must NOT overwrite them; it returns
        // Err(DirtyFile) and leaves the file bytes untouched.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        // Edit disk WITHOUT importing: now disk != baseline and disk != store.
        std::fs::write(&file, "local edit\n").unwrap();

        let result = b.project_file(&mut store, &file);
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
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        // Advance the store only (disk stays at the baseline "hello\n").
        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        store.edit_text(&container, 5, " world").unwrap();
        assert_eq!(store.text(&container), "hello world\n");

        let outcome = b.project_file(&mut store, &file).unwrap();
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
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        let container = container_id(&vault, &file).unwrap();
        assert_eq!(store.text(&container), "hello world\n");

        // Simulate a REMOTE merge: a peer inserted "XYZ " at the front of the
        // container. Inject it directly through the store (the same private
        // access `project_file_projects_when_disk_is_clean_but_stale` uses),
        // WITHOUT touching the sidecar — exactly what the sync engine does when
        // it merges a peer's ops into a container this device also syncs.
        store.edit_text(&container, 0, "XYZ ").unwrap();
        assert_eq!(store.text(&container), "XYZ hello world\n");

        // Local disk edit: insert " END" before the trailing newline.
        std::fs::write(&file, "hello world END\n").unwrap();
        let outcome = b.import_file(&mut store, &file).unwrap();
        assert!(outcome.changed);
        assert!(outcome.ops_applied > 0);

        // The 3-way merge keeps BOTH the remote "XYZ " prefix AND the local
        // " END" suffix.
        assert_eq!(store.text(&container), "XYZ hello world END\n");

        // Sidecar baseline tracks the DISK text (L), not the merged store text.
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "hello world END\n");
    }

    #[test]
    fn concurrent_remote_delete_local_insert_merges_both() {
        // Test #2: remote deleted a region the local edit didn't touch; the
        // merge keeps the remote deletion AND the local insertion.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remote deletes "world" → store reads "hello \n".
        store.delete_text(&container, 6, 5).unwrap();
        assert_eq!(store.text(&container), "hello \n");

        // Local inserts " END" before the newline (untouched region).
        std::fs::write(&file, "hello world END\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        assert_eq!(store.text(&container), "hello  END\n");
    }

    #[test]
    fn local_delete_of_partially_remote_deleted_region() {
        // Test #3: local deletes a run remote already partially removed — only
        // the still-present chars are deleted; no out-of-bounds, no error.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remote deletes "wor" (chars 6..9) → store reads "hello ld\n".
        store.delete_text(&container, 6, 3).unwrap();
        assert_eq!(store.text(&container), "hello ld\n");

        // Local deletes the whole "world" run → disk "hello \n".
        std::fs::write(&file, "hello \n").unwrap();
        let outcome = b.import_file(&mut store, &file).unwrap();
        assert!(outcome.changed);

        // Only the still-present "ld" is removed; result converges cleanly.
        assert_eq!(store.text(&container), "hello \n");
    }

    #[test]
    fn multibyte_rebase_stays_char_correct() {
        // Test #4: remote inserts a multi-byte (CJK + emoji) prefix, local edits
        // after it — offsets stay char-correct through the rebase.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("cafe.md");
        std::fs::write(&file, "café\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remote inserts "世界🚀 " at the front (4 chars).
        store.edit_text(&container, 0, "世界🚀 ").unwrap();
        assert_eq!(store.text(&container), "世界🚀 café\n");

        // Local appends " latte" before the newline.
        std::fs::write(&file, "café latte\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        assert_eq!(store.text(&container), "世界🚀 café latte\n");
    }

    #[test]
    fn concurrent_merge_import_then_project_converges_to_fast_path() {
        // Test #6: a concurrent-merge import, then project_file, then a second
        // import must reach the R == A fast path — stable, byte-stable disk, no
        // drift or re-corruption.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Concurrent remote merge + local edit, then import (rebase path).
        store.edit_text(&container, 0, "XYZ ").unwrap();
        std::fs::write(&file, "hello world END\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        assert_eq!(store.text(&container), "XYZ hello world END\n");

        // After import the baseline tracks disk (L), not the merged store text.
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "hello world END\n");

        // Project the merged store text to disk: now disk == store == baseline.
        let projected = b.project_file(&mut store, &file).unwrap();
        assert!(projected.changed);
        assert_eq!(std::fs::read(&file).unwrap(), b"XYZ hello world END\n");
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "XYZ hello world END\n");

        // A second import now hits the fast path (R == A): a stable no-op.
        let outcome = b.import_file(&mut store, &file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(!outcome.changed);
        assert_eq!(store.text(&container), "XYZ hello world END\n");

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
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        store.edit_text(&container, 0, "XYZ ").unwrap();
        std::fs::write(&file, "hello world END\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        // Baseline == disk text L, NOT the merged store text.
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "hello world END\n");
        assert_ne!(sidecar.last_synced_text, store.text(&container));

        // Dirty-check still works: disk == baseline, so projection is allowed
        // (not treated as dirty) and advances the baseline to the store text.
        b.project_file(&mut store, &file).unwrap();
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, store.text(&container));
        assert_eq!(sidecar.last_synced_text, "XYZ hello world END\n");
    }

    #[test]
    fn non_utf8_file_is_not_text() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("binary.md");
        std::fs::write(&file, [0xff, 0xfe]).unwrap();

        assert!(matches!(
            b.import_file(&mut store, &file),
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
        let result = reconcile_sidecar(
            &file,
            "note.md",
            "hello world",
            "hello world",
            "partial",
            1,
            None,
        );
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
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let a = vault.join("a.md");
        let c = vault.join("c.md");
        std::fs::write(&a, "aaa").unwrap();
        std::fs::write(&c, "ccc").unwrap();

        b.import_file(&mut store, &a).unwrap();
        b.import_file(&mut store, &c).unwrap();

        let ca = container_id(&vault, &a).unwrap();
        let cc = container_id(&vault, &c).unwrap();
        assert_ne!(ca, cc);
        assert_eq!(store.text(&ca), "aaa");
        assert_eq!(store.text(&cc), "ccc");

        // Editing one must not disturb the other.
        std::fs::write(&a, "aaaZ").unwrap();
        b.import_file(&mut store, &a).unwrap();
        assert_eq!(store.text(&ca), "aaaZ");
        assert_eq!(store.text(&cc), "ccc");
    }

    #[test]
    fn project_file_is_byte_stable_round_trip() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("a.md");
        // Multi-byte content with NO trailing newline.
        let original = "# Title\ncafé — 世界";
        std::fs::write(&file, original).unwrap();
        let original_bytes = std::fs::read(&file).unwrap();

        b.import_file(&mut store, &file).unwrap();
        std::fs::remove_file(&file).unwrap();

        let outcome = b.project_file(&mut store, &file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(outcome.changed);

        // Byte-for-byte identical to the original file.
        assert_eq!(std::fs::read(&file).unwrap(), original_bytes);
    }

    #[test]
    fn project_then_import_is_a_no_op() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();

        b.import_file(&mut store, &file).unwrap();
        // Disk already matches the store and the sidecar records it: a no-op.
        let projected = b.project_file(&mut store, &file).unwrap();
        assert!(!projected.changed);

        let outcome = b.import_file(&mut store, &file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(!outcome.changed);
    }

    #[test]
    fn project_file_writes_store_text_when_disk_missing() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("x.md");
        std::fs::write(&file, "hello").unwrap();
        b.import_file(&mut store, &file).unwrap();

        std::fs::remove_file(&file).unwrap();
        let outcome = b.project_file(&mut store, &file).unwrap();
        assert!(outcome.changed);
        assert_eq!(std::fs::read(&file).unwrap(), b"hello");
    }

    #[test]
    fn project_file_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let deep = dir
            .path()
            .join("vault")
            .join("sub")
            .join("dir")
            .join("deep.md");

        let outcome = b.project_file(&mut store, &deep).unwrap();
        assert!(outcome.changed);
        assert!(deep.exists());
        // Empty container projects an empty file (byte-stable, no newline).
        assert_eq!(std::fs::read(&deep).unwrap(), b"");
    }

    #[test]
    fn scan_imports_md_and_org_ignoring_others() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
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

        let outcomes = b.scan(&mut store).unwrap();
        assert_eq!(outcomes.len(), 2);
        for (path, outcome) in &outcomes {
            assert!(outcome.changed);
            assert!(path == &one || path == &two);
            let container = container_id(&vault, path).unwrap();
            let expected = std::fs::read_to_string(path).unwrap();
            assert_eq!(store.text(&container), expected);
        }
    }

    #[test]
    fn scan_skips_non_utf8_md_without_aborting() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let good = vault.join("good.md");
        std::fs::write(&good, "good").unwrap();
        std::fs::write(vault.join("bad.md"), [0xff, 0xff]).unwrap();

        let outcomes = b.scan(&mut store).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].0, good);
        let container = container_id(&vault, &good).unwrap();
        assert_eq!(store.text(&container), "good");
    }

    #[cfg(unix)]
    #[test]
    fn scan_does_not_recurse_into_symlink_cycle() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let real = vault.join("real.md");
        std::fs::write(&real, "real body").unwrap();
        // A directory symlink pointing back at the vault: descending it would
        // loop forever. scan must terminate.
        std::os::unix::fs::symlink(&vault, vault.join("loop")).unwrap();

        let outcomes = b.scan(&mut store).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].0, real);
        let container = container_id(&vault, &real).unwrap();
        assert_eq!(store.text(&container), "real body");
    }

    /// Find the file-set entry for `container` in the map, if any.
    fn fileset_entry(store: &Store, container: &str) -> Option<FileEntry> {
        store
            .entries(FILESET_MAP_ID)
            .into_iter()
            .find(|(key, _)| key == container)
            .map(|(_, value)| FileEntry::from_value(&value).unwrap())
    }

    #[test]
    fn import_upserts_live_fileset_entry() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        let container = container_id(&vault, &file).unwrap();
        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(
            entry,
            FileEntry {
                kind: EntryKind::Text,
                status: EntryStatus::Live,
                content_hash: text_hash("hello\n"),
            }
        );
    }

    #[test]
    fn reimport_after_edit_updates_entry_hash_still_live() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        let container = container_id(&vault, &file).unwrap();
        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.status, EntryStatus::Live);
        assert_eq!(entry.content_hash, text_hash("hello world\n"));
    }

    #[test]
    fn errored_import_does_not_write_live_entry() {
        // A NotText import errors before any ops/sidecar/entry write, so no
        // file-set entry must be created.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("binary.md");
        std::fs::write(&file, [0xff, 0xfe]).unwrap();

        assert!(matches!(
            b.import_file(&mut store, &file),
            Err(FilesError::NotText(_))
        ));

        let container = container_id(&vault, &file).unwrap();
        assert!(fileset_entry(&store, &container).is_none());
    }

    #[test]
    fn delete_file_tombstones_entry_removes_disk_keeps_container() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();
        let store_text_before = store.text(&container);

        let outcome = b.delete_file(&mut store, &file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(outcome.changed);

        // Entry tombstoned with hash == store text at delete time.
        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.status, EntryStatus::Tombstoned);
        assert_eq!(entry.kind, EntryKind::Text);
        assert_eq!(entry.content_hash, text_hash(&store_text_before));

        // Disk file and sidecar are gone.
        assert!(!file.exists());
        assert!(!crate::sidecar::sidecar_path(&file).exists());

        // Container text is intact (history / resurrection).
        assert_eq!(store.text(&container), store_text_before);
        assert_eq!(store_text_before, "hello\n");
    }

    #[test]
    fn delete_file_tolerates_already_absent_disk_file() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remove disk file + sidecar out from under delete_file.
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_file(crate::sidecar::sidecar_path(&file)).unwrap();

        let outcome = b.delete_file(&mut store, &file).unwrap();
        assert!(outcome.changed);
        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.status, EntryStatus::Tombstoned);
    }

    #[test]
    fn delete_file_leaves_exactly_one_tombstoned_entry_for_path() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        b.delete_file(&mut store, &file).unwrap();

        let matching: Vec<_> = store
            .entries(FILESET_MAP_ID)
            .into_iter()
            .filter(|(key, _)| key == &container)
            .collect();
        assert_eq!(matching.len(), 1);
        let entry = FileEntry::from_value(&matching[0].1).unwrap();
        assert_eq!(entry.status, EntryStatus::Tombstoned);
    }

    /// A stable, sorted snapshot of the whole file-set map for equality asserts.
    fn fileset_snapshot(store: &Store) -> Vec<(String, String)> {
        let mut entries = store.entries(FILESET_MAP_ID);
        entries.sort();
        entries
    }

    fn live(hash: String) -> String {
        FileEntry {
            kind: EntryKind::Text,
            status: EntryStatus::Live,
            content_hash: hash,
        }
        .to_value()
    }

    fn tombstoned(hash: String) -> String {
        FileEntry {
            kind: EntryKind::Text,
            status: EntryStatus::Tombstoned,
            content_hash: hash,
        }
        .to_value()
    }

    #[test]
    fn scan_tombstones_locally_deleted_file() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("a.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Delete the disk file directly (NOT via delete_file); the sidecar is
        // left behind, which is what proves this device once had the file.
        std::fs::remove_file(&file).unwrap();
        assert!(sidecar_path(&file).exists());

        b.scan(&mut store).unwrap();

        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.status, EntryStatus::Tombstoned);
        assert_eq!(entry.content_hash, text_hash("hello\n"));
        // The stale sidecar is dropped so a later remote re-create reads as new.
        assert!(!sidecar_path(&file).exists());

        // Idempotent: a second scan with no external change mutates nothing.
        let before = fileset_snapshot(&store);
        b.scan(&mut store).unwrap();
        assert_eq!(fileset_snapshot(&store), before);
        assert!(!file.exists());
    }

    #[test]
    fn scan_projects_remote_new_file() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("b.md");

        // Inject a remote Live entry AND remote container content, with no disk
        // file and no sidecar — exactly what a synced-in peer create looks like.
        store
            .set_entry(FILESET_MAP_ID, "b.md", &live(text_hash("remote\n")))
            .unwrap();
        store.edit_text("b.md", 0, "remote\n").unwrap();
        assert!(!file.exists());
        assert!(!sidecar_path(&file).exists());

        b.scan(&mut store).unwrap();

        // The file is created on disk with the remote content and a sidecar.
        assert_eq!(std::fs::read(&file).unwrap(), b"remote\n");
        assert!(sidecar_path(&file).exists());
        assert_eq!(
            fileset_entry(&store, "b.md").unwrap().status,
            EntryStatus::Live
        );

        // Idempotent.
        let before = fileset_snapshot(&store);
        let disk_before = std::fs::read(&file).unwrap();
        b.scan(&mut store).unwrap();
        assert_eq!(fileset_snapshot(&store), before);
        assert_eq!(std::fs::read(&file).unwrap(), disk_before);
    }

    #[test]
    fn scan_reprojects_remotely_edited_present_file() {
        // Core convergence bug: this device holds a synced file on disk (Live
        // entry + sidecar). A remote peer edits it and the edit merges into the
        // CONTAINER via sync, but this device's DISK stays stale. Step 1's
        // import is a no-op (disk unchanged), so scan must reconcile the
        // CRDT->disk direction for a Live+present entry and reproject.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("x.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // A remote edit merges into the container after the last local sync.
        // Disk is untouched and still holds the old "hello\n".
        store.edit_text(&container, 5, " world").unwrap();
        assert_eq!(store.text(&container), "hello world\n");
        assert_eq!(std::fs::read(&file).unwrap(), b"hello\n");

        b.scan(&mut store).unwrap();

        // Disk now reflects the remote edit; baseline advanced; entry Live.
        assert_eq!(std::fs::read(&file).unwrap(), b"hello world\n");
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "hello world\n");
        assert_eq!(
            fileset_entry(&store, &container).unwrap().status,
            EntryStatus::Live
        );

        // Idempotent: a second scan makes no further disk/entry mutation.
        let before = fileset_snapshot(&store);
        let disk_before = std::fs::read(&file).unwrap();
        b.scan(&mut store).unwrap();
        assert_eq!(fileset_snapshot(&store), before);
        assert_eq!(std::fs::read(&file).unwrap(), disk_before);
    }

    #[test]
    fn scan_merges_remote_and_uncommitted_local_edits_on_disk() {
        // A dirty local disk edit (not yet imported) AND a remote edit merged
        // into the container. Step 1 imports the local edit (OT rebase folds it
        // into the container), then Step 3 reprojects the merged container to
        // disk. BOTH edits must survive — no data loss, no clobber.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("x.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remote edit merges into the container: "hello\n" -> "hello world\n".
        store.edit_text(&container, 5, " world").unwrap();
        assert_eq!(store.text(&container), "hello world\n");

        // Local un-imported disk edit: prepend "LOCAL " -> "LOCAL hello\n".
        std::fs::write(&file, "LOCAL hello\n").unwrap();

        b.scan(&mut store).unwrap();

        // Both edits survive as the OT merge on disk.
        let disk = std::fs::read_to_string(&file).unwrap();
        assert_eq!(disk, "LOCAL hello world\n");
        // Converged: disk == container == baseline.
        assert_eq!(store.text(&container), disk);
        let sidecar = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, disk);
    }

    #[test]
    fn scan_applies_remote_tombstone_delete_wins() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("c.md");
        std::fs::write(&file, "x\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Simulate a synced-in remote tombstone whose hash matches the
        // container's CURRENT text: no edit landed after the delete.
        store
            .set_entry(
                FILESET_MAP_ID,
                &container,
                &tombstoned(text_hash(&store.text(&container))),
            )
            .unwrap();

        b.scan(&mut store).unwrap();

        // Delete wins: the disk file and its sidecar are removed.
        assert!(!file.exists());
        assert!(!sidecar_path(&file).exists());
        assert_eq!(
            fileset_entry(&store, &container).unwrap().status,
            EntryStatus::Tombstoned
        );

        // Idempotent.
        let before = fileset_snapshot(&store);
        b.scan(&mut store).unwrap();
        assert_eq!(fileset_snapshot(&store), before);
        assert!(!file.exists());
    }

    #[test]
    fn scan_tombstone_uses_last_synced_hash_not_current_store_text() {
        // CRITICAL 1: a remote edit may merge into the container BEFORE this
        // device's local delete is tombstoned. The tombstone must capture what
        // this device last synced (sidecar.last_synced_hash), NOT the current
        // (remote-merged) store text — otherwise the resurrection guard can
        // never fire and the peer's concurrent edit is silently deleted.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("x.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // A remote edit merges into the container after the last local sync.
        store.edit_text(&container, 5, " world").unwrap();
        assert_eq!(store.text(&container), "hello world\n");

        // Local delete of the disk file (sidecar left behind).
        std::fs::remove_file(&file).unwrap();

        b.scan(&mut store).unwrap();

        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.status, EntryStatus::Tombstoned);
        // The OLD/last-synced hash, not the current merged store text.
        assert_eq!(entry.content_hash, text_hash("hello\n"));
        assert_ne!(entry.content_hash, text_hash("hello world\n"));
    }

    #[test]
    fn delete_file_uses_last_synced_hash_not_current_store_text() {
        // CRITICAL 1 (delete_file variant): same invariant via the explicit API.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("x.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        store.edit_text(&container, 5, " world").unwrap();
        assert_eq!(store.text(&container), "hello world\n");

        b.delete_file(&mut store, &file).unwrap();

        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.status, EntryStatus::Tombstoned);
        assert_eq!(entry.content_hash, text_hash("hello\n"));
    }

    #[test]
    fn scan_cleans_orphan_sidecar_then_remote_new_reworks() {
        // CRITICAL 2: a remote tombstone for a file already gone locally but
        // whose sidecar lingers must clean the orphan sidecar, else the
        // remote-new gate (Live + absent + !sidecar) stays false forever and
        // the path can never be re-materialized.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("y.md");

        // Orphan state: a lingering sidecar, no disk file, a Tombstoned entry.
        Sidecar {
            version: SIDECAR_VERSION,
            doc_id: "y.md".to_string(),
            last_synced_hash: text_hash("old\n"),
            last_synced_text: "old\n".to_string(),
        }
        .store(&file)
        .unwrap();
        assert!(sidecar_path(&file).exists());
        assert!(!file.exists());
        store
            .set_entry(FILESET_MAP_ID, "y.md", &tombstoned(text_hash("old\n")))
            .unwrap();

        b.scan(&mut store).unwrap();
        // The orphan sidecar is cleaned.
        assert!(!sidecar_path(&file).exists());

        // Now a remote re-create at the same path must materialize again.
        store
            .set_entry(FILESET_MAP_ID, "y.md", &live(text_hash("remote\n")))
            .unwrap();
        store.edit_text("y.md", 0, "remote\n").unwrap();

        b.scan(&mut store).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"remote\n");
        assert_eq!(
            fileset_entry(&store, "y.md").unwrap().status,
            EntryStatus::Live
        );

        // Idempotent.
        let before = fileset_snapshot(&store);
        b.scan(&mut store).unwrap();
        assert_eq!(fileset_snapshot(&store), before);
    }

    #[test]
    fn scan_heals_present_file_missing_fileset_entry() {
        // IMPORTANT 3: a present file with a valid sidecar + populated container
        // but NO file-set entry (pre-file-set migration or a lost entry op) must
        // gain a Live entry, else peers never learn it exists.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("m.md");
        std::fs::write(&file, "hello\n").unwrap();

        // Populate the container to match the disk, and write a matching sidecar
        // — but never import_file, so no file-set entry exists.
        store.edit_text("m.md", 0, "hello\n").unwrap();
        Sidecar {
            version: SIDECAR_VERSION,
            doc_id: "m.md".to_string(),
            last_synced_hash: text_hash("hello\n"),
            last_synced_text: "hello\n".to_string(),
        }
        .store(&file)
        .unwrap();
        assert!(fileset_entry(&store, "m.md").is_none());

        b.scan(&mut store).unwrap();

        let entry = fileset_entry(&store, "m.md").unwrap();
        assert_eq!(entry.status, EntryStatus::Live);
        assert_eq!(entry.content_hash, text_hash("hello\n"));

        // Idempotent.
        let before = fileset_snapshot(&store);
        b.scan(&mut store).unwrap();
        assert_eq!(fileset_snapshot(&store), before);
    }

    #[test]
    fn scan_heal_does_not_force_live_a_tombstoned_present_file() {
        // IMPORTANT 3 guard: the missing-entry heal must NOT touch a present
        // file that already carries a Tombstoned entry — delete-wins must stay
        // reachable (Step 3 owns it).
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("c.md");
        std::fs::write(&file, "x\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remote tombstone whose hash matches the current text (delete wins).
        store
            .set_entry(
                FILESET_MAP_ID,
                &container,
                &tombstoned(text_hash(&store.text(&container))),
            )
            .unwrap();

        b.scan(&mut store).unwrap();

        // Delete wins: the entry stays Tombstoned and the file is removed — the
        // heal did NOT force it back to Live.
        assert_eq!(
            fileset_entry(&store, &container).unwrap().status,
            EntryStatus::Tombstoned
        );
        assert!(!file.exists());
    }

    #[test]
    fn scan_applies_remote_tombstone_resurrection_edit_wins() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("d.md");
        std::fs::write(&file, "x\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remote tombstone with a STALE hash (the pre-edit text)...
        store
            .set_entry(FILESET_MAP_ID, &container, &tombstoned(text_hash("x\n")))
            .unwrap();
        // ...then a concurrent edit merged into the container AFTER the delete,
        // so the container diverges from the tombstone hash.
        let end = store.text(&container).chars().count();
        store.edit_text(&container, end, "more\n").unwrap();
        assert_eq!(store.text(&container), "x\nmore\n");

        b.scan(&mut store).unwrap();

        // Edit wins: the file is kept, the entry flips back to Live with the NEW
        // hash, and disk matches the edited container.
        assert!(file.exists());
        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.status, EntryStatus::Live);
        assert_eq!(entry.content_hash, text_hash("x\nmore\n"));
        assert_eq!(std::fs::read(&file).unwrap(), b"x\nmore\n");

        // Idempotent.
        let before = fileset_snapshot(&store);
        let disk_before = std::fs::read(&file).unwrap();
        b.scan(&mut store).unwrap();
        assert_eq!(fileset_snapshot(&store), before);
        assert_eq!(std::fs::read(&file).unwrap(), disk_before);
    }

    #[test]
    fn rename_file_moves_content_disk_and_entries() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let old = vault.join("old.md");
        let new = vault.join("new.md");
        std::fs::write(&old, "content\n").unwrap();
        b.import_file(&mut store, &old).unwrap();
        let old_container = container_id(&vault, &old).unwrap();
        let new_container = container_id(&vault, &new).unwrap();

        let outcome = b.rename_file(&mut store, &old, &new).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(outcome.changed);

        // The content lives in the new container now.
        assert_eq!(store.text(&new_container), "content\n");

        // The new file exists on disk with the content and a sidecar.
        assert_eq!(std::fs::read(&new).unwrap(), b"content\n");
        assert!(sidecar_path(&new).exists());

        // The old file and its sidecar are gone.
        assert!(!old.exists());
        assert!(!sidecar_path(&old).exists());

        // Entries: new → Live, old → Tombstoned, both hashing the moved content.
        let new_entry = fileset_entry(&store, &new_container).unwrap();
        assert_eq!(new_entry.status, EntryStatus::Live);
        assert_eq!(new_entry.content_hash, text_hash("content\n"));
        let old_entry = fileset_entry(&store, &old_container).unwrap();
        assert_eq!(old_entry.status, EntryStatus::Tombstoned);
        assert_eq!(old_entry.content_hash, text_hash("content\n"));
    }

    #[test]
    fn rename_into_subdir_creates_parent_dir() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let old = vault.join("old.md");
        let new = vault.join("sub").join("new.md");
        std::fs::write(&old, "content\n").unwrap();
        b.import_file(&mut store, &old).unwrap();

        b.rename_file(&mut store, &old, &new).unwrap();

        assert!(new.exists());
        assert_eq!(std::fs::read(&new).unwrap(), b"content\n");
        assert!(!old.exists());
    }

    #[test]
    fn rename_flushes_pending_disk_edits_before_moving() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let old = vault.join("old.md");
        let new = vault.join("new.md");
        std::fs::write(&old, "a\n").unwrap();
        b.import_file(&mut store, &old).unwrap();

        // Edit the disk file WITHOUT importing: the pending edit must be flushed
        // by rename so the LATEST disk content ("a b\n") is what moves.
        std::fs::write(&old, "a b\n").unwrap();

        b.rename_file(&mut store, &old, &new).unwrap();

        let new_container = container_id(&vault, &new).unwrap();
        assert_eq!(store.text(&new_container), "a b\n");
        assert_eq!(std::fs::read(&new).unwrap(), b"a b\n");
    }

    #[test]
    fn rename_then_scan_is_stable() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let old = vault.join("old.md");
        let new = vault.join("new.md");
        std::fs::write(&old, "content\n").unwrap();
        b.import_file(&mut store, &old).unwrap();

        b.rename_file(&mut store, &old, &new).unwrap();

        // A post-rename scan must not recreate old.md (Tombstoned + absent) nor
        // disturb new.md (Live + present): disk and entries stay stable.
        let entries_before = fileset_snapshot(&store);
        let new_disk_before = std::fs::read(&new).unwrap();
        b.scan(&mut store).unwrap();
        assert_eq!(fileset_snapshot(&store), entries_before);
        assert_eq!(std::fs::read(&new).unwrap(), new_disk_before);
        assert!(!old.exists());
        assert!(new.exists());
    }

    #[test]
    fn rename_from_equals_to_is_a_no_op() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "content\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        let outcome = b.rename_file(&mut store, &file, &file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(!outcome.changed);

        // No data lost: file, sidecar, container, and the Live entry all survive.
        assert_eq!(std::fs::read(&file).unwrap(), b"content\n");
        assert!(sidecar_path(&file).exists());
        assert_eq!(store.text(&container), "content\n");
        assert_eq!(
            fileset_entry(&store, &container).unwrap().status,
            EntryStatus::Live
        );
    }
}
