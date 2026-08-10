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
//! ## #5 — Tombstone retention: client-driven via `Store::checkpoint`
//!
//! The causally-stable tombstone REAPER that [`FolderBridge::scan_gc`] once ran
//! has been RETIRED. Retention is now client-driven via [`Store::checkpoint`]:
//! a `Tombstoned` entry is RETAINED (its history recoverable via
//! [`FolderBridge::resurrect`]) rather than dropped by a sweep. Two properties
//! are KEPT: (a) deletion PROPAGATION — a delete stays a normal op that syncs,
//! so peers converge to the tombstone; and (b) the RESURRECTION GUARD — a stale
//! peer's `Live` entry cannot resurrect a deleted file (see
//! [`FolderBridge::scan_gc`], Step 3). The [`GcContext`] and its
//! [`GcContext::tombstone_is_stable`] predicate remain defined for tests and
//! potential engine callers, but no longer drive any sweep here.
//!
//! [`FolderBridge::list_deleted`] enumerates the retained tombstones so a caller
//! (e.g. a restore UI) can offer to [`resurrect`](FolderBridge::resurrect) them.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use roam_storage::{version_dominates, Store};

use crate::error::FilesError;
use crate::fileset::{EntryKind, EntryStatus, FileEntry, FILESET_MAP_ID};
use crate::path::{container_id, key_to_path};
use crate::rebase::{merge_local_onto_remote, Conflict};
use crate::sidecar::{sidecar_path, text_hash, Sidecar};
use crate::textdiff::{diff_to_ops, TextOp};

/// Current sidecar format version written by [`FolderBridge::import_file`].
const SIDECAR_VERSION: u32 = 1;

/// The result of reconciling a single file into the CRDT store.
///
/// No longer `Copy`: `conflicts` owns a `Vec`. It is cheap to `Clone` and, in
/// the overwhelmingly common no-conflict case, the `Vec` is empty (no
/// allocation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Number of edit ops applied to the container.
    pub ops_applied: usize,
    /// Whether anything changed (ops applied + sidecar rewritten).
    pub changed: bool,
    /// Concurrent-edit conflicts surfaced by the 3-way merge during this import
    /// (both sides changed overlapping ancestor content). Empty when there was
    /// no merge or the concurrent edits were disjoint. Purely informational —
    /// the merge result (and thus the store text) is unaffected by conflicts.
    pub conflicts: Vec<Conflict>,
}

impl SyncOutcome {
    /// A no-op outcome: nothing changed, no ops, no conflicts.
    fn unchanged() -> Self {
        Self {
            ops_applied: 0,
            changed: false,
            conflicts: Vec::new(),
        }
    }

    /// A changed outcome that applied no edit ops (a projection/deletion/entry
    /// flip) and carries no conflicts.
    fn changed_no_ops() -> Self {
        Self {
            ops_applied: 0,
            changed: true,
            conflicts: Vec::new(),
        }
    }
}

/// Plain-data snapshot the causally-stable tombstone GC needs, passed into
/// [`FolderBridge::scan_gc`]. Deliberately runtime-agnostic (no engine/tokio
/// dependency): the caller (the sync engine / CLI) gathers this from its roster
/// and per-peer acked-version tracking and hands it in, and the bridge computes
/// stability itself using [`roam_storage::version_dominates`].
///
/// SAFETY CONTRACT: a tombstone is GC-eligible only when EVERY peer in
/// [`trusted_peers`](Self::trusted_peers) (other than [`self_peer`](Self::self_peer))
/// has an entry in [`acked_versions`](Self::acked_versions) whose version
/// dominates the tombstone's checkpoint. A trusted peer that is ABSENT from
/// `acked_versions` (never heard from — e.g. offline during the delete) makes
/// the tombstone NON-eligible, which is exactly what stops a later-reconnecting
/// peer from resurrecting the file.
///
/// An EMPTY [`trusted_peers`](Self::trusted_peers) set is treated as NEVER
/// stable (see [`tombstone_is_stable`](Self::tombstone_is_stable)), so an
/// incomplete/empty roster snapshot can never trivially GC every tombstone. In
/// practice callers always include `self` in the trusted set, but this makes GC
/// safe-by-construction regardless of caller discipline. For the same reason
/// `GcContext` deliberately does NOT derive `Default` — a caller must build a
/// real context from actual roster + acked-version data.
///
/// TRUST DEPENDENCY: GC correctness assumes trusted peers HONESTLY report the
/// document version they have applied in their `Have` frames — the acked
/// versions here are peer-reported. A malicious or buggy TRUSTED peer that
/// advertises a version it does not actually hold could advance its recorded
/// ack and drive PREMATURE GC (and thus resurrection on a peer that really
/// still holds a stale `Live`). This is accepted under the project's current
/// deferred trust model (trusted peers are assumed honest); revisit when the
/// security slice lands.
#[derive(Debug, Clone)]
pub struct GcContext {
    /// This device's own peer id. Always treated as having observed the
    /// tombstone (it authored or already holds it), so it never blocks GC.
    pub self_peer: u64,
    /// The trusted, non-revoked peer ids (a roster snapshot). Every one of these
    /// (except `self_peer`) must have acked the tombstone before it may drop.
    pub trusted_peers: Vec<u64>,
    /// Each peer's last-acked document version (`roam_storage`-comparable bytes).
    /// A peer missing here has never told us what it holds → not-yet-observed.
    pub acked_versions: HashMap<u64, Vec<u8>>,
}

impl GcContext {
    /// Whether `entry` (assumed [`EntryStatus::Tombstoned`]) is causally stable
    /// — every trusted non-self peer has acked a version dominating the
    /// tombstone's checkpoint. A tombstone with no checkpoint
    /// ([`FileEntry::tombstoned_at`] `None`, e.g. old-format) is NEVER stable.
    ///
    /// An EMPTY [`trusted_peers`](Self::trusted_peers) set is treated as NEVER
    /// stable: with no known peer set there is no evidence any holder has
    /// observed the tombstone, so GC would otherwise vacuously fire and let an
    /// Active-but-offline peer resurrect the file on reconnect. GC requires the
    /// real trusted peer set (which always includes `self`).
    ///
    /// GC correctness depends on trusted peers honestly reporting their applied
    /// version in `Have` frames — see the [`GcContext`] TRUST DEPENDENCY note.
    ///
    /// Retained for tests and potential engine callers after the tombstone
    /// reaper was retired (retention is now client-driven via
    /// [`Store::checkpoint`]); no longer invoked by [`FolderBridge::scan_gc`].
    #[allow(dead_code)]
    fn tombstone_is_stable(&self, entry: &FileEntry) -> bool {
        // Empty trusted set → never stable (defense-in-depth against an
        // incomplete/empty roster snapshot GC-ing every checkpointed tombstone).
        if self.trusted_peers.is_empty() {
            return false;
        }
        let Some(hex) = &entry.tombstoned_at else {
            return false;
        };
        let Some(tombstone_vv) = hex_decode(hex) else {
            return false;
        };
        for &peer in &self.trusted_peers {
            if peer == self.self_peer {
                continue; // self always counts as having observed it.
            }
            match self.acked_versions.get(&peer) {
                // The peer's acked version must DOMINATE the tombstone checkpoint.
                Some(acked) if version_dominates(acked, &tombstone_vv) => {}
                // Missing acked version, or a version that does not dominate:
                // this peer has NOT provably observed the tombstone → not stable.
                _ => return false,
            }
        }
        true
    }
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
    /// Store-owned metadata directory where sidecars and blob markers live,
    /// OUTSIDE the user's vault folder. Sidecars go under `<meta_dir>/sidecars/`
    /// and blob presence markers under `<meta_dir>/blobmarkers/`, each keyed by
    /// the file's `container_id` so nested notes never collide.
    meta_dir: PathBuf,
}

impl FolderBridge {
    /// Create a bridge over a vault directory plus a store-owned metadata
    /// directory. Does NOT open a Store — the caller owns the Store and passes
    /// it into each operation (so the engine and the bridge can share one Store
    /// instance). `meta_dir` MUST live outside `vault_root` (it holds internal
    /// sidecars/markers that must never pollute the user's notes folder).
    pub fn new(vault_root: &Path, meta_dir: &Path) -> Self {
        Self {
            vault_root: vault_root.to_path_buf(),
            meta_dir: meta_dir.to_path_buf(),
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

        // Case-only-collision guard (B2). On a case-insensitive filesystem two
        // keys that differ ONLY by case (`a.md` vs `A.md`) name the SAME disk
        // file, so tracking the second would silently clobber the first. Reject
        // (don't clobber) before any mutation. The check is at the CRDT-key
        // level — on a truly case-insensitive FS both names are the same disk
        // file anyway; this stops two DISTINCT live keys from ever coexisting.
        // Comparison is ASCII-case-insensitive (see `FilesError::CaseCollision`).
        // A byte-identical re-import (same `a.md` again) is NOT a collision.
        if let Some(existing) = live_case_collision(store, &container) {
            return Err(FilesError::CaseCollision {
                existing,
                incoming: container,
            });
        }

        // Read bytes, then route TEXT vs BLOB purely by CONTENT (never by
        // extension): decode the bytes as UTF-8.
        // - UTF-8 OK  → TEXT path (OT-rebase into a text container). This is the
        //   only char-mergeable form; latin-1 that happens to be valid UTF-8
        //   merges as text too. Nothing is transcoded.
        // - NOT UTF-8 → BLOB path (bytes → BlobStore, Blob entry), ALWAYS,
        //   regardless of extension. A `.md` with invalid UTF-8, a UTF-16 file, a
        //   binary asset — all are whole-file blobs (whole-file sync, no
        //   char-merge). There is no md/org carve-out: nothing is reinterpreted,
        //   only classified by what the bytes actually are.
        let bytes = std::fs::read(file)?;
        let file_text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(err) => {
                let outcome = self.import_blob(store, &container, err.into_bytes())?;
                // Record device-local presence: this device now HAS the blob on
                // disk, so a later scan that finds the file gone (marker still
                // present) can tell it was locally deleted. Written unconditionally
                // (even on an idempotent no-op import) so the marker exists for a
                // pre-existing untracked blob file too. Cheap + idempotent.
                write_blob_marker(&self.meta_dir, &container)?;
                return Ok(outcome);
            }
        };

        // Baseline (`A`) for the diff: the sidecar's last-synced text when
        // present, otherwise the store's CURRENT text (NOT ""). Re-seeding
        // against "" when the container is already populated (cold-reopen oplog
        // replay, or a deleted/unsynced `.roammeta`) would make an unchanged
        // file diff as a full insert at pos 0 — DOUBLING the container.
        let sidecar = Sidecar::load(&self.meta_dir, &container)?;
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
        let (expected, conflicts) = if remote_text == baseline {
            (file_text.clone(), Vec::new())
        } else {
            merge_local_onto_remote(&baseline, &file_text, &remote_text)
        };

        // Ops that carry the store from its CURRENT text to the merged text.
        // Deriving them from `R -> expected` (rather than the raw `A -> L`
        // offsets) is what makes the offsets correct regardless of remote merges.
        let ops = diff_to_ops(&remote_text, &expected);
        if ops.is_empty() {
            return Ok(SyncOutcome::unchanged());
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
        let mut outcome = reconcile_sidecar(
            &self.meta_dir,
            &container,
            &file_text,
            &expected,
            &actual,
            ops.len(),
            apply_err,
        )?;
        // Surface any concurrent-edit conflicts the 3-way merge detected. This
        // is reached only on the success path (reconcile_sidecar returns `Err`
        // on any error/desync), so the store already holds the merged text; the
        // conflicts describe overlaps WITHOUT altering that result.
        outcome.conflicts = conflicts;

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
                renamed_from: None,
                tombstoned_at: None,
            }
            .to_value(),
        )?;

        Ok(outcome)
    }

    /// Route a non-text file's BYTES into the content-addressed blob store and
    /// upsert a [`EntryKind::Blob`] file-set entry that references them.
    ///
    /// The bytes are kept OUTSIDE the CRDT (in [`Store::blobs`]); only the blake3
    /// hash-reference — the entry's `content_hash` — rides the op-log, so the ref
    /// gossips to peers while the bytes transfer out-of-band (a later slice). NO
    /// text container is created, and a blob has NO sidecar: re-import change
    /// detection compares the file's hash against the existing entry, so an
    /// unchanged binary is idempotent (no new map op, no new blob).
    fn import_blob(
        &self,
        store: &mut Store,
        container: &str,
        bytes: Vec<u8>,
    ) -> Result<SyncOutcome, FilesError> {
        // Store the bytes (idempotent/dedup) and take their content hash as the
        // blob-ref. `content_hash` doubles as the blob-ref for a Blob entry.
        let hash = store.blobs().put(&bytes)?;

        // Remote-delete parity guard: if a Tombstoned Blob entry already
        // references THESE exact bytes, this device has NOT locally changed the
        // blob — the file lingers on disk only because a remote delete has not
        // yet been projected (Step 3 removes it). Resurrecting to Live here would
        // author a NEW map op that dominates and cancels the remote tombstone,
        // defeating the delete. Mirror the text path (where an unchanged present
        // file returns early WITHOUT rewriting its entry) and leave the tombstone
        // intact so Step 3 can project the delete to disk. Bytes that DIFFER
        // (a genuine local re-creation/edit) fall through and resurrect to Live,
        // exactly as the text resurrection branch does.
        if let Some(existing) = store.get_entry(FILESET_MAP_ID, container) {
            if let Ok(entry) = FileEntry::from_value(&existing) {
                if entry.status == EntryStatus::Tombstoned
                    && entry.kind == EntryKind::Blob
                    && entry.content_hash == hash
                {
                    return Ok(SyncOutcome::unchanged());
                }
            }
        }

        let value = FileEntry {
            kind: EntryKind::Blob,
            status: EntryStatus::Live,
            content_hash: hash,
            renamed_from: None,
            tombstoned_at: None,
        }
        .to_value();

        // Idempotent no-op: an unchanged binary hashes the same and yields the
        // identical entry value, so re-importing writes no new map op.
        if store.get_entry(FILESET_MAP_ID, container).as_deref() == Some(value.as_str()) {
            return Ok(SyncOutcome::unchanged());
        }
        store.set_entry(FILESET_MAP_ID, container, &value)?;
        Ok(SyncOutcome::changed_no_ops())
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
        let hash = match Sidecar::load(&self.meta_dir, &container)? {
            Some(sidecar) => sidecar.last_synced_hash,
            None => text_hash(&store.text(&container)),
        };

        write_tombstone(store, &container, EntryKind::Text, hash)?;

        // Remove the disk file; already-gone is fine, other IO errors propagate.
        remove_if_present(file)?;
        // Drop the sidecar too so a later remote re-create reads as remote-new.
        remove_if_present(&sidecar_path(&self.meta_dir, &container))?;

        Ok(SyncOutcome::changed_no_ops())
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
        let sidecar = Sidecar::load(&self.meta_dir, &container)?;

        if on_disk.as_deref() == Some(text.as_str()) {
            if let Some(sidecar) = &sidecar {
                if sidecar.last_synced_text == text {
                    return Ok(SyncOutcome::unchanged());
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
            doc_id: container.clone(),
            last_synced_hash: text_hash(&text),
            last_synced_text: text,
        }
        .store(&self.meta_dir, &container)?;

        Ok(SyncOutcome::changed_no_ops())
    }

    /// Project a `Blob` entry's stored bytes onto disk (blob-ref → disk bytes).
    ///
    /// The blob analogue of [`project_file`](Self::project_file), but far
    /// simpler: a blob has NO sidecar and NO CRDT text container — the bytes live
    /// in [`Store::blobs`] and change-detection is purely by content hash.
    ///
    /// - **Bytes absent** (`store.blobs().get` is `None`): a remote-new blob-ref
    ///   whose bytes have not transferred yet — GRACEFULLY SKIP (return
    ///   `unchanged`). Nothing is written, so there is never an empty/corrupt
    ///   file on disk.
    /// - **File already present on disk**: no-op (`unchanged`). A present blob is
    ///   NEVER overwritten here — Step 1's `import_blob` owns present files and
    ///   has already reconciled their on-disk bytes into the entry (disk-wins,
    ///   the blob analogue of the text dirty-file guard). So by the time Step 3
    ///   runs, a present file's bytes already match its entry; and were they to
    ///   differ, they are a LOCAL edit we must not clobber. This is the blob
    ///   equivalent of refusing to overwrite a dirty text file.
    /// - **File absent**: write the blob's bytes ATOMICALLY (sibling temp +
    ///   rename, as elsewhere), byte-identical to the stored payload, and record
    ///   the presence marker. This is the ONLY case that touches disk — a
    ///   remote-new blob-ref whose bytes have now transferred.
    fn project_blob(
        &self,
        store: &mut Store,
        file: &Path,
        content_hash: &str,
    ) -> Result<SyncOutcome, FilesError> {
        // Graceful skip: the bytes for this ref are not local yet.
        let Some(bytes) = store.blobs().get(content_hash)? else {
            return Ok(SyncOutcome::unchanged());
        };

        // Present-file guard: never overwrite a blob already on disk. Step 1 owns
        // present files (disk-wins); a present file either already matches the
        // ref or holds a local edit we must not destroy. Only ABSENT files are
        // projected.
        if file.exists() {
            return Ok(SyncOutcome::unchanged());
        }

        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        atomic_write(file, &bytes)?;
        // Record device-local presence: this device now HAS the blob on disk, so
        // a later scan that finds the file gone (marker present) can tell the
        // blob was locally deleted rather than never-projected (Step 2).
        let container = container_id(&self.vault_root, file)?;
        write_blob_marker(&self.meta_dir, &container)?;
        Ok(SyncOutcome::changed_no_ops())
    }

    /// Reconcile the whole vault against the file-set map (disk ↔ CRDT).
    ///
    /// This is the reconcile entry point. It runs three ordered, single-pass
    /// steps over snapshots of the file-set map — never looping until stable —
    /// and is itself idempotent: a second `scan` with no external change makes
    /// no further mutations.
    ///
    /// **Step 1 — flush local disk → CRDT.** Recursively import every regular
    /// file under `vault_root` ([`import_file`](Self::import_file), which upserts
    /// a [`EntryStatus::Live`] entry; text files also get a sidecar). Files are
    /// classified by CONTENT: valid UTF-8 becomes text, everything else a blob.
    /// Hidden files/directories and our own `.roammeta`/`.roamblob` metadata are
    /// skipped. The set of container ids present on disk is remembered for the
    /// later steps.
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
        self.scan_gc(store, None, None)
    }

    /// Reconcile, but in Step 1 only (re)import the hinted paths instead of
    /// reading+diffing every file under the vault. Steps 1b/2/3 still iterate the
    /// full file-set map (delete detection + remote projection must see every
    /// entry). `None` hint = full walk (identical to [`scan`](Self::scan)).
    ///
    /// TRADEOFF — the hint saves the per-file READ + DIFF, not the directory
    /// walk. Even when hinted we still run `collect_vault_files` (a cheap
    /// `O(files)` stat-only dir walk) to build the accurate `present` set that
    /// Steps 2/3 depend on for delete detection and remote projection; we simply
    /// skip the expensive `import_file` (read + char-diff) for every non-hinted
    /// file. A hinted path that is not actually a vault file on disk (outside the
    /// vault, a symlink, or absent) is silently ignored, because Step 1 only ever
    /// imports the intersection of the hint with the discovered vault files —
    /// exactly the same filtering (hidden/symlink/sidecar) a full walk applies.
    pub fn scan_hinted(
        &self,
        store: &mut Store,
        hint: Option<&HashSet<PathBuf>>,
    ) -> Result<Vec<(PathBuf, SyncOutcome)>, FilesError> {
        self.scan_gc(store, hint, None)
    }

    /// Reconcile (as [`scan_hinted`](Self::scan_hinted)). The causally-stable
    /// tombstone REAPER that this method once ran as a final step has been
    /// RETIRED: retention is now client-driven via [`Store::checkpoint`], so a
    /// tombstone entry is RETAINED rather than dropped. A delete still
    /// PROPAGATES (it is a normal op), and the Step-3 resurrection guard still
    /// prevents a stale peer from resurrecting a deleted file.
    ///
    /// The `_gc` [`GcContext`] parameter is kept only for source-compatibility
    /// with existing callers; it no longer drives any sweep.
    pub fn scan_gc(
        &self,
        store: &mut Store,
        hint: Option<&HashSet<PathBuf>>,
        _gc: Option<&GcContext>,
    ) -> Result<Vec<(PathBuf, SyncOutcome)>, FilesError> {
        // --- Step 1: flush local disk edits into the CRDT. ---
        // The dir walk is ALWAYS done (correctness): Steps 2/3 need an accurate
        // `present` set. Only the import work is narrowed by the hint.
        let mut files = Vec::new();
        collect_vault_files(&self.vault_root, &mut files)?;
        files.sort();

        // Container ids that exist on disk (all discovered vault files; a
        // non-UTF-8 file imports as a blob rather than being skipped).
        let mut present: HashSet<String> = HashSet::new();
        for file in &files {
            present.insert(container_id(&self.vault_root, file)?);
        }

        // When hinted, import ONLY the discovered vault files that are in the
        // hint set — this is the read+diff saving. A full walk imports all.
        let to_import: Vec<PathBuf> = match hint {
            None => files,
            Some(set) => files.into_iter().filter(|f| set.contains(f)).collect(),
        };

        let mut outcomes = Vec::new();
        for file in to_import {
            // Every discovered file imports (text or blob by content); a genuine
            // error (Desync, IO, ...) aborts the scan rather than being skipped.
            let outcome = self.import_file(store, &file)?;
            outcomes.push((file, outcome));
        }

        // --- Step 1b: heal present files with NO file-set entry at all. ---
        // `import_file` writes its Live entry AFTER the `ops.is_empty()` early
        // return, so an unchanged present file that has no entry (pre-file-set
        // migration, or a lost entry op) would stay entry-less forever and never
        // propagate to peers. Heal ONLY a totally-absent entry: a `Tombstoned`
        // entry is owned by Step 3 (delete-wins/resurrection) and a `Live` one
        // is already fine — this must not disturb the "no-op import keeps a
        // remote Tombstoned entry" behavior. Require a sidecar so only TEXT files
        // are healed here (a blob is entried by `import_blob` directly and carries
        // a `.roamblob` marker, not a `.roammeta` sidecar).
        for key in &present {
            if store.get_entry(FILESET_MAP_ID, key).is_some() {
                continue;
            }
            if !sidecar_path(&self.meta_dir, key).exists() {
                continue;
            }
            store.set_entry(
                FILESET_MAP_ID,
                key,
                &FileEntry {
                    kind: EntryKind::Text,
                    status: EntryStatus::Live,
                    content_hash: text_hash(&store.text(key)),
                    renamed_from: None,
                    tombstoned_at: None,
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
            // `key_to_path` inverts container_id → absolute path, splitting the
            // `/`-separated vault-relative key and joining each component so the
            // result uses native separators on every platform (B1).
            let file = key_to_path(&self.vault_root, &key);

            // BLOB local-delete detection (blob-aware variant of the text rule
            // below). A blob has NO sidecar, and — now that pull-transfer (D4)
            // and projection (D5) exist — bytes being present in the local store
            // NO LONGER implies this device ever had the file on disk: a fetched
            // remote-new blob has local bytes BEFORE it is ever projected. The
            // device-local PRESENCE MARKER is the correct "we had it on disk"
            // signal instead (written by import_blob and by project_blob):
            //   Live Blob + file absent + marker PRESENT → locally deleted →
            //     tombstone (the blob-ref IS the entry's own content_hash) and
            //     drop the marker (this device no longer has the file on disk).
            //   Live Blob + file absent + marker ABSENT  → a remote-new blob-ref
            //     never projected here (bytes may or may not have transferred
            //     yet) — leave it for Step 3, do NOT tombstone (never had it).
            if entry.kind == EntryKind::Blob {
                if blob_marker_path(&self.meta_dir, &key).exists() {
                    write_tombstone(store, &key, EntryKind::Blob, entry.content_hash.clone())?;
                    remove_if_present(&blob_marker_path(&self.meta_dir, &key))?;
                    outcomes.push((file, SyncOutcome::changed_no_ops()));
                }
                continue;
            }

            let sidecar = sidecar_path(&self.meta_dir, &key);
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
            let content_hash = match Sidecar::load(&self.meta_dir, &key) {
                Ok(Some(sidecar)) => sidecar.last_synced_hash,
                _ => text_hash(&store.text(&key)),
            };
            write_tombstone(store, &key, entry.kind, content_hash)?;
            remove_if_present(&sidecar)?;
            outcomes.push((file, SyncOutcome::changed_no_ops()));
        }

        // --- Step 3: apply remote state onto disk. ---
        for (key, value) in store.entries(FILESET_MAP_ID) {
            let entry = FileEntry::from_value(&value)?;
            let file = key_to_path(&self.vault_root, &key);
            let file_present = present.contains(&key);
            match entry.status {
                EntryStatus::Live => {
                    // BLOB CRDT→disk projection (D5): write a remote blob's bytes
                    // to disk byte-identically once they are local. `project_blob`
                    // gracefully SKIPS when the bytes have not transferred yet
                    // (bytes-absent remote-new ref: no crash, no empty/corrupt
                    // file) and is a no-op when the on-disk bytes already hash to
                    // `content_hash` (idempotent). It handles the absent-file and
                    // stale-file (differs by hash) cases identically — a fresh
                    // atomic write — so unlike text there is no sidecar/dirty
                    // dance.
                    if entry.kind == EntryKind::Blob {
                        let outcome = self.project_blob(store, &file, &entry.content_hash)?;
                        if outcome.changed {
                            outcomes.push((file, outcome));
                        }
                        continue;
                    }
                    if !file_present && !sidecar_path(&self.meta_dir, &key).exists() {
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
                    // A BLOB tombstone has no text container to hash and no text
                    // file to project. Blob delete projection (D5): mirror the
                    // text delete-wins branch — if the vault file is present,
                    // remove it so a remote blob-delete propagates to disk. Step
                    // 1's `import_blob` guard leaves a same-hash tombstone intact
                    // (does NOT resurrect a present blob), so a remote delete
                    // genuinely reaches this branch with the file still on disk.
                    // Clean any stray sidecar defensively (a blob has none, so
                    // that is a no-op in practice) and skip the text-only
                    // resurrection logic.
                    if entry.kind == EntryKind::Blob {
                        if file_present {
                            remove_if_present(&file)?;
                            outcomes.push((file.clone(), SyncOutcome::changed_no_ops()));
                        }
                        // Drop the presence marker: this device no longer has the
                        // blob on disk, so a future re-projection is treated as
                        // remote-new (not a local delete). Clean any stray sidecar
                        // defensively (a blob has none, so a no-op in practice).
                        remove_if_present(&blob_marker_path(&self.meta_dir, &key))?;
                        remove_if_present(&sidecar_path(&self.meta_dir, &key))?;
                        continue;
                    }
                    if !file_present {
                        // An absent tombstone is reconciled EXCEPT for a leaked
                        // sidecar: a remote tombstone can arrive for a file whose
                        // local disk copy is already gone but whose sidecar
                        // lingers. That orphan sidecar makes the Step-3 remote-new
                        // gate (`Live + absent + !sidecar`) false forever, so the
                        // path could never be re-materialized. Clean it here.
                        remove_if_present(&sidecar_path(&self.meta_dir, &key))?;
                        continue;
                    }
                    let current_hash = text_hash(&store.text(&key));
                    if current_hash == entry.content_hash {
                        // Delete wins: no edit landed after the tombstone.
                        //
                        // EDGE (accepted): the guard is content-hash based, so a
                        // concurrent edit that REVERTS the container to EXACTLY
                        // the tombstoned (last-synced) text hashes back to
                        // `entry.content_hash` and is indistinguishable from "no
                        // edit landed" — delete still wins and that revert edit is
                        // dropped. This is acceptable: the dropped edit reproduced
                        // already-synced content byte-for-byte, so no UNIQUE
                        // content is lost (only a no-op round-trip back to the
                        // synced text). Any edit that ends at DIFFERENT content
                        // changes the hash and takes the resurrection branch
                        // below. See the `resurrection_guard_hash_collision_*`
                        // test, which pins this behavior.
                        remove_if_present(&file)?;
                        remove_if_present(&sidecar_path(&self.meta_dir, &key))?;
                        outcomes.push((file, SyncOutcome::changed_no_ops()));
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
                                renamed_from: None,
                                tombstoned_at: None,
                            }
                            .to_value(),
                        )?;
                        match self.project_file(store, &file) {
                            Ok(outcome) => outcomes.push((file, outcome)),
                            // A dirty disk file carries un-imported local edits —
                            // which ARE the edits the resurrection preserves. Keep
                            // the file as-is (do not clobber) and still report a
                            // change; the entry is already Live.
                            Err(FilesError::DirtyFile(_)) => {
                                outcomes.push((file, SyncOutcome::changed_no_ops()))
                            }
                            Err(err) => return Err(err),
                        }
                    }
                }
            }
        }

        // NOTE: the causally-stable tombstone REAPER (and its companion blob
        // reference-count sweep) has been RETIRED. Tombstone/blob retention is
        // now client-driven via [`Store::checkpoint`]: a tombstone stays a
        // normal, propagating op (deletion PROPAGATION) and its entry is
        // RETAINED so peers converge and history is recoverable via
        // [`FolderBridge::resurrect`]. The resurrection guard above (Step 3)
        // still prevents a stale peer from resurrecting a deleted file. The
        // `_gc` parameter is kept for source-compatibility with callers that
        // pass a [`GcContext`]; it no longer drives any sweep here.

        Ok(outcomes)
    }

    /// Paths of every currently-tombstoned file in the vault (recoverable via
    /// [`FolderBridge::resurrect`] while their history is retained).
    pub fn list_deleted(&self, store: &Store) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for (key, value) in store.entries(FILESET_MAP_ID) {
            if let Ok(entry) = FileEntry::from_value(&value) {
                if entry.status == EntryStatus::Tombstoned {
                    out.push(key_to_path(&self.vault_root, &key));
                }
            }
        }
        out
    }

    /// Re-materialize `file` from its last live content: flip the entry back to
    /// [`EntryStatus::Live`] and re-project the bytes to disk. Produces normal
    /// ops that propagate and heal the mesh. For a blob, the referenced bytes
    /// must still be present.
    pub fn resurrect(&self, store: &mut Store, file: &Path) -> Result<SyncOutcome, FilesError> {
        let key = container_id(&self.vault_root, file)?;
        let value = store
            .get_entry(FILESET_MAP_ID, &key)
            .ok_or_else(|| FilesError::NotFound(file.to_path_buf()))?;
        let entry = FileEntry::from_value(&value)?;
        let live = entry.to_live();
        store.set_entry(FILESET_MAP_ID, &key, &live.to_value())?;
        self.project_file(store, file)
    }

    /// Rename a file within the vault: move its content to the new path's
    /// container, mark the new path Live and the old path Tombstoned in the
    /// file-set map, and move the file + sidecar on disk.
    ///
    /// Modeled as tombstone-old + a new-entry-carrying-content, so the rename
    /// does NOT preserve the old container's edit history — the new container
    /// starts from the old container's CURRENT text.
    ///
    /// WHY history can't move (verified against loro 1.13.9): the crate exposes
    /// no container move/re-key/transplant op. `LoroDoc` offers only
    /// `get_text`/`get_map`/… (attach-or-create by id), `delete_root_container`
    /// (delete only), and `has_container`; container ids are fixed at creation.
    /// The only `mov*` ops are `LoroTree::mov*` (reparent a tree NODE by TreeID)
    /// and `LoroMovableList::mov(from, to)` (reorder a list ELEMENT by index) —
    /// both intra-container element/node moves, neither re-keys a container nor
    /// transplants a text container's op-history to a new id. So a new container
    /// is unavoidable.
    ///
    /// To keep the old history LINKABLE despite that, the new entry records
    /// [`FileEntry::renamed_from`] = the old `container_id` (rename provenance).
    ///
    /// `from == to` is a no-op (returns `changed: false`), never touching disk
    /// or the store. This handles a single file only; directory renames are out
    /// of scope.
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
            return Ok(SyncOutcome::unchanged());
        }

        // Flush any pending local disk edits on `from` first, so the container
        // reflects the LATEST disk content before we copy it. A missing `from`
        // file has nothing to flush.
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
                // Rename provenance: link the new container back to the old one,
                // since Loro can't carry the edit history across (see the fn doc).
                renamed_from: Some(from_container.clone()),
                tombstoned_at: None,
            }
            .to_value(),
        )?;
        write_tombstone(store, &from_container, EntryKind::Text, hash)?;

        // Disk: write the destination FIRST (creates `to` file + sidecar,
        // byte-stable), then remove the source. Removing `from` only after `to`
        // is on disk means a failure partway never loses the content.
        self.project_file(store, to)?;
        remove_if_present(from)?;
        remove_if_present(&sidecar_path(&self.meta_dir, &from_container))?;

        Ok(SyncOutcome::changed_no_ops())
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

/// Find an existing LIVE file-set key that case-insensitively collides with
/// `incoming` but is not byte-identical to it (B2). Returns the colliding
/// existing key, or `None` when there is no case-only collision.
///
/// Only `Live` entries are considered: a tombstoned key names no live disk
/// file, so it cannot be clobbered. An unparseable entry value is skipped
/// (treated as non-colliding) rather than aborting the import. The match uses
/// `eq_ignore_ascii_case`; full Unicode case-folding is not applied.
fn live_case_collision(store: &Store, incoming: &str) -> Option<String> {
    for (key, value) in store.entries(FILESET_MAP_ID) {
        if key == incoming {
            continue; // byte-identical: the same file, never a collision.
        }
        if !key.eq_ignore_ascii_case(incoming) {
            continue;
        }
        if let Ok(entry) = FileEntry::from_value(&value) {
            if entry.status == EntryStatus::Live {
                return Some(key);
            }
        }
    }
    None
}

/// Write a tombstone for `key` with an embedded, causally-sound GC checkpoint
/// ([`FileEntry::tombstoned_at`]).
///
/// The checkpoint MUST causally include the tombstone op itself — otherwise a
/// peer that has seen everything BEFORE the delete (but not the delete) would
/// pass the GC predicate while still holding a stale `Live` entry, and could
/// resurrect the file. Since loro's public API cannot hand us the `(peer,
/// counter)` op id of a map write, we achieve this with a two-op write:
///
///   1. Write the tombstone WITHOUT a checkpoint. This is the causal event.
///   2. Read the document version — which now INCLUDES op 1 — and re-write the
///      tombstone embedding it as the checkpoint.
///
/// A peer that only has op 1 already reads `Tombstoned` (op 2 merely enriches
/// the value with the checkpoint), so the two-op split never opens a
/// resurrection window. A peer whose acked version dominates the recorded
/// checkpoint has provably observed op 1 — the tombstone.
fn write_tombstone(
    store: &mut Store,
    key: &str,
    kind: EntryKind,
    content_hash: String,
) -> Result<(), FilesError> {
    // Op 1 — the tombstone itself (no checkpoint yet).
    store.set_entry(
        FILESET_MAP_ID,
        key,
        &FileEntry {
            kind,
            status: EntryStatus::Tombstoned,
            content_hash: content_hash.clone(),
            renamed_from: None,
            tombstoned_at: None,
        }
        .to_value(),
    )?;
    // The committed doc version now causally includes op 1.
    let checkpoint = hex_encode(&store.doc_version_bytes());
    // Op 2 — re-write embedding the checkpoint (peers with only op 1 already see
    // Tombstoned; this just adds the GC checkpoint).
    store.set_entry(
        FILESET_MAP_ID,
        key,
        &FileEntry {
            kind,
            status: EntryStatus::Tombstoned,
            content_hash,
            renamed_from: None,
            tombstoned_at: Some(checkpoint),
        }
        .to_value(),
    )?;
    Ok(())
}

/// Lowercase-hex encode arbitrary bytes (for embedding version-vector bytes in
/// the JSON [`FileEntry::tombstoned_at`] string). Inverse of [`hex_decode`].
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Decode a lowercase-hex string produced by [`hex_encode`]. Returns `None` on
/// odd length or a non-hex digit (so a corrupt checkpoint is treated as "no
/// checkpoint" — conservatively non-GC-eligible).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The device-local PRESENCE MARKER path for a blob, keyed by `container_id`
/// under `meta_dir`: `<meta_dir>/blobmarkers/<container_id>.roamblob`
/// (`notes/pic.png` → `<meta_dir>/blobmarkers/notes/pic.png.roamblob`). Lives
/// OUTSIDE the user's vault folder, mirroring the container-id path so nested
/// blobs never collide.
///
/// A blob carries NO content sidecar (it is content-addressed; reproject
/// change-detection is by hash — see [`FolderBridge::project_blob`]). This marker
/// is NOT a content baseline: only its EXISTENCE matters. It is the blob analogue
/// of the text sidecar's "this device once had the file here" signal, and it is
/// the ONLY thing that lets [`FolderBridge::scan_gc`] tell a genuinely
/// locally-deleted blob (file gone, marker present → tombstone) apart from a
/// remote-new blob-ref whose bytes just transferred but was never projected
/// (file absent, NO marker → project, do not tombstone). Without it those two
/// states are byte-for-byte identical in the store, and a fetched-but-unprojected
/// remote blob would be spuriously tombstoned — propagating a delete that wipes
/// the file from the peer that authored it. The marker is device-local (never
/// gossiped) and holds no bytes.
fn blob_marker_path(meta_dir: &Path, container_id: &str) -> PathBuf {
    let mut path = meta_dir.join("blobmarkers");
    for component in container_id.split('/') {
        path.push(component);
    }
    let mut name = path.into_os_string();
    name.push(".roamblob");
    PathBuf::from(name)
}

/// Write (touch) the blob presence marker for `container_id` under `meta_dir`.
/// Creates the nested parent dir if missing. Idempotent: an existing marker is
/// simply rewritten empty. Records only presence, never content.
fn write_blob_marker(meta_dir: &Path, container_id: &str) -> Result<(), FilesError> {
    let path = blob_marker_path(meta_dir, container_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, [])?;
    Ok(())
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

/// Recursively collect importable files under `dir` into `out`. Every regular
/// file is collected regardless of extension (or lack of one) — `import_file`
/// classifies each by CONTENT (UTF-8 → text, otherwise blob). Only an explicit
/// exclusion set is skipped (see [`is_excluded_from_walk`]): hidden files and
/// hidden directories (a leading-dot component anywhere), our own `.roammeta`
/// sidecars and `.roamblob` markers, and symlinks. A missing directory yields
/// no files rather than an error.
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
        // A hidden entry is skipped whether it is a file or a directory. Skipping
        // a hidden DIR here also prevents descent, so a leading-dot component
        // anywhere in the tree (`.git/`, `.obsidian/`, `.foo.md.swp`) excludes
        // everything beneath it.
        if is_hidden(&path) {
            continue;
        }
        if file_type.is_dir() {
            collect_vault_files(&path, out)?;
        } else if !is_internal_sidecar(&path) {
            // Any regular file (any extension, or none) is imported; content
            // decides text-vs-blob inside `import_file`. Only our own metadata
            // files (`.roammeta` / `.roamblob`) are excluded.
            out.push(path);
        }
    }
    Ok(())
}

/// Whether `path`'s final component begins with a dot: a hidden file
/// (`.DS_Store`, an editor `.foo.md.swp`) or a hidden directory (`.git`,
/// `.obsidian`). Used by the folder walk to skip such entries and to avoid
/// descending into hidden directories.
fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .map(|name| name.to_string_lossy().starts_with('.'))
        .unwrap_or(false)
}

/// Whether `path` is one of our own internal metadata files that must never be
/// imported as vault content: a `.roammeta` text sidecar or a `.roamblob`
/// presence marker (both are named by appending the suffix to a real file's
/// name, so they do NOT begin with a dot and need this explicit check).
fn is_internal_sidecar(path: &Path) -> bool {
    path.file_name()
        .map(|name| {
            let name = name.to_string_lossy();
            name.ends_with(".roammeta") || name.ends_with(".roamblob")
        })
        .unwrap_or(false)
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
    meta_dir: &Path,
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
        .store(meta_dir, container)?;
        // Conflicts (if any) are attached by the caller (`import_file`); this
        // helper only knows ops/changed, so it leaves the list empty.
        return Ok(SyncOutcome {
            ops_applied,
            changed: true,
            conflicts: Vec::new(),
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
    .store(meta_dir, container)?;

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

    /// A fully-checkpointed tombstone entry (so only the trusted-peer predicate,
    /// not a missing checkpoint, decides stability).
    fn checkpointed_tombstone() -> FileEntry {
        FileEntry {
            kind: EntryKind::Text,
            status: EntryStatus::Tombstoned,
            content_hash: "abc123".to_string(),
            renamed_from: None,
            // Any well-formed hex checkpoint; the empty-set guard fires before it
            // is ever decoded, so its exact value is irrelevant here.
            tombstoned_at: Some("00ff".to_string()),
        }
    }

    #[test]
    fn empty_trusted_set_is_never_stable_even_when_checkpointed() {
        // Defense-in-depth: an empty/incomplete roster snapshot must NOT vacuously
        // GC every checkpointed tombstone (which would let an Active-but-offline
        // peer resurrect the file). Empty trusted set → never eligible.
        let gc = GcContext {
            self_peer: 1,
            trusted_peers: Vec::new(),
            acked_versions: HashMap::new(),
        };
        assert!(
            !gc.tombstone_is_stable(&checkpointed_tombstone()),
            "an empty trusted-peer set must never make a tombstone GC-eligible"
        );
    }

    #[test]
    fn self_only_trusted_set_is_stable_when_checkpointed() {
        // The real single-device case: the roster contains only `self`. With no
        // OTHER holder, a checkpointed tombstone IS stable (self always counts).
        let gc = GcContext {
            self_peer: 1,
            trusted_peers: vec![1],
            acked_versions: HashMap::new(),
        };
        assert!(
            gc.tombstone_is_stable(&checkpointed_tombstone()),
            "a self-only trusted set must allow GC of a checkpointed tombstone"
        );
    }

    /// Build a bridge over a `vault/` subdir plus a separately-opened store
    /// rooted at a `store/` subdir of one tempdir. The bridge is stateless; the
    /// caller owns the returned `Store` and threads it into each operation.
    fn bridge(root: &Path) -> (FolderBridge, Store) {
        let vault = root.join("vault");
        let store_root = root.join("store");
        std::fs::create_dir_all(&vault).unwrap();
        let bridge = FolderBridge::new(&vault, &tmeta(root));
        let store = Store::open(&store_root, Identity::generate()).unwrap();
        (bridge, store)
    }

    /// The metadata dir a `bridge(root)` is built with (mirrors the CLI's
    /// `<vault>/filemeta`, but rooted at the test's `root`, OUTSIDE the vault).
    fn tmeta(root: &Path) -> PathBuf {
        root.join("filemeta")
    }

    /// Load the sidecar for `file` (under `root`'s vault) from `root`'s meta dir.
    fn tload_sidecar(root: &Path, file: &Path) -> Option<Sidecar> {
        let container = container_id(&root.join("vault"), file).unwrap();
        Sidecar::load(&tmeta(root), &container).unwrap()
    }

    /// The sidecar path for `file` (under `root`'s vault) in `root`'s meta dir.
    fn tsidecar_path(root: &Path, file: &Path) -> PathBuf {
        let container = container_id(&root.join("vault"), file).unwrap();
        sidecar_path(&tmeta(root), &container)
    }

    #[test]
    fn new_file_import_seeds_container_and_sidecar() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        // A NESTED note, to also prove the sidecar's parent dirs are created.
        let file = dir.path().join("vault").join("notes").join("foo.md");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "hello\n").unwrap();

        let outcome = b.import_file(&mut store, &file).unwrap();
        assert!(outcome.ops_applied > 0);
        assert!(outcome.changed);

        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(store.text(&container), "hello\n");

        let sidecar = tload_sidecar(dir.path(), &file).unwrap();
        assert_eq!(sidecar.last_synced_text, "hello\n");
        assert_eq!(sidecar.last_synced_hash, text_hash("hello\n"));
        assert_eq!(sidecar.doc_id, container);

        // The sidecar must NOT pollute the user's vault folder...
        let mut beside = file.clone().into_os_string();
        beside.push(".roammeta");
        assert!(
            !PathBuf::from(beside).exists(),
            "no .roammeta may sit beside the user's note"
        );
        // ...and MUST live under the store-owned meta dir, mirroring the id path.
        assert!(tmeta(dir.path())
            .join("sidecars/notes/foo.md.roammeta")
            .exists());
    }

    #[test]
    fn second_import_with_no_change_is_a_no_op() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("note.md");
        std::fs::write(&file, "hello\n").unwrap();

        b.import_file(&mut store, &file).unwrap();
        let sidecar_before = tload_sidecar(dir.path(), &file).unwrap();

        let outcome = b.import_file(&mut store, &file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(!outcome.changed);

        let sidecar_after = tload_sidecar(dir.path(), &file).unwrap();
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
        std::fs::remove_file(tsidecar_path(dir.path(), &file)).unwrap();

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

        std::fs::remove_file(tsidecar_path(dir.path(), &file)).unwrap();
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
        let sidecar = tload_sidecar(dir.path(), &file).unwrap();
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
        let sidecar = tload_sidecar(dir.path(), &file).unwrap();
        assert_eq!(sidecar.last_synced_text, "hello world END\n");

        // Project the merged store text to disk: now disk == store == baseline.
        let projected = b.project_file(&mut store, &file).unwrap();
        assert!(projected.changed);
        assert_eq!(std::fs::read(&file).unwrap(), b"XYZ hello world END\n");
        let sidecar = tload_sidecar(dir.path(), &file).unwrap();
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
        let sidecar = tload_sidecar(dir.path(), &file).unwrap();
        assert_eq!(sidecar.last_synced_text, "hello world END\n");
        assert_ne!(sidecar.last_synced_text, store.text(&container));

        // Dirty-check still works: disk == baseline, so projection is allowed
        // (not treated as dirty) and advances the baseline to the store text.
        b.project_file(&mut store, &file).unwrap();
        let sidecar = tload_sidecar(dir.path(), &file).unwrap();
        assert_eq!(sidecar.last_synced_text, store.text(&container));
        assert_eq!(sidecar.last_synced_text, "XYZ hello world END\n");
    }

    #[test]
    fn case_only_collision_is_rejected() {
        // B2: import `a.md`, then a DISTINCT `A.md`. On a case-insensitive FS
        // both are the same disk file, so the second must be refused rather than
        // silently clobbering the first at the CRDT-key level.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let lower = vault.join("a.md");
        let upper = vault.join("A.md");
        std::fs::write(&lower, "lower\n").unwrap();
        std::fs::write(&upper, "UPPER\n").unwrap();

        b.import_file(&mut store, &lower).unwrap();

        let result = b.import_file(&mut store, &upper);
        assert!(matches!(
            result,
            Err(FilesError::CaseCollision { existing, incoming })
                if existing == "a.md" && incoming == "A.md"
        ));
    }

    #[test]
    fn byte_identical_reimport_is_not_a_collision() {
        // Re-importing the SAME key (byte-identical) must not be flagged as a
        // case collision — it is just an idempotent re-import.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("a.md");
        std::fs::write(&file, "hello\n").unwrap();

        b.import_file(&mut store, &file).unwrap();
        // Second import of the identical key: fine (no-op, no collision).
        let outcome = b.import_file(&mut store, &file).unwrap();
        assert_eq!(outcome.ops_applied, 0);
        assert!(!outcome.changed);
    }

    #[test]
    fn non_utf8_file_is_a_blob() {
        // Classification is by CONTENT, not extension: a non-UTF-8 file is ALWAYS
        // a whole-file blob now (no char-merge), regardless of its extension.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("binary.md");
        std::fs::write(&file, [0xff, 0xfe]).unwrap();

        let outcome = b.import_file(&mut store, &file).unwrap();
        assert!(outcome.changed);
        let container = container_id(&vault, &file).unwrap();
        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.kind, EntryKind::Blob);
        assert_eq!(entry.status, EntryStatus::Live);
    }

    #[test]
    fn reconcile_heals_sidecar_to_actual_on_desync() {
        // Fabricate a mismatch: the store actually holds "partial" but the file
        // wanted "hello world". The sidecar must record the ACTUAL store text so
        // the next import diffs "partial" -> "hello world" (the remaining delta),
        // never re-applying the stale baseline diff.
        let dir = tempdir().unwrap();
        let meta = dir.path();

        // expected == file_text here (a non-rebase desync): the store diverged
        // from what we intended, so it heals to the actual "partial".
        let result = reconcile_sidecar(
            meta,
            "note.md",
            "hello world",
            "hello world",
            "partial",
            1,
            None,
        );
        assert!(matches!(result, Err(FilesError::Desync(_))));

        let sidecar = Sidecar::load(meta, "note.md").unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "partial");
        assert_eq!(sidecar.last_synced_hash, text_hash("partial"));
    }

    #[test]
    fn reconcile_heals_sidecar_then_propagates_apply_error() {
        let dir = tempdir().unwrap();
        let meta = dir.path();

        // A simulated storage failure captured mid-sequence must still heal the
        // sidecar to the store's actual state before propagating.
        let err = FilesError::Sidecar("simulated storage failure".into());
        let result = reconcile_sidecar(
            meta,
            "note.md",
            "hello world",
            "hello world",
            "partial",
            1,
            Some(err),
        );
        assert!(result.is_err());

        let sidecar = Sidecar::load(meta, "note.md").unwrap().unwrap();
        assert_eq!(sidecar.last_synced_text, "partial");
    }

    #[test]
    fn reconcile_success_records_file_text_and_reports_change() {
        let dir = tempdir().unwrap();
        let meta = dir.path();

        let outcome = reconcile_sidecar(meta, "note.md", "same", "same", "same", 2, None).unwrap();
        assert_eq!(
            outcome,
            SyncOutcome {
                ops_applied: 2,
                changed: true,
                conflicts: Vec::new(),
            }
        );
        assert_eq!(
            Sidecar::load(meta, "note.md").unwrap().unwrap().last_synced_text,
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
    fn scan_hinted_imports_only_hinted_paths() {
        // A3: two files change on disk, but the hint names only `a.md`. The
        // hinted scan must import `a.md` and NOT import `b.md`'s change that call.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let a = vault.join("a.md");
        let bfile = vault.join("b.md");
        std::fs::write(&a, "a0\n").unwrap();
        std::fs::write(&bfile, "b0\n").unwrap();
        b.scan(&mut store).unwrap();

        let ca = container_id(&vault, &a).unwrap();
        let cb = container_id(&vault, &bfile).unwrap();
        assert_eq!(store.text(&ca), "a0\n");
        assert_eq!(store.text(&cb), "b0\n");

        // Both change on disk; hint only a.md.
        std::fs::write(&a, "a1\n").unwrap();
        std::fs::write(&bfile, "b1\n").unwrap();
        let hint: HashSet<PathBuf> = [a.clone()].into_iter().collect();
        b.scan_hinted(&mut store, Some(&hint)).unwrap();

        // a.md's change imported; b.md's change NOT imported this call.
        assert_eq!(store.text(&ca), "a1\n");
        assert_eq!(store.text(&cb), "b0\n");
    }

    #[test]
    fn scan_hinted_none_matches_scan_and_is_idempotent() {
        // A3: `scan_hinted(None)` behaves identically to `scan`, and re-running
        // it makes no further mutation (idempotence preserved).
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let a = vault.join("a.md");
        let bfile = vault.join("nested").join("b.org");
        std::fs::create_dir_all(vault.join("nested")).unwrap();
        std::fs::write(&a, "a0\n").unwrap();
        std::fs::write(&bfile, "b0\n").unwrap();

        let first = b.scan_hinted(&mut store, None).unwrap();
        assert!(first.iter().any(|(_, o)| o.changed));

        let ca = container_id(&vault, &a).unwrap();
        let cb = container_id(&vault, &bfile).unwrap();
        assert_eq!(store.text(&ca), "a0\n");
        assert_eq!(store.text(&cb), "b0\n");

        // Second full scan with no external change: a no-op reconcile.
        let second = b.scan_hinted(&mut store, None).unwrap();
        assert!(second.iter().all(|(_, o)| !o.changed));
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
    fn txt_utf8_imports_as_text_and_round_trips() {
        // A `.txt` (previously outside the allowlist) with UTF-8 content is now
        // classified as TEXT by content and round-trips byte-for-byte.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let file = dir.path().join("vault").join("plain.txt");
        let original = "just some text\nwith a second line";
        std::fs::write(&file, original).unwrap();
        let original_bytes = std::fs::read(&file).unwrap();

        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&dir.path().join("vault"), &file).unwrap();
        assert_eq!(fileset_entry(&store, &container).unwrap().kind, EntryKind::Text);

        std::fs::remove_file(&file).unwrap();
        b.project_file(&mut store, &file).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), original_bytes);
    }

    #[test]
    fn no_extension_utf8_imports_as_text() {
        // A file with NO extension and UTF-8 content classifies as TEXT.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("README");
        std::fs::write(&file, "readme body\n").unwrap();

        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();
        assert_eq!(fileset_entry(&store, &container).unwrap().kind, EntryKind::Text);
        assert_eq!(store.text(&container), "readme body\n");
    }

    #[test]
    fn utf16_file_imports_as_blob() {
        // UTF-16 bytes (interior NUL, invalid UTF-8) are not char-mergeable text:
        // they classify as a whole-file BLOB. Nothing is transcoded.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.txt");
        // UTF-16LE with a BOM (0xff 0xfe) then "é" (0xe9 0x00): interior NUL and a
        // lone 0xff/0xfe make this invalid UTF-8, so it must classify as a blob.
        let bytes = [0xffu8, 0xfe, 0xe9, 0x00];
        std::fs::write(&file, bytes).unwrap();

        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();
        assert_eq!(fileset_entry(&store, &container).unwrap().kind, EntryKind::Blob);
    }

    #[test]
    fn walk_skips_dotfiles_and_dot_dirs() {
        // The folder walk imports files of any extension but must skip anything
        // hidden: a leading-dot file, and everything inside a dot-directory
        // (`.git`, `.obsidian`, editor `.swp` files, ...).
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let visible = vault.join("visible.md");
        std::fs::write(&visible, "keep me\n").unwrap();
        // A dotfile beside it.
        std::fs::write(vault.join(".hidden.md"), "skip me\n").unwrap();
        // A `.md` buried inside a dot-directory — must not be descended into.
        let git = vault.join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(git.join("config.md"), "not a note\n").unwrap();

        let outcomes = b.scan(&mut store).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].0, visible);
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
    fn scan_imports_any_extension_but_skips_sidecars() {
        // Content-based classification: files of ANY extension (`.md`, `.org`,
        // `.txt`, ...) are imported. Only our own `.roammeta` sidecar is skipped.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let one = vault.join("one.md");
        let two = vault.join("nested").join("two.org");
        let three = vault.join("plain.txt");
        std::fs::create_dir_all(vault.join("nested")).unwrap();
        std::fs::write(&one, "one body").unwrap();
        std::fs::write(&two, "two body").unwrap();
        std::fs::write(&three, "three body").unwrap();
        // A STALE leftover metadata file sitting IN the user folder (e.g. from an
        // old version that wrote sidecars/markers beside notes). The walk must
        // still defensively exclude `.roammeta`/`.roamblob` so it is never
        // imported as a note.
        std::fs::write(vault.join("one.md.roammeta"), "stale").unwrap();
        std::fs::write(vault.join("one.md.roamblob"), []).unwrap();

        let outcomes = b.scan(&mut store).unwrap();
        assert_eq!(outcomes.len(), 3);
        for (path, outcome) in &outcomes {
            assert!(outcome.changed);
            assert!(path == &one || path == &two || path == &three);
            let container = container_id(&vault, path).unwrap();
            let expected = std::fs::read_to_string(path).unwrap();
            assert_eq!(store.text(&container), expected);
        }
    }

    #[test]
    fn scan_imports_non_utf8_md_as_blob() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let good = vault.join("good.md");
        let bad = vault.join("bad.md");
        std::fs::write(&good, "good").unwrap();
        std::fs::write(&bad, [0xff, 0xff]).unwrap();

        // Both files import: the UTF-8 one as text, the non-UTF-8 one as a blob.
        let outcomes = b.scan(&mut store).unwrap();
        assert_eq!(outcomes.len(), 2);

        let good_c = container_id(&vault, &good).unwrap();
        assert_eq!(store.text(&good_c), "good");
        assert_eq!(fileset_entry(&store, &good_c).unwrap().kind, EntryKind::Text);

        let bad_c = container_id(&vault, &bad).unwrap();
        assert_eq!(fileset_entry(&store, &bad_c).unwrap().kind, EntryKind::Blob);

        // The blob's presence marker must NOT sit beside the user's file...
        let mut beside = bad.clone().into_os_string();
        beside.push(".roamblob");
        assert!(
            !PathBuf::from(beside).exists(),
            "no .roamblob may sit beside the user's blob file"
        );
        // ...and MUST live under the store-owned meta dir's blobmarkers tree.
        assert!(tmeta(dir.path())
            .join("blobmarkers/bad.md.roamblob")
            .exists());
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
                renamed_from: None,
                tombstoned_at: None,
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
    fn non_utf8_md_writes_live_blob_entry() {
        // Content-based classification: a non-UTF-8 `.md` is a blob, so import
        // writes a Live Blob file-set entry (it no longer errors out).
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("binary.md");
        std::fs::write(&file, [0xff, 0xfe]).unwrap();

        b.import_file(&mut store, &file).unwrap();

        let container = container_id(&vault, &file).unwrap();
        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.kind, EntryKind::Blob);
        assert_eq!(entry.status, EntryStatus::Live);
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
        assert!(!tsidecar_path(dir.path(), &file).exists());

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
        std::fs::remove_file(tsidecar_path(dir.path(), &file)).unwrap();

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
            renamed_from: None,
            tombstoned_at: None,
        }
        .to_value()
    }

    fn tombstoned(hash: String) -> String {
        FileEntry {
            kind: EntryKind::Text,
            status: EntryStatus::Tombstoned,
            content_hash: hash,
            renamed_from: None,
            tombstoned_at: None,
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
        assert!(tsidecar_path(dir.path(), &file).exists());

        b.scan(&mut store).unwrap();

        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.status, EntryStatus::Tombstoned);
        assert_eq!(entry.content_hash, text_hash("hello\n"));
        // The stale sidecar is dropped so a later remote re-create reads as new.
        assert!(!tsidecar_path(dir.path(), &file).exists());

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
        assert!(!tsidecar_path(dir.path(), &file).exists());

        b.scan(&mut store).unwrap();

        // The file is created on disk with the remote content and a sidecar.
        assert_eq!(std::fs::read(&file).unwrap(), b"remote\n");
        assert!(tsidecar_path(dir.path(), &file).exists());
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
        let sidecar = tload_sidecar(dir.path(), &file).unwrap();
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
        let sidecar = tload_sidecar(dir.path(), &file).unwrap();
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
        assert!(!tsidecar_path(dir.path(), &file).exists());
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
        .store(&tmeta(dir.path()), "y.md")
        .unwrap();
        assert!(tsidecar_path(dir.path(), &file).exists());
        assert!(!file.exists());
        store
            .set_entry(FILESET_MAP_ID, "y.md", &tombstoned(text_hash("old\n")))
            .unwrap();

        b.scan(&mut store).unwrap();
        // The orphan sidecar is cleaned.
        assert!(!tsidecar_path(dir.path(), &file).exists());

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
        .store(&tmeta(dir.path()), "m.md")
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
    fn resurrection_guard_hash_collision_drops_a_revert_to_synced_edit() {
        // EDGE (pinned): the resurrection guard is content-hash based. If a
        // concurrent edit REVERTS the container to EXACTLY the last-synced text,
        // the container's current hash equals the tombstone hash, so DELETE WINS
        // and that revert edit is dropped (the file is removed). This is
        // acceptable because the dropped edit reproduced already-synced content
        // byte-for-byte — no UNIQUE content is lost. This test pins the current
        // behavior so any future change to the guard is caught.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");

        // Import "hello\n": container seeded, Live entry, sidecar records it.
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();
        let synced_hash = text_hash("hello\n");

        // A remote tombstone arrives recording the LAST-SYNCED hash (the content
        // this device last synced — "hello\n").
        store
            .set_entry(FILESET_MAP_ID, &container, &tombstoned(synced_hash.clone()))
            .unwrap();

        // A concurrent edit merges into the container AFTER the tombstone but
        // happens to REVERT to exactly the last-synced text: insert "X" then
        // delete it, leaving "hello\n". The container hash collides with the
        // tombstone hash.
        store.edit_text(&container, 5, "X").unwrap();
        store.delete_text(&container, 5, 1).unwrap();
        assert_eq!(store.text(&container), "hello\n");
        assert_eq!(text_hash(&store.text(&container)), synced_hash);

        b.scan(&mut store).unwrap();

        // Delete wins: the guard sees current_hash == tombstone hash, so the file
        // and its sidecar are removed and the entry stays Tombstoned.
        assert!(
            !file.exists(),
            "delete wins: the hash-collision revert edit is dropped"
        );
        assert!(
            !tsidecar_path(dir.path(), &file).exists(),
            "sidecar removed alongside the file"
        );
        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.status, EntryStatus::Tombstoned);
        // The container is intentionally left intact (history/resurrection); only
        // the file-set entry + disk file reflect the delete. No unique content is
        // lost — the dropped edit was byte-identical to the already-synced text.
        assert_eq!(store.text(&container), "hello\n");
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
        assert!(tsidecar_path(dir.path(), &new).exists());

        // The old file and its sidecar are gone.
        assert!(!old.exists());
        assert!(!tsidecar_path(dir.path(), &old).exists());

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
        assert!(tsidecar_path(dir.path(), &file).exists());
        assert_eq!(store.text(&container), "content\n");
        assert_eq!(
            fileset_entry(&store, &container).unwrap().status,
            EntryStatus::Live
        );
    }

    #[test]
    fn rename_records_provenance_on_new_entry() {
        // E2: after a rename, the NEW entry links back to the OLD container id
        // via `renamed_from`, so the (unpreservable) history stays discoverable.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let old = vault.join("old.md");
        let new = vault.join("new.md");
        std::fs::write(&old, "content\n").unwrap();
        b.import_file(&mut store, &old).unwrap();
        let old_container = container_id(&vault, &old).unwrap();
        let new_container = container_id(&vault, &new).unwrap();

        b.rename_file(&mut store, &old, &new).unwrap();

        let new_entry = fileset_entry(&store, &new_container).unwrap();
        assert_eq!(new_entry.renamed_from, Some(old_container.clone()));
        // Sanity: the container id is the vault-relative key.
        assert_eq!(new_entry.renamed_from, Some("old.md".to_string()));
        // The tombstoned old entry carries no provenance of its own.
        let old_entry = fileset_entry(&store, &old_container).unwrap();
        assert_eq!(old_entry.renamed_from, None);
    }

    #[test]
    fn normal_import_writes_no_rename_provenance() {
        // E2: a plain import (not a rename) records `renamed_from: None`.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello\n").unwrap();
        b.import_file(&mut store, &file).unwrap();

        let container = container_id(&vault, &file).unwrap();
        assert_eq!(fileset_entry(&store, &container).unwrap().renamed_from, None);
    }

    #[test]
    fn import_surfaces_overlapping_concurrent_edit_conflict() {
        // E3: a remote edit merged into the container AND a local disk edit both
        // change the SAME region → the merge still converges (both edits kept)
        // AND the import outcome carries a conflict describing the overlap.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "abc\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remote replaces "b" with "Z" (container: "aZc\n").
        store.delete_text(&container, 1, 1).unwrap();
        store.edit_text(&container, 1, "Z").unwrap();
        assert_eq!(store.text(&container), "aZc\n");

        // Local (on disk) replaces "b" with "Y": overlapping the SAME "b".
        std::fs::write(&file, "aYc\n").unwrap();
        let outcome = b.import_file(&mut store, &file).unwrap();

        assert!(outcome.changed);
        assert!(
            !outcome.conflicts.is_empty(),
            "overlapping concurrent edits must surface a conflict: {outcome:?}"
        );
        // Merge output unchanged by the conflict signal: both sides survive.
        assert_eq!(store.text(&container), "aZYc\n");
    }

    #[test]
    fn import_does_not_flag_non_overlapping_concurrent_edits() {
        // E3: remote changes the START, local changes the END — disjoint
        // regions. Both merge in and NO conflict is reported.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("note.md");
        std::fs::write(&file, "hello world\n").unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();

        // Remote inserts a prefix (touches the start region only).
        store.edit_text(&container, 0, "XYZ ").unwrap();
        assert_eq!(store.text(&container), "XYZ hello world\n");

        // Local appends a suffix (touches the end region only).
        std::fs::write(&file, "hello world END\n").unwrap();
        let outcome = b.import_file(&mut store, &file).unwrap();

        assert!(outcome.changed);
        assert!(
            outcome.conflicts.is_empty(),
            "disjoint concurrent edits must NOT be flagged: {outcome:?}"
        );
        assert_eq!(store.text(&container), "XYZ hello world END\n");
    }

    // --- D3: binary files route to the blob store (EntryKind::Blob). ---

    #[test]
    fn import_binary_file_stores_blob_and_writes_blob_entry() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("image.png");
        let payload: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0xff, 0x00, 0xfe];
        std::fs::write(&file, &payload).unwrap();

        let outcome = b.import_file(&mut store, &file).unwrap();
        assert!(outcome.changed);
        assert_eq!(outcome.ops_applied, 0, "a blob applies no CRDT text ops");

        let container = container_id(&vault, &file).unwrap();
        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.kind, EntryKind::Blob);
        assert_eq!(entry.status, EntryStatus::Live);
        // content_hash doubles as the blob-ref: the blake3 of the file's bytes.
        assert_eq!(
            entry.content_hash,
            roam_storage::BlobStore::hash(&payload)
        );
        // The bytes are in the blob store, keyed by that hash.
        assert!(store.blobs().has(&entry.content_hash));
        assert_eq!(store.blobs().get(&entry.content_hash).unwrap(), Some(payload));
        // No text container was created for the blob.
        assert_eq!(store.text(&container), "");
    }

    #[test]
    fn reimport_unchanged_binary_is_idempotent() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("data.bin");
        std::fs::write(&file, [0x00, 0xff, 0x01]).unwrap();
        b.import_file(&mut store, &file).unwrap();

        let log_before = store.export_own_log().unwrap().len();
        let outcome = b.import_file(&mut store, &file).unwrap();
        assert!(!outcome.changed, "unchanged binary re-import must be a no-op");
        assert_eq!(
            store.export_own_log().unwrap().len(),
            log_before,
            "an idempotent blob re-import must append no new op"
        );
    }

    #[test]
    fn changed_binary_updates_entry_hash_and_stores_new_blob() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("data.bin");
        std::fs::write(&file, [0x00, 0xff]).unwrap();
        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();
        let first = fileset_entry(&store, &container).unwrap().content_hash;

        let new_bytes = vec![0xfe, 0x00, 0x7f];
        std::fs::write(&file, &new_bytes).unwrap();
        let outcome = b.import_file(&mut store, &file).unwrap();
        assert!(outcome.changed);

        let second = fileset_entry(&store, &container).unwrap().content_hash;
        assert_ne!(first, second, "a changed blob must update the entry hash");
        assert_eq!(second, roam_storage::BlobStore::hash(&new_bytes));
        // Both blobs are stored (the old one is orphaned, GC'd in a later slice).
        assert!(store.blobs().has(&first));
        assert!(store.blobs().has(&second));
    }

    #[test]
    fn binary_md_becomes_a_blob() {
        // A `.md`/`.org` file that fails UTF-8 is now classified by CONTENT: it
        // becomes a whole-file blob, not a text note. Extension is irrelevant.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("corrupt.md");
        let bytes = [0xff, 0xfe];
        std::fs::write(&file, bytes).unwrap();

        b.import_file(&mut store, &file).unwrap();
        let container = container_id(&vault, &file).unwrap();
        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.kind, EntryKind::Blob);
        assert_eq!(entry.content_hash, roam_storage::BlobStore::hash(&bytes));
    }

    #[test]
    fn deleting_a_binary_file_locally_tombstones_the_blob_entry() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("pic.png");
        std::fs::write(&file, [0x89, 0xff, 0x00]).unwrap();

        // A full scan discovers + imports the blob (Live Blob entry).
        b.scan(&mut store).unwrap();
        let container = container_id(&vault, &file).unwrap();
        assert_eq!(fileset_entry(&store, &container).unwrap().status, EntryStatus::Live);

        // Delete the file on disk, then scan: blob-aware local-delete detection
        // (bytes still in the blob store = this device once had it, file now
        // absent) must tombstone the entry even though a blob has NO sidecar.
        std::fs::remove_file(&file).unwrap();
        b.scan(&mut store).unwrap();
        assert_eq!(
            fileset_entry(&store, &container).unwrap().status,
            EntryStatus::Tombstoned
        );
    }

    #[test]
    fn scan_reconciles_text_and_binary_together() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let note = vault.join("note.md");
        let pic = vault.join("pic.png");
        std::fs::write(&note, "hello\n").unwrap();
        std::fs::write(&pic, [0xff, 0x00, 0x10]).unwrap();

        b.scan(&mut store).unwrap();

        let note_c = container_id(&vault, &note).unwrap();
        let pic_c = container_id(&vault, &pic).unwrap();
        let note_entry = fileset_entry(&store, &note_c).unwrap();
        let pic_entry = fileset_entry(&store, &pic_c).unwrap();
        assert_eq!(note_entry.kind, EntryKind::Text);
        assert_eq!(note_entry.status, EntryStatus::Live);
        assert_eq!(pic_entry.kind, EntryKind::Blob);
        assert_eq!(pic_entry.status, EntryStatus::Live);
        assert_eq!(store.text(&note_c), "hello\n");
        assert!(store.blobs().has(&pic_entry.content_hash));

        // Idempotent: a second scan with no change makes no further mutation and
        // leaves BOTH entries Live (the blob is not falsely tombstoned).
        b.scan(&mut store).unwrap();
        assert_eq!(fileset_entry(&store, &note_c).unwrap().status, EntryStatus::Live);
        assert_eq!(fileset_entry(&store, &pic_c).unwrap().status, EntryStatus::Live);
    }

    #[test]
    fn remote_new_blob_without_bytes_is_skipped_gracefully() {
        // Simulate a Blob entry that arrived from a peer (its hash-ref rode the
        // op-log) whose BYTES have not yet transferred (a later slice). scan must
        // NOT crash, NOT tombstone it (bytes absent = never had it locally), and
        // NOT project a corrupt/empty file to disk.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("remote.png");
        let container = container_id(&vault, &file).unwrap();

        // A well-formed blob-ref whose bytes are NOT in the local blob store.
        let phantom = roam_storage::BlobStore::hash(&[0x01, 0x02, 0x03, 0xff]);
        assert!(!store.blobs().has(&phantom));
        store
            .set_entry(
                FILESET_MAP_ID,
                &container,
                &FileEntry {
                    kind: EntryKind::Blob,
                    status: EntryStatus::Live,
                    content_hash: phantom.clone(),
                    renamed_from: None,
                    tombstoned_at: None,
                }
                .to_value(),
            )
            .unwrap();

        // Must not panic/error.
        b.scan(&mut store).unwrap();

        // Entry stays Live (not tombstoned) and NO file was written to disk.
        let entry = fileset_entry(&store, &container).unwrap();
        assert_eq!(entry.status, EntryStatus::Live);
        assert_eq!(entry.content_hash, phantom);
        assert!(!file.exists(), "a bytes-absent blob-ref must not project a file");
    }

    // --- D5: project fetched blob bytes onto disk. ---

    /// Seed a `Live` `Blob` file-set entry for `container` referencing `hash`
    /// (simulating a ref that arrived from a peer via map sync).
    fn seed_live_blob_entry(store: &mut Store, container: &str, hash: &str) {
        store
            .set_entry(
                FILESET_MAP_ID,
                container,
                &FileEntry {
                    kind: EntryKind::Blob,
                    status: EntryStatus::Live,
                    content_hash: hash.to_string(),
                    renamed_from: None,
                    tombstoned_at: None,
                }
                .to_value(),
            )
            .unwrap();
    }

    /// A self-only GC context: the roster contains only `self`, so any
    /// checkpointed tombstone is causally stable (see
    /// `self_only_trusted_set_is_stable_when_checkpointed`).
    fn self_only_gc() -> GcContext {
        GcContext {
            self_peer: 1,
            trusted_peers: vec![1],
            acked_versions: HashMap::new(),
        }
    }

    #[test]
    fn scan_gc_no_longer_reaps_stable_tombstones() {
        let dir = tempdir().unwrap();
        let (bridge, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("gc.txt");
        std::fs::write(&file, "content").unwrap();
        bridge.import_file(&mut store, &file).unwrap();
        std::fs::remove_file(&file).unwrap();
        bridge.delete_file(&mut store, &file).unwrap();

        // Even with a self-only (trivially stable) GcContext, the entry is RETAINED.
        bridge.scan_gc(&mut store, None, Some(&self_only_gc())).unwrap();
        let entries = store.entries(FILESET_MAP_ID);
        let key = container_id(&vault, &file).unwrap();
        assert!(
            entries.iter().any(|(k, _)| *k == key),
            "tombstone entry must survive GC now that the reaper is retired"
        );
    }

    #[test]
    fn list_deleted_reports_tombstoned_files() {
        let dir = tempdir().unwrap();
        let (bridge, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("doc.txt");
        std::fs::write(&file, "hi").unwrap();
        bridge.import_file(&mut store, &file).unwrap();
        std::fs::remove_file(&file).unwrap();
        bridge.delete_file(&mut store, &file).unwrap();

        let deleted = bridge.list_deleted(&store);
        assert_eq!(deleted, vec![file.clone()]);
    }

    #[test]
    fn resurrect_flips_tombstone_to_live_and_reprojects() {
        let dir = tempdir().unwrap();
        let (bridge, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("doc.txt");
        std::fs::write(&file, "hi").unwrap();
        bridge.import_file(&mut store, &file).unwrap();
        std::fs::remove_file(&file).unwrap();
        bridge.delete_file(&mut store, &file).unwrap();

        bridge.resurrect(&mut store, &file).unwrap();

        let container = container_id(&vault, &file).unwrap();
        assert_eq!(
            fileset_entry(&store, &container).unwrap().status,
            EntryStatus::Live,
            "resurrect must flip the entry back to Live"
        );
        assert!(file.exists(), "resurrect must re-project the bytes to disk");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "hi");
    }

    #[test]
    fn resurrect_unknown_path_is_not_found() {
        let dir = tempdir().unwrap();
        let (bridge, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("never.txt");
        assert!(matches!(
            bridge.resurrect(&mut store, &file),
            Err(FilesError::NotFound(_))
        ));
    }

    #[test]
    fn remote_blob_is_projected_to_disk_once_bytes_are_local() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("photo.png");
        let container = container_id(&vault, &file).unwrap();

        // A remote-new Live Blob entry whose bytes ARE now local (fetched).
        let payload: Vec<u8> = vec![0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0x7f];
        let hash = store.blobs().put(&payload).unwrap();
        seed_live_blob_entry(&mut store, &container, &hash);
        assert!(!file.exists(), "precondition: file absent before projection");

        b.scan(&mut store).unwrap();

        assert!(file.exists(), "blob bytes must be projected to disk");
        assert_eq!(
            std::fs::read(&file).unwrap(),
            payload,
            "projected file must be byte-identical to the stored blob"
        );
    }

    #[test]
    fn present_blob_on_disk_wins_over_a_differing_ref() {
        // A blob already ON DISK is authoritative (disk-wins), the blob analogue
        // of the text dirty-file guard: a present file is NEVER overwritten by a
        // differing ref (that would silently destroy a local edit). Instead Step 1
        // reconciles the on-disk bytes INTO the entry, and projection is a no-op.
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("photo.png");
        let container = container_id(&vault, &file).unwrap();

        // Disk holds LOCAL bytes (non-UTF-8 so import routes them as a blob); the
        // entry references DIFFERENT bytes (a stale/remote ref).
        let on_disk: Vec<u8> = vec![0xff, 0x00, 0x89, 0x50];
        std::fs::write(&file, &on_disk).unwrap();
        let stale: Vec<u8> = vec![0xfe, 0xfd, 0xfc];
        let stale_hash = store.blobs().put(&stale).unwrap();
        seed_live_blob_entry(&mut store, &container, &stale_hash);

        b.scan(&mut store).unwrap();

        // Disk bytes are untouched — the local file wins.
        assert_eq!(
            std::fs::read(&file).unwrap(),
            on_disk,
            "a present blob file must never be clobbered by a differing ref"
        );
        // Step 1 reconciled the entry to the on-disk bytes (disk-wins).
        assert_eq!(
            fileset_entry(&store, &container).unwrap().content_hash,
            roam_storage::BlobStore::hash(&on_disk),
            "the entry must be updated to the on-disk blob's hash"
        );
    }

    #[test]
    fn blob_projection_is_a_noop_when_disk_already_matches() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("photo.png");
        let container = container_id(&vault, &file).unwrap();

        let payload: Vec<u8> = vec![0x10, 0x20, 0x30, 0xaa];
        let hash = store.blobs().put(&payload).unwrap();
        std::fs::write(&file, &payload).unwrap();
        seed_live_blob_entry(&mut store, &container, &hash);

        // Step 1 imports the present blob (idempotent Live), Step 3 sees disk ==
        // ref → project_blob is a no-op. No outcome should report a blob rewrite.
        let outcomes = b.scan(&mut store).unwrap();
        assert!(
            !outcomes.iter().any(|(p, o)| p == &file && o.changed),
            "an up-to-date blob must not be reprojected: {outcomes:?}"
        );
        assert_eq!(std::fs::read(&file).unwrap(), payload);
    }

    #[test]
    fn remote_blob_tombstone_removes_the_present_disk_file() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("photo.png");
        let container = container_id(&vault, &file).unwrap();

        // Establish a projected, Live blob on disk.
        let payload: Vec<u8> = vec![0x89, 0xff, 0x00, 0x42];
        let hash = store.blobs().put(&payload).unwrap();
        seed_live_blob_entry(&mut store, &container, &hash);
        b.scan(&mut store).unwrap();
        assert!(file.exists(), "precondition: blob projected to disk");

        // A remote delete arrives: the entry flips to a checkpointed Tombstoned
        // referencing the SAME bytes. Step 1 must NOT resurrect it; Step 3 must
        // remove the disk file.
        write_tombstone(&mut store, &container, EntryKind::Blob, hash.clone()).unwrap();
        b.scan(&mut store).unwrap();

        assert!(!file.exists(), "a remote blob-delete must remove the disk file");
        assert_eq!(
            fileset_entry(&store, &container).unwrap().status,
            EntryStatus::Tombstoned,
            "the entry must stay Tombstoned (not resurrected to Live)"
        );
    }

    // --- D6: reference-counting blob GC. ---

    #[test]
    fn unreferenced_blob_is_retained_by_scan_gc() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());

        // A stored blob that NO file-set entry references (an orphan).
        let hash = store.blobs().put(&[0x01, 0x02, 0x03, 0xff]).unwrap();
        assert!(store.blobs().has(&hash));

        // The reaper is retired: scan_gc no longer reclaims blobs. Reclaim now
        // happens only via `Store::checkpoint` (out of this crate's tests), so
        // the orphan blob is RETAINED here.
        b.scan_gc(&mut store, None, Some(&self_only_gc())).unwrap();
        assert!(
            store.blobs().has(&hash),
            "scan_gc no longer collects blobs; the orphan must be retained"
        );
    }

    #[test]
    fn live_referenced_blob_is_never_collected_by_gc() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("keep.png");
        let container = container_id(&vault, &file).unwrap();

        let hash = store.blobs().put(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
        seed_live_blob_entry(&mut store, &container, &hash);

        // Even with a stability context, a Live-referenced blob is retained.
        b.scan_gc(&mut store, None, Some(&self_only_gc())).unwrap();
        assert!(
            store.blobs().has(&hash),
            "a blob referenced by a Live entry must never be collected"
        );
    }

    #[test]
    fn tombstoned_blob_and_its_bytes_are_retained_by_scan_gc() {
        let dir = tempdir().unwrap();
        let (b, mut store) = bridge(dir.path());
        let vault = dir.path().join("vault");
        let file = vault.join("gc.png");
        let container = container_id(&vault, &file).unwrap();

        // Create + import a blob (Live entry + bytes stored), then locally delete
        // it so Step 2 writes a checkpointed Tombstoned entry (bytes still stored).
        std::fs::write(&file, [0x11, 0x22, 0x33, 0xff]).unwrap();
        b.scan(&mut store).unwrap();
        let hash = fileset_entry(&store, &container).unwrap().content_hash;
        std::fs::remove_file(&file).unwrap();
        b.scan(&mut store).unwrap();
        assert_eq!(
            fileset_entry(&store, &container).unwrap().status,
            EntryStatus::Tombstoned
        );
        assert!(store.blobs().has(&hash), "bytes still present while tombstoned");

        // The reaper is retired: even a self-only (trivially stable) GcContext
        // no longer drops the tombstone entry or reclaims its blob. Retention is
        // now client-driven via `Store::checkpoint` (out of this crate's tests).
        b.scan_gc(&mut store, None, Some(&self_only_gc())).unwrap();
        assert_eq!(
            fileset_entry(&store, &container).unwrap().status,
            EntryStatus::Tombstoned,
            "a stable tombstone entry must now be RETAINED (reaper retired)"
        );
        assert!(
            store.blobs().has(&hash),
            "the blob must be RETAINED; reclaim now happens only via Store::checkpoint"
        );
    }
}
