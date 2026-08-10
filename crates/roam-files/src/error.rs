use std::path::PathBuf;

/// Errors produced by the `roam-files` crate.
#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    /// An error surfaced from the underlying storage layer.
    #[error(transparent)]
    Storage(#[from] roam_storage::StorageError),

    /// An I/O error while accessing a file.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The resolved path escapes the vault root.
    #[error("path escapes vault: {0}")]
    PathEscapesVault(PathBuf),

    /// A sidecar metadata file could not be parsed or written.
    #[error("sidecar error: {0}")]
    Sidecar(String),

    /// A file-set map entry value could not be parsed or serialized.
    #[error("entry error: {0}")]
    Entry(String),

    /// No file-set map entry exists for the requested path (e.g. attempting to
    /// [`resurrect`](crate::FolderBridge::resurrect) a path that was never
    /// tracked). Holds the affected path.
    #[error("not found: {0}")]
    NotFound(PathBuf),

    /// After applying computed ops to a container, the store's text did not
    /// match the file text — a symptom of an offset/diff bug. The message
    /// includes the affected container id.
    #[error("desync: {0}")]
    Desync(String),

    /// Projecting the CRDT onto disk would overwrite a file that carries
    /// local, un-imported edits (its on-disk bytes differ from both the
    /// last-synced baseline and the store text). Refused rather than
    /// silently destroying the user's edits — the caller must import first
    /// (or otherwise resolve) before projecting. Holds the affected path.
    #[error("refusing to overwrite un-imported local edits: {0}")]
    DirtyFile(PathBuf),

    /// Two container keys differ only by letter case (e.g. `a.md` vs `A.md`).
    /// On a case-insensitive filesystem both keys map to the SAME on-disk file,
    /// so materializing the second would silently clobber the first. Refused so
    /// the collision surfaces instead of destroying data. `existing` is the live
    /// key already tracked; `incoming` is the colliding key being introduced.
    ///
    /// The comparison is ASCII-case-insensitive (`eq_ignore_ascii_case`), which
    /// covers the common `A`/`a` clobber; full Unicode case-folding is not
    /// applied (a rarer source of case-insensitive-FS collisions).
    #[error("case-only key collision: {incoming:?} collides with existing {existing:?}")]
    CaseCollision {
        /// The live key already present in the file-set map.
        existing: String,
        /// The colliding key being introduced.
        incoming: String,
    },

    /// A vault file resolved to a container id that collides with a reserved,
    /// well-known container id (e.g. the file-set map's [`FILESET_MAP_ID`]). Such
    /// a file cannot be tracked without its text container overwriting the
    /// reserved container, so it is rejected. Holds the offending key.
    ///
    /// [`FILESET_MAP_ID`]: crate::FILESET_MAP_ID
    #[error("reserved container id cannot be used as a vault file: {0}")]
    ReservedName(String),

    /// A blob file was rolled back to a prior version, but that version's bytes
    /// are not recoverable: either the blob opted OUT of edit history
    /// (single-version mode released the superseded bytes on the next edit), or
    /// the requested point is below the retained history base. Returned instead
    /// of ever projecting wrong/empty bytes. Holds the affected path.
    #[error("no blob history for {0}")]
    NoBlobHistory(PathBuf),

    /// This device has no write role, so it may not author or propagate content
    /// ops. Every write path (edit, restore, resurrect) checks
    /// [`Store::may_write`](roam_storage::Store::may_write) and refuses with this
    /// error when it returns `false`.
    #[error("device is read-only (no write role)")]
    ReadOnly,
}
