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

    /// The file is not valid UTF-8 text and cannot be handled as such.
    #[error("file is not text: {0}")]
    NotText(PathBuf),

    /// The resolved path escapes the vault root.
    #[error("path escapes vault: {0}")]
    PathEscapesVault(PathBuf),

    /// A sidecar metadata file could not be parsed or written.
    #[error("sidecar error: {0}")]
    Sidecar(String),

    /// A file-set map entry value could not be parsed or serialized.
    #[error("entry error: {0}")]
    Entry(String),

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
}
