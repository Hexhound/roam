use std::path::PathBuf;

/// Errors produced by the `roam-files` crate.
///
/// Several variants are defined ahead of the tasks that use them
/// (sidecar parsing, text diffing, storage bridging); `dead_code` is
/// allowed on the enum until those tasks land.
#[allow(dead_code)]
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

    /// After applying computed ops to a container, the store's text did not
    /// match the file text — a symptom of an offset/diff bug. The message
    /// includes the affected container id.
    #[error("desync: {0}")]
    Desync(String),
}
