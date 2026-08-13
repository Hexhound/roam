use thiserror::Error;

/// Errors from the CRDT layer. Wraps loro's error types so callers never
/// depend on `loro` directly.
#[derive(Debug, Error)]
pub enum CrdtError {
    #[error("loro operation failed: {0}")]
    Loro(String),
    #[error("loro encode failed: {0}")]
    Encode(String),
    #[error("target frontier is not retained in this oplog (compacted away)")]
    FrontierNotRetained,
    #[error("update authored by peer {found} but attributed to {expected}")]
    ForeignAuthor { expected: u64, found: u64 },
}

impl From<loro::LoroError> for CrdtError {
    fn from(e: loro::LoroError) -> Self {
        CrdtError::Loro(e.to_string())
    }
}

impl From<loro::LoroEncodeError> for CrdtError {
    fn from(e: loro::LoroEncodeError) -> Self {
        CrdtError::Encode(e.to_string())
    }
}
