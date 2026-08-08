use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 decode error: {0}")]
    Base64(String),
    #[error("malformed identity file")]
    MalformedIdentity,
    #[error("malformed oplog entry: {0}")]
    MalformedEntry(String),
    #[error("signature verification failed for peer {0}")]
    BadSignature(u64),
    #[error(transparent)]
    Crdt(#[from] roam_crdt::CrdtError),
}
