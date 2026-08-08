//! roam-storage — op-log-is-truth persistence for roam-crdt documents.

mod error;
mod identity;

pub use error::StorageError;
pub use identity::{Identity, VerifyingKey};
