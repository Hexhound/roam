//! roam-storage — op-log-is-truth persistence for roam-crdt documents.

mod error;
mod identity;
mod oplog;
mod snapshot;

pub use error::StorageError;
pub use identity::{Identity, VerifyingKey};
pub use oplog::{Entry, OpLog};
