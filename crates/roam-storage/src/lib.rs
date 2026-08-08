//! roam-storage — op-log-is-truth persistence for roam-crdt documents.

mod error;
mod identity;
mod ids;
mod oplog;
mod snapshot;
mod store;

pub use error::StorageError;
pub use identity::{Identity, VerifyingKey};
pub use ids::VaultId;
pub use oplog::{Entry, OpLog};
pub use store::Store;
