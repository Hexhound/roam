//! roam-storage — op-log-is-truth persistence for roam-crdt documents.

mod error;
mod identity;
mod ids;
mod oplog;
mod roster;
mod snapshot;
mod store;

pub use error::StorageError;
pub use identity::{Identity, VerifyingKey};
pub use ids::VaultId;
pub use oplog::{Entry, OpLog};
pub use roster::{RosterEntry, RosterLog, RosterOp};
pub use store::Store;
