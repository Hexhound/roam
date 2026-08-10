//! roam-storage — op-log-is-truth persistence for roam-crdt documents.

mod blob;
mod error;
mod identity;
mod ids;
mod keychain;
mod keylog;
mod keywrap;
mod oplog;
mod roster;
mod snapshot;
mod store;

pub use blob::BlobStore;
pub use error::StorageError;
pub use identity::{Identity, VerifyingKey};
pub use ids::VaultId;
pub use keychain::{compute_epoch_id, EpochNode, Keychain, ReadPlan, VaultIssue, EPOCH0_ID};
pub use keylog::{KeyBody, KeyLog, KeyLogEntry, Recipient};
pub use keywrap::{unwrap, wrap};
pub use oplog::{Entry, OpLog};
pub use roster::{merge_roster, PeerRecord, PeerStatus, RosterEntry, RosterLog, RosterOp};
pub use store::{version_dominates, Store};
