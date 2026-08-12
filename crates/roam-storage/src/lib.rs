//! roam-storage — op-log-is-truth persistence for roam-crdt documents.

mod blob;
pub mod checkpoint;
pub mod epoch_crypto;
mod error;
mod founder;
mod history;
mod history_util;
mod identity;
mod ids;
mod keychain;
mod keylog;
mod keywrap;
mod oplog;
mod paper;
mod roster;
mod snapshot;
pub mod snapshot_bootstrap;
pub mod snapshot_msg;
mod store;
mod text_history;
mod vault_key;

pub use blob::BlobStore;
pub use error::StorageError;
pub use history::{HistoryIndex, Marker};
pub use identity::{Identity, VerifyingKey};
pub use ids::VaultId;
pub use keychain::{compute_epoch_id, EpochNode, Keychain, ReadPlan, VaultIssue, EPOCH0_ID};
pub use keylog::{KeyBody, KeyLog, KeyLogEntry, Recipient};
pub use keywrap::{unwrap, wrap};
pub use oplog::{Entry, OpLog};
pub use paper::PaperKey;
pub use roster::{merge_roster, PeerRecord, PeerStatus, Role, RosterEntry, RosterLog, RosterOp};
pub use store::{version_dominates, BackendSnapshot, DataSize, HeldSnapshot, Store};
pub use text_history::{TextVersion, VersionKind};
pub use vault_key::{vault_subkeys, VAULT_AEAD_LABEL, VAULT_ID_LABEL};
