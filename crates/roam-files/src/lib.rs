//! `roam-files` maps on-disk vault files into Roam's sync model.
//!
//! This crate is responsible for turning filesystem paths into stable
//! container identifiers, and (in later tasks) for sidecar metadata,
//! text diffing, and bridging file state into the CRDT storage layer.
//!
//! Task 1 provides the crate scaffold and [`path::container_id`], which
//! maps a file under a vault root to a normalized, vault-relative id.

mod bridge;
mod error;
mod fileset;
mod path;
mod rebase;
mod sidecar;
mod textdiff;

pub use bridge::{FolderBridge, GcContext, SyncOutcome};
pub use error::FilesError;
pub use fileset::{EntryKind, EntryStatus, FileEntry, FILESET_MAP_ID};
pub use rebase::Conflict;
// Re-exported so consumers can construct a `FolderBridge` without depending on
// `roam-storage` directly.
pub use path::{container_id, key_to_path};
pub use roam_storage::Identity;
pub use sidecar::{sidecar_path, text_hash, Sidecar};
pub use textdiff::{diff_to_ops, TextOp};
