//! Storage-level per-file text history: a crdt change joined with a roster
//! author lookup, plus a created/edited classification.

use roam_crdt::{Frontier, TextDiff};

/// Whether a version is the file's first appearance or a later edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionKind {
    Created,
    Edited,
}

/// One entry in a text file's version list (UI-consumable).
#[derive(Debug, Clone)]
pub struct TextVersion {
    /// Handle to pass to [`crate::Store::revert_text`].
    pub frontier: Frontier,
    pub ts_ms: i64,
    /// Authoring device (Loro change peer id).
    pub author_peer: u64,
    /// The author's verifying key (== iroh NodeId), resolved via the roster.
    /// `None` if the peer is absent from the roster (unknown device).
    pub author_key: Option<[u8; 32]>,
    pub kind: VersionKind,
    /// The char-level delta this version introduced, for UI preview.
    pub diff: TextDiff,
}
