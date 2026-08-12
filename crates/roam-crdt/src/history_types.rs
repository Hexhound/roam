//! Plain data types describing a text container's change history. These carry
//! no roster/identity knowledge — the storage layer joins `author_peer` to a
//! verifying key.

use crate::doc::Frontier;

/// One span of a text delta, in unicode-char units (roam's text-op unit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextSpan {
    /// Keep the next N chars unchanged.
    Retain(usize),
    /// Insert this string at the cursor.
    Insert(String),
    /// Delete the next N chars.
    Delete(usize),
}

/// The char-level delta a change (or a frontier→frontier diff) applied to one
/// text container.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TextDiff {
    pub spans: Vec<TextSpan>,
}

/// One change touching a text container, crdt-level (author is a raw peer id).
#[derive(Debug, Clone)]
pub struct ChangeInfo {
    /// Op-log frontier AS OF this change (this change + all its ancestors).
    pub frontier: Frontier,
    /// Wall-clock milliseconds of the (coalesced) change.
    pub ts_ms: i64,
    /// Authoring device: the Loro change peer id.
    pub author_peer: u64,
}
