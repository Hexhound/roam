//! Value types for the file-set map: the well-known Loro map that tracks
//! which vault files participate in sync and their last-synced content hash.
//!
//! Each map entry is keyed by a file's [`container_id`](crate::container_id)
//! and holds a JSON-encoded [`FileEntry`] as its string value. This module
//! owns only the value types and their serde encoding; wiring entries into
//! the bridge, import, and scan flows lands in later tasks.
//!
//! On-wire JSON is intentionally forward-compatible: unknown fields are
//! ignored on load (no `deny_unknown_fields`), mirroring [`Sidecar`], so a
//! newer writer can add fields without breaking an older reader.
//!
//! [`Sidecar`]: crate::Sidecar

use serde::{Deserialize, Serialize};

use crate::error::FilesError;

/// Well-known Loro map container id holding the file-set map. Must NOT collide
/// with any container_id (which are vault-relative paths); the double-underscore
/// sentinel guarantees that since container_id never yields this exact string.
///
/// Residual risk: a real file literally named `__roam_fileset__` at the vault
/// root would produce this exact container_id. That collision is accepted and
/// deferred — normal notes do not carry the sentinel name.
pub const FILESET_MAP_ID: &str = "__roam_fileset__";

/// Whether a file-set entry is currently live or has been tombstoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    /// The file is an active participant in sync.
    Live,
    /// The file was removed; the entry is retained as a tombstone.
    Tombstoned,
}

/// The kind of content an entry tracks. Only [`EntryKind::Text`] exists this
/// slice; binary/blob kinds are deferred to a later task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// UTF-8 text content synced via the CRDT text layer.
    Text,
}

/// A single file-set map value: the sync-relevant metadata for one file,
/// stored (JSON-encoded) as the string value under its `container_id` key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// The content kind this entry tracks.
    pub kind: EntryKind,
    /// Whether the entry is live or tombstoned.
    pub status: EntryStatus,
    /// blake3 hex digest (see [`text_hash`](crate::text_hash)) of the
    /// last-synced content.
    pub content_hash: String,
}

impl FileEntry {
    /// Serialize to the JSON string stored as the map value.
    pub fn to_value(&self) -> String {
        // Serializing a struct of owned strings and unit enums is infallible,
        // but avoid `unwrap`: fall back to an empty object rather than panic.
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Parse a map value string back into a [`FileEntry`].
    pub fn from_value(s: &str) -> Result<FileEntry, FilesError> {
        serde_json::from_str(s)
            .map_err(|err| FilesError::Entry(format!("failed to parse file-set entry: {err}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::container_id;
    use std::path::PathBuf;

    fn sample(status: EntryStatus) -> FileEntry {
        FileEntry {
            kind: EntryKind::Text,
            status,
            content_hash: "abc123".to_string(),
        }
    }

    #[test]
    fn round_trip_live() {
        let entry = sample(EntryStatus::Live);
        let value = entry.to_value();
        assert_eq!(FileEntry::from_value(&value).unwrap(), entry);
    }

    #[test]
    fn round_trip_tombstoned() {
        let entry = sample(EntryStatus::Tombstoned);
        let value = entry.to_value();
        assert_eq!(FileEntry::from_value(&value).unwrap(), entry);
    }

    #[test]
    fn invalid_json_is_entry_error() {
        assert!(matches!(
            FileEntry::from_value("not json"),
            Err(FilesError::Entry(_))
        ));
    }

    #[test]
    fn forward_compatible_unknown_fields_ignored() {
        let json = r#"{
            "kind": "text",
            "status": "live",
            "content_hash": "deadbeef",
            "future_field": 42
        }"#;
        let entry = FileEntry::from_value(json).unwrap();
        assert_eq!(
            entry,
            FileEntry {
                kind: EntryKind::Text,
                status: EntryStatus::Live,
                content_hash: "deadbeef".to_string(),
            }
        );
    }

    #[test]
    fn wire_shape_uses_lowercase_status_tokens() {
        // Pins the on-wire status tokens so a future rename is caught.
        assert!(sample(EntryStatus::Live).to_value().contains("\"live\""));
        assert!(sample(EntryStatus::Tombstoned)
            .to_value()
            .contains("\"tombstoned\""));
        // And the kind token, likewise.
        assert!(sample(EntryStatus::Live).to_value().contains("\"text\""));
    }

    #[test]
    fn fileset_map_id_never_collides_with_container_id() {
        let vault = PathBuf::from("/vault/root");
        let ids = [
            container_id(&vault, &vault.join("a/b.md")).unwrap(),
            container_id(&vault, &vault.join("notes/foo.md")).unwrap(),
            container_id(&vault, &vault.join("deep/nested/path/note.md")).unwrap(),
        ];
        for id in &ids {
            assert_ne!(id, FILESET_MAP_ID);
        }
        // The sentinel that a normal NFC vault-relative path cannot produce.
        assert!(FILESET_MAP_ID.contains("__"));
    }
}
