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

/// The kind of content an entry tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// UTF-8 text content synced via the CRDT text layer. Its
    /// [`FileEntry::content_hash`] is the blake3 hash of the file's TEXT.
    Text,
    /// Binary content kept OUTSIDE the CRDT in the content-addressed
    /// [`roam_storage::BlobStore`]; only the hash-reference rides the op-log.
    ///
    /// A `Blob` entry REUSES [`FileEntry::content_hash`] as its blob-ref: the
    /// field holds the blake3 hex hash of the file's BYTES, which is exactly the
    /// key under which those bytes live in the `BlobStore`. No separate
    /// `blob_ref` field is needed — for `kind == Blob`, `content_hash` IS the
    /// blob reference. The bytes themselves are transferred out-of-band (a later
    /// slice); only this hash-ref is carried by the CRDT.
    Blob,
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
    /// When this entry was created by a rename, the `container_id` of the file
    /// it was renamed FROM (rename provenance). Loro cannot transplant a
    /// container's edit history to a new id (see
    /// [`FolderBridge::rename_file`](crate::FolderBridge::rename_file)), so the
    /// history is not preserved; this field makes the old container LINKABLE
    /// from the new one. `None` for a normally-imported (non-renamed) entry.
    ///
    /// On-wire: `#[serde(default, skip_serializing_if = "Option::is_none")]`
    /// keeps the JSON forward/backward compatible — an old value with no
    /// `renamed_from` key parses to `None`, and a `None` field is omitted so
    /// old readers still see exactly the old shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renamed_from: Option<String>,
    /// For a [`EntryStatus::Tombstoned`] entry, a hex-encoded
    /// [`roam_storage::version_dominates`]-comparable document version vector
    /// that CAUSALLY INCLUDES the tombstone op — the "creation version" the
    /// causally-stable GC predicate requires every trusted peer to dominate
    /// before the tombstone may be dropped. `None` for a `Live` entry, and also
    /// for an old-format tombstone written before this field existed (which is
    /// therefore never GC-eligible — conservative).
    ///
    /// It is a CONSERVATIVE checkpoint, not the precise op id of the map write:
    /// loro's public API surfaces only a map key's last-editor `PeerID`, not the
    /// `(peer, counter)` op id, so the precise-op-id approach is not soundly
    /// available. The checkpoint is the document version RIGHT AFTER the
    /// tombstone op is committed, so a peer whose acked version dominates it has
    /// provably observed the tombstone (and possibly more) — GC fires later than
    /// a precise op id would, never earlier.
    ///
    /// On-wire: `#[serde(default, skip_serializing_if = "Option::is_none")]` for
    /// the same forward/backward compatibility as `renamed_from`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstoned_at: Option<String>,
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

    /// A copy with status [`EntryStatus::Live`] and its tombstone checkpoint
    /// cleared. Content hash + kind are preserved. Used to re-materialize a
    /// tombstoned file (see [`FolderBridge::resurrect`](crate::FolderBridge::resurrect)).
    pub fn to_live(&self) -> FileEntry {
        let mut entry = self.clone();
        entry.status = EntryStatus::Live;
        entry.tombstoned_at = None;
        entry
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
            renamed_from: None,
            tombstoned_at: None,
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
                renamed_from: None,
                tombstoned_at: None,
            }
        );
    }

    #[test]
    fn old_shape_without_renamed_from_still_deserializes() {
        // Forward/backward compat (E2): an OLD-shape value written before the
        // `renamed_from` field existed (no such key) must still parse, defaulting
        // the field to `None`.
        let json = r#"{"kind":"text","status":"live","content_hash":"cafe"}"#;
        let entry = FileEntry::from_value(json).unwrap();
        assert_eq!(entry.renamed_from, None);
        assert_eq!(entry.kind, EntryKind::Text);
        assert_eq!(entry.status, EntryStatus::Live);
    }

    #[test]
    fn renamed_from_omitted_from_wire_when_none() {
        // When `renamed_from` is `None` it must be OMITTED from the JSON so old
        // readers see exactly the old shape (no new key at all).
        let value = sample(EntryStatus::Live).to_value();
        assert!(!value.contains("renamed_from"), "None must not serialize a key: {value}");
    }

    #[test]
    fn renamed_from_round_trips_when_set() {
        let entry = FileEntry {
            kind: EntryKind::Text,
            status: EntryStatus::Live,
            content_hash: "abc123".to_string(),
            renamed_from: Some("old.md".to_string()),
            tombstoned_at: None,
        };
        let value = entry.to_value();
        assert!(value.contains("renamed_from"));
        assert!(value.contains("old.md"));
        assert_eq!(FileEntry::from_value(&value).unwrap(), entry);
    }

    #[test]
    fn tombstoned_at_omitted_from_wire_when_none() {
        // A `None` checkpoint must be OMITTED so old readers see the old shape.
        let value = sample(EntryStatus::Tombstoned).to_value();
        assert!(
            !value.contains("tombstoned_at"),
            "None must not serialize a key: {value}"
        );
    }

    #[test]
    fn tombstoned_at_round_trips_when_set() {
        let entry = FileEntry {
            kind: EntryKind::Text,
            status: EntryStatus::Tombstoned,
            content_hash: "abc123".to_string(),
            renamed_from: None,
            tombstoned_at: Some("00ff13".to_string()),
        };
        let value = entry.to_value();
        assert!(value.contains("tombstoned_at"));
        assert!(value.contains("00ff13"));
        assert_eq!(FileEntry::from_value(&value).unwrap(), entry);
    }

    #[test]
    fn old_shape_without_tombstoned_at_still_deserializes() {
        // A tombstone written before the GC checkpoint field existed must parse,
        // defaulting `tombstoned_at` to `None` (thus never GC-eligible).
        let json = r#"{"kind":"text","status":"tombstoned","content_hash":"cafe"}"#;
        let entry = FileEntry::from_value(json).unwrap();
        assert_eq!(entry.tombstoned_at, None);
        assert_eq!(entry.status, EntryStatus::Tombstoned);
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
    fn blob_entry_round_trips() {
        // A Blob entry: content_hash doubles as the blob-ref (blake3 of the
        // file's BYTES). Round-trip through the JSON map value must preserve it.
        let entry = FileEntry {
            kind: EntryKind::Blob,
            status: EntryStatus::Live,
            content_hash: "a".repeat(64), // a 64-hex blob hash
            renamed_from: None,
            tombstoned_at: None,
        };
        let value = entry.to_value();
        assert_eq!(FileEntry::from_value(&value).unwrap(), entry);
    }

    #[test]
    fn blob_wire_shape_uses_lowercase_blob_token() {
        // Pins the on-wire kind token so a future rename is caught, and asserts a
        // Text entry still serializes `"kind":"text"`.
        let blob = FileEntry {
            kind: EntryKind::Blob,
            status: EntryStatus::Live,
            content_hash: "ff".repeat(32),
            renamed_from: None,
            tombstoned_at: None,
        };
        assert!(blob.to_value().contains("\"kind\":\"blob\""), "{}", blob.to_value());
        assert!(sample(EntryStatus::Live).to_value().contains("\"kind\":\"text\""));
    }

    #[test]
    fn blob_entry_parses_from_explicit_wire_json() {
        // A hand-written wire value with kind:blob must deserialize, and the
        // forward-compat rule (unknown fields ignored) must still hold for blobs.
        let json = r#"{
            "kind": "blob",
            "status": "live",
            "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "future_field": true
        }"#;
        let entry = FileEntry::from_value(json).unwrap();
        assert_eq!(entry.kind, EntryKind::Blob);
        assert_eq!(entry.status, EntryStatus::Live);
        assert_eq!(
            entry.content_hash,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn to_live_flips_status_and_clears_checkpoint() {
        let tomb = FileEntry {
            kind: EntryKind::Text,
            status: EntryStatus::Tombstoned,
            content_hash: "abc123".to_string(),
            renamed_from: None,
            tombstoned_at: Some("00ff13".to_string()),
        };
        let live = tomb.to_live();
        assert_eq!(live.status, EntryStatus::Live);
        assert_eq!(live.tombstoned_at, None);
        assert_eq!(live.content_hash, "abc123");
        assert_eq!(live.kind, EntryKind::Text);
    }

    #[test]
    fn fileset_map_id_matches_storage_mirror() {
        // roam-storage hardcodes this literal (store.rs) to avoid a dep cycle.
        assert_eq!(FILESET_MAP_ID, "__roam_fileset__");
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
