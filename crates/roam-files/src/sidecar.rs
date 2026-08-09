//! Sidecar metadata (`.roammeta`) that records the last-synced state of a
//! vault file.
//!
//! A sidecar lives beside the file it describes (`foo.md` →
//! `foo.md.roammeta`) and stores, as JSON, the container id together with
//! the exact text and hash that were last reconciled with the CRDT layer.
//! This lets a later sync compute what changed on disk without re-reading
//! the entire history.
//!
//! On-disk JSON is intentionally forward-compatible: unknown fields are
//! ignored on load, so newer writers can add fields without breaking older
//! readers.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::FilesError;

/// Last-synced metadata for a single vault file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sidecar {
    /// Sidecar format version.
    pub version: u32,
    /// The container id of the described file (equal to its `container_id`).
    pub doc_id: String,
    /// blake3 hex digest of [`Sidecar::last_synced_text`].
    pub last_synced_hash: String,
    /// The exact file text captured at the last successful sync.
    pub last_synced_text: String,
}

impl Sidecar {
    /// Load the sidecar that describes `file`, if one exists.
    ///
    /// Returns `Ok(None)` when no sidecar is present. A sidecar that exists
    /// but cannot be parsed as JSON yields [`FilesError::Sidecar`]; other IO
    /// failures propagate as [`FilesError::Io`].
    pub fn load(file: &Path) -> Result<Option<Sidecar>, FilesError> {
        let path = sidecar_path(file);
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(FilesError::Io(err)),
        };

        let sidecar = serde_json::from_str(&contents).map_err(|err| {
            FilesError::Sidecar(format!("failed to parse {}: {err}", path.display()))
        })?;
        Ok(Some(sidecar))
    }

    /// Atomically write this sidecar beside `file`.
    ///
    /// The JSON is written to a temporary file in the same directory and
    /// then renamed over the final `.roammeta` path, so readers never see a
    /// partially written sidecar.
    pub fn store(&self, file: &Path) -> Result<(), FilesError> {
        let path = sidecar_path(file);
        let json = serde_json::to_vec_pretty(self)
            .map_err(|err| FilesError::Sidecar(format!("failed to serialize sidecar: {err}")))?;

        // Write to a sibling temp file so the final rename stays on the same
        // filesystem and is therefore atomic.
        let mut temp = path.clone().into_os_string();
        temp.push(".tmp");
        let temp = PathBuf::from(temp);

        std::fs::write(&temp, &json)?;
        match std::fs::rename(&temp, &path) {
            Ok(()) => Ok(()),
            Err(err) => {
                // Best-effort cleanup so a failed rename leaves no debris.
                let _ = std::fs::remove_file(&temp);
                Err(FilesError::Io(err))
            }
        }
    }
}

/// The sidecar path for `file`: the full filename plus `.roammeta`.
///
/// `notes/foo.md` → `notes/foo.md.roammeta`. The suffix is appended to the
/// whole filename (not swapped for the extension) so files that differ only
/// by extension get distinct sidecars.
pub fn sidecar_path(file: &Path) -> PathBuf {
    let mut name: OsString = file.as_os_str().to_os_string();
    name.push(".roammeta");
    PathBuf::from(name)
}

/// blake3 hex digest of `text`, as used for `last_synced_hash`.
pub fn text_hash(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample(text: &str) -> Sidecar {
        Sidecar {
            version: 1,
            doc_id: "notes/foo.md".to_string(),
            last_synced_hash: text_hash(text),
            last_synced_text: text.to_string(),
        }
    }

    #[test]
    fn round_trip() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("foo.md");
        let sidecar = sample("hello world");

        sidecar.store(&file).unwrap();
        let loaded = Sidecar::load(&file).unwrap();
        assert_eq!(loaded, Some(sidecar));
    }

    #[test]
    fn sidecar_path_appends_suffix() {
        assert_eq!(
            sidecar_path(Path::new("foo.md")),
            PathBuf::from("foo.md.roammeta")
        );
        assert_eq!(
            sidecar_path(Path::new("notes/foo.md")),
            PathBuf::from("notes/foo.md.roammeta")
        );
    }

    #[test]
    fn absent_sidecar_loads_none() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("missing.md");
        assert_eq!(Sidecar::load(&file).unwrap(), None);
    }

    #[test]
    fn forward_compatible_unknown_fields_ignored() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("foo.md");
        let json = r#"{
            "version": 1,
            "doc_id": "notes/foo.md",
            "last_synced_hash": "deadbeef",
            "last_synced_text": "body",
            "future_field": 42
        }"#;
        std::fs::write(sidecar_path(&file), json).unwrap();

        let loaded = Sidecar::load(&file).unwrap().unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.doc_id, "notes/foo.md");
        assert_eq!(loaded.last_synced_hash, "deadbeef");
        assert_eq!(loaded.last_synced_text, "body");
    }

    #[test]
    fn malformed_json_is_sidecar_error() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("foo.md");
        std::fs::write(sidecar_path(&file), "{not json").unwrap();

        assert!(matches!(
            Sidecar::load(&file),
            Err(FilesError::Sidecar(_))
        ));
    }

    #[test]
    fn store_leaves_no_temp_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("foo.md");
        sample("content").store(&file).unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![OsString::from("foo.md.roammeta")]);

        // The single artifact must be complete and parseable.
        assert!(Sidecar::load(&file).unwrap().is_some());
    }

    #[test]
    fn text_hash_is_stable_and_distinct() {
        assert_eq!(text_hash("abc"), text_hash("abc"));
        assert_ne!(text_hash("abc"), text_hash("abd"));
    }
}
