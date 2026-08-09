//! Sidecar metadata (`.roammeta`) that records the last-synced state of a
//! vault file.
//!
//! A sidecar is INTERNAL metadata that lives OUTSIDE the user's vault folder,
//! under a store-owned metadata directory, keyed by the file's `container_id`
//! (`notes/foo.md` → `<meta_dir>/sidecars/notes/foo.md.roammeta`). It stores,
//! as JSON, the container id together with the exact text and hash that were
//! last reconciled with the CRDT layer. This lets a later sync compute what
//! changed on disk without re-reading the entire history — and keeps our
//! bookkeeping out of the user's notes directory.
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
    /// Load the sidecar for `container_id` under `meta_dir`, if one exists.
    ///
    /// Returns `Ok(None)` when no sidecar is present. A sidecar that exists
    /// but cannot be parsed as JSON yields [`FilesError::Sidecar`]; other IO
    /// failures propagate as [`FilesError::Io`].
    pub fn load(meta_dir: &Path, container_id: &str) -> Result<Option<Sidecar>, FilesError> {
        let path = sidecar_path(meta_dir, container_id);
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

    /// Atomically write this sidecar for `container_id` under `meta_dir`.
    ///
    /// The nested parent directory (mirroring the container id path) is
    /// created if missing. The JSON is written to a temporary file in the
    /// same directory and then renamed over the final `.roammeta` path, so
    /// readers never see a partially written sidecar.
    pub fn store(&self, meta_dir: &Path, container_id: &str) -> Result<(), FilesError> {
        let path = sidecar_path(meta_dir, container_id);
        // Create the nested parent (e.g. `<meta_dir>/sidecars/notes/`) so a
        // deeply-nested container id round-trips.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
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

/// The sidecar path for `container_id` under `meta_dir`:
/// `<meta_dir>/sidecars/<container_id>.roammeta`.
///
/// The container-id path is mirrored (its `/`-separated components are pushed
/// as native path components) so nested notes never collide, and the
/// `.roammeta` suffix is appended to the whole thing (not swapped for the
/// extension) so files that differ only by extension get distinct sidecars.
/// `notes/foo.md` → `<meta_dir>/sidecars/notes/foo.md.roammeta`.
pub fn sidecar_path(meta_dir: &Path, container_id: &str) -> PathBuf {
    let mut path = meta_dir.join("sidecars");
    for component in container_id.split('/') {
        path.push(component);
    }
    let mut name: OsString = path.into_os_string();
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
        let meta = dir.path();
        let sidecar = sample("hello world");

        sidecar.store(meta, "foo.md").unwrap();
        let loaded = Sidecar::load(meta, "foo.md").unwrap();
        assert_eq!(loaded, Some(sidecar));
    }

    #[test]
    fn nested_container_id_round_trips() {
        // A nested container id must create its parent dirs on store and load
        // back byte-identically.
        let dir = tempdir().unwrap();
        let meta = dir.path();
        let sidecar = sample("nested body");

        sidecar.store(meta, "a/b/c.md").unwrap();
        assert!(meta.join("sidecars/a/b/c.md.roammeta").exists());
        assert_eq!(Sidecar::load(meta, "a/b/c.md").unwrap(), Some(sidecar));
    }

    #[test]
    fn sidecar_path_appends_suffix_under_meta_dir() {
        let meta = Path::new("/meta");
        assert_eq!(
            sidecar_path(meta, "foo.md"),
            PathBuf::from("/meta/sidecars/foo.md.roammeta")
        );
        assert_eq!(
            sidecar_path(meta, "notes/foo.md"),
            PathBuf::from("/meta/sidecars/notes/foo.md.roammeta")
        );
    }

    #[test]
    fn absent_sidecar_loads_none() {
        let dir = tempdir().unwrap();
        assert_eq!(Sidecar::load(dir.path(), "missing.md").unwrap(), None);
    }

    #[test]
    fn forward_compatible_unknown_fields_ignored() {
        let dir = tempdir().unwrap();
        let meta = dir.path();
        let json = r#"{
            "version": 1,
            "doc_id": "notes/foo.md",
            "last_synced_hash": "deadbeef",
            "last_synced_text": "body",
            "future_field": 42
        }"#;
        let path = sidecar_path(meta, "foo.md");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, json).unwrap();

        let loaded = Sidecar::load(meta, "foo.md").unwrap().unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.doc_id, "notes/foo.md");
        assert_eq!(loaded.last_synced_hash, "deadbeef");
        assert_eq!(loaded.last_synced_text, "body");
    }

    #[test]
    fn malformed_json_is_sidecar_error() {
        let dir = tempdir().unwrap();
        let meta = dir.path();
        let path = sidecar_path(meta, "foo.md");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "{not json").unwrap();

        assert!(matches!(
            Sidecar::load(meta, "foo.md"),
            Err(FilesError::Sidecar(_))
        ));
    }

    #[test]
    fn store_leaves_no_temp_file() {
        let dir = tempdir().unwrap();
        let meta = dir.path();
        sample("content").store(meta, "foo.md").unwrap();

        let entries: Vec<_> = std::fs::read_dir(meta.join("sidecars"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![OsString::from("foo.md.roammeta")]);

        // The single artifact must be complete and parseable.
        assert!(Sidecar::load(meta, "foo.md").unwrap().is_some());
    }

    #[test]
    fn text_hash_is_stable_and_distinct() {
        assert_eq!(text_hash("abc"), text_hash("abc"));
        assert_ne!(text_hash("abc"), text_hash("abd"));
    }
}
