//! Content-addressed blob store — binary payloads kept OUTSIDE the CRDT.
//!
//! A [`BlobStore`] persists arbitrary bytes under an `assets` directory, keyed
//! by the blake3 hex digest of their content. The CRDT (op-log) only ever
//! carries the hash reference; the bytes themselves live here on plain disk.
//! Because the filename IS the hash, an identical payload stored twice occupies
//! a single file (automatic dedup), and any consumer can pre-check presence by
//! hash before transferring bytes over the wire.

use crate::error::StorageError;
use std::path::{Path, PathBuf};

/// A blake3 hex digest is exactly 32 bytes rendered as 64 lowercase hex chars.
const HASH_HEX_LEN: usize = 64;

/// Content-addressed byte store rooted at an `assets` directory.
///
/// Every blob is stored at `<root>/<blake3-hex>`; the filename IS the content
/// hash, so identical bytes collapse to one file (dedup) and any hash maps to
/// at most one on-disk copy. Blobs live entirely OUTSIDE the CRDT — the op-log
/// only ever references the hash.
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Open a blob store rooted at `assets_dir`, creating the directory (and
    /// any missing parents) if absent.
    pub fn open(assets_dir: &Path) -> Result<Self, StorageError> {
        std::fs::create_dir_all(assets_dir)?;
        Ok(Self {
            root: assets_dir.to_path_buf(),
        })
    }

    /// The blake3 hex digest of `bytes`, WITHOUT storing them. Matches the hex
    /// convention used everywhere else in roam (see `roam_files` `text_hash`).
    pub fn hash(bytes: &[u8]) -> String {
        blake3::hash(bytes).to_hex().to_string()
    }

    /// Store `bytes`, returning their blake3 hex hash.
    ///
    /// Content-addressed and idempotent: the hash is computed first, and if a
    /// file with that name already exists the bytes are NOT rewritten (dedup).
    /// The write is atomic — bytes land in a sibling temp file that is then
    /// renamed over the final path, so a partial write is never observable.
    pub fn put(&self, bytes: &[u8]) -> Result<String, StorageError> {
        let hash = Self::hash(bytes);
        let path = self.root.join(&hash);

        // Dedup: an existing blob with this hash already holds these exact bytes
        // (the filename is the content hash), so never rewrite it.
        if path.exists() {
            return Ok(hash);
        }

        // Atomic write: a uniquely-named sibling temp file + rename, so the
        // final path only ever appears complete. The temp name embeds the hash
        // (unique per content) so concurrent puts of distinct blobs never race
        // on the same temp path.
        let temp = self.root.join(format!("{hash}.tmp"));
        std::fs::write(&temp, bytes)?;
        match std::fs::rename(&temp, &path) {
            Ok(()) => Ok(hash),
            Err(err) => {
                let _ = std::fs::remove_file(&temp);
                Err(err.into())
            }
        }
    }

    /// Read the bytes for `hash`, or `Ok(None)` if no such blob is present.
    ///
    /// Verify-on-read: the stored bytes are re-hashed and compared against the
    /// requested `hash`. A mismatch means on-disk corruption — this returns a
    /// [`StorageError::Blob`] error rather than ever handing back wrong bytes.
    pub fn get(&self, hash: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let path = self.blob_path(hash)?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        if Self::hash(&bytes) != hash {
            return Err(StorageError::Blob(format!(
                "blob {hash} is corrupt: on-disk content does not match its hash"
            )));
        }
        Ok(Some(bytes))
    }

    /// Whether a blob for `hash` is present locally. An invalid hash is never
    /// present (and never touches the filesystem outside `assets`).
    pub fn has(&self, hash: &str) -> bool {
        match self.blob_path(hash) {
            Ok(path) => path.exists(),
            Err(_) => false,
        }
    }

    /// Remove the blob for `hash`. A missing blob is tolerated (not an error),
    /// so this is safe to call from a later garbage collector.
    pub fn remove(&self, hash: &str) -> Result<(), StorageError> {
        let path = self.blob_path(hash)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Every stored blob hash (for GC ref-counting). Non-blob entries (e.g. a
    /// leftover `.tmp`) are skipped, so the list is exactly the valid hashes.
    pub fn list(&self) -> Result<Vec<String>, StorageError> {
        let mut hashes = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let name = entry?.file_name();
            if let Some(name) = name.to_str() {
                if is_valid_hash(name) {
                    hashes.push(name.to_string());
                }
            }
        }
        Ok(hashes)
    }

    /// Byte length of the blob for `hash`, or `Ok(None)` if absent. Used for
    /// checkpoint reclaim accounting without reading the whole file.
    pub fn size(&self, hash: &str) -> Result<Option<u64>, StorageError> {
        let path = self.blob_path(hash)?;
        match std::fs::metadata(&path) {
            Ok(m) => Ok(Some(m.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Resolve `hash` to its on-disk path, rejecting anything that is not a
    /// valid blake3 hex digest.
    ///
    /// Path safety: because the hash is validated to be exactly 64 lowercase
    /// hex chars, it can never contain a path separator, `..`, or any other
    /// component that would escape the `assets` directory. `get("../../x")` is
    /// refused before the filesystem is ever touched.
    fn blob_path(&self, hash: &str) -> Result<PathBuf, StorageError> {
        if !is_valid_hash(hash) {
            return Err(StorageError::Blob(format!(
                "invalid blob hash {hash:?}: expected {HASH_HEX_LEN} lowercase hex chars"
            )));
        }
        Ok(self.root.join(hash))
    }
}

/// A well-formed blake3 hex hash: exactly [`HASH_HEX_LEN`] lowercase hex chars.
/// This is the single path-safety gate — it rejects separators, `..`, and any
/// other filename that could escape the assets directory.
fn is_valid_hash(hash: &str) -> bool {
    hash.len() == HASH_HEX_LEN
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::super::blob::BlobStore;
    use crate::error::StorageError;
    use std::fs;
    use tempfile::tempdir;

    fn open(dir: &tempfile::TempDir) -> BlobStore {
        BlobStore::open(&dir.path().join("assets")).unwrap()
    }

    #[test]
    fn put_then_get_round_trips() {
        let dir = tempdir().unwrap();
        let store = open(&dir);
        let hash = store.put(b"hello").unwrap();
        assert!(!hash.is_empty());
        assert_eq!(store.get(&hash).unwrap(), Some(b"hello".to_vec()));
    }

    #[test]
    fn put_is_idempotent_and_dedups_on_disk() {
        let dir = tempdir().unwrap();
        let assets = dir.path().join("assets");
        let store = BlobStore::open(&assets).unwrap();

        let h1 = store.put(b"same bytes").unwrap();
        let h2 = store.put(b"same bytes").unwrap();
        assert_eq!(h1, h2, "same bytes must yield the same hash");

        let count = fs::read_dir(&assets).unwrap().count();
        assert_eq!(count, 1, "dedup: only one file for identical content");
    }

    #[test]
    fn different_bytes_hash_differently_and_static_hash_matches_put() {
        let dir = tempdir().unwrap();
        let store = open(&dir);
        let a = store.put(b"aaa").unwrap();
        let b = store.put(b"bbb").unwrap();
        assert_ne!(a, b, "distinct content → distinct hash");
        assert_eq!(BlobStore::hash(b"aaa"), a, "static hash matches put's hash");
    }

    #[test]
    fn get_of_absent_hash_is_none_and_has_tracks_presence() {
        let dir = tempdir().unwrap();
        let store = open(&dir);
        let hash = BlobStore::hash(b"not stored yet");
        assert_eq!(store.get(&hash).unwrap(), None);
        assert!(!store.has(&hash));

        let stored = store.put(b"not stored yet").unwrap();
        assert_eq!(stored, hash);
        assert!(store.has(&hash));
    }

    #[test]
    fn put_leaves_no_temp_file_behind() {
        let dir = tempdir().unwrap();
        let assets = dir.path().join("assets");
        let store = BlobStore::open(&assets).unwrap();
        let hash = store.put(b"atomic").unwrap();

        let names: Vec<String> = fs::read_dir(&assets)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![hash], "only the blob remains, no temp debris");
    }

    #[test]
    fn path_traversal_and_non_hex_hashes_are_rejected() {
        let dir = tempdir().unwrap();
        let store = open(&dir);

        for bad in ["../../etc/passwd", "abc/def", "not-hex!!", "", "ABCDEF"] {
            assert!(matches!(store.get(bad), Err(StorageError::Blob(_))));
            assert!(!store.has(bad), "has must be false for invalid hash {bad}");
            assert!(matches!(store.remove(bad), Err(StorageError::Blob(_))));
        }

        // Nothing outside assets was touched.
        assert!(!dir.path().join("etc").exists());
    }

    #[test]
    fn corrupted_blob_is_rejected_on_read() {
        let dir = tempdir().unwrap();
        let assets = dir.path().join("assets");
        let store = BlobStore::open(&assets).unwrap();

        // Claim a valid hash but store mismatched garbage under it.
        let claimed = BlobStore::hash(b"the real bytes");
        fs::write(assets.join(&claimed), b"tampered content").unwrap();

        // A hash/content mismatch is corruption: error, never wrong bytes.
        assert!(matches!(store.get(&claimed), Err(StorageError::Blob(_))));
    }

    #[test]
    fn remove_deletes_and_tolerates_absent() {
        let dir = tempdir().unwrap();
        let store = open(&dir);
        let hash = store.put(b"delete me").unwrap();
        assert!(store.has(&hash));

        store.remove(&hash).unwrap();
        assert!(!store.has(&hash));

        // Removing an absent (but valid) hash is not an error.
        store.remove(&hash).unwrap();
    }

    #[test]
    fn list_returns_stored_hashes() {
        let dir = tempdir().unwrap();
        let store = open(&dir);
        let a = store.put(b"one").unwrap();
        let b = store.put(b"two").unwrap();

        let mut listed = store.list().unwrap();
        listed.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(listed, expected);
    }

    #[test]
    fn binary_bytes_round_trip() {
        let dir = tempdir().unwrap();
        let store = open(&dir);
        let payload: Vec<u8> = vec![0x00, 0xff, 0x00, 0x01, 0xfe, 0x80, 0x7f, 0x00];
        let hash = store.put(&payload).unwrap();
        assert_eq!(store.get(&hash).unwrap(), Some(payload));
    }

    #[test]
    fn size_reports_byte_length_and_none_when_absent() {
        let dir = tempdir().unwrap();
        let store = open(&dir);
        let hash = store.put(b"12345").unwrap();
        assert_eq!(store.size(&hash).unwrap(), Some(5));
        assert_eq!(store.size(&BlobStore::hash(b"absent")).unwrap(), None);
    }
}
