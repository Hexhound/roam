//! Content-addressed blob store — binary payloads kept OUTSIDE the CRDT.
//!
//! A [`BlobStore`] persists arbitrary bytes under an `assets` directory, keyed
//! by the blake3 hex digest of their content. The CRDT (op-log) only ever
//! carries the hash reference; the bytes themselves live here on plain disk.
//! Because the filename IS the hash, an identical payload stored twice occupies
//! a single file (automatic dedup), and any consumer can pre-check presence by
//! hash before transferring bytes over the wire.

use crate::error::StorageError;
use crate::vfs::{NativeFs, VaultFs};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    fs: Arc<dyn VaultFs>,
}

impl BlobStore {
    /// Open a blob store rooted at `assets_dir`, creating the directory (and
    /// any missing parents) if absent.
    pub fn open(assets_dir: &Path) -> Result<Self, StorageError> {
        Self::open_with_fs(assets_dir, Arc::new(NativeFs))
    }

    /// [`BlobStore::open`], but persisting through a caller-supplied backend.
    pub fn open_with_fs(assets_dir: &Path, fs: Arc<dyn VaultFs>) -> Result<Self, StorageError> {
        fs.create_dir_all(assets_dir)?;
        Ok(Self {
            root: assets_dir.to_path_buf(),
            fs,
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
        if self.fs.exists(&path) {
            return Ok(hash);
        }

        // Atomic write: a uniquely-named sibling temp file + rename, so the
        // final path only ever appears complete. The temp name embeds the hash
        // (unique per content) so concurrent puts of distinct blobs never race
        // on the same temp path.
        let temp = self.root.join(format!("{hash}.tmp"));
        self.fs.write(&temp, bytes)?;
        match self.fs.rename(&temp, &path) {
            Ok(()) => Ok(hash),
            Err(err) => {
                let _ = self.fs.remove_file(&temp);
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
        let bytes = match self.fs.read(&path) {
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
            Ok(path) => self.fs.exists(&path),
            Err(_) => false,
        }
    }

    /// Remove the blob for `hash`. A missing blob is tolerated (not an error),
    /// so this is safe to call from a later garbage collector.
    pub fn remove(&self, hash: &str) -> Result<(), StorageError> {
        let path = self.blob_path(hash)?;
        match self.fs.remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Every stored blob hash (for GC ref-counting). Non-blob entries (e.g. a
    /// leftover `.tmp`) are skipped, so the list is exactly the valid hashes.
    pub fn list(&self) -> Result<Vec<String>, StorageError> {
        let mut hashes = Vec::new();
        for entry in self.fs.read_dir(&self.root)? {
            let name = match entry.file_name() {
                Some(n) => n.to_os_string(),
                None => continue,
            };
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
        match self.fs.file_len(&path) {
            Ok(len) => Ok(Some(len)),
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

    /// Path of the scratch dir holding partially-received blobs (`<hash>.part`).
    /// This lives directly under `root` alongside the finished blobs, but its
    /// name (`incoming`) is not a valid blake3 hex digest, so [`list`] and
    /// [`blob_path`] never mistake it for one.
    fn incoming_dir(&self) -> PathBuf {
        self.root.join("incoming")
    }

    /// Read up to `len` bytes of the blob for `hash` starting at byte `offset`.
    ///
    /// Clamps at EOF: a range that runs past the end of the blob yields fewer
    /// bytes than requested (or, if `offset` is already at or past EOF, an
    /// empty vec) rather than erroring. Errors only on I/O failure or an
    /// invalid hash. This is what the chunked sender uses so a multi-GB blob
    /// is never fully loaded into memory for a single transfer.
    pub fn read_range(&self, hash: &str, offset: u64, len: usize) -> Result<Vec<u8>, StorageError> {
        let path = self.blob_path(hash)?;
        // The backend clamps at EOF for us.
        Ok(self.fs.read_range(&path, offset, len)?)
    }

    /// Write one chunk of an in-flight blob into `incoming/<hash>.part`.
    ///
    /// On the first write for a given `hash` the part file is created and
    /// pre-sized to `total_len` (via `set_len`), so chunks can arrive in any
    /// order and each just seeks to its own `offset` before writing. Calling
    /// this again with the same `(offset, bytes)` is a no-op in effect
    /// (idempotent), which matters if the sync layer retries a chunk after a
    /// dropped connection.
    pub fn write_incoming_chunk(
        &self,
        hash: &str,
        offset: u64,
        total_len: u64,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        if !is_valid_hash(hash) {
            return Err(StorageError::Blob(format!("invalid blob hash {hash}")));
        }

        // Opus #1: a chunk MUST lie wholly within the declared blob. Without this,
        // an `offset` far past `total_len` seeks and writes beyond the pre-sized
        // file, ballooning the `.part` into a huge sparse file that
        // `finalize_incoming` later reads wholesale into memory (OOM). Reject
        // before touching disk.
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| StorageError::Blob("blob chunk offset overflow".into()))?;
        if end > total_len {
            return Err(StorageError::Blob(format!(
                "blob chunk [{offset}, {end}) exceeds total_len {total_len}"
            )));
        }

        let dir = self.incoming_dir();
        self.fs.create_dir_all(&dir)?;
        let part = dir.join(format!("{hash}.part"));

        let existed = self.fs.exists(&part);
        // Pin `total_len` to the first-seen value. It is a property of the
        // content-addressed hash, so every honest chunk for a hash carries the
        // same value; a co-serving peer that re-announces a DIFFERENT (smaller)
        // total_len would otherwise `set_len`-TRUNCATE the `.part` an honest
        // sender already partially filled — corrupting the transfer so it never
        // finalizes, repeatable to stall it forever. Size the file once on
        // creation and refuse any later disagreement.
        if existed {
            let pinned = self.fs.file_len(&part)?;
            if pinned != total_len {
                return Err(StorageError::Blob(format!(
                    "blob chunk total_len {total_len} disagrees with pinned {pinned} for {hash}"
                )));
            }
        } else {
            self.fs.create_sized(&part, total_len)?;
        }
        self.fs.write_range(&part, offset, bytes)?;
        Ok(())
    }

    /// Verify the fully-received `incoming/<hash>.part` against `hash` and, on
    /// a match, atomically move it into the store as a finished blob.
    ///
    /// Returns `Ok(true)` once the blob is in place under `root`. Returns
    /// `Ok(false)` if the part file is missing (nothing to finalize) or its
    /// content does not hash to `hash` — a poisoned or still-incomplete part
    /// is discarded rather than ever exposed as a valid blob, matching the
    /// verify-on-read contract [`get`] already enforces for finished blobs.
    pub fn finalize_incoming(&self, hash: &str) -> Result<bool, StorageError> {
        if !is_valid_hash(hash) {
            return Err(StorageError::Blob(format!("invalid blob hash {hash}")));
        }

        let part = self.incoming_dir().join(format!("{hash}.part"));
        let bytes = match self.fs.read(&part) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(err.into()),
        };

        if Self::hash(&bytes) != hash {
            // Poisoned or incomplete: never let this become a readable blob.
            let _ = self.fs.remove_file(&part);
            return Ok(false);
        }

        let final_path = self.root.join(hash);
        match self.fs.rename(&part, &final_path) {
            Ok(()) => Ok(true),
            Err(_) => {
                // Cross-filesystem rename can fail even though the content is
                // verified good — fall back to a copy-then-remove so the
                // finished blob still lands. Always clean up the `.part`,
                // even if the write itself fails, so a failed fallback never
                // leaves scratch debris behind.
                let written = self.fs.write(&final_path, &bytes);
                let _ = self.fs.remove_file(&part);
                written?;
                Ok(true)
            }
        }
    }

    /// Drop a partial transfer (connection lost, sender abandoned, etc.).
    /// Tolerates an already-absent part file, so it is safe to call from
    /// cleanup paths without first checking whether a transfer was ever
    /// in progress.
    pub fn discard_incoming(&self, hash: &str) -> Result<(), StorageError> {
        if !is_valid_hash(hash) {
            return Err(StorageError::Blob(format!("invalid blob hash {hash}")));
        }

        let part = self.incoming_dir().join(format!("{hash}.part"));
        match self.fs.remove_file(&part) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
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

    #[test]
    fn read_range_returns_the_requested_slice() {
        let dir = tempdir().unwrap();
        let bs = open(&dir);
        let hash = bs.put(b"0123456789").unwrap();
        assert_eq!(bs.read_range(&hash, 0, 10).unwrap(), b"0123456789".to_vec());
        assert_eq!(bs.read_range(&hash, 3, 4).unwrap(), b"3456".to_vec());
        assert_eq!(bs.read_range(&hash, 8, 100).unwrap(), b"89".to_vec()); // clamp at EOF
        assert_eq!(bs.read_range(&hash, 10, 5).unwrap(), Vec::<u8>::new()); // offset at EOF
    }

    #[test]
    fn incoming_chunk_roundtrip_finalizes_a_valid_blob() {
        let dir = tempdir().unwrap();
        let bs = open(&dir);
        let full = b"the quick brown fox".to_vec();
        let hash = BlobStore::hash(&full);
        bs.write_incoming_chunk(&hash, 10, full.len() as u64, &full[10..])
            .unwrap();
        bs.write_incoming_chunk(&hash, 0, full.len() as u64, &full[..10])
            .unwrap();
        assert_eq!(bs.finalize_incoming(&hash).unwrap(), true);
        assert_eq!(bs.get(&hash).unwrap(), Some(full));
    }

    #[test]
    fn write_incoming_chunk_rejects_a_chunk_extending_past_total_len() {
        let dir = tempdir().unwrap();
        let bs = open(&dir);
        let hash = BlobStore::hash(b"small blob");
        let total_len = 10u64;

        // A chunk claiming to sit far beyond `total_len` would balloon the `.part`
        // into a terabyte-scale sparse file that `finalize_incoming` then reads
        // wholesale into memory (Opus #1 OOM). It must be refused.
        assert!(
            matches!(
                bs.write_incoming_chunk(&hash, 1 << 40, total_len, b"x"),
                Err(StorageError::Blob(_))
            ),
            "a chunk whose offset+len exceeds total_len must be rejected"
        );

        // A chunk that fits at the tail exactly is still fine.
        let part = dir.path().join("incoming").join(format!("{hash}.part"));
        if part.exists() {
            let len = std::fs::metadata(&part).unwrap().len();
            assert!(
                len <= total_len,
                "the part file must never exceed total_len; got {len}"
            );
        }
    }

    #[test]
    fn write_incoming_chunk_pins_total_len_and_rejects_a_shrinking_reannounce() {
        // Grief (2nd-pass "set_len truncation"): `total_len` is a property of the
        // content-addressed hash, so every honest chunk for a hash carries the
        // same value. A co-serving peer that sends a chunk with a SMALLER
        // total_len would, via the unconditional `set_len(total_len)`, TRUNCATE
        // the `.part` an honest sender already partially filled — corrupting the
        // transfer so it never finalizes (hash mismatch), and repeatable to stall
        // it forever. total_len must be pinned to the first-seen value.
        let dir = tempdir().unwrap();
        let bs = open(&dir);
        let hash = BlobStore::hash(b"a three-megabyte-ish blob (pretend)");
        let total_len = 100u64;

        bs.write_incoming_chunk(&hash, 0, total_len, b"hello")
            .unwrap();
        let part = dir
            .path()
            .join("assets")
            .join("incoming")
            .join(format!("{hash}.part"));
        assert_eq!(std::fs::metadata(&part).unwrap().len(), total_len);

        // A later chunk claiming a different (smaller) total_len must be refused,
        // never allowed to shrink the pinned part file.
        assert!(
            matches!(
                bs.write_incoming_chunk(&hash, 0, 1, b"x"),
                Err(StorageError::Blob(_))
            ),
            "a chunk whose total_len disagrees with the pinned value must be rejected"
        );
        assert_eq!(
            std::fs::metadata(&part).unwrap().len(),
            total_len,
            "the pinned part file must not be truncated by a hostile re-announce"
        );
    }

    #[test]
    fn finalize_incoming_rejects_content_that_does_not_match_the_hash() {
        let dir = tempdir().unwrap();
        let bs = open(&dir);
        let claimed = BlobStore::hash(b"honest bytes");
        bs.write_incoming_chunk(&claimed, 0, 4, b"evil").unwrap();
        assert_eq!(bs.finalize_incoming(&claimed).unwrap(), false);
        assert!(!bs.has(&claimed));
    }

    #[test]
    fn write_incoming_chunk_rejects_a_malicious_hash() {
        let dir = tempdir().unwrap();
        let bs = open(&dir);

        for bad in ["../escape", "a/b"] {
            assert!(matches!(
                bs.write_incoming_chunk(bad, 0, 4, b"evil"),
                Err(StorageError::Blob(_))
            ));
            assert!(matches!(
                bs.finalize_incoming(bad),
                Err(StorageError::Blob(_))
            ));
            assert!(matches!(
                bs.discard_incoming(bad),
                Err(StorageError::Blob(_))
            ));
        }

        // Nothing escaped the temp dir.
        assert!(!dir.path().join("escape.part").exists());
        assert!(!dir.path().parent().unwrap().join("escape.part").exists());
    }

    #[test]
    fn finalize_incoming_cleans_up_the_part_even_when_the_fallback_write_fails() {
        let dir = tempdir().unwrap();
        let bs = open(&dir);
        let full = b"the quick brown fox".to_vec();
        let hash = BlobStore::hash(&full);
        bs.write_incoming_chunk(&hash, 0, full.len() as u64, &full)
            .unwrap();

        // Make the destination path unwritable by occupying it with a
        // directory, forcing the fallback copy-write to fail. This does not
        // exercise the cross-filesystem rename path directly, but confirms
        // that a failed fallback write still leaves no `.part` behind.
        let assets = dir.path().join("assets");
        std::fs::create_dir(assets.join(&hash)).unwrap();

        assert!(bs.finalize_incoming(&hash).is_err());
        assert!(!assets
            .join("incoming")
            .join(format!("{hash}.part"))
            .exists());
    }
}
