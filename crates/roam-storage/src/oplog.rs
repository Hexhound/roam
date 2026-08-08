use crate::error::StorageError;
use crate::identity::{Identity, VerifyingKey};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// One signed update in a peer's append-only log.
#[derive(Debug, Clone)]
pub struct Entry {
    pub peer_id: u64,
    pub update: Vec<u8>,
}

/// JSONL wire form of an [`Entry`].
#[derive(Serialize, Deserialize)]
struct EntryLine {
    peer: u64,
    /// base64 of the ed25519 signature over `update` bytes.
    sig: String,
    /// base64 of the loro update blob.
    update: String,
}

/// An append-only, per-peer log of signed loro update blobs
/// (`<dir>/ops-<peer>.jsonl`). This is the durable "op-log-is-truth" record.
pub struct OpLog {
    path: PathBuf,
    peer_id: u64,
}

impl OpLog {
    /// Open (do not create yet) the log for `peer_id` under `dir`.
    pub fn new(dir: &Path, peer_id: u64) -> Self {
        Self {
            path: dir.join(format!("ops-{peer_id}.jsonl")),
            peer_id,
        }
    }

    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    /// Sign `update` with `id` and append it as one JSONL line.
    pub fn append(&self, id: &Identity, update: &[u8]) -> Result<(), StorageError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let sig = id.sign(update);
        let line = EntryLine {
            peer: self.peer_id,
            sig: B64.encode(sig.to_bytes()),
            update: B64.encode(update),
        };
        let mut json = serde_json::to_vec(&line)?;
        json.push(b'\n');

        // Whether this append creates the file (vs. extends an existing one).
        let is_create = !self.path.exists();

        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        file.write_all(&json)?;
        file.sync_all()?;

        // On file creation, the new directory entry itself must be flushed, or a
        // power failure can lose the whole file (and thus the first op) despite
        // the content sync above. Only needed on create; append-to-existing is fine.
        #[cfg(unix)]
        if is_create {
            if let Some(dir) = self.path.parent() {
                if let Ok(d) = std::fs::File::open(dir) {
                    let _ = d.sync_all();
                }
            }
        }
        Ok(())
    }

    /// Read every entry, verifying each signature against `key`.
    ///
    /// Fails closed: returns `Err` on the first tampered, malformed, or
    /// wrong-peer line. The one tolerated corruption is a **torn tail** — a
    /// crash mid-append can leave a partial final line with no trailing
    /// newline; that single incomplete last line is dropped rather than
    /// bricking the whole log. Interior malformed lines are still errors.
    ///
    /// Assumes a single writer per file (the log is per-peer: `ops-<peer>.jsonl`).
    pub fn read_verified(&self, key: &VerifyingKey) -> Result<Vec<Entry>, StorageError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        self.verify_text(key, &text)
    }

    /// Verify raw log `bytes` (as received from a peer) WITHOUT touching disk.
    /// Same rules as [`OpLog::read_verified`]; lets a caller check bytes before
    /// persisting them. Invalid UTF-8 is a malformed log.
    pub fn verify_bytes(&self, key: &VerifyingKey, bytes: &[u8]) -> Result<Vec<Entry>, StorageError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| StorageError::MalformedEntry(e.to_string()))?;
        self.verify_text(key, text)
    }

    fn verify_text(&self, key: &VerifyingKey, text: &str) -> Result<Vec<Entry>, StorageError> {
        // A completed append always ends with '\n'. A missing trailing newline
        // means the final line was torn by a crash and may be tolerated.
        let torn_tail = !text.is_empty() && !text.ends_with('\n');
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        let last = lines.len().saturating_sub(1);

        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let parsed: EntryLine = match serde_json::from_str(line) {
                Ok(p) => p,
                // Tolerate a parse failure ONLY on a torn final line.
                Err(_) if i == last && torn_tail => break,
                Err(e) => return Err(StorageError::MalformedEntry(e.to_string())),
            };
            // The on-disk `peer` is untrusted metadata; it must match this log's
            // owner, or the entry is not authentically ours.
            if parsed.peer != self.peer_id {
                return Err(StorageError::BadSignature(parsed.peer));
            }
            let update = B64
                .decode(parsed.update.as_bytes())
                .map_err(|e| StorageError::MalformedEntry(e.to_string()))?;
            let sig_bytes = B64
                .decode(parsed.sig.as_bytes())
                .map_err(|e| StorageError::MalformedEntry(e.to_string()))?;
            let sig_arr: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| StorageError::MalformedEntry("signature length".into()))?;
            let sig = Signature::from_bytes(&sig_arr);
            if !key.verify(&update, &sig) {
                return Err(StorageError::BadSignature(parsed.peer));
            }
            out.push(Entry { peer_id: parsed.peer, update });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use tempfile::tempdir;

    #[test]
    fn appends_and_reads_back_verified_entries() {
        let dir = tempdir().unwrap();
        let id = Identity::generate();
        let log = OpLog::new(dir.path(), id.peer_id());

        log.append(&id, b"update-one").unwrap();
        log.append(&id, b"update-two").unwrap();

        let entries = log.read_verified(&id.verifying_key()).unwrap();
        let payloads: Vec<&[u8]> = entries.iter().map(|e| e.update.as_slice()).collect();
        assert_eq!(payloads, vec![b"update-one".as_ref(), b"update-two".as_ref()]);
    }

    #[test]
    fn rejects_a_tampered_entry() {
        use crate::error::StorageError;
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        let dir = tempdir().unwrap();
        let id = Identity::generate();
        let log = OpLog::new(dir.path(), id.peer_id());
        log.append(&id, b"legit").unwrap();

        // Rewrite the stored `update` payload to different bytes, leaving the old
        // signature in place — so verification must fail.
        let path = log.path();
        let line = std::fs::read_to_string(&path).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        v["update"] = serde_json::Value::String(B64.encode(b"tampered!"));
        std::fs::write(&path, format!("{}\n", v)).unwrap();

        let result = log.read_verified(&id.verifying_key());
        assert!(
            matches!(result, Err(StorageError::BadSignature(_))),
            "tampered payload must fail signature verification, got {result:?}"
        );
    }

    #[test]
    fn tolerates_a_torn_final_line_but_keeps_prior_entries() {
        let dir = tempdir().unwrap();
        let id = Identity::generate();
        let log = OpLog::new(dir.path(), id.peer_id());
        log.append(&id, b"good-one").unwrap();
        log.append(&id, b"good-two").unwrap();

        // Simulate a crash mid-append: append a partial line with NO newline.
        let path = log.path();
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        std::io::Write::write_all(&mut file, br#"{"peer":1,"sig":"broke"#).unwrap();

        // The two complete entries survive; the torn tail is dropped.
        let entries = log.read_verified(&id.verifying_key()).unwrap();
        let payloads: Vec<&[u8]> = entries.iter().map(|e| e.update.as_slice()).collect();
        assert_eq!(payloads, vec![b"good-one".as_ref(), b"good-two".as_ref()]);
    }

    #[test]
    fn rejects_a_malformed_interior_line() {
        use crate::error::StorageError;
        let dir = tempdir().unwrap();
        let id = Identity::generate();
        let log = OpLog::new(dir.path(), id.peer_id());
        log.append(&id, b"first").unwrap();
        log.append(&id, b"second").unwrap();

        // Corrupt the FIRST (interior) line into invalid JSON; file still ends with '\n'.
        let path = log.path();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines[0] = "{not valid json";
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        // An interior malformed line is real corruption — must error, not be skipped.
        assert!(matches!(
            log.read_verified(&id.verifying_key()),
            Err(StorageError::MalformedEntry(_))
        ));
    }

    #[test]
    fn rejects_an_entry_claiming_a_different_peer() {
        use crate::error::StorageError;
        let dir = tempdir().unwrap();
        let id = Identity::generate();
        let log = OpLog::new(dir.path(), id.peer_id());
        log.append(&id, b"mine").unwrap();

        // Flip the on-disk `peer` field to a value that isn't this log's owner.
        let path = log.path();
        let line = std::fs::read_to_string(&path).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        v["peer"] = serde_json::Value::from(id.peer_id().wrapping_add(1));
        std::fs::write(&path, format!("{}\n", v)).unwrap();

        assert!(matches!(
            log.read_verified(&id.verifying_key()),
            Err(StorageError::BadSignature(_))
        ));
    }
}
