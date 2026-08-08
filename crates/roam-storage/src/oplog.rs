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
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        file.write_all(&json)?;
        file.sync_all()?;
        Ok(())
    }

    /// Read every entry, verifying each signature against `key`.
    /// Returns `Err` on the first tampered or malformed line.
    pub fn read_verified(&self, key: &VerifyingKey) -> Result<Vec<Entry>, StorageError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let parsed: EntryLine =
                serde_json::from_str(line).map_err(|e| StorageError::MalformedEntry(e.to_string()))?;
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
}
