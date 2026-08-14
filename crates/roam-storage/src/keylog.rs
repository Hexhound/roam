//! The key-log: a signed, append-only, per-author JSONL log
//! (`<dir>/keylog-<author>.jsonl`) distributing epoch keys P2P. Sibling to the
//! roster log; clones its durability + torn-tail + verify rules. NEVER uploaded
//! to the backend.

use crate::error::StorageError;
use crate::identity::{Identity, VerifyingKey};
use crate::vfs::{NativeFs, VaultFs};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Who an epoch key is wrapped to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Recipient {
    /// A device, identified by its loro/roster peer id.
    Device(u64),
    /// The vault's opt-in paper recovery key (single paper key per vault).
    Paper,
}

/// The body of a key-log entry. Both variants name an `epoch_id` (carried on the
/// entry, not here). A `Rotate` announces an epoch's DAG metadata (cleartext, no
/// key material); a `Wrap` delivers the epoch key to one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyBody {
    Rotate {
        parent_epochs: Vec<[u8; 32]>,
        nonce: [u8; 32],
    },
    Wrap {
        recipient: Recipient,
        /// Sealed-box blob from [`crate::keywrap::wrap`].
        blob: Vec<u8>,
    },
}

/// One signed key-log entry. Signed by `author`, who MUST be a current roster
/// member (enforced by the replaying `Store`, exactly like roster ops).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLogEntry {
    pub seq: u64,
    pub author: u64,
    pub epoch_id: [u8; 32],
    pub body: KeyBody,
}

impl KeyLogEntry {
    /// Deterministic signed bytes. Domain-separated; encodes a discriminant per
    /// body so a `Rotate` can never be reinterpreted as a `Wrap`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"roam.keylog.v1");
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.extend_from_slice(&self.author.to_le_bytes());
        buf.extend_from_slice(&self.epoch_id);
        match &self.body {
            KeyBody::Rotate {
                parent_epochs,
                nonce,
            } => {
                buf.push(0);
                buf.extend_from_slice(&(parent_epochs.len() as u64).to_le_bytes());
                for p in parent_epochs {
                    buf.extend_from_slice(p);
                }
                buf.extend_from_slice(nonce);
            }
            KeyBody::Wrap { recipient, blob } => {
                buf.push(1);
                match recipient {
                    Recipient::Device(p) => {
                        buf.push(0);
                        buf.extend_from_slice(&p.to_le_bytes());
                    }
                    Recipient::Paper => buf.push(1),
                }
                buf.extend_from_slice(&(blob.len() as u64).to_le_bytes());
                buf.extend_from_slice(blob);
            }
        }
        buf
    }
}

/// JSONL wire/disk form.
#[derive(Serialize, Deserialize)]
struct KeyLine {
    seq: u64,
    author: u64,
    epoch_id: String, // base64 [u8;32]
    body: KeyBodyLine,
    sig: String, // base64 ed25519 sig over canonical_bytes()
}

#[derive(Serialize, Deserialize)]
enum KeyBodyLine {
    Rotate { parents: Vec<String>, nonce: String },
    Wrap { recipient: Recipient, blob: String },
}

fn b64_32(s: &str) -> Result<[u8; 32], StorageError> {
    let v = B64
        .decode(s.as_bytes())
        .map_err(|e| StorageError::MalformedEntry(e.to_string()))?;
    v.try_into()
        .map_err(|_| StorageError::MalformedEntry("expected 32 bytes".into()))
}

/// An append-only per-device signed key log (`<dir>/keylog-<author>.jsonl`).
pub struct KeyLog {
    path: PathBuf,
    author: u64,
    fs: Arc<dyn VaultFs>,
}

impl KeyLog {
    pub fn new(dir: &Path, author: u64) -> Self {
        Self::new_with_fs(dir, author, Arc::new(NativeFs))
    }

    /// [`KeyLog::new`], but persisting through a caller-supplied backend.
    pub fn new_with_fs(dir: &Path, author: u64, fs: Arc<dyn VaultFs>) -> Self {
        Self {
            path: dir.join(format!("keylog-{author}.jsonl")),
            author,
            fs,
        }
    }

    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    pub fn last_seq(&self, key: &VerifyingKey) -> Result<u64, StorageError> {
        Ok(self.read_verified(key)?.last().map(|e| e.seq).unwrap_or(0))
    }

    /// Sign `body` for `epoch_id` with `id` (== this log's author) and append it.
    pub fn append(
        &self,
        id: &Identity,
        epoch_id: [u8; 32],
        body: KeyBody,
    ) -> Result<KeyLogEntry, StorageError> {
        if id.peer_id() != self.author {
            return Err(StorageError::Peer(format!(
                "identity {} may not author keylog of {}",
                id.peer_id(),
                self.author
            )));
        }
        if let Some(parent) = self.path.parent() {
            self.fs.create_dir_all(parent)?;
        }
        let seq = self.last_seq(&id.verifying_key())? + 1;
        let entry = KeyLogEntry {
            seq,
            author: self.author,
            epoch_id,
            body,
        };
        let sig = id.sign(&entry.canonical_bytes());

        let body_line = match &entry.body {
            KeyBody::Rotate {
                parent_epochs,
                nonce,
            } => KeyBodyLine::Rotate {
                parents: parent_epochs.iter().map(|p| B64.encode(p)).collect(),
                nonce: B64.encode(nonce),
            },
            KeyBody::Wrap { recipient, blob } => KeyBodyLine::Wrap {
                recipient: *recipient,
                blob: B64.encode(blob),
            },
        };
        let line = KeyLine {
            seq: entry.seq,
            author: entry.author,
            epoch_id: B64.encode(entry.epoch_id),
            body: body_line,
            sig: B64.encode(sig.to_bytes()),
        };
        let mut json = serde_json::to_vec(&line)?;
        json.push(b'\n');

        // Durable append: key material must not be lost to a power failure.
        self.fs.append_sync(&self.path, &json)?;
        Ok(entry)
    }

    pub fn read_verified(&self, key: &VerifyingKey) -> Result<Vec<KeyLogEntry>, StorageError> {
        let text = match self.fs.read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        self.verify_text(key, &text)
    }

    pub fn verify_bytes(
        &self,
        key: &VerifyingKey,
        bytes: &[u8],
    ) -> Result<Vec<KeyLogEntry>, StorageError> {
        let text =
            std::str::from_utf8(bytes).map_err(|e| StorageError::MalformedEntry(e.to_string()))?;
        self.verify_text(key, text)
    }

    fn verify_text(
        &self,
        key: &VerifyingKey,
        text: &str,
    ) -> Result<Vec<KeyLogEntry>, StorageError> {
        let torn_tail = !text.is_empty() && !text.ends_with('\n');
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        let last = lines.len().saturating_sub(1);
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let parsed: KeyLine = match serde_json::from_str(line) {
                Ok(p) => p,
                Err(_) if i == last && torn_tail => break,
                Err(e) => return Err(StorageError::MalformedEntry(e.to_string())),
            };
            if parsed.author != self.author {
                return Err(StorageError::BadSignature(parsed.author));
            }
            let body = match parsed.body {
                KeyBodyLine::Rotate { parents, nonce } => {
                    let mut ps = Vec::with_capacity(parents.len());
                    for p in &parents {
                        ps.push(b64_32(p)?);
                    }
                    KeyBody::Rotate {
                        parent_epochs: ps,
                        nonce: b64_32(&nonce)?,
                    }
                }
                KeyBodyLine::Wrap { recipient, blob } => KeyBody::Wrap {
                    recipient,
                    blob: B64
                        .decode(blob.as_bytes())
                        .map_err(|e| StorageError::MalformedEntry(e.to_string()))?,
                },
            };
            let sig_bytes = B64
                .decode(parsed.sig.as_bytes())
                .map_err(|e| StorageError::MalformedEntry(e.to_string()))?;
            let sig_arr: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| StorageError::MalformedEntry("signature length".into()))?;
            let sig = Signature::from_bytes(&sig_arr);
            let entry = KeyLogEntry {
                seq: parsed.seq,
                author: parsed.author,
                epoch_id: b64_32(&parsed.epoch_id)?,
                body,
            };
            if !key.verify(&entry.canonical_bytes(), &sig) {
                return Err(StorageError::BadSignature(self.author));
            }
            out.push(entry);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn appends_and_reads_back_rotate_and_wrap() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let log = KeyLog::new(dir.path(), a.peer_id());

        let e1 = log
            .append(
                &a,
                [7u8; 32],
                KeyBody::Rotate {
                    parent_epochs: vec![[0u8; 32]],
                    nonce: [9u8; 32],
                },
            )
            .unwrap();
        assert_eq!(e1.seq, 1);
        let e2 = log
            .append(
                &a,
                [7u8; 32],
                KeyBody::Wrap {
                    recipient: Recipient::Device(a.peer_id()),
                    blob: vec![1, 2, 3],
                },
            )
            .unwrap();
        assert_eq!(e2.seq, 2);

        let got = log.read_verified(&a.verifying_key()).unwrap();
        assert_eq!(got.len(), 2);
        assert!(matches!(got[0].body, KeyBody::Rotate { .. }));
        assert!(matches!(got[1].body, KeyBody::Wrap { .. }));
    }

    #[test]
    fn rejects_a_tampered_entry() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let log = KeyLog::new(dir.path(), a.peer_id());
        log.append(
            &a,
            [7u8; 32],
            KeyBody::Rotate {
                parent_epochs: vec![],
                nonce: [9u8; 32],
            },
        )
        .unwrap();

        let path = log.path();
        let line = std::fs::read_to_string(&path).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        v["seq"] = serde_json::Value::from(999u64);
        std::fs::write(&path, format!("{}\n", v)).unwrap();
        assert!(matches!(
            log.read_verified(&a.verifying_key()),
            Err(StorageError::BadSignature(_))
        ));
    }

    #[test]
    fn append_rejects_wrong_author() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let other = Identity::generate();
        let log = KeyLog::new(dir.path(), a.peer_id());
        let err = log.append(
            &other,
            [0u8; 32],
            KeyBody::Rotate {
                parent_epochs: vec![],
                nonce: [0u8; 32],
            },
        );
        assert!(matches!(err, Err(StorageError::Peer(_))));
    }

    #[test]
    fn tolerates_a_torn_final_line() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let log = KeyLog::new(dir.path(), a.peer_id());
        log.append(
            &a,
            [7u8; 32],
            KeyBody::Rotate {
                parent_epochs: vec![],
                nonce: [9u8; 32],
            },
        )
        .unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap();
        std::io::Write::write_all(&mut f, br#"{"seq":2,"author":1"#).unwrap();
        assert_eq!(log.read_verified(&a.verifying_key()).unwrap().len(), 1);
    }
}
