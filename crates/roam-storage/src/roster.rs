use crate::error::StorageError;
use crate::identity::{Identity, VerifyingKey};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// A membership change. Basic revocation only in Slice 2 (stop accepting a
/// peer's ops); key rotation / compromise-recovery is deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RosterOp {
    Add,
    Revoke,
}

/// One signed roster entry. Signed by `added_by` (an already-trusted device).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    pub seq: u64,
    pub op: RosterOp,
    pub subject_peer: u64,
    /// The subject's ed25519 verifying key — ALSO its iroh NodeId.
    pub subject_key: [u8; 32],
    pub added_by: u64,
}

/// JSONL wire/disk form. The signature covers `canonical_bytes()`.
#[derive(Serialize, Deserialize)]
struct RosterLine {
    seq: u64,
    op: RosterOp,
    subject_peer: u64,
    subject_key: String, // base64 of [u8;32]
    added_by: u64,
    sig: String, // base64 of the ed25519 signature over canonical_bytes()
}

impl RosterEntry {
    /// Deterministic bytes that the signature is computed over. MUST be stable
    /// across encode/decode (do not sign the JSON — field order/formatting is
    /// not guaranteed).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 8 + 1 + 8 + 32 + 8);
        buf.extend_from_slice(b"roam.roster.v1");
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.push(match self.op {
            RosterOp::Add => 0,
            RosterOp::Revoke => 1,
        });
        buf.extend_from_slice(&self.subject_peer.to_le_bytes());
        buf.extend_from_slice(&self.subject_key);
        buf.extend_from_slice(&self.added_by.to_le_bytes());
        buf
    }
}

/// Whether a peer's ops are currently accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    Active,
    Revoked,
}

/// A materialized, deduped view of one peer derived from all roster logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    pub peer_id: u64,
    /// ed25519 verifying key == iroh NodeId.
    pub verifying_key: [u8; 32],
    pub status: PeerStatus,
}

/// Fold a set of verified roster entries into the current peer set. Later
/// entries (by any author) win: a `Revoke` after an `Add` yields `Revoked`.
/// Entries are applied in a deterministic order: (subject_peer, added_by, seq).
pub fn merge_roster(entries: &mut [RosterEntry]) -> Vec<PeerRecord> {
    use std::collections::BTreeMap;
    entries.sort_by_key(|e| (e.subject_peer, e.added_by, e.seq));
    let mut out: BTreeMap<u64, PeerRecord> = BTreeMap::new();
    for e in entries.iter() {
        // Defense against a malicious trusted author injecting a mismatched
        // entry: every peer_id MUST be the first 8 LE bytes of its key. Drop
        // (don't brick the whole log on) an entry that breaks that binding.
        if e.subject_peer != u64::from_le_bytes(e.subject_key[0..8].try_into().unwrap()) {
            continue;
        }
        let rec = out.entry(e.subject_peer).or_insert(PeerRecord {
            peer_id: e.subject_peer,
            verifying_key: e.subject_key,
            status: PeerStatus::Active,
        });
        rec.verifying_key = e.subject_key;
        // Revocation is terminal in Slice 2 (prefer-deny): once ANY trusted
        // author revokes a subject, no later Add from any author resurrects it.
        // Key rotation / un-revoke is deferred. This makes status order-independent
        // (`seq` is per-author, so it cannot order cross-author entries) and blocks
        // the stolen-device attack where a stale Add masks a Revoke.
        if e.op == RosterOp::Revoke {
            rec.status = PeerStatus::Revoked;
        }
    }
    out.into_values().collect()
}

/// An append-only, per-device signed roster log (`<dir>/roster-<peer>.jsonl`).
/// Same durability + torn-tail rules as [`crate::OpLog`].
pub struct RosterLog {
    path: PathBuf,
    author: u64,
}

impl RosterLog {
    pub fn new(dir: &Path, author: u64) -> Self {
        Self {
            path: dir.join(format!("roster-{author}.jsonl")),
            author,
        }
    }

    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    /// Highest `seq` already written (0 if empty). The next append uses `seq+1`.
    pub fn last_seq(&self, key: &VerifyingKey) -> Result<u64, StorageError> {
        Ok(self.read_verified(key)?.last().map(|e| e.seq).unwrap_or(0))
    }

    /// Sign `op` for `subject` with `id` (which MUST be this log's author) and
    /// append it as one JSONL line.
    pub fn append(
        &self,
        id: &Identity,
        op: RosterOp,
        subject_peer: u64,
        subject_key: [u8; 32],
    ) -> Result<RosterEntry, StorageError> {
        // A device may only author its own roster.
        if id.peer_id() != self.author {
            return Err(StorageError::Peer(format!(
                "identity {} may not author roster of {}",
                id.peer_id(),
                self.author
            )));
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let seq = self.last_seq(&id.verifying_key())? + 1;
        let entry = RosterEntry {
            seq,
            op,
            subject_peer,
            subject_key,
            added_by: self.author,
        };
        let sig = id.sign(&entry.canonical_bytes());
        let line = RosterLine {
            seq: entry.seq,
            op: entry.op,
            subject_peer: entry.subject_peer,
            subject_key: B64.encode(entry.subject_key),
            added_by: entry.added_by,
            sig: B64.encode(sig.to_bytes()),
        };
        let mut json = serde_json::to_vec(&line)?;
        json.push(b'\n');

        // Whether this append creates the file (vs. extends an existing one).
        let is_create = !self.path.exists();

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&json)?;
        file.sync_all()?;

        // On file creation, the new directory entry itself must be flushed, or a
        // power failure can lose the whole file (and thus the first entry) despite
        // the content sync above. Only needed on create; append-to-existing is fine.
        #[cfg(unix)]
        if is_create {
            if let Some(dir) = self.path.parent() {
                if let Ok(d) = std::fs::File::open(dir) {
                    let _ = d.sync_all();
                }
            }
        }
        Ok(entry)
    }

    /// Read every entry, verifying each signature against `key` (the author's).
    /// Same fail-closed + torn-tail rules as `OpLog::read_verified`.
    pub fn read_verified(&self, key: &VerifyingKey) -> Result<Vec<RosterEntry>, StorageError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        self.verify_text(key, &text)
    }

    /// Verify raw bytes received from a peer WITHOUT touching disk.
    pub fn verify_bytes(
        &self,
        key: &VerifyingKey,
        bytes: &[u8],
    ) -> Result<Vec<RosterEntry>, StorageError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| StorageError::MalformedEntry(e.to_string()))?;
        self.verify_text(key, text)
    }

    fn verify_text(
        &self,
        key: &VerifyingKey,
        text: &str,
    ) -> Result<Vec<RosterEntry>, StorageError> {
        // A completed append always ends with '\n'. A missing trailing newline
        // means the final line was torn by a crash and may be tolerated.
        let torn_tail = !text.is_empty() && !text.ends_with('\n');
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        let last = lines.len().saturating_sub(1);

        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let parsed: RosterLine = match serde_json::from_str(line) {
                Ok(p) => p,
                // Tolerate a parse failure ONLY on a torn final line.
                Err(_) if i == last && torn_tail => break,
                Err(e) => return Err(StorageError::MalformedEntry(e.to_string())),
            };
            // The on-disk `added_by` is untrusted metadata; it must match this
            // log's author, or the entry is not authentically ours.
            if parsed.added_by != self.author {
                return Err(StorageError::BadSignature(parsed.added_by));
            }
            let key_bytes = B64
                .decode(parsed.subject_key.as_bytes())
                .map_err(|e| StorageError::MalformedEntry(e.to_string()))?;
            let subject_key: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| StorageError::MalformedEntry("subject key length".into()))?;
            let sig_bytes = B64
                .decode(parsed.sig.as_bytes())
                .map_err(|e| StorageError::MalformedEntry(e.to_string()))?;
            let sig_arr: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| StorageError::MalformedEntry("signature length".into()))?;
            let sig = Signature::from_bytes(&sig_arr);
            let entry = RosterEntry {
                seq: parsed.seq,
                op: parsed.op,
                subject_peer: parsed.subject_peer,
                subject_key,
                added_by: parsed.added_by,
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
    fn merge_roster_drops_a_mismatched_peer_id_entry() {
        let a = Identity::generate();
        let b = Identity::generate();
        let b_key = b.verifying_key().to_bytes();

        let mut entries = vec![
            // Honest entry: peer_id derives from the key.
            RosterEntry {
                seq: 1,
                op: RosterOp::Add,
                subject_peer: b.peer_id(),
                subject_key: b_key,
                added_by: a.peer_id(),
            },
            // Poisoned entry: peer_id does NOT derive from the key.
            RosterEntry {
                seq: 2,
                op: RosterOp::Add,
                subject_peer: b.peer_id().wrapping_add(999),
                subject_key: b_key,
                added_by: a.peer_id(),
            },
        ];
        let merged = merge_roster(&mut entries);
        assert_eq!(merged.len(), 1, "the mismatched entry must be dropped");
        assert_eq!(merged[0].peer_id, b.peer_id());
    }

    #[test]
    fn appends_and_reads_back_verified_roster_entries() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let b = Identity::generate();
        let log = RosterLog::new(dir.path(), a.peer_id());

        let e1 = log
            .append(&a, RosterOp::Add, b.peer_id(), b.verifying_key().to_bytes())
            .unwrap();
        assert_eq!(e1.seq, 1);
        let e2 = log
            .append(&a, RosterOp::Revoke, b.peer_id(), b.verifying_key().to_bytes())
            .unwrap();
        assert_eq!(e2.seq, 2);

        let entries = log.read_verified(&a.verifying_key()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].op, RosterOp::Add);
        assert_eq!(entries[1].op, RosterOp::Revoke);
        assert_eq!(entries[0].subject_peer, b.peer_id());
    }

    #[test]
    fn rejects_a_tampered_roster_entry() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let b = Identity::generate();
        let log = RosterLog::new(dir.path(), a.peer_id());
        log.append(&a, RosterOp::Add, b.peer_id(), b.verifying_key().to_bytes())
            .unwrap();

        // Flip subject_peer, keep the old signature -> must fail verification.
        let path = log.path();
        let line = std::fs::read_to_string(&path).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        v["subject_peer"] = serde_json::Value::from(b.peer_id().wrapping_add(1));
        std::fs::write(&path, format!("{}\n", v)).unwrap();

        assert!(matches!(
            log.read_verified(&a.verifying_key()),
            Err(StorageError::BadSignature(_))
        ));
    }

    #[test]
    fn revoke_is_terminal_even_with_a_later_add_from_another_author() {
        let key = [3u8; 32];
        // The peer_id MUST derive from the key (first 8 LE bytes) or merge_roster
        // drops the entry; this test is about revoke terminality, not the binding.
        let x = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let mut entries = vec![
            RosterEntry { seq: 1, op: RosterOp::Add,    subject_peer: x, subject_key: key, added_by: 1 },
            RosterEntry { seq: 2, op: RosterOp::Revoke, subject_peer: x, subject_key: key, added_by: 1 },
            // Stale Add from a DIFFERENT, higher-id author must NOT resurrect X.
            RosterEntry { seq: 1, op: RosterOp::Add,    subject_peer: x, subject_key: key, added_by: 2 },
        ];
        let peers = merge_roster(&mut entries);
        let rec = peers.iter().find(|p| p.peer_id == x).unwrap();
        assert_eq!(rec.status, PeerStatus::Revoked, "revocation must be terminal across authors");
    }

    #[test]
    fn append_rejects_wrong_author() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let other = Identity::generate();
        let log = RosterLog::new(dir.path(), a.peer_id());
        // `other` is not this log's author -> append must refuse.
        let err = log.append(&other, RosterOp::Add, 7, [0u8; 32]);
        assert!(matches!(err, Err(StorageError::Peer(_))));
    }

    #[test]
    fn tolerates_a_torn_final_roster_line() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let b = Identity::generate();
        let log = RosterLog::new(dir.path(), a.peer_id());
        log.append(&a, RosterOp::Add, b.peer_id(), b.verifying_key().to_bytes())
            .unwrap();

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap();
        std::io::Write::write_all(&mut f, br#"{"seq":2,"op":"Add"#).unwrap();

        let entries = log.read_verified(&a.verifying_key()).unwrap();
        assert_eq!(entries.len(), 1);
    }
}
