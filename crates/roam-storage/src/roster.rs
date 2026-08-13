use crate::error::StorageError;
use crate::identity::{Identity, VerifyingKey};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// A client role, ordered ascending by privilege so that `Ord`'s `min()`
/// selects the LEAST privilege: Reader < Writer < Admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    Reader,
    Writer,
    Admin,
}

/// Maximum device-name length in unicode chars (authoring boundary rejects longer).
pub const MAX_NAME_LEN: usize = 64;

/// A membership change under the grant-certificate model. `Add`/`SetRole` carry
/// the role the author intends for the subject; `Revoke` is terminal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RosterOp {
    Add {
        role: Role,
    },
    SetRole {
        role: Role,
    },
    Revoke,
    /// Self-asserted device name. Valid only when `added_by == subject_peer`.
    /// Completely orthogonal to privilege: never changes any peer's role,
    /// `ever_admin` membership, or revocation status.
    SetName {
        name: String,
    },
}

/// One signed roster entry. Signed by `added_by` (an already-trusted device).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    pub seq: u64,
    /// Per-SUBJECT Lamport clock for role resolution (N3). When an admin authors
    /// an `Add`/`SetRole`/`Revoke` for a subject it sets `lamport = 1 + max` of
    /// every lamport it has observed for that subject, so the newest admin
    /// decision wins the role fold regardless of WHICH admin made it — any admin
    /// can freely re-promote or demote any client. Distinct from `seq` (the
    /// per-author append-only log position); this is signed and compared ACROSS
    /// authors. Ties (equal lamport) break by `added_by`, then least privilege.
    pub lamport: u64,
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
    lamport: u64,
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
        let mut buf = Vec::with_capacity(14 + 8 + 8 + 2 + 8 + 32 + 8);
        buf.extend_from_slice(b"roam.roster.v3");
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.extend_from_slice(&self.lamport.to_le_bytes());
        let (op_tag, role_tag) = match &self.op {
            RosterOp::Add { role } => (0u8, role_byte(*role)),
            RosterOp::SetRole { role } => (2u8, role_byte(*role)),
            RosterOp::Revoke => (1u8, 0xFF),
            RosterOp::SetName { .. } => (3u8, 0xFF),
        };
        buf.push(op_tag);
        buf.push(role_tag);
        buf.extend_from_slice(&self.subject_peer.to_le_bytes());
        buf.extend_from_slice(&self.subject_key);
        buf.extend_from_slice(&self.added_by.to_le_bytes());
        // Length-prefixed name AFTER the fixed fields so the name is inside the
        // signed bytes without disturbing the layout of the privilege-carrying ops.
        if let RosterOp::SetName { name } = &self.op {
            buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
            buf.extend_from_slice(name.as_bytes());
        }
        buf
    }
}

fn role_byte(role: Role) -> u8 {
    match role {
        Role::Reader => 0,
        Role::Writer => 1,
        Role::Admin => 2,
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
    pub role: Role,
    /// Self-asserted display name (highest-seq `SetName` authored by the peer
    /// itself), or `None`. Folded independently of privilege.
    pub name: Option<String>,
}

/// Fold a set of signed roster entries into the current peer set using the
/// grant-certificate model. Purely a function of the signed entry set:
/// `ever_admin` is a monotone closure seeded by `founder`; a `Revoke` by any
/// `ever_admin` peer is terminal (prefer-deny); and the role is the NEWEST admin
/// decision — the `Add`/`SetRole` with the highest per-subject `lamport` (N3),
/// tie-broken by `added_by` then least privilege. Any admin can thus re-promote
/// or demote any client; there is no per-granting-admin floor.
pub fn merge_roster(entries: &mut [RosterEntry], founder: Option<u64>) -> Vec<PeerRecord> {
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    let valid: Vec<&RosterEntry> = entries
        .iter()
        .filter(|e| e.subject_peer == u64::from_le_bytes(e.subject_key[0..8].try_into().unwrap()))
        .collect();
    let mut ever_admin: HashSet<u64> = HashSet::new();
    if let Some(f) = founder {
        ever_admin.insert(f);
    }
    loop {
        let before = ever_admin.len();
        for e in &valid {
            let grants_admin = matches!(
                &e.op,
                RosterOp::Add { role: Role::Admin } | RosterOp::SetRole { role: Role::Admin }
            );
            if grants_admin && ever_admin.contains(&e.added_by) {
                ever_admin.insert(e.subject_peer);
            }
        }
        if ever_admin.len() == before {
            break;
        }
    }
    let mut keys: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
    let mut revoked: HashSet<u64> = HashSet::new();
    // N3: newest admin decision wins. Per subject we keep the single winning role
    // op ordered by (lamport, added_by) — the highest Lamport is the most recent
    // decision ANY admin has made about this subject, so any admin can freely
    // re-promote or demote it (no per-granting-admin floor). Equal (lamport,
    // added_by) — the same admin asserting two roles at one clock, e.g. a
    // hand-built or replayed tie — falls back to least privilege.
    let mut roles: BTreeMap<u64, (u64, u64, Role)> = BTreeMap::new();
    // H-A causal gap-rule: the per-subject role Lamport is a self-asserted scalar
    // signed by its author. Honest clocks climb by exactly +1 per decision
    // (`next_role_lamport` = 1 + max observed for the subject), so a legitimate
    // sequence is contiguous (concurrent decisions merely SHARE a value — a
    // duplicate, not a gap). A grant whose lamport jumps more than 1 past the
    // grounded prefix is a forged clock (e.g. a malicious admin asserting
    // `u64::MAX` to make a role pin unbeatable — one that would survive even the
    // attacker's own later revocation via the grandfathered `ever_admin` set).
    // Per subject, walk its admin-authored grant lamports ascending and take the
    // contiguous prefix from its floor as the admissible ceiling; grants above it
    // are ignored for role selection (keys/revocation are unaffected).
    let mut ceilings: BTreeMap<u64, u64> = BTreeMap::new();
    {
        let mut per_subject: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for e in valid.iter().filter(|e| ever_admin.contains(&e.added_by)) {
            if matches!(&e.op, RosterOp::Add { .. } | RosterOp::SetRole { .. }) {
                per_subject
                    .entry(e.subject_peer)
                    .or_default()
                    .insert(e.lamport);
            }
        }
        for (subject, lamports) in per_subject {
            let mut ceiling = 0u64;
            for (i, lamport) in lamports.into_iter().enumerate() {
                if i == 0 || lamport <= ceiling + 1 {
                    ceiling = lamport;
                } else {
                    break;
                }
            }
            ceilings.insert(subject, ceiling);
        }
    }
    for e in valid.iter().filter(|e| ever_admin.contains(&e.added_by)) {
        keys.entry(e.subject_peer)
            .and_modify(|k| {
                if e.subject_key < *k {
                    *k = e.subject_key;
                }
            })
            .or_insert(e.subject_key);
        match &e.op {
            RosterOp::Revoke => {
                revoked.insert(e.subject_peer);
            }
            RosterOp::Add { role } | RosterOp::SetRole { role } => {
                // Ignore forged clock jumps above the subject's causal ceiling.
                if e.lamport > *ceilings.get(&e.subject_peer).unwrap_or(&0) {
                    continue;
                }
                let cand = (e.lamport, e.added_by, *role);
                roles
                    .entry(e.subject_peer)
                    .and_modify(|cur| {
                        if (cand.0, cand.1) > (cur.0, cur.1) {
                            *cur = cand;
                        } else if (cand.0, cand.1) == (cur.0, cur.1) {
                            // True tie (same clock AND author): least privilege.
                            cur.2 = cur.2.min(cand.2);
                        }
                    })
                    .or_insert(cand);
            }
            // Names are folded separately (see below); a SetName is never a grant.
            RosterOp::SetName { .. } => {}
        }
    }
    // Self-asserted device names. Folded ENTIRELY separately from the privilege
    // logic above: this pass never touches `ever_admin`, `revoked`, or `intents`,
    // so a SetName can NEVER change any peer's role, status, or revocation. It runs
    // over the same key-derivation-validated entries, but is gated ONLY on
    // `added_by == subject_peer` (a name is authoritative solely for oneself);
    // highest-seq wins.
    let mut names: BTreeMap<u64, (u64, String)> = BTreeMap::new();
    for e in &valid {
        if let RosterOp::SetName { name } = &e.op {
            if e.added_by != e.subject_peer {
                continue; // foreign name — a device may only name itself
            }
            let slot = names.entry(e.subject_peer).or_insert((0, String::new()));
            if e.seq >= slot.0 {
                *slot = (e.seq, name.clone());
            }
        }
    }
    let mut out: Vec<PeerRecord> = roles
        .iter()
        .map(|(subject, (_, _, role))| {
            let role = *role;
            let status = if revoked.contains(subject) {
                PeerStatus::Revoked
            } else {
                PeerStatus::Active
            };
            PeerRecord {
                peer_id: *subject,
                verifying_key: keys[subject],
                status,
                role,
                name: names.get(subject).map(|(_, n)| n.clone()),
            }
        })
        .collect();
    out.sort_by_key(|p| p.peer_id);
    out
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
        lamport: u64,
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
            lamport,
            op,
            subject_peer,
            subject_key,
            added_by: self.author,
        };
        let sig = id.sign(&entry.canonical_bytes());
        let line = RosterLine {
            seq: entry.seq,
            lamport: entry.lamport,
            op: entry.op.clone(),
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

    /// Peek the key this log's author vouches for ITSELF: the `subject_key` of the
    /// first entry whose `subject_peer == author` (a self-`Add`). Read WITHOUT
    /// verification — the caller derives the peer-id binding and re-verifies the
    /// whole log against this key before trusting it. Used to bootstrap trust in a
    /// pinned founder whose self-signed log is the only proof of its key. Returns
    /// `None` if the log is absent or carries no self entry.
    pub fn peek_self_key(&self) -> Result<Option<[u8; 32]>, StorageError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let parsed: RosterLine = match serde_json::from_str(line) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if parsed.subject_peer != self.author {
                continue;
            }
            let key_bytes = match B64.decode(parsed.subject_key.as_bytes()) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Ok(arr) = <[u8; 32]>::try_from(key_bytes) {
                return Ok(Some(arr));
            }
        }
        Ok(None)
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
        let text =
            std::str::from_utf8(bytes).map_err(|e| StorageError::MalformedEntry(e.to_string()))?;
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
                lamport: parsed.lamport,
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

    /// A subject/key pair whose `peer_id` derives from the key's first 8 LE bytes.
    fn pid(k: u8) -> (u64, [u8; 32]) {
        let key = [k; 32];
        (u64::from_le_bytes(key[0..8].try_into().unwrap()), key)
    }

    #[test]
    fn duplicate_seq_role_conflict_is_order_independent() {
        let (f, fk) = pid(1);
        let (b, bk) = pid(2);
        // Two same-author (founder) entries for b at the SAME seq, different roles.
        let e_admin = RosterEntry {
            seq: 2,
            lamport: 2,
            op: RosterOp::SetRole { role: Role::Admin },
            subject_peer: b,
            subject_key: bk,
            added_by: f,
        };
        let e_reader = RosterEntry {
            seq: 2,
            lamport: 2,
            op: RosterOp::SetRole { role: Role::Reader },
            subject_peer: b,
            subject_key: bk,
            added_by: f,
        };
        let seed = RosterEntry {
            seq: 1,
            lamport: 1,
            op: RosterOp::Add { role: Role::Admin },
            subject_peer: f,
            subject_key: fk,
            added_by: f,
        };
        let mut order1 = vec![seed.clone(), e_admin.clone(), e_reader.clone()];
        let mut order2 = vec![seed, e_reader, e_admin];
        let r1 = merge_roster(&mut order1, Some(f));
        let r2 = merge_roster(&mut order2, Some(f));
        let role1 = r1.iter().find(|p| p.peer_id == b).unwrap().role;
        let role2 = r2.iter().find(|p| p.peer_id == b).unwrap().role;
        assert_eq!(role1, role2, "same set, different order → same result");
        assert_eq!(
            role1,
            Role::Reader,
            "equal-seq tie resolves to least privilege"
        );
    }

    #[test]
    fn merge_roster_drops_a_mismatched_peer_id_entry() {
        let a = Identity::generate();
        let b = Identity::generate();
        let b_key = b.verifying_key().to_bytes();

        let mut entries = vec![
            // Honest entry: peer_id derives from the key.
            RosterEntry {
                seq: 1,
                lamport: 1,
                op: RosterOp::Add { role: Role::Admin },
                subject_peer: b.peer_id(),
                subject_key: b_key,
                added_by: a.peer_id(),
            },
            // Poisoned entry: peer_id does NOT derive from the key.
            RosterEntry {
                seq: 2,
                lamport: 2,
                op: RosterOp::Add { role: Role::Admin },
                subject_peer: b.peer_id().wrapping_add(999),
                subject_key: b_key,
                added_by: a.peer_id(),
            },
        ];
        let merged = merge_roster(&mut entries, Some(a.peer_id()));
        assert_eq!(merged.len(), 1, "the mismatched entry must be dropped");
        assert_eq!(merged[0].peer_id, b.peer_id());
    }

    #[test]
    fn founder_self_add_seeds_admin_but_other_self_add_does_not() {
        let (f, f_key) = pid(10);
        let (b, b_key) = pid(20);
        let mut entries = vec![
            RosterEntry {
                seq: 1,
                lamport: 1,
                op: RosterOp::Add { role: Role::Admin },
                subject_peer: f,
                subject_key: f_key,
                added_by: f,
            },
            RosterEntry {
                seq: 1,
                lamport: 1,
                op: RosterOp::Add { role: Role::Admin },
                subject_peer: b,
                subject_key: b_key,
                added_by: b,
            },
        ];
        let peers = merge_roster(&mut entries, Some(f));
        let frec = peers.iter().find(|p| p.peer_id == f).unwrap();
        assert_eq!(frec.role, Role::Admin);
        assert!(
            peers.iter().all(|p| p.peer_id != b),
            "self-add cannot bootstrap admin"
        );
    }

    #[test]
    fn non_admin_grant_has_no_effect() {
        let (f, f_key) = pid(10);
        let (w, w_key) = pid(20);
        let (c, c_key) = pid(30);
        let mut entries = vec![
            RosterEntry {
                seq: 1,
                lamport: 1,
                op: RosterOp::Add { role: Role::Admin },
                subject_peer: f,
                subject_key: f_key,
                added_by: f,
            },
            RosterEntry {
                seq: 2,
                lamport: 2,
                op: RosterOp::Add { role: Role::Writer },
                subject_peer: w,
                subject_key: w_key,
                added_by: f,
            },
            RosterEntry {
                seq: 1,
                lamport: 1,
                op: RosterOp::Add { role: Role::Admin },
                subject_peer: c,
                subject_key: c_key,
                added_by: w,
            },
        ];
        let peers = merge_roster(&mut entries, Some(f));
        assert!(
            peers.iter().all(|p| p.peer_id != c),
            "a non-admin cannot grant anything"
        );
    }

    #[test]
    fn newest_admin_decision_wins_regardless_of_which_admin_made_it() {
        // N3: any admin can change any client's role; the NEWEST decision (highest
        // per-subject lamport) wins, no matter which admin authored it — there is
        // no "only the granting admin can override" floor. Here founder f grants b
        // Admin (lamport 3), a DIFFERENT admin a2 later demotes b to Reader
        // (lamport 4), then f re-promotes b to Admin (lamport 5, newest of all).
        let (f, f_key) = pid(10);
        let (a2, a2_key) = pid(20);
        let (b, b_key) = pid(30);
        let grant = |sub, key, by, lamport, role| RosterEntry {
            seq: lamport,
            lamport,
            op: RosterOp::Add { role },
            subject_peer: sub,
            subject_key: key,
            added_by: by,
        };
        let mut base = vec![
            grant(f, f_key, f, 1, Role::Admin),
            grant(a2, a2_key, f, 2, Role::Admin),
            grant(b, b_key, f, 3, Role::Admin),
        ];
        // a2 (not the granter of b's Admin was also f, but a2 is a peer admin)
        // demotes b — newer than f's grant, so it takes effect.
        let demote = RosterEntry {
            seq: 4,
            lamport: 4,
            op: RosterOp::SetRole { role: Role::Reader },
            subject_peer: b,
            subject_key: b_key,
            added_by: a2,
        };
        let mut demoted = base.clone();
        demoted.push(demote.clone());
        let peers = merge_roster(&mut demoted, Some(f));
        assert_eq!(
            peers.iter().find(|p| p.peer_id == b).unwrap().role,
            Role::Reader,
            "a newer decision by a DIFFERENT admin (a2) overrides f's grant"
        );

        // f re-promotes b with an even-newer lamport — no per-admin floor blocks it.
        base.push(demote);
        base.push(RosterEntry {
            seq: 5,
            lamport: 5,
            op: RosterOp::SetRole { role: Role::Admin },
            subject_peer: b,
            subject_key: b_key,
            added_by: f,
        });
        let peers = merge_roster(&mut base, Some(f));
        assert_eq!(
            peers.iter().find(|p| p.peer_id == b).unwrap().role,
            Role::Admin,
            "the newest decision (f's re-promote) wins; a2's earlier demotion no longer floors"
        );
    }

    #[test]
    fn a_forged_max_lamport_pin_cannot_survive_an_honest_re_promote() {
        // N3 hardening (H-A): the per-subject role Lamport is a self-asserted
        // scalar signed by its author. A malicious admin must NOT be able to pin a
        // victim's role by asserting `u64::MAX` (an unbeatable clock value that no
        // honest admin could ever exceed, so the pin would survive even the
        // attacker's own later revocation via the grandfathered ever_admin set).
        // Honest clocks climb by exactly +1 per decision, so a lamport that jumps
        // more than 1 past a subject's grounded sequence is a forged jump and must
        // be ignored for role selection.
        let (f, f_key) = pid(10);
        let (a, a_key) = pid(20);
        let (b, b_key) = pid(30);
        let grant = |sub, key, by, lamport, role| RosterEntry {
            seq: lamport,
            lamport,
            op: RosterOp::Add { role },
            subject_peer: sub,
            subject_key: key,
            added_by: by,
        };
        let set = |sub, key, by, lamport, role| RosterEntry {
            seq: lamport,
            lamport,
            op: RosterOp::SetRole { role },
            subject_peer: sub,
            subject_key: key,
            added_by: by,
        };
        let mut entries = vec![
            grant(f, f_key, f, 1, Role::Admin),
            grant(a, a_key, f, 1, Role::Admin),
            grant(b, b_key, f, 1, Role::Admin),
            // Malicious admin a asserts an unbeatable clock to pin b to Reader.
            set(b, b_key, a, u64::MAX, Role::Reader),
            // Honest founder f re-promotes b with a normal causal +1 step.
            set(b, b_key, f, 2, Role::Admin),
        ];
        let peers = merge_roster(&mut entries, Some(f));
        assert_eq!(
            peers.iter().find(|p| p.peer_id == b).unwrap().role,
            Role::Admin,
            "a forged u64::MAX pin is a non-causal jump and must not floor an honest re-promote"
        );
    }

    #[test]
    fn a_true_concurrent_role_tie_is_deterministic_and_least_privilege_on_full_tie() {
        // Equal lamport AND equal author is the only genuine tie (a replay/hand-
        // built duplicate); it resolves to least privilege. Distinct authors at
        // equal lamport resolve deterministically by added_by (higher wins).
        let (f, f_key) = pid(10);
        let (b, b_key) = pid(30);
        let seed = RosterEntry {
            seq: 1,
            lamport: 1,
            op: RosterOp::Add { role: Role::Admin },
            subject_peer: f,
            subject_key: f_key,
            added_by: f,
        };
        let admin = RosterEntry {
            seq: 2,
            lamport: 2,
            op: RosterOp::SetRole { role: Role::Admin },
            subject_peer: b,
            subject_key: b_key,
            added_by: f,
        };
        let reader = RosterEntry {
            seq: 2,
            lamport: 2,
            op: RosterOp::SetRole { role: Role::Reader },
            subject_peer: b,
            subject_key: b_key,
            added_by: f,
        };
        let mut entries = vec![seed, admin, reader];
        let peers = merge_roster(&mut entries, Some(f));
        assert_eq!(
            peers.iter().find(|p| p.peer_id == b).unwrap().role,
            Role::Reader,
            "same-clock same-author conflict → least privilege"
        );
    }

    #[test]
    fn grandfathered_grant_survives_granter_demotion_and_revocation() {
        let (a, a_key) = pid(10);
        let (b, b_key) = pid(20);
        let (c, c_key) = pid(30);
        let mut entries = vec![
            RosterEntry {
                seq: 1,
                lamport: 1,
                op: RosterOp::Add { role: Role::Admin },
                subject_peer: a,
                subject_key: a_key,
                added_by: a,
            },
            RosterEntry {
                seq: 2,
                lamport: 2,
                op: RosterOp::Add { role: Role::Admin },
                subject_peer: b,
                subject_key: b_key,
                added_by: a,
            },
            RosterEntry {
                seq: 1,
                lamport: 1,
                op: RosterOp::Add { role: Role::Admin },
                subject_peer: c,
                subject_key: c_key,
                added_by: b,
            },
            RosterEntry {
                seq: 3,
                lamport: 3,
                op: RosterOp::SetRole { role: Role::Reader },
                subject_peer: b,
                subject_key: b_key,
                added_by: a,
            },
            RosterEntry {
                seq: 4,
                lamport: 4,
                op: RosterOp::Revoke,
                subject_peer: b,
                subject_key: b_key,
                added_by: a,
            },
        ];
        let peers = merge_roster(&mut entries, Some(a));
        let brec = peers.iter().find(|p| p.peer_id == b).unwrap();
        assert_eq!(brec.role, Role::Reader);
        assert_eq!(brec.status, PeerStatus::Revoked);
        let crec = peers.iter().find(|p| p.peer_id == c).unwrap();
        assert_eq!(crec.role, Role::Admin);
        assert_eq!(crec.status, PeerStatus::Active);
    }

    #[test]
    fn same_author_latest_seq_intent_wins() {
        let (f, f_key) = pid(10);
        let (b, b_key) = pid(20);
        let mut entries = vec![
            RosterEntry {
                seq: 1,
                lamport: 1,
                op: RosterOp::Add { role: Role::Admin },
                subject_peer: f,
                subject_key: f_key,
                added_by: f,
            },
            RosterEntry {
                seq: 2,
                lamport: 2,
                op: RosterOp::Add { role: Role::Reader },
                subject_peer: b,
                subject_key: b_key,
                added_by: f,
            },
            RosterEntry {
                seq: 3,
                lamport: 3,
                op: RosterOp::SetRole { role: Role::Writer },
                subject_peer: b,
                subject_key: b_key,
                added_by: f,
            },
        ];
        let peers = merge_roster(&mut entries, Some(f));
        let brec = peers.iter().find(|p| p.peer_id == b).unwrap();
        assert_eq!(brec.role, Role::Writer);
    }

    #[test]
    fn appends_and_reads_back_verified_roster_entries() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let b = Identity::generate();
        let log = RosterLog::new(dir.path(), a.peer_id());

        let e1 = log
            .append(
                &a,
                1,
                RosterOp::Add { role: Role::Admin },
                b.peer_id(),
                b.verifying_key().to_bytes(),
            )
            .unwrap();
        assert_eq!(e1.seq, 1);
        let e2 = log
            .append(
                &a,
                1,
                RosterOp::Revoke,
                b.peer_id(),
                b.verifying_key().to_bytes(),
            )
            .unwrap();
        assert_eq!(e2.seq, 2);

        let entries = log.read_verified(&a.verifying_key()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].op, RosterOp::Add { role: Role::Admin });
        assert_eq!(entries[1].op, RosterOp::Revoke);
        assert_eq!(entries[0].subject_peer, b.peer_id());
    }

    #[test]
    fn rejects_a_tampered_roster_entry() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let b = Identity::generate();
        let log = RosterLog::new(dir.path(), a.peer_id());
        log.append(
            &a,
            1,
            RosterOp::Add { role: Role::Admin },
            b.peer_id(),
            b.verifying_key().to_bytes(),
        )
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
            RosterEntry {
                seq: 1,
                lamport: 1,
                op: RosterOp::Add { role: Role::Writer },
                subject_peer: x,
                subject_key: key,
                added_by: 1,
            },
            RosterEntry {
                seq: 2,
                lamport: 2,
                op: RosterOp::Revoke,
                subject_peer: x,
                subject_key: key,
                added_by: 1,
            },
            // Stale Add from a DIFFERENT, higher-id author must NOT resurrect X.
            RosterEntry {
                seq: 1,
                lamport: 1,
                op: RosterOp::Add { role: Role::Writer },
                subject_peer: x,
                subject_key: key,
                added_by: 2,
            },
        ];
        let peers = merge_roster(&mut entries, Some(1));
        let rec = peers.iter().find(|p| p.peer_id == x).unwrap();
        assert_eq!(
            rec.status,
            PeerStatus::Revoked,
            "revocation must be terminal across authors"
        );
    }

    #[test]
    fn append_rejects_wrong_author() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let other = Identity::generate();
        let log = RosterLog::new(dir.path(), a.peer_id());
        // `other` is not this log's author -> append must refuse.
        let err = log.append(
            &other,
            1,
            RosterOp::Add { role: Role::Reader },
            7,
            [0u8; 32],
        );
        assert!(matches!(err, Err(StorageError::Peer(_))));
    }

    /// A key whose first 8 little-endian bytes equal `peer`, so the
    /// key-derivation validity filter in `merge_roster` accepts entries for it.
    fn key_for(peer: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0..8].copy_from_slice(&peer.to_le_bytes());
        key
    }

    fn entry(
        seq: u64,
        op: RosterOp,
        subject_peer: u64,
        subject_key: [u8; 32],
        added_by: u64,
    ) -> RosterEntry {
        // Default the per-subject Lamport to `seq` for the single-author tests
        // that use this helper; cross-author LWW tests build entries explicitly.
        RosterEntry {
            seq,
            lamport: seq,
            op,
            subject_peer,
            subject_key,
            added_by,
        }
    }

    #[test]
    fn set_name_folds_onto_peer_and_latest_wins() {
        let key1 = key_for(1);
        let mut entries = vec![
            entry(1, RosterOp::Add { role: Role::Admin }, 1, key1, 1),
            entry(2, RosterOp::SetName { name: "old".into() }, 1, key1, 1),
            entry(3, RosterOp::SetName { name: "new".into() }, 1, key1, 1),
        ];
        let peers = merge_roster(&mut entries, Some(1));
        let me = peers.iter().find(|p| p.peer_id == 1).unwrap();
        assert_eq!(me.name.as_deref(), Some("new"));
    }

    #[test]
    fn foreign_set_name_is_ignored_and_privilege_unchanged() {
        let key1 = key_for(1);
        let key2 = key_for(2);
        // entry #3: subject_peer=2 (matches key2, so it PASSES the validity filter),
        // but added_by=1 (foreign author). ONLY the fold's `added_by == subject_peer`
        // gate can drop it — the validity filter does not, which is what makes this a
        // genuine test of the self-only rule (not the key-derivation filter).
        let mut with_foreign = vec![
            entry(1, RosterOp::Add { role: Role::Admin }, 1, key1, 1),
            entry(2, RosterOp::Add { role: Role::Writer }, 2, key2, 1),
            entry(
                3,
                RosterOp::SetName {
                    name: "hacked".into(),
                },
                2,
                key2,
                1,
            ),
        ];
        let mut without = vec![
            entry(1, RosterOp::Add { role: Role::Admin }, 1, key1, 1),
            entry(2, RosterOp::Add { role: Role::Writer }, 2, key2, 1),
        ];
        let a = merge_roster(&mut with_foreign, Some(1));
        let b = merge_roster(&mut without, Some(1));
        assert_eq!(
            a.iter().find(|p| p.peer_id == 2).unwrap().name,
            None,
            "a name whose author != subject must never land"
        );
        let roles = |v: &[PeerRecord]| {
            v.iter()
                .map(|p| (p.peer_id, p.role, p.status))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            roles(&a),
            roles(&b),
            "SetName must not change any role/status"
        );
    }

    #[test]
    fn set_name_is_covered_by_canonical_bytes() {
        let base = RosterEntry {
            seq: 1,
            lamport: 1,
            op: RosterOp::SetName {
                name: "Sam's laptop".to_string(),
            },
            subject_peer: 42,
            subject_key: [7u8; 32],
            added_by: 42,
        };
        let mut other = base.clone();
        other.op = RosterOp::SetName {
            name: "Other name".to_string(),
        };
        assert_ne!(
            base.canonical_bytes(),
            other.canonical_bytes(),
            "name must be inside signed bytes"
        );
        let add = RosterEntry {
            op: RosterOp::Add { role: Role::Admin },
            ..base.clone()
        };
        assert_ne!(base.canonical_bytes(), add.canonical_bytes());
    }

    #[test]
    fn tolerates_a_torn_final_roster_line() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let b = Identity::generate();
        let log = RosterLog::new(dir.path(), a.peer_id());
        log.append(
            &a,
            1,
            RosterOp::Add { role: Role::Admin },
            b.peer_id(),
            b.verifying_key().to_bytes(),
        )
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
