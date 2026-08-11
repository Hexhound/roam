use crate::blob::BlobStore;
use crate::error::StorageError;
use crate::history::{HistoryIndex, Marker};
use crate::history_util::count_log_lines;
use crate::identity::{Identity, VerifyingKey};
use crate::keychain::{compute_epoch_id, Keychain, VaultIssue};
use crate::keylog::{KeyBody, KeyLog, KeyLogEntry, Recipient};
use crate::keywrap;
use crate::oplog::OpLog;
use crate::roster::{merge_roster, PeerRecord, PeerStatus, Role, RosterEntry, RosterLog, RosterOp};
use crate::snapshot;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use roam_crdt::{Document, Version};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Base64-encode bytes for storage in a history marker (same STANDARD engine
/// the op-log uses for its signed lines).
fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// The `peer_id` a verifying key MUST map to: the first 8 little-endian bytes of
/// the key (see `Identity::generate`). The roster binds every peer to this so op
/// attribution (`peer_id -> key`) can never be poisoned by a mismatched pair.
fn derived_peer_id(key_bytes: &[u8; 32]) -> u64 {
    u64::from_le_bytes(
        key_bytes[0..8]
            .try_into()
            .expect("32-byte key has an 8-byte prefix"),
    )
}

/// Whether the version vector encoded in `superset` causally DOMINATES the one
/// in `subset` (`superset ⊇ subset`) — i.e. everything `subset` has observed,
/// `superset` has observed too. Both args are [`roam_crdt::Version`] bytes
/// (as produced by [`Store::doc_version_bytes`]).
///
/// CONSERVATIVE on any error: if EITHER side fails to decode, returns `false`
/// (treat as "not dominated"). For the tombstone GC this means an unparseable
/// acked version can never make a tombstone look stable — GC only ever errs
/// toward retaining a tombstone, never toward dropping one prematurely.
pub fn version_dominates(superset: &[u8], subset: &[u8]) -> bool {
    match (Version::from_bytes(superset), Version::from_bytes(subset)) {
        (Ok(sup), Ok(sub)) => sup.includes(&sub),
        _ => false,
    }
}

/// On-disk byte usage of a vault, broken down by category. Every field counts
/// bytes physically stored under the vault root; `total` is their sum. Reported
/// by [`Store::data_size`] so a client can show the user how much space the
/// vault uses (and, paired with [`Store::checkpoint_dry_run`], how much a
/// compaction would reclaim) without walking the disk itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataSize {
    /// Content-addressed blob bytes (`<root>/assets`) — binary payloads that
    /// live outside the CRDT.
    pub blobs: u64,
    /// CRDT op-logs and the fast-load snapshot (`<root>/ops`, `<root>/snapshots`).
    pub oplog: u64,
    /// Signed roster/key logs, the local history index, and the founder pin
    /// (`<root>/roster`, `<root>/keylog`, `<root>/history`, `<root>/founder`).
    pub meta: u64,
    /// Sum of every bucket above.
    pub total: u64,
}

/// Total byte size of every regular file at or under `path`, recursively. A
/// missing directory counts as 0 (an empty vault has not created it yet). Any
/// other IO error propagates — a size report must never silently undercount.
fn dir_size(path: &Path) -> Result<u64, StorageError> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let mut total = 0u64;
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            total = total.saturating_add(dir_size(&entry.path())?);
        } else if file_type.is_file() {
            total = total.saturating_add(entry.metadata()?.len());
        }
    }
    Ok(total)
}

/// Total byte size of the regular files sitting DIRECTLY in `path` (its
/// non-recursive top level; subdirectories are ignored — they are summed
/// separately by [`dir_size`]). A missing directory counts as 0.
fn root_file_bytes(path: &Path) -> Result<u64, StorageError> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let mut total = 0u64;
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            total = total.saturating_add(entry.metadata()?.len());
        }
    }
    Ok(total)
}

/// A vault-backed CRDT document store. Layout under `root`:
/// - `ops/ops-<peer>.jsonl` — one signed append-log per peer
/// - `roster/roster-<peer>.jsonl` — one signed membership log per device
/// - `snapshots/snapshot.loro` — fast-load snapshot (rebuildable)
/// - `peers.json` — materialized, rebuildable cache of the merged roster
pub struct Store {
    root: PathBuf,
    identity: Identity,
    doc: Document,
    own_log: OpLog,
    /// The document version already written to `own_log` (so we only append new ops).
    persisted: Version,
    /// This device's own signed membership log.
    own_roster: RosterLog,
    /// Materialized view of the merged roster across all trusted logs.
    peers: Vec<PeerRecord>,
    /// Content-addressed store for binary blobs, rooted at `<root>/assets`.
    /// Blob bytes live BESIDE the CRDT state (not inside it) so the file-set
    /// map only ever carries a blob's hash-reference while the bytes are kept
    /// here on plain disk (see [`BlobStore`]). Owning it on `Store` lets the
    /// bridge (and later blob-transfer/projection slices) reach the blobs
    /// through the one shared store handle.
    blobs: BlobStore,
    /// Append-only local history index (`<root>/history/history.jsonl`). A
    /// marker is recorded on every `write_snapshot`, capturing the op-log
    /// frontier + per-peer log lengths for later checkpoint compaction.
    history: HistoryIndex,
    /// The pinned vault founder's `peer_id` (`<root>/founder`), if any. Seeds the
    /// monotone `ever_admin` closure in `merge_roster` so grant certificates fold.
    founder: Option<u64>,
}

impl Store {
    /// Open (creating if needed) the vault at `root` for device `identity`.
    ///
    /// Rebuilds the document from the snapshot (if any), a replay of THIS
    /// device's own signed log, and then a replay of every `Active` peer's log.
    /// Peer trust comes from the replicated roster logs, not `peers.json` (a mere
    /// cache) — `open()` always rebuilds the peer set from the signed roster logs
    /// so a lost/stale cache can never affect correctness.
    pub fn open(root: &Path, identity: Identity) -> Result<Self, StorageError> {
        let ops_dir = root.join("ops");
        let roster_dir = root.join("roster");
        let snap_path = root.join("snapshots").join("snapshot.loro");

        // 1. Rebuild the trusted peer set from the signed roster logs (fixpoint),
        //    seeded by the pinned founder so grant certificates actually fold.
        let founder = crate::founder::read_founder(root)?;
        let peers =
            Self::rebuild_peers(root, identity.peer_id(), &identity.verifying_key(), founder)?;

        // 2. Base document: from snapshot if present, else empty.
        let doc = match snapshot::load(&snap_path)? {
            Some(bytes) => Document::from_snapshot(identity.peer_id(), &bytes)?,
            None => Document::new(identity.peer_id())?,
        };

        // 3. Replay our own log (verified against our own key).
        let own_log = OpLog::new(&ops_dir, identity.peer_id());
        for entry in own_log.read_verified(&identity.verifying_key())? {
            doc.import(&entry.update)?;
        }

        // 4. Replay every Active peer's log, verified against the key the roster
        //    vouches for. A missing peer op-log is fine (read_verified ⇒ empty).
        for peer in peers.iter() {
            if peer.status != PeerStatus::Active || peer.peer_id == identity.peer_id() {
                continue;
            }
            let peer_key = match VerifyingKey::from_bytes(&peer.verifying_key) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let peer_log = OpLog::new(&ops_dir, peer.peer_id);
            for entry in peer_log.read_verified(&peer_key)? {
                doc.import(&entry.update)?;
            }
        }

        doc.commit();
        let persisted = doc.version();
        let own_roster = RosterLog::new(&roster_dir, identity.peer_id());
        // Blob bytes live beside the CRDT state under `<root>/assets`. Opening
        // it here (creating the dir if absent) means every caller sharing this
        // Store reaches the same blob store via `blobs()`.
        let blobs = BlobStore::open(&root.join("assets"))?;
        let history = HistoryIndex::new(&root.join("history"));
        let store = Self {
            root: root.to_path_buf(),
            identity,
            doc,
            own_log,
            persisted,
            own_roster,
            peers,
            blobs,
            history,
            founder,
        };
        store.write_peers_cache()?;
        Ok(store)
    }

    /// Rebuild the trusted peer set from the signed roster logs under
    /// `root/roster/`. Resolves the bootstrap cycle (verifying author X's roster
    /// needs X's key, which itself comes from the roster) with a fixpoint:
    /// start trusting only ourselves, then repeatedly read any roster log whose
    /// author is already keyed, learning new subject keys, until no new author
    /// becomes processable.
    fn rebuild_peers(
        root: &Path,
        self_id: u64,
        self_key: &VerifyingKey,
        founder: Option<u64>,
    ) -> Result<Vec<PeerRecord>, StorageError> {
        let roster_dir = root.join("roster");

        // Trusted author keys (as raw bytes; `VerifyingKey` is not `Copy`), seeded
        // with ourselves.
        let mut trusted: HashMap<u64, [u8; 32]> = HashMap::new();
        trusted.insert(self_id, self_key.to_bytes());

        // Bootstrap trust in a pinned founder that is NOT ourselves. A device we
        // have not vouched for (e.g. a Reader that can't author roster ops) still
        // needs to read the founder's self-signed log to learn its OWN role. The
        // founder's log proves its key: its self-`Add` carries the founder key, and
        // the peer-id binding (`fid == first-8-LE-bytes(key)`) prevents a swap.
        if let Some(fid) = founder {
            if !trusted.contains_key(&fid) {
                let flog = RosterLog::new(&roster_dir, fid);
                if let Some(fkey) = flog.peek_self_key()? {
                    if derived_peer_id(&fkey) == fid {
                        trusted.insert(fid, fkey);
                    }
                }
            }
        }

        let mut processed: HashSet<u64> = HashSet::new();
        let mut all_entries: Vec<RosterEntry> = Vec::new();

        loop {
            // Find an author we now trust, whose roster log we have not read yet.
            let next = trusted
                .keys()
                .copied()
                .find(|author| !processed.contains(author));
            let Some(author) = next else { break };
            processed.insert(author);

            // A malformed trusted-key entry can't verify anything; skip its log.
            let author_key = match VerifyingKey::from_bytes(&trusted[&author]) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let log = RosterLog::new(&roster_dir, author);
            let entries = match log.read_verified(&author_key) {
                Ok(e) => e,
                Err(_) => continue, // a corrupt/forged log for one author must not brick the roster
            };
            for entry in &entries {
                // Learn subject keys this author vouches for (Add or Revoke both
                // carry the key; a later fixpoint pass never removes trust).
                trusted
                    .entry(entry.subject_peer)
                    .or_insert(entry.subject_key);
            }
            all_entries.extend(entries);
        }

        Ok(merge_roster(&mut all_entries, founder))
    }

    pub fn text(&self, id: &str) -> String {
        self.doc.text(id)
    }

    /// The content-addressed [`BlobStore`] rooted at `<root>/assets`, holding
    /// binary payloads that live OUTSIDE the CRDT (only their hash-reference
    /// rides the op-log). The bridge routes non-text files here; later slices
    /// (cross-device byte transfer, disk projection, GC) reach them the same way.
    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    /// On-disk byte usage of this vault, broken down by category (see
    /// [`DataSize`]). Walks the vault directories and sums file sizes — cheap
    /// enough for a UI to call on demand (one `read_dir` + a stat per file), but
    /// not O(1): cost scales with the number of stored files. Pair with
    /// [`Store::checkpoint_dry_run`] to show "total now" vs "freeable by
    /// compacting" side by side.
    pub fn data_size(&self) -> Result<DataSize, StorageError> {
        let blobs = dir_size(&self.root.join("assets"))?;
        let oplog = dir_size(&self.root.join("ops"))?
            .saturating_add(dir_size(&self.root.join("snapshots"))?);
        let mut meta = dir_size(&self.root.join("roster"))?
            .saturating_add(dir_size(&self.root.join("keylog"))?)
            .saturating_add(dir_size(&self.root.join("history"))?);
        // Bare files directly at the vault root (the `founder` pin, the
        // `peers.json` roster cache, the vault-key file, …) are all metadata.
        // Count them generically so a new root-level file is never silently
        // dropped from the total — subdirectories are summed above.
        meta = meta.saturating_add(root_file_bytes(&self.root)?);
        let total = blobs.saturating_add(oplog).saturating_add(meta);
        Ok(DataSize {
            blobs,
            oplog,
            meta,
            total,
        })
    }

    /// Insert text, commit, and durably append the resulting signed delta.
    pub fn edit_text(&mut self, id: &str, pos: usize, s: &str) -> Result<(), StorageError> {
        self.doc.insert_text(id, pos, s)?;
        self.persist_new_ops()
    }

    /// Delete text, commit, and durably append the resulting signed delta.
    pub fn delete_text(&mut self, id: &str, pos: usize, len: usize) -> Result<(), StorageError> {
        self.doc.delete_text(id, pos, len)?;
        self.persist_new_ops()
    }

    /// Set a file-set-map entry, commit, and durably append the resulting signed
    /// delta. Rides the exact same commit + version-guarded export + own-log
    /// append path as `edit_text`, so the map op merges through the standard
    /// export/import peer path with no roster/transport changes.
    pub fn set_entry(&mut self, map_id: &str, key: &str, value: &str) -> Result<(), StorageError> {
        self.doc.set_entry(map_id, key, value)?;
        self.persist_new_ops()
    }

    /// Remove `key` from map `map_id`, commit, and durably append the resulting
    /// signed delete op. This is a real CRDT map-delete (see
    /// [`roam_crdt::Document::remove_entry`]) that propagates to peers, so it
    /// rides the same export/import path as [`Store::set_entry`]. Used by the
    /// tombstone garbage collector once a tombstone is causally stable.
    pub fn remove_entry(&mut self, map_id: &str, key: &str) -> Result<(), StorageError> {
        self.doc.remove_entry(map_id, key)?;
        self.persist_new_ops()
    }

    /// The current value for `key` in map `map_id`, if any.
    pub fn get_entry(&self, map_id: &str, key: &str) -> Option<String> {
        self.doc.get_entry(map_id, key)
    }

    /// All key/value pairs in map `map_id`.
    pub fn entries(&self, map_id: &str) -> Vec<(String, String)> {
        self.doc.entries(map_id)
    }

    fn persist_new_ops(&mut self) -> Result<(), StorageError> {
        self.doc.commit();
        // Guard on the version, not `delta.is_empty()`: loro's updates export is
        // never byte-empty (it always carries a format header), so an edit that
        // produced no ops (e.g. a zero-length delete) must be detected by the
        // version being unchanged — otherwise we'd append header-only junk.
        let current = self.doc.version();
        if current != self.persisted {
            let delta = self.doc.export_from(&self.persisted)?;
            self.own_log.append(&self.identity, &delta)?;
            self.persisted = current;
        }
        Ok(())
    }

    /// Whether THIS device may author/propagate content ops (Writer or Admin).
    /// A Reader-role device (or one not yet in the roster) may not write.
    pub fn may_write(&self) -> bool {
        matches!(self.self_role(), Some(Role::Writer) | Some(Role::Admin))
    }

    /// Write a fast-load snapshot of the current state, then record a history
    /// marker pinning this moment: the op-log frontier (base64) and every
    /// peer's op-log line count. Later checkpoint compaction keys off these.
    pub fn write_snapshot(&self) -> Result<(), StorageError> {
        let path = self.root.join("snapshots").join("snapshot.loro");
        snapshot::save(&path, &self.doc.snapshot()?)?;

        let frontier = self.doc.oplog_frontier();
        let mut log_lens = std::collections::BTreeMap::new();
        log_lens.insert(self.peer_id(), count_log_lines(&self.own_log.path()));
        for peer in &self.peers {
            let path = self
                .root
                .join("ops")
                .join(format!("ops-{}.jsonl", peer.peer_id));
            log_lens.insert(peer.peer_id, count_log_lines(&path));
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        self.history.append(&Marker {
            ts_ms: now_ms,
            frontier: b64(&frontier.to_bytes()),
            log_lens,
        })?;
        Ok(())
    }

    /// The raw bytes of this device's own oplog file (for copying to a peer).
    pub fn export_own_log(&self) -> Result<Vec<u8>, StorageError> {
        match std::fs::read(self.own_log.path()) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// The roster directory under this vault (`root/roster`).
    fn roster_dir(&self) -> PathBuf {
        self.root.join("roster")
    }

    /// This device's peer id (loro/index handle).
    pub fn peer_id(&self) -> u64 {
        self.identity.peer_id()
    }

    /// This device's ed25519 verifying-key bytes (for cross-vouching and for peers
    /// to trust our authored ops).
    /// This device's identity — used by the backend client to sign artifacts it
    /// authors (e.g. a snapshot manifest) with the device's own key.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn identity_verifying_bytes(&self) -> [u8; 32] {
        self.identity.verifying_key_bytes()
    }

    /// The committed document version, encoded for the `Have` wire frame.
    pub fn doc_version_bytes(&self) -> Vec<u8> {
        self.doc.version().to_bytes()
    }

    /// The raw bytes of `peer_id`'s stored oplog file (`ops/ops-<peer>.jsonl`),
    /// for relaying a third-party log to another peer. NotFound ⇒ empty.
    pub fn export_peer_log(&self, peer_id: u64) -> Result<Vec<u8>, StorageError> {
        let path = self.root.join("ops").join(format!("ops-{peer_id}.jsonl"));
        match std::fs::read(&path) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Apply an appended chunk of `author`'s oplog received from a peer.
    ///
    /// These logs are append-only JSONL: earlier bytes never change, so the
    /// correct log is byte-prefix-consistent. The engine ships the author's FULL
    /// log on every handshake/`Have` (not just a suffix), so we merge the incoming
    /// `appended` bytes against what we already hold prefix-aware, avoiding
    /// doubling the on-disk `ops/ops-<author>.jsonl` on every reconnect:
    /// - `appended` starts with ours → take `appended` (first time, since empty
    ///   is a prefix of everything, or a full/longer resend);
    /// - ours starts with `appended` → keep ours (stale/duplicate prefix);
    /// - otherwise                   → `stored ++ appended` with any shared
    ///   boundary trimmed (a genuine suffix that raced a full relayed copy can
    ///   start mid-log; the overlap trim keeps it from duplicating an entry).
    ///
    /// The resulting whole log goes to [`Store::import_peer`], which verifies,
    /// refuses to shrink, and advances `persisted`. We never import our own ops
    /// as a peer.
    pub fn apply_peer_ops(
        &mut self,
        author: u64,
        key: &VerifyingKey,
        appended: &[u8],
    ) -> Result<(), StorageError> {
        if author == self.identity.peer_id() {
            return Ok(());
        }
        let stored = self.export_peer_log(author)?;
        let whole = if appended.starts_with(&stored) {
            // First time (empty stored is a prefix of everything) or a full/longer
            // resend: take `appended`, avoiding a duplicate concatenation.
            appended.to_vec()
        } else if stored.starts_with(appended) {
            // Stale/duplicate prefix: keep the longer bytes we already hold.
            stored
        } else {
            // Genuine suffix continuation. Trim any overlap so a suffix learned
            // from another source at a different byte offset can't duplicate a
            // boundary entry (append-only logs can arrive interleaved: a
            // live-push suffix may race a full relayed copy).
            let overlap = (1..=stored.len().min(appended.len()))
                .rev()
                .find(|&k| stored.ends_with(&appended[..k]))
                .unwrap_or(0);
            let mut whole = stored;
            whole.extend_from_slice(&appended[overlap..]);
            whole
        };
        self.import_peer(author, key, whole)
    }

    /// The current materialized roster (clone of the cached peer set).
    pub fn roster(&self) -> Vec<PeerRecord> {
        self.peers.clone()
    }

    /// Vouch for `peer_id` (holding `key_bytes`): append an `Add` to our own
    /// roster log, re-merge the peer set, and refresh the `peers.json` cache.
    ///
    /// Enforces the `peer_id == first-8-LE-bytes(key)` binding (see
    /// [`derived_peer_id`]) BEFORE writing anything, so a joiner (e.g. via
    /// pairing) can never register a `peer_id` that does not derive from the key
    /// it presents — that would poison op attribution (`key_for(peer_id)` would
    /// map to the wrong key).
    ///
    /// Admin-only: only a device whose own materialized role is `Admin` may vouch.
    pub fn add_peer(
        &mut self,
        peer_id: u64,
        key_bytes: [u8; 32],
        role: Role,
    ) -> Result<(), StorageError> {
        self.require_admin()?;
        Self::check_peer_id_binding(peer_id, &key_bytes)?;
        self.own_roster
            .append(&self.identity, RosterOp::Add { role }, peer_id, key_bytes)?;
        self.refresh_peers()
    }

    /// Change an existing peer's role. Admin-only.
    pub fn set_role(
        &mut self,
        peer_id: u64,
        key_bytes: [u8; 32],
        role: Role,
    ) -> Result<(), StorageError> {
        self.require_admin()?;
        Self::check_peer_id_binding(peer_id, &key_bytes)?;
        self.own_roster.append(
            &self.identity,
            RosterOp::SetRole { role },
            peer_id,
            key_bytes,
        )?;
        self.refresh_peers()
    }

    /// A peer's materialized role, or `None` if not vouched.
    pub fn role_of(&self, peer_id: u64) -> Option<Role> {
        self.peers
            .iter()
            .find(|p| p.peer_id == peer_id)
            .map(|p| p.role)
    }

    /// Guard for Admin-only mutations.
    fn require_admin(&self) -> Result<(), StorageError> {
        if self.self_role() == Some(Role::Admin) {
            Ok(())
        } else {
            Err(StorageError::Peer("device is not an admin".into()))
        }
    }

    /// Revoke `peer_id`: append a `Revoke` to our own roster log, re-merge the
    /// peer set, and refresh the `peers.json` cache. Admin-only.
    pub fn revoke_peer(&mut self, peer_id: u64, key_bytes: [u8; 32]) -> Result<(), StorageError> {
        self.require_admin()?;
        Self::check_peer_id_binding(peer_id, &key_bytes)?;
        self.own_roster
            .append(&self.identity, RosterOp::Revoke, peer_id, key_bytes)?;
        self.refresh_peers()
    }

    /// Genesis: pin THIS device as founder and self-vouch it with `role`. Refuses if
    /// a founder is already pinned (re-declaring would fork trust).
    pub fn declare_founder(&mut self, role: Role) -> Result<(), StorageError> {
        if role != Role::Admin {
            return Err(StorageError::Peer(
                "founder must be Admin (it is the vault's root authority)".into(),
            ));
        }
        if crate::founder::read_founder(&self.root)?.is_some() {
            return Err(StorageError::Peer("vault founder already pinned".into()));
        }
        let me = self.identity.peer_id();
        crate::founder::write_founder(&self.root, me)?;
        self.founder = Some(me);
        let key = self.identity.verifying_key().to_bytes();
        self.own_roster
            .append(&self.identity, RosterOp::Add { role }, me, key)?;
        self.refresh_peers()
    }

    /// Write a founder pin delivered out-of-band (joiner). Idempotent if it matches;
    /// refuses a conflicting re-pin.
    pub fn pin_founder(&mut self, peer_id: u64) -> Result<(), StorageError> {
        match crate::founder::read_founder(&self.root)? {
            Some(existing) if existing == peer_id => Ok(()),
            Some(existing) => Err(StorageError::Peer(format!(
                "founder already pinned to {existing}, refusing to re-pin to {peer_id}"
            ))),
            None => {
                crate::founder::write_founder(&self.root, peer_id)?;
                self.founder = Some(peer_id);
                self.refresh_peers()
            }
        }
    }

    /// The pinned vault founder's `peer_id` (`<root>/founder`), if any. The
    /// founder seeds the roster fold's `ever_admin` closure; a joiner needs it
    /// to materialize any role at all.
    pub fn founder_pin(&self) -> Option<u64> {
        self.founder
    }

    /// This device's own materialized role (None if not yet in the roster).
    pub fn self_role(&self) -> Option<Role> {
        let me = self.identity.peer_id();
        self.peers.iter().find(|p| p.peer_id == me).map(|p| p.role)
    }

    /// Reject a roster mutation whose `peer_id` does not match the key it is
    /// bound to. Everywhere in roam a `peer_id` is the first 8 little-endian
    /// bytes of the ed25519 verifying key (see `Identity::generate`), so this is
    /// the single binding invariant every roster-add path must uphold.
    fn check_peer_id_binding(peer_id: u64, key_bytes: &[u8; 32]) -> Result<(), StorageError> {
        if peer_id != derived_peer_id(key_bytes) {
            return Err(StorageError::Peer(
                "peer_id does not match verifying key (first 8 LE bytes)".into(),
            ));
        }
        Ok(())
    }

    /// Re-run the roster fixpoint from disk and rewrite the cache. Called after
    /// any roster mutation so `self.peers` and `peers.json` stay in sync.
    fn refresh_peers(&mut self) -> Result<(), StorageError> {
        self.peers = Self::rebuild_peers(
            &self.root,
            self.identity.peer_id(),
            &self.identity.verifying_key(),
            self.founder,
        )?;
        self.write_peers_cache()
    }

    /// The raw bytes of this device's own roster log (for copying to a peer).
    pub fn export_own_roster(&self) -> Result<Vec<u8>, StorageError> {
        match std::fs::read(self.own_roster.path()) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Import a peer's roster-log bytes: verify against `key` before writing,
    /// refuse an older/shorter resend, persist, then re-merge the peer set.
    pub fn import_roster(
        &mut self,
        author: u64,
        key: &VerifyingKey,
        bytes: Vec<u8>,
    ) -> Result<(), StorageError> {
        // Never write foreign bytes over our OWN roster.
        if author == self.identity.peer_id() {
            return Err(StorageError::Peer(
                "cannot import a roster log under our own peer id".into(),
            ));
        }

        let roster_dir = self.roster_dir();
        std::fs::create_dir_all(&roster_dir)?;
        let roster_log = RosterLog::new(&roster_dir, author);
        let roster_path = roster_log.path();

        // Roster logs are append-only: refuse a shorter/older resend that would
        // truncate newer entries already on disk.
        if let Ok(existing) = std::fs::read(&roster_path) {
            if bytes.len() < existing.len() {
                return Err(StorageError::Peer(format!(
                    "refusing to shrink roster {author} log ({} < {} bytes)",
                    bytes.len(),
                    existing.len()
                )));
            }
        }

        // Verify BEFORE persisting: a forged/tampered roster must never touch disk.
        roster_log.verify_bytes(key, &bytes)?;
        std::fs::write(&roster_path, &bytes)?;
        self.refresh_peers()
    }

    /// The raw bytes of EVERY roster log this device holds, keyed by author
    /// peer id. This is the TRANSITIVE roster the host ships at pairing: a
    /// non-founder admin B holds both `roster-<A>.jsonl` (the founder chain it
    /// received when it joined) and its own `roster-<B>.jsonl`, so a joiner C can
    /// fold the full A->B->C chain. Bytes are returned unverified — each trusted
    /// author's log is verified during the roster fold on the receiving side.
    pub fn export_all_rosters(&self) -> Result<Vec<(u64, Vec<u8>)>, StorageError> {
        let roster_dir = self.roster_dir();
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&roster_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // Filenames are `roster-<author>.jsonl`; skip anything else.
            let Some(rest) = name.strip_prefix("roster-") else {
                continue;
            };
            let Some(author_str) = rest.strip_suffix(".jsonl") else {
                continue;
            };
            let Ok(author) = author_str.parse::<u64>() else {
                continue;
            };
            let bytes = std::fs::read(entry.path())?;
            out.push((author, bytes));
        }
        Ok(out)
    }

    /// Import a bundle of roster logs delivered at pairing (the host's transitive
    /// roster). Unlike [`Self::import_roster`], the receiver does NOT yet hold each
    /// author's key, so verification is deferred to the roster fold: we dump the
    /// raw logs to disk (never overwriting our OWN, never shrinking an existing
    /// log) and then `refresh_peers` once — `rebuild_peers` verifies each trusted
    /// author's log as it folds, and skips any that fail.
    pub fn import_roster_bundle(&mut self, logs: Vec<(u64, Vec<u8>)>) -> Result<(), StorageError> {
        let roster_dir = self.roster_dir();
        std::fs::create_dir_all(&roster_dir)?;
        let me = self.identity.peer_id();
        for (author, bytes) in logs {
            // Never overwrite our own roster log with foreign bytes.
            if author == me {
                continue;
            }
            let roster_log = RosterLog::new(&roster_dir, author);
            let roster_path = roster_log.path();
            // Append-only: refuse a shorter/older resend that would truncate newer
            // entries already on disk.
            if let Ok(existing) = std::fs::read(&roster_path) {
                if bytes.len() < existing.len() {
                    continue;
                }
            }
            std::fs::write(&roster_path, &bytes)?;
        }
        self.refresh_peers()
    }

    fn keylog_dir(&self) -> PathBuf {
        self.root.join("keylog")
    }

    /// Replay every trusted author's key-log (verified against the key the roster
    /// vouches for) into one merged, verified entry list. Untrusted/unkeyed
    /// authors are skipped — same trust boundary as ops/roster replay.
    fn merged_keylog(&self) -> Result<Vec<KeyLogEntry>, StorageError> {
        let dir = self.keylog_dir();
        let mut all = Vec::new();
        let own = KeyLog::new(&dir, self.identity.peer_id());
        all.extend(own.read_verified(&self.identity.verifying_key())?);
        for peer in self.peers.iter() {
            if peer.status != PeerStatus::Active || peer.peer_id == self.identity.peer_id() {
                continue;
            }
            let Ok(pkey) = VerifyingKey::from_bytes(&peer.verifying_key) else {
                continue;
            };
            let log = KeyLog::new(&dir, peer.peer_id);
            all.extend(log.read_verified(&pkey)?);
        }
        Ok(all)
    }

    /// Build this device's [`Keychain`] from the merged key-log. `id_key` and
    /// `epoch0_key` are the two subkeys of the vault key (see
    /// `roam_backend_client::crypto::VaultKey::{id_key,epoch0_key}`), passed in
    /// because the Store deliberately never persists the vault secret.
    pub fn keychain(
        &self,
        id_key: &[u8; 32],
        epoch0_key: &[u8; 32],
    ) -> Result<Keychain, StorageError> {
        let entries = self.merged_keylog()?;
        Ok(Keychain::build(
            *id_key,
            *epoch0_key,
            self.identity.peer_id(),
            &self.identity.x25519_secret(),
            &entries,
        ))
    }

    /// The recovery state machine result (empty == `Synced`).
    pub fn vault_state(
        &self,
        id_key: &[u8; 32],
        epoch0_key: &[u8; 32],
    ) -> Result<Vec<VaultIssue>, StorageError> {
        let kc = self.keychain(id_key, epoch0_key)?;
        Ok(kc.diagnose(&self.peers))
    }

    /// Mint a new epoch: a fresh random key parented on the current DAG head(s),
    /// wrapped to every current member and (optionally) the paper key. Appends a
    /// `Rotate` + the `Wrap`s to our OWN key-log, signed. Returns the new
    /// `epoch_id`.
    pub fn rotate_epoch(
        &mut self,
        id_key: &[u8; 32],
        epoch0_key: &[u8; 32],
        paper_public: Option<[u8; 32]>,
    ) -> Result<[u8; 32], StorageError> {
        self.require_admin()?;
        let kc = self.keychain(id_key, epoch0_key)?;
        let parents = kc.dag_heads();
        let mut nonce = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut new_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut new_key);
        let epoch_id = compute_epoch_id(&parents, self.identity.peer_id(), &nonce);

        let log = KeyLog::new(&self.keylog_dir(), self.identity.peer_id());
        log.append(
            &self.identity,
            epoch_id,
            KeyBody::Rotate {
                parent_epochs: parents,
                nonce,
            },
        )?;
        for peer in self.peers.iter().filter(|p| p.status == PeerStatus::Active) {
            let pub_x = match VerifyingKey::from_bytes(&peer.verifying_key) {
                Ok(k) => k.to_x25519(),
                Err(_) => continue,
            };
            let blob = keywrap::wrap(&pub_x, &new_key);
            log.append(
                &self.identity,
                epoch_id,
                KeyBody::Wrap {
                    recipient: Recipient::Device(peer.peer_id),
                    blob,
                },
            )?;
        }
        // Always wrap to self even if not yet in our own roster.
        if !self
            .peers
            .iter()
            .any(|p| p.peer_id == self.identity.peer_id())
        {
            let blob = keywrap::wrap(&self.identity.x25519_public(), &new_key);
            log.append(
                &self.identity,
                epoch_id,
                KeyBody::Wrap {
                    recipient: Recipient::Device(self.identity.peer_id()),
                    blob,
                },
            )?;
        }
        if let Some(paper) = paper_public {
            let blob = keywrap::wrap(&paper, &new_key);
            log.append(
                &self.identity,
                epoch_id,
                KeyBody::Wrap {
                    recipient: Recipient::Paper,
                    blob,
                },
            )?;
        }
        Ok(epoch_id)
    }

    /// Wrap-back-fill: for every (epoch we can open, current member with no wrap),
    /// append a `Wrap` to our OWN key-log. Convergent; safe to call on any
    /// key-log/roster change. Returns how many wraps were published.
    pub fn backfill_wraps(
        &mut self,
        id_key: &[u8; 32],
        epoch0_key: &[u8; 32],
    ) -> Result<usize, StorageError> {
        let kc = self.keychain(id_key, epoch0_key)?;
        let targets = kc.backfill_targets(&self.peers);
        if targets.is_empty() {
            return Ok(0);
        }
        let log = KeyLog::new(&self.keylog_dir(), self.identity.peer_id());
        let mut published = 0;
        for (epoch, key, peer_id) in targets {
            let pub_x = match self.peers.iter().find(|p| p.peer_id == peer_id) {
                Some(p) => match VerifyingKey::from_bytes(&p.verifying_key) {
                    Ok(k) => k.to_x25519(),
                    Err(_) => continue,
                },
                None => continue,
            };
            let blob = keywrap::wrap(&pub_x, &key);
            log.append(
                &self.identity,
                epoch,
                KeyBody::Wrap {
                    recipient: Recipient::Device(peer_id),
                    blob,
                },
            )?;
            published += 1;
        }
        Ok(published)
    }

    /// The raw bytes of this device's own key-log (for copying to a peer).
    pub fn export_own_keylog(&self) -> Result<Vec<u8>, StorageError> {
        match std::fs::read(KeyLog::new(&self.keylog_dir(), self.identity.peer_id()).path()) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// The raw bytes of `author`'s stored key-log (for relaying). NotFound ⇒ empty.
    pub fn export_keylog(&self, author: u64) -> Result<Vec<u8>, StorageError> {
        match std::fs::read(KeyLog::new(&self.keylog_dir(), author).path()) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Import a peer's key-log bytes: verify against `key` before writing, refuse
    /// a shorter/older resend, persist. Mirrors [`Store::import_roster`].
    pub fn import_keylog(
        &mut self,
        author: u64,
        key: &VerifyingKey,
        bytes: Vec<u8>,
    ) -> Result<(), StorageError> {
        if author == self.identity.peer_id() {
            return Err(StorageError::Peer(
                "cannot import a key-log under our own peer id".into(),
            ));
        }
        let dir = self.keylog_dir();
        std::fs::create_dir_all(&dir)?;
        let log = KeyLog::new(&dir, author);
        let path = log.path();
        if let Ok(existing) = std::fs::read(&path) {
            if bytes.len() < existing.len() {
                return Err(StorageError::Peer(format!(
                    "refusing to shrink keylog {author} ({} < {} bytes)",
                    bytes.len(),
                    existing.len()
                )));
            }
        }
        log.verify_bytes(key, &bytes)?;
        std::fs::write(&path, &bytes)?;
        Ok(())
    }

    /// Import a peer's oplog bytes: write them to `ops/ops-<peer>.jsonl`,
    /// verify every entry against `key`, and merge into the document.
    pub fn import_peer(
        &mut self,
        peer_id: u64,
        key: &VerifyingKey,
        log_bytes: Vec<u8>,
    ) -> Result<(), StorageError> {
        // The roster is the trust boundary: only accept ops from a peer we
        // currently vouch for. Unknown or revoked peers are refused outright.
        match self.peers.iter().find(|p| p.peer_id == peer_id) {
            Some(p) if p.status == PeerStatus::Active && p.role != Role::Reader => {}
            Some(p) if p.status == PeerStatus::Active => {
                return Err(StorageError::Peer(format!(
                    "refusing content ops from reader peer {peer_id}"
                )));
            }
            Some(_) => {
                return Err(StorageError::Peer(format!(
                    "refusing ops from revoked peer {peer_id}"
                )));
            }
            None => {
                return Err(StorageError::Peer(format!(
                    "refusing ops from unknown peer {peer_id}"
                )));
            }
        }

        // Never write foreign bytes over our OWN log.
        if peer_id == self.identity.peer_id() {
            return Err(StorageError::Peer(
                "cannot import a peer log under our own peer id".into(),
            ));
        }

        let ops_dir = self.root.join("ops");
        std::fs::create_dir_all(&ops_dir)?;
        let peer_log_path = ops_dir.join(format!("ops-{peer_id}.jsonl"));

        // Op logs are append-only and single-author, so every correct copy of an
        // author's log is byte-prefix-consistent. The entry-level reconciliation
        // is now done up-stack by [`Store::apply_peer_ops`] (prefix-aware +
        // overlap-trim merge), enabled by the roster (peers.json) and the iroh
        // transport that have since landed — so this method receives an already
        // merged, longer-or-equal `log_bytes` on that path. This length check is
        // the remaining truncation guard: refuse a shorter/older resend that would
        // clobber newer peer ops already on disk. (`apply_peer_ops` never trips it
        // — it always yields a longer-or-equal log; it only catches a raw,
        // out-of-band shorter `import_peer` call.)
        if let Ok(existing) = std::fs::read(&peer_log_path) {
            if log_bytes.len() < existing.len() {
                return Err(StorageError::Peer(format!(
                    "refusing to shrink peer {peer_id} log ({} < {} bytes)",
                    log_bytes.len(),
                    existing.len()
                )));
            }
        }

        // Verify BEFORE persisting: a forged/tampered peer log must never touch
        // disk (it would become a live corruption source once `open` replays
        // peer logs). Only after full verification do we write, then merge.
        let peer_log = OpLog::new(&ops_dir, peer_id);
        let entries = peer_log.verify_bytes(key, &log_bytes)?;
        std::fs::write(&peer_log_path, &log_bytes)?;
        for entry in entries {
            self.doc.import(&entry.update)?;
        }
        self.doc.commit();
        // Peer ops are now part of our committed state; advance `persisted` so a
        // later local edit does NOT re-export them into our OWN (own-key-signed)
        // log — that would mis-attribute the peer's ops to us.
        self.persisted = self.doc.version();
        Ok(())
    }

    /// Append one already-formed peer op-log line if absent (exact-bytes dedup),
    /// then re-import the peer log. Order-independent: Loro buffers ops whose
    /// deps are absent and converges once the missing ancestor lands. Used by
    /// the backend content-id fetch path (`roam-backend-client::sync`), which
    /// resolves entries out of causal order (RBSR discovery is set-based, not
    /// sequential).
    pub fn dedup_append_peer_line(
        &mut self,
        author: u64,
        key: &VerifyingKey,
        line: &[u8],
    ) -> Result<(), StorageError> {
        if author == self.identity.peer_id() {
            return Ok(());
        }
        let existing = self.export_peer_log(author)?;
        let already = split_log_lines_bytes(&existing)
            .iter()
            .any(|l| l.as_slice() == line);
        if already {
            return Ok(());
        }
        // Build the candidate whole log IN MEMORY and hand it to `import_peer`,
        // which verifies (`verify_bytes`) BEFORE it persists. Never append the
        // raw fetched line to disk ourselves: a corrupt/forged/bit-flipped line
        // would otherwise land on disk unverified, and since `verify_bytes`
        // rejects the WHOLE log on the first bad line, every future import would
        // fail — permanently poisoning that peer's log. Keeping the write inside
        // `import_peer` means a bad line leaves the on-disk file untouched.
        let mut whole = existing;
        if !whole.is_empty() && !whole.ends_with(b"\n") {
            whole.push(b'\n');
        }
        whole.extend_from_slice(line);
        if !whole.ends_with(b"\n") {
            whole.push(b'\n');
        }
        self.import_peer(author, key, whole)
    }

    /// Rewrite the `peers.json` materialized cache via a temp file + rename.
    ///
    /// Like the snapshot, this is a **rebuildable cache** (the signed roster logs
    /// are the source of truth, and `open()` always rebuilds from them), so it
    /// deliberately does NOT `fsync` — a crash that loses the newest cache just
    /// means a rebuild from the roster logs on next open, never lost trust.
    fn write_peers_cache(&self) -> Result<(), StorageError> {
        let path = self.root.join("peers.json");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(&self.peers)?;
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Every blob hash referenced by the fileset map across the retained marker
    /// frontiers (base64) in `retained`, plus the current live/tombstoned set.
    /// Walks history via checkout, then returns to latest.
    fn referenced_hashes(&self, retained: &[String]) -> Result<HashSet<String>, StorageError> {
        use roam_crdt::Frontier;
        let mut refs = HashSet::new();
        for f_b64 in retained {
            let bytes = B64
                .decode(f_b64.as_bytes())
                .map_err(|e| StorageError::Base64(e.to_string()))?;
            let frontier = Frontier::from_bytes(&bytes)?;
            self.doc.checkout(&frontier)?;
            for (_k, v) in self.doc.entries(FILESET_MAP_ID) {
                if let Some(h) = extract_content_hash(&v) {
                    refs.insert(h);
                }
            }
        }
        self.doc.checkout_latest();
        for (_k, v) in self.doc.entries(FILESET_MAP_ID) {
            if let Some(h) = extract_content_hash(&v) {
                refs.insert(h);
            }
        }
        Ok(refs)
    }

    /// Bytes a checkpoint at `before_ts` would free (blobs). No mutation.
    pub fn checkpoint_dry_run(&self, before_ts: i64) -> Result<u64, StorageError> {
        let idx = HistoryIndex::new(&self.root.join("history"));
        let target = match idx.marker_before(before_ts)? {
            Some(m) => m,
            None => return Ok(0),
        };
        let retained: Vec<String> = idx
            .markers()?
            .into_iter()
            .filter(|m| m.ts_ms >= target.ts_ms)
            .map(|m| m.frontier)
            .collect();
        let referenced = self.referenced_hashes(&retained)?;
        let mut on_disk = Vec::new();
        for h in self.blobs.list()? {
            let sz = self.blobs.size(&h)?.unwrap_or(0);
            on_disk.push((h, sz));
        }
        Ok(crate::checkpoint::reclaimable_blob_bytes(
            &on_disk,
            &referenced,
        ))
    }

    /// Execute a checkpoint keeping history at/after the newest marker with
    /// `ts_ms <= before_ts`. Shallow-snapshots at that frontier, truncates each
    /// peer op-log to its retained tail, reclaims unreferenced blobs. Local-only;
    /// emits no ops. Returns bytes freed. `i64::MAX` = checkpoint to latest.
    pub fn checkpoint(&mut self, before_ts: i64) -> Result<u64, StorageError> {
        use roam_crdt::Frontier;
        let idx = HistoryIndex::new(&self.root.join("history"));
        let target = match idx.marker_before(before_ts)? {
            Some(m) => m,
            None => return Ok(0),
        };
        let all = idx.markers()?;
        let retained: Vec<String> = all
            .iter()
            .filter(|m| m.ts_ms >= target.ts_ms)
            .map(|m| m.frontier.clone())
            .collect();

        // 1. Referenced hashes BEFORE mutating (needs full history present).
        let referenced = self.referenced_hashes(&retained)?;

        // 2. Shallow snapshot at the target frontier -> overwrite the snapshot base.
        let fbytes = B64
            .decode(target.frontier.as_bytes())
            .map_err(|e| StorageError::Base64(e.to_string()))?;
        let frontier = Frontier::from_bytes(&fbytes)?;
        let shallow = self.doc.shallow_snapshot(&frontier)?;
        crate::snapshot::save(&self.root.join("snapshots").join("snapshot.loro"), &shallow)?;

        // 3. Truncate each peer op-log to its retained tail.
        let plan = crate::checkpoint::plan_from_marker(&target);
        for (peer, drop) in &plan.drop_lines {
            let path = if *peer == self.peer_id() {
                self.own_log.path()
            } else {
                self.root.join("ops").join(format!("ops-{peer}.jsonl"))
            };
            truncate_leading_lines(&path, *drop as usize)?;
        }

        // 4. Reclaim unreferenced blobs.
        let mut freed = 0u64;
        for h in self.blobs.list()? {
            if !referenced.contains(&h) {
                freed += self.blobs.size(&h)?.unwrap_or(0);
                self.blobs.remove(&h)?;
            }
        }

        // 5. Compact history to the retained markers.
        rewrite_history(&self.root.join("history"), &all, target.ts_ms)?;
        Ok(freed)
    }

    /// Build a shallow snapshot suitable for upload to the backend, at the newest
    /// history marker with `ts_ms <= before_ts`. Read-only — emits no ops, mutates
    /// nothing on disk. Returns `None` when no marker qualifies (nothing to
    /// snapshot yet). The caller seals `bytes`, derives entry-ids from
    /// `subsumed_lines`, and derives blob-ids from `blob_refs`.
    ///
    /// `before_ts` is an ABSOLUTE timestamp (like [`Store::checkpoint`]); a caller
    /// wanting a "keep the last N days as a replayable tail" policy passes
    /// `now_ms - retention_lag_ms`, and one wanting a head snapshot passes
    /// `i64::MAX`.
    pub fn build_backend_snapshot(
        &self,
        before_ts: i64,
    ) -> Result<Option<BackendSnapshot>, StorageError> {
        use roam_crdt::Frontier;
        let idx = HistoryIndex::new(&self.root.join("history"));
        let target = match idx.marker_before(before_ts)? {
            Some(m) => m,
            None => return Ok(None),
        };

        // Shallow snapshot at the target frontier.
        let fbytes = B64
            .decode(target.frontier.as_bytes())
            .map_err(|e| StorageError::Base64(e.to_string()))?;
        let frontier = Frontier::from_bytes(&fbytes)?;
        let bytes = self.doc.shallow_snapshot(&frontier)?;
        let frontier_digest: [u8; 32] = blake3::hash(&fbytes).into();

        // Subsumed op-log lines: the first `count` lines of each peer's log are
        // the ones this snapshot replaces (mirrors the checkpoint drop plan).
        let plan = crate::checkpoint::plan_from_marker(&target);
        let mut subsumed_lines = Vec::new();
        for (peer, count) in &plan.drop_lines {
            let log = if *peer == self.peer_id() {
                self.export_own_log()?
            } else {
                self.export_peer_log(*peer)?
            };
            for line in split_log_lines_bytes(&log)
                .into_iter()
                .take(*count as usize)
            {
                subsumed_lines.push((*peer, line));
            }
        }

        // Blobs referenced by the snapshot state — the keep-alive set for blob GC.
        // (`referenced_hashes` also unions the latest state, which can only
        // over-retain a blob, never orphan one still in use — safe.)
        let mut blob_refs: Vec<String> = self
            .referenced_hashes(&[target.frontier.clone()])?
            .into_iter()
            .collect();
        blob_refs.sort();

        Ok(Some(BackendSnapshot {
            bytes,
            frontier_digest,
            subsumed_lines,
            blob_refs,
        }))
    }

    /// Record that this device holds backend snapshot `id`, which subsumes the
    /// given entry-ids. Append-only sidecar (`<root>/snapshots/held.jsonl`),
    /// deduped by id. Drives the backend loop's snapshot advertising +
    /// stop-advertising-subsumed logic.
    pub fn record_held_snapshot(&self, id: &str, subsumed: &[String]) -> Result<(), StorageError> {
        if self.held_snapshots()?.iter().any(|h| h.id == id) {
            return Ok(());
        }
        let dir = self.root.join("snapshots");
        std::fs::create_dir_all(&dir)?;
        let held = HeldSnapshot {
            id: id.to_string(),
            subsumed: subsumed.to_vec(),
        };
        let mut line = serde_json::to_vec(&held)?;
        line.push(b'\n');
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("held.jsonl"))?;
        f.write_all(&line)?;
        Ok(())
    }

    /// The backend snapshots this device holds (see [`Store::record_held_snapshot`]).
    pub fn held_snapshots(&self) -> Result<Vec<HeldSnapshot>, StorageError> {
        let path = self.root.join("snapshots").join("held.jsonl");
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            out.push(serde_json::from_str(line)?);
        }
        Ok(out)
    }

    /// Adopt a snapshot received from a peer or the backend. **Additive**: it
    /// merges the snapshot's state into the live doc and NEVER truncates this
    /// device's op-logs. A device can therefore only ever "lose" history it never
    /// had — importing a snapshot cannot reach across and drop history a
    /// well-stocked device holds locally (design invariant). Local space reclaim
    /// remains the separate, explicit job of [`Store::checkpoint`].
    pub fn adopt_snapshot(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        self.doc.import(bytes)?;
        self.doc.commit();
        // Persist the merged state as the fast-load base so a reopen keeps it —
        // the op-logs are untouched, so without this the adopted state would be
        // lost on reload. No history marker: adopting a peer's snapshot is not a
        // local checkpoint moment.
        let path = self.root.join("snapshots").join("snapshot.loro");
        snapshot::save(&path, &self.doc.snapshot()?)?;
        // Advance `persisted` so these foreign ops are never re-exported into our
        // own (own-key-signed) log — mirrors `import_peer`.
        self.persisted = self.doc.version();
        Ok(())
    }

    /// The serialized entry value for `key` in `map_id` as of the newest retained
    /// marker at/before `before_ts`, or `None` if no such marker exists or that
    /// point can't be checked out (already compacted below the shallow base).
    /// Checks out the historical frontier, reads, and returns to latest.
    pub fn historical_entry(
        &self,
        map_id: &str,
        key: &str,
        before_ts: i64,
    ) -> Result<Option<String>, StorageError> {
        use roam_crdt::Frontier;
        let idx = HistoryIndex::new(&self.root.join("history"));
        let marker = match idx.marker_before(before_ts)? {
            Some(m) => m,
            None => return Ok(None),
        };
        let fbytes = B64
            .decode(marker.frontier.as_bytes())
            .map_err(|e| StorageError::Base64(e.to_string()))?;
        let frontier = Frontier::from_bytes(&fbytes)?;
        if self.doc.checkout(&frontier).is_err() {
            // Re-attach to latest even on the error branch so a failed checkout
            // never leaves the doc pinned at a partial/old frontier.
            self.doc.checkout_latest();
            return Ok(None);
        }
        let value = self.doc.get_entry(map_id, key);
        self.doc.checkout_latest();
        Ok(value)
    }
}

/// A shallow snapshot ready for backend upload, plus the metadata the backend's
/// zero-knowledge retention sweep needs (all opaque once ids are derived).
/// Produced by [`Store::build_backend_snapshot`]; the caller seals `bytes` and
/// maps `subsumed_lines`/`blob_refs` into backend ids.
#[derive(Debug, Clone)]
pub struct BackendSnapshot {
    /// Loro shallow-snapshot bytes at the covered frontier (PLAINTEXT — the
    /// caller seals before upload).
    pub bytes: Vec<u8>,
    /// blake3 of the covered frontier bytes; the snapshot's stable identity.
    pub frontier_digest: [u8; 32],
    /// `(peer, line)` for every op-log line this snapshot subsumes. The caller
    /// derives each backend entry-id via `VaultKey::entry_id_content(peer, line)`.
    pub subsumed_lines: Vec<(u64, Vec<u8>)>,
    /// Content hashes of blobs the snapshot state references (sorted, deduped).
    /// The caller maps each to a backend blob-id via `VaultKey::blob_id`.
    pub blob_refs: Vec<String>,
}

/// A backend snapshot this device holds (authored or adopted), plus the entry-ids
/// it subsumes. Persisted so the backend sync loop can advertise held snapshots
/// and stop advertising the entries they replace (killing the RBSR re-pull fight).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeldSnapshot {
    pub id: String,
    pub subsumed: Vec<String>,
}

/// Mirrors `roam_files::fileset::FILESET_MAP_ID`. Kept as a literal to avoid a
/// storage->files dependency cycle; a roam-files test asserts they stay equal.
const FILESET_MAP_ID: &str = "__roam_fileset__";

/// Extract the `content_hash` string from a serialized `FileEntry` JSON value.
fn extract_content_hash(value: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(value).ok()?;
    v.get("content_hash")?.as_str().map(|s| s.to_string())
}

/// Split a JSONL byte buffer into its individual lines, each chunk keeping its
/// trailing `\n` (a torn final line without a newline is its own chunk).
/// Mirrors `roam_backend_client::entries::split_log_lines`, duplicated here so
/// `roam-storage` (a dependency of that crate) never needs a reverse edge.
fn split_log_lines_bytes(log: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, b) in log.iter().enumerate() {
        if *b == b'\n' {
            out.push(log[start..=i].to_vec());
            start = i + 1;
        }
    }
    if start < log.len() {
        out.push(log[start..].to_vec());
    }
    out
}

/// Drop the first `n` non-empty lines from a JSONL file, rewriting atomically.
fn truncate_leading_lines(path: &std::path::Path, n: usize) -> Result<(), StorageError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .skip(n)
        .collect();
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    let tmp = path.with_extension("jsonl.tmp");
    std::fs::write(&tmp, out.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Rewrite history.jsonl keeping only markers with `ts_ms >= keep_from`.
fn rewrite_history(
    dir: &std::path::Path,
    all: &[Marker],
    keep_from: i64,
) -> Result<(), StorageError> {
    let path = dir.join("history.jsonl");
    let mut out = String::new();
    for m in all.iter().filter(|m| m.ts_ms >= keep_from) {
        out.push_str(&serde_json::to_string(m)?);
        out.push('\n');
    }
    let tmp = path.with_extension("jsonl.tmp");
    std::fs::write(&tmp, out.as_bytes())?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use tempfile::tempdir;

    #[test]
    fn store_owns_a_blob_store_rooted_at_assets() {
        // The Store opens a BlobStore under `<root>/assets` so blob bytes live
        // beside the CRDT state and callers reach them via `blobs()`.
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path(), Identity::generate()).unwrap();

        let hash = store.blobs().put(&[0x00, 0xff, 0x7f]).unwrap();
        assert!(store.blobs().has(&hash));
        assert_eq!(
            store.blobs().get(&hash).unwrap(),
            Some(vec![0x00, 0xff, 0x7f])
        );
        // Bytes landed under the assets dir beside the CRDT state.
        assert!(dir.path().join("assets").join(&hash).exists());
    }

    #[test]
    fn data_size_sums_blobs_oplog_and_meta_on_disk() {
        // data_size() reports on-disk byte usage broken down by category so a
        // client can show "how big is my vault" without walking the disk itself.
        let dir = tempdir().unwrap();
        let mut store = Store::open(dir.path(), Identity::generate()).unwrap();

        // Empty vault: nothing written yet, every bucket is zero.
        let empty = store.data_size().unwrap();
        assert_eq!(empty.blobs, 0, "no blobs yet");
        assert_eq!(empty.total, empty.blobs + empty.oplog + empty.meta);

        // Blobs bucket == exact sum of stored blob bytes (3 + 5 = 8).
        store.blobs().put(&[1, 2, 3]).unwrap();
        store.blobs().put(&[9, 8, 7, 6, 5]).unwrap();
        // An edit + snapshot writes the op-log and snapshot (the oplog bucket).
        store.declare_founder(Role::Admin).unwrap();
        store.edit_text("greeting", 0, "hello world").unwrap();
        store.write_snapshot().unwrap();

        let size = store.data_size().unwrap();
        assert_eq!(size.blobs, 8, "blobs bucket is the exact blob byte sum");
        assert!(size.oplog > 0, "op-log/snapshot bytes were written");
        assert!(size.meta > 0, "roster/founder metadata was written");
        assert_eq!(
            size.total,
            size.blobs + size.oplog + size.meta,
            "total is the sum of every bucket"
        );
    }

    #[test]
    fn may_write_is_false_without_a_role() {
        // Role-aware may_write: a fresh store not yet in any roster has no role and
        // must not write; becoming founder-admin grants write.
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path(), Identity::generate()).unwrap();
        assert!(!store.may_write(), "no-role device must not write");
        store.declare_founder(Role::Admin).unwrap();
        assert!(store.may_write(), "admin may write");
    }

    #[test]
    fn declare_founder_rejects_a_non_admin_role() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let mut store = Store::open(dir.path(), id).unwrap();
        assert!(store.declare_founder(Role::Reader).is_err());
        assert!(store.declare_founder(Role::Writer).is_err());
        // founder file must NOT have been written by the rejected attempts:
        store.declare_founder(Role::Admin).unwrap(); // still succeeds afterwards
    }

    #[test]
    fn write_snapshot_records_a_history_marker() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path(), Identity::generate()).unwrap();
        store.edit_text("note", 0, "alpha").unwrap();
        store.write_snapshot().unwrap();

        let idx = crate::history::HistoryIndex::new(&dir.path().join("history"));
        let markers = idx.markers().unwrap();
        assert_eq!(markers.len(), 1, "one marker recorded on write_snapshot");
        let m = &markers[0];
        assert!(!m.frontier.is_empty(), "frontier bytes captured");
        assert_eq!(
            m.log_lens.get(&store.peer_id()).copied(),
            Some(1),
            "own op-log had one line at snapshot time"
        );
    }

    #[test]
    fn edits_persist_and_survive_reopen() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let id = Identity::generate();

        {
            let mut store = Store::open(&vault, id.clone()).unwrap();
            store.edit_text("note", 0, "durable").unwrap();
        } // drop: everything is on disk now.

        // Reopen from a cold Store — disk is the source of truth.
        let reopened = Store::open(&vault, id).unwrap();
        assert_eq!(reopened.text("note"), "durable");
    }

    #[test]
    fn snapshot_then_reopen_is_equivalent() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let id = Identity::generate();

        let mut store = Store::open(&vault, id.clone()).unwrap();
        store.edit_text("note", 0, "hello").unwrap();
        store.write_snapshot().unwrap();
        store.edit_text("note", 5, " more").unwrap();

        let reopened = Store::open(&vault, id).unwrap();
        assert_eq!(reopened.text("note"), "hello more");
    }

    #[test]
    fn two_stores_converge_by_exchanging_oplogs() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a.clone()).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();

        a.edit_text("note", 0, "AAA").unwrap();
        b.edit_text("note", 0, "BBB").unwrap();

        // The roster is the trust boundary: each device must vouch for the other
        // before its ops are accepted. Each vault's founder is itself (admin), so
        // its own `add_peer` vouches actually fold into the roster.
        a.declare_founder(Role::Admin).unwrap();
        b.declare_founder(Role::Admin).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();
        b.add_peer(id_a.peer_id(), id_a.verifying_key().to_bytes(), Role::Admin)
            .unwrap();

        // Copy each store's own oplog into the other and re-import.
        a.import_peer(
            id_b.peer_id(),
            &id_b.verifying_key(),
            b.export_own_log().unwrap(),
        )
        .unwrap();
        b.import_peer(
            id_a.peer_id(),
            &id_a.verifying_key(),
            a.export_own_log().unwrap(),
        )
        .unwrap();

        assert_eq!(a.text("note"), b.text("note"));
        assert_eq!(a.text("note").len(), 6); // both edits survived
        assert!(a.text("note").contains("AAA"), "lost A: {}", a.text("note"));
        assert!(a.text("note").contains("BBB"), "lost B: {}", a.text("note"));
    }

    #[test]
    fn deletes_persist_across_reopen() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let id = Identity::generate();

        {
            let mut store = Store::open(&vault, id.clone()).unwrap();
            store.edit_text("note", 0, "hello world").unwrap();
            store.delete_text("note", 5, 6).unwrap();
        }

        let reopened = Store::open(&vault, id).unwrap();
        assert_eq!(reopened.text("note"), "hello");
    }

    #[test]
    fn a_no_op_edit_appends_nothing() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let id = Identity::generate();
        let mut store = Store::open(&vault, id.clone()).unwrap();

        store.edit_text("note", 0, "hi").unwrap();
        let after_real = store.export_own_log().unwrap().len();
        // Deleting zero chars produces no ops → the log must not grow.
        store.delete_text("note", 0, 0).unwrap();
        assert_eq!(store.export_own_log().unwrap().len(), after_real);
    }

    #[test]
    fn import_peer_rejects_our_own_peer_id() {
        let dir = tempdir().unwrap();
        let id = Identity::generate();
        let mut store = Store::open(dir.path(), id.clone()).unwrap();
        let err = store.import_peer(id.peer_id(), &id.verifying_key(), Vec::new());
        assert!(matches!(err, Err(StorageError::Peer(_))));
    }

    #[test]
    fn import_peer_refuses_to_shrink_a_peer_log() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();

        // Trust b before importing its ops (a is its vault's founder-admin).
        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();

        b.edit_text("note", 0, "one").unwrap();
        b.edit_text("note", 3, "two").unwrap();
        let full = b.export_own_log().unwrap();
        a.import_peer(id_b.peer_id(), &id_b.verifying_key(), full.clone())
            .unwrap();

        // A shorter/older resend must be refused, not silently truncate on disk.
        let shorter = full[..full.len() / 2].to_vec();
        let err = a.import_peer(id_b.peer_id(), &id_b.verifying_key(), shorter);
        assert!(matches!(err, Err(StorageError::Peer(_))));
    }

    #[test]
    fn edit_after_import_does_not_re_sign_peer_ops_into_own_log() {
        // Regression: importing a peer must advance `persisted`, so a later local
        // edit exports only OUR new op — not the peer's ops re-signed under our key.
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a.clone()).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();

        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();
        a.edit_text("note", 0, "A").unwrap();
        b.edit_text("note", 0, "B").unwrap();
        a.import_peer(
            id_b.peer_id(),
            &id_b.verifying_key(),
            b.export_own_log().unwrap(),
        )
        .unwrap();
        a.edit_text("note", a.text("note").chars().count(), "C")
            .unwrap();

        // Reconstruct a document from ONLY a's own signed log. It must not contain
        // B's edit — if it does, a re-signed B's ops under its own key.
        let a_ops = dir_a.path().join("ops");
        let entries = OpLog::new(&a_ops, id_a.peer_id())
            .read_verified(&id_a.verifying_key())
            .unwrap();
        let rebuilt = roam_crdt::Document::new(id_a.peer_id()).unwrap();
        for e in &entries {
            // Ops causally depending on B's (unavailable here) simply stay pending.
            let _ = rebuilt.import(&e.update);
        }
        assert!(
            !rebuilt.text("note").contains("B"),
            "own log leaked peer B's ops under our key: {:?}",
            rebuilt.text("note")
        );
    }

    #[test]
    fn reopen_tolerates_a_torn_own_log_tail() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let id = Identity::generate();

        {
            let mut store = Store::open(&vault, id.clone()).unwrap();
            store.edit_text("note", 0, "keep").unwrap();
        }

        // Simulate a crash mid-append: a partial trailing line with no newline.
        let own_log = vault
            .join("ops")
            .join(format!("ops-{}.jsonl", id.peer_id()));
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&own_log)
            .unwrap();
        std::io::Write::write_all(&mut f, br#"{"peer":1,"sig":"tor"#).unwrap();

        // Reopen must recover the complete edit and ignore the torn tail — no error.
        let reopened = Store::open(&vault, id).unwrap();
        assert_eq!(reopened.text("note"), "keep");
    }

    #[test]
    fn add_peer_rejects_a_mismatched_peer_id_key() {
        let dir = tempdir().unwrap();
        let a = Identity::generate();
        let b = Identity::generate();
        let mut store = Store::open(dir.path(), a).unwrap();

        // Wrong peer_id (does not derive from b's key) → refused before any write.
        let bad_id = b.peer_id().wrapping_add(1);
        let err = store.add_peer(bad_id, b.verifying_key().to_bytes(), Role::Admin);
        assert!(
            matches!(err, Err(StorageError::Peer(_))),
            "mismatched peer_id must be refused"
        );
        assert!(
            store.roster().is_empty(),
            "a refused add must not touch the roster"
        );

        // Become the vault founder-admin so our own `add_peer` vouches fold.
        store.declare_founder(Role::Admin).unwrap();

        // The matching pair succeeds.
        store
            .add_peer(b.peer_id(), b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();
        assert!(store.roster().iter().any(|p| p.peer_id == b.peer_id()));
    }

    #[test]
    fn add_peer_then_reopen_lists_the_peer() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let a = Identity::generate();
        let b = Identity::generate();

        {
            let mut store = Store::open(&vault, a.clone()).unwrap();
            store.declare_founder(Role::Admin).unwrap();
            store
                .add_peer(b.peer_id(), b.verifying_key().to_bytes(), Role::Admin)
                .unwrap();
        }
        let reopened = Store::open(&vault, a).unwrap();
        let roster = reopened.roster();
        assert!(roster
            .iter()
            .any(|p| p.peer_id == b.peer_id() && p.status == crate::PeerStatus::Active));
    }

    #[test]
    fn peer_ops_survive_a_cold_reopen_once_the_peer_is_in_the_roster() {
        // Regression (resolved by the roster / peers.json, now landed): before it,
        // a peer's ops vanished on cold reopen when no snapshot existed. Now that
        // the roster vouches for the peer, open() replays its ops, so they survive.
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let a_id = Identity::generate();
        let b_id = Identity::generate();
        let vault_a = dir_a.path().join("vault");

        {
            let mut a = Store::open(&vault_a, a_id.clone()).unwrap();
            let mut b = Store::open(dir_b.path(), b_id.clone()).unwrap();
            a.declare_founder(Role::Admin).unwrap();
            a.add_peer(b_id.peer_id(), b_id.verifying_key().to_bytes(), Role::Admin)
                .unwrap();
            b.edit_text("note", 0, "from-b").unwrap();
            a.import_peer(
                b_id.peer_id(),
                &b_id.verifying_key(),
                b.export_own_log().unwrap(),
            )
            .unwrap();
            assert_eq!(a.text("note"), "from-b");
        } // drop a: no snapshot written.

        let reopened = Store::open(&vault_a, a_id).unwrap();
        assert_eq!(
            reopened.text("note"),
            "from-b",
            "roster replay must restore peer ops"
        );
    }

    #[test]
    fn revoked_peer_ops_are_rejected_on_import() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let a_id = Identity::generate();
        let b_id = Identity::generate();

        let mut a = Store::open(dir_a.path(), a_id).unwrap();
        let mut b = Store::open(dir_b.path(), b_id.clone()).unwrap();
        // Seed an admin founder so the roster fold counts a's grant certificates;
        // without it add_peer/revoke_peer are ignored and the peer stays UNKNOWN,
        // which would exercise the wrong import_peer rejection path.
        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(b_id.peer_id(), b_id.verifying_key().to_bytes(), Role::Admin)
            .unwrap();
        a.revoke_peer(b_id.peer_id(), b_id.verifying_key().to_bytes())
            .unwrap();

        b.edit_text("note", 0, "sneaky").unwrap();
        let err = a.import_peer(
            b_id.peer_id(),
            &b_id.verifying_key(),
            b.export_own_log().unwrap(),
        );
        // Must be the REVOKED path, not the UNKNOWN path: the peer was genuinely
        // vouched-for then revoked through a real founder-rooted roster.
        assert!(
            matches!(&err, Err(StorageError::Peer(msg)) if msg.contains("revoked")),
            "revoked peer ops must be refused via the revoke path, got: {err:?}"
        );
    }

    #[test]
    fn apply_peer_ops_appends_suffixes_and_converges() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();
        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();

        // First op → whole log, applied as a suffix onto empty stored bytes.
        b.edit_text("note", 0, "one").unwrap();
        let first = b.export_own_log().unwrap();
        a.apply_peer_ops(id_b.peer_id(), &id_b.verifying_key(), &first)
            .unwrap();
        assert_eq!(a.text("note"), "one");

        // Second op → only the appended suffix beyond what a already holds.
        b.edit_text("note", 3, "two").unwrap();
        let full = b.export_own_log().unwrap();
        let suffix = &full[first.len()..];
        a.apply_peer_ops(id_b.peer_id(), &id_b.verifying_key(), suffix)
            .unwrap();
        assert_eq!(a.text("note"), "onetwo");

        // Importing our own author id via apply_peer_ops is a no-op.
        a.apply_peer_ops(a.peer_id(), &id_b.verifying_key(), &[1, 2, 3])
            .unwrap();
    }

    #[test]
    fn apply_peer_ops_full_resend_does_not_duplicate_on_disk() {
        // The engine ships the author's FULL log on every handshake/Have. A naive
        // concatenate would double the on-disk log each time; a prefix-aware merge
        // must recognize the full resend and leave the stored bytes unchanged.
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();
        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();

        b.edit_text("note", 0, "one").unwrap();
        b.edit_text("note", 3, "two").unwrap();
        let full = b.export_own_log().unwrap();

        a.apply_peer_ops(id_b.peer_id(), &id_b.verifying_key(), &full)
            .unwrap();
        let after_first = a.export_peer_log(id_b.peer_id()).unwrap().len();

        // Apply the SAME full log again: a full resend must not grow disk.
        a.apply_peer_ops(id_b.peer_id(), &id_b.verifying_key(), &full)
            .unwrap();
        let after_second = a.export_peer_log(id_b.peer_id()).unwrap().len();

        assert_eq!(
            after_first, after_second,
            "full resend duplicated the stored peer log on disk"
        );
        assert_eq!(
            after_first,
            full.len(),
            "stored log is not exactly one copy"
        );
        assert_eq!(a.text("note"), "onetwo");
    }

    #[test]
    fn apply_peer_ops_appends_a_genuine_suffix() {
        // Guard against over-correcting the prefix-aware merge into dropping real
        // live-push continuations: a genuine suffix (bytes beyond what we hold)
        // must still be appended.
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();
        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();

        // First: the full 2-entry log.
        b.edit_text("note", 0, "one").unwrap();
        b.edit_text("note", 3, "two").unwrap();
        let full_two = b.export_own_log().unwrap();
        a.apply_peer_ops(id_b.peer_id(), &id_b.verifying_key(), &full_two)
            .unwrap();

        // Then: only the suffix bytes for a later entry (entry 2).
        b.edit_text("note", 6, "six").unwrap();
        let full_three = b.export_own_log().unwrap();
        let suffix = &full_three[full_two.len()..];
        a.apply_peer_ops(id_b.peer_id(), &id_b.verifying_key(), suffix)
            .unwrap();

        assert_eq!(
            a.export_peer_log(id_b.peer_id()).unwrap(),
            full_three,
            "genuine suffix was not appended to the stored log"
        );
        assert_eq!(a.text("note"), "onetwosix");
    }

    #[test]
    fn apply_peer_ops_ignores_a_stale_prefix() {
        // A stale/duplicate resend (a prefix of what we already hold) must be
        // dropped: no shrink and no duplication.
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();
        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();

        b.edit_text("note", 0, "one").unwrap();
        let first = b.export_own_log().unwrap(); // 1-entry prefix
        b.edit_text("note", 3, "two").unwrap();
        b.edit_text("note", 6, "six").unwrap();
        let full = b.export_own_log().unwrap(); // 3-entry log

        a.apply_peer_ops(id_b.peer_id(), &id_b.verifying_key(), &full)
            .unwrap();
        let after_full = a.export_peer_log(id_b.peer_id()).unwrap().len();

        // Apply the older 1-entry prefix: must be a no-op on disk.
        a.apply_peer_ops(id_b.peer_id(), &id_b.verifying_key(), &first)
            .unwrap();
        let after_stale = a.export_peer_log(id_b.peer_id()).unwrap().len();

        assert_eq!(
            after_full, after_stale,
            "stale prefix resend altered the stored peer log length"
        );
        assert_eq!(a.text("note"), "onetwosix");
    }

    #[test]
    fn apply_peer_ops_trims_a_partial_overlap_suffix() {
        // Under mesh concurrency an author's log reaches a receiver from two
        // sources at different offsets: a live-push suffix and a full relayed
        // resend can interleave. Applying the full log `[l0,l1]` then an
        // overlapping suffix `[l1,l2]` must trim the shared boundary entry, not
        // duplicate `l1` on disk.
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();
        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();

        // Build b's 1-, 2-, and 3-entry logs so we can slice at line boundaries.
        b.edit_text("note", 0, "l0").unwrap();
        let first = b.export_own_log().unwrap(); // [l0]
        b.edit_text("note", 2, "l1").unwrap();
        let full_two = b.export_own_log().unwrap(); // [l0,l1]
        b.edit_text("note", 4, "l2").unwrap();
        let full_three = b.export_own_log().unwrap(); // [l0,l1,l2]

        // Receiver first learns the full 2-entry log.
        a.apply_peer_ops(id_b.peer_id(), &id_b.verifying_key(), &full_two)
            .unwrap();

        // Then an OVERLAPPING suffix `[l1,l2]` (bytes from the end of l0 onward)
        // races in from another source.
        let overlapping = &full_three[first.len()..];
        a.apply_peer_ops(id_b.peer_id(), &id_b.verifying_key(), overlapping)
            .unwrap();

        assert_eq!(
            a.export_peer_log(id_b.peer_id()).unwrap(),
            full_three,
            "overlapping suffix duplicated a boundary entry on disk"
        );
        assert_eq!(a.text("note"), "l0l1l2");
    }

    #[test]
    fn map_entries_persist_across_reopen() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let id = Identity::generate();

        {
            let mut store = Store::open(&vault, id.clone()).unwrap();
            store.set_entry("m", "k", "v").unwrap();
        } // drop: everything is on disk now.

        // Reopen from a cold Store — oplog replay must restore the map state.
        let reopened = Store::open(&vault, id).unwrap();
        assert_eq!(reopened.get_entry("m", "k"), Some("v".to_string()));
    }

    #[test]
    fn two_stores_converge_map_entries_by_exchanging_oplogs() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a.clone()).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();

        a.set_entry("m", "k", "from-A").unwrap();
        b.set_entry("m", "k", "from-B").unwrap();

        // The roster is the trust boundary: each device must vouch for the other
        // before its ops are accepted.
        a.declare_founder(Role::Admin).unwrap();
        b.declare_founder(Role::Admin).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();
        b.add_peer(id_a.peer_id(), id_a.verifying_key().to_bytes(), Role::Admin)
            .unwrap();

        // Exchange own-logs both directions via the real peer-merge API.
        a.apply_peer_ops(
            id_b.peer_id(),
            &id_b.verifying_key(),
            &b.export_own_log().unwrap(),
        )
        .unwrap();
        b.apply_peer_ops(
            id_a.peer_id(),
            &id_a.verifying_key(),
            &a.export_own_log().unwrap(),
        )
        .unwrap();

        // Both converge to the single LWW winner for the key.
        let winner = a.get_entry("m", "k");
        assert!(winner.is_some(), "converged winner must be set");
        assert_eq!(winner, b.get_entry("m", "k"), "stores did not converge");
    }

    #[test]
    fn a_redundant_set_entry_appends_nothing() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let id = Identity::generate();
        let mut store = Store::open(&vault, id.clone()).unwrap();

        store.set_entry("m", "k", "v").unwrap();
        let after_real = store.export_own_log().unwrap().len();
        // Setting the SAME key+value produces no state change → the version guard
        // in persist_new_ops must keep the own log from growing.
        store.set_entry("m", "k", "v").unwrap();
        assert_eq!(store.export_own_log().unwrap().len(), after_real);
    }

    #[test]
    fn map_and_text_coexist_across_reopen() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let id = Identity::generate();

        {
            let mut store = Store::open(&vault, id.clone()).unwrap();
            store.edit_text("note", 0, "hello").unwrap();
            store.set_entry("m", "k", "v").unwrap();
        }

        let reopened = Store::open(&vault, id).unwrap();
        assert_eq!(reopened.text("note"), "hello");
        assert_eq!(reopened.get_entry("m", "k"), Some("v".to_string()));
    }

    #[test]
    fn remove_entry_drops_the_key_and_persists_across_reopen() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let id = Identity::generate();

        {
            let mut store = Store::open(&vault, id.clone()).unwrap();
            store.set_entry("m", "k", "v").unwrap();
            assert_eq!(store.get_entry("m", "k"), Some("v".to_string()));
            store.remove_entry("m", "k").unwrap();
            assert_eq!(
                store.get_entry("m", "k"),
                None,
                "removed key must read absent"
            );
        }

        // The delete op is durable: a cold reopen replays it and the key stays gone.
        let reopened = Store::open(&vault, id).unwrap();
        assert_eq!(
            reopened.get_entry("m", "k"),
            None,
            "removal must survive reopen"
        );
    }

    #[test]
    fn remove_entry_propagates_to_a_trusted_peer() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a.clone()).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();
        b.declare_founder(Role::Admin).unwrap();
        b.add_peer(id_a.peer_id(), id_a.verifying_key().to_bytes(), Role::Admin)
            .unwrap();

        // A sets then removes the key; both ops ride A's own signed log.
        a.set_entry("m", "k", "v").unwrap();
        a.remove_entry("m", "k").unwrap();

        b.apply_peer_ops(
            id_a.peer_id(),
            &id_a.verifying_key(),
            &a.export_own_log().unwrap(),
        )
        .unwrap();
        assert_eq!(
            b.get_entry("m", "k"),
            None,
            "removal must converge on the peer"
        );
    }

    #[test]
    fn version_dominates_matches_causal_order() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let id = Identity::generate();
        let mut store = Store::open(&vault, id).unwrap();

        store.edit_text("note", 0, "abc").unwrap();
        let early = store.doc_version_bytes();
        store.edit_text("note", 3, "def").unwrap();
        let late = store.doc_version_bytes();

        assert!(version_dominates(&late, &early), "later ⊇ earlier");
        assert!(
            version_dominates(&late, &late),
            "a version dominates itself"
        );
        assert!(
            !version_dominates(&early, &late),
            "earlier must NOT dominate later"
        );
        // Garbage bytes never dominate (conservative decode-failure guard).
        assert!(!version_dominates(&[0xff, 0x00, 0x13], &early));
        assert!(!version_dominates(&late, &[0xff, 0x00, 0x13]));
    }

    #[test]
    fn version_dominates_is_false_for_concurrent_versions() {
        // Two independent stores produce concurrent versions: neither dominates.
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let mut a = Store::open(dir_a.path(), Identity::generate()).unwrap();
        let mut b = Store::open(dir_b.path(), Identity::generate()).unwrap();
        a.edit_text("note", 0, "aaa").unwrap();
        b.edit_text("note", 0, "bbb").unwrap();
        let va = a.doc_version_bytes();
        let vb = b.doc_version_bytes();
        assert!(!version_dominates(&va, &vb));
        assert!(!version_dominates(&vb, &va));
    }

    #[test]
    fn import_peer_rejects_a_wrong_key_and_leaves_disk_untouched() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let wrong = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();
        // b is a trusted peer; the import must still fail on the wrong key alone.
        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();
        b.edit_text("note", 0, "peerdata").unwrap();

        // Verify against the WRONG key: must fail, not mutate the doc, and not
        // persist the peer log to disk (verify-before-write).
        let err = a.import_peer(
            id_b.peer_id(),
            &wrong.verifying_key(),
            b.export_own_log().unwrap(),
        );
        assert!(matches!(err, Err(StorageError::BadSignature(_))));
        assert_eq!(a.text("note"), "");
        let peer_log = dir_a
            .path()
            .join("ops")
            .join(format!("ops-{}.jsonl", id_b.peer_id()));
        assert!(!peer_log.exists(), "forged peer log must not be persisted");
    }

    use crate::keychain::EPOCH0_ID;

    // Test vault-key subkeys: the Store keychain API takes id_key + epoch0_key as
    // raw bytes (the backend-client derives them from VaultKey).
    fn keys() -> ([u8; 32], [u8; 32]) {
        ([0x1au8; 32], [0x2bu8; 32])
    }

    #[test]
    fn fresh_vault_keychain_is_epoch0_only_and_synced() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path(), Identity::generate()).unwrap();
        let (id_key, epoch0) = keys();
        let kc = store.keychain(&id_key, &epoch0).unwrap();
        assert_eq!(kc.head, EPOCH0_ID);
        assert!(
            store.vault_state(&id_key, &epoch0).unwrap().is_empty(),
            "epoch-0-only vault is Synced"
        );
    }

    #[test]
    fn rotate_epoch_mints_a_new_head_the_device_can_open() {
        let dir = tempdir().unwrap();
        let id = Identity::generate();
        let mut store = Store::open(dir.path(), id).unwrap();
        let (id_key, epoch0) = keys();
        store.declare_founder(Role::Admin).unwrap();

        let new_epoch = store.rotate_epoch(&id_key, &epoch0, None).unwrap();
        let kc = store.keychain(&id_key, &epoch0).unwrap();
        assert_eq!(kc.head, new_epoch);
        assert!(
            kc.epoch_key(&new_epoch).is_some(),
            "minter can open its own new epoch"
        );
        assert_ne!(
            kc.epoch_key(&new_epoch),
            Some(epoch0),
            "epoch key is fresh random"
        );
    }

    #[test]
    fn rotation_survives_reopen() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("v");
        let id = Identity::generate();
        let (id_key, epoch0) = keys();
        let minted = {
            let mut store = Store::open(&vault, id.clone()).unwrap();
            store.declare_founder(Role::Admin).unwrap();
            store.rotate_epoch(&id_key, &epoch0, None).unwrap()
        };
        let reopened = Store::open(&vault, id).unwrap();
        let kc = reopened.keychain(&id_key, &epoch0).unwrap();
        assert_eq!(kc.head, minted);
        assert!(
            kc.epoch_key(&minted).is_some(),
            "epoch key recovered from own key-log wrap after reopen"
        );
    }

    #[test]
    fn a_peer_added_after_rotation_gets_backfilled() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let (id_key, epoch0) = keys();

        let mut a = Store::open(dir_a.path(), id_a.clone()).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();
        // Each device is the founder-admin of its own vault so its `add_peer`
        // vouches actually fold into the roster (and back-fill can target the peer).
        a.declare_founder(Role::Admin).unwrap();
        b.declare_founder(Role::Admin).unwrap();

        let epoch = a.rotate_epoch(&id_key, &epoch0, None).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();
        a.backfill_wraps(&id_key, &epoch0).unwrap();

        b.add_peer(id_a.peer_id(), id_a.verifying_key().to_bytes(), Role::Admin)
            .unwrap();
        b.import_roster(
            id_a.peer_id(),
            &id_a.verifying_key(),
            a.export_own_roster().unwrap(),
        )
        .unwrap();
        b.import_keylog(
            id_a.peer_id(),
            &id_a.verifying_key(),
            a.export_own_keylog().unwrap(),
        )
        .unwrap();

        let kc_b = b.keychain(&id_key, &epoch0).unwrap();
        assert_eq!(
            kc_b.epoch_key(&epoch),
            a.keychain(&id_key, &epoch0).unwrap().epoch_key(&epoch),
            "B recovered the same epoch key A minted, via back-fill"
        );
    }

    #[test]
    fn checkpoint_compacts_ops_and_reopens_to_same_text() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        {
            let mut store = Store::open(dir.path(), id.clone()).unwrap();
            store.edit_text("note", 0, "one").unwrap();
            store.write_snapshot().unwrap();
            store.edit_text("note", 3, "-two").unwrap();
            store.write_snapshot().unwrap();
            let _freed = store.checkpoint(i64::MAX).unwrap();
            assert_eq!(
                store.text("note"),
                "one-two",
                "state preserved across checkpoint"
            );
        }
        let store = Store::open(dir.path(), id).unwrap();
        assert_eq!(
            store.text("note"),
            "one-two",
            "reopen after checkpoint is identical"
        );
    }

    #[test]
    fn checkpoint_dry_run_reports_without_mutating() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path(), Identity::generate()).unwrap();
        store.edit_text("note", 0, "data").unwrap();
        store.write_snapshot().unwrap();
        let before = store.text("note");
        let markers_before = crate::history::HistoryIndex::new(&dir.path().join("history"))
            .markers()
            .unwrap()
            .len();
        let _bytes = store.checkpoint_dry_run(i64::MAX).unwrap();
        assert_eq!(store.text("note"), before, "dry run does not mutate state");
        let markers_after = crate::history::HistoryIndex::new(&dir.path().join("history"))
            .markers()
            .unwrap()
            .len();
        assert_eq!(
            markers_before, markers_after,
            "dry run does not rewrite history"
        );
    }

    #[test]
    fn declare_founder_makes_this_device_admin() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let mut store = Store::open(dir.path(), id.clone()).unwrap();
        store.declare_founder(Role::Admin).unwrap();
        let me = store
            .roster()
            .into_iter()
            .find(|p| p.peer_id == id.peer_id())
            .unwrap();
        assert_eq!(me.role, Role::Admin);
        assert_eq!(store.self_role(), Some(Role::Admin));
        let store2 = Store::open(dir.path(), id).unwrap();
        assert_eq!(store2.self_role(), Some(Role::Admin));
    }

    #[test]
    fn declare_founder_twice_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let mut store = Store::open(dir.path(), id).unwrap();
        store.declare_founder(Role::Admin).unwrap();
        assert!(store.declare_founder(Role::Admin).is_err());
    }

    #[test]
    fn non_founder_admin_can_bootstrap_a_joiner_via_roster_bundle() {
        // A founds (Admin), grants B Admin.
        let da = tempfile::tempdir().unwrap();
        let a = Identity::generate();
        let mut sa = Store::open(da.path(), a.clone()).unwrap();
        sa.declare_founder(Role::Admin).unwrap();
        let b = Identity::generate();
        sa.add_peer(b.peer_id(), b.verifying_key().to_bytes(), Role::Admin)
            .unwrap();

        // B store: pin founder A, import A's roster bundle, then B (admin) adds C as Reader.
        let db = tempfile::tempdir().unwrap();
        let mut sb = Store::open(db.path(), b.clone()).unwrap();
        sb.pin_founder(a.peer_id()).unwrap();
        sb.import_roster_bundle(sa.export_all_rosters().unwrap())
            .unwrap();
        assert_eq!(
            sb.self_role(),
            Some(Role::Admin),
            "B is admin after bootstrap"
        );
        let c = Identity::generate();
        sb.add_peer(c.peer_id(), c.verifying_key().to_bytes(), Role::Reader)
            .unwrap();

        // C store: pin founder A, import B's TRANSITIVE roster bundle (contains A's + B's logs).
        let dc = tempfile::tempdir().unwrap();
        let mut sc = Store::open(dc.path(), c.clone()).unwrap();
        sc.pin_founder(a.peer_id()).unwrap();
        sc.import_roster_bundle(sb.export_all_rosters().unwrap())
            .unwrap();
        assert_eq!(
            sc.self_role(),
            Some(Role::Reader),
            "C folds its role via the A->B->C chain"
        );
        // C trusts A and B in its roster:
        assert!(sc.role_of(a.peer_id()).is_some());
        assert!(sc.role_of(b.peer_id()).is_some());
    }

    #[test]
    fn historical_entry_none_when_no_markers() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), Identity::generate()).unwrap();
        assert_eq!(
            store
                .historical_entry("__roam_fileset__", "x", i64::MAX)
                .unwrap(),
            None
        );
    }

    #[test]
    fn reader_may_not_write_writer_and_admin_may() {
        let dir = tempfile::tempdir().unwrap();
        let admin = Identity::generate();
        let mut store = Store::open(dir.path(), admin.clone()).unwrap();
        store.declare_founder(Role::Admin).unwrap();
        assert!(store.may_write(), "admin may write");
        let reader = Identity::generate();
        store
            .add_peer(
                reader.peer_id(),
                reader.verifying_key().to_bytes(),
                Role::Reader,
            )
            .unwrap();
        let writer = Identity::generate();
        store
            .add_peer(
                writer.peer_id(),
                writer.verifying_key().to_bytes(),
                Role::Writer,
            )
            .unwrap();
        assert_eq!(store.role_of(reader.peer_id()), Some(Role::Reader));
        assert_eq!(store.role_of(writer.peer_id()), Some(Role::Writer));
    }

    #[test]
    fn reader_device_may_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let admin = Identity::generate();
        let reader = Identity::generate();
        let mut a = Store::open(dir.path(), admin.clone()).unwrap();
        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(
            reader.peer_id(),
            reader.verifying_key().to_bytes(),
            Role::Reader,
        )
        .unwrap();

        let dir2 = tempfile::tempdir().unwrap();
        let mut r = Store::open(dir2.path(), reader.clone()).unwrap();
        r.pin_founder(admin.peer_id()).unwrap();
        r.import_roster(
            admin.peer_id(),
            &admin.verifying_key(),
            a.export_own_roster().unwrap(),
        )
        .unwrap();
        assert_eq!(r.self_role(), Some(Role::Reader));
        assert!(!r.may_write(), "reader device must not write");
    }

    #[test]
    fn set_role_demotes_a_peer() {
        let dir = tempfile::tempdir().unwrap();
        let admin = Identity::generate();
        let mut store = Store::open(dir.path(), admin).unwrap();
        store.declare_founder(Role::Admin).unwrap();
        let p = Identity::generate();
        store
            .add_peer(p.peer_id(), p.verifying_key().to_bytes(), Role::Writer)
            .unwrap();
        store
            .set_role(p.peer_id(), p.verifying_key().to_bytes(), Role::Reader)
            .unwrap();
        assert_eq!(store.role_of(p.peer_id()), Some(Role::Reader));
    }

    #[test]
    fn non_admin_cannot_add_or_set_role() {
        // A store whose own role is Writer must be refused add_peer/set_role/revoke_peer.
        let dir = tempfile::tempdir().unwrap();
        let admin = Identity::generate();
        let writer = Identity::generate();
        let mut a = Store::open(dir.path(), admin.clone()).unwrap();
        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(
            writer.peer_id(),
            writer.verifying_key().to_bytes(),
            Role::Writer,
        )
        .unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let mut w = Store::open(dir2.path(), writer.clone()).unwrap();
        w.pin_founder(admin.peer_id()).unwrap();
        w.import_roster(
            admin.peer_id(),
            &admin.verifying_key(),
            a.export_own_roster().unwrap(),
        )
        .unwrap();
        let victim = Identity::generate();
        assert!(w
            .add_peer(
                victim.peer_id(),
                victim.verifying_key().to_bytes(),
                Role::Reader
            )
            .is_err());
        assert!(w
            .set_role(
                writer.peer_id(),
                writer.verifying_key().to_bytes(),
                Role::Admin
            )
            .is_err());
    }

    #[test]
    fn import_peer_rejects_reader_authored_content_ops() {
        // admin founder adds P as Writer
        let dir = tempfile::tempdir().unwrap();
        let admin = Identity::generate();
        let p = Identity::generate();
        let mut a = Store::open(dir.path(), admin.clone()).unwrap();
        a.declare_founder(Role::Admin).unwrap();
        a.add_peer(p.peer_id(), p.verifying_key().to_bytes(), Role::Writer)
            .unwrap();

        // P materializes as Writer and authors an op
        let pdir = tempfile::tempdir().unwrap();
        let mut ps = Store::open(pdir.path(), p.clone()).unwrap();
        ps.pin_founder(admin.peer_id()).unwrap();
        ps.import_roster(
            admin.peer_id(),
            &admin.verifying_key(),
            a.export_own_roster().unwrap(),
        )
        .unwrap();
        assert!(ps.may_write());
        ps.edit_text("note", 0, "hello").unwrap();
        // capture P's own signed op-log bytes:
        let p_ops = ps.export_own_log().unwrap();

        // sanity: while P is a Writer, import is accepted
        a.import_peer(p.peer_id(), &p.verifying_key(), p_ops.clone())
            .unwrap();

        // demote P to Reader, then a FRESH admin store must refuse P's ops
        let dir2 = tempfile::tempdir().unwrap();
        let mut a2 = Store::open(dir2.path(), admin.clone()).unwrap();
        a2.declare_founder(Role::Admin).unwrap();
        a2.add_peer(p.peer_id(), p.verifying_key().to_bytes(), Role::Reader)
            .unwrap();
        let err = a2.import_peer(p.peer_id(), &p.verifying_key(), p_ops);
        assert!(err.is_err(), "reader-authored content ops must be refused");
    }

    #[test]
    fn dedup_append_peer_line_is_idempotent_and_order_free() {
        // Exercises the backend content-id fetch path's write primitive: lines
        // can arrive one at a time, out of order, and with duplicates (RBSR
        // discovery is set-based, not sequential) — the peer log must still end
        // up holding exactly the distinct lines, and Loro must converge once
        // both are present regardless of arrival order.
        let dir = tempdir().unwrap();
        let author = Identity::generate();
        let mut s = Store::open(dir.path(), Identity::generate()).unwrap();
        s.declare_founder(Role::Admin).unwrap();
        s.add_peer(
            author.peer_id(),
            author.verifying_key().to_bytes(),
            Role::Admin,
        )
        .unwrap();

        // Build a real 2-line signed log: a throwaway store owned by `author`
        // produces two ops, then we split its own log into lines.
        let adir = tempdir().unwrap();
        let mut astore = Store::open(adir.path(), author.clone()).unwrap();
        astore.declare_founder(Role::Admin).unwrap();
        astore.set_entry("files", "k", "v1").unwrap();
        astore.set_entry("files", "k", "v2").unwrap();
        let log = astore.export_own_log().unwrap();
        let lines = split_log_lines_bytes(&log);
        assert_eq!(
            lines.len(),
            2,
            "two set_entry calls produce two op-log lines"
        );

        let vk = author.verifying_key();
        // Out of order, plus a duplicate of an already-applied line.
        s.dedup_append_peer_line(author.peer_id(), &vk, &lines[1])
            .unwrap();
        s.dedup_append_peer_line(author.peer_id(), &vk, &lines[0])
            .unwrap();
        s.dedup_append_peer_line(author.peer_id(), &vk, &lines[1])
            .unwrap(); // dup: no-op

        // Exactly 2 distinct lines retained on disk (dedup, not 3).
        let stored = s.export_peer_log(author.peer_id()).unwrap();
        assert_eq!(
            stored.iter().filter(|&&b| b == b'\n').count(),
            2,
            "duplicate line must not be appended twice"
        );
        // And the doc converged to the final value despite the reordering.
        assert_eq!(s.get_entry("files", "k"), Some("v2".to_string()));
    }

    #[test]
    fn adopt_snapshot_is_additive_and_never_truncates_existing_history() {
        // Producer builds a snapshot at head.
        let pd = tempdir().unwrap();
        let mut prod = Store::open(pd.path(), Identity::generate()).unwrap();
        prod.declare_founder(Role::Admin).unwrap();
        prod.set_entry("files", "k", "v1").unwrap();
        prod.write_snapshot().unwrap();
        let snap = prod.build_backend_snapshot(i64::MAX).unwrap().unwrap();

        // A fresh consumer adopting it gains the producer's state.
        let cd = tempdir().unwrap();
        let mut cons = Store::open(cd.path(), Identity::generate()).unwrap();
        cons.declare_founder(Role::Admin).unwrap();
        cons.adopt_snapshot(&snap.bytes).unwrap();
        assert_eq!(cons.get_entry("files", "k"), Some("v1".to_string()));

        // A consumer that already holds richer local history keeps it after
        // adopting the (older) snapshot — adoption is additive, never truncating.
        cons.set_entry("files", "k2", "local").unwrap();
        let own_before = cons.export_own_log().unwrap();
        cons.adopt_snapshot(&snap.bytes).unwrap();
        assert_eq!(cons.get_entry("files", "k2"), Some("local".to_string()));
        assert_eq!(
            cons.export_own_log().unwrap(),
            own_before,
            "adopting a snapshot must not touch our own op-log"
        );
    }

    #[test]
    fn build_backend_snapshot_produces_a_loadable_shallow_snapshot() {
        let dir = tempdir().unwrap();
        let mut s = Store::open(dir.path(), Identity::generate()).unwrap();
        s.declare_founder(Role::Admin).unwrap();
        for i in 0..5 {
            s.set_entry("files", "k", &format!("v{i}")).unwrap();
        }
        // No history marker yet -> nothing to snapshot.
        assert!(s.build_backend_snapshot(i64::MAX).unwrap().is_none());

        // Record a marker at head, then snapshot at it.
        s.write_snapshot().unwrap();
        let snap = s
            .build_backend_snapshot(i64::MAX)
            .unwrap()
            .expect("a marker now exists");

        // Reloading the shallow snapshot into a fresh doc yields head state.
        let restored = roam_crdt::Document::from_snapshot(99, &snap.bytes).unwrap();
        assert_eq!(restored.get_entry("files", "k"), Some("v4".to_string()));

        // Subsumed lines cover this peer's own op-log.
        assert!(!snap.subsumed_lines.is_empty());
        assert!(snap.subsumed_lines.iter().all(|(p, _)| *p == s.peer_id()));
        assert_ne!(snap.frontier_digest, [0u8; 32]);
    }

    #[test]
    fn a_bad_fetched_line_never_poisons_the_peer_log() {
        // The backend fetch path feeds attacker-influenced bytes (a malicious or
        // buggy backend, a bit-flip) into `dedup_append_peer_line`. Because
        // `verify_bytes` rejects the WHOLE log on the first bad line, a single
        // unverified line persisted to disk would permanently break every future
        // import of that peer. So a bad line must leave the on-disk log untouched.
        let dir = tempdir().unwrap();
        let author = Identity::generate();
        let mut s = Store::open(dir.path(), Identity::generate()).unwrap();
        s.declare_founder(Role::Admin).unwrap();
        s.add_peer(
            author.peer_id(),
            author.verifying_key().to_bytes(),
            Role::Admin,
        )
        .unwrap();

        // Seed one GOOD line so there is a non-empty log to (not) corrupt.
        let adir = tempdir().unwrap();
        let mut astore = Store::open(adir.path(), author.clone()).unwrap();
        astore.declare_founder(Role::Admin).unwrap();
        astore.set_entry("files", "k", "good").unwrap();
        let good = split_log_lines_bytes(&astore.export_own_log().unwrap());
        let vk = author.verifying_key();
        s.dedup_append_peer_line(author.peer_id(), &vk, &good[0])
            .unwrap();

        let before = s.export_peer_log(author.peer_id()).unwrap();

        // A garbage line claiming to be from `author` with an invalid signature.
        let bad = format!(
            "{{\"peer\":{},\"sig\":\"AAAA\",\"update\":\"AAAA\"}}\n",
            author.peer_id()
        );
        let result = s.dedup_append_peer_line(author.peer_id(), &vk, bad.as_bytes());
        assert!(
            result.is_err(),
            "a bad line must be rejected, not persisted"
        );

        let after = s.export_peer_log(author.peer_id()).unwrap();
        assert_eq!(
            before, after,
            "on-disk peer log must be byte-identical after a rejected bad line"
        );

        // The good state still reads back — no collateral damage.
        assert_eq!(s.get_entry("files", "k"), Some("good".to_string()));
    }
}
