use crate::error::StorageError;
use crate::identity::{Identity, VerifyingKey};
use crate::oplog::OpLog;
use crate::roster::{merge_roster, PeerRecord, PeerStatus, RosterEntry, RosterLog, RosterOp};
use crate::snapshot;
use roam_crdt::{Document, Version};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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

        // 1. Rebuild the trusted peer set from the signed roster logs (fixpoint).
        let peers = Self::rebuild_peers(root, identity.peer_id(), &identity.verifying_key())?;

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
        let store = Self {
            root: root.to_path_buf(),
            identity,
            doc,
            own_log,
            persisted,
            own_roster,
            peers,
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
    ) -> Result<Vec<PeerRecord>, StorageError> {
        let roster_dir = root.join("roster");

        // Trusted author keys (as raw bytes; `VerifyingKey` is not `Copy`), seeded
        // with ourselves.
        let mut trusted: HashMap<u64, [u8; 32]> = HashMap::new();
        trusted.insert(self_id, self_key.to_bytes());

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
            let entries = log.read_verified(&author_key)?;
            for entry in &entries {
                // Learn subject keys this author vouches for (Add or Revoke both
                // carry the key; a later fixpoint pass never removes trust).
                trusted
                    .entry(entry.subject_peer)
                    .or_insert(entry.subject_key);
            }
            all_entries.extend(entries);
        }

        Ok(merge_roster(&mut all_entries))
    }

    pub fn text(&self, id: &str) -> String {
        self.doc.text(id)
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

    /// Write a fast-load snapshot of the current state.
    pub fn write_snapshot(&self) -> Result<(), StorageError> {
        let path = self.root.join("snapshots").join("snapshot.loro");
        snapshot::save(&path, &self.doc.snapshot()?)
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
    /// The wire may carry only a suffix, so we concatenate `appended` onto the
    /// bytes we already hold for `ops/ops-<author>.jsonl` and hand the whole log
    /// to [`Store::import_peer`], which verifies, refuses to shrink, dedups, and
    /// advances `persisted`. Because logs are append-only and loro dedups on
    /// import, resending overlapping suffixes is safe. We never import our own
    /// ops as a peer.
    pub fn apply_peer_ops(
        &mut self,
        author: u64,
        key: &VerifyingKey,
        appended: &[u8],
    ) -> Result<(), StorageError> {
        if author == self.identity.peer_id() {
            return Ok(());
        }
        let mut whole = self.export_peer_log(author)?;
        whole.extend_from_slice(appended);
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
    pub fn add_peer(&mut self, peer_id: u64, key_bytes: [u8; 32]) -> Result<(), StorageError> {
        Self::check_peer_id_binding(peer_id, &key_bytes)?;
        self.own_roster
            .append(&self.identity, RosterOp::Add, peer_id, key_bytes)?;
        self.refresh_peers()
    }

    /// Revoke `peer_id`: append a `Revoke` to our own roster log, re-merge the
    /// peer set, and refresh the `peers.json` cache.
    pub fn revoke_peer(&mut self, peer_id: u64, key_bytes: [u8; 32]) -> Result<(), StorageError> {
        Self::check_peer_id_binding(peer_id, &key_bytes)?;
        self.own_roster
            .append(&self.identity, RosterOp::Revoke, peer_id, key_bytes)?;
        self.refresh_peers()
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
            Some(p) if p.status == PeerStatus::Active => {}
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

        // Op logs are append-only: refuse a shorter/older resend that would
        // truncate newer peer ops already on disk. (TODO: entry-level merge once
        // peers.json + a real sync transport land; for now a wholesale, longer-or-
        // equal replacement is sufficient since peers ship their full log.)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use tempfile::tempdir;

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
        // before its ops are accepted.
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes()).unwrap();
        b.add_peer(id_a.peer_id(), id_a.verifying_key().to_bytes()).unwrap();

        // Copy each store's own oplog into the other and re-import.
        a.import_peer(id_b.peer_id(), &id_b.verifying_key(), b.export_own_log().unwrap())
            .unwrap();
        b.import_peer(id_a.peer_id(), &id_a.verifying_key(), a.export_own_log().unwrap())
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

        // Trust b before importing its ops.
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes()).unwrap();

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

        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes()).unwrap();
        a.edit_text("note", 0, "A").unwrap();
        b.edit_text("note", 0, "B").unwrap();
        a.import_peer(id_b.peer_id(), &id_b.verifying_key(), b.export_own_log().unwrap())
            .unwrap();
        a.edit_text("note", a.text("note").chars().count(), "C").unwrap();

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
        let own_log = vault.join("ops").join(format!("ops-{}.jsonl", id.peer_id()));
        let mut f = std::fs::OpenOptions::new().append(true).open(&own_log).unwrap();
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
        let err = store.add_peer(bad_id, b.verifying_key().to_bytes());
        assert!(matches!(err, Err(StorageError::Peer(_))), "mismatched peer_id must be refused");
        assert!(store.roster().is_empty(), "a refused add must not touch the roster");

        // The matching pair succeeds.
        store
            .add_peer(b.peer_id(), b.verifying_key().to_bytes())
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
            store.add_peer(b.peer_id(), b.verifying_key().to_bytes()).unwrap();
        }
        let reopened = Store::open(&vault, a).unwrap();
        let roster = reopened.roster();
        assert!(roster.iter().any(|p| p.peer_id == b.peer_id()
            && p.status == crate::PeerStatus::Active));
    }

    #[test]
    fn peer_ops_survive_a_cold_reopen_once_the_peer_is_in_the_roster() {
        // The Slice-1 TODO(peers.json) gap: without a roster, a peer's ops vanished
        // on cold reopen (no snapshot). With the roster, open() replays them.
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let a_id = Identity::generate();
        let b_id = Identity::generate();
        let vault_a = dir_a.path().join("vault");

        {
            let mut a = Store::open(&vault_a, a_id.clone()).unwrap();
            let mut b = Store::open(dir_b.path(), b_id.clone()).unwrap();
            a.add_peer(b_id.peer_id(), b_id.verifying_key().to_bytes()).unwrap();
            b.edit_text("note", 0, "from-b").unwrap();
            a.import_peer(b_id.peer_id(), &b_id.verifying_key(), b.export_own_log().unwrap()).unwrap();
            assert_eq!(a.text("note"), "from-b");
        } // drop a: no snapshot written.

        let reopened = Store::open(&vault_a, a_id).unwrap();
        assert_eq!(reopened.text("note"), "from-b", "roster replay must restore peer ops");
    }

    #[test]
    fn revoked_peer_ops_are_rejected_on_import() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let a_id = Identity::generate();
        let b_id = Identity::generate();

        let mut a = Store::open(dir_a.path(), a_id).unwrap();
        let mut b = Store::open(dir_b.path(), b_id.clone()).unwrap();
        a.add_peer(b_id.peer_id(), b_id.verifying_key().to_bytes()).unwrap();
        a.revoke_peer(b_id.peer_id(), b_id.verifying_key().to_bytes()).unwrap();

        b.edit_text("note", 0, "sneaky").unwrap();
        let err = a.import_peer(b_id.peer_id(), &b_id.verifying_key(), b.export_own_log().unwrap());
        assert!(matches!(err, Err(StorageError::Peer(_))), "revoked peer ops must be refused");
    }

    #[test]
    fn apply_peer_ops_appends_suffixes_and_converges() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes())
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
    fn import_peer_rejects_a_wrong_key_and_leaves_disk_untouched() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let wrong = Identity::generate();

        let mut a = Store::open(dir_a.path(), id_a).unwrap();
        let mut b = Store::open(dir_b.path(), id_b.clone()).unwrap();
        // b is a trusted peer; the import must still fail on the wrong key alone.
        a.add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes()).unwrap();
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
}
