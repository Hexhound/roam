use crate::error::StorageError;
use crate::identity::{Identity, VerifyingKey};
use crate::oplog::OpLog;
use crate::snapshot;
use roam_crdt::{Document, Version};
use std::path::{Path, PathBuf};

/// A vault-backed CRDT document store. Layout under `root`:
/// - `ops/ops-<peer>.jsonl` — one signed append-log per peer
/// - `snapshots/snapshot.loro` — fast-load snapshot (rebuildable)
pub struct Store {
    root: PathBuf,
    identity: Identity,
    doc: Document,
    own_log: OpLog,
    /// The document version already written to `own_log` (so we only append new ops).
    persisted: Version,
}

impl Store {
    /// Open (creating if needed) the vault at `root` for device `identity`.
    ///
    /// Rebuilds the document from the snapshot (if any) plus a replay of THIS
    /// device's own signed log. NOTE: peer logs (`ops-<peer>.jsonl`) are NOT yet
    /// replayed here — peer ops survive a cold reopen only if a snapshot captured
    /// them. Replaying peer logs safely needs a trusted `peer_id -> verifying key`
    /// registry (`peers.json`), which lands with pairing in a later slice.
    // TODO(peers.json): enumerate ops-*.jsonl and replay each peer log verified
    // against its registered key.
    pub fn open(root: &Path, identity: Identity) -> Result<Self, StorageError> {
        let ops_dir = root.join("ops");
        let snap_path = root.join("snapshots").join("snapshot.loro");

        // 1. Base document: from snapshot if present, else empty.
        let doc = match snapshot::load(&snap_path)? {
            Some(bytes) => Document::from_snapshot(identity.peer_id(), &bytes)?,
            None => Document::new(identity.peer_id())?,
        };

        // 2. Replay our own log (verified against our own key).
        let own_log = OpLog::new(&ops_dir, identity.peer_id());
        for entry in own_log.read_verified(&identity.verifying_key())? {
            doc.import(&entry.update)?;
        }
        // (Peer logs are imported via `import_peer`, which knows the peer's key.)

        doc.commit();
        let persisted = doc.version();
        Ok(Self {
            root: root.to_path_buf(),
            identity,
            doc,
            own_log,
            persisted,
        })
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

    /// Import a peer's oplog bytes: write them to `ops/ops-<peer>.jsonl`,
    /// verify every entry against `key`, and merge into the document.
    pub fn import_peer(
        &mut self,
        peer_id: u64,
        key: &VerifyingKey,
        log_bytes: Vec<u8>,
    ) -> Result<(), StorageError> {
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
        std::fs::write(&peer_log_path, &log_bytes)?;

        let peer_log = OpLog::new(&ops_dir, peer_id);
        for entry in peer_log.read_verified(key)? {
            self.doc.import(&entry.update)?;
        }
        self.doc.commit();
        // Peer ops are now part of our committed state; advance `persisted` so a
        // later local edit does NOT re-export them into our OWN (own-key-signed)
        // log — that would mis-attribute the peer's ops to us.
        self.persisted = self.doc.version();
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
}
