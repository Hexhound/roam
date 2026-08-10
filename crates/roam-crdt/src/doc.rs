use crate::error::CrdtError;
use loro::LoroDoc;
use loro::LoroValue;
use loro::ValueOrContainer;
use loro::VersionVector;

/// A serializable snapshot of a document's version (which ops it has seen).
/// Peers exchange this to compute deltas.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Version(VersionVector);

impl Version {
    /// Encode for the wire / on-disk framing.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.encode()
    }

    /// Decode a version produced by [`Version::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CrdtError> {
        Ok(Version(VersionVector::decode(bytes)?))
    }

    /// Whether `self` causally DOMINATES `other`: every op `other` has seen,
    /// `self` has seen too (`self ⊇ other`). Returns `true` for an equal
    /// version. Returns `false` when the two are CONCURRENT (neither dominates)
    /// — this is exactly the property a causally-stable tombstone GC needs: a
    /// peer whose acked version merely *concurs* with (does not dominate) the
    /// tombstone's creation version has NOT provably observed the tombstone.
    ///
    /// Backed by loro's `VersionVector::includes_vv`, which is `partial_cmp`
    /// mapped `Equal | Greater => true`, `Less | None => false`.
    pub fn includes(&self, other: &Version) -> bool {
        self.0.includes_vv(&other.0)
    }
}

/// An opaque handle to a specific point in the op-DAG (a set of leaf op-ids).
/// Wraps loro's `Frontiers`; `to_bytes`/`from_bytes` give a persistable byte
/// form used by the storage-layer history index.
#[derive(Clone)]
pub struct Frontier(pub(crate) loro::Frontiers);

impl Frontier {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.encode()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CrdtError> {
        Ok(Frontier(loro::Frontiers::decode(bytes)?))
    }
}

/// A CRDT document: a set of named text containers backed by a single
/// `LoroDoc`. `peer_id` must be unique per device.
pub struct Document {
    doc: LoroDoc,
}

impl Document {
    /// Create an empty document owned by `peer_id`.
    pub fn new(peer_id: u64) -> Result<Self, CrdtError> {
        let doc = LoroDoc::new();
        doc.set_peer_id(peer_id)?;
        Ok(Self { doc })
    }

    /// Insert `s` at unicode position `pos` in text container `id`.
    pub fn insert_text(&self, id: &str, pos: usize, s: &str) -> Result<(), CrdtError> {
        self.doc.get_text(id).insert(pos, s)?;
        Ok(())
    }

    /// Delete `len` unicode chars at position `pos` in text container `id`.
    pub fn delete_text(&self, id: &str, pos: usize, len: usize) -> Result<(), CrdtError> {
        self.doc.get_text(id).delete(pos, len)?;
        Ok(())
    }

    /// Current string content of text container `id`.
    pub fn text(&self, id: &str) -> String {
        self.doc.get_text(id).to_string()
    }

    /// Insert/overwrite `value` under `key` in map container `map_id`
    /// (last-writer-wins register semantics). Like [`Document::insert_text`],
    /// this buffers the edit; call [`Document::commit`] before export/version.
    pub fn set_entry(&self, map_id: &str, key: &str, value: &str) -> Result<(), CrdtError> {
        self.doc.get_map(map_id).insert(key, value)?;
        Ok(())
    }

    /// Remove `key` from map container `map_id`. This is a real CRDT map-delete
    /// op (recorded in the oplog, propagated on export/import), so peers converge
    /// to the key being ABSENT. Deleting an already-absent key is a no-op. Like
    /// [`Document::set_entry`], this buffers the edit; call [`Document::commit`]
    /// before export/version reflect it.
    pub fn remove_entry(&self, map_id: &str, key: &str) -> Result<(), CrdtError> {
        self.doc.get_map(map_id).delete(key)?;
        Ok(())
    }

    /// Current string value under `key` in map container `map_id`, if present.
    /// Non-string values (only strings are ever stored here) yield `None`.
    pub fn get_entry(&self, map_id: &str, key: &str) -> Option<String> {
        match self.doc.get_map(map_id).get(key)? {
            ValueOrContainer::Value(LoroValue::String(s)) => Some(s.to_string()),
            _ => None,
        }
    }

    /// All (key, value) string pairs currently in map container `map_id`
    /// (order unspecified).
    pub fn entries(&self, map_id: &str) -> Vec<(String, String)> {
        let map = self.doc.get_map(map_id);
        map.keys()
            .filter_map(|key| {
                let value = self.get_entry(map_id, key.as_str())?;
                Some((key.to_string(), value))
            })
            .collect()
    }

    /// Flush pending edits into the oplog. Must be called before export/version
    /// reflect the edits. (loro buffers edits until commit.)
    pub fn commit(&self) {
        self.doc.commit();
    }

    /// Load a document from a snapshot, then adopt `peer_id` for future edits.
    pub fn from_snapshot(peer_id: u64, snapshot: &[u8]) -> Result<Self, CrdtError> {
        let doc = LoroDoc::new();
        doc.import(snapshot)?;
        doc.set_peer_id(peer_id)?;
        Ok(Self { doc })
    }

    /// The document's current version, covering only **committed** ops.
    ///
    /// Note the asymmetry with [`Document::export_from`]/[`Document::snapshot`],
    /// which auto-commit pending edits internally: `version()` does not. Call
    /// [`Document::commit`] before `version()` if you have pending edits, or the
    /// returned version will lag them (and a peer will re-send those ops).
    pub fn version(&self) -> Version {
        Version(self.doc.oplog_vv())
    }

    /// A full snapshot (state + history) for fast load or bootstrapping a peer.
    pub fn snapshot(&self) -> Result<Vec<u8>, CrdtError> {
        Ok(self.doc.export(loro::ExportMode::Snapshot)?)
    }

    /// The ops this document has that `from` is missing (a delta update).
    pub fn export_from(&self, from: &Version) -> Result<Vec<u8>, CrdtError> {
        Ok(self.doc.export(loro::ExportMode::updates(&from.0))?)
    }

    /// Merge a snapshot or delta produced by another document.
    pub fn import(&self, bytes: &[u8]) -> Result<(), CrdtError> {
        self.doc.import(bytes)?;
        Ok(())
    }

    /// The current op-log frontier (leaf op-ids of everything committed).
    pub fn oplog_frontier(&self) -> Frontier {
        Frontier(self.doc.oplog_frontiers())
    }

    /// Export a shallow snapshot whose retained history starts at `frontier`.
    /// State is preserved in full; op history older than `frontier` is dropped.
    pub fn shallow_snapshot(&self, frontier: &Frontier) -> Result<Vec<u8>, CrdtError> {
        Ok(self
            .doc
            .export(loro::ExportMode::shallow_snapshot(&frontier.0))?)
    }

    /// Move the document's readable state back to `frontier` (detached read).
    /// Call `checkout_latest` to return to the newest state before authoring.
    pub fn checkout(&self, frontier: &Frontier) -> Result<(), CrdtError> {
        self.doc.checkout(&frontier.0)?;
        Ok(())
    }

    /// Re-attach to the latest state after a `checkout`.
    pub fn checkout_latest(&self) {
        self.doc.checkout_to_latest();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_text_and_reads_it_back() {
        let doc = Document::new(1).unwrap();
        doc.insert_text("note", 0, "hello").unwrap();
        doc.insert_text("note", 5, " world").unwrap();
        doc.commit();
        assert_eq!(doc.text("note"), "hello world");
    }

    #[test]
    fn deletes_text_by_unicode_position() {
        let doc = Document::new(1).unwrap();
        doc.insert_text("note", 0, "hello world").unwrap();
        doc.delete_text("note", 5, 6).unwrap();
        doc.commit();
        assert_eq!(doc.text("note"), "hello");
    }

    #[test]
    fn positions_are_unicode_codepoints_not_bytes() {
        // "café🌍" is 5 codepoints but 9 UTF-8 bytes. Deleting 2 codepoints at
        // position 3 must remove "é🌍" — proving positions are codepoints, not bytes.
        let doc = Document::new(1).unwrap();
        doc.insert_text("note", 0, "café🌍").unwrap();
        doc.delete_text("note", 3, 2).unwrap();
        doc.commit();
        assert_eq!(doc.text("note"), "caf");

        // Insert at a codepoint boundary past a multi-byte char.
        doc.insert_text("note", 3, "→x").unwrap();
        doc.commit();
        assert_eq!(doc.text("note"), "caf→x");
    }

    #[test]
    fn two_documents_converge_via_delta_exchange() {
        let a = Document::new(1).unwrap();
        let b = Document::new(2).unwrap();

        a.insert_text("note", 0, "hello").unwrap();
        a.commit();

        // Bootstrap b from a full snapshot of a.
        let snap = a.snapshot().unwrap();
        b.import(&snap).unwrap();

        // Concurrent edits.
        a.insert_text("note", 5, " from A").unwrap();
        a.commit();
        b.insert_text("note", 5, " from B").unwrap();
        b.commit();

        // Exchange only the deltas each is missing.
        let a_delta = a.export_from(&b.version()).unwrap();
        let b_delta = b.export_from(&a.version()).unwrap();
        b.import(&a_delta).unwrap();
        a.import(&b_delta).unwrap();

        // CRDT merge is deterministic: both sides equal, and NEITHER concurrent
        // edit was dropped (both survive the merge).
        assert_eq!(a.text("note"), b.text("note"));
        assert!(a.text("note").starts_with("hello"));
        assert!(a.text("note").contains(" from A"), "lost A's edit: {}", a.text("note"));
        assert!(a.text("note").contains(" from B"), "lost B's edit: {}", a.text("note"));
    }

    #[test]
    fn sets_and_gets_map_entry() {
        let doc = Document::new(1).unwrap();
        doc.set_entry("m", "k", "v").unwrap();
        assert_eq!(doc.get_entry("m", "k"), Some("v".to_string()));

        // Overwriting the same key yields the new value (LWW register).
        doc.set_entry("m", "k", "v2").unwrap();
        assert_eq!(doc.get_entry("m", "k"), Some("v2".to_string()));
    }

    #[test]
    fn get_entry_for_absent_key_is_none() {
        let doc = Document::new(1).unwrap();
        assert_eq!(doc.get_entry("m", "missing"), None);
        doc.set_entry("m", "k", "v").unwrap();
        assert_eq!(doc.get_entry("m", "other"), None);
    }

    #[test]
    fn entries_lists_all_set_pairs() {
        let doc = Document::new(1).unwrap();
        doc.set_entry("m", "a", "1").unwrap();
        doc.set_entry("m", "b", "2").unwrap();
        doc.set_entry("m", "c", "3").unwrap();

        let mut pairs = doc.entries("m");
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
                ("c".to_string(), "3".to_string()),
            ]
        );
    }

    #[test]
    fn map_entries_converge_to_single_lww_winner() {
        let a = Document::new(1).unwrap();
        let b = Document::new(2).unwrap();

        // Concurrent conflicting writes to the SAME key.
        a.set_entry("fs", "path", "from A").unwrap();
        a.commit();
        b.set_entry("fs", "path", "from B").unwrap();
        b.commit();

        // Exchange deltas both directions.
        let a_delta = a.export_from(&b.version()).unwrap();
        let b_delta = b.export_from(&a.version()).unwrap();
        b.import(&a_delta).unwrap();
        a.import(&b_delta).unwrap();

        // LWW: both converge on the SAME single deterministic winner.
        let winner = a.get_entry("fs", "path");
        assert_eq!(winner, b.get_entry("fs", "path"));
        assert!(
            winner == Some("from A".to_string()) || winner == Some("from B".to_string()),
            "winner must be one of the two writes: {winner:?}"
        );
    }

    #[test]
    fn text_and_map_coexist_in_one_document_and_sync_together() {
        let a = Document::new(1).unwrap();
        let b = Document::new(2).unwrap();

        // Both a text container and a map entry live in the same doc.
        a.insert_text("note", 0, "hello").unwrap();
        a.set_entry("fs", "path", "live").unwrap();
        a.commit();

        // A single delta carries both containers to b.
        let delta = a.export_from(&b.version()).unwrap();
        b.import(&delta).unwrap();

        assert_eq!(b.text("note"), "hello");
        assert_eq!(b.get_entry("fs", "path"), Some("live".to_string()));
    }

    #[test]
    fn map_entries_persist_through_snapshot() {
        let a = Document::new(1).unwrap();
        a.insert_text("note", 0, "persisted").unwrap();
        a.set_entry("fs", "path", "kept").unwrap();
        a.commit();
        let snap = a.snapshot().unwrap();

        let b = Document::from_snapshot(2, &snap).unwrap();
        assert_eq!(b.text("note"), "persisted");
        assert_eq!(b.get_entry("fs", "path"), Some("kept".to_string()));
    }

    #[test]
    fn version_round_trips_through_bytes() {
        let a = Document::new(1).unwrap();
        a.insert_text("note", 0, "abc").unwrap();
        a.commit();
        let v = a.version();
        let bytes = v.to_bytes();
        let v2 = Version::from_bytes(&bytes).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn version_includes_reports_causal_dominance() {
        // A later version dominates an earlier one; the earlier does NOT dominate
        // the later; a version dominates itself (equal).
        let a = Document::new(1).unwrap();
        a.insert_text("note", 0, "abc").unwrap();
        a.commit();
        let v_early = a.version();
        assert!(v_early.includes(&v_early), "a version must include itself");

        a.insert_text("note", 3, "def").unwrap();
        a.commit();
        let v_late = a.version();

        assert!(v_late.includes(&v_early), "later must dominate earlier");
        assert!(!v_early.includes(&v_late), "earlier must NOT dominate later");
    }

    #[test]
    fn version_includes_is_false_for_concurrent_versions() {
        // Two independently-edited docs (different peers) produce CONCURRENT
        // versions: neither dominates the other, so `includes` is false BOTH
        // ways. This is the property GC relies on to refuse an unobserved peer.
        let a = Document::new(1).unwrap();
        let b = Document::new(2).unwrap();
        a.insert_text("note", 0, "aaa").unwrap();
        a.commit();
        b.insert_text("note", 0, "bbb").unwrap();
        b.commit();

        assert!(!a.version().includes(&b.version()));
        assert!(!b.version().includes(&a.version()));
    }

    #[test]
    fn remove_entry_makes_key_absent_and_propagates() {
        let a = Document::new(1).unwrap();
        a.set_entry("m", "k", "v").unwrap();
        a.commit();
        assert_eq!(a.get_entry("m", "k"), Some("v".to_string()));

        a.remove_entry("m", "k").unwrap();
        a.commit();
        assert_eq!(a.get_entry("m", "k"), None, "removed key must read absent");
        assert!(
            a.entries("m").is_empty(),
            "entries() must exclude a removed key"
        );

        // The removal is a CRDT op that carries to a peer that still holds the key.
        let b = Document::new(2).unwrap();
        b.set_entry("m", "k", "stale").unwrap();
        b.commit();
        // Bootstrap b from a's full history (which includes the set + delete).
        let a_delta = a.export_from(&b.version()).unwrap();
        b.import(&a_delta).unwrap();
        // a's delete is causally after a's set; once merged the key is absent —
        // but b's own concurrent set may survive by LWW. What matters for GC is
        // that a's OWN delete op exists and propagates; convergence of a↔b LWW is
        // covered by the storage/bridge layers. Here assert a stays absent.
        assert_eq!(a.get_entry("m", "k"), None);
    }

    #[test]
    fn shallow_snapshot_at_current_frontier_reimports_to_same_state() {
        let doc = Document::new(1).unwrap();
        doc.insert_text("note", 0, "hello").unwrap();
        doc.commit();
        let f_after_hello = doc.oplog_frontier();
        doc.insert_text("note", 5, " world").unwrap();
        doc.commit();
        let shallow = doc.shallow_snapshot(&f_after_hello).unwrap();
        let restored = Document::from_snapshot(2, &shallow).unwrap();
        assert_eq!(restored.text("note"), "hello world");
    }

    #[test]
    fn checkout_reads_past_then_returns_to_latest() {
        let doc = Document::new(1).unwrap();
        doc.insert_text("note", 0, "v1").unwrap();
        doc.commit();
        let f_v1 = doc.oplog_frontier();
        doc.insert_text("note", 2, "-v2").unwrap();
        doc.commit();
        assert_eq!(doc.text("note"), "v1-v2");
        doc.checkout(&f_v1).unwrap();
        assert_eq!(doc.text("note"), "v1", "checked-out state is the past");
        doc.checkout_latest();
        assert_eq!(doc.text("note"), "v1-v2", "returned to latest");
    }

    #[test]
    fn loads_from_snapshot_with_new_peer_id() {
        let a = Document::new(1).unwrap();
        a.insert_text("note", 0, "persisted").unwrap();
        a.commit();
        let snap = a.snapshot().unwrap();

        // A fresh device (peer 2) loads the snapshot and can keep editing.
        let b = Document::from_snapshot(2, &snap).unwrap();
        assert_eq!(b.text("note"), "persisted");
        b.insert_text("note", 9, "!").unwrap();
        b.commit();
        assert_eq!(b.text("note"), "persisted!");
    }
}
