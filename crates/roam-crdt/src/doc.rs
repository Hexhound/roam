use crate::error::CrdtError;
use loro::LoroDoc;
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
