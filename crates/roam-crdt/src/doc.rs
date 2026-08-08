use crate::error::CrdtError;
use loro::LoroDoc;

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
}
