use roam_crdt::{CrdtError, Document};

/// A CRDT document, as the browser sees it.
///
/// Deliberately a thin pass-through to [`roam_crdt::Document`]: the browser must
/// converge on exactly the same bytes as a native peer, so any behaviour that
/// lived here instead of in `roam-crdt` would be behaviour the two platforms
/// could disagree about.
pub struct Doc {
    inner: Document,
}

impl Doc {
    /// `peer_id` identifies this replica. A browser session must use an id
    /// distinct from every other peer in the vault, or their op logs collide.
    pub fn new(peer_id: u64) -> Result<Self, CrdtError> {
        Ok(Self {
            inner: Document::new(peer_id)?,
        })
    }

    pub fn insert_text(&self, id: &str, pos: usize, s: &str) -> Result<(), CrdtError> {
        self.inner.insert_text(id, pos, s)
    }

    pub fn text(&self, id: &str) -> String {
        self.inner.text(id)
    }

    pub fn set_entry(&self, map_id: &str, key: &str, value: &str) -> Result<(), CrdtError> {
        self.inner.set_entry(map_id, key, value)
    }

    pub fn get_entry(&self, map_id: &str, key: &str) -> Option<String> {
        self.inner.get_entry(map_id, key)
    }

    pub fn commit(&self) {
        self.inner.commit()
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, CrdtError> {
        self.inner.snapshot()
    }

    pub fn import(&self, bytes: &[u8]) -> Result<(), CrdtError> {
        self.inner.import(bytes)
    }
}
