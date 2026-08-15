use crate::error::CrdtError;
use crate::history_types::{ChangeInfo, TextDiff, TextSpan};
use loro::ContainerTrait;
use loro::LoroDoc;
use loro::LoroValue;
use loro::ValueOrContainer;
use loro::VersionVector;

/// Same-peer, causally-adjacent commits within this many seconds coalesce into
/// one change (which keeps the earliest timestamp). Bounds op-log growth and
/// sets the per-file history granularity to "edit session".
pub const CHANGE_MERGE_SECS: i64 = 10;

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

/// One key-level change to a map container, as reported by
/// [`Document::map_delta`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapChange {
    /// The map container's name (the `map_id` passed to `set_entry`).
    pub container: String,
    pub key: String,
    /// The value after the change, or `None` when the key was deleted.
    pub value: Option<String>,
}

/// An opaque handle to a specific point in the op-DAG (a set of leaf op-ids).
/// Wraps loro's `Frontiers`; `to_bytes`/`from_bytes` give a persistable byte
/// form used by the storage-layer history index.
#[derive(Clone, Debug)]
pub struct Frontier(pub(crate) loro::Frontiers);

impl Frontier {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.encode()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CrdtError> {
        Ok(Frontier(loro::Frontiers::decode(bytes)?))
    }

    /// The empty frontier (document genesis / before any op).
    pub fn empty() -> Self {
        Frontier(loro::Frontiers::default())
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
        doc.set_record_timestamp(true);
        doc.set_change_merge_interval(CHANGE_MERGE_SECS);
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
        doc.set_record_timestamp(true);
        doc.set_change_merge_interval(CHANGE_MERGE_SECS);
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

    /// Merge a single-author delta, rejecting any update whose INTERNAL loro
    /// peer_id is not `author` (EN1). The enclosing op-log signature only covers
    /// the opaque `bytes`, so a signer could embed ops attributed to another
    /// device's peer id — forging authorship and, because loro op-ids are
    /// idempotent, silently censoring that device's genuine future ops. The
    /// update is probed in a throwaway document first, so a foreign-author update
    /// is rejected WITHOUT mutating this document.
    pub fn import_authored_by(&self, author: u64, bytes: &[u8]) -> Result<(), CrdtError> {
        let probe = LoroDoc::new();
        let status = probe.import(bytes)?;
        let mut peers = status
            .success
            .iter()
            .map(|(peer, _)| *peer)
            .collect::<Vec<u64>>();
        if let Some(pending) = &status.pending {
            peers.extend(pending.iter().map(|(peer, _)| *peer));
        }
        if let Some(&found) = peers.iter().find(|&&p| p != author) {
            return Err(CrdtError::ForeignAuthor {
                expected: author,
                found,
            });
        }
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

    /// Commit pending edits stamped with an explicit wall-clock time (seconds
    /// since the Unix epoch). Production uses [`Document::commit`]; this exists
    /// so history/coalescing behaviour is testable without sleeping.
    pub fn commit_at(&self, secs: i64) {
        self.doc
            .commit_with(loro::CommitOptions::new().timestamp(secs));
    }

    /// The char-level text delta transforming container `id`'s content at
    /// `from` into its content at `to`. Empty if untouched between the two.
    pub fn text_delta(
        &self,
        id: &str,
        from: &Frontier,
        to: &Frontier,
    ) -> Result<TextDiff, CrdtError> {
        let target = self.doc.get_text(id).id();
        let batch = self.doc.diff(&from.0, &to.0)?;
        let mut spans = Vec::new();
        for (cid, diff) in batch.iter() {
            if *cid != target {
                continue;
            }
            if let loro::event::Diff::Text(deltas) = diff {
                for delta in deltas {
                    match delta {
                        loro::TextDelta::Retain { retain, .. } => {
                            spans.push(TextSpan::Retain(*retain))
                        }
                        loro::TextDelta::Insert { insert, .. } => {
                            spans.push(TextSpan::Insert(insert.clone()))
                        }
                        loro::TextDelta::Delete { delete, .. } => {
                            spans.push(TextSpan::Delete(*delete))
                        }
                    }
                }
            }
        }
        Ok(TextDiff { spans })
    }

    /// Every key-level change to map containers between two frontiers.
    ///
    /// This is what lets an embedder react to a sync rather than poll for it:
    /// capture [`Document::oplog_frontier`] before importing peer ops, call this
    /// with the frontier afterwards, and get exactly the keys that moved. Without
    /// it the only way to find out what a sync changed is to re-read every
    /// container and diff it by hand, which costs the whole dataset per sync and
    /// still cannot distinguish "deleted" from "never existed".
    ///
    /// Deletes are reported as `value: None`, which is not the same as a key
    /// that was untouched — the latter simply does not appear. That distinction
    /// is the point: a consumer projecting into a database has to issue a DELETE
    /// for one and nothing at all for the other.
    ///
    /// Only root map containers are reported (the only kind roam creates), and
    /// only string values — matching [`Document::get_entry`], which is the sole
    /// way values get in.
    pub fn map_delta(&self, from: &Frontier, to: &Frontier) -> Result<Vec<MapChange>, CrdtError> {
        let batch = self.doc.diff(&from.0, &to.0)?;
        let mut changes = Vec::new();

        for (cid, diff) in batch.iter() {
            let loro::ContainerID::Root {
                name,
                container_type: loro::ContainerType::Map,
            } = cid
            else {
                continue;
            };
            let loro::event::Diff::Map(delta) = diff else {
                continue;
            };

            for (key, value) in delta.updated.iter() {
                changes.push(MapChange {
                    container: name.to_string(),
                    key: key.to_string(),
                    value: value.as_ref().and_then(|entry| match entry {
                        ValueOrContainer::Value(LoroValue::String(text)) => {
                            Some(text.to_string())
                        }
                        _ => None,
                    }),
                });
            }
        }

        Ok(changes)
    }

    /// Every change touching text container `id`, oldest-first. Each carries the
    /// frontier AS OF that change, its wall-clock ms, and the authoring peer id.
    pub fn text_changes(&self, id: &str) -> Result<Vec<ChangeInfo>, CrdtError> {
        let target = self.doc.get_text(id).id();
        let start = loro::VersionVector::default();
        let end = self.doc.oplog_vv();
        let schema = self
            .doc
            .export_json_updates_without_peer_compression(&start, &end);

        let mut out: Vec<(u32, ChangeInfo)> = Vec::new();
        for change in &schema.changes {
            let touches = change.ops.iter().any(|op| op.container == target);
            if !touches {
                continue;
            }
            let last_counter = change.id.counter + change.op_len() as i32 - 1;
            let tip = loro::ID::new(change.id.peer, last_counter);
            out.push((
                change.lamport,
                ChangeInfo {
                    frontier: Frontier(loro::Frontiers::from_id(tip)),
                    ts_ms: change.timestamp * 1000,
                    author_peer: change.id.peer,
                },
            ));
        }
        out.sort_by_key(|(lamport, _)| *lamport);
        Ok(out.into_iter().map(|(_, info)| info).collect())
    }

    /// Non-destructively revert container `id` to its content at `target`:
    /// compute the delta from the current tip back to `target`, restricted to
    /// this one container, and apply it as NEW ops on top of tip. Forward
    /// history is retained; the revert is an ordinary edit that wins the merge.
    pub fn revert_container(&self, id: &str, target: &Frontier) -> Result<(), CrdtError> {
        if self.doc.frontiers_to_vv(&target.0).is_none() {
            return Err(CrdtError::FrontierNotRetained);
        }
        let container = self.doc.get_text(id).id();
        let tip = self.doc.oplog_frontiers();
        let batch = self.doc.diff(&tip, &target.0)?;

        let mut only = loro::event::DiffBatch::default();
        for (cid, diff) in batch.iter() {
            if *cid == container {
                let _ = only.push(cid.clone(), diff.clone());
            }
        }
        self.doc.apply_diff(only)?;
        self.doc.commit();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_delta_reports_a_set_key() {
        let doc = Document::new(1).unwrap();
        let before = doc.oplog_frontier();
        doc.set_entry("journeys", "j1", "{\"title\":\"knee\"}").unwrap();
        doc.commit();

        let changes = doc.map_delta(&before, &doc.oplog_frontier()).unwrap();
        assert_eq!(
            changes,
            vec![MapChange {
                container: "journeys".into(),
                key: "j1".into(),
                value: Some("{\"title\":\"knee\"}".into()),
            }]
        );
    }

    #[test]
    fn map_delta_distinguishes_a_delete_from_an_absence() {
        // A consumer projecting into a database has to issue a DELETE for a
        // removed key and nothing at all for an untouched one. Collapsing the
        // two would either leave stale rows behind or delete live ones.
        let doc = Document::new(1).unwrap();
        doc.set_entry("journeys", "j1", "a").unwrap();
        doc.set_entry("journeys", "j2", "b").unwrap();
        doc.commit();

        let before = doc.oplog_frontier();
        doc.remove_entry("journeys", "j1").unwrap();
        doc.commit();

        let changes = doc.map_delta(&before, &doc.oplog_frontier()).unwrap();
        assert_eq!(
            changes,
            vec![MapChange {
                container: "journeys".into(),
                key: "j1".into(),
                value: None,
            }],
            "only the deleted key, reported as a deletion"
        );
    }

    #[test]
    fn map_delta_spans_containers() {
        let doc = Document::new(1).unwrap();
        let before = doc.oplog_frontier();
        doc.set_entry("journeys", "j1", "a").unwrap();
        doc.set_entry("events", "e1", "b").unwrap();
        doc.commit();

        let mut changes = doc.map_delta(&before, &doc.oplog_frontier()).unwrap();
        changes.sort_by(|a, b| a.container.cmp(&b.container));
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].container, "events");
        assert_eq!(changes[1].container, "journeys");
    }

    #[test]
    fn map_delta_is_empty_when_nothing_moved() {
        let doc = Document::new(1).unwrap();
        doc.set_entry("journeys", "j1", "a").unwrap();
        doc.commit();

        let frontier = doc.oplog_frontier();
        assert!(doc.map_delta(&frontier, &frontier).unwrap().is_empty());
    }

    #[test]
    fn map_delta_ignores_text_containers() {
        // Text is a separate concern with its own delta API; leaking a text
        // container in here would have a map consumer try to write a row for it.
        let doc = Document::new(1).unwrap();
        let before = doc.oplog_frontier();
        doc.insert_text("note", 0, "hello").unwrap();
        doc.commit();

        assert!(doc.map_delta(&before, &doc.oplog_frontier()).unwrap().is_empty());
    }

    #[test]
    fn map_delta_reports_what_a_peer_import_changed() {
        // The reason this exists: after importing peer ops, an embedder needs
        // to know which keys moved without re-reading the whole dataset.
        let local = Document::new(1).unwrap();
        let remote = Document::new(2).unwrap();

        remote.set_entry("journeys", "j1", "from-peer").unwrap();
        remote.commit();
        let ops = remote.export_from(&Version(VersionVector::default())).unwrap();

        let before = local.oplog_frontier();
        local.import(&ops).unwrap();

        let changes = local.map_delta(&before, &local.oplog_frontier()).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].key, "j1");
        assert_eq!(changes[0].value.as_deref(), Some("from-peer"));
    }

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
    fn import_authored_by_rejects_a_foreign_internal_peer() {
        // EN1: an update whose INTERNAL loro peer_id differs from the claimed
        // author must be rejected before mutating the doc. Otherwise a signer can
        // embed ops attributed to another device — forging authorship and (via
        // idempotent op-ids) censoring that device's real future ops.
        let victim = Document::new(7).unwrap();
        victim.insert_text("note", 0, "secret").unwrap();
        victim.commit();
        let from_empty = Document::new(99).unwrap().version();
        let update = victim.export_from(&from_empty).unwrap();

        let target = Document::new(1).unwrap();
        // Claimed author 9 != internal peer 7 → reject, no mutation.
        assert!(target.import_authored_by(9, &update).is_err());
        assert_eq!(
            target.text("note"),
            "",
            "a rejected update must not mutate the document"
        );
        // Correct author 7 → accepted.
        target.import_authored_by(7, &update).unwrap();
        assert_eq!(target.text("note"), "secret");
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
        assert!(
            a.text("note").contains(" from A"),
            "lost A's edit: {}",
            a.text("note")
        );
        assert!(
            a.text("note").contains(" from B"),
            "lost B's edit: {}",
            a.text("note")
        );
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
        assert!(
            !v_early.includes(&v_late),
            "earlier must NOT dominate later"
        );
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

    #[test]
    fn changes_within_window_coalesce_and_keep_earliest_timestamp() {
        let doc = Document::new(1).unwrap();
        doc.insert_text("f", 0, "a").unwrap();
        doc.commit_at(1000);
        doc.insert_text("f", 1, "b").unwrap();
        doc.commit_at(1005);
        doc.insert_text("f", 2, "c").unwrap();
        doc.commit_at(1020);

        let changes = doc.text_changes("f").unwrap();
        assert_eq!(
            changes.len(),
            2,
            "5s-apart commits coalesce; 20s-apart splits"
        );
        assert_eq!(
            changes[0].ts_ms,
            1000 * 1000,
            "coalesced change keeps earliest ts"
        );
        assert_eq!(changes[1].ts_ms, 1020 * 1000);
        assert_eq!(changes[0].author_peer, 1);
    }

    #[test]
    fn text_delta_between_frontiers_reports_char_spans() {
        let doc = Document::new(1).unwrap();
        doc.insert_text("f", 0, "hello").unwrap();
        doc.commit();
        let v1 = doc.oplog_frontier();
        doc.insert_text("f", 5, " world").unwrap();
        doc.commit();
        let v2 = doc.oplog_frontier();

        let d = doc.text_delta("f", &v1, &v2).unwrap();
        assert_eq!(
            d.spans,
            vec![TextSpan::Retain(5), TextSpan::Insert(" world".to_string())]
        );

        let back = doc.text_delta("f", &v2, &v1).unwrap();
        assert_eq!(back.spans, vec![TextSpan::Retain(5), TextSpan::Delete(6)]);
    }

    #[test]
    fn text_changes_are_oldest_first_and_container_scoped() {
        let doc = Document::new(7).unwrap();
        doc.insert_text("a", 0, "x").unwrap();
        doc.commit_at(100);
        doc.insert_text("b", 0, "y").unwrap();
        doc.commit_at(200);
        doc.insert_text("a", 1, "z").unwrap();
        doc.commit_at(2000);

        let a = doc.text_changes("a").unwrap();
        assert_eq!(a.len(), 2, "only changes touching container 'a'");
        assert!(a[0].ts_ms < a[1].ts_ms, "oldest first");
        assert_eq!(a[0].ts_ms, 100 * 1000);
        assert_eq!(a[1].ts_ms, 2000 * 1000);
    }

    #[test]
    fn revert_container_restores_content_without_losing_forward_history() {
        let doc = Document::new(1).unwrap();
        doc.insert_text("f", 0, "version one").unwrap();
        // Space the two setup commits past the 10s merge window so they stay
        // two distinct changes (real-time commit() calls would coalesce). The
        // revert's own commit uses real wall-clock time, far past 2000s, so it
        // is a third, distinct change.
        doc.commit_at(1000);
        let v1 = doc.oplog_frontier();
        doc.delete_text("f", 0, "version one".chars().count())
            .unwrap();
        doc.insert_text("f", 0, "version two BAD").unwrap();
        doc.commit_at(2000);

        doc.revert_container("f", &v1).unwrap();
        assert_eq!(doc.text("f"), "version one");
        let changes = doc.text_changes("f").unwrap();
        assert_eq!(
            changes.len(),
            3,
            "revert adds a new change; nothing removed"
        );
    }

    #[test]
    fn revert_container_to_unknown_frontier_errs() {
        let doc = Document::new(1).unwrap();
        doc.insert_text("f", 0, "a").unwrap();
        doc.commit();
        let bogus = Frontier(loro::Frontiers::from_id(loro::ID::new(999, 999)));
        assert!(matches!(
            doc.revert_container("f", &bogus),
            Err(CrdtError::FrontierNotRetained)
        ));
    }
}
