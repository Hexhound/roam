//! Local history index: an append-only JSONL log of checkpoint-able markers.
//!
//! Each marker pins a moment: the wall-clock time, the Loro op-log frontier at
//! that moment (bytes from `roam_crdt::Frontier::to_bytes`), and the number of
//! op-log lines each peer had written by then. `checkpoint` uses a marker to
//! (a) shallow-snapshot at its frontier and (b) truncate each peer op-log to the
//! lines *after* its recorded length. Purely a local cache — never gossiped.

use crate::error::StorageError;
use crate::vfs::{NativeFs, VaultFs};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// One retained point in local history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Marker {
    /// Wall-clock milliseconds since the Unix epoch when this marker was cut.
    pub ts_ms: i64,
    /// Base64 of `roam_crdt::Frontier::to_bytes` at this point.
    pub frontier: String,
    /// Per-peer op-log line count at this point (`peer_id -> lines written`).
    pub log_lens: BTreeMap<u64, u64>,
}

/// Append-only marker log at `<dir>/history.jsonl`.
pub struct HistoryIndex {
    path: PathBuf,
    fs: Arc<dyn VaultFs>,
}

impl HistoryIndex {
    /// Open (lazily; the file is created on first append) rooted at `dir`,
    /// backed by the real filesystem.
    pub fn new(dir: &Path) -> Self {
        Self::new_with_fs(dir, Arc::new(NativeFs))
    }

    /// [`HistoryIndex::new`], but persisting through a caller-supplied backend.
    pub fn new_with_fs(dir: &Path, fs: Arc<dyn VaultFs>) -> Self {
        Self {
            path: dir.join("history.jsonl"),
            fs,
        }
    }

    /// Append one marker as a JSON line.
    pub fn append(&self, marker: &Marker) -> Result<(), StorageError> {
        if let Some(parent) = self.path.parent() {
            self.fs.create_dir_all(parent)?;
        }
        let mut line = serde_json::to_string(marker)?;
        line.push('\n');
        self.fs.append(&self.path, line.as_bytes())?;
        Ok(())
    }

    /// All markers in write order. Missing file => empty. A torn final line
    /// (partial write) is tolerated and dropped, matching the op-log reader.
    pub fn markers(&self) -> Result<Vec<Marker>, StorageError> {
        let text = match self.fs.read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Marker>(line) {
                Ok(m) => out.push(m),
                Err(_) => break, // torn tail: stop at first unparsable line
            }
        }
        Ok(out)
    }

    /// The newest marker with `ts_ms <= ts`, or `None` if none qualify.
    pub fn marker_before(&self, ts: i64) -> Result<Option<Marker>, StorageError> {
        Ok(self.markers()?.into_iter().rfind(|m| m.ts_ms <= ts))
    }

    /// The most recent marker, or `None`.
    pub fn latest(&self) -> Result<Option<Marker>, StorageError> {
        Ok(self.markers()?.pop())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn marker(ts: i64) -> Marker {
        let mut log_lens = BTreeMap::new();
        log_lens.insert(7u64, ts as u64);
        Marker {
            ts_ms: ts,
            frontier: format!("f{ts}"),
            log_lens,
        }
    }

    #[test]
    fn append_then_read_round_trips_in_order() {
        let dir = tempdir().unwrap();
        let idx = HistoryIndex::new(dir.path());
        idx.append(&marker(100)).unwrap();
        idx.append(&marker(200)).unwrap();
        let all = idx.markers().unwrap();
        assert_eq!(all, vec![marker(100), marker(200)]);
    }

    #[test]
    fn marker_before_picks_newest_at_or_before() {
        let dir = tempdir().unwrap();
        let idx = HistoryIndex::new(dir.path());
        idx.append(&marker(100)).unwrap();
        idx.append(&marker(200)).unwrap();
        idx.append(&marker(300)).unwrap();
        assert_eq!(idx.marker_before(250).unwrap(), Some(marker(200)));
        assert_eq!(idx.marker_before(300).unwrap(), Some(marker(300)));
        assert_eq!(idx.marker_before(50).unwrap(), None);
    }

    #[test]
    fn latest_returns_last_marker_or_none() {
        let dir = tempdir().unwrap();
        let idx = HistoryIndex::new(dir.path());
        assert_eq!(idx.latest().unwrap(), None);
        idx.append(&marker(100)).unwrap();
        idx.append(&marker(200)).unwrap();
        assert_eq!(idx.latest().unwrap(), Some(marker(200)));
    }

    /// The index behaves identically off a non-`std::fs` backend, and appends
    /// really append — a marker log that got rewritten would lose history.
    #[test]
    fn appends_on_a_non_native_backend_extend_the_log() {
        use crate::vfs::MemFs;

        let fs = Arc::new(MemFs::new());
        let idx = HistoryIndex::new_with_fs(Path::new("/vault/history"), fs.clone());

        assert_eq!(idx.markers().unwrap(), vec![], "absent log reads empty");

        idx.append(&marker(100)).unwrap();
        let after_first = fs.read(Path::new("/vault/history/history.jsonl")).unwrap();

        idx.append(&marker(200)).unwrap();
        let after_second = fs.read(Path::new("/vault/history/history.jsonl")).unwrap();

        assert!(
            after_second.starts_with(&after_first),
            "second append rewrote the log instead of extending it"
        );
        assert_eq!(idx.markers().unwrap(), vec![marker(100), marker(200)]);
    }

    /// A torn final line is dropped rather than failing the whole read.
    #[test]
    fn a_torn_final_line_is_tolerated() {
        use crate::vfs::MemFs;

        let fs = Arc::new(MemFs::new());
        let path = Path::new("/vault/history/history.jsonl");
        let idx = HistoryIndex::new_with_fs(Path::new("/vault/history"), fs.clone());

        idx.append(&marker(100)).unwrap();
        fs.append(path, b"{\"ts_ms\":200,\"fron").unwrap(); // half a line

        assert_eq!(idx.markers().unwrap(), vec![marker(100)]);
    }
}
