use crate::error::StorageError;
use std::path::Path;

/// Write snapshot `bytes` to `path` via a temp file + rename (atomic on the
/// same filesystem). Assumes a single writer.
///
/// Unlike the identity key and op-log, the snapshot is a **rebuildable cache**
/// (the op-log is the source of truth), so this deliberately does NOT `fsync`
/// before the rename — a crash that loses the newest snapshot just means a
/// slower next load that replays the op-log, never data loss.
pub fn save(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("loro.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read a snapshot; `Ok(None)` if the file does not exist.
pub fn load(path: &Path) -> Result<Option<Vec<u8>>, StorageError> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roam_crdt::Document;
    use tempfile::tempdir;

    #[test]
    fn writes_and_reads_a_snapshot() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("snap.loro");

        let doc = Document::new(1).unwrap();
        doc.insert_text("note", 0, "snap me").unwrap();
        doc.commit();

        save(&path, &doc.snapshot().unwrap()).unwrap();
        let loaded = load(&path).unwrap();
        assert!(loaded.is_some());

        let restored = Document::from_snapshot(2, &loaded.unwrap()).unwrap();
        assert_eq!(restored.text("note"), "snap me");
    }

    #[test]
    fn load_returns_none_when_absent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.loro");
        assert!(load(&path).unwrap().is_none());
    }
}
