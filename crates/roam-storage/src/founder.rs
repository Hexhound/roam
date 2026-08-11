use crate::error::StorageError;
use std::path::{Path, PathBuf};

/// `<root>/founder` — the raw 8 little-endian bytes of the vault founder's
/// `peer_id`. Written once at genesis (creator) or delivered to a joiner over the
/// proven pairing stream. It seeds the `ever_admin` closure in `merge_roster`.
pub fn founder_path(root: &Path) -> PathBuf {
    root.join("founder")
}

pub fn read_founder(root: &Path) -> Result<Option<u64>, StorageError> {
    match std::fs::read(founder_path(root)) {
        Ok(bytes) => {
            let raw: [u8; 8] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| StorageError::Peer("founder file is not 8 bytes".into()))?;
            Ok(Some(u64::from_le_bytes(raw)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Persist the founder pin (atomic; caller enforces write-once policy).
pub fn write_founder(root: &Path, peer_id: u64) -> Result<(), StorageError> {
    std::fs::create_dir_all(root)?;
    let tmp = founder_path(root).with_extension("tmp");
    std::fs::write(&tmp, peer_id.to_le_bytes())?;
    std::fs::rename(&tmp, founder_path(root))?;
    Ok(())
}
