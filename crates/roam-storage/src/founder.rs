use crate::error::StorageError;
use crate::vfs::VaultFs;
use std::path::{Path, PathBuf};

/// `<root>/founder` — the raw 8 little-endian bytes of the vault founder's
/// `peer_id`. Written once at genesis (creator) or delivered to a joiner over the
/// proven pairing stream. It seeds the `ever_admin` closure in `merge_roster`.
pub fn founder_path(root: &Path) -> PathBuf {
    root.join("founder")
}

pub fn read_founder(fs: &dyn VaultFs, root: &Path) -> Result<Option<u64>, StorageError> {
    match fs.read(&founder_path(root)) {
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
pub fn write_founder(fs: &dyn VaultFs, root: &Path, peer_id: u64) -> Result<(), StorageError> {
    fs.create_dir_all(root)?;
    let tmp = founder_path(root).with_extension("tmp");
    fs.write(&tmp, &peer_id.to_le_bytes())?;
    fs.rename(&tmp, &founder_path(root))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::{MemFs, NativeFs};

    /// Runs against any backend: the founder pin is storage-agnostic, which is
    /// the whole point of routing it through `VaultFs`.
    fn round_trip(fs: &dyn VaultFs, root: &Path) {
        assert_eq!(read_founder(fs, root).unwrap(), None, "absent pin reads None");

        write_founder(fs, root, 0xDEAD_BEEF_1234_5678).unwrap();
        assert_eq!(read_founder(fs, root).unwrap(), Some(0xDEAD_BEEF_1234_5678));

        // Atomic publish must leave no scratch file behind.
        assert!(
            !fs.exists(&founder_path(root).with_extension("tmp")),
            "tmp file survived the rename"
        );
    }

    #[test]
    fn round_trips_on_native_fs() {
        let dir = tempfile::tempdir().unwrap();
        round_trip(&NativeFs, dir.path());
    }

    #[test]
    fn round_trips_on_mem_fs() {
        round_trip(&MemFs::new(), Path::new("/vault"));
    }

    /// The pin is a fixed-width record; a truncated one is corruption, not an
    /// absent pin, and must not silently read as "no founder".
    #[test]
    fn a_short_founder_file_is_an_error_not_none() {
        let fs = MemFs::new();
        let root = Path::new("/vault");
        fs.create_dir_all(root).unwrap();
        fs.write(&founder_path(root), b"abc").unwrap();

        assert!(read_founder(&fs, root).is_err());
    }

    /// Byte-for-byte compatibility with the pre-`VaultFs` format: 8 little-endian
    /// bytes, no framing. An existing vault on disk must still be readable.
    #[test]
    fn on_disk_format_is_eight_little_endian_bytes() {
        let dir = tempfile::tempdir().unwrap();
        write_founder(&NativeFs, dir.path(), 1).unwrap();

        let raw = std::fs::read(dir.path().join("founder")).unwrap();
        assert_eq!(raw, vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }
}
