//! Small helpers for the history index that need filesystem access.
use crate::vfs::VaultFs;
use std::path::Path;

/// Count non-empty lines in an op-log file. A missing file is zero. Used to
/// snapshot per-peer op-log lengths into a history marker.
pub fn count_log_lines(fs: &dyn VaultFs, path: &Path) -> u64 {
    match fs.read_to_string(path) {
        Ok(t) => t.lines().filter(|l| !l.trim().is_empty()).count() as u64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::MemFs;

    #[test]
    fn counts_non_empty_lines_and_treats_missing_as_zero() {
        let fs = MemFs::new();
        let path = Path::new("/vault/ops/ops-1.jsonl");

        assert_eq!(count_log_lines(&fs, path), 0, "missing file counts as zero");

        fs.write(path, b"a\nb\n\n  \nc\n").unwrap();
        assert_eq!(count_log_lines(&fs, path), 3, "blank lines are not counted");
    }

    /// A torn tail (no trailing newline) still counts as a line — the marker
    /// records what the log physically holds.
    #[test]
    fn a_final_line_without_a_newline_still_counts() {
        let fs = MemFs::new();
        let path = Path::new("/vault/ops/ops-1.jsonl");
        fs.write(path, b"a\nb").unwrap();

        assert_eq!(count_log_lines(&fs, path), 2);
    }
}
