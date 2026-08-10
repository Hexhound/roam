//! Small helpers for the history index that need filesystem access.
use std::path::Path;

/// Count non-empty lines in an op-log file. A missing file is zero. Used to
/// snapshot per-peer op-log lengths into a history marker.
pub fn count_log_lines(path: &Path) -> u64 {
    match std::fs::read_to_string(path) {
        Ok(t) => t.lines().filter(|l| !l.trim().is_empty()).count() as u64,
        Err(_) => 0,
    }
}
