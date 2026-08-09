use crate::crypto::VaultKey;
use roam_storage::{StorageError, Store};

/// Split a per-peer op-log into its individual JSONL line-entries. Each returned
/// chunk includes its trailing `\n` so that [`reassemble_log`] is a byte-exact
/// inverse. A torn final line without a newline is captured as its own chunk.
pub fn split_log_lines(log: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, b) in log.iter().enumerate() {
        if *b == b'\n' {
            out.push(log[start..=i].to_vec());
            start = i + 1;
        }
    }
    if start < log.len() {
        out.push(log[start..].to_vec());
    }
    out
}

/// Concatenate line chunks back into a whole log (inverse of [`split_log_lines`]).
pub fn reassemble_log(lines: &[Vec<u8>]) -> Vec<u8> {
    lines.iter().flatten().copied().collect()
}

/// The set of peers whose logs this device holds: its own, plus every roster peer.
pub fn held_peers(store: &Store) -> Vec<u64> {
    let mut peers = vec![store.peer_id()];
    for rec in store.roster() {
        if rec.peer_id != store.peer_id() {
            peers.push(rec.peer_id);
        }
    }
    peers.sort_unstable();
    peers.dedup();
    peers
}

/// Every local op-log entry, keyed by its backend `entry_id`, paired with the
/// exact JSONL line bytes (including trailing `\n`) to seal and upload.
pub fn local_entries(
    store: &Store,
    key: &VaultKey,
) -> Result<Vec<(String, Vec<u8>)>, StorageError> {
    let mut out = Vec::new();
    for peer_id in held_peers(store) {
        let log = if peer_id == store.peer_id() {
            store.export_own_log()?
        } else {
            store.export_peer_log(peer_id)?
        };
        for (index, line) in split_log_lines(&log).into_iter().enumerate() {
            out.push((key.entry_id(peer_id, index as u64), line));
        }
    }
    Ok(out)
}

/// Every local blob, keyed by its backend `blob_id`, paired with its content hash.
pub fn local_blobs(store: &Store, key: &VaultKey) -> Result<Vec<(String, String)>, StorageError> {
    Ok(store
        .blobs()
        .list()?
        .into_iter()
        .map(|content_hash| (key.blob_id(&content_hash), content_hash))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_peer_log_into_line_entries() {
        let log = b"{\"a\":1}\n{\"b\":2}\n";
        let lines = split_log_lines(log);
        assert_eq!(
            lines,
            vec![b"{\"a\":1}\n".to_vec(), b"{\"b\":2}\n".to_vec()]
        );
    }

    #[test]
    fn empty_log_yields_no_lines() {
        assert!(split_log_lines(b"").is_empty());
    }

    #[test]
    fn a_trailing_partial_line_without_newline_is_still_captured() {
        let lines = split_log_lines(b"{\"a\":1}\n{\"b\":2}");
        assert_eq!(lines, vec![b"{\"a\":1}\n".to_vec(), b"{\"b\":2}".to_vec()]);
    }

    #[test]
    fn reassemble_is_the_inverse_of_split() {
        let log = b"{\"a\":1}\n{\"b\":2}\n".to_vec();
        assert_eq!(reassemble_log(&split_log_lines(&log)), log);
    }
}
