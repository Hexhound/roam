use crate::crypto::VaultKey;
use roam_storage::{PeerStatus, StorageError, Store};

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

/// The set of peers whose logs this device holds: its own, plus every ACTIVE
/// roster peer. Revoked peers are excluded — mirrors the iroh channel's
/// Active-only filter and the backend's own Active-only read/import path, so we
/// don't waste an upload relaying a log the backend would refuse to honor anyway.
pub fn held_peers(store: &Store) -> Vec<u64> {
    let mut peers = vec![store.peer_id()];
    for rec in store.roster() {
        if rec.peer_id != store.peer_id() && rec.status == PeerStatus::Active {
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
        for line in split_log_lines(&log) {
            out.push((key.entry_id_content(peer_id, &line), line));
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

    #[test]
    fn held_peers_excludes_revoked() {
        use roam_storage::{Identity, Role};

        let dir = tempfile::tempdir().unwrap();
        let me = Identity::generate();
        let active = Identity::generate();
        let revoked = Identity::generate();

        let mut store = Store::open(dir.path(), me.clone()).unwrap();
        // Found the vault as admin so this device may vouch/revoke peers.
        store.declare_founder(Role::Admin).unwrap();
        store
            .add_peer(
                active.peer_id(),
                active.verifying_key().to_bytes(),
                Role::Admin,
            )
            .unwrap();
        store
            .add_peer(
                revoked.peer_id(),
                revoked.verifying_key().to_bytes(),
                Role::Admin,
            )
            .unwrap();
        store
            .revoke_peer(revoked.peer_id(), revoked.verifying_key().to_bytes())
            .unwrap();

        let peers = held_peers(&store);
        assert!(peers.contains(&me.peer_id()), "must include own log");
        assert!(
            peers.contains(&active.peer_id()),
            "must include the still-active peer"
        );
        assert!(
            !peers.contains(&revoked.peer_id()),
            "must exclude the revoked peer"
        );
    }

    #[test]
    fn local_entries_are_keyed_by_content_and_survive_truncation() {
        use roam_storage::{Identity, Role, Store};
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(dir.path(), Identity::generate()).unwrap();
        s.declare_founder(Role::Admin).unwrap();
        s.set_entry("files", "k", "v1").unwrap();
        s.set_entry("files", "k", "v2").unwrap();
        let key = crate::crypto::VaultKey([9u8; 32]);
        let listed = local_entries(&s, &key).unwrap();
        assert_eq!(listed.len(), 2);
        for (id, line) in &listed {
            assert_eq!(*id, key.entry_id_content(s.peer_id(), line));
        }
    }
}
