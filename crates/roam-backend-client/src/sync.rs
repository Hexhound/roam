use crate::crypto::VaultKey;
use crate::entries::{local_blobs, local_entries, reassemble_log, split_log_lines};
use crate::transport::Backend;
use roam_storage::{PeerStatus, Store, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::sync::Mutex;

/// One full reconcile pass against the backend: push what the backend lacks,
/// pull what the local store lacks, apply pulled ops through the existing
/// idempotent import path. Stateless — the manifest diff each round is
/// authoritative; a stale manifest just defers work to the next round.
///
/// INVARIANT: every mutation of `store` goes through the SAME `Arc<Mutex<Store>>`
/// the iroh Engine holds, so the two apply paths never race.
pub async fn reconcile_once<B: Backend>(
    store: &Arc<Mutex<Store>>,
    backend: &Arc<B>,
    key: &VaultKey,
) -> anyhow::Result<()> {
    // Opt-in tracing (set ROAM_DEBUG) — the sync engine's `dlog!` lives in
    // roam-sync-core, so this crate does its own env check.
    let debug = std::env::var_os("ROAM_DEBUG").is_some();
    let bucket = key.bucket_id();

    // `local_entries_vec` is ordered by (peer, ascending index); keep it ordered
    // for the upload loop so any mid-loop `put_entry` failure leaves a clean
    // contiguous prefix per peer (never a hole that would strand later entries
    // behind the reader's GET-until-404 walk). `local_entry_ids` is only for the
    // set-membership `has_missing` check.
    let (local_entries_vec, local_blobs_vec, self_peer, own_log_len, roster_peers) = {
        let guard = store.lock().await;
        let roster_peers: Vec<(u64, roam_storage::PeerStatus)> = guard
            .roster()
            .into_iter()
            .map(|r| (r.peer_id, r.status))
            .collect();
        (
            local_entries(&guard, key)?,
            local_blobs(&guard, key)?,
            guard.peer_id(),
            guard.export_own_log().map(|b| b.len()).unwrap_or(0),
            roster_peers,
        )
    };
    let local_entry_ids: BTreeSet<String> =
        local_entries_vec.iter().map(|(id, _)| id.clone()).collect();
    let local_blob_ids: BTreeMap<String, String> = local_blobs_vec.into_iter().collect();

    if debug {
        eprintln!(
            "[be-sync] tick self_peer={self_peer} own_log={own_log_len}B \
             local_entries={} local_blobs={} roster={:?}",
            local_entries_vec.len(),
            local_blob_ids.len(),
            roster_peers,
        );
    }

    let manifest = backend.manifest(&bucket).await?;
    let remote_entry_ids: BTreeSet<String> = manifest.entry_ids.into_iter().collect();
    let remote_blob_ids: BTreeSet<String> = manifest.blob_ids.into_iter().collect();

    if debug {
        eprintln!(
            "[be-sync]   remote_entries={} remote_blobs={}",
            remote_entry_ids.len(),
            remote_blob_ids.len(),
        );
    }

    // Upload entries the backend lacks, in strict (peer, index) order (encrypt
    // the line bytes). Ascending order also self-heals any pre-existing gap by
    // filling it from the bottom.
    let mut uploaded_entries = 0usize;
    for (id, line) in &local_entries_vec {
        if !remote_entry_ids.contains(id) {
            let ct = key.seal(line);
            backend.put_entry(&bucket, id, ct).await?;
            uploaded_entries += 1;
        }
    }
    if debug {
        eprintln!("[be-sync]   uploaded_entries={uploaded_entries}");
    }
    // Upload blobs the backend lacks (encrypt the plaintext bytes). Order is
    // irrelevant — blobs are independent, self-identifying by content hash.
    for (id, content_hash) in &local_blob_ids {
        if !remote_blob_ids.contains(id) {
            // The blob may have been removed between the initial listing and this
            // re-lock; if so, skip it — sealing an empty payload under the real
            // blob_id would corrupt it for every peer.
            let bytes = {
                let guard = store.lock().await;
                guard.blobs().get(content_hash)?
            };
            let Some(bytes) = bytes else {
                continue;
            };
            let ct = key.seal(&bytes);
            backend.put_blob(&bucket, id, ct).await?;
        }
    }

    // Fetch blobs we lack, decrypt, store.
    for id in &remote_blob_ids {
        if local_blob_ids.contains_key(id) {
            continue;
        }
        if let Some(ct) = backend.get_blob(&bucket, id).await? {
            let plaintext = key.open(&ct)?;
            let guard = store.lock().await;
            guard.blobs().put(&plaintext)?;
        }
    }

    // Fetch entries we lack, per peer, in strict index order, then import.
    let has_missing = remote_entry_ids
        .iter()
        .any(|id| !local_entry_ids.contains(id));
    if debug {
        eprintln!("[be-sync]   has_missing_entries={has_missing}");
    }
    if has_missing {
        import_missing_entries(store, backend, key, &bucket, self_peer, debug).await?;
    }

    Ok(())
}

/// For every roster peer, pull backend entries beyond what we hold locally, in
/// strict index order, then import the reassembled suffix via `apply_peer_ops`.
async fn import_missing_entries<B: Backend>(
    store: &Arc<Mutex<Store>>,
    backend: &Arc<B>,
    key: &VaultKey,
    bucket: &str,
    self_peer: u64,
    debug: bool,
) -> anyhow::Result<()> {
    let peers: Vec<(u64, VerifyingKey)> = {
        let guard = store.lock().await;
        guard
            .roster()
            .into_iter()
            .filter(|r| r.peer_id != self_peer)
            .filter(|r| r.status == PeerStatus::Active)
            .filter_map(|r| {
                VerifyingKey::from_bytes(&r.verifying_key)
                    .ok()
                    .map(|k| (r.peer_id, k))
            })
            .collect()
    };

    for (peer_id, vkey) in peers {
        let mut index = {
            let guard = store.lock().await;
            split_log_lines(&guard.export_peer_log(peer_id).unwrap_or_default()).len() as u64
        };
        let mut fetched: Vec<Vec<u8>> = Vec::new();
        loop {
            let id = key.entry_id(peer_id, index);
            match backend.get_entry(bucket, &id).await? {
                Some(ct) => {
                    fetched.push(key.open(&ct)?);
                    index += 1;
                }
                None => break,
            }
        }
        if fetched.is_empty() {
            continue;
        }
        if debug {
            eprintln!(
                "[be-sync]   import peer={peer_id}: fetched {} new entries (from index {})",
                fetched.len(),
                index - fetched.len() as u64,
            );
        }
        let appended = reassemble_log(&fetched);
        let mut guard = store.lock().await;
        // A bad entry must not abort the whole pass (matching Engine behavior),
        // but it must be observable rather than silently swallowed.
        if let Err(err) = guard.apply_peer_ops(peer_id, &vkey, &appended) {
            eprintln!("backend sync: apply_peer_ops for peer {peer_id} failed: {err}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::VaultKey;
    use crate::transport::MemoryBackend;
    use roam_storage::{Identity, Store};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    async fn store_at(dir: &std::path::Path) -> Arc<Mutex<Store>> {
        Arc::new(Mutex::new(Store::open(dir, Identity::generate()).unwrap()))
    }

    #[tokio::test]
    async fn edits_on_a_flow_to_b_purely_through_the_backend() {
        let key = VaultKey([9u8; 32]);
        let backend = Arc::new(MemoryBackend::default());
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = store_at(a_dir.path()).await;
        let b = store_at(b_dir.path()).await;

        let (a_peer, a_key) = {
            let g = a.lock().await;
            (g.peer_id(), g.identity_verifying_bytes())
        };
        let (b_peer, b_key) = {
            let g = b.lock().await;
            (g.peer_id(), g.identity_verifying_bytes())
        };
        a.lock().await.add_peer(b_peer, b_key).unwrap();
        b.lock().await.add_peer(a_peer, a_key).unwrap();

        a.lock().await.set_entry("files", "note", "hello").unwrap();

        reconcile_once(&a, &backend, &key).await.unwrap();
        reconcile_once(&b, &backend, &key).await.unwrap();

        assert_eq!(
            b.lock().await.get_entry("files", "note"),
            Some("hello".to_string())
        );
    }

    #[tokio::test]
    async fn reconcile_is_idempotent() {
        let key = VaultKey([9u8; 32]);
        let backend = Arc::new(MemoryBackend::default());
        let dir = tempfile::tempdir().unwrap();
        let s = store_at(dir.path()).await;
        s.lock().await.set_entry("files", "k", "v").unwrap();
        reconcile_once(&s, &backend, &key).await.unwrap();
        let v1 = s.lock().await.doc_version_bytes();
        reconcile_once(&s, &backend, &key).await.unwrap();
        assert_eq!(s.lock().await.doc_version_bytes(), v1);
    }

    /// A multi-line log, then a partial catch-up: B first pulls A's whole log,
    /// then (after A appends more) pulls only the new suffix — exercising
    /// multi-line reassembly and a walk that starts mid-log.
    #[tokio::test]
    async fn multiline_partial_catch_up_converges() {
        let key = VaultKey([9u8; 32]);
        let backend = Arc::new(MemoryBackend::default());
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = store_at(a_dir.path()).await;
        let b = store_at(b_dir.path()).await;

        let (a_peer, a_key) = {
            let g = a.lock().await;
            (g.peer_id(), g.identity_verifying_bytes())
        };
        let (b_peer, b_key) = {
            let g = b.lock().await;
            (g.peer_id(), g.identity_verifying_bytes())
        };
        a.lock().await.add_peer(b_peer, b_key).unwrap();
        b.lock().await.add_peer(a_peer, a_key).unwrap();

        // Several edits so A's own log holds multiple lines.
        a.lock().await.set_entry("files", "note", "one").unwrap();
        a.lock().await.set_entry("files", "note", "two").unwrap();
        a.lock().await.set_entry("files", "note", "three").unwrap();

        reconcile_once(&a, &backend, &key).await.unwrap();
        reconcile_once(&b, &backend, &key).await.unwrap();
        assert_eq!(
            b.lock().await.get_entry("files", "note"),
            Some("three".to_string())
        );

        // A appends more; B must pick up only the new suffix (partial catch-up).
        a.lock().await.set_entry("files", "note", "four").unwrap();
        reconcile_once(&a, &backend, &key).await.unwrap();
        reconcile_once(&b, &backend, &key).await.unwrap();
        assert_eq!(
            b.lock().await.get_entry("files", "note"),
            Some("four".to_string())
        );
    }

    /// A raw blob stored on A flows to B purely through the backend.
    #[tokio::test]
    async fn a_blob_flows_through_the_backend() {
        let key = VaultKey([9u8; 32]);
        let backend = Arc::new(MemoryBackend::default());
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = store_at(a_dir.path()).await;
        let b = store_at(b_dir.path()).await;

        let (a_peer, a_key) = {
            let g = a.lock().await;
            (g.peer_id(), g.identity_verifying_bytes())
        };
        let (b_peer, b_key) = {
            let g = b.lock().await;
            (g.peer_id(), g.identity_verifying_bytes())
        };
        a.lock().await.add_peer(b_peer, b_key).unwrap();
        b.lock().await.add_peer(a_peer, a_key).unwrap();

        let hash = a.lock().await.blobs().put(b"blobdata").unwrap();

        reconcile_once(&a, &backend, &key).await.unwrap();
        reconcile_once(&b, &backend, &key).await.unwrap();

        assert_eq!(
            b.lock().await.blobs().get(&hash).unwrap(),
            Some(b"blobdata".to_vec())
        );
    }
}
