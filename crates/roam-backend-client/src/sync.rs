use crate::crypto::VaultKey;
use crate::entries::{local_blobs, local_entries};
use crate::transport::Backend;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use roam_rbsr::{initiate, reconcile, ItemSet, SetKind};
use roam_storage::{Keychain, PeerStatus, Store, VerifyingKey, EPOCH0_ID};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Client-side round cap: bounds a pathological/hostile server that never
/// converges. The 2s reconcile loop is self-healing, so aborting a pass is safe.
const RBSR_ROUND_CAP: usize = 32;

/// Open a stored ciphertext via the keychain's read rule. Returns:
/// - `Ok(Some(plaintext))` — opened,
/// - `Ok(None)` — `Undecryptable` (epoch key missing, or an unknown-epoch blob
///   whose epoch-0 fallback failed the AEAD tag check). NEVER aborts the pass.
fn open_classified(kc: &Keychain, payload: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    let plan = kc.classify(payload);
    let Some(key) = plan.key else { return Ok(None) };
    match crate::crypto::open_epoch(&key, &payload[plan.body_offset..]) {
        Ok(pt) => Ok(Some(pt)),
        // A wrong/unknown-epoch blob mis-read as epoch 0 fails the tag check ->
        // pending Undecryptable, self-heals when the key-log delivers the epoch.
        Err(_) => Ok(None),
    }
}

/// What a sync pass could not yet decrypt (surface for `WaitingKey`).
#[derive(Debug, Default, Clone)]
pub struct DecryptReport {
    pub undecryptable: usize,
}

/// Drive an RBSR session for one `kind` to convergence against the backend.
/// Returns `(have, need)` as id strings: `have` = ids the backend lacks
/// (we upload), `need` = ids we lack (we fetch). Both are returned in the same
/// base64url (no-pad) encoding used for entry/blob ids elsewhere.
async fn reconcile_set<B: Backend>(
    backend: &Arc<B>,
    bucket: &str,
    kind: SetKind,
    local_ids: &BTreeSet<String>,
) -> anyhow::Result<(BTreeSet<String>, BTreeSet<String>)> {
    let id_bytes: Vec<[u8; 32]> = local_ids.iter().filter_map(|s| str_to_id(s)).collect();
    let set = ItemSet::from_ids(id_bytes);

    let mut msg = initiate(&set);
    let mut have = BTreeSet::new();
    let mut need = BTreeSet::new();
    for _ in 0..RBSR_ROUND_CAP {
        let reply = backend.reconcile(bucket, kind, msg).await?;
        let out = reconcile(&set, &reply).map_err(|e| anyhow::anyhow!(e))?;
        have.extend(out.have.iter().map(id_to_str));
        need.extend(out.need.iter().map(id_to_str));
        match out.next_msg {
            Some(next) => msg = next,
            None => return Ok((have, need)),
        }
    }
    anyhow::bail!("RBSR did not converge within {RBSR_ROUND_CAP} rounds")
}

fn id_to_str(id: &[u8; 32]) -> String {
    B64URL.encode(id)
}

fn str_to_id(s: &str) -> Option<[u8; 32]> {
    B64URL.decode(s).ok()?.try_into().ok()
}

/// One full reconcile pass against the backend: push what the backend lacks,
/// pull what the local store lacks, apply pulled ops through the existing
/// idempotent import path. Stateless — RBSR discovery each round is
/// authoritative; anything missed just defers work to the next round.
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

    // Rebuild the keychain each pass — a P2P key-log gossip may have delivered a
    // new epoch since the last tick. Writes seal under the head epoch; reads
    // classify against the epochs known right now.
    let kc = {
        let guard = store.lock().await;
        guard.keychain(&key.id_key(), &key.epoch0_key())?
    };
    let mut report = DecryptReport::default();

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

    // RBSR discovery: reconcile the entry and blob id sets independently. `need_*`
    // are ids we lack (fetch); `have_*` are ids the backend lacks (upload).
    let (have_entry_ids, need_entry_ids) =
        reconcile_set(backend, &bucket, SetKind::Entries, &local_entry_ids).await?;
    let (have_blob_ids, need_blob_ids) = {
        let local_blob_id_set: BTreeSet<String> = local_blob_ids.keys().cloned().collect();
        reconcile_set(backend, &bucket, SetKind::Blobs, &local_blob_id_set).await?
    };

    if debug {
        eprintln!(
            "[be-sync]   rbsr entries: upload={} fetch={}  blobs: upload={} fetch={}",
            have_entry_ids.len(),
            need_entry_ids.len(),
            have_blob_ids.len(),
            need_blob_ids.len(),
        );
    }

    // Upload entries the backend lacks, in strict (peer, index) order (encrypt
    // the line bytes). Ascending order also self-heals any pre-existing gap by
    // filling it from the bottom.
    let mut uploaded_entries = 0usize;
    for (id, line) in &local_entries_vec {
        if have_entry_ids.contains(id) {
            let ct = match kc.head_write_key() {
                Some((epoch_id, epoch_key)) if epoch_id != EPOCH0_ID => {
                    crate::crypto::seal_epoch(&epoch_key, &epoch_id, line)
                }
                _ => key.seal(line),
            };
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
        if have_blob_ids.contains(id) {
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
            let ct = match kc.head_write_key() {
                Some((epoch_id, epoch_key)) if epoch_id != EPOCH0_ID => {
                    crate::crypto::seal_epoch(&epoch_key, &epoch_id, &bytes)
                }
                _ => key.seal(&bytes),
            };
            backend.put_blob(&bucket, id, ct).await?;
        }
    }

    // Fetch blobs we lack, decrypt, store.
    for id in &need_blob_ids {
        if let Some(ct) = backend.get_blob(&bucket, id).await? {
            match open_classified(&kc, &ct)? {
                Some(plaintext) => {
                    let guard = store.lock().await;
                    guard.blobs().put(&plaintext)?;
                }
                None => {
                    report.undecryptable += 1;
                    continue; // pending; self-heals when the key-log delivers the epoch
                }
            }
        }
    }

    // Fetch entries we lack, per peer, in strict index order, then import.
    let has_missing = !need_entry_ids.is_empty();
    if debug {
        eprintln!("[be-sync]   has_missing_entries={has_missing}");
    }
    if has_missing {
        import_needed_entries(
            store,
            backend,
            &bucket,
            &need_entry_ids,
            self_peer,
            debug,
            &kc,
            &mut report,
        )
        .await?;
    }

    if report.undecryptable > 0 {
        eprintln!(
            "[be-sync] {} item(s) undecryptable this pass (WaitingKey — a peer holds the epoch key)",
            report.undecryptable
        );
    }

    Ok(())
}

/// Fetch every content-addressed entry id in `need_entry_ids` directly from the
/// backend (RBSR's discovery is set-based, not sequential, so there is no
/// per-peer index to walk anymore), decrypt, attribute it to its author via the
/// line's own `peer` field, and append it into that author's op-log through
/// [`Store::dedup_append_peer_line`] — which re-imports the whole log each
/// time, so Loro buffers any op whose dependency hasn't landed yet and
/// converges once it does, regardless of fetch order.
async fn import_needed_entries<B: Backend>(
    store: &Arc<Mutex<Store>>,
    backend: &Arc<B>,
    bucket: &str,
    need_entry_ids: &BTreeSet<String>,
    self_peer: u64,
    debug: bool,
    kc: &Keychain,
    report: &mut DecryptReport,
) -> anyhow::Result<()> {
    // Active roster peers (peer_id -> VerifyingKey), excluding self — the trust
    // boundary for attributing a fetched line to an author.
    let peers: std::collections::HashMap<u64, VerifyingKey> = {
        let guard = store.lock().await;
        guard
            .roster()
            .into_iter()
            .filter(|r| r.peer_id != self_peer && r.status == PeerStatus::Active)
            .filter_map(|r| {
                VerifyingKey::from_bytes(&r.verifying_key)
                    .ok()
                    .map(|k| (r.peer_id, k))
            })
            .collect()
    };

    let mut imported = 0usize;
    for id in need_entry_ids {
        let Some(ct) = backend.get_entry(bucket, id).await? else {
            continue;
        };
        let Some(line) = open_classified(kc, &ct)? else {
            // Missing this epoch's key; self-heals when the key-log delivers it.
            report.undecryptable += 1;
            continue;
        };
        let Some(author) = parse_entry_author(&line) else {
            continue; // malformed line; nothing sane to attribute it to
        };
        let Some(vkey) = peers.get(&author) else {
            continue; // unknown/untrusted author -> drop
        };
        let mut guard = store.lock().await;
        // A bad entry must not abort the whole pass (matching Engine behavior),
        // but it must be observable rather than silently swallowed.
        if let Err(err) = guard.dedup_append_peer_line(author, vkey, &line) {
            eprintln!("backend sync: dedup_append_peer_line peer={author} failed: {err}");
        } else {
            imported += 1;
        }
    }
    if debug {
        eprintln!(
            "[be-sync]   import_needed_entries: fetched/imported {imported} of {} needed",
            need_entry_ids.len(),
        );
    }
    Ok(())
}

/// Pull the `peer` field out of one op-log JSONL line (`{"peer":<u64>,...}`).
fn parse_entry_author(line: &[u8]) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_slice(line).ok()?;
    v.get("peer")?.as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::VaultKey;
    use crate::transport::MemoryBackend;
    use roam_storage::{Identity, Role, Store};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    async fn store_at(dir: &std::path::Path) -> Arc<Mutex<Store>> {
        let mut store = Store::open(dir, Identity::generate()).unwrap();
        // Found this vault as admin so local writes + `add_peer` vouches are allowed.
        store.declare_founder(Role::Admin).unwrap();
        Arc::new(Mutex::new(store))
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
        a.lock().await.add_peer(b_peer, b_key, Role::Admin).unwrap();
        b.lock().await.add_peer(a_peer, a_key, Role::Admin).unwrap();

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
        a.lock().await.add_peer(b_peer, b_key, Role::Admin).unwrap();
        b.lock().await.add_peer(a_peer, a_key, Role::Admin).unwrap();

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
        a.lock().await.add_peer(b_peer, b_key, Role::Admin).unwrap();
        b.lock().await.add_peer(a_peer, a_key, Role::Admin).unwrap();

        let hash = a.lock().await.blobs().put(b"blobdata").unwrap();

        reconcile_once(&a, &backend, &key).await.unwrap();
        reconcile_once(&b, &backend, &key).await.unwrap();

        assert_eq!(
            b.lock().await.blobs().get(&hash).unwrap(),
            Some(b"blobdata".to_vec())
        );
    }

    #[test]
    fn undecryptable_report_counts_items_whose_epoch_key_is_missing() {
        use roam_storage::{Keychain, EPOCH0_ID};
        let vault = VaultKey([9u8; 32]);
        let kc = Keychain::build(vault.id_key(), vault.epoch0_key(), 1, &[0u8; 32], &[]);

        // Genuine epoch-0 (legacy) ciphertext opens.
        let legacy = vault.seal(b"ok");
        let plan = kc.classify(&legacy);
        assert_eq!(plan.epoch, EPOCH0_ID);
        assert!(open_classified(&kc, &legacy).unwrap().is_some());

        // A payload prefixed with an unknown 32-byte "epoch" + random body: classify
        // says epoch 0 (prefix unknown), AEAD open fails -> None (Undecryptable),
        // not an error that aborts the pass.
        let mut bogus = [0xC7u8; 32].to_vec();
        bogus.extend_from_slice(&[0u8; 40]);
        assert!(open_classified(&kc, &bogus).unwrap().is_none());
    }
}
