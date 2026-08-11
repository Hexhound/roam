use crate::crypto::VaultKey;
use crate::entries::{local_blobs, local_entries};
use crate::transport::Backend;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use roam_rbsr::{initiate, reconcile, ItemSet, SetKind};
use roam_storage::{Keychain, PeerStatus, Role, Store, VerifyingKey, EPOCH0_ID};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
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

    // Snapshot reconcile FIRST: fetch/verify/adopt any backend snapshot we lack.
    // Adoption is additive; recording each held snapshot lets us stop advertising
    // (below) the entries it subsumes.
    import_needed_snapshots(store, backend, &bucket, &kc, &mut report, debug).await?;

    // Entries a held snapshot subsumes must never re-enter our fetch set — we hold
    // the snapshot that covers them. This is the fix for the RBSR re-pull fight:
    // without it, ops we compacted locally reappear in `need` every pass until the
    // backend prunes.
    let subsumed_entry_ids: BTreeSet<String> = {
        let guard = store.lock().await;
        guard
            .held_snapshots()?
            .into_iter()
            .flat_map(|h| h.subsumed)
            .collect()
    };

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
    // Drop subsumed ids from the fetch set: a held snapshot already covers them.
    let need_entry_ids: BTreeSet<String> = need_entry_ids
        .difference(&subsumed_entry_ids)
        .cloned()
        .collect();
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

    // If the backend asked for a snapshot and we're an Admin, produce + upload one.
    maybe_produce_snapshot(store, backend, key, &bucket, &kc, debug).await?;

    Ok(())
}

/// Reconcile the snapshot id-set against the backend; for each snapshot we lack,
/// fetch it, verify the author's signature + ciphertext binding, decrypt, adopt
/// it (additively), and record it as held. A snapshot that fails verification or
/// can't be decrypted yet is skipped — never adopted — so a forged or
/// wrong-epoch snapshot can't corrupt state.
async fn import_needed_snapshots<B: Backend>(
    store: &Arc<Mutex<Store>>,
    backend: &Arc<B>,
    bucket: &str,
    kc: &Keychain,
    report: &mut DecryptReport,
    debug: bool,
) -> anyhow::Result<()> {
    let held: BTreeSet<String> = {
        let guard = store.lock().await;
        guard.held_snapshots()?.into_iter().map(|h| h.id).collect()
    };
    let (_have, need) = reconcile_set(backend, bucket, SetKind::Snapshots, &held).await?;
    if need.is_empty() {
        return Ok(());
    }

    // Verifying keys we trust to author a snapshot: ADMIN roster peers only (plus
    // self iff this device is an Admin). Authoring a snapshot authorizes a future
    // prune and injects state via an additive `doc.import` that bypasses the
    // per-op Reader-content-drop rule — so a non-Admin author must never be
    // adopted, even with a valid self-signature. Producer-side gating is
    // voluntary; this receiver-side gate is what actually enforces Admin-only.
    let author_keys: std::collections::HashMap<u64, VerifyingKey> = {
        let guard = store.lock().await;
        let mut m = std::collections::HashMap::new();
        for r in guard.roster() {
            if r.role == Role::Admin {
                if let Ok(k) = VerifyingKey::from_bytes(&r.verifying_key) {
                    m.insert(r.peer_id, k);
                }
            }
        }
        if guard.self_role() == Some(Role::Admin) {
            if let Ok(k) = VerifyingKey::from_bytes(&guard.identity_verifying_bytes()) {
                m.insert(guard.peer_id(), k);
            }
        }
        m
    };

    for id in &need {
        let Some(framed) = backend.get_snapshot(bucket, id).await? else {
            continue;
        };
        let Some((manifest_json, sealed)) = crate::snapshot_msg::unframe(&framed) else {
            eprintln!("backend sync: snapshot {id} has a malformed frame; skipping");
            continue;
        };
        let manifest: crate::snapshot_msg::SnapshotManifest =
            match serde_json::from_slice(manifest_json) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("backend sync: snapshot {id} manifest parse failed: {e}");
                    continue;
                }
            };
        // Authority + integrity: signed by a trusted roster author, and the sig
        // binds exactly these sealed bytes.
        let Some(vk) = author_keys.get(&manifest.author) else {
            eprintln!("backend sync: snapshot {id} author not in roster; skipping");
            continue;
        };
        if !manifest.verify(vk) {
            eprintln!("backend sync: snapshot {id} signature invalid; skipping");
            continue;
        }
        if <[u8; 32]>::from(blake3::hash(sealed)) != manifest.snapshot_ct_hash {
            eprintln!("backend sync: snapshot {id} ciphertext hash mismatch; skipping");
            continue;
        }
        // Decrypt through the keychain's read rule (may be pending if the epoch
        // key hasn't arrived; that self-heals next pass).
        let Some(plaintext) = open_classified(kc, sealed)? else {
            report.undecryptable += 1;
            continue;
        };
        {
            let mut guard = store.lock().await;
            guard.adopt_snapshot(&plaintext)?;
            guard.record_held_snapshot(id, &manifest.subsumed_entry_ids)?;
        }
        if debug {
            eprintln!(
                "[be-sync]   adopted snapshot {id} subsuming {} entries",
                manifest.subsumed_entry_ids.len()
            );
        }
    }
    Ok(())
}

/// Seal `plaintext` under the head epoch — the same rule the entry/blob upload
/// paths use (tagged epoch seal above epoch 0, legacy `VaultKey::seal` at 0).
fn seal_under_head(kc: &Keychain, key: &VaultKey, plaintext: &[u8]) -> Vec<u8> {
    match kc.head_write_key() {
        Some((epoch_id, epoch_key)) if epoch_id != EPOCH0_ID => {
            crate::crypto::seal_epoch(&epoch_key, &epoch_id, plaintext)
        }
        _ => key.seal(plaintext),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Op-log tail (in ms) left replayable beyond the snapshot frontier. Peers only
/// recently behind catch up by normal op-replay and never adopt a snapshot.
/// Default 14 days; override with `ROAM_SNAPSHOT_LAG_DAYS` (tests set 0).
fn retention_lag_ms() -> i64 {
    let days: i64 = std::env::var("ROAM_SNAPSHOT_LAG_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(14);
    days.saturating_mul(86_400_000)
}

/// When the backend signals `snapshot_wanted` and this device is an Admin, pin a
/// head history marker, build a shallow snapshot at `head − retention_lag`, seal
/// it, and upload it framed with a signed manifest. Only Admins may author (the
/// act authorizes a future prune); non-Admins ignore the request.
async fn maybe_produce_snapshot<B: Backend>(
    store: &Arc<Mutex<Store>>,
    backend: &Arc<B>,
    key: &VaultKey,
    bucket: &str,
    kc: &Keychain,
    debug: bool,
) -> anyhow::Result<()> {
    if !backend.manifest(bucket).await?.snapshot_wanted {
        return Ok(());
    }
    if store.lock().await.self_role() != Some(Role::Admin) {
        return Ok(());
    }

    // Pin a head marker so there is always a frontier to snapshot, then build.
    // Compute `before_ts` AFTER writing the marker: the marker's timestamp is
    // taken inside write_snapshot, so a `before_ts` sampled earlier could sit just
    // below it and miss the fresh marker (flaky on the ms boundary). With the
    // default lag the head marker is intentionally excluded, leaving a replayable
    // tail; lag 0 (tests) snapshots at head.
    let snap = {
        let mut guard = store.lock().await;
        guard.write_snapshot()?;
        let before_ts = now_ms().saturating_sub(retention_lag_ms());
        guard.build_backend_snapshot(before_ts)?
    };
    let Some(snap) = snap else {
        if debug {
            eprintln!("[be-sync]   snapshot_wanted but no qualifying marker yet");
        }
        return Ok(());
    };

    let sealed = seal_under_head(kc, key, &snap.bytes);
    let snapshot_id = key.snapshot_id(&snap.frontier_digest);
    let subsumed_entry_ids: Vec<String> = snap
        .subsumed_lines
        .iter()
        .map(|(peer, line)| key.entry_id_content(*peer, line))
        .collect();
    let blob_ref_ids: Vec<String> = snap.blob_refs.iter().map(|h| key.blob_id(h)).collect();

    let manifest = crate::snapshot_msg::SnapshotManifest {
        frontier_digest: snap.frontier_digest,
        snapshot_ct_hash: blake3::hash(&sealed).into(),
        subsumed_entry_ids,
        blob_ref_ids,
        author: 0,
        sig: String::new(),
    }
    .signed(store.lock().await.identity());

    let manifest_json = serde_json::to_vec(&manifest)?;
    let framed = crate::snapshot_msg::frame(&manifest_json, &sealed);
    backend.put_snapshot(bucket, &snapshot_id, framed).await?;
    // Record it as held so future passes advertise it and stop advertising the
    // entries it subsumes.
    store
        .lock()
        .await
        .record_held_snapshot(&snapshot_id, &manifest.subsumed_entry_ids)?;
    if debug {
        eprintln!(
            "[be-sync]   uploaded snapshot {snapshot_id} subsuming {} entries, {} blob refs",
            manifest.subsumed_entry_ids.len(),
            manifest.blob_ref_ids.len(),
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

    #[tokio::test]
    async fn consumer_fetches_verifies_and_adopts_a_snapshot() {
        std::env::set_var("ROAM_SNAPSHOT_LAG_DAYS", "0");
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
        // Mutual roster so B can verify A's snapshot author signature.
        a.lock().await.add_peer(b_peer, b_key, Role::Admin).unwrap();
        b.lock().await.add_peer(a_peer, a_key, Role::Admin).unwrap();

        a.lock().await.set_entry("files", "k", "hello").unwrap();
        reconcile_once(&a, &backend, &key).await.unwrap();

        // Backend asks -> A uploads a snapshot on the next pass.
        backend.set_snapshot_wanted(&key.bucket_id(), true);
        reconcile_once(&a, &backend, &key).await.unwrap();
        assert_eq!(
            backend
                .list_snapshots(&key.bucket_id())
                .await
                .unwrap()
                .len(),
            1
        );

        // B is fresh: one pass bootstraps it to head via the snapshot alone.
        reconcile_once(&b, &backend, &key).await.unwrap();
        assert_eq!(
            b.lock().await.get_entry("files", "k"),
            Some("hello".to_string())
        );
        // B recorded the snapshot as held (so it will advertise it + stop
        // advertising the entries it subsumes next pass).
        assert_eq!(b.lock().await.held_snapshots().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_non_admin_authored_snapshot_is_never_adopted() {
        // Admin-only authorship is enforced RECEIVER-side: producer gating is
        // voluntary, so a peer must reject a validly-signed snapshot whose author
        // is not an Admin in the receiver's roster. Otherwise a Reader/Writer
        // could inject content via the additive `doc.import` in `adopt_snapshot`,
        // bypassing the per-op Reader-content-drop rule.
        std::env::set_var("ROAM_SNAPSHOT_LAG_DAYS", "0");
        let key = VaultKey([9u8; 32]);
        let backend = Arc::new(MemoryBackend::default());
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = store_at(a_dir.path()).await; // Admin in its OWN roster -> can produce
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
        // B sees A as a WRITER, not an Admin.
        b.lock()
            .await
            .add_peer(a_peer, a_key, Role::Writer)
            .unwrap();

        a.lock().await.set_entry("files", "k", "hello").unwrap();
        reconcile_once(&a, &backend, &key).await.unwrap();
        backend.set_snapshot_wanted(&key.bucket_id(), true);
        reconcile_once(&a, &backend, &key).await.unwrap();
        assert_eq!(
            backend
                .list_snapshots(&key.bucket_id())
                .await
                .unwrap()
                .len(),
            1,
            "A (Admin in its own roster) uploaded a validly-signed snapshot"
        );

        // Clear the request so B (also an Admin in its OWN roster) does not
        // self-produce a snapshot on its pass — we want to test only whether B
        // adopts A's Writer-authored one.
        backend.set_snapshot_wanted(&key.bucket_id(), false);

        // B runs a pass: it must NOT adopt the Writer-authored snapshot, and must
        // not record it as held. (It still learns "k" via ordinary op-replay,
        // which is correctly role-gated elsewhere — assert only the snapshot path.)
        reconcile_once(&b, &backend, &key).await.unwrap();
        assert_eq!(
            b.lock().await.held_snapshots().unwrap().len(),
            0,
            "a non-Admin-authored snapshot must never be adopted/held"
        );
    }

    #[tokio::test]
    async fn subsumed_ops_are_never_re_pulled_after_adoption() {
        // The seed §2a regression: a client holding a snapshot must NOT re-fetch
        // the ops that snapshot subsumes, on this or any later pass.
        std::env::set_var("ROAM_SNAPSHOT_LAG_DAYS", "0");
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

        for i in 0..3 {
            a.lock()
                .await
                .set_entry("files", "k", &format!("v{i}"))
                .unwrap();
        }
        reconcile_once(&a, &backend, &key).await.unwrap();
        backend.set_snapshot_wanted(&key.bucket_id(), true);
        reconcile_once(&a, &backend, &key).await.unwrap();

        // Read the uploaded snapshot's manifest to learn which entry ids it subsumes.
        let sid = backend.list_snapshots(&key.bucket_id()).await.unwrap()[0].clone();
        let framed = backend
            .get_snapshot(&key.bucket_id(), &sid)
            .await
            .unwrap()
            .unwrap();
        let (mjson, _) = crate::snapshot_msg::unframe(&framed).unwrap();
        let manifest: crate::snapshot_msg::SnapshotManifest =
            serde_json::from_slice(mjson).unwrap();
        assert!(!manifest.subsumed_entry_ids.is_empty());

        // B bootstraps from the snapshot, then runs several more passes.
        for _ in 0..3 {
            reconcile_once(&b, &backend, &key).await.unwrap();
        }
        assert_eq!(
            b.lock().await.get_entry("files", "k"),
            Some("v2".to_string())
        );
        for id in &manifest.subsumed_entry_ids {
            assert_eq!(
                backend.entry_get_count(id),
                0,
                "subsumed op {id} must never be fetched once the snapshot is held"
            );
        }
    }

    #[tokio::test]
    async fn admin_produces_and_uploads_snapshot_when_backend_asks() {
        // lag 0 => snapshot at the head marker, so the test needs no time travel.
        std::env::set_var("ROAM_SNAPSHOT_LAG_DAYS", "0");
        let key = VaultKey([9u8; 32]);
        let backend = Arc::new(MemoryBackend::default());
        let dir = tempfile::tempdir().unwrap();
        let s = store_at(dir.path()).await; // Admin founder
        s.lock().await.set_entry("files", "k", "v").unwrap();

        // No request pending: a normal pass uploads no snapshot.
        reconcile_once(&s, &backend, &key).await.unwrap();
        assert!(backend
            .list_snapshots(&key.bucket_id())
            .await
            .unwrap()
            .is_empty());

        // Backend asks -> an Admin produces and uploads exactly one.
        backend.set_snapshot_wanted(&key.bucket_id(), true);
        reconcile_once(&s, &backend, &key).await.unwrap();
        let ids = backend.list_snapshots(&key.bucket_id()).await.unwrap();
        assert_eq!(ids.len(), 1, "one snapshot uploaded on request");

        // The uploaded object unframes into a verifiable manifest + sealed body.
        let framed = backend
            .get_snapshot(&key.bucket_id(), &ids[0])
            .await
            .unwrap()
            .unwrap();
        let (manifest_json, sealed) = crate::snapshot_msg::unframe(&framed).unwrap();
        let manifest: crate::snapshot_msg::SnapshotManifest =
            serde_json::from_slice(manifest_json).unwrap();
        let author_vk = {
            let g = s.lock().await;
            roam_storage::VerifyingKey::from_bytes(&g.identity_verifying_bytes()).unwrap()
        };
        assert!(manifest.verify(&author_vk), "manifest signature verifies");
        assert_eq!(
            <[u8; 32]>::from(blake3::hash(sealed)),
            manifest.snapshot_ct_hash,
            "manifest binds the sealed ciphertext"
        );
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
