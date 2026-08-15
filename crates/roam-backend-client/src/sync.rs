use crate::crypto::VaultKey;
use crate::entries::{local_blobs, local_entries};
use crate::transport::Backend;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use futures::stream::{self, StreamExt};
use roam_rbsr::{initiate, reconcile, ItemSet, SetKind};
use roam_storage::{Keychain, PeerStatus, Role, Store, VerifyingKey, EPOCH0_ID};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
// Not `SystemTime::now()`: it traps on wasm32. One shared shim, so the browser
// build cannot silently reacquire the bug.
use roam_storage::wallclock::now_ms;
use tokio::sync::Mutex;

/// Client-side round cap: bounds a pathological/hostile server that never
/// converges. The 2s reconcile loop is self-healing, so aborting a pass is safe.
const RBSR_ROUND_CAP: usize = 32;

/// How many entry GETs may be in flight at once during a pull.
///
/// Chosen for the case that hurts — a device pairing for the first time, which
/// needs every entry in the vault and is therefore entirely latency-bound. Eight
/// is high enough to hide typical mobile round trips and low enough not to look
/// like a flood to the relay or to a phone's connection pool; `reqwest` keeps at
/// most this many connections busy per host either way.
const ENTRY_FETCH_CONCURRENCY: usize = 8;

/// Open a stored ciphertext via the keychain's read rule. Returns:
/// - `Ok(Some(plaintext))` — opened,
/// - `Ok(None)` — `Undecryptable` (epoch key missing, or an unknown-epoch blob
///   whose epoch-0 fallback failed the AEAD tag check). NEVER aborts the pass.
fn open_classified(kc: &Keychain, payload: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    let plan = kc.classify(payload);
    let Some(key) = plan.key else { return Ok(None) };
    match crate::crypto::open_epoch(key.expose(), &payload[plan.body_offset..]) {
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
pub(crate) async fn reconcile_set<B: Backend>(
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

    // Trust BEFORE content. Roster and key logs decide who may author an entry
    // and which epoch keys we can open, so exchanging them first means a peer
    // vouched for during this pass has its ops accepted during this pass — and
    // that an epoch minted elsewhere is readable before we try to read under it.
    crate::trust::reconcile_trust(store, backend, key, &bucket, debug).await?;

    // Rebuild the keychain each pass — the trust exchange above, or a P2P
    // key-log gossip, may have delivered a new epoch since the last tick. Writes
    // seal under the head epoch; reads classify against the epochs known now.
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
            // H1: skip uploading if the head rotated past epoch 0 and we don't yet
            // hold its key — an epoch-0 write would be readable by revoked members.
            let Some(ct) = seal_under_head(&kc, key, line) else {
                continue;
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
            // H1: same guard as entries — don't seal under epoch 0 mid-rotation.
            let Some(ct) = seal_under_head(&kc, key, &bytes) else {
                continue;
            };
            backend.put_blob(&bucket, id, ct).await?;
        }
    }

    // Ids a prior pass proved poisoned (content didn't bind to the id). BE1: the
    // backend can't overwrite a squatted id, so never re-fetch it — the correct
    // content arrives peer-to-peer, verified there independently.
    let poisoned = {
        let guard = store.lock().await;
        guard.poisoned_ids()?
    };

    // Fetch blobs we lack, decrypt, store.
    for id in need_blob_ids.difference(&poisoned) {
        if let Some(ct) = backend.get_blob(&bucket, id).await? {
            let opened = open_classified(&kc, &ct)?;
            // The ciphertext is dead the moment it is opened, and holding both
            // buffers doubles the peak for the largest thing this pass touches.
            // Dropping it here is not tidiness — on a phone it is the
            // difference between one blob's worth of memory and two.
            drop(ct);
            match opened {
                Some(plaintext) => {
                    // BE1: a content-addressed blob id MUST re-derive from its
                    // decrypted bytes. A mismatch means the id was squatted with
                    // the wrong content — reject it, don't store garbage.
                    let content_hash = blake3::hash(&plaintext).to_hex().to_string();
                    if key.blob_id(&content_hash) != *id {
                        let guard = store.lock().await;
                        guard.mark_poisoned(id)?;
                        eprintln!("[be-sync] rejected poisoned blob id (content mismatch): {id}");
                        continue;
                    }
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
            key,
            &poisoned,
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
    maybe_produce_snapshot(store, backend, key, &bucket, debug).await?;

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

    // Verifying keys we trust to author a snapshot: ADMIN + Active roster peers
    // (plus self iff this device is an Admin). The whole verify+adopt gate — the
    // receiver-side Admin enforcement that stops a non-Admin author from injecting
    // state via the additive `doc.import` — lives in the shared bootstrap module,
    // so the backend HTTP loop and the P2P Engine run one identical copy.
    let author_keys = {
        let guard = store.lock().await;
        roam_storage::snapshot_bootstrap::admin_author_keys(&guard)
    };

    for id in &need {
        let Some(framed) = backend.get_snapshot(bucket, id).await? else {
            continue;
        };
        let outcome = {
            let mut guard = store.lock().await;
            roam_storage::snapshot_bootstrap::verify_and_adopt_snapshot(
                &mut guard,
                kc,
                &author_keys,
                id,
                &framed,
            )?
        };
        match outcome {
            roam_storage::snapshot_bootstrap::AdoptOutcome::Adopted { subsumed, .. } => {
                if debug {
                    eprintln!(
                        "[be-sync]   adopted snapshot {id} subsuming {} entries",
                        subsumed.len()
                    );
                }
            }
            roam_storage::snapshot_bootstrap::AdoptOutcome::Undecryptable => {
                report.undecryptable += 1;
            }
            roam_storage::snapshot_bootstrap::AdoptOutcome::Rejected(why) => {
                eprintln!("backend sync: snapshot {id} rejected: {why}");
            }
        }
    }
    Ok(())
}

/// Seal `plaintext` under the head epoch. Returns `None` when the vault has
/// rotated past epoch 0 but this device hasn't received the head epoch key yet:
/// sealing under epoch 0 then would be readable by rotated-out members (H1). The
/// caller skips the write; it self-heals once the key-log delivers the epoch.
fn seal_under_head(kc: &Keychain, key: &VaultKey, plaintext: &[u8]) -> Option<Vec<u8>> {
    match kc.head_write_key() {
        Some((epoch_id, epoch_key)) if epoch_id != EPOCH0_ID => Some(crate::crypto::seal_epoch(
            epoch_key.expose(),
            &epoch_id,
            plaintext,
        )),
        // Head key held and head is epoch 0 -> legacy seal is the correct write.
        Some(_) => Some(key.seal(plaintext)),
        // No head key. Only safe if the vault never rotated (head is epoch 0);
        // otherwise block rather than leak an epoch-0 write to revoked members.
        None if kc.head() == EPOCH0_ID => Some(key.seal(plaintext)),
        None => None,
    }
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
    debug: bool,
) -> anyhow::Result<()> {
    if !backend.manifest(bucket).await?.snapshot_wanted {
        return Ok(());
    }
    if store.lock().await.self_role() != Some(Role::Admin) {
        return Ok(());
    }

    // Pin a head marker so there is always a frontier to snapshot, then produce.
    // before_ts is computed AFTER write_snapshot so the fresh marker isn't missed
    // on the ms boundary (default lag leaves a replayable tail; lag 0 => head).
    // produce_held_snapshot persists the framed object locally + records it held;
    // we additionally upload it to the backend here.
    let produced = {
        let guard = store.lock().await;
        guard.write_snapshot()?;
        let before_ts = now_ms().saturating_sub(retention_lag_ms());
        produce_held_snapshot(&guard, key, before_ts)?
    };
    let Some((snapshot_id, framed)) = produced else {
        if debug {
            eprintln!("[be-sync]   snapshot_wanted but no qualifying marker yet");
        }
        return Ok(());
    };

    backend.put_snapshot(bucket, &snapshot_id, framed).await?;
    if debug {
        eprintln!("[be-sync]   uploaded snapshot {snapshot_id}");
    }
    Ok(())
}

/// Build a shallow snapshot at `before_ts`, seal + sign it, PERSIST the framed
/// object locally (so this device can P2P-serve it via `offer_snapshots`), and
/// record it held. Does NOT upload to any backend — the caller uploads the
/// returned `framed` bytes if a backend is present. Returns `(snapshot_id,
/// framed)`, or `None` when self is not Admin (only Admins may author a
/// snapshot) or no history marker qualifies at `before_ts`.
///
/// Callers that also truncate (checkpoint) MUST call this FIRST, with the SAME
/// `before_ts`: `build_backend_snapshot` reads the pre-truncation op-logs to
/// derive `subsumed_lines`, and the shared `before_ts` makes the produced
/// snapshot cover exactly the frontier the checkpoint compacts to.
pub fn produce_held_snapshot(
    store: &Store,
    key: &VaultKey,
    before_ts: i64,
) -> anyhow::Result<Option<(String, Vec<u8>)>> {
    if store.self_role() != Some(Role::Admin) {
        return Ok(None);
    }
    let kc = store.keychain(&key.id_key(), &key.epoch0_key())?;
    let Some(snap) = store.build_backend_snapshot(before_ts)? else {
        return Ok(None);
    };

    // H1: never seal a snapshot under epoch 0 while a rotation is in effect but
    // this device lacks the head key — that would hand full plaintext to a
    // rotated-out member. Skip; another Admin (or this one, once the key lands)
    // produces it next pass.
    let Some(sealed) = seal_under_head(&kc, key, &snap.bytes) else {
        return Ok(None);
    };
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
    .signed(store.identity());

    let manifest_json = serde_json::to_vec(&manifest)?;
    let framed = crate::snapshot_msg::frame(&manifest_json, &sealed);

    store.persist_snapshot_object(&snapshot_id, &framed)?;
    store.record_held_snapshot(&snapshot_id, &manifest.subsumed_entry_ids)?;

    Ok(Some((snapshot_id, framed)))
}

/// Fetch every content-addressed entry id in `need_entry_ids` directly from the
/// backend (RBSR's discovery is set-based, not sequential, so there is no
/// per-peer index to walk anymore), decrypt, attribute it to its author via the
/// line's own `peer` field, and append it into that author's op-log through
/// [`Store::dedup_append_peer_line`] — which re-imports the whole log each
/// time, so Loro buffers any op whose dependency hasn't landed yet and
/// converges once it does, regardless of fetch order.
#[allow(clippy::too_many_arguments)]
async fn import_needed_entries<B: Backend>(
    store: &Arc<Mutex<Store>>,
    backend: &Arc<B>,
    bucket: &str,
    need_entry_ids: &BTreeSet<String>,
    self_peer: u64,
    debug: bool,
    kc: &Keychain,
    key: &VaultKey,
    poisoned: &std::collections::BTreeSet<String>,
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

    // Fetch with a bounded number of requests in flight, then import in the
    // order RBSR named them.
    //
    // These GETs used to be sequential — one await per entry — which made a
    // first sync cost one full round trip per op. On a device pairing for the
    // first time that is the whole history: 240 entries took 140s against a
    // relay on the same machine, and every one of those seconds was latency,
    // not work. `buffered` preserves input order, so what changes is only how
    // many requests are outstanding; the import below still runs one at a time,
    // in the same sequence, under the same lock.
    //
    // Bounded rather than unbounded: `need_entry_ids` is attacker-influenced in
    // the sense that any peer can author ops, and turning that set directly
    // into concurrent sockets would be a self-inflicted flood on a phone's
    // network stack. Entries are small (one op-log line), so the buffered
    // bodies are bounded by roughly ENTRY_FETCH_CONCURRENCY × line size.
    // Each future owns its id, bucket and backend handle rather than borrowing
    // them. Borrowing compiles for the host build and then fails the Android
    // one with "implementation of `FnOnce` is not general enough" — the
    // higher-ranked lifetime on `Backend::get_entry` cannot be proven for a
    // future the buffer holds across polls. Cloning an `Arc` and two short
    // strings per entry is nothing next to the round trip it replaces.
    let wanted: Vec<String> = need_entry_ids
        .iter()
        // A prior pass proved these ids squatted; the real op flows P2P.
        .filter(|id| !poisoned.contains(*id))
        .cloned()
        .collect();

    let fetched: Vec<(String, anyhow::Result<Option<Vec<u8>>>)> = stream::iter(wanted)
        .map(|id| {
            let backend = Arc::clone(backend);
            let bucket = bucket.to_string();
            async move {
                let out = backend.get_entry(&bucket, &id).await;
                (id, out)
            }
        })
        .buffered(ENTRY_FETCH_CONCURRENCY)
        .collect()
        .await;

    let mut imported = 0usize;
    // Verified lines, grouped by the author they attribute to, in fetch order.
    let mut by_author: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();
    for (id, result) in fetched {
        let Some(ct) = result? else {
            continue;
        };
        let id = &id;
        let Some(line) = open_classified(kc, &ct)? else {
            // Missing this epoch's key; self-heals when the key-log delivers it.
            report.undecryptable += 1;
            continue;
        };
        let Some(author) = parse_entry_author(&line) else {
            continue; // malformed line; nothing sane to attribute it to
        };
        // BE1: a content-addressed entry id MUST re-derive from (author, line).
        // A mismatch means the id was squatted with a line that binds elsewhere —
        // reject it so a validly-signed but mis-addressed op can't censor the real
        // one. The genuinely-addressed line still arrives under its own id.
        if key.entry_id_content(author, &line) != *id {
            let guard = store.lock().await;
            guard.mark_poisoned(id)?;
            eprintln!("[be-sync] rejected poisoned entry id (content mismatch): {id}");
            continue;
        }
        if !peers.contains_key(&author) {
            continue; // unknown/untrusted author -> drop
        }
        by_author.entry(author).or_default().push(line);
    }

    // One import per author rather than one per line. Appending line by line
    // re-read, re-verified and re-imported that peer's ENTIRE log for every
    // line, so a first sync cost O(n²) signature checks — the dominant cost of
    // pairing a device, well ahead of the network.
    for (author, lines) in by_author {
        let Some(vkey) = peers.get(&author) else {
            continue;
        };
        let mut guard = store.lock().await;
        match guard.dedup_append_peer_lines(author, vkey, &lines) {
            Ok(added) => imported += added,
            Err(err) => {
                // `import_peer` verifies the whole candidate log and rejects it
                // entire, so one bad line in the batch would otherwise discard
                // every good line beside it. Fall back to line-at-a-time, which
                // is the slow path precisely because it re-verifies each time —
                // and that is what isolates the offender.
                eprintln!(
                    "backend sync: batch import peer={author} failed ({err}); \
                     retrying line by line"
                );
                for line in &lines {
                    if let Err(err) = guard.dedup_append_peer_line(author, vkey, line) {
                        eprintln!(
                            "backend sync: dedup_append_peer_line peer={author} failed: {err}"
                        );
                    } else {
                        imported += 1;
                    }
                }
            }
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

    /// Wraps a backend and records how many `get_entry` calls overlap.
    ///
    /// Every other method delegates untouched — the only thing under
    /// observation is the shape of the entry pull.
    struct CountsConcurrentGets<B> {
        inner: Arc<B>,
        in_flight: std::sync::atomic::AtomicUsize,
        peak: std::sync::atomic::AtomicUsize,
    }

    impl<B> CountsConcurrentGets<B> {
        fn wrapping(inner: Arc<B>) -> Self {
            Self {
                inner,
                in_flight: std::sync::atomic::AtomicUsize::new(0),
                peak: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn peak_concurrency(&self) -> usize {
            self.peak.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl<B: Backend + Send + Sync> Backend for CountsConcurrentGets<B> {
        async fn get_entry(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
            use std::sync::atomic::Ordering::SeqCst;
            let now = self.in_flight.fetch_add(1, SeqCst) + 1;
            self.peak.fetch_max(now, SeqCst);
            // Yield so the executor can poll the other buffered futures. Without
            // a suspension point every call would run to completion inside one
            // poll and the peak would read 1 even when the fetch *is* buffered —
            // a real request suspends on the socket for far longer than this.
            tokio::task::yield_now().await;
            let out = self.inner.get_entry(bucket, id).await;
            self.in_flight.fetch_sub(1, SeqCst);
            out
        }

        async fn manifest(&self, bucket: &str) -> anyhow::Result<crate::transport::Manifest> {
            self.inner.manifest(bucket).await
        }
        async fn put_entry(
            &self,
            bucket: &str,
            id: &str,
            ct: Vec<u8>,
        ) -> anyhow::Result<crate::transport::PutOutcome> {
            self.inner.put_entry(bucket, id, ct).await
        }
        async fn get_blob(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
            self.inner.get_blob(bucket, id).await
        }
        async fn put_blob(
            &self,
            bucket: &str,
            id: &str,
            ct: Vec<u8>,
        ) -> anyhow::Result<crate::transport::PutOutcome> {
            self.inner.put_blob(bucket, id, ct).await
        }
        async fn get_snapshot(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
            self.inner.get_snapshot(bucket, id).await
        }
        async fn put_snapshot(
            &self,
            bucket: &str,
            id: &str,
            ct: Vec<u8>,
        ) -> anyhow::Result<crate::transport::PutOutcome> {
            self.inner.put_snapshot(bucket, id, ct).await
        }
        async fn list_snapshots(&self, bucket: &str) -> anyhow::Result<Vec<String>> {
            self.inner.list_snapshots(bucket).await
        }
        async fn get_trust(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
            self.inner.get_trust(bucket, id).await
        }
        async fn put_trust(
            &self,
            bucket: &str,
            id: &str,
            ct: Vec<u8>,
        ) -> anyhow::Result<crate::transport::PutOutcome> {
            self.inner.put_trust(bucket, id, ct).await
        }
        async fn reconcile(
            &self,
            bucket: &str,
            kind: SetKind,
            msg: Vec<u8>,
        ) -> anyhow::Result<Vec<u8>> {
            self.inner.reconcile(bucket, kind, msg).await
        }
    }

    async fn store_at(dir: &std::path::Path) -> Arc<Mutex<Store>> {
        let mut store = Store::open(dir, Identity::generate()).unwrap();
        // Found this vault as admin so local writes + `add_peer` vouches are allowed.
        store.declare_founder(Role::Admin).unwrap();
        Arc::new(Mutex::new(store))
    }

    /// A first sync is entirely latency-bound: the joining device needs every
    /// entry in the vault, and fetching them one await at a time cost one round
    /// trip per op — 140 seconds for 240 entries against a relay on the same
    /// machine, measured on an emulator. Nothing about the result changes if the
    /// GETs overlap, so nothing but this test notices if they stop overlapping.
    #[tokio::test]
    async fn a_joining_device_fetches_entries_concurrently() {
        let key = VaultKey([11u8; 32]);
        let memory = Arc::new(MemoryBackend::default());
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

        // Comfortably more entries than ENTRY_FETCH_CONCURRENCY, so the buffer
        // is the limit rather than the supply.
        for i in 0..40 {
            a.lock()
                .await
                .set_entry("files", &format!("k{i}"), "v")
                .unwrap();
        }
        reconcile_once(&a, &memory, &key).await.unwrap();

        let counting = Arc::new(CountsConcurrentGets::wrapping(memory));
        reconcile_once(&b, &counting, &key).await.unwrap();

        assert_eq!(
            b.lock().await.get_entry("files", "k39"),
            Some("v".to_string()),
            "setup: the pull has to actually deliver the entries",
        );
        assert!(
            counting.peak_concurrency() > 1,
            "entry GETs ran one at a time (peak in flight: {}), which is one \
             round trip per op on a first sync",
            counting.peak_concurrency(),
        );
    }

    /// Scratch probe: how does a first sync scale with entry count when the
    /// backend has no latency at all? Run with `--ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn probe_pull_cost_by_entry_count() {
        for count in [50usize, 100, 200, 400] {
            let key = VaultKey([7u8; 32]);
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
            for i in 0..count {
                a.lock()
                    .await
                    .set_entry("files", &format!("k{i}"), "some value here")
                    .unwrap();
            }
            reconcile_once(&a, &backend, &key).await.unwrap();
            let started = std::time::Instant::now();
            reconcile_once(&b, &backend, &key).await.unwrap();
            println!(
                "PROBE entries={count} pull={}ms",
                started.elapsed().as_millis()
            );
        }
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
    async fn a_produced_bootstrap_snapshot_lets_a_fresh_peer_converge() {
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
        // Mutual roster so B can verify A's snapshot-author signature.
        a.lock().await.add_peer(b_peer, b_key, Role::Admin).unwrap();
        b.lock().await.add_peer(a_peer, a_key, Role::Admin).unwrap();

        // A writes, records a marker, then produces a bootstrap snapshot the way the
        // checkpoint path does — directly, no backend snapshot_wanted, no manual seed.
        {
            let mut g = a.lock().await;
            g.set_entry("files", "note", "hello").unwrap();
            g.write_snapshot().unwrap();
        }
        let (id, framed) = {
            let g = a.lock().await;
            produce_held_snapshot(&g, &key, i64::MAX).unwrap().unwrap()
        };

        // Deliver the produced object to B via the backend object store, then B's
        // normal reconcile fetches, verifies (Admin sig + ct-hash), and adopts it.
        // No `set_snapshot_wanted` here: unlike `consumer_fetches_verifies_and_adopts_a_snapshot`,
        // this snapshot's discovery does not depend on the backend requesting one —
        // `put_snapshot` alone makes it visible to B's SetKind::Snapshots RBSR reconcile.
        let bucket = key.bucket_id();
        backend.put_snapshot(&bucket, &id, framed).await.unwrap();
        reconcile_once(&b, &backend, &key).await.unwrap();

        assert_eq!(
            b.lock().await.get_entry("files", "note"),
            Some("hello".to_string())
        );
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

    /// BE1: the backend is first-writer-wins with no id↔content check, so any
    /// member (or a future compromised backend) can pre-seed a blob id with a
    /// ciphertext that decrypts to the WRONG bytes. The client must re-derive the
    /// id from the decrypted content and refuse a mismatch — never store garbage
    /// under a content-addressed id.
    #[tokio::test]
    async fn a_poisoned_blob_is_rejected_and_not_stored() {
        let key = VaultKey([9u8; 32]);
        let backend = Arc::new(MemoryBackend::default());
        let dir = tempfile::tempdir().unwrap();
        let b = store_at(dir.path()).await;

        // The id CLAIMS to hold the bytes "real blob bytes", but the ciphertext
        // stored under it decrypts to attacker-chosen garbage.
        let real_hash = blake3::hash(b"real blob bytes").to_hex().to_string();
        let poison_id = key.blob_id(&real_hash);
        let poison_ct = key.seal(b"attacker garbage");
        backend
            .put_blob(&key.bucket_id(), &poison_id, poison_ct)
            .await
            .unwrap();

        reconcile_once(&b, &backend, &key).await.unwrap();

        assert!(
            b.lock().await.blobs().list().unwrap().is_empty(),
            "a blob whose content does not hash to its id must be rejected"
        );
        assert!(
            b.lock().await.poisoned_ids().unwrap().contains(&poison_id),
            "the forged id must be marked poisoned so we stop re-fetching it"
        );
    }

    /// BE1 (entries): an attacker squats a victim's content-addressed entry id
    /// with a validly-signed line whose content binds to a DIFFERENT id. Without
    /// the id↔content check the client would treat that slot as satisfied and the
    /// real op could be censored. The re-derivation must reject the squatter while
    /// leaving the genuinely-addressed op untouched.
    #[tokio::test]
    async fn a_squatted_entry_id_is_rejected_and_marked_poisoned() {
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

        // A publishes a real op under its true, content-addressed id.
        a.lock().await.set_entry("files", "note", "hi").unwrap();
        reconcile_once(&a, &backend, &key).await.unwrap();

        // Attacker copies A's valid line and re-uploads it under a DIFFERENT id
        // (one that would address different content) — id↔content now disagrees.
        let bucket = key.bucket_id();
        let true_id = backend.manifest(&bucket).await.unwrap().entry_ids[0].clone();
        let ct = backend.get_entry(&bucket, &true_id).await.unwrap().unwrap();
        let wrong_id = key.entry_id_content(a_peer, b"unrelated content");
        backend.put_entry(&bucket, &wrong_id, ct).await.unwrap();

        reconcile_once(&b, &backend, &key).await.unwrap();

        // The genuinely-addressed op imports fine.
        assert_eq!(
            b.lock().await.get_entry("files", "note"),
            Some("hi".to_string())
        );
        // The squatter is rejected + marked poisoned.
        assert!(
            b.lock().await.poisoned_ids().unwrap().contains(&wrong_id),
            "a line whose content does not bind to its id must be rejected"
        );

        // Second pass must NOT re-fetch the poisoned id (no churn).
        let before = backend.entry_get_count(&wrong_id);
        reconcile_once(&b, &backend, &key).await.unwrap();
        assert_eq!(
            backend.entry_get_count(&wrong_id),
            before,
            "a poisoned id must never be fetched again"
        );
    }

    #[tokio::test]
    async fn produce_held_snapshot_persists_and_records_when_admin() {
        std::env::set_var("ROAM_SNAPSHOT_LAG_DAYS", "0");
        let key = VaultKey([9u8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let s = store_at(dir.path()).await; // founder Admin
        {
            let mut g = s.lock().await;
            g.set_entry("files", "note", "hello").unwrap();
            g.write_snapshot().unwrap(); // record a history marker to snapshot at
        }
        let out = {
            let g = s.lock().await;
            produce_held_snapshot(&g, &key, i64::MAX).unwrap()
        };
        let (id, framed) = out.expect("admin with history produces a snapshot");
        assert!(!framed.is_empty());
        let held = s.lock().await.held_snapshot_ids().unwrap();
        assert!(
            held.contains(&id),
            "produced snapshot must be locally held/advertisable"
        );
    }

    #[tokio::test]
    async fn produce_held_snapshot_is_none_without_history() {
        let key = VaultKey([9u8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let s = store_at(dir.path()).await;
        let g = s.lock().await;
        assert!(produce_held_snapshot(&g, &key, i64::MAX).unwrap().is_none());
    }

    #[tokio::test]
    async fn produce_held_snapshot_is_none_for_non_admin() {
        let key = VaultKey([9u8; 32]);
        let dir = tempfile::tempdir().unwrap();
        // No declare_founder => self has no Admin role.
        let store = Store::open(dir.path(), Identity::generate()).unwrap();
        assert!(produce_held_snapshot(&store, &key, i64::MAX)
            .unwrap()
            .is_none());
    }

    /// H1: after a rotation, a device that has seen the `Rotate` but not yet
    /// received the new epoch key (its `Wrap`) must NOT seal fresh writes under
    /// epoch 0 — a rotated-out member still holds the epoch-0 key and would read
    /// them. The write is blocked (skipped) until the key-log delivers the epoch.
    #[test]
    fn h1_write_is_blocked_when_head_rotated_but_key_missing() {
        use roam_storage::{compute_epoch_id, KeyBody, KeyLogEntry, Keychain, EPOCH0_ID};
        let vault = VaultKey([9u8; 32]);

        // No rotation: the head is epoch 0, so the legacy seal is correct.
        let kc0 = Keychain::build(*vault.id_key(), *vault.epoch0_key(), 1, &[0u8; 32], &[]);
        assert_eq!(kc0.head(), EPOCH0_ID);
        assert!(
            seal_under_head(&kc0, &vault, b"x").is_some(),
            "an un-rotated vault writes under epoch 0"
        );

        // A Rotate announces a new epoch (parent epoch 0) but no Wrap delivers its
        // key to us — the head advances to it while we hold no key for it.
        let nonce = [7u8; 32];
        // No Wrap delivers this epoch's key to us, so the committed key is never
        // learned here — a placeholder key is fine for the head-advance assertion.
        let epoch = compute_epoch_id(&[EPOCH0_ID], 1, &nonce, &[0u8; 32]);
        let rotate = KeyLogEntry {
            seq: 0,
            author: 1,
            epoch_id: epoch,
            body: KeyBody::Rotate {
                parent_epochs: vec![EPOCH0_ID],
                nonce,
            },
        };
        let kc = Keychain::build(
            *vault.id_key(),
            *vault.epoch0_key(),
            1,
            &[0u8; 32],
            &[rotate],
        );
        assert_eq!(kc.head(), epoch, "head advances to the rotated epoch");
        assert!(kc.head_write_key().is_none(), "we hold no key for the head");
        assert!(
            seal_under_head(&kc, &vault, b"secret").is_none(),
            "H1: must not fall back to an epoch-0 write a revoked member can read"
        );
    }

    #[test]
    fn undecryptable_report_counts_items_whose_epoch_key_is_missing() {
        use roam_storage::{Keychain, EPOCH0_ID};
        let vault = VaultKey([9u8; 32]);
        let kc = Keychain::build(*vault.id_key(), *vault.epoch0_key(), 1, &[0u8; 32], &[]);

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
