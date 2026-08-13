//! FULL feature end-to-end against the REAL zero-knowledge Phoenix backend.
//!
//! This is the acceptance sweep for the encrypted-backend data path. It boots the
//! actual `mix phx.server` (the same server that ships) and drives multiple real
//! `Store`s through `reconcile_once` over live HTTP — no in-memory doubles. Every
//! feature is proven by the mechanism that actually carries it in production:
//!
//!   F1  key/value entry convergence      A writes, B + D read it back
//!   F2  text-CRDT concurrent merge        A and B edit the same note, both merge
//!   F3  binary blob transfer              A's blob bytes reach B, content-addressed
//!   F4  Admin snapshot bootstrap          a fresh device adopts A's backend snapshot
//!   F5  rotate + revocation confidentiality
//!                                         after A revokes B and rotates, an ACTIVE
//!                                         reader still reads new writes but the
//!                                         REVOKED device cannot — while old data
//!                                         it already had stays readable.
//!
//! What this test deliberately does NOT re-cover: live P2P transfer over iroh and
//! receiver-side role-drop enforcement — those are proven by the iroh-loopback
//! e2e tests (`roam-cli/tests/{folder_sync_e2e,roles_e2e}.rs`) and the transport
//! e2e. Trust bootstrap here is the documented **bundle** path (roster + key-log
//! copied out of band), exactly as `roles_e2e.rs` does, because `reconcile_once`
//! carries entries/blobs/snapshots but not roster/key-log gossip (that is iroh's
//! job); the pairing handshake itself has its own tests.
//!
//! Marked `#[ignore]`: it needs `mix` on PATH and boots the full Phoenix app
//! (first boot compiles it). Run with:
//!   cargo test -p roam-backend-client --test full_feature_e2e -- --ignored --nocapture

use std::process::{Child, Command};
use std::sync::Arc;

use roam_backend_client::crypto::VaultKey;
use roam_backend_client::http::HttpBackend;
use roam_backend_client::sync::{produce_held_snapshot, reconcile_once};
use roam_backend_client::transport::Backend;
use roam_storage::{Identity, PaperKey, Role, Store, VerifyingKey};
use tokio::sync::Mutex;

/// Port distinct from `e2e_backend.rs` (4577). All feature sections (F1–F6) run
/// inside ONE test against ONE server, so only one port is needed — booting a
/// second `mix phx.server` concurrently races on the shared `_build`.
const PORT_FEATURES: u16 = 4578;

struct Server {
    child: Child,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Boot the real Phoenix backend against a throwaway data root on `port` and wait
/// until it answers. (Async reqwest, not the blocking client — the blocking
/// client spins its own runtime and panics inside `#[tokio::test]`; see
/// e2e_backend.rs.)
async fn start_server(root: &std::path::Path, port: u16) -> Server {
    let child = Command::new("mix")
        .arg("phx.server")
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../sync"))
        .env("PORT", port.to_string())
        .env("ROAM_BACKEND_DATA", root)
        .env("MIX_ENV", "dev")
        .env("PHX_SERVER", "true")
        .spawn()
        .expect("start sync phx server (is mix on PATH?)");
    let client = reqwest::Client::new();
    for _ in 0..600 {
        if client
            .get(format!("http://127.0.0.1:{port}/b/probe/manifest"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Server { child }
}

// --- test-local helpers ---------------------------------------------------

type SharedStore = Arc<Mutex<Store>>;

async fn open_store(dir: &std::path::Path) -> SharedStore {
    Arc::new(Mutex::new(Store::open(dir, Identity::generate()).unwrap()))
}

async fn peer_and_key(store: &SharedStore) -> (u64, [u8; 32]) {
    let g = store.lock().await;
    (g.peer_id(), g.identity_verifying_bytes())
}

/// Bundle-bootstrap a joiner's trust in the founder: pin the founder and import
/// its full roster, then import the founder's key-log so the joiner can unwrap
/// epoch keys. This is what live iroh pairing delivers; here we copy it out of
/// band because `reconcile_once` intentionally does not gossip roster/key-log.
async fn bootstrap_joiner(
    joiner: &SharedStore,
    founder_peer: u64,
    founder_vkey: &VerifyingKey,
    roster_bundle: &[(u64, Vec<u8>)],
    founder_keylog: &[u8],
) {
    let mut g = joiner.lock().await;
    g.pin_founder(founder_peer).unwrap();
    g.import_roster_bundle(roster_bundle.to_vec()).unwrap();
    g.import_keylog(founder_peer, founder_vkey, founder_keylog.to_vec())
        .unwrap();
}

/// One reconcile pass per store, in order. Convergence for already-present ops is
/// a single set-based RBSR round each way; call this a couple of times so a value
/// one store uploaded this round is available for the next to pull.
async fn sync_round<B: roam_backend_client::transport::Backend>(
    stores: &[&SharedStore],
    backend: &Arc<B>,
    key: &VaultKey,
) {
    for st in stores {
        reconcile_once(st, backend, key).await.unwrap();
    }
}

async fn get_entry(store: &SharedStore, map: &str, k: &str) -> Option<String> {
    store.lock().await.get_entry(map, k)
}

#[tokio::test]
#[ignore = "requires mix on PATH and the sync Phoenix backend; run with --ignored"]
async fn all_backend_features_end_to_end() {
    let data_root = tempfile::tempdir().unwrap();
    let _server = start_server(data_root.path(), PORT_FEATURES).await;
    let base = format!("http://127.0.0.1:{PORT_FEATURES}");
    let backend = Arc::new(HttpBackend::new(&base));
    // One shared vault key; every device of this vault holds it (delivered over
    // pairing in production). Bucket/entry/blob ids all derive from it.
    let key = VaultKey([7u8; 32]);

    // --- devices --------------------------------------------------------
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let d_dir = tempfile::tempdir().unwrap();
    let a = open_store(a_dir.path()).await; // Admin founder
    let b = open_store(b_dir.path()).await; // Writer
    let d = open_store(d_dir.path()).await; // Reader

    let (a_peer, a_key) = peer_and_key(&a).await;
    let (b_peer, b_key) = peer_and_key(&b).await;
    let (d_peer, d_key) = peer_and_key(&d).await;
    let a_vkey = VerifyingKey::from_bytes(&a_key).unwrap();

    // --- trust bootstrap ------------------------------------------------
    // A founds the vault and enrolls B (Writer) and D (Reader).
    {
        let mut ga = a.lock().await;
        ga.declare_founder(Role::Admin).unwrap();
        ga.add_peer(b_peer, b_key, Role::Writer).unwrap();
        ga.add_peer(d_peer, d_key, Role::Reader).unwrap();
    }
    let roster_bundle = a.lock().await.export_all_rosters().unwrap();
    let a_keylog = a.lock().await.export_own_keylog().unwrap();
    bootstrap_joiner(&b, a_peer, &a_vkey, &roster_bundle, &a_keylog).await;
    bootstrap_joiner(&d, a_peer, &a_vkey, &roster_bundle, &a_keylog).await;

    // Sanity: roles folded on the joiners' side.
    assert_eq!(
        b.lock().await.role_of(b_peer),
        Some(Role::Writer),
        "B is Writer"
    );
    assert_eq!(
        d.lock().await.role_of(d_peer),
        Some(Role::Reader),
        "D is Reader"
    );

    // === F1: key/value entry convergence ================================
    a.lock().await.set_entry("kv", "greeting", "hello").unwrap();
    // A uploads; B and D pull. Two rounds: A publishes, then B/D fetch.
    sync_round(&[&a, &b, &d], &backend, &key).await;
    sync_round(&[&a, &b, &d], &backend, &key).await;
    assert_eq!(
        get_entry(&b, "kv", "greeting").await,
        Some("hello".to_string()),
        "F1: Writer B must read A's entry through the backend"
    );
    assert_eq!(
        get_entry(&d, "kv", "greeting").await,
        Some("hello".to_string()),
        "F1: Reader D must read A's entry through the backend"
    );

    // === F2: text-CRDT concurrent merge =================================
    // A and B edit the SAME text container concurrently (neither has seen the
    // other's edit yet). Loro must merge both inserts losslessly.
    a.lock().await.edit_text("note", 0, "alpha ").unwrap();
    b.lock().await.edit_text("note", 0, "beta ").unwrap();
    // Three rounds to exchange both directions and re-converge.
    for _ in 0..3 {
        sync_round(&[&a, &b, &d], &backend, &key).await;
    }
    let a_note = a.lock().await.text("note");
    let b_note = b.lock().await.text("note");
    assert_eq!(
        a_note, b_note,
        "F2: A and B must converge to identical text"
    );
    assert!(
        a_note.contains("alpha") && a_note.contains("beta"),
        "F2: merged note must keep BOTH concurrent inserts, got {a_note:?}"
    );

    // === F3: binary blob transfer =======================================
    // A stores raw (non-UTF-8) bytes; content-addressed by blake3. reconcile
    // ships the encrypted bytes; B re-derives the same hash and stores them.
    let payload: Vec<u8> = vec![0x00, 0xFF, 0x10, 0x42, 0x00, 0x99, 0xAB];
    let hash = a.lock().await.blobs().put(&payload).unwrap();
    sync_round(&[&a, &b], &backend, &key).await;
    sync_round(&[&a, &b], &backend, &key).await;
    assert_eq!(
        b.lock().await.blobs().get(&hash).unwrap(),
        Some(payload.clone()),
        "F3: B must reassemble A's blob bytes byte-for-byte through the backend"
    );

    // === F4: Admin snapshot bootstrap ===================================
    // A (Admin) records a history marker and produces a backend snapshot at the
    // current frontier, then uploads it. A brand-new device E — which never saw
    // any op — adopts that snapshot from the backend and holds the state.
    a.lock().await.write_snapshot().unwrap(); // append a history marker
    let produced = {
        let ga = a.lock().await;
        produce_held_snapshot(&ga, &key, i64::MAX).unwrap()
    };
    let (snapshot_id, framed) = produced.expect("F4: Admin must produce a snapshot");
    // Publish the framed snapshot object directly. (A device only auto-uploads a
    // snapshot when the backend advertises `snapshot_wanted`; a direct
    // `put_snapshot` makes it visible to every peer's Snapshots-set RBSR reconcile,
    // which is exactly the bootstrap path a fresh device needs.) Also push A's
    // latest ops so the backend holds a complete picture.
    sync_round(&[&a], &backend, &key).await;
    backend
        .put_snapshot(&key.bucket_id(), &snapshot_id, framed)
        .await
        .unwrap();

    let e_dir = tempfile::tempdir().unwrap();
    let e = open_store(e_dir.path()).await;
    // A fresh device trusts A the same way B/D did (roster + key-log bundle).
    bootstrap_joiner(&e, a_peer, &a_vkey, &roster_bundle, &a_keylog).await;
    // E reconciles: import_needed_snapshots fetches + verifies + adopts A's
    // snapshot, then any remaining ops fill in.
    for _ in 0..3 {
        sync_round(&[&e], &backend, &key).await;
    }
    let e_held = e.lock().await.held_snapshots().unwrap();
    assert!(
        e_held.iter().any(|h| h.id == snapshot_id),
        "F4: fresh device E must have ADOPTED A's backend snapshot {snapshot_id}, held={:?}",
        e_held.iter().map(|h| &h.id).collect::<Vec<_>>()
    );
    assert_eq!(
        get_entry(&e, "kv", "greeting").await,
        Some("hello".to_string()),
        "F4: E must hold the vault state carried by the adopted snapshot"
    );

    // === F5: rotate + revocation confidentiality ========================
    // A revokes the Writer B, rotates the payload key (new epoch wrapped to the
    // remaining ACTIVE members — A and the Reader D — but NOT to revoked B), then
    // writes a NEW secret under the new epoch.
    a.lock().await.revoke_peer(b_peer, b_key).unwrap();
    let new_epoch = a
        .lock()
        .await
        .rotate_epoch(&key.id_key(), &key.epoch0_key(), None)
        .unwrap();
    assert_ne!(
        new_epoch,
        roam_storage::EPOCH0_ID,
        "F5: rotation must mint a non-zero epoch"
    );
    a.lock()
        .await
        .set_entry("kv", "secret", "top-secret")
        .unwrap();

    // Publish A's post-rotation key-log to BOTH remaining devices — even to the
    // revoked B. This is the STRONGEST form of the confidentiality claim: B is
    // handed everything A published, yet the Rotate carries no wrap addressed to
    // B, so B still cannot derive the new epoch key.
    let a_keylog_rotated = a.lock().await.export_own_keylog().unwrap();
    d.lock()
        .await
        .import_keylog(a_peer, &a_vkey, a_keylog_rotated.clone())
        .unwrap();
    b.lock()
        .await
        .import_keylog(a_peer, &a_vkey, a_keylog_rotated)
        .unwrap();

    for _ in 0..3 {
        sync_round(&[&a, &d, &b], &backend, &key).await;
    }

    // The ACTIVE reader D holds the new epoch key → reads the new secret.
    assert_eq!(
        get_entry(&d, "kv", "secret").await,
        Some("top-secret".to_string()),
        "F5: active reader D must read the post-rotation secret"
    );
    // The REVOKED device B was excluded from the new epoch's wraps → the new
    // secret is Undecryptable to it, so it never lands.
    assert_eq!(
        get_entry(&b, "kv", "secret").await,
        None,
        "F5: revoked B must NOT be able to read anything written after the rotation"
    );
    // ...but data B legitimately received BEFORE the rotation stays readable
    // (rotation is forward-secrecy for NEW writes, not retroactive erasure).
    assert_eq!(
        get_entry(&b, "kv", "greeting").await,
        Some("hello".to_string()),
        "F5: revoked B keeps the pre-rotation data it already held"
    );

    // === F6: paper-recovery restore (data-level, through the backend) ====
    // A device that joined AFTER a rotation (never a wrap recipient) cannot
    // decrypt post-rotation data — until it re-enters the paper phrase. This is
    // the consume side of `rotate --generate-paper`: without
    // `Store::recover_with_paper` the printed phrase would be inert. A fresh vault
    // key gives F6 its own backend bucket, isolated from F1–F5 above (and it runs
    // in this SAME test so only one Phoenix server ever boots).
    let key6 = VaultKey([9u8; 32]);
    let a6_dir = tempfile::tempdir().unwrap();
    let a6 = open_store(a6_dir.path()).await;
    let (a6_peer, a6_key) = peer_and_key(&a6).await;
    let a6_vkey = VerifyingKey::from_bytes(&a6_key).unwrap();
    a6.lock().await.declare_founder(Role::Admin).unwrap();

    // A6 rotates, sealing the new epoch to a generated PAPER key, then writes a
    // secret UNDER the new epoch and pushes it to the backend.
    let (paper, phrase) = PaperKey::generate();
    a6.lock()
        .await
        .rotate_epoch(&key6.id_key(), &key6.epoch0_key(), Some(paper.public()))
        .unwrap();
    a6.lock()
        .await
        .set_entry("kv", "vault-secret", "moonlight")
        .unwrap();
    sync_round(&[&a6], &backend, &key6).await;
    sync_round(&[&a6], &backend, &key6).await;

    // Device R6 joins AFTER the rotation: A6 enrolls it and R6 bundle-bootstraps
    // trust (incl. A6's key-log, which carries the paper wrap + A6's own device
    // wraps, but NO wrap addressed to R6).
    let r6_dir = tempfile::tempdir().unwrap();
    let r6 = open_store(r6_dir.path()).await;
    let (r6_peer, r6_key) = peer_and_key(&r6).await;
    a6.lock()
        .await
        .add_peer(r6_peer, r6_key, Role::Reader)
        .unwrap();
    let roster6 = a6.lock().await.export_all_rosters().unwrap();
    let a6_keylog = a6.lock().await.export_own_keylog().unwrap();
    bootstrap_joiner(&r6, a6_peer, &a6_vkey, &roster6, &a6_keylog).await;

    for _ in 0..3 {
        sync_round(&[&r6], &backend, &key6).await;
    }
    // Before recovery: R6 holds the ciphertext but no epoch key → Undecryptable.
    assert_eq!(
        get_entry(&r6, "kv", "vault-secret").await,
        None,
        "F6: R must NOT read the post-rotation secret before paper recovery"
    );

    // Recover using ONLY the paper phrase.
    let recovered = r6
        .lock()
        .await
        .recover_with_paper(&phrase, &key6.id_key(), &key6.epoch0_key())
        .unwrap();
    assert!(
        recovered >= 1,
        "F6: paper recovery must restore at least one epoch key"
    );

    // Re-reconcile: the now-decryptable entry is re-fetched and applied.
    for _ in 0..3 {
        sync_round(&[&r6], &backend, &key6).await;
    }
    assert_eq!(
        get_entry(&r6, "kv", "vault-secret").await,
        Some("moonlight".to_string()),
        "F6: after paper recovery R reads the post-rotation secret"
    );
}
