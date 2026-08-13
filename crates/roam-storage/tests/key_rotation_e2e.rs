//! Regression scenarios for key-rotation foundation (spec §8). Drives Stores
//! directly through the export/import key-log + roster APIs (no transport).

use roam_storage::Identity;
use roam_storage::Role;
use roam_storage::Store;
use roam_storage::EPOCH0_ID;
use tempfile::tempdir;

const ID_KEY: [u8; 32] = [0x1au8; 32];
const EPOCH0: [u8; 32] = [0x2bu8; 32];

/// Cross-vouch A<->B and sync both roster + key-logs both directions.
fn full_sync(a: &mut Store, ia: &Identity, b: &mut Store, ib: &Identity) {
    a.import_roster(
        ib.peer_id(),
        &ib.verifying_key(),
        b.export_own_roster().unwrap(),
    )
    .ok();
    b.import_roster(
        ia.peer_id(),
        &ia.verifying_key(),
        a.export_own_roster().unwrap(),
    )
    .ok();
    a.import_keylog(
        ib.peer_id(),
        &ib.verifying_key(),
        b.export_own_keylog().unwrap(),
    )
    .ok();
    b.import_keylog(
        ia.peer_id(),
        &ia.verifying_key(),
        a.export_own_keylog().unwrap(),
    )
    .ok();
}

#[test]
fn scenario1_rotate_then_disconnect_then_peer_catches_up() {
    let da = tempdir().unwrap();
    let db = tempdir().unwrap();
    let ia = Identity::generate();
    let ib = Identity::generate();
    let mut a = Store::open(da.path(), ia.clone()).unwrap();
    let mut b = Store::open(db.path(), ib.clone()).unwrap();

    // Each device is the founder-admin of its own vault so its `add_peer`
    // vouches (and, post-sync, the peer's grants) actually fold into the roster.
    a.declare_founder(Role::Admin).unwrap();
    b.declare_founder(Role::Admin).unwrap();
    a.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    b.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    let epoch = a.rotate_epoch(&ID_KEY, &EPOCH0, None).unwrap();

    full_sync(&mut a, &ia, &mut b, &ib);
    let kc_b = b.keychain(&ID_KEY, &EPOCH0).unwrap();
    assert!(
        kc_b.epoch_key(&epoch).is_some(),
        "B caught up to the rotated epoch via key-log"
    );
}

#[test]
fn scenario3_concurrent_rotations_form_siblings_and_a_deterministic_head() {
    let da = tempdir().unwrap();
    let db = tempdir().unwrap();
    let ia = Identity::generate();
    let ib = Identity::generate();
    let mut a = Store::open(da.path(), ia.clone()).unwrap();
    let mut b = Store::open(db.path(), ib.clone()).unwrap();
    // Each device is the founder-admin of its own vault so its `add_peer`
    // vouches (and, post-sync, the peer's grants) actually fold into the roster.
    a.declare_founder(Role::Admin).unwrap();
    b.declare_founder(Role::Admin).unwrap();
    a.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    b.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    full_sync(&mut a, &ia, &mut b, &ib);

    let ea = a.rotate_epoch(&ID_KEY, &EPOCH0, None).unwrap();
    let eb = b.rotate_epoch(&ID_KEY, &EPOCH0, None).unwrap();
    assert_ne!(ea, eb, "independent rotations mint sibling epochs");

    full_sync(&mut a, &ia, &mut b, &ib);
    let kc_a = a.keychain(&ID_KEY, &EPOCH0).unwrap();
    let kc_b = b.keychain(&ID_KEY, &EPOCH0).unwrap();
    assert_eq!(kc_a.head, kc_b.head, "deterministic head converges");
    assert_eq!(kc_a.head, ea.min(eb), "head is the lowest sibling epoch id");
}

#[test]
fn forward_secrecy_a_revoked_peer_cannot_open_the_new_epoch() {
    let da = tempdir().unwrap();
    let db = tempdir().unwrap();
    let ia = Identity::generate();
    let ib = Identity::generate();
    let mut a = Store::open(da.path(), ia.clone()).unwrap();
    let mut b = Store::open(db.path(), ib.clone()).unwrap();
    // Each device is the founder-admin of its own vault so its `add_peer`
    // vouches (and, post-sync, the peer's grants) actually fold into the roster.
    a.declare_founder(Role::Admin).unwrap();
    b.declare_founder(Role::Admin).unwrap();
    a.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    b.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    full_sync(&mut a, &ia, &mut b, &ib);

    a.revoke_peer(ib.peer_id(), ib.verifying_key().to_bytes())
        .unwrap();
    let epoch = a.rotate_epoch(&ID_KEY, &EPOCH0, None).unwrap();

    b.import_keylog(
        ia.peer_id(),
        &ia.verifying_key(),
        a.export_own_keylog().unwrap(),
    )
    .unwrap();
    let kc_b = b.keychain(&ID_KEY, &EPOCH0).unwrap();
    assert!(
        kc_b.epoch_key(&epoch).is_none(),
        "revoked peer cannot open the post-revocation epoch"
    );
    assert!(a
        .keychain(&ID_KEY, &EPOCH0)
        .unwrap()
        .epoch_key(&epoch)
        .is_some());
}

#[test]
fn a_non_admins_rotate_is_not_folded_into_the_keychain() {
    // N5: epoch rotation is Admin-only. A Reader/Writer can author a Rotate+Wrap
    // in its own key-log, but when a peer imports that log the fold MUST ignore it
    // because the author's roster role is not Admin — otherwise a non-admin
    // installs epoch keys / steers the write head (KC1's reachability).
    let da = tempdir().unwrap();
    let db = tempdir().unwrap();
    let ia = Identity::generate();
    let ib = Identity::generate();
    let mut a = Store::open(da.path(), ia.clone()).unwrap();
    let mut b = Store::open(db.path(), ib.clone()).unwrap();

    a.declare_founder(Role::Admin).unwrap();
    b.declare_founder(Role::Admin).unwrap();
    // A vouches for B as a READER (B is only ever a reader in A's roster).
    a.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Reader)
        .unwrap();

    // B (founder-admin of ITS OWN vault) mints an epoch in its own key-log.
    let epoch = b.rotate_epoch(&ID_KEY, &EPOCH0, None).unwrap();

    // A imports only B's key-log (B stays a Reader in A's view).
    a.import_keylog(
        ib.peer_id(),
        &ib.verifying_key(),
        b.export_own_keylog().unwrap(),
    )
    .unwrap();

    let kc_a = a.keychain(&ID_KEY, &EPOCH0).unwrap();
    assert!(
        !kc_a.epochs.contains_key(&epoch),
        "a Reader-authored epoch must not fold into the keychain"
    );
    assert!(
        kc_a.epoch_key(&epoch).is_none(),
        "a Reader-authored epoch key must never be installed"
    );
}

#[test]
fn a_revoked_admin_can_no_longer_author_admin_ops() {
    // N1: `require_admin` must also require Active status. Role and status are
    // independent fields; a device revoked by another admin still materializes
    // role==Admin, and must NOT keep signing roster/keylog ops locally.
    let da = tempdir().unwrap();
    let db = tempdir().unwrap();
    let ia = Identity::generate();
    let ib = Identity::generate();
    let mut a = Store::open(da.path(), ia.clone()).unwrap();
    let mut b = Store::open(db.path(), ib.clone()).unwrap();

    a.declare_founder(Role::Admin).unwrap();
    b.declare_founder(Role::Admin).unwrap();
    a.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    b.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    full_sync(&mut a, &ia, &mut b, &ib);

    // B revokes A; A folds B's revocation into its own view.
    b.revoke_peer(ia.peer_id(), ia.verifying_key().to_bytes())
        .unwrap();
    a.import_roster(
        ib.peer_id(),
        &ib.verifying_key(),
        b.export_own_roster().unwrap(),
    )
    .unwrap();

    // A is now revoked. It must not be able to author further admin ops.
    let c = Identity::generate();
    assert!(
        a.add_peer(c.peer_id(), c.verifying_key().to_bytes(), Role::Reader)
            .is_err(),
        "a revoked admin must not author roster ops"
    );
    assert!(
        a.rotate_epoch(&ID_KEY, &EPOCH0, None).is_err(),
        "a revoked admin must not author epoch rotations"
    );
}

#[test]
fn backcompat_a_vault_with_no_keylog_is_epoch0_only() {
    let dir = tempdir().unwrap();
    let store = Store::open(dir.path(), Identity::generate()).unwrap();
    let kc = store.keychain(&ID_KEY, &EPOCH0).unwrap();
    assert_eq!(kc.head, EPOCH0_ID);
    assert_eq!(kc.epochs.len(), 1, "only the genesis epoch exists");
    assert!(
        store.vault_state(&ID_KEY, &EPOCH0).unwrap().is_empty(),
        "Synced"
    );
}

#[test]
fn paper_recovery_reconstructs_a_rotated_epoch_key() {
    use roam_storage::PaperKey;
    let dir = tempdir().unwrap();
    let id = Identity::generate();
    let mut store = Store::open(dir.path(), id.clone()).unwrap();
    store.declare_founder(Role::Admin).unwrap();

    let paper = PaperKey::from_passphrase("twelve word printed recovery phrase");
    let epoch = store
        .rotate_epoch(&ID_KEY, &EPOCH0, Some(paper.public()))
        .unwrap();

    let kc = store.keychain(&ID_KEY, &EPOCH0).unwrap();
    let epoch_key = kc.epoch_key(&epoch).unwrap();

    let bytes = store.export_own_keylog().unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let paper_blob = find_paper_blob(&text, &epoch);
    let recovered = PaperKey::from_passphrase("twelve word printed recovery phrase");
    let unwrapped = roam_storage::unwrap(&recovered.secret(), &paper_blob).unwrap();
    assert_eq!(
        *unwrapped,
        *epoch_key.expose(),
        "paper passphrase recovers the epoch key"
    );
}

/// Pull the base64 `blob` of the `Recipient::Paper` Wrap for `epoch` out of a
/// key-log's JSONL (test helper — avoids exposing internals from the crate).
fn find_paper_blob(jsonl: &str, epoch: &[u8; 32]) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let want = B64.encode(epoch);
    for line in jsonl.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        if v["epoch_id"] == want {
            if let Some(w) = v["body"].get("Wrap") {
                if w["recipient"] == "Paper" {
                    return B64.decode(w["blob"].as_str().unwrap()).unwrap();
                }
            }
        }
    }
    panic!("no paper wrap for epoch");
}
