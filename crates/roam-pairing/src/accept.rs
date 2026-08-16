//! What a host hands a proven joiner, and the exact order the joiner applies it.
//!
//! This used to live in `roam-transport-iroh::pairing`, copied by value into
//! `pairing_lan`, and would have been copied a third time for the mailbox flow.
//! Three copies of a sequence whose *order* is the security property is three
//! chances to get the order wrong, so it lives here once and the transports
//! call it.
//!
//! The order is not incidental:
//!
//! 1. **Pin the founder first.** The roster fold seeds `ever_admin` from the
//!    founder pin. Import a roster before pinning and a Reader or Writer joiner
//!    materialises no role at all and is inert — it holds a vault it cannot act
//!    in, with nothing to say why.
//! 2. **Then the transitive roster**, which carries the founder's self-`Add`
//!    (the anchor), the host's own log, and the `Add{role}` the host just
//!    authored for the joiner. Each author's log is verified against the
//!    roster-vouched key during the fold.
//! 3. **Then the key log**, which needs the roster to already name its author.
//!
//! And on the host's side, `add_peer` must precede `backfill_wraps`: wraps are
//! addressed to roster members, so wrapping before enrolling wraps to nobody and
//! the joiner starts in `WaitingKey` with no way out but a later rotation.

use anyhow::{Context, Result};
use roam_storage::{vault_subkeys, Identity, Role, Store, VaultId, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Host → joiner: accepted; here is everything needed to be a member.
///
/// The `vault_key` (the backend decryption secret) is wiped on drop; every other
/// field is public roster/key-log material and skipped.
#[derive(Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
pub struct JoinAccept {
    /// The vault being joined. A flow that named the vault out of band (the
    /// token flow does; a six-digit code cannot) must re-check this against what
    /// it was told.
    #[zeroize(skip)]
    pub vault: [u8; 32],
    /// The shared vault key. Sent only here, only after the joiner has proved
    /// it, and only over an encrypted channel.
    pub vault_key: [u8; 32],
    /// Every roster log the host holds, keyed by author peer id — including the
    /// founder chain the host itself received when it joined, so a joiner behind
    /// a non-founder admin folds the whole founder→host→joiner chain.
    #[zeroize(skip)]
    pub rosters: Vec<(u64, Vec<u8>)>,
    /// The host's signed key log, so the joiner learns the epoch DAG and any
    /// wraps addressed to it. Empty for an un-rotated vault.
    #[zeroize(skip)]
    pub keylog_author: u64,
    #[zeroize(skip)]
    pub keylog_jsonl: Vec<u8>,
    /// The pinned vault founder's `peer_id` — the anchor the joiner's roster
    /// fold needs. Delivered only over a proven channel, never out of band.
    #[zeroize(skip)]
    pub founder: u64,
}

/// Redacting, and hand-written for that reason: this struct holds the vault key,
/// and a derived `Debug` would put it in the first log line, panic message or
/// `expect_err` that touched it.
impl std::fmt::Debug for JoinAccept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinAccept")
            .field("vault", &"<redacted>")
            .field("vault_key", &"<redacted>")
            .field("rosters", &self.rosters.len())
            .field("keylog_author", &self.keylog_author)
            .field("keylog_bytes", &self.keylog_jsonl.len())
            .field("founder", &self.founder)
            .finish()
    }
}

/// Enrol a joiner in the host's store and build the accept to hand back.
///
/// **Mutates the host's store**: the joiner is added to the roster with `role`
/// and every epoch the host can open is wrapped to it. Call this only once the
/// joiner has proved whatever the flow requires — a signature over a token
/// secret, or a PAKE confirmation. There is no proof checked here, by design:
/// the transports authenticate differently and each must do it before calling.
pub fn enrol_joiner(
    store: &mut Store,
    identity: &Identity,
    vault: VaultId,
    vault_key: &[u8; 32],
    role: Role,
    joiner_key: [u8; 32],
    joiner_peer_id: u64,
) -> Result<JoinAccept> {
    // A host that is not founded has no anchor to give, and a joiner without an
    // anchor folds no role. Fail here rather than shipping a bogus 0.
    let founder = store
        .founder_pin()
        .context("host is not founded — cannot deliver a founder pin to the joiner")?;

    store
        .add_peer(joiner_peer_id, joiner_key, role)
        .context("add paired peer to roster")?;
    // After `add_peer`, never before: a wrap is addressed to a roster member.
    // No-op for an un-rotated vault, where only epoch 0 exists and it is never
    // wrapped.
    let (id_key, epoch0) = vault_subkeys(vault_key);
    store
        .backfill_wraps(&id_key, &epoch0)
        .context("wrap epochs to the new joiner")?;

    Ok(JoinAccept {
        vault: vault.0,
        vault_key: *vault_key,
        rosters: store
            .export_all_rosters()
            .context("export transitive roster")?,
        keylog_author: identity.peer_id(),
        keylog_jsonl: store.export_own_keylog().context("export own keylog")?,
        founder,
    })
}

/// What a joiner walks away with once an accept has been applied.
///
/// A struct rather than a tuple because the caller persists most of it
/// (`<vault>/vault-id`, `<vault>/vault-key`) and a triple of two 32-byte blobs
/// and a `u64` is exactly the shape that gets silently mis-ordered.
pub struct Joined {
    /// The vault just joined, as the host named it.
    pub vault: VaultId,
    /// The shared backend decryption secret, wiped when this drops.
    pub vault_key: zeroize::Zeroizing<[u8; 32]>,
    /// The pinned founder's peer id — already written to the store.
    pub founder: u64,
}

/// Apply a host's accept to the joiner's store, in the one order that works.
///
/// `host_key` authenticates the key log. Every flow must obtain it in a way the
/// flow itself makes trustworthy — the token flow binds it to the dialled
/// endpoint id, the LAN flow *is* the dialled endpoint id, and the mailbox flow
/// binds it into the SPAKE2 transcript so a substituted key fails as a wrong
/// code. Passing a key this function cannot check is deliberate: there is no
/// check available here that would mean anything.
///
/// Consumes the accept, so its `vault_key` cannot be read again after the
/// [`Joined`] has taken its own wiped copy.
pub fn adopt_accept(
    store: &mut Store,
    mut accept: JoinAccept,
    host_key: &VerifyingKey,
) -> Result<Joined> {
    store
        .pin_founder(accept.founder)
        .context("pin founder delivered by host")?;
    // `JoinAccept` wipes its `vault_key` on drop, so its fields cannot be moved
    // out by value — take the owned Vecs and leave empties the Drop runs over.
    store
        .import_roster_bundle(std::mem::take(&mut accept.rosters))
        .context("import host transitive roster")?;
    if !accept.keylog_jsonl.is_empty() {
        store
            .import_keylog(
                accept.keylog_author,
                host_key,
                std::mem::take(&mut accept.keylog_jsonl),
            )
            .context("import host keylog")?;
    }

    Ok(Joined {
        vault: VaultId(accept.vault),
        vault_key: zeroize::Zeroizing::new(accept.vault_key),
        founder: accept.founder,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use roam_storage::PeerStatus;
    use tempfile::tempdir;

    /// A founded admin host and a would-be joiner, with nothing between them.
    fn host_and_joiner() -> (
        Store,
        Identity,
        Store,
        Identity,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let (host_dir, joiner_dir) = (tempdir().unwrap(), tempdir().unwrap());
        let (host_identity, joiner_identity) = (Identity::generate(), Identity::generate());
        let mut host = Store::open(host_dir.path(), host_identity.clone()).unwrap();
        host.declare_founder(Role::Admin).unwrap();
        let joiner = Store::open(joiner_dir.path(), joiner_identity.clone()).unwrap();
        (
            host,
            host_identity,
            joiner,
            joiner_identity,
            host_dir,
            joiner_dir,
        )
    }

    #[test]
    fn a_joiner_that_adopts_an_accept_holds_the_role_the_host_granted() {
        let (mut host, host_identity, mut joiner, joiner_identity, _hd, _jd) = host_and_joiner();
        let vault = VaultId::generate();
        let vault_key = [42u8; 32];

        let accept = enrol_joiner(
            &mut host,
            &host_identity,
            vault,
            &vault_key,
            Role::Reader,
            joiner_identity.verifying_key().to_bytes(),
            joiner_identity.peer_id(),
        )
        .expect("enrol");

        let joined = adopt_accept(&mut joiner, accept, &host_identity.verifying_key())
            .expect("adopt the accept");

        assert_eq!(joined.vault, vault);
        assert_eq!(*joined.vault_key, vault_key);
        assert_eq!(joined.founder, host_identity.peer_id());
        assert_eq!(joiner.self_role(), Some(Role::Reader));
        assert_eq!(joiner.founder_pin(), Some(host_identity.peer_id()));
        assert!(
            host.roster()
                .iter()
                .any(|p| p.peer_id == joiner_identity.peer_id() && p.status == PeerStatus::Active),
            "the host must trust the joiner it enrolled"
        );
    }

    /// The founder pin has to be written before the roster is folded, and the
    /// failure mode if it is not is silence rather than an error: a Reader folds
    /// no role and is simply inert. So assert the role, which is the thing the
    /// ordering actually buys.
    #[test]
    fn a_reader_joiner_is_not_left_roleless() {
        let (mut host, host_identity, mut joiner, joiner_identity, _hd, _jd) = host_and_joiner();
        let accept = enrol_joiner(
            &mut host,
            &host_identity,
            VaultId::generate(),
            &[7u8; 32],
            Role::Reader,
            joiner_identity.verifying_key().to_bytes(),
            joiner_identity.peer_id(),
        )
        .unwrap();
        adopt_accept(&mut joiner, accept, &host_identity.verifying_key()).unwrap();

        assert_eq!(
            joiner.self_role(),
            Some(Role::Reader),
            "a Reader that folded no role would hold a vault it cannot act in"
        );
    }

    /// A host that never founded a vault has no anchor to hand over. It must say
    /// so rather than enrol the joiner and deliver a founder of 0 — which folds
    /// to no role and looks, from the joiner's side, exactly like a bug.
    #[test]
    fn an_unfounded_host_refuses_to_enrol_rather_than_deliver_a_bogus_anchor() {
        let dir = tempdir().unwrap();
        let identity = Identity::generate();
        let mut unfounded = Store::open(dir.path(), identity.clone()).unwrap();
        let joiner_identity = Identity::generate();

        let err = enrol_joiner(
            &mut unfounded,
            &identity,
            VaultId::generate(),
            &[1u8; 32],
            Role::Admin,
            joiner_identity.verifying_key().to_bytes(),
            joiner_identity.peer_id(),
        )
        .expect_err("an unfounded host cannot enrol");
        assert!(err.to_string().contains("not founded"), "unhelpful: {err}");

        assert!(
            !unfounded
                .roster()
                .iter()
                .any(|p| p.peer_id == joiner_identity.peer_id()),
            "a refused enrolment must not leave the joiner in the roster"
        );
    }

    /// The key log is authenticated against the key the flow says the host has.
    /// Hand over the wrong one and the import must fail rather than fold
    /// unverified epoch material into the joiner's keychain.
    #[test]
    fn a_keylog_under_the_wrong_host_key_is_refused() {
        let (mut host, host_identity, mut joiner, joiner_identity, _hd, _jd) = host_and_joiner();
        let vault_key = [42u8; 32];
        let (id_key, epoch0) = vault_subkeys(&vault_key);
        // Rotate so there is a key log to authenticate at all; an un-rotated
        // vault has an empty one and this test would pass vacuously.
        host.rotate_epoch(&id_key, &epoch0, None).unwrap();

        let accept = enrol_joiner(
            &mut host,
            &host_identity,
            VaultId::generate(),
            &vault_key,
            Role::Admin,
            joiner_identity.verifying_key().to_bytes(),
            joiner_identity.peer_id(),
        )
        .unwrap();
        assert!(
            !accept.keylog_jsonl.is_empty(),
            "the host must actually have a key log, or this proves nothing"
        );

        let impostor = Identity::generate();
        assert!(
            adopt_accept(&mut joiner, accept, &impostor.verifying_key()).is_err(),
            "a key log must not import under a key that did not sign it"
        );
    }

    #[test]
    fn the_vault_key_is_wiped_when_the_accept_drops() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<JoinAccept>();
    }
}
