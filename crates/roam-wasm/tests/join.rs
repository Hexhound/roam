//! A browser device joining somebody else's vault.
//!
//! The handshake itself is roam-pairing's, and tested there. What is new here —
//! and what these cover — is the browser-shaped wiring around it:
//!
//! * the joiner must NOT found. `Vault::open` declares a founder when none is
//!   pinned, which is right for the device that creates a vault and catastrophic
//!   for one that joins: it would pin itself as founder of a vault it did not
//!   create, and the host's roster could never fold over it.
//! * the accept has to be fetched *before* any store exists, because the OPFS
//!   pool is named after the bucket id and the bucket id comes from the vault
//!   key the accept carries.
//!
//! Both run on `MemFs` rather than in a browser. That is deliberate and it is
//! the right seam: OPFS and `MemFs` are the same `VaultFs`, the browser harness
//! already proves the OPFS implementation of it, and none of the logic below is
//! browser-specific. What genuinely cannot be checked here is only the mount.

use std::sync::Arc;
use std::time::Duration;

use roam_pairing::handshake::fetch_accept_via_mailbox;
use roam_pairing::{host_via_mailbox, Invite, MemoryMailbox};
use roam_storage::vfs::{MemFs, VaultFs};
use roam_storage::{Identity, PeerStatus, Role, Store, VaultId};
use roam_wasm::Vault;

const VAULT_KEY: [u8; 32] = [42u8; 32];

/// Host and joiner, paired over an in-process mailbox. Returns the host's store
/// (to inspect its roster), the joiner's vault, and the host's identity.
async fn pair() -> (Store, Vault, Identity, Identity) {
    let host_identity = Identity::generate();
    let joiner_identity = Identity::generate();

    let host_fs: Arc<dyn VaultFs> = Arc::new(MemFs::new());
    let mut host_store = Store::open_with_fs(
        std::path::Path::new("/vault"),
        host_identity.clone(),
        host_fs,
    )
    .expect("open host store");
    host_store.declare_founder(Role::Admin).expect("found");

    let invite = Invite::generate(
        "https://relay.example",
        host_identity.verifying_key().to_bytes(),
    );
    let mailbox = MemoryMailbox::new();

    let (code, host) = host_via_mailbox(
        &host_identity,
        VaultId::generate(),
        VAULT_KEY,
        Role::Writer,
        &mut host_store,
        mailbox.clone(),
        invite.clone(),
    );
    let host = host.with_timeouts(Duration::from_secs(5), Duration::from_millis(5));

    let joiner_identity_for_task = joiner_identity.clone();
    let (host_result, joined) = tokio::join!(host.accept_for(Duration::from_secs(10)), async {
        let (accept, host_key) =
            fetch_accept_via_mailbox(&joiner_identity_for_task, &mailbox, &invite, &code)
                .await
                .expect("fetch the accept");
        // Exactly the browser's order: the handshake finishes, and only then is
        // there anywhere to put a store.
        Vault::join(
            Arc::new(MemFs::new()),
            joiner_identity_for_task,
            accept,
            &host_key,
        )
        .expect("join")
    });
    host_result.expect("host accepts");

    (host_store, joined, host_identity, joiner_identity)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_joined_vault_holds_the_role_the_host_granted() {
    let (host_store, joined, host_identity, joiner_identity) = pair().await;

    assert_eq!(
        joined.vault_key(),
        VAULT_KEY,
        "the joiner must come away with the shared key — without it the bucket \
         id is wrong and it addresses a vault nobody else uses"
    );
    assert_eq!(joined.self_role().await, Some(Role::Writer));
    assert!(
        host_store
            .roster()
            .iter()
            .any(|p| p.peer_id == joiner_identity.peer_id() && p.status == PeerStatus::Active),
        "the host must trust the browser device it enrolled"
    );
    assert_eq!(
        joined.founder_pin().await,
        Some(host_identity.peer_id()),
        "the joiner must anchor on the host's founder, not on itself"
    );
}

/// The bug `Vault::open` would cause if a joiner used it.
///
/// A joiner that founded would pin ITSELF as the founder, and its roster fold
/// would anchor on an identity the host has never heard of — leaving a device
/// that believes it is an Admin of a vault nobody else recognises. That failure
/// is silent: no error, just two vaults that never converge.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_anchors_on_the_hosts_founder_and_never_on_itself() {
    let (_host_store, joined, host_identity, joiner_identity) = pair().await;

    let founder = joined
        .founder_pin()
        .await
        .expect("a joiner must be anchored");
    assert_ne!(
        founder,
        joiner_identity.peer_id(),
        "the joiner founded a vault of its own instead of joining one"
    );
    assert_eq!(founder, host_identity.peer_id());
    // And it must NOT have quietly made itself an Admin along the way.
    assert_eq!(
        joined.self_role().await,
        Some(Role::Writer),
        "the joiner holds a role the host did not grant"
    );
}

/// The bucket a joiner addresses has to be the host's, or it would sync into an
/// empty corner of the relay and appear to work while sharing nothing. It is
/// also the OPFS pool name, so getting it wrong means the vault is stored
/// somewhere the next open will not look.
#[tokio::test(flavor = "multi_thread")]
async fn a_joined_vault_addresses_the_same_bucket_as_the_host() {
    let (_host_store, joined, _host_identity, _joiner_identity) = pair().await;

    let host_bucket = roam_backend_client::crypto::VaultKey(VAULT_KEY).bucket_id();
    assert_eq!(joined.bucket_id(), host_bucket);
}
