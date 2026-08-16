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

/// Everything a paired-up pair leaves behind, so a check can look at whichever
/// side it is about.
struct Paired {
    host_store: Store,
    host_identity: Identity,
    host_vault_id: VaultId,
    joined: Vault,
    joiner_identity: Identity,
    /// The joiner's storage, kept so a check can reopen the vault it created.
    joiner_fs: Arc<dyn VaultFs>,
}

/// Host and joiner, paired over an in-process mailbox, with the joiner granted
/// `Role::Writer` — enough to edit, and deliberately not enough to vouch.
async fn pair() -> Paired {
    pair_granting(Role::Writer).await
}

/// The same, with the role the host grants chosen by the caller.
async fn pair_granting(granted: Role) -> Paired {
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
    let host_vault_id = VaultId::generate();

    let (code, host) = host_via_mailbox(
        &host_identity,
        host_vault_id,
        VAULT_KEY,
        granted,
        &mut host_store,
        mailbox.clone(),
        invite.clone(),
    );
    let host = host.with_timeouts(Duration::from_secs(5), Duration::from_millis(5));

    let joiner_fs: Arc<dyn VaultFs> = Arc::new(MemFs::new());
    let joiner_fs_for_task = Arc::clone(&joiner_fs);
    let joiner_identity_for_task = joiner_identity.clone();
    let (host_result, joined) = tokio::join!(host.accept_for(Duration::from_secs(10)), async {
        let (accept, host_key) =
            fetch_accept_via_mailbox(&joiner_identity_for_task, &mailbox, &invite, &code)
                .await
                .expect("fetch the accept");
        // Exactly the browser's order: the handshake finishes, and only then is
        // there anywhere to put a store.
        Vault::join(
            joiner_fs_for_task,
            joiner_identity_for_task,
            accept,
            &host_key,
        )
        .expect("join")
    });
    host_result.expect("host accepts");

    Paired {
        host_store,
        host_identity,
        host_vault_id,
        joined,
        joiner_identity,
        joiner_fs,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_joined_vault_holds_the_role_the_host_granted() {
    let Paired {
        host_store,
        joined,
        host_identity,
        joiner_identity,
        ..
    } = pair().await;

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
    let Paired {
        joined,
        host_identity,
        joiner_identity,
        ..
    } = pair().await;

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
    let Paired { joined, .. } = pair().await;

    let host_bucket = roam_backend_client::crypto::VaultKey(VAULT_KEY).bucket_id();
    assert_eq!(joined.bucket_id(), host_bucket);
}

/// A joiner has to write down the vault id it was *given*.
///
/// It cannot derive one — a vault id is minted at founding and every member must
/// name the vault identically. A joiner that generated its own would look fine
/// until the day it hosted somebody, and then enrol them into a vault that does
/// not exist. The failure would land on a third device, one hop from the bug.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_records_the_hosts_vault_id_and_keeps_it_across_a_reopen() {
    let Paired {
        joined,
        host_vault_id,
        joiner_fs,
        ..
    } = pair().await;

    assert_eq!(
        joined.vault_id(),
        host_vault_id,
        "the joiner named the vault something the host would not recognise"
    );

    // A second open of the same storage — the browser's next page load. `open`
    // mints a vault id when it finds none, so this is also the check that the
    // join path wrote one at all.
    let reopened = Vault::open(joiner_fs, VAULT_KEY).expect("reopen the joined vault");
    assert_eq!(
        reopened.vault_id(),
        host_vault_id,
        "reopening minted a fresh vault id over the one the host gave"
    );
    assert_eq!(
        reopened.peer_id().await,
        joined.peer_id().await,
        "reopening produced a different device"
    );
}

/// A Writer holds no power to vouch, and must be told so at once.
///
/// Found by watching this test fail as a *timeout*: a Writer's `add_peer` fails
/// inside the handshake, that session is abandoned exactly like a wrong-code
/// one, and the host waits out its entire window before saying anything — while
/// the joiner is told its code was probably wrong. Two devices, both misled,
/// about a condition knowable before the code was ever shown.
#[tokio::test(flavor = "multi_thread")]
async fn a_writer_cannot_host_and_is_told_immediately() {
    let Paired { joined, .. } = pair_granting(Role::Writer).await;

    let started = std::time::Instant::now();
    let error = joined
        .host_invite(
            MemoryMailbox::new(),
            Invite::generate("https://relay.example", joined.verifying_key().await),
            Role::Reader,
            // A window long enough that waiting it out would be unmistakable.
            Duration::from_secs(600),
            |_code, _invite| {},
        )
        .await
        .expect_err("a Writer must not be able to host");

    assert!(
        error.to_string().contains("only an Admin"),
        "unhelpful error: {error}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the refusal waited out the window instead of failing fast"
    );
}

/// A browser that joined a vault as an **Admin** can admit the next device.
///
/// The point is that there is no native host anywhere in this chain: the second
/// joiner is enrolled by a `Vault`, into the vault id the first one was handed.
/// If `join` had not persisted that id — or `host_invite` had minted a fresh one
/// — this is where it would show.
#[tokio::test(flavor = "multi_thread")]
async fn a_joined_browser_vault_can_host_the_next_device() {
    let Paired {
        joined,
        host_vault_id,
        ..
    } = pair_granting(Role::Admin).await;

    let second_identity = Identity::generate();
    let mailbox = MemoryMailbox::new();
    let invite = Invite::generate("https://relay.example", joined.verifying_key().await);

    let (send_code, take_code) = std::sync::mpsc::channel();
    let hosting = joined.host_invite(
        mailbox.clone(),
        invite.clone(),
        Role::Reader,
        Duration::from_secs(10),
        move |code, _invite| {
            send_code
                .send(code.as_str().to_string())
                .expect("hand over the code")
        },
    );

    let second_identity_for_task = second_identity.clone();
    let mailbox_for_task = mailbox.clone();
    let invite_for_task = invite.clone();
    let (enrolled, second) = tokio::join!(hosting, async move {
        // The code cannot be read before hosting starts producing it, which is
        // the whole reason `show` is a callback.
        let code = tokio::task::spawn_blocking(move || take_code.recv().expect("a code"))
            .await
            .expect("await the code");
        let code = roam_pairing::PairingCode::parse(&code).expect("parse the code");
        let (accept, host_key) = fetch_accept_via_mailbox(
            &second_identity_for_task,
            &mailbox_for_task,
            &invite_for_task,
            &code,
        )
        .await
        .expect("fetch the accept");
        Vault::join(
            Arc::new(MemFs::new()),
            second_identity_for_task,
            accept,
            &host_key,
        )
        .expect("join")
    });

    assert_eq!(
        enrolled.expect("host the second device"),
        second_identity.peer_id()
    );
    assert_eq!(
        second.vault_id(),
        host_vault_id,
        "the browser host enrolled a device into a vault of its own invention"
    );
    assert_eq!(
        second.self_role().await,
        Some(Role::Reader),
        "the role the browser host granted did not materialise"
    );
    assert_eq!(second.vault_key(), VAULT_KEY);
}
