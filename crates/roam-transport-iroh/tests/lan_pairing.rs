//! F2(c): pairing a device INTO a vault over the LAN, authenticated by a short
//! typed code instead of a copy-pasted token.
//!
//! The token flow (`pairing.rs`) is a *bearer* flow: the token is a 256-bit
//! secret that must travel over a trusted out-of-band channel, which is fine for
//! a QR across the internet and miserable for "read six digits off my laptop".
//! This flow closes that gap with a PAKE: the host shows six digits, the joiner
//! types them, and a wrong guess costs one of three attempts and learns nothing.
//!
//! These run over loopback with `presets::Minimal` — no relay, no pkarr, no DNS
//! — because that is what "on the LAN, with no internet" means. On a real LAN
//! the host's address comes from `crate::discovery`; here the test passes it
//! directly, which is the same `EndpointAddr` discovery would have produced.

use std::time::Duration;

use roam_pake::{PairingCode, MAX_ATTEMPTS};
use roam_storage::{Identity, Role, Store, VaultId};
use roam_transport_iroh::pairing_lan::{host_lan_pairing, join_lan_pairing};
use tempfile::tempdir;

/// Hard ceiling so a broken handshake fails loudly instead of hanging out the
/// host's whole accept window.
const PAIR_TIMEOUT: Duration = Duration::from_secs(30);

/// A founded vault plus an armed host, ready for one join.
struct Founded {
    vault: VaultId,
    vault_key: [u8; 32],
    identity: Identity,
    store_dir: tempfile::TempDir,
}

fn found() -> (Founded, Store) {
    let store_dir = tempdir().unwrap();
    let identity = Identity::generate();
    let mut store = Store::open(store_dir.path(), identity.clone()).unwrap();
    store.declare_founder(Role::Admin).unwrap();
    (
        Founded {
            vault: VaultId::generate(),
            vault_key: [0x33u8; 32],
            identity,
            store_dir,
        },
        store,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn typing_the_right_code_joins_the_vault_with_key_role_and_founder() {
    let (host_state, mut store_a) = found();
    let joiner_identity = Identity::generate();
    let joiner_dir = tempdir().unwrap();

    let (code, host) = host_lan_pairing(
        &host_state.identity,
        host_state.vault,
        host_state.vault_key,
        Role::Writer,
        &mut store_a,
    )
    .await
    .expect("arm the LAN pairing host");

    let host_addr = host.addr();
    let join = tokio::spawn(join_lan_pairing(
        joiner_identity.clone(),
        joiner_dir.path().to_path_buf(),
        host_addr,
        code,
    ));

    let added = tokio::time::timeout(PAIR_TIMEOUT, host.accept_auto())
        .await
        .expect("host accept did not time out")
        .expect("host accepted the join");
    assert_eq!(added, joiner_identity.peer_id());

    let joined = tokio::time::timeout(PAIR_TIMEOUT, join)
        .await
        .expect("joiner did not time out")
        .expect("join task did not panic")
        .expect("join succeeded");
    let store_b = joined.store;

    // Everything the token flow delivers, delivered here over the PAKE channel.
    assert_eq!(*joined.vault_key, host_state.vault_key);
    assert_eq!(joined.founder, host_state.identity.peer_id());
    assert_eq!(
        joined.vault, host_state.vault,
        "joiner learned which vault it joined"
    );
    assert_eq!(
        store_a.role_of(joiner_identity.peer_id()),
        Some(Role::Writer),
        "host granted the joiner the Writer role"
    );
    assert_eq!(
        store_b.role_of(host_state.identity.peer_id()),
        Some(Role::Admin),
        "joiner folds the founder chain and sees the host as Admin"
    );
    assert_eq!(
        store_b.role_of(joiner_identity.peer_id()),
        Some(Role::Writer),
        "joiner materializes its own granted role"
    );
    drop(host_state.store_dir);
}

/// The whole point of the PAKE. A wrong guess must not obtain the vault key, and
/// — just as important — must not get the guesser into the host's roster.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_code_gets_neither_the_vault_key_nor_a_roster_entry() {
    let (host_state, mut store_a) = found();
    let joiner_identity = Identity::generate();
    let joiner_dir = tempdir().unwrap();

    let (_real_code, host) = host_lan_pairing(
        &host_state.identity,
        host_state.vault,
        host_state.vault_key,
        Role::Writer,
        &mut store_a,
    )
    .await
    .expect("arm the LAN pairing host");

    let host_addr = host.addr();
    let join = tokio::spawn(join_lan_pairing(
        joiner_identity.clone(),
        joiner_dir.path().to_path_buf(),
        host_addr,
        PairingCode::parse("000000").unwrap(),
    ));

    // The host keeps listening after a bad guess (the budget, not the first
    // connection, is what ends the session), so bound it with a short window.
    let accepted = tokio::time::timeout(PAIR_TIMEOUT, host.accept_for(Duration::from_secs(3)))
        .await
        .expect("host accept did not hang");
    assert!(accepted.is_err(), "a wrong code must not complete a join");

    let joined = tokio::time::timeout(PAIR_TIMEOUT, join)
        .await
        .expect("joiner did not hang")
        .expect("join task did not panic");
    assert!(joined.is_err(), "a wrong code must not yield a vault key");

    assert_eq!(
        store_a.role_of(joiner_identity.peer_id()),
        None,
        "a peer that never proved the code was added to the roster"
    );
    drop(host_state.store_dir);
}

/// Unlike the token flow — whose accept window is deliberately unbounded in
/// attempts, to keep a hostile first connection from burning the session (P2) —
/// a six-digit code MUST have a hard guess budget, or it is a one-in-a-million
/// lock an attacker can pick in a million tries.
#[tokio::test(flavor = "multi_thread")]
async fn the_code_dies_after_the_attempt_budget_is_spent() {
    let (host_state, mut store_a) = found();

    let (_real_code, host) = host_lan_pairing(
        &host_state.identity,
        host_state.vault,
        host_state.vault_key,
        Role::Writer,
        &mut store_a,
    )
    .await
    .expect("arm the LAN pairing host");
    let host_addr = host.addr();

    // Spend the budget from separate guessing devices, all with wrong codes.
    // `accept_for` borrows the store, so it cannot be spawned — run both halves
    // concurrently on this task instead.
    let guessing = async {
        for _ in 0..MAX_ATTEMPTS {
            let dir = tempdir().unwrap();
            let _ = join_lan_pairing(
                Identity::generate(),
                dir.path().to_path_buf(),
                host_addr.clone(),
                PairingCode::parse("000000").unwrap(),
            )
            .await;
        }
    };
    let (outcome, ()) = tokio::time::timeout(
        PAIR_TIMEOUT,
        futures::future::join(host.accept_for(Duration::from_secs(20)), guessing),
    )
    .await
    .expect("host did not hang");
    let message = outcome
        .expect_err("the host must give up, not pair")
        .to_string();
    assert!(
        message.contains("used up"),
        "expected a spent-code error, got: {message}"
    );
    drop(host_state.store_dir);
}

/// Proving the code says "this connection knows the six digits". It says nothing
/// about which long-term key the peer *claims* to be. If the host trusted the
/// claim, a joiner could type a legitimately-shown code and enrol somebody
/// else's key into the roster. The claim must equal the endpoint id iroh already
/// authenticated in the QUIC handshake.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_cannot_enrol_a_key_that_is_not_its_own() {
    use roam_transport_iroh::pairing_lan::testing::join_lan_pairing_claiming;

    let (host_state, mut store_a) = found();
    let joiner_identity = Identity::generate();
    let victim = Identity::generate();
    let joiner_dir = tempdir().unwrap();

    let (code, host) = host_lan_pairing(
        &host_state.identity,
        host_state.vault,
        host_state.vault_key,
        Role::Writer,
        &mut store_a,
    )
    .await
    .expect("arm the LAN pairing host");
    let host_addr = host.addr();

    let join = tokio::spawn(join_lan_pairing_claiming(
        joiner_identity.clone(),
        joiner_dir.path().to_path_buf(),
        host_addr,
        code,
        victim.verifying_key().to_bytes(),
        victim.peer_id(),
    ));

    let accepted = tokio::time::timeout(PAIR_TIMEOUT, host.accept_for(Duration::from_secs(3)))
        .await
        .expect("host accept did not hang");
    assert!(
        accepted.is_err(),
        "the host enrolled a key the peer did not prove it holds"
    );
    let _ = join.await;

    assert_eq!(
        store_a.role_of(victim.peer_id()),
        None,
        "a third party's key was smuggled into the roster"
    );
    assert_eq!(
        store_a.role_of(joiner_identity.peer_id()),
        None,
        "nothing should have been added at all"
    );
    drop(host_state.store_dir);
}

/// The pairing equivalent of `roam-share-iroh`'s stalled-peer test.
///
/// `accept_for` serves connections one at a time, so a device that connects and
/// then says nothing occupies the host for a whole handshake timeout. That must
/// cost time and nothing else: the code must survive, the session must survive,
/// and a real joiner behind the staller must still get through.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_connects_and_stalls_does_not_block_a_real_joiner() {
    use roam_transport_iroh::PAIRING_LAN_ALPN;

    let (host_state, mut store_a) = found();
    let joiner_identity = Identity::generate();
    let joiner_dir = tempdir().unwrap();

    let (code, host) = host_lan_pairing(
        &host_state.identity,
        host_state.vault,
        host_state.vault_key,
        Role::Writer,
        &mut store_a,
    )
    .await
    .expect("arm the LAN pairing host");
    // Short, so the test does not sit out the production bound. The bug this
    // guards is "a staller ends the session"; the duration is policy.
    let host = host.with_handshake_timeout(Duration::from_millis(300));
    let host_addr = host.addr();

    // `accept_for` borrows the store, so it cannot be spawned — run the host and
    // the two clients concurrently on this task. The host must already be
    // accepting before anyone dials.
    let clients = async {
        // A device that connects, opens a stream, and then goes quiet forever.
        let staller = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        let stall_conn = staller
            .connect(host_addr.clone(), PAIRING_LAN_ALPN)
            .await
            .expect("staller connects");
        let _stall_stream = stall_conn.open_bi().await.unwrap();

        join_lan_pairing(
            joiner_identity.clone(),
            joiner_dir.path().to_path_buf(),
            host_addr,
            code,
        )
        .await
    };

    let (added, joined) = tokio::time::timeout(
        PAIR_TIMEOUT,
        futures::future::join(host.accept_for(Duration::from_secs(20)), clients),
    )
    .await
    .expect("host did not hang");

    let added = added.expect("a stalled peer ended the pairing session");
    assert_eq!(added, joiner_identity.peer_id());
    let joined = joined.expect("the real joiner still got through");
    assert_eq!(*joined.vault_key, host_state.vault_key);
    drop(host_state.store_dir);
}

/// A peer that says *rubbish* must be as harmless as one that says nothing.
///
/// The attempt budget is the one thing that can end a pairing session from the
/// outside, so what spends it decides who can kill a pairing. It used to be
/// spent when a run started, before the message was parsed — so three junk
/// connections retired the code with no guessing and no knowledge of it, from
/// any device that could reach the host. The host advertises over mDNS, so that
/// is any device on the network.
///
/// The budget is now charged on a failed confirmation. Guessing is still capped
/// at [`MAX_ATTEMPTS`] — see `the_code_dies_after_the_attempt_budget_is_spent`,
/// which must keep passing alongside this.
#[tokio::test(flavor = "multi_thread")]
async fn junk_connections_cannot_retire_the_pairing_code() {
    use roam_transport_iroh::PAIRING_LAN_ALPN;

    let (host_state, mut store_a) = found();
    let joiner_identity = Identity::generate();
    let joiner_dir = tempdir().unwrap();

    let (code, host) = host_lan_pairing(
        &host_state.identity,
        host_state.vault,
        host_state.vault_key,
        Role::Writer,
        &mut store_a,
    )
    .await
    .expect("arm the LAN pairing host");
    let host = host.with_handshake_timeout(Duration::from_millis(300));
    let host_addr = host.addr();

    let clients = async {
        // More junk runs than the whole budget. Each is a complete, correctly
        // framed message that simply is not a SPAKE2 one.
        for attempt in 0..MAX_ATTEMPTS + 2 {
            let junk = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .bind()
                .await
                .unwrap();
            let conn = junk
                .connect(host_addr.clone(), PAIRING_LAN_ALPN)
                .await
                .unwrap_or_else(|e| panic!("junk connection {attempt} could not connect: {e}"));
            let (mut send, _recv) = conn.open_bi().await.unwrap();
            let garbage = b"not a spake2 message";
            // The pairing wire is big-endian length-prefixed (see `pairing_lan.rs`),
            // the opposite of the share wire — worth stating, since copying this
            // block across crates silently produces a length nobody can read.
            send.write_all(&(garbage.len() as u32).to_be_bytes())
                .await
                .unwrap();
            send.write_all(garbage).await.unwrap();
            send.finish().unwrap();
            // One at a time, so the runs land in order rather than racing the
            // host's sequential accept loop.
            conn.closed().await;
        }

        join_lan_pairing(
            joiner_identity.clone(),
            joiner_dir.path().to_path_buf(),
            host_addr,
            code,
        )
        .await
    };

    let (added, joined) = tokio::time::timeout(
        PAIR_TIMEOUT,
        futures::future::join(host.accept_for(Duration::from_secs(20)), clients),
    )
    .await
    .expect("host did not hang");

    let added = added.expect("junk connections retired a code they never guessed");
    assert_eq!(added, joiner_identity.peer_id());
    let joined = joined.expect("the real joiner still got through");
    assert_eq!(*joined.vault_key, host_state.vault_key);
    drop(host_state.store_dir);
}
