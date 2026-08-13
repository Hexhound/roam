//! Live pairing end-to-end over the REAL iroh transport (loopback).
//!
//! This exercises the actual `host_pairing` / `join_pairing` handshake that the
//! `roam pair-token` / `roam pair` CLI commands wrap — the one path every other
//! multi-device test deliberately SIDE-STEPS by bundle-bootstrapping trust out of
//! band. Here the joiner learns everything the honest way: it dials the host over
//! iroh using only the address embedded in the token, proves it saw the one-time
//! secret, and receives — over the proven, encrypted stream — the shared vault
//! key, the founder pin, and the host's roster/key-log. A green run proves the
//! whole enrolment path works, not just its pieces (the crypto of the handshake
//! has its own unit tests in `pairing.rs`).
//!
//! Loopback works with no discovery service because the token carries the host's
//! dialable `EndpointAddr` (snapshotted via `ready_addr` at mint time).

use std::time::Duration;

use roam_storage::{Identity, Role, Store, VaultId};
use roam_transport_iroh::{host_pairing, join_pairing};
use tempfile::tempdir;

/// Hard ceiling so a broken handshake fails loudly instead of blocking on the
/// host's full token-TTL accept window.
const PAIR_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread")]
async fn a_device_pairs_over_real_iroh_and_inherits_key_role_and_founder() {
    // Host A founds the vault as Admin and mints a shared vault key. (In the CLI,
    // `init` does exactly this and persists both next to the vault.)
    let vault = VaultId::generate();
    let vault_key = [0x11u8; 32];
    let id_a = Identity::generate();
    let id_b = Identity::generate();

    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let mut store_a = Store::open(a_dir.path(), id_a.clone()).unwrap();
    store_a.declare_founder(Role::Admin).unwrap();

    // Arm the host: it will grant the next proven joiner the WRITER role.
    let (token, host) = host_pairing(&id_a, vault, vault_key, Role::Writer, &mut store_a)
        .await
        .expect("arm pairing host");

    // The joiner runs concurrently: it decodes the token, dials A over iroh, and
    // proves the secret. `join_pairing` takes owned args so it can be spawned.
    let b_root = b_dir.path().to_path_buf();
    let join = tokio::spawn(join_pairing(id_b.clone(), b_root, token));

    // Host accepts exactly one join. Bounded so a failed handshake never hangs.
    let added_peer = tokio::time::timeout(PAIR_TIMEOUT, host.accept_auto())
        .await
        .expect("host accept did not time out")
        .expect("host accepted the join");
    assert_eq!(
        added_peer,
        id_b.peer_id(),
        "host added the joiner's peer id"
    );

    let (store_b, vault_key_b, founder) = tokio::time::timeout(PAIR_TIMEOUT, join)
        .await
        .expect("joiner did not time out")
        .expect("join task did not panic")
        .expect("join_pairing succeeded");

    // 1. The shared vault key was delivered over the proven stream (never in the
    //    out-of-band token), so both devices agree on the backend secret.
    assert_eq!(
        *vault_key_b, vault_key,
        "joiner received the shared vault key"
    );
    // 2. The joiner pinned the vault founder — without this its roster fold learns
    //    no role and it would be inert.
    assert_eq!(founder, id_a.peer_id(), "joiner pinned the host as founder");

    // 3. Host side: the joiner is now an active Writer in A's roster.
    assert_eq!(
        store_a.role_of(id_b.peer_id()),
        Some(Role::Writer),
        "host granted the joiner the Writer role"
    );

    // 4. Joiner side: it folds the founder chain, so it sees A as Admin and itself
    //    as the Writer A just granted.
    assert_eq!(
        store_b.role_of(id_a.peer_id()),
        Some(Role::Admin),
        "joiner recognizes the host as Admin founder"
    );
    assert_eq!(
        store_b.role_of(id_b.peer_id()),
        Some(Role::Writer),
        "joiner materializes its own granted Writer role"
    );
}
