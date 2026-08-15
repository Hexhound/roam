//! F2(a): two roam devices find each other on the LAN with no internet.
//!
//! These talk to the real network stack (multicast UDP on 224.0.0.251/ff02::fb),
//! so they are `#[ignore]`d by default and run with `--ignored`. They are not
//! unit tests and cannot be: mDNS is announcement-driven, and the thing worth
//! testing is precisely that real announcements arrive.
//!
//! If they fail in a sandbox or a container, suspect blocked multicast before
//! suspecting the code.

use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use roam_transport_iroh::discovery::{advertise_name, LanDiscovery, ROAM_MDNS_SERVICE};
use std::time::Duration;

/// Generous: mDNS announcements are timer-driven, and a tight window would make
/// this flaky for reasons that have nothing to do with correctness.
const WINDOW: Duration = Duration::from_secs(5);

/// `presets::Minimal` deliberately: no relay, no pkarr, no DNS. If discovery
/// works here, it worked over the LAN and nothing else.
async fn lan_only_endpoint(seed: u8) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[seed; 32]))
        .bind()
        .await
        .expect("bind LAN-only endpoint")
}

#[tokio::test]
#[ignore = "needs real multicast on the local network; run with --ignored"]
async fn two_devices_find_each_other_with_no_internet() {
    let alice = lan_only_endpoint(1).await;
    let bob = lan_only_endpoint(2).await;

    advertise_name(&alice, Some("alice-laptop")).unwrap();
    advertise_name(&bob, Some("bob-phone")).unwrap();

    let alice_discovery = LanDiscovery::attach(&alice, true).unwrap();
    let bob_discovery = LanDiscovery::attach(&bob, true).unwrap();

    let (alice_sees, bob_sees) =
        tokio::join!(alice_discovery.peers(WINDOW), bob_discovery.peers(WINDOW));

    let found_bob = alice_sees
        .iter()
        .find(|peer| peer.endpoint_id == bob.id())
        .expect("alice did not see bob on the LAN");
    assert_eq!(found_bob.name.as_deref(), Some("bob-phone"));

    let found_alice = bob_sees
        .iter()
        .find(|peer| peer.endpoint_id == alice.id())
        .expect("bob did not see alice on the LAN");
    assert_eq!(found_alice.name.as_deref(), Some("alice-laptop"));
}

/// A device that browses without advertising must stay invisible. This is the
/// property the privacy decision in `discovery.rs` rests on — if `advertise:
/// false` still announced, "open the app on café Wi-Fi" would broadcast a stable
/// device identifier.
#[tokio::test]
#[ignore = "needs real multicast on the local network; run with --ignored"]
async fn a_passive_browser_does_not_announce_itself() {
    let watcher = lan_only_endpoint(3).await;
    let lurker = lan_only_endpoint(4).await;

    let watcher_discovery = LanDiscovery::attach(&watcher, true).unwrap();
    let lurker_discovery = LanDiscovery::attach(&lurker, false).unwrap();

    let (watcher_sees, lurker_sees) = tokio::join!(
        watcher_discovery.peers(WINDOW),
        lurker_discovery.peers(WINDOW)
    );

    assert!(
        !watcher_sees
            .iter()
            .any(|peer| peer.endpoint_id == lurker.id()),
        "a passive browser announced itself on the network"
    );
    // The lurker must still be able to *see*, or "browse without advertising"
    // would be useless rather than private.
    assert!(
        lurker_sees
            .iter()
            .any(|peer| peer.endpoint_id == watcher.id()),
        "the passive browser saw nothing, so the test above proves nothing"
    );
}

/// roam announces under its own service name, so it neither shows up in, nor
/// picks up, unrelated iroh applications on the same network.
#[tokio::test]
#[ignore = "needs real multicast on the local network; run with --ignored"]
async fn devices_on_irohs_default_service_are_not_seen_as_roam_peers() {
    use iroh_mdns_address_lookup::MdnsAddressLookup;

    let roam_device = lan_only_endpoint(5).await;
    let other_app = lan_only_endpoint(6).await;
    // A second roam device, purely so the negative assertion below cannot pass
    // by discovery being broken and seeing nothing at all.
    let roam_control = lan_only_endpoint(7).await;

    // A non-roam iroh app: iroh's default service name, not ours.
    let other_mdns = MdnsAddressLookup::builder()
        .build(other_app.id())
        .expect("start default-service mDNS");
    other_app.address_lookup().unwrap().add(other_mdns);

    let roam_discovery = LanDiscovery::attach(&roam_device, true).unwrap();
    let _control_discovery = LanDiscovery::attach(&roam_control, true).unwrap();
    let seen = roam_discovery.peers(WINDOW).await;

    assert!(
        seen.iter()
            .any(|peer| peer.endpoint_id == roam_control.id()),
        "the browser saw no roam peer at all, so the assertion below is vacuous"
    );
    assert!(
        !seen.iter().any(|peer| peer.endpoint_id == other_app.id()),
        "an unrelated iroh app on service `irohv1` leaked into roam's peer list \
         (roam advertises under `{ROAM_MDNS_SERVICE}`)"
    );
}

/// F2(c) over the real network: the joiner is given nothing but the host's
/// endpoint id — no address — and has to find it by multicast.
///
/// The unit-level LAN pairing tests in `lan_pairing.rs` hand the joiner a
/// loopback `EndpointAddr`, which sidesteps discovery entirely. This is the only
/// test that covers `join_lan_pairing_by_id` resolving an id to an address, and
/// it needs real multicast, hence `#[ignore]`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs real multicast on the local network; run with --ignored"]
async fn a_device_pairs_over_the_lan_knowing_only_the_host_id() {
    use roam_storage::{Identity, Role, Store, VaultId};
    use roam_transport_iroh::pairing_lan::{host_lan_pairing, join_lan_pairing_by_id};

    let host_identity = Identity::generate();
    let joiner_identity = Identity::generate();
    let host_dir = tempfile::tempdir().unwrap();
    let joiner_dir = tempfile::tempdir().unwrap();
    let vault = VaultId::generate();
    let vault_key = [0x5au8; 32];

    let mut host_store = Store::open(host_dir.path(), host_identity.clone()).unwrap();
    host_store.declare_founder(Role::Admin).unwrap();

    let (code, mut host) = host_lan_pairing(
        &host_identity,
        vault,
        vault_key,
        Role::Writer,
        &mut host_store,
    )
    .await
    .expect("arm the host");
    host.advertise_on_lan(Some("host-laptop"))
        .expect("announce on the LAN");
    let host_id = host.endpoint_id();

    let join = tokio::spawn(join_lan_pairing_by_id(
        joiner_identity.clone(),
        joiner_dir.path().to_path_buf(),
        host_id,
        code,
    ));

    let added = tokio::time::timeout(Duration::from_secs(30), host.accept_auto())
        .await
        .expect("host did not hang")
        .expect("host accepted the join");
    assert_eq!(added, joiner_identity.peer_id());

    let joined = join.await.unwrap().expect("joiner paired over mDNS alone");
    assert_eq!(*joined.vault_key, vault_key);
    assert_eq!(joined.vault, vault);
}
