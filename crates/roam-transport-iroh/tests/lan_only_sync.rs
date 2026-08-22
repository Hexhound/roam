//! F2(b): two roam devices sync with **no internet at all** — no relay, no
//! pkarr, no DNS. Only mDNS on the local network.
//!
//! This is the free p2p path a consumer app relies on when two devices sit on
//! the same Wi-Fi. It is deliberately stricter than `e2e.rs`, which seeds each
//! side with the other's `EndpointAddr` and keeps the n0 relay stack available:
//! here the ONLY way a peer's address can be learned is an mDNS announcement, so
//! a pass proves LAN discovery is wired through `build_endpoint_with` rather
//! than proving that a relay worked.
//!
//! Real multicast (224.0.0.251/ff02::fb), so `#[ignore]`d like the rest of the
//! LAN suite; run with `--ignored`. A failure in a container or a sandbox is
//! blocked multicast until proven otherwise.

use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_transport_iroh::{EndpointConfig, IrohTransport};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

/// mDNS announcements are timer-driven; a tight budget makes this flaky for
/// reasons unrelated to correctness.
const CONVERGE: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs real multicast on the local network; run with --ignored"]
async fn two_devices_converge_over_the_lan_with_no_relay() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();
    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let vault = VaultId::generate();

    let mut store_a = Store::open(dir_a.path(), id_a.clone()).unwrap();
    let mut store_b = Store::open(dir_b.path(), id_b.clone()).unwrap();
    store_a.declare_founder(Role::Admin).unwrap();
    store_b.declare_founder(Role::Admin).unwrap();
    store_a
        .add_peer(id_b.peer_id(), id_b.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    store_b
        .add_peer(id_a.peer_id(), id_a.verifying_key().to_bytes(), Role::Admin)
        .unwrap();

    // Both devices hold data before they ever talk — the pre-pairing merge case.
    store_a.edit_text("note", 0, "from-A").unwrap();
    store_b.edit_text("note", 0, "from-B").unwrap();

    let mut routes_a = HashMap::new();
    routes_a.insert(id_b.peer_id(), id_b.verifying_key().to_bytes());
    let mut routes_b = HashMap::new();
    routes_b.insert(id_a.peer_id(), id_a.verifying_key().to_bytes());

    // `lan_only()`: RelayMode::Disabled + presets::Minimal, so there is no
    // relay, no pkarr and no DNS to fall back on, plus mDNS both ways.
    let config = EndpointConfig::lan_only();
    let transport_a = IrohTransport::spawn_with(&id_a, routes_a, &config)
        .await
        .unwrap();
    let transport_b = IrohTransport::spawn_with(&id_b, routes_b, &config)
        .await
        .unwrap();

    // Note what is NOT here: no `add_addr`. Each side must learn the other's
    // address from mDNS alone, which is the whole point of the test.

    let engine_a = Arc::new(Engine::new(
        id_a.clone(),
        vault,
        store_a,
        Arc::new(transport_a),
        [0u8; 32],
    ));
    let engine_b = Arc::new(Engine::new(
        id_b.clone(),
        vault,
        store_b,
        Arc::new(transport_b),
        [0u8; 32],
    ));
    tokio::spawn(engine_a.clone().run());
    tokio::spawn(engine_b.clone().run());

    engine_a.connect(id_b.peer_id()).await.unwrap();
    engine_b.connect(id_a.peer_id()).await.unwrap();
    tokio::time::sleep(CONVERGE).await;

    let text_a = engine_a.store().lock().await.text("note");
    let text_b = engine_b.store().lock().await.text("note");
    assert_eq!(text_a, text_b, "LAN-only devices must converge");
    assert!(
        text_a.contains("A") && text_a.contains("B"),
        "a pre-pairing edit was lost instead of merged: {text_a}"
    );
}
