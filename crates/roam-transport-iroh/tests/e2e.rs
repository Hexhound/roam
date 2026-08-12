use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_transport_iroh::IrohTransport;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

#[tokio::test(flavor = "multi_thread")]
async fn two_real_endpoints_catch_up_offline_edits() {
    let da = tempdir().unwrap();
    let db = tempdir().unwrap();
    let ia = Identity::generate();
    let ib = Identity::generate();
    let vault = VaultId::generate();

    let mut sa = Store::open(da.path(), ia.clone()).unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    // Each device founds its own vault as admin so its own `add_peer` vouches fold.
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    // Edit BEFORE connecting (offline).
    sa.edit_text("note", 0, "offline-A").unwrap();
    sb.edit_text("note", 0, "offline-B").unwrap();

    let mut ra = HashMap::new();
    ra.insert(ib.peer_id(), ib.verifying_key().to_bytes());
    let mut rb = HashMap::new();
    rb.insert(ia.peer_id(), ia.verifying_key().to_bytes());
    let ta = IrohTransport::spawn(&ia, ra).await.unwrap();
    let tb = IrohTransport::spawn(&ib, rb).await.unwrap();
    ta.add_addr(ib.peer_id(), tb.endpoint_addr()).await;
    tb.add_addr(ia.peer_id(), ta.endpoint_addr()).await;

    let ea = Arc::new(Engine::new(ia.clone(), vault, sa, Arc::new(ta), [0u8; 32]));
    let eb = Arc::new(Engine::new(ib.clone(), vault, sb, Arc::new(tb), [0u8; 32]));
    tokio::spawn(ea.clone().run());
    tokio::spawn(eb.clone().run());

    ea.connect(ib.peer_id()).await.unwrap();
    eb.connect(ia.peer_id()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    let ta_text = ea.store().lock().await.text("note");
    let tb_text = eb.store().lock().await.text("note");
    assert_eq!(ta_text, tb_text, "real endpoints must converge");
    assert!(
        ta_text.contains("A") && ta_text.contains("B"),
        "lost an offline edit: {ta_text}"
    );
}
