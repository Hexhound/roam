//! Three-device role-enforcement end-to-end test over the REAL iroh transport
//! (loopback), driven through the sync engine and the folder bridge.
//!
//! Devices: **Admin** (founder), **Writer**, **Reader** — a single-founder mesh.
//! This is the role-aware analogue of `folder_sync_e2e.rs`: it reuses the same
//! harness shape (one `Identity` per device, one shared `VaultId`, one `Store`
//! per device, one `IrohTransport::spawn` per device wired for loopback via
//! `add_addr`/`endpoint_addr`, one `Engine` per device each `run()` in a spawned
//! task, a full mesh of `connect`s) and layers a `FolderBridge` per device so a
//! disk change on one device propagates through the CRDT to the others — subject
//! to role enforcement.
//!
//! TRUST BOOTSTRAP: **bundle-bootstrap** (NOT live iroh pairing). The Admin
//! founds the vault and `add_peer`s the Writer (Writer) and Reader (Reader); the
//! two joiners each `pin_founder(admin)` + `import_roster_bundle(admin's full
//! roster)`. This is the documented fallback and exercises the exact same
//! enforcement paths (`import_peer` refuses Reader-authored content ops; the
//! bridge force-reverts a Reader's local edits) as live pairing, while giving a
//! fully-connected 3-mesh where every device knows every other from the start
//! (a single sequential pairing would not transitively wire the Writer<->Reader
//! edge). Roles are the point here, not the pairing handshake (covered by
//! `roam-transport-iroh/src/pairing.rs` tests).
//!
//! The three enforcement assertions:
//!   1. Writer's edits propagate to Admin AND Reader.
//!   2. Reader's edits do NOT propagate (dropped by receivers' `import_peer`),
//!      and the Reader's OWN vault force-reverts to the authoritative state.
//!   3. After the Admin DEMOTES the Writer to Reader, the (now-Reader ex-Writer)
//!      device's NEW edits are dropped mesh-wide. The ex-Writer is deliberately
//!      kept UNAWARE of its own demotion (its roster is not updated) so that it
//!      still authors + gossips — proving the drop is RECEIVER-side (the security
//!      model never trusts an author to self-censor): both Admin and Reader drop
//!      the ops purely on their own view of the author's role.
//!
//! Every wait is a bounded poll with a hard timeout (convergence) or a fixed
//! settle window over which a condition must HOLD (the "did not propagate"
//! assertions) — never sleep-and-hope.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use roam_files::FolderBridge;
use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_transport_iroh::IrohTransport;
use tempfile::TempDir;

/// Ceiling for a positive convergence wait over the loopback network.
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(20);
/// Poll interval between re-scans.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long a "must NOT propagate" invariant is continuously re-checked while the
/// mesh is actively pumped. Generous enough that a real cross-device leak (if the
/// enforcement were broken) would have landed many times over.
const SETTLE: Duration = Duration::from_secs(4);

/// One device: its vault dir, the bridge over it, and the engine that owns the
/// Store the bridge reconciles against.
struct Device {
    _vault_dir: TempDir,
    _store_dir: TempDir,
    vault: PathBuf,
    bridge: FolderBridge,
    engine: Arc<Engine<IrohTransport>>,
}

impl Device {
    fn note(&self) -> PathBuf {
        self.vault.join("note.md")
    }
}

/// Drive one device's reconcile against ITS engine's shared store, then gossip
/// any resulting local ops. Same lock discipline as the folder-sync harness:
/// drop the store guard BEFORE awaiting `flush_local` (never hold a lock across a
/// transport await).
async fn scan(device: &Device) {
    let store = device.engine.store();
    {
        let mut guard = store.lock().await;
        device.bridge.scan(&mut guard).expect("scan must succeed");
    } // guard dropped before the flush await.
    device.engine.flush_local().await;
}

/// Pump every device once (project inbound state to disk + flush local deltas),
/// keeping the whole mesh live while we wait on one device's disk state.
async fn pump(devices: &[&Device]) {
    for device in devices {
        scan(device).await;
    }
}

/// Read a device's note.md, or "" if absent.
fn note_text(device: &Device) -> String {
    let file = device.note();
    if file.exists() {
        std::fs::read_to_string(&file).expect("read note.md")
    } else {
        String::new()
    }
}

/// Pump the mesh until `target`'s note.md equals `want`, or fail loudly on
/// timeout. `devices` is the full mesh (pumped each round so ops keep flowing).
async fn converge_note(devices: &[&Device], target: &Device, want: &str, label: &str) {
    let start = Instant::now();
    loop {
        pump(devices).await;
        if note_text(target) == want {
            return;
        }
        if start.elapsed() > CONVERGE_TIMEOUT {
            panic!(
                "timed out after {CONVERGE_TIMEOUT:?} waiting for {label}: \
                 note.md is {:?}, wanted {want:?}",
                note_text(target)
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Continuously pump the mesh for `SETTLE`, asserting `target`'s note.md stays
/// `want` the WHOLE time. This is how the "did not propagate" invariants are
/// checked: if enforcement were broken, a leaked edit would land during this
/// window and trip the assertion.
async fn note_stays(devices: &[&Device], target: &Device, want: &str, label: &str) {
    let start = Instant::now();
    while start.elapsed() < SETTLE {
        pump(devices).await;
        assert_eq!(
            note_text(target),
            want,
            "role enforcement violated ({label}): {want:?} was expected to hold"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Build a live device: transport + engine + bridge over fresh tempdirs. The
/// transport's routes and loopback addrs are wired by the caller AFTER all three
/// transports exist (each needs the others' `endpoint_addr`).
#[allow(clippy::too_many_arguments)]
fn make_device(
    identity: Identity,
    vault_id: VaultId,
    store: Store,
    transport: IrohTransport,
    vault_dir: TempDir,
    store_dir: TempDir,
) -> Device {
    let vault = vault_dir.path().to_path_buf();
    let meta = store_dir.path().join("filemeta");
    let engine = Arc::new(Engine::new(identity, vault_id, store, Arc::new(transport)));
    Device {
        vault: vault.clone(),
        bridge: FolderBridge::new(&vault, &meta),
        engine,
        _vault_dir: vault_dir,
        _store_dir: store_dir,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn three_device_admin_writer_reader_role_enforcement() {
    // ---- Identities + one shared vault id. ----
    let admin_id = Identity::generate();
    let writer_id = Identity::generate();
    let reader_id = Identity::generate();
    let vault_id = VaultId::generate();

    let admin_key = admin_id.verifying_key().to_bytes();
    let writer_key = writer_id.verifying_key().to_bytes();
    let reader_key = reader_id.verifying_key().to_bytes();

    // ---- Tempdirs: each device fully isolated (vault folder + store). ----
    let admin_vault_dir = tempfile::tempdir().unwrap();
    let admin_store_dir = tempfile::tempdir().unwrap();
    let writer_vault_dir = tempfile::tempdir().unwrap();
    let writer_store_dir = tempfile::tempdir().unwrap();
    let reader_vault_dir = tempfile::tempdir().unwrap();
    let reader_store_dir = tempfile::tempdir().unwrap();

    // ---- Stores + BUNDLE-BOOTSTRAP trust (single founder = Admin). ----
    let mut admin_store = Store::open(admin_store_dir.path(), admin_id.clone()).unwrap();
    admin_store.declare_founder(Role::Admin).unwrap();
    admin_store.add_peer(writer_id.peer_id(), writer_key, Role::Writer).unwrap();
    admin_store.add_peer(reader_id.peer_id(), reader_key, Role::Reader).unwrap();

    // The Admin's transitive roster after BOTH adds: every device learns every
    // other (so the Writer<->Reader edge is trusted from the start).
    let roster_bundle = admin_store.export_all_rosters().unwrap();

    let mut writer_store = Store::open(writer_store_dir.path(), writer_id.clone()).unwrap();
    writer_store.pin_founder(admin_id.peer_id()).unwrap();
    writer_store.import_roster_bundle(roster_bundle.clone()).unwrap();

    let mut reader_store = Store::open(reader_store_dir.path(), reader_id.clone()).unwrap();
    reader_store.pin_founder(admin_id.peer_id()).unwrap();
    reader_store.import_roster_bundle(roster_bundle.clone()).unwrap();

    // Sanity: roles materialized exactly as granted.
    assert_eq!(admin_store.self_role(), Some(Role::Admin), "admin self-role");
    assert_eq!(writer_store.self_role(), Some(Role::Writer), "writer self-role");
    assert_eq!(reader_store.self_role(), Some(Role::Reader), "reader self-role");
    assert!(writer_store.may_write(), "writer may write");
    assert!(!reader_store.may_write(), "reader may NOT write");

    // ---- Transports: each routes to the OTHER two peers. ----
    let admin_routes = HashMap::from([
        (writer_id.peer_id(), writer_key),
        (reader_id.peer_id(), reader_key),
    ]);
    let writer_routes = HashMap::from([
        (admin_id.peer_id(), admin_key),
        (reader_id.peer_id(), reader_key),
    ]);
    let reader_routes = HashMap::from([
        (admin_id.peer_id(), admin_key),
        (writer_id.peer_id(), writer_key),
    ]);
    let admin_tp = IrohTransport::spawn(&admin_id, admin_routes).await.unwrap();
    let writer_tp = IrohTransport::spawn(&writer_id, writer_routes).await.unwrap();
    let reader_tp = IrohTransport::spawn(&reader_id, reader_routes).await.unwrap();

    // Loopback reachability: full-mesh addr exchange.
    admin_tp.add_addr(writer_id.peer_id(), writer_tp.endpoint_addr()).await;
    admin_tp.add_addr(reader_id.peer_id(), reader_tp.endpoint_addr()).await;
    writer_tp.add_addr(admin_id.peer_id(), admin_tp.endpoint_addr()).await;
    writer_tp.add_addr(reader_id.peer_id(), reader_tp.endpoint_addr()).await;
    reader_tp.add_addr(admin_id.peer_id(), admin_tp.endpoint_addr()).await;
    reader_tp.add_addr(writer_id.peer_id(), writer_tp.endpoint_addr()).await;

    // ---- Engines + bridges. ----
    let admin = make_device(
        admin_id.clone(), vault_id, admin_store, admin_tp, admin_vault_dir, admin_store_dir,
    );
    let writer = make_device(
        writer_id.clone(), vault_id, writer_store, writer_tp, writer_vault_dir, writer_store_dir,
    );
    let reader = make_device(
        reader_id.clone(), vault_id, reader_store, reader_tp, reader_vault_dir, reader_store_dir,
    );

    tokio::spawn(admin.engine.clone().run());
    tokio::spawn(writer.engine.clone().run());
    tokio::spawn(reader.engine.clone().run());

    // Full-mesh connect so ops flow along every edge.
    admin.engine.connect(writer_id.peer_id()).await.unwrap();
    admin.engine.connect(reader_id.peer_id()).await.unwrap();
    writer.engine.connect(admin_id.peer_id()).await.unwrap();
    writer.engine.connect(reader_id.peer_id()).await.unwrap();
    reader.engine.connect(admin_id.peer_id()).await.unwrap();
    reader.engine.connect(writer_id.peer_id()).await.unwrap();

    let mesh = [&admin, &writer, &reader];

    // ================================================================
    // Phase 1 — Admin seeds `note = "hello"` and it converges everywhere.
    // ================================================================
    std::fs::write(admin.note(), "hello").unwrap();
    scan(&admin).await; // import + gossip
    converge_note(&mesh, &writer, "hello", "writer to receive seed 'hello'").await;
    converge_note(&mesh, &reader, "hello", "reader to receive seed 'hello'").await;

    // ================================================================
    // Phase 2 — WRITER edit propagates to Admin AND Reader.
    // ================================================================
    std::fs::write(writer.note(), "hello world").unwrap();
    scan(&writer).await; // import writer's edit + gossip
    converge_note(&mesh, &admin, "hello world", "admin to receive writer's edit").await;
    converge_note(&mesh, &reader, "hello world", "reader to receive writer's edit").await;

    // ================================================================
    // Phase 3 — READER edit is DROPPED by receivers and REVERTED locally.
    // The reader dirties its own note.md; its next scan (read-only vault) never
    // authors an op and force-reverts to the authoritative projection.
    // ================================================================
    std::fs::write(reader.note(), "hello world READER-TAMPER").unwrap();
    // Admin and Writer must NEVER see the reader's tampered text.
    note_stays(&mesh, &admin, "hello world", "reader edit must not reach admin").await;
    note_stays(&mesh, &writer, "hello world", "reader edit must not reach writer").await;
    // The reader's OWN note reverted (the mesh pumping above scanned it repeatedly).
    assert_eq!(
        note_text(&reader),
        "hello world",
        "reader's own note.md must force-revert to the authoritative projection"
    );

    // ================================================================
    // Phase 4 — DEMOTION: Admin demotes the Writer to Reader. The demotion is
    // propagated to the Reader (so it too drops), but deliberately NOT to the
    // ex-Writer, which keeps authoring — proving receiver-side enforcement.
    // ================================================================
    {
        let store = admin.engine.store();
        let mut guard = store.lock().await;
        guard.set_role(writer_id.peer_id(), writer_key, Role::Reader).unwrap();
        assert_eq!(
            guard.role_of(writer_id.peer_id()),
            Some(Role::Reader),
            "admin now sees the writer as a Reader"
        );
    }
    // Propagate the demotion to the Reader by importing the Admin's updated
    // roster log directly (what a RosterOps gossip would deliver).
    let admin_roster_bytes = {
        let store = admin.engine.store();
        let guard = store.lock().await;
        guard.export_own_roster().unwrap()
    };
    {
        let store = reader.engine.store();
        let mut guard = store.lock().await;
        guard
            .import_roster(admin_id.peer_id(), &admin_id.verifying_key(), admin_roster_bytes)
            .unwrap();
        assert_eq!(
            guard.role_of(writer_id.peer_id()),
            Some(Role::Reader),
            "reader now sees the ex-writer as a Reader"
        );
    }

    // The ex-Writer (still believing it is a Writer) edits again and gossips.
    std::fs::write(writer.note(), "hello world DEMOTED-EDIT").unwrap();
    scan(&writer).await; // authors + gossips (its store still says Writer)
    // Dropped mesh-wide: neither Admin nor Reader accepts the now-Reader's ops.
    note_stays(&mesh, &admin, "hello world", "demoted writer's edit must not reach admin").await;
    note_stays(&mesh, &reader, "hello world", "demoted writer's edit must not reach reader").await;
}
