//! End-to-end P2P snapshot bootstrap over the in-memory transport. Exercises the
//! serve + adopt path (Tasks 5/6) as a full negotiation across the switchboard:
//!
//!  1. `p2p_snapshot_lets_a_lagging_peer_converge_past_a_compaction_frontier`
//!     — a real compaction-frontier stall: A checkpoints so its own op-log is
//!       truncated; a fresh peer replaying only those Ops does NOT converge
//!       (PART 1 inequality), then the snapshot negotiation makes it converge
//!       (PART 2).
//!  2. `a_writer_relays_an_admin_signed_snapshot_to_a_third_peer_with_no_admin_online`
//!     — model A: a non-Admin holder (B) re-serves an Admin-signed object to C
//!       while the original Admin (A) is offline; C still verifies A's signature.
//!  3. `a_writer_fabricated_snapshot_is_rejected_by_the_receiver_author_gate`
//!     — a Writer's well-formed, self-signed, decryptable object is rejected by
//!       the receiver-side Admin-author gate, across the wire.
//!
//! Drive style mirrors `read_gate.rs`: each engine keeps its endpoint so we can
//! both observe frames it sends (`incoming()`) and hand-deliver frames to it
//! (`handle()`), rather than spawning `run()` — that lets PART 1 of test 1
//! deliver ONLY the Ops (not the snapshot frames) so the pre-snapshot stall is
//! observable.

use futures::stream::BoxStream;
use futures::StreamExt;
use roam_backend_client::crypto::VaultKey;
use roam_storage::snapshot_msg::{frame, SnapshotManifest};
use roam_storage::{BlobStore, Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_sync_core::frame::Frame;
use roam_sync_core::memory::{MemorySwitchboard, MemoryTransport};
use roam_sync_core::Transport;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

const VAULT_KEY: [u8; 32] = [42u8; 32];
const MAP: &str = "notes";

/// Collect every frame currently queued on an endpoint's inbox (a short timeout
/// per frame; returns once the stream goes quiet). Each item is
/// `(sender_peer_id, frame)`.
async fn drain(rx: &mut BoxStream<'static, (u64, Frame)>) -> Vec<(u64, Frame)> {
    let mut out = Vec::new();
    while let Ok(Some(item)) = tokio::time::timeout(Duration::from_millis(150), rx.next()).await {
        out.push(item);
    }
    out
}

/// Build a VALID framed snapshot object capturing `store`'s CURRENT full state,
/// sealed at epoch 0 under `vault_key` and signed by `admin`. Unlike the
/// `build_admin_framed_snapshot` helper in `read_gate.rs` (which snapshots a
/// throwaway store), this snapshots the REAL store passed in, so a peer adopting
/// it reconstructs exactly this store's document. The store must already hold a
/// history marker (`write_snapshot`) so `build_backend_snapshot` has a frontier.
fn frame_full_snapshot(store: &Store, admin: &Identity, vault_key: &[u8; 32]) -> Vec<u8> {
    let snap = store
        .build_backend_snapshot(i64::MAX)
        .unwrap()
        .expect("a snapshot at the head marker");
    let vk = VaultKey(*vault_key);
    let sealed = vk.seal(&snap.bytes);
    let manifest = SnapshotManifest {
        frontier_digest: snap.frontier_digest,
        snapshot_ct_hash: blake3::hash(&sealed).into(),
        subsumed_entry_ids: Vec::new(),
        blob_ref_ids: Vec::new(),
        author: 0, // overwritten by `.signed()` to `admin.peer_id()`
        sig: String::new(),
    }
    .signed(admin);
    let manifest_json = serde_json::to_vec(&manifest).unwrap();
    frame(&manifest_json, &sealed)
}

/// Same as `read_gate.rs::build_admin_framed_snapshot`, but the signer is
/// arbitrary — used by test 3 to have a WRITER (not an Admin) self-sign a
/// well-formed object. Everything is valid (frame, self-signature, ct-hash,
/// decryptable at epoch 0) EXCEPT that the author is not an Admin.
fn build_framed_snapshot_signed_by(signer: &Identity, vault_key: &[u8; 32]) -> Vec<u8> {
    let dir = tempdir().unwrap();
    let mut store = Store::open(dir.path(), signer.clone()).unwrap();
    store.declare_founder(Role::Admin).unwrap();
    store.set_entry(MAP, "fabricated", "value").unwrap();
    store.write_snapshot().unwrap();
    frame_full_snapshot(&store, signer, vault_key)
}

/// Engine + its endpoint's inbox stream. We drive `handle()` by hand and read
/// what the engine emits from `inbox`, never spawning `run()`.
struct Node {
    engine: Arc<Engine<MemoryTransport>>,
    inbox: BoxStream<'static, (u64, Frame)>,
}

impl Node {
    fn new(board: &MemorySwitchboard, id: &Identity, vault: VaultId, store: Store) -> Self {
        let transport = Arc::new(board.endpoint(id.peer_id()));
        let inbox = transport.incoming();
        let engine = Arc::new(Engine::new(
            id.clone(),
            vault,
            store,
            transport,
            VAULT_KEY,
        ));
        Node { engine, inbox }
    }

    async fn entry(&self, key: &str) -> Option<String> {
        self.engine.store().lock().await.get_entry(MAP, key)
    }

    async fn held(&self) -> Vec<String> {
        self.engine
            .store()
            .lock()
            .await
            .held_snapshot_ids()
            .unwrap()
    }
}

/// Seed a full, checkpoint-compacted Admin store for A: three map entries, a head
/// marker, a framed snapshot persisted on disk, then a checkpoint that truncates
/// A's own op-log. Returns `(store, expected_entries)`. After this, A's op-log
/// replayed ALONE reconstructs nothing (the compaction stall), but A's in-memory
/// doc — and its held framed snapshot — carry the full state.
fn seed_compacted_admin(id: &Identity) -> Store {
    let dir = tempdir().unwrap();
    // Persist the tempdir so the on-disk vault outlives this function (the Store
    // keeps reading the path for held-snapshot serves; the OS cleans /tmp between
    // runs). `keep` hands us the PathBuf and disarms the auto-delete.
    let path = dir.keep();
    let mut store = Store::open(&path, id.clone()).unwrap();
    store.declare_founder(Role::Admin).unwrap();

    // Real document state: three distinct map entries, each its own op-log line.
    store.set_entry(MAP, "a", "1").unwrap();
    store.set_entry(MAP, "b", "2").unwrap();
    store.set_entry(MAP, "c", "3").unwrap();

    // Pin a history marker at the current head, then build + persist an
    // Admin-signed framed snapshot of the full {a,b,c} state.
    store.write_snapshot().unwrap();
    let framed = frame_full_snapshot(&store, id, &VAULT_KEY);
    let snap_id = BlobStore::hash(&framed);
    store.persist_snapshot_object(&snap_id, &framed).unwrap();

    // Checkpoint to the head marker: this truncates A's own op-log to the
    // retained tail. Because the marker is AT head, the entire own-log prefix is
    // subsumed and dropped — a fresh peer replaying the remaining (empty) log
    // cannot reconstruct {a,b,c}. That is the compaction-frontier stall this
    // feature fixes.
    store.checkpoint(i64::MAX).unwrap();

    store
}

/// Sanity: after `seed_compacted_admin`, A's own op-log no longer reconstructs
/// its doc (a fresh store replaying it stays empty), yet A still holds the
/// framed snapshot. This proves the stall fixture is genuine BEFORE any engine
/// wiring.
#[test]
fn seeded_admin_oplog_alone_does_not_reconstruct_the_doc() {
    let ia = Identity::generate();
    let ib = Identity::generate();
    let sa = seed_compacted_admin(&ia);

    // A's doc has the full state and A holds its framed snapshot.
    assert_eq!(sa.get_entry(MAP, "a").as_deref(), Some("1"));
    assert!(
        !sa.held_snapshot_ids().unwrap().is_empty(),
        "A must hold the framed snapshot"
    );

    // Replay A's own op-log ALONE into a fresh peer store. The compaction
    // truncated the log, so the replay does NOT reconstruct {a,b,c}.
    let a_log = sa.export_own_log().unwrap();
    let db = tempdir().unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    let key = roam_storage::VerifyingKey::from_bytes(&ia.verifying_key().to_bytes()).unwrap();
    let _ = sb.apply_peer_ops(ia.peer_id(), &key, &a_log);

    assert_eq!(
        sb.get_entry(MAP, "a"),
        None,
        "replaying A's compacted op-log alone must NOT reconstruct its doc (the stall)"
    );
}

#[tokio::test]
async fn p2p_snapshot_lets_a_lagging_peer_converge_past_a_compaction_frontier() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (ia, ib) = (Identity::generate(), Identity::generate());

    // A: full state, checkpoint-compacted, holding an Admin-signed framed snapshot.
    let mut sa = seed_compacted_admin(&ia);
    // A vouches for B as Active Admin (serve gates require an active peer).
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)
        .unwrap();

    // Fresh B on the SAME vault key; B lists A as Active Admin (author gate).
    let db = tempdir().unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    let behind_version = sb.doc_version_bytes();

    let mut a = Node::new(&board, &ia, vault, sa);
    let mut b = Node::new(&board, &ib, vault, sb);

    // A answers B's (behind) Have: it pushes its own op-log (truncated!) and
    // advertises its held snapshot. A's responses land in B's inbox.
    a.engine
        .handle(ib.peer_id(), Frame::Have { doc_version: behind_version.clone() })
        .await
        .unwrap();
    let from_a = drain(&mut b.inbox).await;

    // ---- PART 1: prove the stall. Deliver ONLY the Ops frames to B (not the
    // snapshot advert). From the compacted op-log alone, B cannot converge.
    let mut advert: Option<Frame> = None;
    for (_from, fr) in from_a {
        match fr {
            Frame::Ops { .. } => b.engine.handle(ia.peer_id(), fr).await.unwrap(),
            Frame::SnapshotHave { .. } => advert = Some(fr),
            _ => {}
        }
    }
    assert_eq!(
        b.entry("a").await,
        None,
        "PART 1: B converged from Ops alone — the compaction stall was not reproduced"
    );

    // ---- PART 2: run the snapshot negotiation. B handles the advert -> Want to
    // A -> A serves Data -> B adopts.
    let advert = advert.expect("A must advertise its held snapshot to a behind peer");
    b.engine.handle(ia.peer_id(), advert).await.unwrap();

    // B -> A: SnapshotWant(s) land in A's inbox.
    for (_from, fr) in drain(&mut a.inbox).await {
        if matches!(fr, Frame::SnapshotWant { .. }) {
            a.engine.handle(ib.peer_id(), fr).await.unwrap();
        }
    }
    // A -> B: SnapshotData lands in B's inbox; B adopts.
    for (_from, fr) in drain(&mut b.inbox).await {
        if matches!(fr, Frame::SnapshotData { .. }) {
            b.engine.handle(ia.peer_id(), fr).await.unwrap();
        }
    }

    // B now equals A: every entry present and equal, and B holds the object.
    for key in ["a", "b", "c"] {
        assert_eq!(
            b.entry(key).await,
            a.entry(key).await,
            "B did not converge to A's entry {key:?} after adopting the snapshot"
        );
    }
    assert_eq!(b.entry("a").await.as_deref(), Some("1"));
    assert!(
        !b.held().await.is_empty(),
        "B must persist the adopted snapshot for re-serving"
    );
}

#[tokio::test]
async fn a_writer_relays_an_admin_signed_snapshot_to_a_third_peer_with_no_admin_online() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (ia, ib, ic) = (
        Identity::generate(),
        Identity::generate(),
        Identity::generate(),
    );

    // A (Admin) holds a framed snapshot of full state {a,b,c}.
    let mut sa = seed_compacted_admin(&ia);
    // A vouches for B (a Writer, in A's view) as Active so it will serve B.
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Writer)
        .unwrap();

    // B: own store (Admin so it can vouch for C), lists A as Active Admin (author
    // gate) and, later, C as Active so it can re-serve C.
    let db = tempdir().unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sb.add_peer(ic.peer_id(), ic.verifying_key().to_bytes(), Role::Writer)
        .unwrap();
    let b_behind = sb.doc_version_bytes();

    // C: fresh, lists A as the ORIGINAL Active Admin signer, and B (Writer) as the
    // Active relayer it will actually receive bytes from. Same vault key.
    let dc = tempdir().unwrap();
    let mut sc = Store::open(dc.path(), ic.clone()).unwrap();
    sc.declare_founder(Role::Admin).unwrap();
    sc.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    sc.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Writer)
        .unwrap();
    let c_behind = sc.doc_version_bytes();

    let mut a = Node::new(&board, &ia, vault, sa);
    let mut b = Node::new(&board, &ib, vault, sb);
    let mut c = Node::new(&board, &ic, vault, sc);

    // ---- Phase 1: A serves B; B adopts A's Admin-signed object.
    // A's responses land in B's inbox; B's Want lands in A's inbox.
    a.engine
        .handle(ib.peer_id(), Frame::Have { doc_version: b_behind })
        .await
        .unwrap();
    for (_f, fr) in drain(&mut b.inbox).await {
        if matches!(fr, Frame::SnapshotHave { .. }) {
            b.engine.handle(ia.peer_id(), fr).await.unwrap();
        }
    }
    for (_f, fr) in drain(&mut a.inbox).await {
        if matches!(fr, Frame::SnapshotWant { .. }) {
            a.engine.handle(ib.peer_id(), fr).await.unwrap();
        }
    }
    for (_f, fr) in drain(&mut b.inbox).await {
        if matches!(fr, Frame::SnapshotData { .. }) {
            b.engine.handle(ia.peer_id(), fr).await.unwrap();
        }
    }
    assert!(
        !b.held().await.is_empty(),
        "B (Writer) must hold the adopted Admin-signed object for re-serving"
    );
    assert_eq!(b.entry("a").await.as_deref(), Some("1"), "B must converge to A's state");

    // ---- A goes OFFLINE: drop its engine + endpoint. From here only B and C
    // route/exchange frames; A never participates again.
    drop(a);

    // ---- Phase 2: fresh C pairs with B; B (no Admin online) re-serves the SAME
    // Admin-signed object. C verifies A's (original) signature and adopts.
    // B's responses land in C's inbox; C's Want lands in B's inbox.
    b.engine
        .handle(ic.peer_id(), Frame::Have { doc_version: c_behind })
        .await
        .unwrap();
    for (_f, fr) in drain(&mut c.inbox).await {
        if matches!(fr, Frame::SnapshotHave { .. }) {
            c.engine.handle(ib.peer_id(), fr).await.unwrap();
        }
    }
    for (_f, fr) in drain(&mut b.inbox).await {
        if matches!(fr, Frame::SnapshotWant { .. }) {
            b.engine.handle(ic.peer_id(), fr).await.unwrap();
        }
    }
    for (_f, fr) in drain(&mut c.inbox).await {
        if matches!(fr, Frame::SnapshotData { .. }) {
            c.engine.handle(ib.peer_id(), fr).await.unwrap();
        }
    }

    assert!(
        !c.held().await.is_empty(),
        "C must adopt+hold the object relayed by a non-Admin with no Admin online"
    );
    for (key, val) in [("a", "1"), ("b", "2"), ("c", "3")] {
        assert_eq!(
            c.entry(key).await.as_deref(),
            Some(val),
            "C did not converge to A's original state via B's relay (entry {key:?})"
        );
    }
}

#[tokio::test]
async fn a_writer_fabricated_snapshot_is_rejected_by_the_receiver_author_gate() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let (ib, ic) = (Identity::generate(), Identity::generate());

    // B (a Writer, in C's view) fabricates + SELF-SIGNS a well-formed object over
    // the shared vault key: valid frame, valid self-signature, valid ct-hash,
    // decryptable at epoch 0. The ONLY thing wrong is that B is not an Admin.
    let framed = build_framed_snapshot_signed_by(&ib, &VAULT_KEY);
    let snap_id = BlobStore::hash(&framed);

    // B's store lists C as Active so B will serve it; B persists the fabricated
    // object so a Want is answerable.
    let db = tempdir().unwrap();
    let mut sb = Store::open(db.path(), ib.clone()).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    sb.add_peer(ic.peer_id(), ic.verifying_key().to_bytes(), Role::Writer)
        .unwrap();
    sb.persist_snapshot_object(&snap_id, &framed).unwrap();

    // C lists B as a WRITER (Active) — so the transport/read gate passes, but B is
    // NOT in C's admin-author set, so the AUTHOR gate must reject.
    let dc = tempdir().unwrap();
    let mut sc = Store::open(dc.path(), ic.clone()).unwrap();
    sc.declare_founder(Role::Admin).unwrap();
    sc.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Writer)
        .unwrap();
    let before = sc.doc_version_bytes();

    let b = Node::new(&board, &ib, vault, sb);
    let mut c = Node::new(&board, &ic, vault, sc);

    // C asks B for the object; B serves the fabricated SnapshotData across the
    // wire — B's response lands in C's inbox, where C runs the author gate.
    b.engine
        .handle(ic.peer_id(), Frame::SnapshotWant { id: snap_id })
        .await
        .unwrap();
    let served = drain(&mut c.inbox).await;
    assert!(
        served.iter().any(|(_f, fr)| matches!(fr, Frame::SnapshotData { .. })),
        "B must actually serve the fabricated object across the wire (else the reject is vacuous)"
    );
    for (_f, fr) in served {
        if matches!(fr, Frame::SnapshotData { .. }) {
            c.engine.handle(ib.peer_id(), fr).await.unwrap();
        }
    }

    // The author gate holds across the wire: C holds nothing and does not adopt.
    assert!(
        c.held().await.is_empty(),
        "C adopted a non-Admin (Writer) fabricated snapshot"
    );
    assert_eq!(
        c.engine.store().lock().await.doc_version_bytes(),
        before,
        "a rejected fabricated snapshot must not advance C's document"
    );
    assert_eq!(
        c.entry("fabricated").await,
        None,
        "C must not adopt the fabricated state"
    );
}
