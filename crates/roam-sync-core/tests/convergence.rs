use proptest::prelude::*;
use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_sync_core::memory::MemorySwitchboard;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

// Pair a and b in the roster (Task-7 pairing wires this over the network; here
// we seed the roster directly to test the engine in isolation).
fn seed_pair(store: &mut Store, me: &Identity, peer: &Identity) {
    store
        .add_peer(peer.peer_id(), peer.verifying_key().to_bytes(), Role::Admin)
        .unwrap();
    let _ = me;
}

#[tokio::test]
async fn two_engines_converge_on_connect() {
    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let da = tempdir().unwrap();
    let db = tempdir().unwrap();
    let ida = Identity::generate();
    let idb = Identity::generate();

    let mut sa = Store::open(da.path(), ida.clone()).unwrap();
    let mut sb = Store::open(db.path(), idb.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    seed_pair(&mut sa, &ida, &idb);
    seed_pair(&mut sb, &idb, &ida);

    let ea = Arc::new(Engine::new(
        ida.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ida.peer_id())),
    ));
    let eb = Arc::new(Engine::new(
        idb.clone(),
        vault,
        sb,
        Arc::new(board.endpoint(idb.peer_id())),
    ));
    tokio::spawn(ea.clone().run());
    tokio::spawn(eb.clone().run());

    ea.edit_text("note", 0, "hello from A").await.unwrap();
    eb.edit_text("note", 0, "hello from B").await.unwrap();
    ea.connect(idb.peer_id()).await.unwrap();
    eb.connect(ida.peer_id()).await.unwrap();

    // Allow the async exchange to settle.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let ta = ea.store().lock().await.text("note");
    let tb = eb.store().lock().await.text("note");
    assert_eq!(ta, tb, "engines must converge");
    assert!(ta.contains('A') && ta.contains('B'), "no edit lost: {ta}");
}

#[tokio::test]
async fn keylog_gossips_a_rotated_epoch_to_a_trusted_peer() {
    // A rotates + wraps to B; gossip must carry A's key-log to B so B can
    // open A's epoch. Mirrors the roster-gossip convergence test.
    // id_key/epoch0 are arbitrary fixed test bytes, identical on both sides.
    let id_key = [0x1au8; 32];
    let epoch0 = [0x2bu8; 32];

    let board = MemorySwitchboard::new();
    let vault = VaultId::generate();
    let da = tempdir().unwrap();
    let db = tempdir().unwrap();
    let ida = Identity::generate();
    let idb = Identity::generate();

    let mut sa = Store::open(da.path(), ida.clone()).unwrap();
    let mut sb = Store::open(db.path(), idb.clone()).unwrap();
    sa.declare_founder(Role::Admin).unwrap();
    sb.declare_founder(Role::Admin).unwrap();
    // Cross-vouch: each engine vouches for the other.
    seed_pair(&mut sa, &ida, &idb);
    seed_pair(&mut sb, &idb, &ida);

    // A rotates to a fresh epoch and back-fills wraps to current members.
    let epoch = sa.rotate_epoch(&id_key, &epoch0, None).unwrap();
    sa.backfill_wraps(&id_key, &epoch0).unwrap();

    let ea = Arc::new(Engine::new(
        ida.clone(),
        vault,
        sa,
        Arc::new(board.endpoint(ida.peer_id())),
    ));
    let eb = Arc::new(Engine::new(
        idb.clone(),
        vault,
        sb,
        Arc::new(board.endpoint(idb.peer_id())),
    ));
    tokio::spawn(ea.clone().run());
    tokio::spawn(eb.clone().run());

    // Drive the mesh so KeylogOps flows A -> B.
    ea.connect(idb.peer_id()).await.unwrap();
    eb.connect(ida.peer_id()).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // B must now be able to open A's rotated epoch via the gossiped key-log.
    let kc_b = eb.store().lock().await.keychain(&id_key, &epoch0).unwrap();
    assert!(
        kc_b.epoch_key(&epoch).is_some(),
        "B must recover A's rotated epoch key via key-log gossip"
    );
}

/// A single random edit: which of the three engines authors it, and the (unique,
/// tracked) marker text inserted at the end of its "note".
#[derive(Clone, Debug)]
struct Edit {
    who: usize,
    text: String,
}

fn edits_strategy() -> impl Strategy<Value = Vec<Edit>> {
    prop::collection::vec(
        (0usize..3, "[a-z]{1,5}").prop_map(|(who, text)| Edit { who, text }),
        1..12,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Three engines on one switchboard, pairwise-seeded rosters, random insert
    /// edits across all three, then every pair connected. After settling all
    /// three must hold identical `note` text and no inserted marker may be lost.
    #[test]
    fn three_engines_converge_under_random_edits(edits in edits_strategy()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            const N: usize = 3;
            let board = MemorySwitchboard::new();
            let vault = VaultId::generate();

            let dirs: Vec<_> = (0..N).map(|_| tempdir().unwrap()).collect();
            let ids: Vec<Identity> = (0..N).map(|_| Identity::generate()).collect();

            // Pairwise-seed every roster: each engine vouches for the other two.
            let mut stores: Vec<Store> = Vec::with_capacity(N);
            for (i, dir) in dirs.iter().enumerate() {
                let mut store = Store::open(dir.path(), ids[i].clone()).unwrap();
                store.declare_founder(Role::Admin).unwrap();
                for (j, peer) in ids.iter().enumerate() {
                    if i != j {
                        store
                            .add_peer(peer.peer_id(), peer.verifying_key().to_bytes(), Role::Admin)
                            .unwrap();
                    }
                }
                stores.push(store);
            }

            let engines: Vec<Arc<Engine<_>>> = stores
                .into_iter()
                .enumerate()
                .map(|(i, store)| {
                    Arc::new(Engine::new(
                        ids[i].clone(),
                        vault,
                        store,
                        Arc::new(board.endpoint(ids[i].peer_id())),
                    ))
                })
                .collect();
            for e in &engines {
                tokio::spawn(e.clone().run());
            }

            // Apply the random edits, each appended at the end of its author's note.
            for e in &edits {
                let engine = &engines[e.who % N];
                let end = engine.store().lock().await.text("note").chars().count();
                engine.edit_text("note", end, &e.text).await.unwrap();
            }

            // Fully connect every ordered pair.
            for (i, engine) in engines.iter().enumerate() {
                for (j, peer) in ids.iter().enumerate() {
                    if i != j {
                        engine.connect(peer.peer_id()).await.unwrap();
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(300)).await;

            let texts: Vec<String> = {
                let mut out = Vec::with_capacity(N);
                for e in &engines {
                    out.push(e.store().lock().await.text("note"));
                }
                out
            };

            for t in &texts[1..] {
                prop_assert_eq!(t, &texts[0], "engines diverged: {:?}", texts);
            }
            // No inserted marker lost: every edit's chars are present.
            for e in &edits {
                for ch in e.text.chars() {
                    prop_assert!(
                        texts[0].contains(ch),
                        "lost inserted char {:?} from {:?}: {:?}",
                        ch,
                        e,
                        texts[0]
                    );
                }
            }
            let total: usize = edits.iter().map(|e| e.text.chars().count()).sum();
            prop_assert_eq!(texts[0].chars().count(), total, "char count mismatch");
            Ok(())
        })?;
    }
}
