//! The browser storage acceptance test, minus the browser.
//!
//! `vault_on_memfs.rs` proves a vault runs with no filesystem. This proves it
//! runs on the shape the *browser* backend actually has: a fixed pool of
//! pre-opened, byte-addressable slots, with the path map stored in the slots
//! themselves. See `docs/browser_storage_opfs.md` for why OPFS forces that
//! shape.
//!
//! The part `MemFs` structurally cannot test is the one that matters most here:
//! **a remount**. `MemFs` dies with the process, so "reopen the store" only ever
//! re-reads a map that never went away. Here the slots are handed to a brand-new
//! `SlotPool` that has to rebuild the whole path map from the bytes on the
//! slots — which is precisely what a new browser tab does to the same OPFS
//! files. A pool that kept its map only in memory passes every test in
//! `vault_on_memfs.rs` and loses the entire vault on tab close.
//!
//! What is left for a real browser to prove is therefore only the `Slot` impl:
//! five methods delegating to a sync access handle.

use roam_storage::vfs::VaultFs;
use roam_storage::vfs_pool::{Slot, SlotPool};
use roam_storage::{Identity, Role, Store};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

const ROOT: &str = "/vault";
const TEXT_ID: &str = "notes/hello.md";

/// A slot backed by a `Vec`, standing in for an OPFS sync access handle. The
/// operations a handle offers are exactly these five, which is why the trait is
/// this small.
#[derive(Default)]
struct VecSlot {
    bytes: Mutex<Vec<u8>>,
}

impl Slot for VecSlot {
    fn size(&self) -> io::Result<u64> {
        Ok(self.bytes.lock().unwrap().len() as u64)
    }

    fn truncate(&self, len: u64) -> io::Result<()> {
        self.bytes.lock().unwrap().resize(len as usize, 0);
        Ok(())
    }

    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.bytes.lock().unwrap();
        let start = (at as usize).min(bytes.len());
        let n = buf.len().min(bytes.len() - start);
        buf[..n].copy_from_slice(&bytes[start..start + n]);
        Ok(n)
    }

    fn write_at(&self, at: u64, buf: &[u8]) -> io::Result<()> {
        let mut bytes = self.bytes.lock().unwrap();
        let start = at as usize;
        if start + buf.len() > bytes.len() {
            bytes.resize(start + buf.len(), 0);
        }
        bytes[start..start + buf.len()].copy_from_slice(buf);
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

/// The persistent backing store, independent of any pool mounted over it.
fn backing_store(capacity: usize) -> Vec<Arc<VecSlot>> {
    (0..capacity)
        .map(|_| Arc::new(VecSlot::default()))
        .collect()
}

fn mount(slots: &[Arc<VecSlot>]) -> Arc<dyn VaultFs> {
    Arc::new(SlotPool::adopt(slots.to_vec()).expect("mount pool"))
}

#[test]
fn a_full_vault_lifecycle_survives_a_remount_of_the_pool() {
    let slots = backing_store(64);
    let identity = Identity::generate();

    let blob_hash = {
        let mut store = Store::open_with_fs(Path::new(ROOT), identity.clone(), mount(&slots))
            .expect("open vault on the slot pool");

        store.declare_founder(Role::Admin).expect("declare founder");
        store
            .edit_text(TEXT_ID, 0, "hello from the pool")
            .expect("edit text");
        store
            .set_entry("meta", "title", "Hello")
            .expect("set entry");
        let hash = store.blobs().put(b"blob payload").expect("put blob");
        store.write_snapshot().expect("write snapshot");

        hash
    };

    assert!(
        !Path::new(ROOT).exists(),
        "vault leaked onto the real filesystem"
    );

    // A whole new pool over the same slots: nothing carries over but the bytes,
    // so the path map has to be rebuilt from the slot headers alone.
    let reopened = Store::open_with_fs(Path::new(ROOT), identity.clone(), mount(&slots))
        .expect("reopen the vault on a freshly mounted pool");

    assert_eq!(reopened.text(TEXT_ID), "hello from the pool", "text lost");
    assert_eq!(
        reopened.get_entry("meta", "title").as_deref(),
        Some("Hello"),
        "map entry lost"
    );
    assert_eq!(
        reopened.blobs().get(&blob_hash).expect("get blob"),
        Some(b"blob payload".to_vec()),
        "blob lost"
    );
    assert_eq!(
        reopened.founder_pin(),
        Some(identity.peer_id()),
        "founder pin lost"
    );
    assert_eq!(reopened.self_role(), Some(Role::Admin), "role lost");
}

/// A vault does not just persist, it keeps *growing* across restarts. Three
/// sessions, each appending, because the op-log's append-only invariant is the
/// one a slot-recycling backend is most likely to break.
#[test]
fn edits_accumulate_across_repeated_remounts() {
    let slots = backing_store(64);
    let identity = Identity::generate();

    for word in ["one ", "two ", "three"] {
        let mut store =
            Store::open_with_fs(Path::new(ROOT), identity.clone(), mount(&slots)).expect("open");
        if store.founder_pin().is_none() {
            store.declare_founder(Role::Admin).expect("declare founder");
        }
        let at = store.text(TEXT_ID).chars().count();
        store.edit_text(TEXT_ID, at, word).expect("edit text");
    }

    let final_store =
        Store::open_with_fs(Path::new(ROOT), identity, mount(&slots)).expect("final open");
    assert_eq!(final_store.text(TEXT_ID), "one two three");
}

/// The store's own layout, seen through the pool. Same paths as every other
/// backend — a browser vault that keyed them differently would not be
/// interchangeable with a phone's.
#[test]
fn the_expected_paths_are_written_into_the_pool() {
    let slots = backing_store(64);
    let identity = Identity::generate();
    let peer_id = identity.peer_id();

    let pool = Arc::new(SlotPool::adopt(slots).expect("mount pool"));
    let mut store = Store::open_with_fs(Path::new(ROOT), identity, pool.clone()).expect("open");
    store.declare_founder(Role::Admin).expect("declare founder");
    store.edit_text(TEXT_ID, 0, "hi").expect("edit text");
    store.write_snapshot().expect("write snapshot");

    for expected in [
        "/vault/founder",
        &format!("/vault/ops/ops-{peer_id}.jsonl"),
        &format!("/vault/roster/roster-{peer_id}.jsonl"),
        "/vault/snapshots/snapshot.loro",
        "/vault/history/history.jsonl",
    ] {
        assert!(
            pool.exists(Path::new(expected)),
            "expected {expected} in the pool"
        );
    }

    // Atomic publish goes through a temp path; a `.tmp` still holding a slot
    // means a rename leaked one, and the pool is finite.
    let root = pool.read_dir(Path::new(ROOT)).expect("read root");
    assert!(
        !root.iter().any(|p| p.to_string_lossy().ends_with(".tmp")),
        "temporary files left in the pool: {root:?}"
    );
}
