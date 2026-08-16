//! The browser half of the OPFS storage tests.
//!
//! Almost everything about the pool is plain Rust and already covered natively
//! (`roam-storage`: `vfs_pool` unit tests, `tests/vault_on_slot_pool.rs`). What
//! no native test can reach is the `Slot` impl over a real sync access handle —
//! five delegations whose semantics are the browser's, not ours. So these checks
//! deliberately assert the *browser's* behaviour, not roam's logic:
//!
//! * that `truncate` upward really zero-fills (the `Slot` contract says so; OPFS
//!   is what has to honour it),
//! * that bytes survive closing every handle and reopening the pool, which is
//!   the whole claim "a browser vault outlives the tab",
//! * that a pool can be grown after mount, which is how the worker avoids
//!   exhaustion.
//!
//! Compiled only under the `browser-test` feature so a shipped artifact cannot
//! contain a test suite.

use roam_storage::vfs::{conformance, VaultFs};
use roam_storage::vfs_opfs;
use roam_storage::{Identity, Role, Store};
use std::path::Path;
use wasm_bindgen::prelude::*;

const CAPACITY: usize = 48;

/// Route panic messages to `console.error` before the abort.
///
/// wasm32 panics are aborts, so a failed `assert!` inside [`conformance`]
/// surfaces in JS as a bare `RuntimeError: unreachable` with the message lost.
/// The harness captures `console.error` in the worker to recover it — without
/// this, a failing conformance check tells you nothing about which assertion
/// broke.
#[wasm_bindgen(start)]
pub fn report_panics() {
    std::panic::set_hook(Box::new(|info| {
        error(&info.to_string());
    }));
}

#[wasm_bindgen(js_namespace = console)]
extern "C" {
    fn error(message: &str);
}

fn js(e: std::io::Error) -> JsError {
    JsError::new(&e.to_string())
}

/// The suite every `VaultFs` backend must pass, run against real OPFS.
#[wasm_bindgen]
pub async fn opfs_conformance() -> Result<(), JsError> {
    let pool = vfs_opfs::mount("test-conformance", CAPACITY)
        .await
        .map_err(js)?;
    conformance(&*pool.fs(), Path::new("/vault"));
    Ok(())
}

/// The claim that justifies this whole module: a vault survives the tab.
///
/// Every handle is closed between the two mounts (dropping `OpfsPool` closes
/// them), so the second mount reads the path map back out of bytes that OPFS
/// persisted. Nothing is carried across in memory.
#[wasm_bindgen]
pub async fn opfs_survives_a_remount() -> Result<String, JsError> {
    const DIR: &str = "test-durability";
    const TEXT_ID: &str = "notes/hello.md";

    let identity = Identity::generate();

    let blob_hash = {
        let pool = vfs_opfs::mount(DIR, CAPACITY).await.map_err(js)?;
        let mut store = Store::open_with_fs(Path::new("/vault"), identity.clone(), pool.fs())
            .map_err(|e| JsError::new(&format!("open: {e}")))?;
        store
            .declare_founder(Role::Admin)
            .map_err(|e| JsError::new(&format!("declare_founder: {e}")))?;
        store
            .edit_text(TEXT_ID, 0, "written before the tab closed")
            .map_err(|e| JsError::new(&format!("edit_text: {e}")))?;
        store
            .set_entry("meta", "title", "Hello")
            .map_err(|e| JsError::new(&format!("set_entry: {e}")))?;
        let hash = store
            .blobs()
            .put(b"blob payload")
            .map_err(|e| JsError::new(&format!("put blob: {e}")))?;
        // Reads the wall clock, which *traps* on wasm32 unless it goes through
        // `roam_storage::wallclock`. Kept here for the same reason the M3 node
        // harness keeps its own: `cargo check` cannot see that trap.
        store
            .write_snapshot()
            .map_err(|e| JsError::new(&format!("write_snapshot: {e}")))?;
        hash
    };

    let pool = vfs_opfs::mount(DIR, CAPACITY).await.map_err(js)?;
    let reopened = Store::open_with_fs(Path::new("/vault"), identity.clone(), pool.fs())
        .map_err(|e| JsError::new(&format!("reopen: {e}")))?;

    expect(
        reopened.text(TEXT_ID) == "written before the tab closed",
        "text lost across the remount",
    )?;
    expect(
        reopened.get_entry("meta", "title").as_deref() == Some("Hello"),
        "map entry lost across the remount",
    )?;
    expect(
        reopened.blobs().get(&blob_hash).ok().flatten() == Some(b"blob payload".to_vec()),
        "blob lost across the remount",
    )?;
    expect(
        reopened.founder_pin() == Some(identity.peer_id()),
        "founder pin lost across the remount",
    )?;
    expect(
        reopened.self_role() == Some(Role::Admin),
        "role lost across the remount",
    )?;

    Ok(format!(
        "recovered text, map entry, blob, founder pin and role from {} slots",
        pool.fs().capacity()
    ))
}

/// `truncate` upward must zero-fill, because `create_sized` pre-sizes a blob and
/// then lets its chunks arrive out of order. A backend that left the gap
/// undefined would hand back whatever the previous tenant of that slot wrote —
/// and slots are recycled, so that is a real disclosure, not a theoretical one.
#[wasm_bindgen]
pub async fn opfs_presizes_with_zeroes() -> Result<(), JsError> {
    let pool = vfs_opfs::mount("test-presize", 8).await.map_err(js)?;
    let fs = pool.fs();
    let path = Path::new("/vault/blob.part");

    fs.write(path, &[0xAB; 4096]).map_err(js)?;
    fs.remove_file(path).map_err(js)?;

    fs.create_sized(path, 4096).map_err(js)?;
    let bytes = fs.read(path).map_err(js)?;

    expect(bytes.len() == 4096, "pre-sized file has the wrong length")?;
    expect(
        bytes.iter().all(|&b| b == 0),
        "a pre-sized region exposed a recycled slot's previous bytes",
    )
}

/// Growing the pool after mount — how the worker stays ahead of exhaustion.
#[wasm_bindgen]
pub async fn opfs_grows_after_mount() -> Result<String, JsError> {
    let pool = vfs_opfs::mount("test-growth", 2).await.map_err(js)?;
    let fs = pool.fs();

    fs.write(Path::new("/vault/a"), b"one").map_err(js)?;
    fs.write(Path::new("/vault/b"), b"two").map_err(js)?;
    expect(fs.free_slots() == 0, "pool should be full")?;

    let err = fs.write(Path::new("/vault/c"), b"three").unwrap_err();
    expect(
        err.kind() == std::io::ErrorKind::StorageFull,
        "exhaustion must be distinguishable, since it is the one error the \
         worker recovers from by growing",
    )?;

    pool.ensure_free(4).await.map_err(js)?;
    fs.write(Path::new("/vault/c"), b"three").map_err(js)?;

    expect(
        fs.read(Path::new("/vault/a")).map_err(js)? == b"one",
        "growing the pool disturbed an existing file",
    )?;

    Ok(format!("grew from 2 to {} slots", fs.capacity()))
}

fn expect(condition: bool, message: &str) -> Result<(), JsError> {
    if condition {
        Ok(())
    } else {
        Err(JsError::new(message))
    }
}
