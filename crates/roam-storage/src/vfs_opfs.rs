//! The OPFS backing for [`crate::vfs_pool`] — the browser's durable storage.
//!
//! Everything interesting about the design lives in `vfs_pool`, which is plain
//! Rust and natively tested. This module is the part that can only exist in a
//! browser: five `Slot` methods delegating to a sync access handle, plus the
//! asynchronous mount that opens the handles in the first place.
//!
//! # This only works inside a dedicated Web Worker
//!
//! Measured in Chromium 150, not assumed: `createSyncAccessHandle` is **absent**
//! on a document's main thread — the property is `undefined`, so this is not a
//! permission that can be prompted for or a flag that can be enabled. It exists
//! only in a worker. [`mount`] therefore fails with a message saying so rather
//! than with a bare `TypeError`, because "is not a function" is a genuinely
//! confusing way to learn about a threading constraint.
//!
//! See `docs/browser_storage_opfs.md`.

use crate::vfs_pool::{Slot, SlotPool};
use std::io;
use std::sync::Arc;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetDirectoryOptions,
    FileSystemGetFileOptions, FileSystemReadWriteOptions, FileSystemSyncAccessHandle,
};

/// Default directory inside the origin's OPFS root for the pool's backing
/// files. Their names are indices and carry no meaning; a slot's identity is the
/// vault path in its header.
pub const DEFAULT_POOL_DIR: &str = ".roam-pool";

fn js_err(context: &str, value: JsValue) -> io::Error {
    io::Error::other(format!("{context}: {value:?}"))
}

/// One pooled OPFS file, held open for the lifetime of the worker.
pub struct OpfsSlot {
    handle: FileSystemSyncAccessHandle,
}

// SAFETY: a `FileSystemSyncAccessHandle` is a JS value, and JS values are not
// `Send`/`Sync` in general because they belong to one agent. On wasm32 there is
// exactly one thread per agent and no way to move a value between agents except
// by structured clone, which this type never undergoes — a handle is created in
// the worker that owns this pool and only ever used there. `VaultFs: Send +
// Sync` is therefore satisfiable without lying about anything observable.
//
// Note this is a wrapper impl rather than a cfg'd bound on the trait, unlike
// `Backend`. That relaxation is sound only because `Backend` is always used as
// `B: Backend`; `Store` holds an `Arc<dyn VaultFs>`, and auto traits do not
// elaborate onto a trait object through a named supertrait, so cfg'ing the
// bound would not have worked here.
unsafe impl Send for OpfsSlot {}
unsafe impl Sync for OpfsSlot {}

impl OpfsSlot {
    fn at(offset: u64) -> FileSystemReadWriteOptions {
        let options = FileSystemReadWriteOptions::new();
        options.set_at(offset as f64);
        options
    }
}

impl Slot for OpfsSlot {
    fn size(&self) -> io::Result<u64> {
        self.handle
            .get_size()
            .map(|n| n as u64)
            .map_err(|e| js_err("getSize", e))
    }

    fn truncate(&self, len: u64) -> io::Result<()> {
        self.handle
            .truncate_with_f64(len as f64)
            .map_err(|e| js_err("truncate", e))
    }

    fn read_at(&self, at: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.handle
            .read_with_u8_array_and_options(buf, &Self::at(at))
            .map(|n| n as usize)
            .map_err(|e| js_err("read", e))
    }

    fn write_at(&self, at: u64, buf: &[u8]) -> io::Result<()> {
        let written = self
            .handle
            .write_with_u8_array_and_options(buf, &Self::at(at))
            .map(|n| n as usize)
            .map_err(|e| js_err("write", e))?;

        // A short write is how OPFS reports the storage quota being hit. Left
        // unchecked it would silently truncate an op-log append, which is the
        // one thing the whole storage layer is built not to do.
        if written != buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                format!(
                    "OPFS accepted {written} of {} bytes; the origin's storage \
                     quota is likely exhausted",
                    buf.len()
                ),
            ));
        }
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        self.handle.flush().map_err(|e| js_err("flush", e))
    }
}

impl Drop for OpfsSlot {
    fn drop(&mut self) {
        // A handle left open blocks every future `createSyncAccessHandle` on the
        // same file with `NoModificationAllowedError` — including the one a
        // reloaded tab makes. Not closing would make the vault unopenable until
        // the browser reaped the worker.
        self.handle.close();
    }
}

/// A mounted pool plus the directory handle it came from, so it can grow.
///
/// Growth is separate from the [`crate::vfs::VaultFs`] surface on purpose:
/// opening a slot needs an `await`, and no `VaultFs` method has one. The worker
/// calls [`OpfsPool::ensure_free`] between commands, where awaiting is free.
pub struct OpfsPool {
    dir: FileSystemDirectoryHandle,
    pool: Arc<SlotPool<OpfsSlot>>,
}

impl OpfsPool {
    /// The `VaultFs` to hand to `Store::open_with_fs`.
    pub fn fs(&self) -> Arc<SlotPool<OpfsSlot>> {
        self.pool.clone()
    }

    /// Open enough additional slots that at least `wanted` are free.
    ///
    /// Call this from the worker's message loop *before* dispatching a command,
    /// never from inside one. A command that exhausts the pool mid-way fails
    /// with `ErrorKind::StorageFull`, which is a provisioning bug to surface
    /// rather than a condition to recover from — there is nowhere to await.
    pub async fn ensure_free(&self, wanted: usize) -> io::Result<()> {
        while self.pool.free_slots() < wanted {
            let index = self.pool.capacity();
            self.pool.add_slot(open_slot(&self.dir, index).await?)?;
        }
        Ok(())
    }
}

async fn open_slot(dir: &FileSystemDirectoryHandle, index: usize) -> io::Result<OpfsSlot> {
    let options = FileSystemGetFileOptions::new();
    options.set_create(true);

    let file = JsFuture::from(dir.get_file_handle_with_options(&index.to_string(), &options))
        .await
        .map_err(|e| js_err("getFileHandle", e))?
        .unchecked_into::<FileSystemFileHandle>();

    let handle = JsFuture::from(file.create_sync_access_handle())
        .await
        .map_err(|e| {
            js_err(
                "createSyncAccessHandle (this must run in a dedicated Web \
                 Worker; the method does not exist on the main thread)",
                e,
            )
        })?
        .unchecked_into::<FileSystemSyncAccessHandle>();

    Ok(OpfsSlot { handle })
}

/// Open (or reopen) a vault's storage pool in the origin's OPFS.
///
/// `capacity` slots are opened up front. Reopening the same `dir` finds the same
/// backing files, and [`SlotPool::adopt`] rebuilds the path map from their
/// headers — that is what makes a browser vault survive a tab close.
///
/// `dir` is a parameter rather than a constant so one origin can hold more than
/// one pool. Two pools must never name the same directory: the second `mount`
/// would fail on `NoModificationAllowedError`, since the first still holds every
/// handle open.
///
/// Must be called from a dedicated Web Worker; see the module docs.
pub async fn mount(dir: &str, capacity: usize) -> io::Result<OpfsPool> {
    let storage = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("navigator"))
        .and_then(|navigator| js_sys::Reflect::get(&navigator, &JsValue::from_str("storage")))
        .map_err(|e| js_err("navigator.storage", e))?;

    let get_directory = js_sys::Reflect::get(&storage, &JsValue::from_str("getDirectory"))
        .map_err(|e| js_err("navigator.storage.getDirectory", e))?
        .unchecked_into::<js_sys::Function>();

    let root = JsFuture::from(
        get_directory
            .call0(&storage)
            .map_err(|e| js_err("getDirectory()", e))?
            .unchecked_into::<js_sys::Promise>(),
    )
    .await
    .map_err(|e| js_err("getDirectory", e))?
    .unchecked_into::<FileSystemDirectoryHandle>();

    let options = FileSystemGetDirectoryOptions::new();
    options.set_create(true);
    let dir = JsFuture::from(root.get_directory_handle_with_options(dir, &options))
        .await
        .map_err(|e| js_err("getDirectoryHandle", e))?
        .unchecked_into::<FileSystemDirectoryHandle>();

    let mut slots = Vec::with_capacity(capacity);
    for index in 0..capacity {
        slots.push(open_slot(&dir, index).await?);
    }

    Ok(OpfsPool {
        dir,
        pool: Arc::new(SlotPool::adopt(slots)?),
    })
}
