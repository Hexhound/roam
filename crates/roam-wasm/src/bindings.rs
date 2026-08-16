//! The `wasm_bindgen` shim. Pure delegation to [`Doc`] — no logic lives here,
//! so nothing in this file can be wrong in a way the native tests would miss.
//!
//! Compiled only for wasm32 (see `lib.rs`), which is why nothing else in the
//! workspace can accidentally depend on `wasm-bindgen`.

use crate::doc::Doc;
use roam_crdt::CrdtError;
use wasm_bindgen::prelude::*;

/// Route panic messages to `console.error` before the process aborts.
///
/// wasm32 panics are **aborts**, not unwinds. Without this hook a panic reaches
/// JS as a bare `RuntimeError: unreachable`, the message having never left the
/// module — and in a worker that abort also kills every pending reply, so the
/// page is left with unsettled promises and no diagnosis. This is not test
/// scaffolding: it is the only way a shipped browser build can say what went
/// wrong.
#[wasm_bindgen(start)]
pub fn report_panics() {
    std::panic::set_hook(Box::new(|info| console_error(&info.to_string())));
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(message: &str);
}

/// `CrdtError` carries no JS-meaningful structure, so it crosses the boundary
/// as its `Display` string. Callers get a normal JS `Error`.
fn to_js(error: CrdtError) -> JsError {
    JsError::new(&error.to_string())
}

#[wasm_bindgen(js_name = Doc)]
pub struct WasmDoc {
    inner: Doc,
}

#[wasm_bindgen(js_class = Doc)]
impl WasmDoc {
    /// `peerId` is a `u64`, so JS must pass a **BigInt** (`42n`), not a number.
    #[wasm_bindgen(constructor)]
    pub fn new(peer_id: u64) -> Result<WasmDoc, JsError> {
        Ok(WasmDoc {
            inner: Doc::new(peer_id).map_err(to_js)?,
        })
    }

    #[wasm_bindgen(js_name = insertText)]
    pub fn insert_text(&self, id: &str, pos: usize, s: &str) -> Result<(), JsError> {
        self.inner.insert_text(id, pos, s).map_err(to_js)
    }

    pub fn text(&self, id: &str) -> String {
        self.inner.text(id)
    }

    #[wasm_bindgen(js_name = setEntry)]
    pub fn set_entry(&self, map_id: &str, key: &str, value: &str) -> Result<(), JsError> {
        self.inner.set_entry(map_id, key, value).map_err(to_js)
    }

    #[wasm_bindgen(js_name = getEntry)]
    pub fn get_entry(&self, map_id: &str, key: &str) -> Option<String> {
        self.inner.get_entry(map_id, key)
    }

    pub fn commit(&self) {
        self.inner.commit()
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, JsError> {
        self.inner.snapshot().map_err(to_js)
    }

    pub fn import(&self, bytes: &[u8]) -> Result<(), JsError> {
        self.inner.import(bytes).map_err(to_js)
    }
}

// ---------------------------------------------------------------------------
// M3 — a whole vault, synced through the backend relay.
// ---------------------------------------------------------------------------

use crate::vault::Vault;
use std::sync::Arc;

/// `anyhow::Error` crosses the boundary as its `Display` string, same as
/// [`to_js`]. Sync failures are ordinary JS `Error`s.
fn any_to_js(error: anyhow::Error) -> JsError {
    JsError::new(&format!("{error:#}"))
}

/// A vault in the browser.
///
/// # SECURITY — read before wiring this to a UI
///
/// * `vaultKey` is the entire vault: it derives every id and opens every
///   payload. In a browser it is XSS-exposed, so it must be **derived per
///   session** (from a passphrase, or a WebAuthn/PRF secret) and **never**
///   written to `localStorage`/`sessionStorage`/IndexedDB in the clear.
/// * It must **never** be placed in a share-link URL fragment. A "click this
///   link to read my notes" flow needs a *reader-scoped* key, which does not
///   exist yet — that is F1 read-scoping. Until then a leaked link would be a
///   whole-vault compromise, so this API deliberately offers no link helper.
/// * Storage here is `MemFs`: correct, but gone when the tab closes. For a
///   durable vault use `Session.openOnOpfs`, which is what the worker runs; this
///   type remains for callers that genuinely want a scratch vault.
#[wasm_bindgen(js_name = Vault)]
pub struct WasmVault {
    inner: Vault,
}

#[wasm_bindgen(js_class = Vault)]
impl WasmVault {
    /// `vaultKey` must be exactly 32 bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(vault_key: &[u8]) -> Result<WasmVault, JsError> {
        let key: [u8; 32] = vault_key
            .try_into()
            .map_err(|_| JsError::new("vaultKey must be exactly 32 bytes"))?;
        Ok(WasmVault {
            inner: Vault::in_memory(key).map_err(any_to_js)?,
        })
    }

    /// A `u64`, so this reaches JS as a **BigInt**.
    #[wasm_bindgen(js_name = peerId)]
    pub async fn peer_id(&self) -> u64 {
        self.inner.peer_id().await
    }

    #[wasm_bindgen(js_name = verifyingKey)]
    pub async fn verifying_key(&self) -> Vec<u8> {
        self.inner.verifying_key().await.to_vec()
    }

    /// Vouch for another device. `peerId` must be passed as a BigInt.
    #[wasm_bindgen(js_name = addPeer)]
    pub async fn add_peer(&self, peer_id: u64, verifying_key: Vec<u8>) -> Result<(), JsError> {
        let key: [u8; 32] = verifying_key
            .try_into()
            .map_err(|_| JsError::new("verifyingKey must be exactly 32 bytes"))?;
        self.inner.add_peer(peer_id, key).await.map_err(any_to_js)
    }

    #[wasm_bindgen(js_name = setEntry)]
    pub async fn set_entry(
        &self,
        container: String,
        key: String,
        value: String,
    ) -> Result<(), JsError> {
        self.inner
            .set_entry(&container, &key, &value)
            .await
            .map_err(any_to_js)
    }

    #[wasm_bindgen(js_name = getEntry)]
    pub async fn get_entry(&self, container: String, key: String) -> Option<String> {
        self.inner.get_entry(&container, &key).await
    }

    #[wasm_bindgen(js_name = editText)]
    pub async fn edit_text(&self, id: String, at: usize, text: String) -> Result<(), JsError> {
        self.inner
            .edit_text(&id, at, &text)
            .await
            .map_err(any_to_js)
    }

    pub async fn text(&self, id: String) -> String {
        self.inner.text(&id).await
    }

    #[wasm_bindgen(js_name = writeSnapshot)]
    pub async fn write_snapshot(&self) -> Result<(), JsError> {
        self.inner.write_snapshot().await.map_err(any_to_js)
    }

    /// One reconcile pass against the relay at `baseUrl`, over `fetch`.
    ///
    /// Everything crossing the wire is ciphertext; the relay is untrusted by
    /// construction.
    pub async fn sync(&self, base_url: String) -> Result<(), JsError> {
        let backend = Arc::new(roam_backend_client::http::HttpBackend::new(&base_url));
        self.inner.sync(&backend).await.map_err(any_to_js)
    }
}

// ---------------------------------------------------------------------------
// M4 — a durable session, hosted in a dedicated Web Worker.
// ---------------------------------------------------------------------------

use crate::session::Session;
use roam_backend_client::http::HttpBackend;
use roam_storage::vfs_opfs::{self, OpfsPool};
use std::cell::RefCell;

/// How many slots to open at mount, and how many free ones to keep ahead of the
/// next command.
///
/// Both are starting values, not measured ones. What sets the floor is that a
/// vault's fixed files (identity, founder pin, roster and key logs, this
/// device's op log, the snapshot) are on the order of ten, and everything above
/// that is one slot per blob chunk. What sets `KEEP_FREE` is that a single
/// command must never be able to exhaust the pool: there is nowhere to `await` a
/// refill inside a synchronous `VaultFs` call, so exhaustion mid-command is a
/// provisioning bug, not a recoverable condition.
///
/// Opening a slot is one `createSyncAccessHandle`, so the mount cost is linear
/// in `MOUNT_CAPACITY` — the reason not to simply open a thousand.
const MOUNT_CAPACITY: usize = 64;
const KEEP_FREE: usize = 16;

/// A vault open on OPFS, driven by JSON commands.
///
/// This is what `worker/roam-worker.js` wraps, and it only works inside a
/// dedicated Web Worker: OPFS sync access handles do not exist on a document's
/// main thread. Constructing one from a page fails at [`open_on_opfs`] with a
/// message saying so.
///
/// [`open_on_opfs`]: WasmSession::open_on_opfs
#[wasm_bindgen(js_name = Session)]
pub struct WasmSession {
    /// Held for its lifetime, not just to grow: dropping an `OpfsPool` closes
    /// every sync access handle, and a closed pool's `VaultFs` cannot read.
    pool: OpfsPool,
    inner: Session<HttpBackend>,
    /// See [`WasmSession::take_reply_bytes`]. `RefCell` and not a lock because
    /// a worker is single-threaded and the borrow never spans an `await`.
    reply_bytes: RefCell<Option<Vec<u8>>>,
}

#[wasm_bindgen(js_class = Session)]
impl WasmSession {
    /// Open (or reopen) the vault `vaultKey` addresses, in this origin's OPFS.
    ///
    /// The pool directory is *derived from the vault key* rather than passed in.
    /// That is what makes reopening automatic — the same key finds the same
    /// files — and it keeps two vaults in one origin from colliding, which would
    /// not be a merge but a `NoModificationAllowedError` at mount. The derived
    /// name is the bucket id, which is already the opaque public name for this
    /// vault, so it discloses nothing that the relay does not already hold.
    #[wasm_bindgen(js_name = openOnOpfs)]
    pub async fn open_on_opfs(vault_key: &[u8], relay_url: String) -> Result<WasmSession, JsError> {
        let key: [u8; 32] = vault_key
            .try_into()
            .map_err(|_| JsError::new("vaultKey must be exactly 32 bytes"))?;

        let bucket = roam_backend_client::crypto::VaultKey(key).bucket_id();
        let pool = vfs_opfs::mount(&format!(".roam-{bucket}"), MOUNT_CAPACITY)
            .await
            .map_err(|e| JsError::new(&format!("mount OPFS pool: {e}")))?;

        let vault = Vault::open(pool.fs(), key).map_err(any_to_js)?;
        Ok(WasmSession {
            pool,
            inner: Session::new(vault, Arc::new(HttpBackend::new(&relay_url))),
            reply_bytes: RefCell::new(None),
        })
    }

    /// Handle one JSON request, returning the JSON reply.
    ///
    /// The pool is topped up *here*, between commands, because this is the only
    /// place in the whole design where awaiting is possible: `VaultFs` is
    /// synchronous, and opening an OPFS handle is not. Growth failing is
    /// reported as an error rather than ignored — a command run against a pool
    /// that could not grow would fail later with `StorageFull`, and blaming the
    /// write is much less useful than blaming the quota.
    ///
    /// NOT RE-ENTRANT. Two overlapping calls would both observe the same pool
    /// capacity across the `await` and then try to open the same slot index;
    /// OPFS enforces exclusivity, so the second fails with
    /// `NoModificationAllowedError`. `worker/roam-worker.js` serializes requests
    /// for this reason.
    pub async fn handle(&self, request: String) -> String {
        if let Err(e) = self.pool.ensure_free(KEEP_FREE).await {
            return format!(
                r#"{{"id":null,"error":"could not reserve storage before the command: {e}"}}"#
            );
        }
        self.inner.handle_json(&request).await
    }

    /// The same, for the commands that carry binary.
    ///
    /// Split from [`handle`] rather than folded into it because `wasm_bindgen`
    /// gives no way to return two values: the reply's bytes have to be fetched
    /// separately. They are stashed on `self` between the two calls, which is
    /// safe for exactly the reason the queue exists — one command at a time.
    ///
    /// [`handle`]: WasmSession::handle
    #[wasm_bindgen(js_name = handleWithBytes)]
    pub async fn handle_with_bytes(&self, request: String, payload: Option<Vec<u8>>) -> String {
        if let Err(e) = self.pool.ensure_free(KEEP_FREE).await {
            return format!(
                r#"{{"id":null,"error":"could not reserve storage before the command: {e}"}}"#
            );
        }
        let reply = self.inner.handle(&request, payload).await;
        *self.reply_bytes.borrow_mut() = reply.bytes;
        reply.json
    }

    /// The binary half of the last [`handle_with_bytes`] reply, if it had one.
    ///
    /// Taken, not copied: calling this twice gives `undefined` the second time,
    /// so a large attachment is not held alive by the session after the page has
    /// read it.
    ///
    /// [`handle_with_bytes`]: WasmSession::handle_with_bytes
    #[wasm_bindgen(js_name = takeReplyBytes)]
    pub fn take_reply_bytes(&self) -> Option<Vec<u8>> {
        self.reply_bytes.borrow_mut().take()
    }
}

/// The relay bucket a vault key addresses.
///
/// Exposed because it is genuinely opaque: it is *derived* from the vault key,
/// never chosen, which is why the relay cannot correlate a bucket with a user or
/// a document name.
#[wasm_bindgen(js_name = bucketId)]
pub fn bucket_id(vault_key: &[u8]) -> Result<String, JsError> {
    let key: [u8; 32] = vault_key
        .try_into()
        .map_err(|_| JsError::new("vaultKey must be exactly 32 bytes"))?;
    Ok(roam_backend_client::crypto::VaultKey(key).bucket_id())
}
