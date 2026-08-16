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
    /// The relay this session was opened against, kept so [`host_invite`] mints
    /// an invite naming it. Reusing the session's relay rather than taking a
    /// second one keeps a device from hosting a pairing on a relay it does not
    /// itself sync through — a mismatch that pairs successfully and then never
    /// converges.
    ///
    /// [`host_invite`]: WasmSession::host_invite
    relay: String,
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
            relay: relay_url,
        })
    }

    /// Join somebody else's vault through a relay mailbox, then open it.
    ///
    /// This is how a browser gets *into* a vault at all. A tab has no UDP
    /// socket, so it can never be an iroh peer and neither of the other two
    /// pairing flows can reach it; the handshake runs over the relay instead.
    /// `invite` is the string the host printed, `code` the six digits it showed.
    ///
    /// # Why the handshake finishes before any storage is touched
    ///
    /// The OPFS pool is named after the bucket id, and the bucket id is derived
    /// from the vault key — which arrives *in* the accept. So there is nowhere
    /// to put a store until pairing has succeeded. That ordering is safe because
    /// the joiner's store is untouched until the accept is adopted: everything
    /// before it is network and cryptography. The identity is minted here and
    /// persisted by [`Vault::join`], so the key the host vouched for is the key
    /// this device keeps.
    ///
    /// A failed join therefore leaves nothing behind — no pool, no identity, no
    /// half-created vault to clean up.
    #[wasm_bindgen(js_name = joinOnOpfs)]
    pub async fn join_on_opfs(invite: String, code: String) -> Result<WasmSession, JsError> {
        let invite = roam_pairing::Invite::decode(&invite)
            .map_err(|e| JsError::new(&format!("invite: {e:#}")))?;
        let code = roam_pairing::PairingCode::parse(code.trim())
            .map_err(|e| JsError::new(&format!("code: {e}")))?;

        let identity = roam_storage::Identity::generate();
        let mailbox = roam_pairing::HttpMailbox::for_invite(&invite);
        let (accept, host_key) =
            roam_pairing::handshake::fetch_accept_via_mailbox(&identity, &mailbox, &invite, &code)
                .await
                .map_err(any_to_js)?;

        // Read the key out before the accept is consumed; it names the pool.
        let key = accept.vault_key;
        let bucket = roam_backend_client::crypto::VaultKey(key).bucket_id();
        let pool = vfs_opfs::mount(&format!(".roam-{bucket}"), MOUNT_CAPACITY)
            .await
            .map_err(|e| JsError::new(&format!("mount OPFS pool: {e}")))?;

        let vault = Vault::join(pool.fs(), identity, accept, &host_key).map_err(any_to_js)?;
        Ok(WasmSession {
            pool,
            inner: Session::new(vault, Arc::new(HttpBackend::new(&invite.relay))),
            reply_bytes: RefCell::new(None),
            relay: invite.relay,
        })
    }

    /// Host a pairing invite, letting one other device into this vault.
    ///
    /// The other half of [`join_on_opfs`], and the reason a browser is a
    /// first-class member rather than a guest: a tab that joined a vault can
    /// itself admit the next device, with no native host anywhere in the story.
    ///
    /// `show` is called with `(invite, code)` as soon as they exist and before
    /// this starts waiting. It has to be a callback: the joiner cannot begin
    /// until it has both, so returning them when the pairing completes would
    /// wait for something that can never happen.
    ///
    /// Resolves to the enrolled peer id, as a string — a peer id is a `u64` and
    /// JSON numbers are doubles, the same rule the command protocol follows.
    ///
    /// SECURITY: `code` is the only thing authenticating the joiner. It must
    /// reach them out of band (spoken, or read off the screen) and never travel
    /// beside the invite — an attacker holding both is the joiner.
    ///
    /// [`join_on_opfs`]: WasmSession::join_on_opfs
    #[wasm_bindgen(js_name = hostInvite)]
    pub async fn host_invite(
        &self,
        role: String,
        seconds: u32,
        show: js_sys::Function,
    ) -> Result<String, JsError> {
        let role: roam_storage::Role = role
            .parse()
            .map_err(|e| JsError::new(&format!("role: {e}")))?;
        let invite =
            roam_pairing::Invite::generate(&self.relay, self.inner.vault().verifying_key().await);

        let peer = self
            .inner
            .vault()
            .host_invite(
                roam_pairing::HttpMailbox::for_invite(&invite),
                invite,
                role,
                std::time::Duration::from_secs(seconds as u64),
                |code, invite| {
                    // A JS callback that throws must not take the pairing down
                    // with it: the host is mid-handshake and the store lock is
                    // held. The error is reported and the wait proceeds — a
                    // caller that never saw the code simply gets a timeout.
                    if let Err(e) = show.call2(
                        &JsValue::NULL,
                        &JsValue::from_str(&invite.encode()),
                        &JsValue::from_str(code.as_str()),
                    ) {
                        console_error(&format!("hostInvite's show callback threw: {e:?}"));
                    }
                },
            )
            .await
            .map_err(any_to_js)?;

        Ok(peer.to_string())
    }

    /// The vault key this session holds, so a joiner can reopen without pairing
    /// again.
    ///
    /// SECURITY: this is the entire vault. A founder passed it *in* to
    /// [`open_on_opfs`], so JS already held it there; a joiner did not have it
    /// until now, and handing it back is the only way the next page load can
    /// call `openOnOpfs`. Everything in this type's security note applies to it
    /// — in particular it must not be written to `localStorage` in the clear.
    ///
    /// [`open_on_opfs`]: WasmSession::open_on_opfs
    #[wasm_bindgen(js_name = vaultKey)]
    pub fn vault_key(&self) -> Vec<u8> {
        self.inner.vault().vault_key().to_vec()
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
