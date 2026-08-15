//! The `wasm_bindgen` shim. Pure delegation to [`Doc`] — no logic lives here,
//! so nothing in this file can be wrong in a way the native tests would miss.
//!
//! Compiled only for wasm32 (see `lib.rs`), which is why nothing else in the
//! workspace can accidentally depend on `wasm-bindgen`.

use crate::doc::Doc;
use roam_crdt::CrdtError;
use wasm_bindgen::prelude::*;

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
/// * Storage is currently `MemFs`: correct, but gone when the tab closes.
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
