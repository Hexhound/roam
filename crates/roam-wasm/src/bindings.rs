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
