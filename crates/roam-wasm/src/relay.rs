//! A relay **test double**, exported to JS so the node harness can be a real
//! HTTP server without reimplementing anything.
//!
//! Behind the `test-relay` cargo feature, so the shipped browser artifact cannot
//! contain it.
//!
//! # Why this exists
//!
//! The node acceptance test needs a server on the other end of `fetch`. Writing
//! one in JavaScript would mean reimplementing negentropy set-reconciliation in
//! JavaScript — a large, subtle, untested pile of code whose bugs would show up
//! as failures of the thing under test. Instead the harness reuses
//! [`MemoryBackend`], which already "mirrors the real server's dedup semantics"
//! and is covered by its own unit tests, and the JS side is reduced to ~50 lines
//! of routing.
//!
//! What this test therefore proves: the client half, the encryption, the RBSR
//! protocol, `fetch`, and real HTTP over a real socket. What it does NOT prove:
//! that the production Elixir backend agrees — that is
//! `roam-backend-client/tests/e2e_backend.rs`, which runs the real Phoenix
//! server. The two tests are complementary and neither replaces the other.

use roam_backend_client::transport::{Backend, MemoryBackend, SetKind};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

fn kind(name: &str) -> Result<SetKind, JsError> {
    match name {
        "entries" => Ok(SetKind::Entries),
        "blobs" => Ok(SetKind::Blobs),
        "snapshots" => Ok(SetKind::Snapshots),
        other => Err(JsError::new(&format!("unknown reconcile set {other}"))),
    }
}

fn err(error: anyhow::Error) -> JsError {
    JsError::new(&format!("{error:#}"))
}

#[wasm_bindgen(js_name = TestRelay)]
pub struct WasmTestRelay {
    inner: Arc<MemoryBackend>,
}

#[wasm_bindgen(js_class = TestRelay)]
impl WasmTestRelay {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmTestRelay {
        WasmTestRelay {
            inner: Arc::new(MemoryBackend::default()),
        }
    }

    /// The manifest as a JSON string, exactly as the HTTP route serves it.
    pub async fn manifest(&self, bucket: String) -> Result<String, JsError> {
        let manifest = self.inner.manifest(&bucket).await.map_err(err)?;
        serde_json::to_string(&manifest).map_err(|e| JsError::new(&e.to_string()))
    }

    /// `None` becomes JS `undefined`, which the harness maps to HTTP 404.
    pub async fn get(
        &self,
        bucket: String,
        set: String,
        id: String,
    ) -> Result<Option<Vec<u8>>, JsError> {
        match kind(&set)? {
            SetKind::Entries => self.inner.get_entry(&bucket, &id).await,
            SetKind::Blobs => self.inner.get_blob(&bucket, &id).await,
            SetKind::Snapshots => self.inner.get_snapshot(&bucket, &id).await,
        }
        .map_err(err)
    }

    /// Returns true when newly created, false when the id already existed —
    /// the harness turns that into 201 vs 409, matching the real routes.
    pub async fn put(
        &self,
        bucket: String,
        set: String,
        id: String,
        body: Vec<u8>,
    ) -> Result<bool, JsError> {
        use roam_backend_client::transport::PutOutcome;
        let outcome = match kind(&set)? {
            SetKind::Entries => self.inner.put_entry(&bucket, &id, body).await,
            SetKind::Blobs => self.inner.put_blob(&bucket, &id, body).await,
            SetKind::Snapshots => self.inner.put_snapshot(&bucket, &id, body).await,
        }
        .map_err(err)?;
        Ok(outcome == PutOutcome::Created)
    }

    pub async fn reconcile(
        &self,
        bucket: String,
        set: String,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        self.inner
            .reconcile(&bucket, kind(&set)?, msg)
            .await
            .map_err(err)
    }

    /// How many payloads the relay is holding for `bucket` — lets the harness
    /// assert that data really crossed the wire rather than passing vacuously.
    #[wasm_bindgen(js_name = entryCount)]
    pub async fn entry_count(&self, bucket: String) -> Result<usize, JsError> {
        Ok(self
            .inner
            .manifest(&bucket)
            .await
            .map_err(err)?
            .entry_ids
            .len())
    }
}

impl Default for WasmTestRelay {
    fn default() -> Self {
        Self::new()
    }
}
