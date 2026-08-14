//! A whole roam vault, portable enough to run in a browser.
//!
//! This is the M3 join: M2's [`VaultFs`] seam supplies storage with no
//! filesystem, and `roam-backend-client` supplies sync over the encrypted relay.
//! Both halves are plain Rust here — `bindings` adds the `#[wasm_bindgen]` shim
//! and nothing else — so everything below is exercised by ordinary native tests
//! against `MemoryBackend`, and the JS harness only has to prove the *transport*
//! and the *runtime* work, not the logic.
//!
//! # Why a browser client is a relay leaf, not a mesh peer
//!
//! A browser cannot open raw UDP/QUIC, so it can never be an iroh peer. It syncs
//! exclusively through the backend relay. That is not a weakening of the threat
//! model: the `Backend` trait moves *already-encrypted* bytes and "never
//! encrypts or decrypts", so the relay learns ciphertext and opaque ids either
//! way. It does mean the web client always requires a running backend.
//!
//! # Storage
//!
//! [`Vault::in_memory`] runs on `MemFs`, which is real and correct but *not*
//! durable — closing the tab loses the vault. The durable browser backend is an
//! OPFS `VaultFs` implementation, which is deliberately still to come; see the
//! handoff doc. Storage is a constructor argument precisely so that swap is a
//! one-line change here.

use roam_backend_client::crypto::VaultKey;
use roam_backend_client::sync::reconcile_once;
use roam_backend_client::transport::Backend;
use roam_storage::vfs::{MemFs, VaultFs};
use roam_storage::{Identity, Role, Store};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Where the vault lives inside the (non-filesystem) storage backend. Any path
/// works — `MemFs` and OPFS both treat it as an opaque key prefix.
const ROOT: &str = "/vault";

/// Cloning shares one vault (the store is behind an `Arc`), it does not copy
/// one. The `wasm_bindgen` async methods need an owned handle to move into the
/// returned future, which is the only reason this is `Clone`.
#[derive(Clone)]
pub struct Vault {
    store: Arc<Mutex<Store>>,
    key: VaultKey,
}

impl Vault {
    /// Open a vault on the given storage backend, founding it as Admin.
    ///
    /// `vault_key` is the shared secret every device of a vault holds; it
    /// derives the bucket id and the content keys, so two `Vault`s built with
    /// the same bytes address the same backend bucket.
    ///
    /// SECURITY: this key is the whole vault. It must never be persisted in
    /// `localStorage` or handed over in a URL fragment — see the module notes in
    /// `bindings` and the handoff doc's F1 dependency.
    pub fn open(fs: Arc<dyn VaultFs>, vault_key: [u8; 32]) -> anyhow::Result<Self> {
        let mut store = Store::open_with_fs(Path::new(ROOT), Identity::generate(), fs)?;
        // Founding as Admin mirrors the native e2e setup: a device's own vouch
        // must fold before its local writes are permitted.
        store.declare_founder(Role::Admin)?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            key: VaultKey(vault_key),
        })
    }

    /// A vault backed by `MemFs` — correct, but lost when the tab closes.
    pub fn in_memory(vault_key: [u8; 32]) -> anyhow::Result<Self> {
        Self::open(Arc::new(MemFs::new()), vault_key)
    }

    pub async fn peer_id(&self) -> u64 {
        self.store.lock().await.peer_id()
    }

    pub async fn verifying_key(&self) -> [u8; 32] {
        self.store.lock().await.identity_verifying_bytes()
    }

    /// Vouch for another device so its ops are accepted on import.
    pub async fn add_peer(&self, peer_id: u64, verifying_key: [u8; 32]) -> anyhow::Result<()> {
        self.store
            .lock()
            .await
            .add_peer(peer_id, verifying_key, Role::Admin)?;
        Ok(())
    }

    pub async fn set_entry(&self, container: &str, key: &str, value: &str) -> anyhow::Result<()> {
        self.store.lock().await.set_entry(container, key, value)?;
        Ok(())
    }

    pub async fn get_entry(&self, container: &str, key: &str) -> Option<String> {
        self.store.lock().await.get_entry(container, key)
    }

    pub async fn edit_text(&self, id: &str, at: usize, text: &str) -> anyhow::Result<()> {
        self.store.lock().await.edit_text(id, at, text)?;
        Ok(())
    }

    pub async fn text(&self, id: &str) -> String {
        self.store.lock().await.text(id)
    }

    /// Write a local checkpoint snapshot.
    ///
    /// Worth exercising in the browser specifically: this is the one vault
    /// operation that reads the wall clock (it stamps a history marker), and
    /// `SystemTime::now()` *traps* on wasm32 rather than returning a wrong
    /// answer. See `roam_storage::wallclock`.
    pub async fn write_snapshot(&self) -> anyhow::Result<()> {
        self.store.lock().await.write_snapshot()?;
        Ok(())
    }

    /// One full reconcile pass against the relay: push what it lacks, pull what
    /// we lack. Everything crossing the wire is ciphertext.
    pub async fn sync<B: Backend>(&self, backend: &Arc<B>) -> anyhow::Result<()> {
        reconcile_once(&self.store, backend, &self.key).await
    }
}
