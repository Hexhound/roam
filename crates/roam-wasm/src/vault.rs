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
//! durable — closing the tab loses the vault. [`Vault::open`] takes the backend
//! as an argument, so the durable browser path is the same code over
//! `roam_storage::vfs_opfs`; see `docs/browser_storage_opfs.md`.
//!
//! Durability is not just a swap of the `VaultFs`, though — it changes what
//! "open" has to mean. See [`Vault::open`].

use roam_backend_client::crypto::VaultKey;
use roam_backend_client::sync::reconcile_once;
use roam_backend_client::transport::Backend;
use roam_crdt::{Frontier, MapChange};
use roam_storage::vfs::{MemFs, VaultFs};
use roam_storage::{Identity, Role, Store, VaultId};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Where the vault lives inside the (non-filesystem) storage backend. Any path
/// works — `MemFs` and OPFS both treat it as an opaque key prefix.
const ROOT: &str = "/vault";

/// This device's signing key, inside the same storage backend as everything
/// else. On OPFS that means it never leaves the origin's private filesystem —
/// in particular it is never in `localStorage`, which is XSS-readable.
const IDENTITY: &str = "/vault/identity.key";

/// The vault's own 32-byte id, beside the identity.
///
/// Not derived from the vault key, and it cannot be: a joiner is *told* its
/// vault id by the host, in the accept, and two devices of one vault must agree
/// on it. So it is stored, and stored on both paths — a founder mints one, a
/// joiner writes down the one it was given. Without this a browser could join a
/// vault but never host anyone into it, having nothing to put in the accept.
const VAULT_ID: &str = "/vault/vault.id";

/// Cloning shares one vault (the store is behind an `Arc`), it does not copy
/// one. The `wasm_bindgen` async methods need an owned handle to move into the
/// returned future, which is the only reason this is `Clone`.
#[derive(Clone)]
pub struct Vault {
    store: Arc<Mutex<Store>>,
    key: VaultKey,
    /// The same identity the store holds. Kept alongside because hosting a
    /// pairing needs `&Identity` and `&mut Store` at once, and the store owns
    /// the identity it would have to lend.
    identity: Identity,
    vault_id: VaultId,
}

impl Vault {
    /// Open a vault on the given storage backend, creating it on first use.
    ///
    /// `vault_key` is the shared secret every device of a vault holds; it
    /// derives the bucket id and the content keys, so two `Vault`s built with
    /// the same bytes address the same backend bucket.
    ///
    /// SECURITY: this key is the whole vault. It must never be persisted in
    /// `localStorage` or handed over in a URL fragment — see the module notes in
    /// `bindings` and the handoff doc's F1 dependency.
    ///
    /// # Both steps here are conditional, and that is the point
    ///
    /// Until storage was durable this function could generate a fresh identity
    /// and declare a founder unconditionally, because every open *was* a first
    /// open — `MemFs` starts empty every time. Against OPFS both are wrong on
    /// the second open, and not subtly: a new identity every reload makes the
    /// device a stranger to its own op log, and `declare_founder` returns
    /// `"vault founder already pinned"`, so reopening would simply fail.
    ///
    /// This is the class of bug `MemFs` structurally cannot catch, which is why
    /// `tests/durable_vault.rs` runs against a remounted slot pool instead.
    ///
    /// A device that *joins* an existing vault must take [`Vault::join`], which
    /// does not found: founding here would pin this device as its own vault's
    /// founder, and the host's roster could then never fold over it. The two
    /// cases cannot be told apart from the arguments, so they are separate
    /// constructors rather than a flag.
    pub fn open(fs: Arc<dyn VaultFs>, vault_key: [u8; 32]) -> anyhow::Result<Self> {
        let identity = load_or_generate_identity(&fs)?;
        let vault_id = load_or_generate_vault_id(&fs)?;
        let mut store = Store::open_with_fs(Path::new(ROOT), identity.clone(), fs)?;
        if store.founder_pin().is_none() {
            // Founding as Admin mirrors the native e2e setup: a device's own
            // vouch must fold before its local writes are permitted.
            store.declare_founder(Role::Admin)?;
        }
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            key: VaultKey(vault_key),
            identity,
            vault_id,
        })
    }

    /// Adopt a pairing accept into a fresh store, joining somebody else's vault.
    ///
    /// The counterpart to [`Vault::open`], and the reason the two are separate:
    /// this one must NOT `declare_founder`. A joiner that founded would pin
    /// itself as the founder of a vault it did not create, and the host's roster
    /// — anchored on the real founder — could never fold over it. The device
    /// would hold a vault nobody else recognised.
    ///
    /// The accept is applied through [`roam_pairing::adopt_accept`], so the
    /// browser gets exactly the import order every other platform gets: founder
    /// pin, then transitive roster, then key log.
    ///
    /// Takes the already-fetched accept rather than running the handshake,
    /// because the handshake has to finish *before* there is anywhere to put a
    /// store: this vault's OPFS pool is named after the bucket id, which is
    /// derived from the vault key the accept carries. See
    /// [`roam_pairing::handshake::fetch_accept_via_mailbox`].
    pub fn join(
        fs: Arc<dyn VaultFs>,
        identity: Identity,
        accept: roam_pairing::JoinAccept,
        host_key: &roam_storage::VerifyingKey,
    ) -> anyhow::Result<Self> {
        // Persist the identity that ran the handshake — it is the key the host
        // just vouched for, so a different one on the next open would be a
        // stranger to the roster this join created.
        identity.save_with_fs(&*fs, Path::new(IDENTITY))?;
        let mut store = Store::open_with_fs(Path::new(ROOT), identity.clone(), Arc::clone(&fs))?;
        let joined = roam_pairing::adopt_accept(&mut store, accept, host_key)?;
        // The host's vault id, not one of our own: this device must name the
        // vault the same way every other member does, or an invite it later
        // hosts would enrol somebody into a vault that does not exist.
        fs.write(Path::new(VAULT_ID), &joined.vault.0)?;

        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            key: VaultKey(*joined.vault_key),
            identity,
            vault_id: joined.vault,
        })
    }

    /// Host a pairing over a relay mailbox, letting one device in.
    ///
    /// The mirror of [`Vault::join`], and the same flow `Engine::host_invite`
    /// runs natively. A browser can host as well as join: nothing about the
    /// mailbox flow needs a socket, which is the whole reason it exists.
    ///
    /// `show` is called with the code and the invite *before* this starts
    /// waiting, and that ordering is not cosmetic — the joiner cannot begin
    /// until it has both, so a version that returned them at the end would
    /// deadlock. It is a callback rather than a return value for the same
    /// reason.
    ///
    /// Returns the peer id enrolled. Holds the store lock for the whole window,
    /// so no other command runs on this vault while an invite is open.
    pub async fn host_invite<M: roam_pairing::Mailbox>(
        &self,
        mailbox: M,
        invite: roam_pairing::Invite,
        role: Role,
        window: std::time::Duration,
        show: impl FnOnce(&roam_pairing::PairingCode, &roam_pairing::Invite),
    ) -> anyhow::Result<u64> {
        let mut store = self.store.lock().await;
        let (code, host) = roam_pairing::host_via_mailbox(
            &self.identity,
            self.vault_id,
            self.key.0,
            role,
            &mut store,
            mailbox,
            invite,
        );
        show(&code, host.invite());
        host.accept_for(window).await
    }

    /// This vault's id — the name every member of it agrees on.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// A vault backed by `MemFs` — correct, but lost when the tab closes.
    pub fn in_memory(vault_key: [u8; 32]) -> anyhow::Result<Self> {
        Self::open(Arc::new(MemFs::new()), vault_key)
    }

    /// The shared vault key. A joiner needs this to persist after pairing, since
    /// unlike a founder it did not have the key before it started.
    pub fn vault_key(&self) -> [u8; 32] {
        self.key.0
    }

    pub async fn peer_id(&self) -> u64 {
        self.store.lock().await.peer_id()
    }

    /// This device's role, or `None` if no roster has vouched for it yet.
    ///
    /// A UI needs this to know what to offer: a Reader that is shown an editor
    /// will have its writes dropped at the receiving end, which reads as data
    /// loss rather than as a permission.
    pub async fn self_role(&self) -> Option<Role> {
        self.store.lock().await.self_role()
    }

    /// The founder this vault's roster fold is anchored on.
    ///
    /// A founder's own peer id; a joiner's, the host's. Which of those it is is
    /// the difference between having joined a vault and having quietly created a
    /// second one that will never converge with anybody.
    pub async fn founder_pin(&self) -> Option<u64> {
        self.store.lock().await.founder_pin()
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

    /// Remove a key. Removing one that is not there is not an error: two devices
    /// deleting the same row concurrently are stating the same intent.
    pub async fn remove_entry(&self, container: &str, key: &str) -> anyhow::Result<()> {
        self.store.lock().await.remove_entry(container, key)?;
        Ok(())
    }

    /// Everything in a container, for the bootstrap pass a freshly paired device
    /// has to make before incremental changes mean anything.
    pub async fn entries(&self, container: &str) -> Vec<(String, String)> {
        self.store.lock().await.entries(container)
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

    /// The relay bucket this vault addresses. Derived from the vault key, never
    /// chosen — so it discloses nothing the relay does not already hold.
    pub fn bucket_id(&self) -> String {
        self.key.bucket_id()
    }

    // -- binary payloads -----------------------------------------------------
    //
    // Blobs live OUTSIDE the CRDT: only a hash-reference rides the op log, so
    // these bytes never pass through the document. That is what makes it safe
    // to move them across the worker boundary as raw buffers rather than as
    // part of a JSON envelope.

    /// Store `bytes`, returning their content hash. Idempotent — the same bytes
    /// always produce the same hash and are never rewritten.
    pub async fn put_blob(&self, bytes: &[u8]) -> anyhow::Result<String> {
        Ok(self.store.lock().await.blobs().put(bytes)?)
    }

    /// The bytes for `hash`, or `None` if this device does not hold them.
    ///
    /// `None` is a normal answer, not an error: blobs sync separately from ops,
    /// so a device can legitimately know a reference before it has the bytes.
    pub async fn get_blob(&self, hash: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.store.lock().await.blobs().get(hash)?)
    }

    pub async fn has_blob(&self, hash: &str) -> bool {
        self.store.lock().await.blobs().has(hash)
    }

    /// Drop this device's copy of `hash`. Local only — blobs are not a shared
    /// collection a device can delete out of, so this reclaims storage here and
    /// says nothing to anyone else. Content-addressed storage has no reference
    /// counting, so the caller must already know nothing refers to it.
    pub async fn remove_blob(&self, hash: &str) -> anyhow::Result<()> {
        self.store.lock().await.blobs().remove(hash)?;
        Ok(())
    }

    // -- membership and maintenance ------------------------------------------

    /// Every device this vault trusts, including this one.
    ///
    /// Authoritative about privilege and silent about liveness: a roster entry is
    /// a signed statement about who may write, not about who is awake.
    pub async fn roster(&self) -> Vec<PeerInfo> {
        let store = self.store.lock().await;
        let me = store.peer_id();
        store
            .roster()
            .into_iter()
            .map(|peer| PeerInfo {
                peer_id: peer.peer_id,
                verifying_key: peer.verifying_key,
                name: peer.name,
                role: peer.role,
                // A revoked peer stays in the roster as a tombstone — forgetting
                // a revocation would let the device back in.
                active: peer.status == roam_storage::PeerStatus::Active,
                is_self: peer.peer_id == me,
            })
            .collect()
    }

    /// Withdraw trust from a device. Terminal: the fold treats a revocation as
    /// final, so it cannot be undone by re-adding the peer.
    ///
    /// It does NOT re-key anything the device already holds — it still knows the
    /// vault key. Pair it with [`Vault::rotate_epoch`] when that matters.
    pub async fn revoke_peer(&self, peer_id: u64, verifying_key: [u8; 32]) -> anyhow::Result<()> {
        self.store
            .lock()
            .await
            .revoke_peer(peer_id, verifying_key)?;
        Ok(())
    }

    /// Storage this vault occupies, split by what is using it.
    pub async fn data_size(&self) -> anyhow::Result<roam_storage::DataSize> {
        Ok(self.store.lock().await.data_size()?)
    }

    /// Bytes compaction would reclaim with this cutoff, changing nothing.
    pub async fn compact_dry_run(&self, before_ms: i64) -> anyhow::Result<u64> {
        Ok(self.store.lock().await.checkpoint_dry_run(before_ms)?)
    }

    /// Compact history older than `before_ms`, returning the bytes reclaimed.
    /// Current data is untouched; what is lost is the ability to roll back past
    /// the cutoff.
    pub async fn compact(&self, before_ms: i64) -> anyhow::Result<u64> {
        Ok(self.store.lock().await.checkpoint(before_ms)?)
    }

    /// Mint a fresh content epoch, wrapped to every current member.
    ///
    /// What makes a revocation bite: writes after it are sealed under a key the
    /// revoked device was never handed. Does not change the vault key, so the
    /// bucket does not move and nothing has to re-pair.
    pub async fn rotate_epoch(&self) -> anyhow::Result<()> {
        let mut store = self.store.lock().await;
        store.rotate_epoch(&self.key.id_key(), &self.key.epoch0_key(), None)?;
        Ok(())
    }

    // -- change reporting ----------------------------------------------------

    /// A marker for "the document as it is right now", for pairing with
    /// [`Vault::changes_since`].
    pub async fn frontier(&self) -> Frontier {
        self.store.lock().await.frontier()
    }

    /// Every key-level map change between `from` and now, deletes included.
    ///
    /// This is what lets an embedder project a vault into its own database: the
    /// alternative — re-reading every container and diffing by hand — costs the
    /// whole dataset per sync and still cannot see a deletion.
    pub async fn changes_since(&self, from: &Frontier) -> anyhow::Result<Vec<MapChange>> {
        let store = self.store.lock().await;
        Ok(store.map_delta(from, &store.frontier())?)
    }
}

/// This device's signing key, loaded from storage or minted on first use.
///
/// Shared by [`Vault::open`] and the join path so both persist it to the same
/// place. A fresh identity on every open would make the device a stranger to its
/// own op log — the class of bug `MemFs` structurally cannot catch, since it
/// starts empty every time.
/// One device in the roster, flattened for a caller that is about to serialize
/// it. Deliberately a plain struct rather than a re-export of the storage type:
/// the command protocol has to encode it, and encoding an internal type would
/// pin its layout to the wire.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: u64,
    /// Carried beside the id because the roster binds the two, and a revocation
    /// naming only an id could be replayed against a different key.
    pub verifying_key: [u8; 32],
    pub name: Option<String>,
    pub role: Role,
    /// False once revoked.
    pub active: bool,
    pub is_self: bool,
}

/// This vault's id, read back or minted on first use.
///
/// Only a *founder* may mint one. A joiner takes the host's, written by
/// [`Vault::join`] — which is why this is not called on that path: a fresh id
/// there would name a vault of one.
fn load_or_generate_vault_id(fs: &Arc<dyn VaultFs>) -> anyhow::Result<VaultId> {
    let path = Path::new(VAULT_ID);
    if let Ok(bytes) = fs.read(path) {
        let id: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("{VAULT_ID} is {} bytes, expected 32", bytes.len()))?;
        return Ok(VaultId(id));
    }
    let fresh = VaultId::generate();
    if let Some(parent) = path.parent() {
        fs.create_dir_all(parent)?;
    }
    fs.write(path, &fresh.0)?;
    Ok(fresh)
}

fn load_or_generate_identity(fs: &Arc<dyn VaultFs>) -> anyhow::Result<Identity> {
    let identity_path = Path::new(IDENTITY);
    match Identity::load_with_fs(&**fs, identity_path) {
        Ok(existing) => Ok(existing),
        Err(_) => {
            let fresh = Identity::generate();
            fresh.save_with_fs(&**fs, identity_path)?;
            Ok(fresh)
        }
    }
}
