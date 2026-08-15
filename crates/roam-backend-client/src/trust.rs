//! Roster and key logs, carried through the backend.
//!
//! # Why this exists
//!
//! Everything else a vault replicates is *content*: CRDT op-log entries and
//! blobs. Trust is not content. A roster log says who may author ops at all,
//! and a key log says which epoch keys each device was handed. Until this
//! module, neither crossed the backend — they moved only over a direct P2P
//! pairing — and two things followed that both read as bugs:
//!
//! - **Trust was not transitive.** A vouched for B and B vouched for C, but
//!   nothing carried B's vouch to A, so A rejected everything C wrote. Silently:
//!   not an error, just rows that never arrived. Every device had to be paired
//!   with every other device — three pairings for three devices, six for four.
//! - **Epoch rotation was unusable.** The backend sync path fully honours
//!   epochs (see [`crate::sync::seal_under_head`]), so a rotation on one device
//!   would have re-keyed writes that no other device could ever open, because
//!   the `Wrap` naming them lived in a key log that never travelled.
//!
//! Both are the same missing pipe, so this is one set kind ([`SetKind::Trust`])
//! carrying both logs rather than two.
//!
//! # Shape
//!
//! A device publishes one [`TrustBundle`]: *every* roster log it holds (not
//! just its own) and every key log it holds. Republishing other devices'
//! logs is what makes trust transitive without any discovery protocol — A never
//! has to learn that C exists in order to fetch C's log, because B's bundle
//! already contains it.
//!
//! Bundles are content-addressed ([`VaultKey::trust_id`]), so once devices agree
//! on the facts they converge on a single id and stop uploading. A bundle is
//! immutable; a change publishes a new one. Superseded bundles linger on the
//! backend until retention ages them out — they are a few hundred bytes each and
//! importing one twice is idempotent, so this costs storage rather than
//! correctness.
//!
//! # Why epoch 0, always
//!
//! Every other payload is sealed under the *head* epoch. A trust bundle must
//! not be, and the reason is circular: a device that has missed a rotation
//! needs the key log precisely in order to obtain the epoch key. Sealing the
//! key log under the epoch it delivers would lock out exactly the device that
//! needs it.
//!
//! Epoch 0 is the vault key, so this means: anyone holding the vault key can
//! read the roster and key logs. That is not a weakening. The material rotation
//! protects is the epoch keys themselves, and those travel inside `Wrap`
//! records that are asymmetrically encrypted to each recipient's X25519 key. A
//! rotated-out ex-member reading this bundle learns the membership list (which
//! they already knew) and a set of wraps they cannot open. What they must not
//! get — content sealed under a post-revocation epoch — is untouched by this.

use crate::crypto::VaultKey;
use crate::transport::Backend;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use roam_storage::{Store, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// One signed log, tagged with the peer that authored it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLog {
    /// Authoring peer. Not trusted on receipt — the fold verifies each log
    /// against the key it actually holds for that peer, and drops the rest.
    pub peer: u64,
    /// Raw log bytes, base64 (standard alphabet — this rides inside JSON, not a
    /// URL, and the id encoding elsewhere is a separate concern).
    pub bytes: String,
}

impl SignedLog {
    fn new(peer: u64, raw: &[u8]) -> Self {
        Self {
            peer,
            bytes: B64.encode(raw),
        }
    }

    fn decode(&self) -> Option<Vec<u8>> {
        B64.decode(&self.bytes).ok()
    }
}

/// One device's whole view of who is trusted and what keys they hold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBundle {
    /// Format version. A reader that does not recognise it skips the bundle
    /// rather than guessing — trust is the wrong place to be lenient.
    pub v: u8,
    pub rosters: Vec<SignedLog>,
    pub keylogs: Vec<SignedLog>,
}

/// Current bundle format.
pub const TRUST_BUNDLE_V1: u8 = 1;

impl TrustBundle {
    /// Everything this device currently holds. Includes logs authored by other
    /// peers — that republication is what carries trust transitively.
    pub fn from_store(store: &Store) -> anyhow::Result<Self> {
        // Sorted by peer, because `export_all_rosters` yields whatever order the
        // directory walk produced. Two devices holding byte-identical logs would
        // otherwise serialise them differently, hash differently, and each
        // re-upload a "new" bundle on every single pass — dedup depends
        // entirely on this ordering being canonical rather than incidental.
        let mut rosters: Vec<(u64, Vec<u8>)> = store
            .export_all_rosters()?
            .into_iter()
            .filter(|(_, bytes)| !bytes.is_empty())
            .collect();
        rosters.sort_by_key(|(peer, _)| *peer);
        let rosters = rosters
            .into_iter()
            .map(|(peer, bytes)| SignedLog::new(peer, &bytes))
            .collect();

        // Key logs have no `export_all` — they are addressed per author — so ask
        // for one per peer the roster knows about, plus our own. A peer with no
        // key log yet (the common case: nothing has ever rotated) exports empty
        // and is skipped.
        let mut peers: Vec<u64> = store.roster().into_iter().map(|p| p.peer_id).collect();
        peers.push(store.peer_id());
        peers.sort_unstable();
        peers.dedup();

        let mut keylogs = Vec::new();
        for peer in peers {
            let bytes = store.export_keylog(peer)?;
            if !bytes.is_empty() {
                keylogs.push(SignedLog::new(peer, &bytes));
            }
        }

        Ok(Self {
            v: TRUST_BUNDLE_V1,
            rosters,
            keylogs,
        })
    }

    /// Canonical bytes to seal and hash. `serde_json` emits struct fields in
    /// declaration order and both log lists are built in a deterministic order,
    /// so two devices holding identical logs produce identical bytes — which is
    /// what lets content addressing dedup them into one backend object.
    pub fn to_canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Backend id for these bytes under `key`.
    pub fn id(&self, key: &VaultKey) -> anyhow::Result<String> {
        let bytes = self.to_canonical_bytes()?;
        Ok(key.trust_id(&blake3::hash(&bytes).to_hex().to_string()))
    }

    /// True if this bundle carries nothing worth publishing.
    pub fn is_empty(&self) -> bool {
        self.rosters.is_empty() && self.keylogs.is_empty()
    }
}

/// Fold a received bundle into `store`.
///
/// Nothing here aborts on a bad log. A trust bundle is fetched from an
/// untrusted server and may contain a forked, truncated or outright forged log;
/// the correct response to one is to drop it and keep the rest, not to fail the
/// sync pass. `Store::import_roster_bundle` and `Store::import_keylog` already
/// refuse anything that does not genuinely extend what is on disk, so a
/// rejection here is a no-op rather than damage.
///
/// Returns how many key logs were newly accepted, which the caller uses to
/// decide whether the keychain needs rebuilding.
pub fn apply_bundle(store: &mut Store, bundle: &TrustBundle) -> anyhow::Result<usize> {
    if bundle.v != TRUST_BUNDLE_V1 {
        return Ok(0);
    }

    // Rosters first, and as a bundle: the receiver does not yet hold keys for
    // the peers it is about to learn about, so verification is deferred to the
    // fold, which checks each trusted author's log as it materialises the peer
    // set. Importing them one at a time through `import_roster` would reject
    // exactly the third-device case this whole module exists for.
    let rosters: Vec<(u64, Vec<u8>)> = bundle
        .rosters
        .iter()
        .filter_map(|log| log.decode().map(|bytes| (log.peer, bytes)))
        .collect();
    if !rosters.is_empty() {
        store.import_roster_bundle(rosters)?;
    }

    // Key logs second, and only now: `import_keylog` verifies against the
    // author's key, which we may only have learned from the roster fold above.
    let mut accepted = 0usize;
    let me = store.peer_id();
    let known: std::collections::BTreeMap<u64, [u8; 32]> = store
        .roster()
        .into_iter()
        .map(|p| (p.peer_id, p.verifying_key))
        .collect();

    for log in &bundle.keylogs {
        if log.peer == me {
            continue; // never let foreign bytes overwrite our own log
        }
        let Some(key_bytes) = known.get(&log.peer) else {
            // Not a peer we trust — no key to verify against, so there is
            // nothing to check the log's signatures with. It may become
            // importable on a later pass once a roster vouches for them.
            continue;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(key_bytes) else {
            continue;
        };
        let Some(bytes) = log.decode() else { continue };
        match store.import_keylog(log.peer, &verifying_key, bytes) {
            Ok(()) => accepted += 1,
            Err(e) => {
                // Expected on a stale bundle: the on-disk log already extends
                // past this copy, so it is refused as a non-extending fork.
                if std::env::var_os("ROAM_DEBUG").is_some() {
                    eprintln!("[be-sync]   keylog {} rejected: {e}", log.peer);
                }
            }
        }
    }

    Ok(accepted)
}

/// Exchange trust bundles with the backend: publish this device's view, take in
/// everyone else's, and apply them.
///
/// Runs FIRST in a sync pass, before entries are reconciled, so a peer vouched
/// for in this pass has its ops accepted in the same pass rather than the next
/// one. Returns true if anything was applied, which tells the caller its cached
/// keychain is stale.
pub async fn reconcile_trust<B: Backend>(
    store: &Arc<Mutex<Store>>,
    backend: &Arc<B>,
    key: &VaultKey,
    bucket: &str,
    debug: bool,
) -> anyhow::Result<bool> {
    let (local_bundle, local_id) = {
        let guard = store.lock().await;
        let bundle = TrustBundle::from_store(&guard)?;
        let id = bundle.id(key)?;
        (bundle, id)
    };

    let mut local_ids = std::collections::BTreeSet::new();
    if !local_bundle.is_empty() {
        local_ids.insert(local_id.clone());
    }

    let (have, need) =
        crate::sync::reconcile_set(backend, bucket, roam_rbsr::SetKind::Trust, &local_ids).await?;

    if debug {
        eprintln!(
            "[be-sync]   rbsr trust: upload={} fetch={}",
            have.len(),
            need.len()
        );
    }

    // Publish. Epoch 0 rather than the head epoch — see the module docs.
    if have.contains(&local_id) {
        let sealed = key.seal(&local_bundle.to_canonical_bytes()?);
        backend.put_trust(bucket, &local_id, sealed).await?;
    }

    let mut applied = false;
    for id in &need {
        let Some(ct) = backend.get_trust(bucket, id).await? else {
            continue;
        };
        // A bundle that will not open under the vault key is not ours to read.
        // Skip it rather than failing: the pass has real work to do.
        let Ok(plaintext) = key.open(&ct) else {
            if debug {
                eprintln!("[be-sync]   trust bundle {id} did not open");
            }
            continue;
        };
        let Ok(bundle) = serde_json::from_slice::<TrustBundle>(&plaintext) else {
            continue;
        };
        let mut guard = store.lock().await;
        apply_bundle(&mut guard, &bundle)?;
        applied = true;
    }

    if applied {
        // A device that joined after an epoch was minted holds no `Wrap` for it
        // and could not read a thing. Back-filling is convergent and cheap when
        // there is nothing to do, so it runs on any trust change rather than
        // being tied to a particular event.
        let mut guard = store.lock().await;
        match guard.backfill_wraps(&key.id_key(), &key.epoch0_key()) {
            Ok(published) if published > 0 && debug => {
                eprintln!("[be-sync]   backfilled {published} epoch wrap(s)");
            }
            Ok(_) => {}
            // Only an Admin can publish wraps; a Reader/Writer simply has no
            // part to play here.
            Err(e) if debug => eprintln!("[be-sync]   wrap backfill skipped: {e}"),
            Err(_) => {}
        }
    }

    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::reconcile_once;
    use crate::transport::MemoryBackend;
    use roam_storage::{Identity, Role};

    async fn store_at(dir: &std::path::Path) -> Arc<Mutex<Store>> {
        let mut store = Store::open(dir, Identity::generate()).unwrap();
        store.declare_founder(Role::Admin).unwrap();
        Arc::new(Mutex::new(store))
    }

    /// Introduce two devices to each other, as a direct pairing does.
    async fn pair(left: &Arc<Mutex<Store>>, right: &Arc<Mutex<Store>>) {
        let (left_peer, left_key) = {
            let guard = left.lock().await;
            (guard.peer_id(), guard.identity_verifying_bytes())
        };
        let (right_peer, right_key) = {
            let guard = right.lock().await;
            (guard.peer_id(), guard.identity_verifying_bytes())
        };
        left.lock()
            .await
            .add_peer(right_peer, right_key, Role::Admin)
            .unwrap();
        right
            .lock()
            .await
            .add_peer(left_peer, left_key, Role::Admin)
            .unwrap();
    }

    /// The whole point of this module. A is paired with B; B is paired with C; A
    /// and C have never met and never exchanged a code. C's writes must still
    /// reach A, because B's bundle republishes the roster log carrying B's vouch
    /// for C, and A's fold trusts B enough to act on it.
    ///
    /// Before trust bundles this was impossible, and the failure was silent —
    /// A simply rejected everything C authored and no error surfaced anywhere.
    #[tokio::test]
    async fn trust_reaches_a_third_device_through_the_relay() {
        let key = VaultKey([9u8; 32]);
        let backend = Arc::new(MemoryBackend::default());
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let c_dir = tempfile::tempdir().unwrap();
        let a = store_at(a_dir.path()).await;
        let b = store_at(b_dir.path()).await;
        let c = store_at(c_dir.path()).await;

        pair(&a, &b).await;
        reconcile_once(&a, &backend, &key).await.unwrap();
        reconcile_once(&b, &backend, &key).await.unwrap();

        // C pairs with B only. A is not involved and never sees C's code.
        pair(&b, &c).await;
        reconcile_once(&b, &backend, &key).await.unwrap();

        c.lock()
            .await
            .set_entry("files", "from-c", "hello")
            .unwrap();
        reconcile_once(&c, &backend, &key).await.unwrap();

        reconcile_once(&a, &backend, &key).await.unwrap();

        assert_eq!(
            a.lock().await.get_entry("files", "from-c"),
            Some("hello".to_string()),
            "A never paired with C directly; B's roster log is what vouches for it"
        );
        let c_peer = c.lock().await.peer_id();
        assert!(
            a.lock()
                .await
                .roster()
                .iter()
                .any(|peer| peer.peer_id == c_peer),
            "C should have materialised in A's peer set"
        );
    }

    /// Epoch rotation across the relay. This is the case that was not merely
    /// missing but actively dangerous: the backend sync path already sealed
    /// writes under the head epoch, so a rotation on A re-keyed content that B
    /// could never open, permanently and silently.
    #[tokio::test]
    async fn an_epoch_rotation_reaches_the_other_device() {
        let key = VaultKey([9u8; 32]);
        let backend = Arc::new(MemoryBackend::default());
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = store_at(a_dir.path()).await;
        let b = store_at(b_dir.path()).await;

        pair(&a, &b).await;
        reconcile_once(&a, &backend, &key).await.unwrap();
        reconcile_once(&b, &backend, &key).await.unwrap();

        // A mints a fresh epoch and writes under it.
        {
            let mut guard = a.lock().await;
            guard
                .rotate_epoch(&key.id_key(), &key.epoch0_key(), None)
                .unwrap();
            guard.set_entry("files", "after", "rotated").unwrap();
        }
        reconcile_once(&a, &backend, &key).await.unwrap();

        reconcile_once(&b, &backend, &key).await.unwrap();
        assert_eq!(
            b.lock().await.get_entry("files", "after"),
            Some("rotated".to_string()),
            "B needs A's key log to hold the Wrap naming it, or this is unreadable"
        );
    }

    /// Content addressing has to actually dedup, or every device would upload a
    /// near-identical bundle on every pass forever. Once two devices hold the
    /// same logs their bundles are byte-identical and collapse to one object.
    #[tokio::test]
    async fn devices_holding_the_same_logs_converge_on_one_bundle() {
        let key = VaultKey([9u8; 32]);
        let backend = Arc::new(MemoryBackend::default());
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = store_at(a_dir.path()).await;
        let b = store_at(b_dir.path()).await;

        pair(&a, &b).await;
        // Several passes each: any per-pass churn would show up as extra objects.
        for _ in 0..3 {
            reconcile_once(&a, &backend, &key).await.unwrap();
            reconcile_once(&b, &backend, &key).await.unwrap();
        }

        let a_id = {
            let guard = a.lock().await;
            TrustBundle::from_store(&guard).unwrap().id(&key).unwrap()
        };
        let b_id = {
            let guard = b.lock().await;
            TrustBundle::from_store(&guard).unwrap().id(&key).unwrap()
        };
        assert_eq!(a_id, b_id, "converged devices must agree on the bundle id");
    }

    /// The relay must not learn who is in a vault. Bundle ids are keyed hashes
    /// and the payload is sealed, so a peer id should appear in neither.
    #[tokio::test]
    async fn the_relay_only_ever_holds_sealed_trust() {
        let key = VaultKey([9u8; 32]);
        let backend = Arc::new(MemoryBackend::default());
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = store_at(a_dir.path()).await;
        let b = store_at(b_dir.path()).await;
        pair(&a, &b).await;
        reconcile_once(&a, &backend, &key).await.unwrap();

        let (id, peer_id) = {
            let guard = a.lock().await;
            (
                TrustBundle::from_store(&guard).unwrap().id(&key).unwrap(),
                guard.peer_id(),
            )
        };
        let stored = backend
            .get_trust(&key.bucket_id(), &id)
            .await
            .unwrap()
            .expect("the bundle should have been published");

        let peer_text = peer_id.to_string();
        assert!(
            !id.contains(&peer_text),
            "the id leaks a peer id in the clear"
        );
        assert!(
            !stored
                .windows(peer_text.len())
                .any(|window| window == peer_text.as_bytes()),
            "the stored bundle leaks a peer id in the clear"
        );
    }
}
