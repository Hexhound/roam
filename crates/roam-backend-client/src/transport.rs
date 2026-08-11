use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use std::collections::BTreeMap;
use std::sync::Mutex;

pub use roam_rbsr::SetKind;

/// What the backend holds for one bucket.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub entry_ids: Vec<String>,
    pub blob_ids: Vec<String>,
    /// Snapshot ids the backend holds. `serde(default)` so a manifest from a
    /// pre-snapshot backend (no such field) still decodes.
    #[serde(default)]
    pub snapshot_ids: Vec<String>,
    /// The backend is asking an Admin client to produce a fresh snapshot (its
    /// entry tail has grown past the configured threshold). `serde(default)` so
    /// a pre-snapshot backend's manifest still decodes to `false`.
    #[serde(default)]
    pub snapshot_wanted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Created,
    Exists,
}

/// The backend as seen by the sync loop. Bytes are already-encrypted payloads;
/// this layer never encrypts or decrypts.
#[async_trait]
pub trait Backend: Send + Sync {
    async fn manifest(&self, bucket: &str) -> anyhow::Result<Manifest>;
    async fn get_entry(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>>;
    async fn put_entry(&self, bucket: &str, id: &str, ct: Vec<u8>) -> anyhow::Result<PutOutcome>;
    async fn get_blob(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>>;
    async fn put_blob(&self, bucket: &str, id: &str, ct: Vec<u8>) -> anyhow::Result<PutOutcome>;
    async fn get_snapshot(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>>;
    async fn put_snapshot(&self, bucket: &str, id: &str, ct: Vec<u8>)
        -> anyhow::Result<PutOutcome>;
    /// All snapshot ids the backend currently holds for `bucket`.
    async fn list_snapshots(&self, bucket: &str) -> anyhow::Result<Vec<String>>;

    /// One RBSR round: hand the backend a negentropy message for `kind`'s id set,
    /// get its reply. Bytes are opaque negentropy protocol frames.
    async fn reconcile(&self, bucket: &str, kind: SetKind, msg: Vec<u8>)
        -> anyhow::Result<Vec<u8>>;
}

/// In-memory backend for unit tests. Mirrors the real server's dedup semantics.
#[derive(Default)]
pub struct MemoryBackend {
    entries: Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>,
    blobs: Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>,
    snapshots: Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>,
    /// Buckets for which the backend is currently requesting a snapshot.
    snapshot_wanted: Mutex<std::collections::BTreeSet<String>>,
    /// Per-entry-id `get_entry` call counts (test instrumentation).
    entry_gets: Mutex<BTreeMap<String, usize>>,
}

impl MemoryBackend {
    /// Test hook: mark (or clear) a bucket as wanting a snapshot, mirroring the
    /// real backend's size-threshold signal.
    pub fn set_snapshot_wanted(&self, bucket: &str, wanted: bool) {
        let mut guard = self.snapshot_wanted.lock().unwrap();
        if wanted {
            guard.insert(bucket.to_string());
        } else {
            guard.remove(bucket);
        }
    }

    /// Test hook: how many times `get_entry` was called for `id` (any bucket).
    pub fn entry_get_count(&self, id: &str) -> usize {
        self.entry_gets
            .lock()
            .unwrap()
            .get(id)
            .copied()
            .unwrap_or(0)
    }

    fn id_set(&self, bucket: &str, kind: SetKind) -> Vec<[u8; 32]> {
        let map = match kind {
            SetKind::Entries => &self.entries,
            SetKind::Blobs => &self.blobs,
            SetKind::Snapshots => &self.snapshots,
        };
        let guard = map.lock().unwrap();
        let Some(b) = guard.get(bucket) else {
            return Vec::new();
        };
        b.keys().filter_map(|k| str_to_id(k)).collect()
    }
}

/// Decode a base64url (no-pad) id back to 32 bytes; `None` if malformed. Matches
/// the id encoding produced by `VaultKey` (see crypto.rs) so the backend's RBSR
/// set is byte-for-byte comparable with the client's.
fn str_to_id(s: &str) -> Option<[u8; 32]> {
    B64URL.decode(s).ok()?.try_into().ok()
}

fn put(
    map: &Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>,
    bucket: &str,
    id: &str,
    ct: Vec<u8>,
) -> PutOutcome {
    let mut guard = map.lock().unwrap();
    let bucket = guard.entry(bucket.to_string()).or_default();
    if bucket.contains_key(id) {
        PutOutcome::Exists
    } else {
        bucket.insert(id.to_string(), ct);
        PutOutcome::Created
    }
}

fn get(
    map: &Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>,
    bucket: &str,
    id: &str,
) -> Option<Vec<u8>> {
    map.lock()
        .unwrap()
        .get(bucket)
        .and_then(|b| b.get(id).cloned())
}

#[async_trait]
impl Backend for MemoryBackend {
    async fn manifest(&self, bucket: &str) -> anyhow::Result<Manifest> {
        let entry_ids = self
            .entries
            .lock()
            .unwrap()
            .get(bucket)
            .map(|b| b.keys().cloned().collect())
            .unwrap_or_default();
        let blob_ids = self
            .blobs
            .lock()
            .unwrap()
            .get(bucket)
            .map(|b| b.keys().cloned().collect())
            .unwrap_or_default();
        let snapshot_ids = self
            .snapshots
            .lock()
            .unwrap()
            .get(bucket)
            .map(|b| b.keys().cloned().collect())
            .unwrap_or_default();
        let snapshot_wanted = self.snapshot_wanted.lock().unwrap().contains(bucket);
        Ok(Manifest {
            entry_ids,
            blob_ids,
            snapshot_ids,
            snapshot_wanted,
        })
    }
    async fn get_entry(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        *self
            .entry_gets
            .lock()
            .unwrap()
            .entry(id.to_string())
            .or_insert(0) += 1;
        Ok(get(&self.entries, bucket, id))
    }
    async fn put_entry(&self, bucket: &str, id: &str, ct: Vec<u8>) -> anyhow::Result<PutOutcome> {
        Ok(put(&self.entries, bucket, id, ct))
    }
    async fn get_blob(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(get(&self.blobs, bucket, id))
    }
    async fn put_blob(&self, bucket: &str, id: &str, ct: Vec<u8>) -> anyhow::Result<PutOutcome> {
        Ok(put(&self.blobs, bucket, id, ct))
    }
    async fn get_snapshot(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(get(&self.snapshots, bucket, id))
    }
    async fn put_snapshot(
        &self,
        bucket: &str,
        id: &str,
        ct: Vec<u8>,
    ) -> anyhow::Result<PutOutcome> {
        Ok(put(&self.snapshots, bucket, id, ct))
    }
    async fn list_snapshots(&self, bucket: &str) -> anyhow::Result<Vec<String>> {
        Ok(self
            .snapshots
            .lock()
            .unwrap()
            .get(bucket)
            .map(|b| b.keys().cloned().collect())
            .unwrap_or_default())
    }
    async fn reconcile(
        &self,
        bucket: &str,
        kind: SetKind,
        msg: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let set = roam_rbsr::ItemSet::from_ids(self.id_set(bucket, kind));
        roam_rbsr::reconcile_server(&set, &msg).map_err(|e| anyhow::anyhow!(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_new_then_dup_is_refused() {
        let b = MemoryBackend::default();
        assert_eq!(
            b.put_entry("bkt", "e1", b"ct".to_vec()).await.unwrap(),
            PutOutcome::Created
        );
        assert_eq!(
            b.put_entry("bkt", "e1", b"ct".to_vec()).await.unwrap(),
            PutOutcome::Exists
        );
    }

    #[tokio::test]
    async fn memory_backend_stores_and_lists_snapshots() {
        let b = MemoryBackend::default();
        assert_eq!(
            b.put_snapshot("bkt", "sid", vec![1, 2, 3]).await.unwrap(),
            PutOutcome::Created
        );
        assert_eq!(
            b.get_snapshot("bkt", "sid").await.unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            b.list_snapshots("bkt").await.unwrap(),
            vec!["sid".to_string()]
        );
        // Snapshot ids also surface through the manifest, isolated per bucket.
        assert_eq!(b.manifest("bkt").await.unwrap().snapshot_ids, vec!["sid"]);
        assert!(b.list_snapshots("other").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn manifest_lists_written_ids_per_bucket() {
        let b = MemoryBackend::default();
        b.put_entry("bkt", "e1", b"x".to_vec()).await.unwrap();
        b.put_blob("bkt", "b1", b"y".to_vec()).await.unwrap();
        b.put_entry("other", "e9", b"z".to_vec()).await.unwrap();
        let m = b.manifest("bkt").await.unwrap();
        assert_eq!(m.entry_ids, vec!["e1".to_string()]);
        assert_eq!(m.blob_ids, vec!["b1".to_string()]);
    }

    #[tokio::test]
    async fn get_returns_bytes_or_none() {
        let b = MemoryBackend::default();
        b.put_entry("bkt", "e1", b"ct".to_vec()).await.unwrap();
        assert_eq!(
            b.get_entry("bkt", "e1").await.unwrap(),
            Some(b"ct".to_vec())
        );
        assert_eq!(b.get_entry("bkt", "missing").await.unwrap(), None);
    }
}

#[cfg(test)]
mod reconcile_tests {
    use super::*;
    use roam_rbsr::{initiate, reconcile, ItemSet, SetKind};

    fn id(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }
    fn id_str(id: &[u8; 32]) -> String {
        B64URL.encode(id)
    }

    #[tokio::test]
    async fn client_reconciles_against_memory_backend() {
        let backend = MemoryBackend::default();
        for n in [1u8, 2, 3] {
            backend
                .put_entry("bucket", &id_str(&id(n)), vec![n])
                .await
                .unwrap();
        }

        let client_set = ItemSet::from_ids([id(1)]);
        let mut msg = initiate(&client_set);
        let (mut have, mut need) = (Vec::new(), Vec::new());
        for _ in 0..64 {
            let reply = backend
                .reconcile("bucket", SetKind::Entries, msg)
                .await
                .unwrap();
            let out = reconcile(&client_set, &reply).unwrap();
            have.extend(out.have);
            need.extend(out.need);
            match out.next_msg {
                Some(next) => msg = next,
                None => break,
            }
        }
        need.sort();
        assert!(have.is_empty());
        assert_eq!(need, vec![id(2), id(3)]);
    }
}
