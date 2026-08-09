use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// What the backend holds for one bucket.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub entry_ids: Vec<String>,
    pub blob_ids: Vec<String>,
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
}

/// In-memory backend for unit tests. Mirrors the real server's dedup semantics.
#[derive(Default)]
pub struct MemoryBackend {
    entries: Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>,
    blobs: Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>,
}

fn put(map: &Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>, bucket: &str, id: &str, ct: Vec<u8>) -> PutOutcome {
    let mut guard = map.lock().unwrap();
    let bucket = guard.entry(bucket.to_string()).or_default();
    if bucket.contains_key(id) {
        PutOutcome::Exists
    } else {
        bucket.insert(id.to_string(), ct);
        PutOutcome::Created
    }
}

fn get(map: &Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>, bucket: &str, id: &str) -> Option<Vec<u8>> {
    map.lock().unwrap().get(bucket).and_then(|b| b.get(id).cloned())
}

#[async_trait]
impl Backend for MemoryBackend {
    async fn manifest(&self, bucket: &str) -> anyhow::Result<Manifest> {
        let entry_ids = self.entries.lock().unwrap().get(bucket).map(|b| b.keys().cloned().collect()).unwrap_or_default();
        let blob_ids = self.blobs.lock().unwrap().get(bucket).map(|b| b.keys().cloned().collect()).unwrap_or_default();
        Ok(Manifest { entry_ids, blob_ids })
    }
    async fn get_entry(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> { Ok(get(&self.entries, bucket, id)) }
    async fn put_entry(&self, bucket: &str, id: &str, ct: Vec<u8>) -> anyhow::Result<PutOutcome> { Ok(put(&self.entries, bucket, id, ct)) }
    async fn get_blob(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> { Ok(get(&self.blobs, bucket, id)) }
    async fn put_blob(&self, bucket: &str, id: &str, ct: Vec<u8>) -> anyhow::Result<PutOutcome> { Ok(put(&self.blobs, bucket, id, ct)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_new_then_dup_is_refused() {
        let b = MemoryBackend::default();
        assert_eq!(b.put_entry("bkt", "e1", b"ct".to_vec()).await.unwrap(), PutOutcome::Created);
        assert_eq!(b.put_entry("bkt", "e1", b"ct".to_vec()).await.unwrap(), PutOutcome::Exists);
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
        assert_eq!(b.get_entry("bkt", "e1").await.unwrap(), Some(b"ct".to_vec()));
        assert_eq!(b.get_entry("bkt", "missing").await.unwrap(), None);
    }
}
