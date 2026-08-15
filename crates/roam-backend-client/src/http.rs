use crate::transport::{Backend, Manifest, PutOutcome, SetKind};
use async_trait::async_trait;

/// Talks to a `roam-backend` server over HTTP. Paths mirror the spec §5 table.
pub struct HttpBackend {
    base: String,
    client: reqwest::Client,
}

impl HttpBackend {
    pub fn new(base_url: &str) -> Self {
        Self {
            base: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    fn entry_url(&self, bucket: &str, id: &str) -> String {
        format!("{}/b/{bucket}/entries/{id}", self.base)
    }
    fn blob_url(&self, bucket: &str, id: &str) -> String {
        format!("{}/b/{bucket}/blobs/{id}", self.base)
    }
    fn snapshot_url(&self, bucket: &str, id: &str) -> String {
        format!("{}/b/{bucket}/snapshots/{id}", self.base)
    }
    fn trust_url(&self, bucket: &str, id: &str) -> String {
        format!("{}/b/{bucket}/trust/{id}", self.base)
    }
}

async fn get_bytes(client: &reqwest::Client, url: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let resp = client.get(url).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let resp = resp.error_for_status()?;
    Ok(Some(resp.bytes().await?.to_vec()))
}

async fn put_bytes(client: &reqwest::Client, url: &str, ct: Vec<u8>) -> anyhow::Result<PutOutcome> {
    let resp = client.put(url).body(ct).send().await?;
    match resp.status() {
        reqwest::StatusCode::CREATED | reqwest::StatusCode::OK => Ok(PutOutcome::Created),
        reqwest::StatusCode::CONFLICT => Ok(PutOutcome::Exists),
        other => Err(anyhow::anyhow!("unexpected PUT status {other}")),
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Backend for HttpBackend {
    async fn manifest(&self, bucket: &str) -> anyhow::Result<Manifest> {
        let url = format!("{}/b/{bucket}/manifest", self.base);
        let resp = self.client.get(&url).send().await?.error_for_status()?;
        Ok(resp.json::<Manifest>().await?)
    }
    async fn get_entry(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        get_bytes(&self.client, &self.entry_url(bucket, id)).await
    }
    async fn put_entry(&self, bucket: &str, id: &str, ct: Vec<u8>) -> anyhow::Result<PutOutcome> {
        put_bytes(&self.client, &self.entry_url(bucket, id), ct).await
    }
    async fn get_blob(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        get_bytes(&self.client, &self.blob_url(bucket, id)).await
    }
    async fn put_blob(&self, bucket: &str, id: &str, ct: Vec<u8>) -> anyhow::Result<PutOutcome> {
        put_bytes(&self.client, &self.blob_url(bucket, id), ct).await
    }
    async fn get_snapshot(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        get_bytes(&self.client, &self.snapshot_url(bucket, id)).await
    }
    async fn put_snapshot(
        &self,
        bucket: &str,
        id: &str,
        ct: Vec<u8>,
    ) -> anyhow::Result<PutOutcome> {
        put_bytes(&self.client, &self.snapshot_url(bucket, id), ct).await
    }
    async fn get_trust(&self, bucket: &str, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        get_bytes(&self.client, &self.trust_url(bucket, id)).await
    }
    async fn put_trust(&self, bucket: &str, id: &str, ct: Vec<u8>) -> anyhow::Result<PutOutcome> {
        put_bytes(&self.client, &self.trust_url(bucket, id), ct).await
    }
    async fn list_snapshots(&self, bucket: &str) -> anyhow::Result<Vec<String>> {
        // The backend surfaces snapshot ids through the manifest endpoint, so a
        // dedicated list route is unnecessary.
        Ok(self.manifest(bucket).await?.snapshot_ids)
    }
    async fn reconcile(
        &self,
        bucket: &str,
        kind: SetKind,
        msg: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let url = format!("{}/b/{bucket}/reconcile/{}", self.base, kind.as_str());
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(msg)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.bytes().await?.to_vec())
    }
}
