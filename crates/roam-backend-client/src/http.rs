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

/// Ceiling on a response body this client will hold in memory.
///
/// Matched to the relay's own PUT cap (`sync_controller.ex`, 64 MB): a body
/// larger than the server is willing to accept cannot be something that server
/// legitimately stored, so refusing it turns nothing away and bounds what a
/// hostile — or merely broken — one can make a client allocate.
///
/// It needs bounding because the alternative is believing the server about
/// size. `Response::bytes` reads to EOF, so an endless response is an endless
/// allocation, and a blob is decrypted into a second buffer of its own size on
/// top of that. On a handset the result of getting this wrong is not an error,
/// it is the process.
const MAX_RESPONSE_BYTES: u64 = 64_000_000;

/// Reads a response body, refusing to buffer more than [`MAX_RESPONSE_BYTES`].
///
/// The declared length is checked first because it costs nothing and catches
/// the honest case before a single byte is read. It is not *trusted*, though:
/// a chunked response declares no length at all, so the body is accumulated a
/// chunk at a time and the running total is what actually enforces the bound.
#[cfg(not(target_arch = "wasm32"))]
async fn read_capped(mut resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    if let Some(declared) = resp.content_length() {
        if declared > MAX_RESPONSE_BYTES {
            anyhow::bail!("response declares {declared} bytes, over the {MAX_RESPONSE_BYTES} cap");
        }
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() as u64 + chunk.len() as u64 > MAX_RESPONSE_BYTES {
            anyhow::bail!("response body exceeded the {MAX_RESPONSE_BYTES} byte cap");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The wasm build gets the declared-length check and nothing more.
///
/// `Response::chunk` does not exist there — the fetch backend hands over a body
/// it has already buffered itself — so there is no point at which this code
/// could stop reading. Stated rather than papered over: on wasm a server that
/// sends a chunked, endless body is bounded by the browser, not by us.
#[cfg(target_arch = "wasm32")]
async fn read_capped(resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    if let Some(declared) = resp.content_length() {
        if declared > MAX_RESPONSE_BYTES {
            anyhow::bail!("response declares {declared} bytes, over the {MAX_RESPONSE_BYTES} cap");
        }
    }
    Ok(resp.bytes().await?.to_vec())
}

async fn get_bytes(client: &reqwest::Client, url: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let resp = client.get(url).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let resp = resp.error_for_status()?;
    Ok(Some(read_capped(resp).await?))
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
        // Through the same cap as everything else. `Response::json` reads to
        // EOF exactly like `bytes` does, so leaving this one alone would leave
        // the bound trivially bypassable — by the first request of every pass.
        Ok(serde_json::from_slice::<Manifest>(
            &read_capped(resp).await?,
        )?)
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
        Ok(read_capped(resp).await?)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Serves one request with a handcrafted response, then closes.
    ///
    /// Raw TCP rather than a server library because the point is to be
    /// *dishonest* in ways a well-behaved server cannot be: claim a length
    /// nothing will ever match, or never stop sending. Returns the bound URL.
    async fn serve_once(response: &'static [u8], endless: bool) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 1024];
            let _ = socket.read(&mut scratch).await;
            if socket.write_all(response).await.is_err() {
                return;
            }
            if endless {
                // One 64 KiB chunk after another, for as long as the client
                // keeps listening. A client that reads to EOF never returns.
                let chunk = format!("{:x}\r\n", 64 * 1024);
                let payload = vec![b'a'; 64 * 1024];
                loop {
                    if socket.write_all(chunk.as_bytes()).await.is_err() {
                        return;
                    }
                    if socket.write_all(&payload).await.is_err() {
                        return;
                    }
                    if socket.write_all(b"\r\n").await.is_err() {
                        return;
                    }
                }
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn a_body_declared_over_the_cap_is_refused_before_it_is_read() {
        let base = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n",
            false,
        )
        .await;
        let backend = HttpBackend::new(&base);

        let err = backend.get_blob("bucket", "id").await.unwrap_err();
        assert!(
            err.to_string().contains("over the"),
            "expected the declared-length refusal, got: {err}"
        );
    }

    #[tokio::test]
    async fn a_chunked_body_that_never_ends_is_cut_off_at_the_cap() {
        // The case the declared length cannot catch: no Content-Length at all,
        // so only the running total stops it.
        //
        // Mutation-verified, and it is worth knowing what "fails" looks like
        // here: with the running total removed, this test does not report a
        // failed assertion — it allocates until the kernel kills the test
        // process (2.4 GB before the OOM killer arrived). So a run of this
        // file that ends in a kill rather than a red test IS this test firing.
        let base = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            true,
        )
        .await;
        let backend = HttpBackend::new(&base);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            backend.get_blob("bucket", "id"),
        )
        .await
        .expect("the read must end on its own, not on the test's timeout");

        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("exceeded"),
            "expected the running-total refusal, got: {err}"
        );
    }

    #[tokio::test]
    async fn a_body_within_the_cap_still_arrives() {
        let base = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", false).await;
        let backend = HttpBackend::new(&base);

        assert_eq!(
            backend.get_blob("bucket", "id").await.unwrap(),
            Some(b"hello".to_vec())
        );
    }
}
