//! End-to-end: the real sync Phoenix backend process + two stores, wired only through
//! the backend (no iroh). B must converge purely from the backend, and re-running
//! reconcile after a hypothetical iroh delivery of the same ops must be a no-op.

use roam_backend_client::crypto::VaultKey;
use roam_backend_client::http::HttpBackend;
use roam_backend_client::sync::reconcile_once;
use roam_storage::{Identity, Store, VerifyingKey};
use std::process::{Child, Command};
use std::sync::Arc;
use tokio::sync::Mutex;

struct Server {
    child: Child,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const PORT: u16 = 4577;

// NOTE: readiness polling uses an async reqwest::Client rather than
// reqwest::blocking — the blocking client spins up its own Tokio runtime
// internally, which panics ("Cannot start a runtime from within a runtime")
// when called from inside the #[tokio::test] runtime that this fn runs under.
async fn start_server(root: &std::path::Path) -> Server {
    let child = Command::new("mix")
        .arg("phx.server")
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../sync"))
        .env("PORT", PORT.to_string())
        .env("ROAM_BACKEND_DATA", root)
        .env("MIX_ENV", "dev")
        .env("PHX_SERVER", "true")
        .spawn()
        .expect("start sync phx server (is mix on PATH?)");
    let client = reqwest::Client::new();
    // First boot compiles/boots the full Phoenix app, which can take a while.
    // Poll generously (up to 120s).
    for _ in 0..600 {
        if client
            .get(format!("http://127.0.0.1:{PORT}/b/probe/manifest"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Server { child }
}

#[tokio::test]
#[ignore = "requires mix on PATH and the sync Phoenix backend; run with --ignored"]
async fn b_converges_via_backend_only_then_race_is_noop() {
    let data_root = tempfile::tempdir().unwrap();
    let _server = start_server(data_root.path()).await;
    let base = format!("http://127.0.0.1:{PORT}");
    let key = VaultKey([3u8; 32]);
    let backend = Arc::new(HttpBackend::new(&base));

    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a = Arc::new(Mutex::new(
        Store::open(a_dir.path(), Identity::generate()).unwrap(),
    ));
    let b = Arc::new(Mutex::new(
        Store::open(b_dir.path(), Identity::generate()).unwrap(),
    ));

    let (ap, ak) = {
        let g = a.lock().await;
        (g.peer_id(), g.identity_verifying_bytes())
    };
    let (bp, bk) = {
        let g = b.lock().await;
        (g.peer_id(), g.identity_verifying_bytes())
    };
    a.lock().await.add_peer(bp, bk).unwrap();
    b.lock().await.add_peer(ap, ak).unwrap();

    a.lock().await.set_entry("files", "k", "v1").unwrap();
    reconcile_once(&a, &backend, &key).await.unwrap();
    reconcile_once(&b, &backend, &key).await.unwrap();
    assert_eq!(
        b.lock().await.get_entry("files", "k"),
        Some("v1".to_string())
    );

    // Simulate iroh ALSO delivering A's ops to B (same bytes): import directly, then
    // reconcile — the store must not change and no dup is created.
    let a_log = a.lock().await.export_own_log().unwrap();
    let a_vkey = VerifyingKey::from_bytes(&ak).unwrap();
    let before = b.lock().await.doc_version_bytes();
    b.lock().await.apply_peer_ops(ap, &a_vkey, &a_log).unwrap();
    reconcile_once(&b, &backend, &key).await.unwrap();
    assert_eq!(
        b.lock().await.doc_version_bytes(),
        before,
        "idempotent: iroh+backend deliver once"
    );
}
