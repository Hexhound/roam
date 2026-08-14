//! M3, native half: two browser-shaped vaults converge through the relay alone.
//!
//! Both vaults here are exactly what the browser runs — storage on a
//! non-filesystem backend, sync through `Backend` — with `MemoryBackend` standing
//! in for the network. That keeps the logic under an ordinary `cargo test`, so
//! the JS harness (`tests/js/sync.mjs`) is left proving only the two things it
//! alone can prove: that this works over real HTTP, and that it works inside a
//! JS runtime.

use roam_backend_client::transport::{Backend, MemoryBackend};
use roam_wasm::Vault;
use std::sync::Arc;

const VAULT_KEY: [u8; 32] = [7u8; 32];
const TEXT_ID: &str = "notes/hello.md";

/// Introduce two devices to each other, as pairing does natively.
async fn vouch(a: &Vault, b: &Vault) {
    let (a_peer, a_key) = (a.peer_id().await, a.verifying_key().await);
    let (b_peer, b_key) = (b.peer_id().await, b.verifying_key().await);
    a.add_peer(b_peer, b_key).await.unwrap();
    b.add_peer(a_peer, a_key).await.unwrap();
}

#[tokio::test]
async fn a_second_vault_converges_through_the_relay_alone() {
    let backend = Arc::new(MemoryBackend::default());
    let a = Vault::in_memory(VAULT_KEY).unwrap();
    let b = Vault::in_memory(VAULT_KEY).unwrap();
    vouch(&a, &b).await;

    a.set_entry("files", "k", "v1").await.unwrap();
    a.edit_text(TEXT_ID, 0, "hello from the browser")
        .await
        .unwrap();

    a.sync(&backend).await.unwrap();
    b.sync(&backend).await.unwrap();

    assert_eq!(b.get_entry("files", "k").await.as_deref(), Some("v1"));
    assert_eq!(b.text(TEXT_ID).await, "hello from the browser");
}

/// The relay must never see plaintext. This is the property that makes syncing
/// through a paid, third-party-operated backend acceptable at all, so it is
/// asserted rather than assumed.
#[tokio::test]
async fn the_relay_only_ever_holds_ciphertext() {
    let backend = Arc::new(MemoryBackend::default());
    let a = Vault::in_memory(VAULT_KEY).unwrap();
    let secret = "attack at dawn";
    a.set_entry("files", "plan", secret).await.unwrap();
    a.sync(&backend).await.unwrap();

    let key = roam_backend_client::crypto::VaultKey(VAULT_KEY);
    let bucket = key.bucket_id();
    let manifest = backend.manifest(&bucket).await.unwrap();
    assert!(
        !manifest.entry_ids.is_empty(),
        "nothing was uploaded, so this test would pass vacuously"
    );

    for id in &manifest.entry_ids {
        let ct = backend.get_entry(&bucket, id).await.unwrap().unwrap();
        assert!(
            !ct.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "plaintext found in the payload the relay stores"
        );
        // The id is opaque too: it is derived through the vault key, not from
        // the container/key names, so the relay cannot tell what changed.
        assert!(!id.contains("plan") && !id.contains("files"));
    }
}

/// A device that does not hold the vault key gets bytes it cannot read. Same
/// bucket, same relay, no content — the reader-scoping story in F1 builds on
/// this being true at the crypto layer first.
#[tokio::test]
async fn a_vault_with_the_wrong_key_learns_nothing() {
    let backend = Arc::new(MemoryBackend::default());
    let a = Vault::in_memory(VAULT_KEY).unwrap();
    let intruder = Vault::in_memory([9u8; 32]).unwrap();
    vouch(&a, &intruder).await;

    a.edit_text(TEXT_ID, 0, "private").await.unwrap();
    a.sync(&backend).await.unwrap();
    // A different vault key means a different bucket, so this is a clean miss
    // rather than a decryption failure — belt and braces both hold.
    intruder.sync(&backend).await.unwrap();

    assert_eq!(intruder.text(TEXT_ID).await, "");
}
