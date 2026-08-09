use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

/// 256-bit symmetric vault key. Shared across a vault's devices; never sent to
/// the backend. Derives all opaque ids and seals/opens all payloads.
#[derive(Clone)]
pub struct VaultKey(pub [u8; 32]);

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("ciphertext too short")]
    Short,
    #[error("aead open failed")]
    Open,
}

impl VaultKey {
    /// Independent subkey for opaque id derivation (keyed BLAKE3).
    fn id_subkey(&self) -> [u8; 32] {
        blake3::derive_key("roam-backend-client id-derivation v1", &self.0)
    }

    /// Independent subkey for AEAD seal/open (XChaCha20-Poly1305).
    fn aead_subkey(&self) -> [u8; 32] {
        blake3::derive_key("roam-backend-client aead v1", &self.0)
    }

    fn keyed(&self, label_and_input: &[u8]) -> String {
        let hash = blake3::keyed_hash(&self.id_subkey(), label_and_input);
        B64URL.encode(hash.as_bytes())
    }

    /// Backend namespace id. Opaque to the server.
    pub fn bucket_id(&self) -> String {
        self.keyed(b"roam-bucket")
    }

    /// Deterministic per-entry id = keyed(vault_key, "entry" || peer_le || index_le).
    /// `index` is the 0-based line number within that peer's op-log.
    pub fn entry_id(&self, peer_id: u64, index: u64) -> String {
        let mut input = Vec::with_capacity(5 + 16);
        input.extend_from_slice(b"entry");
        input.extend_from_slice(&peer_id.to_le_bytes());
        input.extend_from_slice(&index.to_le_bytes());
        self.keyed(&input)
    }

    /// Deterministic blob id = keyed(vault_key, "blob" || content_hash_hex).
    /// `content_hash` is the existing BLAKE3 hex of the PLAINTEXT blob bytes,
    /// so every device derives the same id (nonce never enters here).
    pub fn blob_id(&self, content_hash: &str) -> String {
        let mut input = Vec::with_capacity(4 + content_hash.len());
        input.extend_from_slice(b"blob");
        input.extend_from_slice(content_hash.as_bytes());
        self.keyed(&input)
    }

    /// AEAD seal: returns `nonce(24) || ciphertext`.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let aead_key = self.aead_subkey();
        let cipher = XChaCha20Poly1305::new((&aead_key).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut out = nonce.to_vec();
        let ct = cipher.encrypt(&nonce, plaintext).expect("aead encrypt");
        out.extend_from_slice(&ct);
        out
    }

    /// AEAD open of a `nonce(24) || ciphertext` payload.
    pub fn open(&self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if payload.len() < 24 {
            return Err(CryptoError::Short);
        }
        let (nonce_bytes, ct) = payload.split_at(24);
        let aead_key = self.aead_subkey();
        let cipher = XChaCha20Poly1305::new((&aead_key).into());
        let nonce = XNonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, ct).map_err(|_| CryptoError::Open)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> VaultKey {
        VaultKey([7u8; 32])
    }

    #[test]
    fn bucket_id_is_deterministic_and_opaque() {
        assert_eq!(key().bucket_id(), key().bucket_id());
        assert_ne!(key().bucket_id(), VaultKey([8u8; 32]).bucket_id());
        // url-safe, no path separators
        assert!(key().bucket_id().chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn entry_id_matches_across_devices_for_same_peer_and_index() {
        assert_eq!(key().entry_id(42, 3), key().entry_id(42, 3));
        assert_ne!(key().entry_id(42, 3), key().entry_id(42, 4));
        assert_ne!(key().entry_id(42, 3), key().entry_id(43, 3));
    }

    #[test]
    fn blob_id_is_keyed_over_content_hash() {
        assert_eq!(key().blob_id("abc"), key().blob_id("abc"));
        assert_ne!(key().blob_id("abc"), key().blob_id("abd"));
        assert_ne!(key().blob_id("abc"), VaultKey([8u8; 32]).blob_id("abc"));
    }

    #[test]
    fn seal_open_round_trips() {
        let k = key();
        let ct = k.seal(b"hello world");
        assert_ne!(&ct[..], b"hello world");
        assert_eq!(k.open(&ct).unwrap(), b"hello world");
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let k = key();
        let mut ct = k.seal(b"secret");
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        assert!(k.open(&ct).is_err());
    }

    #[test]
    fn seal_uses_fresh_nonce_each_call() {
        let k = key();
        assert_ne!(k.seal(b"x"), k.seal(b"x"));
    }
}
