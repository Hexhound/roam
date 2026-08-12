//! Epoch-tagged AEAD: chacha20poly1305 body with a 32-byte epoch-id prefix.
//! Moved from roam-backend-client so both the backend and P2P transports share
//! one snapshot-decrypt primitive.
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("ciphertext too short")]
    Short,
    #[error("aead open failed")]
    Open,
}

/// Seal `plaintext` under an explicit epoch key, tagging the output with
/// `epoch_id`: returns `epoch_id(32) || nonce(24) || ct`. Callers writing under
/// epoch 0 use [`VaultKey::seal`] instead (untagged, legacy-compatible).
pub fn seal_epoch(epoch_key: &[u8; 32], epoch_id: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(epoch_key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut out = Vec::with_capacity(32 + 24 + plaintext.len() + 16);
    out.extend_from_slice(epoch_id);
    out.extend_from_slice(&nonce);
    let ct = cipher.encrypt(&nonce, plaintext).expect("aead encrypt");
    out.extend_from_slice(&ct);
    out
}

/// Open a `nonce(24) || ct` body (the epoch tag, if any, already stripped by the
/// caller via the keychain's `ReadPlan.body_offset`) under `epoch_key`.
pub fn open_epoch(epoch_key: &[u8; 32], body: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if body.len() < 24 {
        return Err(CryptoError::Short);
    }
    let (nonce_bytes, ct) = body.split_at(24);
    let cipher = XChaCha20Poly1305::new(epoch_key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce_bytes), ct)
        .map_err(|_| CryptoError::Open)
}
