//! Sealed-box wrapping of a 32-byte epoch key to an X25519 recipient.
//!
//! Anonymous-sender box (age/libsodium style): an ephemeral X25519 keypair does
//! DH with the recipient's static public; a BLAKE3-derived subkey seals the key
//! with XChaCha20-Poly1305. Sender-authenticity is NOT provided here — it comes
//! from the enclosing key-log entry's ed25519 signature (a signed entry from a
//! roster member vouches for its wrap blobs).

use crate::error::StorageError;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Wrapped blob layout: `eph_pub(32) || nonce(24) || ciphertext`.
const EPH_PUB_LEN: usize = 32;
const NONCE_LEN: usize = 24;

fn wrap_subkey(shared: &[u8; 32], eph_pub: &[u8; 32], recipient_pub: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(96);
    input.extend_from_slice(shared);
    input.extend_from_slice(eph_pub);
    input.extend_from_slice(recipient_pub);
    blake3::derive_key("roam keywrap v1", &input)
}

/// Seal `key` to `recipient_pub` (an X25519 public). Returns
/// `eph_pub(32) || nonce(24) || ct`.
pub fn wrap(recipient_pub: &[u8; 32], key: &[u8; 32]) -> Vec<u8> {
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&PublicKey::from(*recipient_pub));
    let subkey = wrap_subkey(&shared.to_bytes(), &eph_pub.to_bytes(), recipient_pub);

    let cipher = XChaCha20Poly1305::new((&subkey).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, key.as_slice())
        .expect("aead encrypt");

    let mut out = Vec::with_capacity(EPH_PUB_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(&eph_pub.to_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Open a blob produced by [`wrap`] using the recipient's X25519 static secret.
pub fn unwrap(recipient_secret: &[u8; 32], blob: &[u8]) -> Result<[u8; 32], StorageError> {
    if blob.len() < EPH_PUB_LEN + NONCE_LEN {
        return Err(StorageError::Keywrap);
    }
    let eph_pub: [u8; 32] = blob[..EPH_PUB_LEN].try_into().unwrap();
    let nonce = &blob[EPH_PUB_LEN..EPH_PUB_LEN + NONCE_LEN];
    let ct = &blob[EPH_PUB_LEN + NONCE_LEN..];

    let secret = StaticSecret::from(*recipient_secret);
    let recipient_pub = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(eph_pub));
    let subkey = wrap_subkey(&shared.to_bytes(), &eph_pub, &recipient_pub);

    let cipher = XChaCha20Poly1305::new((&subkey).into());
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| StorageError::Keywrap)?;
    pt.try_into().map_err(|_| StorageError::Keywrap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn target_opens_non_target_fails() {
        let target = Identity::generate();
        let other = Identity::generate();
        let key = [0x5au8; 32];

        let blob = wrap(&target.x25519_public(), &key);
        assert_eq!(unwrap(&target.x25519_secret(), &blob).unwrap(), key);
        assert!(unwrap(&other.x25519_secret(), &blob).is_err());
    }

    #[test]
    fn tamper_makes_open_fail() {
        let target = Identity::generate();
        let key = [1u8; 32];
        let mut blob = wrap(&target.x25519_public(), &key);
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(unwrap(&target.x25519_secret(), &blob).is_err());
    }

    #[test]
    fn short_blob_is_rejected_not_panicked() {
        let target = Identity::generate();
        assert!(unwrap(&target.x25519_secret(), &[0u8; 10]).is_err());
    }
}
