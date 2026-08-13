use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305, XNonce};

pub use roam_storage::epoch_crypto::{open_epoch, seal_epoch, CryptoError};

/// 256-bit symmetric vault key. Shared across a vault's devices; never sent to
/// the backend. Derives all opaque ids and seals/opens all payloads.
///
/// The root secret is wiped on drop ([`ZeroizeOnDrop`]) so it does not linger in
/// freed memory. Derived subkeys copied out via [`VaultKey::id_key`] /
/// [`VaultKey::epoch0_key`] are handed back as [`zeroize::Zeroizing`] so those
/// short-lived copies self-wipe too.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct VaultKey(pub [u8; 32]);

impl VaultKey {
    /// Independent subkey for opaque id derivation (keyed BLAKE3). Derived via
    /// the shared [`roam_storage::vault_subkeys`] so the backend id namespace and
    /// pairing's epoch-0 derivation can never drift apart.
    fn id_subkey(&self) -> zeroize::Zeroizing<[u8; 32]> {
        roam_storage::vault_subkeys(&self.0).0
    }

    /// Independent subkey for AEAD seal/open (XChaCha20-Poly1305). See
    /// [`Self::id_subkey`] — same shared-derivation rationale.
    fn aead_subkey(&self) -> zeroize::Zeroizing<[u8; 32]> {
        roam_storage::vault_subkeys(&self.0).1
    }

    fn keyed(&self, label_and_input: &[u8]) -> String {
        let hash = blake3::keyed_hash(&self.id_subkey(), label_and_input);
        B64URL.encode(hash.as_bytes())
    }

    /// Backend namespace id. Opaque to the server.
    pub fn bucket_id(&self) -> String {
        // v2: content-addressed entry ids + snapshots kind. A scheme bump moves the
        // whole vault to a new backend namespace, so mixed-scheme reconciliation
        // (positional vs content ids) can never happen.
        self.keyed(b"roam-bucket-v2")
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

    /// Content-addressed entry id = keyed(id_key, "entry" || peer_le || blake3(line)).
    /// Stable under op-log truncation: an entry's id is a function of its bytes, not
    /// its offset. Replaces the positional `entry_id(peer, index)`.
    pub fn entry_id_content(&self, peer_id: u64, line: &[u8]) -> String {
        let mut input = Vec::with_capacity(5 + 8 + 32);
        input.extend_from_slice(b"entry");
        input.extend_from_slice(&peer_id.to_le_bytes());
        input.extend_from_slice(blake3::hash(line).as_bytes());
        self.keyed(&input)
    }

    /// Snapshot backend id = keyed(id_key, "snapshot" || frontier_digest). Two
    /// devices snapshotting at the same frontier derive the same id (dedup).
    pub fn snapshot_id(&self, frontier_digest: &[u8; 32]) -> String {
        let mut input = Vec::with_capacity(8 + 32);
        input.extend_from_slice(b"snapshot");
        input.extend_from_slice(frontier_digest);
        self.keyed(&input)
    }

    /// The STABLE id-derivation key (never rotates). All backend ids derive from
    /// this; a rotated-out member keeps it (can enumerate ids) but not content.
    pub fn id_key(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.id_subkey()
    }

    /// The epoch-0 AEAD key (== today's scheme). Epoch 0 ciphertext is written
    /// UNTAGGED via [`VaultKey::seal`]; this exposes the key for the Keychain.
    pub fn epoch0_key(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.aead_subkey()
    }

    /// AEAD seal: returns `nonce(24) || ciphertext`.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let aead_key = self.aead_subkey();
        let cipher = XChaCha20Poly1305::new((&*aead_key).into());
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
        let cipher = XChaCha20Poly1305::new((&*aead_key).into());
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
    fn the_vault_key_is_wiped_on_drop() {
        // `VaultKey` is the root secret: it derives every id and seals/opens every
        // payload, and it lives for the whole process (held in `Engine`, the CLI,
        // and the pairing host). It must not survive in freed memory. The
        // `ZeroizeOnDrop` bound is the only portable proxy (freed memory can't be
        // inspected).
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<VaultKey>();
    }

    #[test]
    fn the_derived_subkeys_handed_out_are_wiped_on_drop() {
        // `id_key`/`epoch0_key` copy a subkey out of the root vault key. The AEAD
        // (epoch-0) subkey opens content; both must self-zeroize after use rather
        // than linger in freed stack/heap.
        let k = key();
        let _: zeroize::Zeroizing<[u8; 32]> = k.id_key();
        let _: zeroize::Zeroizing<[u8; 32]> = k.epoch0_key();
    }

    #[test]
    fn bucket_id_is_deterministic_and_opaque() {
        assert_eq!(key().bucket_id(), key().bucket_id());
        assert_ne!(key().bucket_id(), VaultKey([8u8; 32]).bucket_id());
        // url-safe, no path separators
        assert!(key()
            .bucket_id()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn bucket_id_carries_scheme_version() {
        let k = VaultKey([1u8; 32]);
        assert_eq!(k.bucket_id(), k.bucket_id());
        assert_eq!(k.bucket_id().len(), 43);
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

    #[test]
    fn epoch0_key_equals_legacy_aead_subkey_roundtrip() {
        let k = key();
        // A payload sealed with legacy `seal` must open under `epoch0_key` via
        // the tagged `open_epoch` (same key) — guarantees epoch 0 == today's scheme.
        let ct = k.seal(b"legacy bytes");
        let opened = open_epoch(&k.epoch0_key(), &ct).unwrap();
        assert_eq!(opened, b"legacy bytes");
    }

    #[test]
    fn seal_epoch_prepends_the_epoch_id_and_open_epoch_strips_it() {
        let epoch_key = [0x33u8; 32];
        let epoch_id = [0xEEu8; 32];
        let sealed = seal_epoch(&epoch_key, &epoch_id, b"secret v2");
        assert_eq!(&sealed[..32], &epoch_id, "epoch id must prefix the payload");
        let opened = open_epoch(&epoch_key, &sealed[32..]).unwrap();
        assert_eq!(opened, b"secret v2");
    }

    #[test]
    fn open_epoch_rejects_a_wrong_key() {
        let sealed = seal_epoch(&[1u8; 32], &[9u8; 32], b"x");
        assert!(open_epoch(&[2u8; 32], &sealed[32..]).is_err());
    }

    #[test]
    fn id_key_is_stable_and_public() {
        let k = key();
        assert_eq!(*k.id_key(), *k.id_key());
    }

    #[test]
    fn content_entry_id_is_stable_under_reordering() {
        let k = VaultKey([3u8; 32]);
        let line_a = b"{\"peer\":1,\"sig\":\"s\",\"update\":\"u1\"}\n";
        let line_b = b"{\"peer\":1,\"sig\":\"s\",\"update\":\"u2\"}\n";
        assert_eq!(k.entry_id_content(1, line_a), k.entry_id_content(1, line_a));
        assert_ne!(k.entry_id_content(1, line_a), k.entry_id_content(1, line_b));
        assert_ne!(k.entry_id_content(1, line_a), k.entry_id_content(2, line_a));
        assert_eq!(k.snapshot_id(&[1u8; 32]), k.snapshot_id(&[1u8; 32]));
        assert_ne!(k.snapshot_id(&[1u8; 32]), k.snapshot_id(&[2u8; 32]));
    }
}
