//! The single source of truth for deriving a vault key's two subkeys.
//!
//! A raw 32-byte vault key is never used directly; it derives two independent
//! BLAKE3 subkeys:
//! - the **stable id key** — keys every opaque backend id (`bucket`/`entry`/
//!   `blob`), and NEVER rotates, and
//! - the **epoch-0 AEAD key** — seals/opens epoch-0 (legacy) ciphertext.
//!
//! Both the backend client (which owns `VaultKey`) and the pairing handshake
//! (which must publish a joiner's epoch wraps) derive these; centralizing the
//! labels + derivation here means the two call sites can never silently drift
//! into disagreeing on the id namespace or epoch 0.
//!
//! WARNING: these two label strings are part of the on-disk/on-wire key
//! derivation. Changing either one re-derives every id and epoch-0 key, orphaning
//! every existing vault. They must NEVER change (the `roam-backend-client` prefix
//! is historical — it predates this module and is kept only for that reason).

/// Domain label for the stable id-derivation subkey.
pub const VAULT_ID_LABEL: &str = "roam-backend-client id-derivation v1";
/// Domain label for the epoch-0 AEAD subkey.
pub const VAULT_AEAD_LABEL: &str = "roam-backend-client aead v1";

/// Derive `(id_key, epoch0_key)` from a raw 32-byte vault key.
pub fn vault_subkeys(
    vault_key: &[u8; 32],
) -> (zeroize::Zeroizing<[u8; 32]>, zeroize::Zeroizing<[u8; 32]>) {
    (
        zeroize::Zeroizing::new(blake3::derive_key(VAULT_ID_LABEL, vault_key)),
        zeroize::Zeroizing::new(blake3::derive_key(VAULT_AEAD_LABEL, vault_key)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_derived_subkeys_are_wiped_on_drop() {
        // Both subkeys are content-relevant derivations of the root vault key
        // (the AEAD subkey seals/opens payloads; the id subkey keys the backend
        // namespace). The copies returned here must not linger in freed memory.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<zeroize::Zeroizing<[u8; 32]>>();
        let (id_key, epoch0_key) = vault_subkeys(&[3u8; 32]);
        let _: zeroize::Zeroizing<[u8; 32]> = id_key;
        let _: zeroize::Zeroizing<[u8; 32]> = epoch0_key;
    }

    #[test]
    fn subkeys_are_deterministic_distinct_and_stable() {
        let vk = [7u8; 32];
        let (id_a, aead_a) = vault_subkeys(&vk);
        let (id_b, aead_b) = vault_subkeys(&vk);
        assert_eq!(*id_a, *id_b);
        assert_eq!(*aead_a, *aead_b);
        assert_ne!(*id_a, *aead_a, "the two subkeys must be independent");

        // Freeze the exact byte values so an accidental label edit is caught here
        // (changing a label would orphan every existing vault).
        assert_eq!(
            *id_a,
            blake3::derive_key("roam-backend-client id-derivation v1", &vk)
        );
        assert_eq!(
            *aead_a,
            blake3::derive_key("roam-backend-client aead v1", &vk)
        );
    }
}
