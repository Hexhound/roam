use serde::{Deserialize, Serialize};

/// A 256-bit vault identifier, random at vault init and carried in every
/// pairing token. Every connection re-validates it. Also the iroh `NodeId` of
/// a device is exactly its ed25519 verifying key (`VerifyingKey::to_bytes()`),
/// so no separate node-id type is needed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct VaultId(pub [u8; 32]);

impl VaultId {
    /// Generate a fresh random vault id.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        VaultId(bytes)
    }

    /// The vault id implied by a vault key.
    ///
    /// For an app whose pairing hands over the vault key itself, a *random* id
    /// is a second thing to agree on: two devices holding identical keys would
    /// still generate different ids, reject each other's `Hello`, and present
    /// as "paired but never syncs". Deriving removes the possibility — same key,
    /// same vault, necessarily.
    ///
    /// Derived through `vault_subkeys` and a distinct label, so the id is not
    /// the key, not the id-subkey, and not any other derived value. It is
    /// carried in pairing tokens and revalidated on every connection, so it is
    /// public by design; recovering the key from it means inverting BLAKE3.
    pub fn derive(vault_key: &[u8; 32]) -> Self {
        let (id_key, _) = crate::vault_subkeys(vault_key);
        VaultId(*blake3::keyed_hash(&id_key, b"roam-vault-id").as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_key_always_derives_the_same_vault() {
        let key = [7u8; 32];
        assert_eq!(VaultId::derive(&key), VaultId::derive(&key));
    }

    #[test]
    fn different_keys_derive_different_vaults() {
        assert_ne!(VaultId::derive(&[7u8; 32]), VaultId::derive(&[8u8; 32]));
    }

    /// The id travels in pairing tokens and over the wire. Publishing the key,
    /// or the subkey that mints entry ids, would be a disclosure rather than an
    /// identifier.
    #[test]
    fn the_id_is_neither_the_key_nor_its_subkey() {
        let key = [7u8; 32];
        let (id_key, _) = crate::vault_subkeys(&key);
        assert_ne!(VaultId::derive(&key).0, key);
        assert_ne!(VaultId::derive(&key).0, *id_key);
    }
}
