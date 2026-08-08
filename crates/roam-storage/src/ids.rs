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
}
