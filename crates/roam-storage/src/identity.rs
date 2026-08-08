use crate::error::StorageError;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey as DalekVerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A device's cryptographic identity: an ed25519 signing key plus the loro
/// `peer_id` it uses. MUST be stored OUTSIDE any synced vault folder — a
/// duplicated identity means two devices share a peer id and silently lose data.
#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
    peer_id: u64,
}

/// On-disk form of an [`Identity`].
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    peer_id: u64,
    /// base64 of the 32-byte ed25519 secret key.
    secret_key: String,
}

impl Identity {
    /// Generate a fresh identity with a random keypair and peer id.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        // Derive a stable, non-zero peer id from the public key.
        let vk = signing_key.verifying_key().to_bytes();
        let peer_id = u64::from_le_bytes(vk[0..8].try_into().unwrap());
        Self {
            signing_key,
            peer_id,
        }
    }

    pub fn peer_id(&self) -> u64 {
        self.peer_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.signing_key.verifying_key())
    }

    /// Sign a message (an update blob).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Persist to `path` (caller chooses a location outside the vault).
    pub fn save(&self, path: &Path) -> Result<(), StorageError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = IdentityFile {
            peer_id: self.peer_id,
            secret_key: B64.encode(self.signing_key.to_bytes()),
        };
        std::fs::write(path, serde_json::to_vec_pretty(&file)?)?;
        Ok(())
    }

    /// Load a previously saved identity.
    pub fn load(path: &Path) -> Result<Self, StorageError> {
        let bytes = std::fs::read(path)?;
        let file: IdentityFile = serde_json::from_slice(&bytes)?;
        let raw = B64
            .decode(file.secret_key.as_bytes())
            .map_err(|e| StorageError::Base64(e.to_string()))?;
        let raw: [u8; 32] = raw.try_into().map_err(|_| StorageError::MalformedIdentity)?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&raw),
            peer_id: file.peer_id,
        })
    }
}

/// A public key that can verify signatures over update blobs.
pub struct VerifyingKey(DalekVerifyingKey);

impl VerifyingKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, StorageError> {
        DalekVerifyingKey::from_bytes(bytes)
            .map(VerifyingKey)
            .map_err(|_| StorageError::MalformedIdentity)
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        self.0.verify(msg, sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generates_signs_and_verifies() {
        let id = Identity::generate();
        let msg = b"some update bytes";
        let sig = id.sign(msg);
        assert!(id.verifying_key().verify(msg, &sig));
        // A different message must not verify.
        assert!(!id.verifying_key().verify(b"tampered", &sig));
    }

    #[test]
    fn persists_and_reloads_outside_the_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");

        let id = Identity::generate();
        id.save(&path).unwrap();
        let reloaded = Identity::load(&path).unwrap();

        assert_eq!(id.peer_id(), reloaded.peer_id());
        assert_eq!(
            id.verifying_key().to_bytes(),
            reloaded.verifying_key().to_bytes()
        );
    }
}
