use crate::error::StorageError;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey as DalekVerifyingKey};
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
        // Derive a stable peer id from the public key (first 8 bytes, little-endian).
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

    /// This identity's raw 32-byte ed25519 verifying-key bytes.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a message (an update blob).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// The raw 32-byte ed25519 secret, for constructing a transport key
    /// (e.g. `iroh::SecretKey`).
    ///
    /// This is the SAME secret already persisted by [`Identity::save`]; it is
    /// handed only to an in-process transport that must bind the SAME key so
    /// the device's iroh `NodeId` equals its ed25519 verifying key. Never log
    /// or serialize the returned bytes.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// This device's X25519 static secret, derived from its ed25519 signing key
    /// (the clamped ed25519 scalar). Pairs with [`Identity::x25519_public`] and
    /// with any peer's [`VerifyingKey::to_x25519`] for sealed-box key wrapping.
    /// Never log or serialize the returned bytes.
    pub fn x25519_secret(&self) -> [u8; 32] {
        self.signing_key.to_scalar_bytes()
    }

    /// This device's X25519 public key, derived from its ed25519 verifying key.
    pub fn x25519_public(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_montgomery().to_bytes()
    }

    /// Persist to `path` (caller chooses a location outside the vault).
    ///
    /// The file holds a raw ed25519 secret key, so this writes it as owner-only
    /// (`0600` on unix) and atomically (write to a temp file, then rename) — the
    /// secret is irreplaceable, so a half-written file must never clobber it.
    pub fn save(&self, path: &Path) -> Result<(), StorageError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = IdentityFile {
            peer_id: self.peer_id,
            secret_key: B64.encode(self.signing_key.to_bytes()),
        };
        let bytes = serde_json::to_vec_pretty(&file)?;

        let tmp = path.with_extension("key.tmp");
        std::fs::write(&tmp, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Load a previously saved identity.
    pub fn load(path: &Path) -> Result<Self, StorageError> {
        let bytes = std::fs::read(path)?;
        let file: IdentityFile = serde_json::from_slice(&bytes)?;
        let raw = B64
            .decode(file.secret_key.as_bytes())
            .map_err(|e| StorageError::Base64(e.to_string()))?;
        let raw: [u8; 32] = raw
            .try_into()
            .map_err(|_| StorageError::MalformedIdentity)?;
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

    /// The X25519 public key for this ed25519 verifying key (Montgomery form).
    /// Lets a sender wrap an epoch key to a roster member using only the key the
    /// roster already carries — no separate DH key, no roster migration.
    pub fn to_x25519(&self) -> [u8; 32] {
        self.0.to_montgomery().to_bytes()
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        // verify_strict rejects non-canonical / malleable signatures — the
        // recommended default for tamper detection.
        self.0.verify_strict(msg, sig).is_ok()
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
    fn secret_bytes_reconstructs_the_same_key() {
        let id = Identity::generate();
        let rebuilt = SigningKey::from_bytes(&id.secret_bytes());
        assert_eq!(
            rebuilt.verifying_key().to_bytes(),
            id.verifying_key().to_bytes(),
            "the secret bytes must reconstruct the same verifying key (== iroh NodeId)"
        );
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

    #[test]
    fn reloaded_identity_still_signs_correctly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let id = Identity::generate();
        id.save(&path).unwrap();
        let reloaded = Identity::load(&path).unwrap();

        // The reloaded secret key must produce signatures the original public key verifies.
        let msg = b"signed after reload";
        let sig = reloaded.sign(msg);
        assert!(id.verifying_key().verify(msg, &sig));
    }

    #[test]
    fn load_rejects_malformed_files() {
        let dir = tempdir().unwrap();

        // Not JSON at all.
        let bad_json = dir.path().join("bad.key");
        std::fs::write(&bad_json, b"not json").unwrap();
        assert!(matches!(
            Identity::load(&bad_json),
            Err(StorageError::Json(_))
        ));

        // Valid JSON, but the secret_key is not valid base64.
        let bad_b64 = dir.path().join("badb64.key");
        std::fs::write(
            &bad_b64,
            br#"{"peer_id":1,"secret_key":"!!!not base64!!!"}"#,
        )
        .unwrap();
        assert!(matches!(
            Identity::load(&bad_b64),
            Err(StorageError::Base64(_))
        ));

        // Valid base64, but wrong length for an ed25519 secret key.
        let wrong_len = dir.path().join("wronglen.key");
        std::fs::write(&wrong_len, br#"{"peer_id":1,"secret_key":"YWJj"}"#).unwrap(); // "abc"
        assert!(matches!(
            Identity::load(&wrong_len),
            Err(StorageError::MalformedIdentity)
        ));
    }

    #[test]
    fn ed25519_converts_to_a_matching_x25519_keypair() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let a = Identity::generate();
        let b = Identity::generate();

        let a_sec = StaticSecret::from(a.x25519_secret());
        let b_sec = StaticSecret::from(b.x25519_secret());
        let a_pub = PublicKey::from(a.x25519_public());
        let b_pub = PublicKey::from(b.x25519_public());

        assert_eq!(PublicKey::from(&a_sec).to_bytes(), a_pub.to_bytes());

        assert_eq!(
            a_sec.diffie_hellman(&b_pub).to_bytes(),
            b_sec.diffie_hellman(&a_pub).to_bytes()
        );
    }

    #[test]
    fn verifying_key_x25519_matches_identity_x25519_public() {
        let a = Identity::generate();
        assert_eq!(a.verifying_key().to_x25519(), a.x25519_public());
    }

    #[cfg(unix)]
    #[test]
    fn saved_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");
        Identity::generate().save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "identity file must be owner-only");
    }
}
