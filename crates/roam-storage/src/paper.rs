//! Opt-in paper recovery key: an X25519 keypair derived from a user passphrase.
//! Epoch keys are wrapped to `public()` (a `Recipient::Paper` key-log entry).
//! With all devices lost, the user re-enters the passphrase, re-derives
//! `secret()`, and unwraps every epoch key.
//!
//! The passphrase is the one persistent secret the user must guard; deriving the
//! X25519 secret directly from a BLAKE3 KDF of the passphrase (no salt) keeps
//! recovery a pure function of the phrase. Choose a high-entropy printed phrase.

use x25519_dalek::{PublicKey, StaticSecret};

/// A paper key derived from a passphrase.
pub struct PaperKey {
    secret: [u8; 32],
}

impl PaperKey {
    /// Derive from a passphrase (e.g. a printed 12-word code).
    pub fn from_passphrase(passphrase: &str) -> Self {
        let secret = blake3::derive_key("roam paper recovery v1", passphrase.as_bytes());
        Self { secret }
    }

    /// The X25519 static secret (for unwrapping epoch keys during recovery).
    pub fn secret(&self) -> [u8; 32] {
        self.secret
    }

    /// The X25519 public (wrap epoch keys to this via `Recipient::Paper`).
    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(self.secret)).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keywrap;

    #[test]
    fn same_passphrase_derives_the_same_keypair() {
        let a = PaperKey::from_passphrase("correct horse battery staple");
        let b = PaperKey::from_passphrase("correct horse battery staple");
        assert_eq!(a.public(), b.public());
        assert_eq!(a.secret(), b.secret());
    }

    #[test]
    fn different_passphrases_differ() {
        assert_ne!(
            PaperKey::from_passphrase("phrase one").public(),
            PaperKey::from_passphrase("phrase two").public()
        );
    }

    #[test]
    fn an_epoch_key_wrapped_to_paper_recovers_from_the_passphrase_alone() {
        let paper = PaperKey::from_passphrase("recover me later");
        let epoch_key = [0x7fu8; 32];
        let blob = keywrap::wrap(&paper.public(), &epoch_key);

        let recovered = PaperKey::from_passphrase("recover me later");
        assert_eq!(
            keywrap::unwrap(&recovered.secret(), &blob).unwrap(),
            epoch_key
        );
    }
}
