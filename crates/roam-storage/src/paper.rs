//! Opt-in paper recovery key: an X25519 keypair derived from a user passphrase.
//! Epoch keys are wrapped to `public()` (a `Recipient::Paper` key-log entry).
//! With all devices lost, the user re-enters the passphrase, re-derives
//! `secret()`, and unwraps every epoch key.
//!
//! The passphrase is the one persistent secret the user must guard; deriving the
//! X25519 secret directly from a BLAKE3 KDF of the passphrase (no salt) keeps
//! recovery a pure function of the phrase. Choose a high-entropy printed phrase.

use argon2::{Algorithm, Argon2, Params, Version};
use x25519_dalek::{PublicKey, StaticSecret};

/// Fixed domain salt. Recovery must stay a pure function of the passphrase (no
/// device survives to hold a per-user salt), so the salt is a constant — the
/// memory-hardness, not a secret salt, is what defends the replicated wrap blobs.
/// This value and the params below are frozen: changing either breaks recovery
/// of every already-wrapped epoch key.
const PAPER_SALT: &[u8] = b"roam-paper-recovery-v1--";

/// Argon2id cost parameters (memory KiB, iterations, lanes, 32-byte output).
/// 64 MiB / 3 passes — recovery is rare, so a heavy factor is affordable and
/// makes offline brute force of the passphrase expensive.
fn paper_argon2() -> Argon2<'static> {
    let params = Params::new(65536, 3, 1, Some(32)).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// A paper key derived from a passphrase.
///
/// The 32-byte X25519 recovery secret is wiped on drop ([`ZeroizeOnDrop`]) so it
/// does not survive in freed memory after use.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct PaperKey {
    secret: [u8; 32],
}

/// Crockford base32 alphabet — omits I, L, O, U so a printed phrase has no
/// visually ambiguous symbols to mis-transcribe.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encode 20 random bytes (160 bits) as 32 Crockford base32 symbols, grouped in
/// eights of four with `-` for legible transcription (e.g. `K3M9-...`).
fn encode_phrase(entropy: &[u8; 20]) -> String {
    let mut symbols = [0u8; 32];
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = 0usize;
    for &byte in entropy {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            symbols[out] = CROCKFORD[((acc >> bits) & 0x1f) as usize];
            out += 1;
        }
    }
    debug_assert_eq!(out, 32, "160 bits encodes to exactly 32 base32 symbols");
    // Regroup into 8 blocks of 4, hyphen-separated.
    let mut phrase = String::with_capacity(32 + 7);
    for (i, chunk) in symbols.chunks(4).enumerate() {
        if i > 0 {
            phrase.push('-');
        }
        phrase.push_str(std::str::from_utf8(chunk).expect("Crockford is ASCII"));
    }
    phrase
}

impl PaperKey {
    /// Generate a fresh, high-entropy paper phrase and the key it derives.
    ///
    /// The **app**, not the user, must mint the recovery phrase: Argon2id raises
    /// the cost of brute-forcing a phrase but cannot rescue a weak one, and the
    /// `Recipient::Paper` wrap blobs that seal epoch keys replicate to the backend
    /// and every peer — an offline attacker grinds them freely. This draws 160
    /// bits from the OS CSPRNG (comfortably past 128-bit), so the phrase is not
    /// guessable. Returns `(key, phrase)`; show the phrase once for the user to
    /// print, then drop it. Recovery is re-entering the phrase **verbatim** into
    /// [`from_passphrase`](PaperKey::from_passphrase).
    pub fn generate() -> (Self, String) {
        use rand::RngCore;
        let mut entropy = [0u8; 20];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        let phrase = encode_phrase(&entropy);
        let key = Self::from_passphrase(&phrase);
        (key, phrase)
    }

    /// Derive from a passphrase (e.g. a printed 12-word code).
    ///
    /// Uses Argon2id (memory-hard) over a fixed domain salt: the wrap blobs that
    /// seal epoch keys to this key replicate to the backend and every peer, so a
    /// fast KDF would let an offline attacker brute-force the passphrase cheaply.
    pub fn from_passphrase(passphrase: &str) -> Self {
        let mut secret = [0u8; 32];
        paper_argon2()
            .hash_password_into(passphrase.as_bytes(), PAPER_SALT, &mut secret)
            .expect("argon2 derivation into a 32-byte buffer never fails");
        Self { secret }
    }

    /// The X25519 static secret (for unwrapping epoch keys during recovery).
    pub fn secret(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.secret)
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
    fn the_paper_kdf_is_memory_hard_argon2id_not_a_fast_hash() {
        // The paper-recovery wrap blobs replicate to the backend and every peer,
        // so an offline attacker can brute-force the passphrase against them. A
        // fast hash (BLAKE3) makes that cheap; the derivation MUST be Argon2id.
        // Recompute independently with the same pinned params + fixed domain salt
        // and assert the production KDF matches — a regression to any fast hash,
        // or a silent param/salt change (which would also break recovery), fails.
        use argon2::{Algorithm, Argon2, Params, Version};

        let passphrase = "correct horse battery staple";
        let params = Params::new(65536, 3, 1, Some(32)).unwrap();
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut expected = [0u8; 32];
        argon
            .hash_password_into(
                passphrase.as_bytes(),
                b"roam-paper-recovery-v1--",
                &mut expected,
            )
            .unwrap();

        assert_eq!(*PaperKey::from_passphrase(passphrase).secret(), expected);
    }

    #[test]
    fn generate_produces_a_high_entropy_phrase_that_recovers_its_own_key() {
        // The app MUST generate the paper phrase (Argon2id only slows brute
        // force; it cannot rescue a low-entropy user-typed phrase). `generate`
        // draws 160 bits from the OS CSPRNG, so the phrase carries 32 Crockford
        // base32 symbols (grouped with '-'). Re-entering the phrase verbatim
        // MUST reproduce the same key — recovery stays a pure function of it.
        let (key, phrase) = PaperKey::generate();
        let symbols: String = phrase.chars().filter(|c| *c != '-').collect();
        assert_eq!(symbols.len(), 32, "160 bits / 5 = 32 base32 symbols");
        const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        assert!(
            symbols.chars().all(|c| CROCKFORD.contains(c)),
            "phrase must use only unambiguous Crockford base32 symbols: {phrase}"
        );
        assert_eq!(
            PaperKey::from_passphrase(&phrase).public(),
            key.public(),
            "the returned phrase, re-entered verbatim, must recover the key"
        );
    }

    #[test]
    fn generate_is_unpredictable_across_calls() {
        // Two generations must not collide — otherwise the entropy claim is a lie.
        let (_, a) = PaperKey::generate();
        let (_, b) = PaperKey::generate();
        assert_ne!(a, b, "each generated phrase must be independently random");
    }

    #[test]
    fn paper_key_wipes_its_secret_on_drop() {
        // The derived X25519 recovery secret must not linger in freed memory
        // after the key is dropped — a passphrase-derived long-lived secret is
        // exactly the kind of material a memory scrape should not recover. The
        // guarantee is carried by the `ZeroizeOnDrop` bound (the only portable,
        // observable proxy: post-free memory can't be inspected safely).
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<PaperKey>();
    }

    #[test]
    fn the_exported_recovery_secret_is_wiped_on_drop() {
        // `secret()` hands out a COPY of the recovery X25519 secret; it must
        // self-zeroize even though `PaperKey` itself is `ZeroizeOnDrop`.
        let paper = PaperKey::from_passphrase("guard me later");
        let _: zeroize::Zeroizing<[u8; 32]> = paper.secret();
    }

    #[test]
    fn same_passphrase_derives_the_same_keypair() {
        let a = PaperKey::from_passphrase("correct horse battery staple");
        let b = PaperKey::from_passphrase("correct horse battery staple");
        assert_eq!(a.public(), b.public());
        assert_eq!(*a.secret(), *b.secret());
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
            *keywrap::unwrap(&recovered.secret(), &blob).unwrap(),
            epoch_key
        );
    }
}
