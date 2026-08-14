//! Short-code pairing over SPAKE2 — for the LAN, where the user reads six
//! digits off one device and types them into another.
//!
//! # Why a PAKE, and not `sign(code)`
//!
//! A six-digit code is ~20 bits. If the code were signed, or hashed, or used as
//! a key directly, an attacker who watched one handshake could try all million
//! candidates **offline** in well under a second. A PAKE is what makes a code
//! this short usable at all: the code never crosses the wire in any form, and an
//! active attacker gets **exactly one guess per protocol run** — there is no
//! offline attack, because testing a candidate would require solving a discrete
//! log. Bound the number of runs and a 20-bit secret becomes genuinely hard.
//!
//! That is the whole design, and it only holds if all three parts hold:
//!
//! 1. **SPAKE2**, so a run leaks nothing about the code.
//! 2. **Identity binding** — both endpoint ids go into the SPAKE2 identities, so
//!    a key agreed with one device cannot be relayed to another. This is what
//!    closes same-LAN MITM.
//! 3. **A bounded attempt budget** ([`MAX_ATTEMPTS`]), so the one-guess-per-run
//!    limit actually bounds anything.
//!
//! # This reverses the DoS trade made for token pairing, on purpose
//!
//! Token pairing (`roam-transport-iroh::pairing`) deliberately does *not*
//! consume its session on a failed attempt: its secret is 256 bits, so guessing
//! is hopeless and the real risk is a hostile peer burning the user's session.
//! Here the secret is 20 bits, so the risk is inverted and the budget is
//! mandatory. An attacker on the LAN can therefore burn the budget and force the
//! user to restart pairing. That is the correct trade for a low-entropy code,
//! and it is a deliberate difference from the token flow rather than an
//! oversight.
//!
//! An attempt is spent when a run **starts**, not when it fails. Counting
//! failures instead would let an attacker guess indefinitely by simply
//! disconnecting after learning their guess was wrong.
//!
//! # Protocol
//!
//! ```text
//!   Initiator (types the code)              Responder (shows the code)
//!   ---------------------------             --------------------------
//!   start ────────── Msg1 ──────────────────▶  (spends one attempt)
//!                  ◀────────── Msg2 ────────   respond
//!   confirm ──────── Confirm ───────────────▶  verify; wrong ⇒ abort
//!                  ◀────────── Confirm ─────   only now does the responder
//!                                              prove anything or send data
//! ```
//!
//! The initiator proves first, so the responder never hands a confirmation
//! value to an unauthenticated peer. Payloads are sealed under a key derived
//! from the PAKE ([`SessionKey`]), so the code protects the payload's
//! confidentiality too, not merely authorisation — the vault key stays safe even
//! if the transport underneath is compromised.
//!
//! # Caveat worth stating plainly
//!
//! `spake2` (RustCrypto/PAKEs) is not independently audited. It is the best
//! maintained Rust option and is the same implementation magic-wormhole relies
//! on, but that is a reason for care, not comfort. The protocol above is a
//! standard composition (SPAKE2 + key confirmation + bound identities) chosen
//! precisely so nothing bespoke is doing security work.

pub mod code;

pub use code::{CodeError, PairingCode, CODE_DIGITS};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use spake2::{Ed25519Group, Identity, Password, Spake2};

/// How many runs a single displayed code allows before it is dead.
///
/// Each run is one guess, so this is the attacker's total probability of
/// success: 3 in 10^6. Raising it trades that off directly.
pub const MAX_ATTEMPTS: u32 = 3;

/// Domain separator; distinguishes these transcripts from every other signature
/// or MAC in roam.
const CONFIRM_CONTEXT: &str = "roam.pake.v1 key confirmation";
const SEAL_CONTEXT: &str = "roam.pake.v1 payload seal";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PakeError {
    #[error("the pairing code did not match")]
    BadCode,
    #[error("malformed handshake message")]
    MalformedMessage,
    #[error("this pairing code is used up — ask for a fresh one")]
    NoAttemptsLeft,
    #[error("could not decrypt the sealed payload")]
    Undecryptable,
}

/// Keys derived from a completed handshake.
///
/// Unique per run, which is why [`SessionKey::seal`] can use a fixed nonce.
pub struct SessionKey {
    seal_key: [u8; 32],
}

impl SessionKey {
    /// Seal one payload.
    ///
    /// # Single use
    ///
    /// The nonce is fixed. That is safe **only** because the key is derived
    /// fresh from one PAKE run and this protocol sends exactly one sealed
    /// payload. Sending a second message under the same `SessionKey` would reuse
    /// the nonce and break ChaCha20-Poly1305 catastrophically — add a counter to
    /// the nonce and a direction tag to the key derivation first.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(&self.seal_key.into());
        cipher
            .encrypt(Nonce::from_slice(&[0u8; 12]), plaintext)
            .expect("ChaCha20-Poly1305 encryption is infallible for in-memory input")
    }

    pub fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PakeError> {
        let cipher = ChaCha20Poly1305::new(&self.seal_key.into());
        cipher
            .decrypt(Nonce::from_slice(&[0u8; 12]), ciphertext)
            .map_err(|_| PakeError::Undecryptable)
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.seal_key.zeroize();
    }
}

/// Which side of the handshake a confirmation value came from. Tagging keeps a
/// confirmation from being echoed straight back as the peer's own.
#[derive(Clone, Copy)]
enum Role {
    Initiator = 1,
    Responder = 2,
}

/// The confirmation MAC over the full transcript.
///
/// Binding both messages means a relayed or spliced transcript produces a
/// different value, so the confirmation covers the whole run rather than just
/// the key.
fn confirm_mac(
    spake_key: &[u8],
    role: Role,
    initiator_id: &[u8; 32],
    responder_id: &[u8; 32],
    msg1: &[u8],
    msg2: &[u8],
) -> [u8; 32] {
    let confirm_key = blake3::derive_key(CONFIRM_CONTEXT, spake_key);
    let mut hasher = blake3::Hasher::new_keyed(&confirm_key);
    hasher.update(&[role as u8]);
    hasher.update(initiator_id);
    hasher.update(responder_id);
    // Length-prefixed so two different (msg1, msg2) splits cannot produce the
    // same byte stream.
    hasher.update(&(msg1.len() as u64).to_le_bytes());
    hasher.update(msg1);
    hasher.update(&(msg2.len() as u64).to_le_bytes());
    hasher.update(msg2);
    *hasher.finalize().as_bytes()
}

fn session_key(spake_key: &[u8]) -> SessionKey {
    SessionKey {
        seal_key: blake3::derive_key(SEAL_CONTEXT, spake_key),
    }
}

/// Compare two confirmation values without leaking where they differ.
///
/// `blake3::Hash`'s `PartialEq` is documented as constant-time; going through it
/// rather than comparing byte slices avoids the usual early-return timing leak.
fn macs_match(a: &[u8; 32], b: &[u8; 32]) -> bool {
    blake3::Hash::from(*a) == blake3::Hash::from(*b)
}

/// The side that **types** the code and dials out.
pub struct Initiator {
    state: Spake2<Ed25519Group>,
    initiator_id: [u8; 32],
    responder_id: [u8; 32],
    msg1: Vec<u8>,
}

impl Initiator {
    /// Begin a run. Returns the first wire message.
    ///
    /// `initiator_id` / `responder_id` are the two endpoint ids (for iroh, the
    /// devices' public keys). They are bound into the exchange, so a key agreed
    /// with one device is worthless when replayed at another.
    pub fn start(
        code: &PairingCode,
        initiator_id: [u8; 32],
        responder_id: [u8; 32],
    ) -> (Self, Vec<u8>) {
        let (state, msg1) = Spake2::<Ed25519Group>::start_a(
            &Password::new(code.as_str().as_bytes()),
            &Identity::new(&initiator_id),
            &Identity::new(&responder_id),
        );
        let me = Initiator {
            state,
            initiator_id,
            responder_id,
            msg1: msg1.clone(),
        };
        (me, msg1)
    }

    /// Process the responder's message and produce our confirmation.
    ///
    /// Returns the confirmation to send and a pending state that will only
    /// yield a [`SessionKey`] once the responder's own confirmation checks out.
    pub fn accept(self, msg2: &[u8]) -> Result<(PendingInitiator, [u8; 32]), PakeError> {
        let spake_key = self
            .state
            .finish(msg2)
            .map_err(|_| PakeError::MalformedMessage)?;
        let ours = confirm_mac(
            &spake_key,
            Role::Initiator,
            &self.initiator_id,
            &self.responder_id,
            &self.msg1,
            msg2,
        );
        let theirs = confirm_mac(
            &spake_key,
            Role::Responder,
            &self.initiator_id,
            &self.responder_id,
            &self.msg1,
            msg2,
        );
        Ok((
            PendingInitiator {
                expected: theirs,
                key: session_key(&spake_key),
            },
            ours,
        ))
    }
}

/// Waiting on the responder to prove it knows the code too.
pub struct PendingInitiator {
    expected: [u8; 32],
    key: SessionKey,
}

impl PendingInitiator {
    /// Verify the responder's confirmation. Mutual authentication only completes
    /// here — a payload received before this must not be acted on.
    pub fn verify(self, responder_confirm: &[u8; 32]) -> Result<SessionKey, PakeError> {
        if !macs_match(&self.expected, responder_confirm) {
            return Err(PakeError::BadCode);
        }
        Ok(self.key)
    }
}

/// The side that **shows** the code and accepts connections.
///
/// Owns the attempt budget, because it is the side an attacker guesses against.
pub struct Responder {
    code: PairingCode,
    responder_id: [u8; 32],
    attempts_left: u32,
}

impl Responder {
    pub fn new(code: PairingCode, responder_id: [u8; 32]) -> Self {
        Responder {
            code,
            responder_id,
            attempts_left: MAX_ATTEMPTS,
        }
    }

    pub fn attempts_left(&self) -> u32 {
        self.attempts_left
    }

    /// Handle an incoming run.
    ///
    /// **Spends one attempt immediately**, before any verification. A peer that
    /// starts a run and then vanishes has still used a guess; counting only
    /// failures would leave the budget trivially bypassable.
    pub fn respond(
        &mut self,
        initiator_id: [u8; 32],
        msg1: &[u8],
    ) -> Result<(PendingResponder, Vec<u8>), PakeError> {
        if self.attempts_left == 0 {
            return Err(PakeError::NoAttemptsLeft);
        }
        self.attempts_left -= 1;

        let (state, msg2) = Spake2::<Ed25519Group>::start_b(
            &Password::new(self.code.as_str().as_bytes()),
            &Identity::new(&initiator_id),
            &Identity::new(&self.responder_id),
        );
        let spake_key = state.finish(msg1).map_err(|_| PakeError::MalformedMessage)?;
        Ok((
            PendingResponder {
                expected: confirm_mac(
                    &spake_key,
                    Role::Initiator,
                    &initiator_id,
                    &self.responder_id,
                    msg1,
                    &msg2,
                ),
                ours: confirm_mac(
                    &spake_key,
                    Role::Responder,
                    &initiator_id,
                    &self.responder_id,
                    msg1,
                    &msg2,
                ),
                key: session_key(&spake_key),
            },
            msg2,
        ))
    }
}

/// Waiting on the initiator to prove it knows the code.
pub struct PendingResponder {
    expected: [u8; 32],
    ours: [u8; 32],
    key: SessionKey,
}

impl PendingResponder {
    /// Verify the initiator's confirmation and, only if it is right, hand back
    /// our own confirmation plus the session key.
    ///
    /// On failure nothing at all is returned: the responder must not reveal its
    /// confirmation value to a peer that has not proved it knows the code.
    pub fn verify(
        self,
        initiator_confirm: &[u8; 32],
    ) -> Result<(SessionKey, [u8; 32]), PakeError> {
        if !macs_match(&self.expected, initiator_confirm) {
            return Err(PakeError::BadCode);
        }
        Ok((self.key, self.ours))
    }
}

// ---------------------------------------------------------------------------
// Debug impls. Hand-written and redacting: these types hold key material, and a
// derived `Debug` would put it in the first log line or panic message that
// touches them.
// ---------------------------------------------------------------------------

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

impl std::fmt::Debug for PendingInitiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingInitiator(<redacted>)")
    }
}

impl std::fmt::Debug for PendingResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingResponder(<redacted>)")
    }
}
