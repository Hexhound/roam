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
//! mandatory. An attacker on the LAN who *guesses* three times can therefore
//! burn the budget and force the user to restart pairing. That is the correct
//! trade for a low-entropy code, and it is a deliberate difference from the
//! token flow rather than an oversight.
//!
//! # What spends an attempt
//!
//! A **wrong confirmation**, and nothing else. Not starting a run, not sending
//! an unparseable message, not disconnecting halfway.
//!
//! An earlier version charged when a run started, on the reasoning that
//! counting only failures "would let an attacker guess indefinitely by simply
//! disconnecting after learning their guess was wrong". An initiator cannot
//! learn that: `Msg2` is not testable against a candidate code, and the
//! responder's confirmation — the only oracle — is withheld until the initiator
//! proves first. That is precisely what makes the guess online, and being unable
//! to test one offline is the defining property of a PAKE.
//!
//! Charging at run start was also a denial of service. `respond` rejects
//! unparseable input, so three connections sending rubbish spent the entire
//! budget without guessing anything, retiring a pairing or share code on demand
//! from any device that could reach the endpoint — and the endpoint is announced
//! over mDNS. Guessing stays bounded either way, because a guess *is* a
//! confirmation.
//!
//! # Protocol
//!
//! ```text
//!   Initiator (types the code)              Responder (shows the code)
//!   ---------------------------             --------------------------
//!   start ────────── Msg1 ──────────────────▶  respond (costs nothing)
//!                  ◀────────── Msg2 ────────   reveals nothing testable
//!   confirm ──────── Confirm ───────────────▶  verify; wrong ⇒ spend an
//!                                              attempt and abort
//!                  ◀────────── Confirm ─────   only now does the responder
//!                                              prove anything or send data
//! ```
//!
//! The initiator proves first, so the responder never hands a confirmation
//! value to an unauthenticated peer. Everything after the handshake is sealed
//! under keys derived from the PAKE ([`SessionKey::split`]), so the code
//! protects confidentiality too, not merely authorisation — the payload stays
//! safe even if the transport underneath is compromised.
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
// Distinct contexts per direction: a message sealed by one side must not open
// as if the other had sent it.
const SEAL_I2R_CONTEXT: &str = "roam.pake.v1 payload seal initiator-to-responder";
const SEAL_R2I_CONTEXT: &str = "roam.pake.v1 payload seal responder-to-initiator";

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
/// A session carries a conversation, not one message, so this splits into a
/// send channel and a receive channel with **separate keys per direction** and a
/// per-message counter. Directions are separated so a message cannot be
/// reflected back at its sender; counters exist because reusing a nonce under
/// ChaCha20-Poly1305 loses confidentiality *and* authenticity outright, and a
/// fixed nonce would do exactly that on the second message.
///
/// [`SessionKey::split`] consumes the key, so there is no way to hold both this
/// and a channel and accidentally seal twice at counter zero.
pub struct SessionKey {
    initiator_to_responder: [u8; 32],
    responder_to_initiator: [u8; 32],
}

/// Which end of the session a party is, used to pick send/receive keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Initiator,
    Responder,
}

impl SessionKey {
    /// Split into `(send, receive)` for one side.
    pub fn split(self, side: Side) -> (Sealer, Opener) {
        let (send, receive) = match side {
            Side::Initiator => (self.initiator_to_responder, self.responder_to_initiator),
            Side::Responder => (self.responder_to_initiator, self.initiator_to_responder),
        };
        (
            Sealer {
                key: send,
                counter: 0,
            },
            Opener {
                key: receive,
                counter: 0,
            },
        )
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.initiator_to_responder.zeroize();
        self.responder_to_initiator.zeroize();
    }
}

/// Counter-based nonce. The counter occupies the low 8 bytes; the rest stay
/// zero. Unique per (key, counter), and the key is unique per run and direction.
fn nonce_for(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// The outbound half of a session. Each call advances the nonce.
pub struct Sealer {
    key: [u8; 32],
    counter: u64,
}

impl Sealer {
    /// Seal the next message.
    ///
    /// Takes `&mut self` so the counter cannot be skipped, and the counter is
    /// private so a caller cannot rewind it.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_for(self.counter)), plaintext)
            .expect("ChaCha20-Poly1305 encryption is infallible for in-memory input");
        // A session that reached 2^64 messages would wrap the nonce and destroy
        // the cipher's guarantees. Unreachable in practice; aborting is still
        // the only safe response if it ever happens.
        self.counter = self
            .counter
            .checked_add(1)
            .expect("PAKE session nonce counter overflowed");
        ciphertext
    }
}

impl Drop for Sealer {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

/// The inbound half of a session. Messages must arrive in the order they were
/// sealed; a gap or a repeat fails to open rather than being tolerated, which is
/// what makes replay and reordering non-issues at this layer.
pub struct Opener {
    key: [u8; 32],
    counter: u64,
}

impl Opener {
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, PakeError> {
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_for(self.counter)), ciphertext)
            .map_err(|_| PakeError::Undecryptable)?;
        self.counter = self
            .counter
            .checked_add(1)
            .expect("PAKE session nonce counter overflowed");
        Ok(plaintext)
    }
}

impl Drop for Opener {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
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
        initiator_to_responder: blake3::derive_key(SEAL_I2R_CONTEXT, spake_key),
        responder_to_initiator: blake3::derive_key(SEAL_R2I_CONTEXT, spake_key),
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
    /// **Spends no attempt.** The budget is charged by [`Responder::verify`],
    /// when a peer actually guesses and gets it wrong.
    ///
    /// An earlier version charged here, before any verification, reasoning that
    /// a peer which "starts a run and then vanishes has still used a guess". It
    /// has not: `msg2` carries nothing an initiator can test a password against,
    /// and the responder's own confirmation — the only oracle — is withheld
    /// until the initiator proves first. Being unable to test a guess offline is
    /// the defining property of a PAKE, so an abandoned run reveals nothing.
    ///
    /// Charging here was also exploitable. `start_b`'s `finish` rejects
    /// unparseable input, so three connections sending rubbish spent the whole
    /// budget without guessing anything — retiring a share code or pairing code
    /// on demand, from any device that can reach the endpoint (which is
    /// announced over mDNS). See the tests in `tests/handshake.rs`.
    pub fn respond(
        &mut self,
        initiator_id: [u8; 32],
        msg1: &[u8],
    ) -> Result<(PendingResponder, Vec<u8>), PakeError> {
        if self.attempts_left == 0 {
            return Err(PakeError::NoAttemptsLeft);
        }

        let (state, msg2) = Spake2::<Ed25519Group>::start_b(
            &Password::new(self.code.as_str().as_bytes()),
            &Identity::new(&initiator_id),
            &Identity::new(&self.responder_id),
        );
        let spake_key = state
            .finish(msg1)
            .map_err(|_| PakeError::MalformedMessage)?;
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

impl Responder {
    /// Verify the initiator's confirmation and, only if it is right, hand back
    /// our own confirmation plus the session key.
    ///
    /// **This is where an attempt is spent**, and only on a wrong one. Reaching
    /// this point means the peer committed to a guess, so a failure here is the
    /// one and only thing the budget is meant to count. The budget therefore
    /// lives on `Responder` and verification is a method on it, rather than on
    /// [`PendingResponder`] — that way there is no way to check a confirmation
    /// without charging for it.
    ///
    /// On failure nothing at all is returned: the responder must not reveal its
    /// confirmation value to a peer that has not proved it knows the code, or
    /// that value becomes an oracle to test guesses against.
    pub fn verify(
        &mut self,
        pending: PendingResponder,
        initiator_confirm: &[u8; 32],
    ) -> Result<(SessionKey, [u8; 32]), PakeError> {
        if self.attempts_left == 0 {
            return Err(PakeError::NoAttemptsLeft);
        }
        if !macs_match(&pending.expected, initiator_confirm) {
            self.attempts_left -= 1;
            return Err(PakeError::BadCode);
        }
        Ok((pending.key, pending.ours))
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

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sealer(<redacted>)")
    }
}

impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Opener(<redacted>)")
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
