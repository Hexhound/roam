//! The short numeric code a human reads off one screen and types into another.

use rand::RngCore;
use std::fmt;

/// Digits in a pairing code.
///
/// Six digits is ~20 bits — **far** too weak to be a secret on its own. It is
/// only safe because it is never sent, never used as a key directly, and can be
/// guessed at most [`crate::MAX_ATTEMPTS`] times before the session dies. Every
/// one of those properties is load-bearing; see the crate docs.
pub const CODE_DIGITS: usize = 6;

const CODE_SPACE: u32 = 1_000_000; // 10^CODE_DIGITS

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    #[error("a pairing code is exactly {CODE_DIGITS} digits")]
    WrongLength,
    #[error("a pairing code contains only digits")]
    NotAllDigits,
}

/// A validated pairing code.
///
/// Deliberately not `Copy` and not `Display`-cheap to misuse: it is a secret for
/// the length of one pairing, and it must never be logged.
#[derive(Clone, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
pub struct PairingCode(String);

impl PairingCode {
    /// A fresh uniformly-random code from the OS CSPRNG.
    ///
    /// Uses rejection sampling rather than `% CODE_SPACE`. The modulo bias here
    /// would be about one part in 10^13 — negligible in practice — but a
    /// reviewer should not have to work that out to convince themselves the
    /// code is uniform, and rejection costs nothing.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        // Largest multiple of CODE_SPACE that fits in u32; anything at or above
        // it would skew the low values.
        let limit = (u32::MAX / CODE_SPACE) * CODE_SPACE;
        loop {
            let candidate = rng.next_u32();
            if candidate < limit {
                return PairingCode(format!(
                    "{:0width$}",
                    candidate % CODE_SPACE,
                    width = CODE_DIGITS
                ));
            }
        }
    }

    /// Parse a code a user typed. Whitespace is trimmed; nothing else is
    /// "helpfully" corrected, because a code that nearly matches is a wrong
    /// code.
    pub fn parse(raw: &str) -> Result<Self, CodeError> {
        let trimmed = raw.trim();
        if trimmed.chars().count() != CODE_DIGITS {
            return Err(CodeError::WrongLength);
        }
        if !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return Err(CodeError::NotAllDigits);
        }
        Ok(PairingCode(trimmed.to_string()))
    }

    /// The digits, for display on the host's screen.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Redacted: a pairing code must never reach a log or a bug report.
impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(<redacted>)")
    }
}
