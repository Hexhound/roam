//! The public half of an invitation. The secret half is six digits, and it is
//! deliberately not in here.
//!
//! # Why two values instead of one
//!
//! The obvious design is one secret that names the mailbox *and* authenticates —
//! derive the rendezvous id from the pairing code and be done. It does not work,
//! and the reason is worth writing down because the design looks fine until you
//! count.
//!
//! A six-digit code is about twenty bits. Derive the rendezvous id from it and
//! anyone can compute all 10^6 ids offline, poll the relay, and learn which ones
//! currently exist — that is, find every live pairing session in the world and
//! spend [`roam_pake::MAX_ATTEMPTS`] guesses against each. The PAKE's whole
//! guarantee is that a guess must be online and is therefore countable. Making
//! the mailbox address a function of the code converts that into a farm.
//!
//! So the two jobs are split, and each value is sized for its own job:
//!
//! * **The rendezvous id** — 32 random bytes. Not a secret; it only has to be
//!   unguessable, so that nobody can enumerate live sessions. It is what the
//!   relay routes on.
//! * **The pairing code** — six digits. The actual secret, and the only thing
//!   that authenticates. Never sent, in any form, by either side.
//!
//! # What this buys over a bearer token
//!
//! The existing QR token is a bearer secret: a screenshot of it is the vault.
//! Here the QR can carry the [`Invite`] and the human can read the six digits
//! aloud, so a leaked QR gives an attacker a mailbox address and nothing else.
//! An app that puts both in one QR is no worse off than it is today, and an app
//! that separates them is meaningfully better off. That choice belongs to the
//! app, which is why the code is not a field here.
//!
//! # The relay's own view
//!
//! Nothing in an `Invite` reaches the relay except the rendezvous id. Not the
//! host key, not the relay-side identity of the vault — the bucket id is a
//! function of the vault key and appears nowhere in pairing, so the relay cannot
//! tell which of the buckets it stores a given pairing belongs to, or whether it
//! stores it at all.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use serde::{Deserialize, Serialize};

/// Bytes in a rendezvous id. Sized to be unguessable rather than to be typed —
/// nobody types this, it rides a QR or a link.
pub const RENDEZVOUS_BYTES: usize = 32;

/// The public half of an invitation: where to meet, and who is waiting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invite {
    /// The mailbox to meet at. Unguessable, single-purpose, and unrelated to the
    /// vault — deriving it from the bucket id would tell the relay which vault
    /// every pairing belonged to.
    pub rendezvous: [u8; RENDEZVOUS_BYTES],
    /// Base URL of the relay carrying the mailbox.
    pub relay: String,
    /// The host's ed25519 verifying key.
    ///
    /// Public, and not trusted on its own: it is mixed into the SPAKE2 exchange
    /// as the responder identity, so an invite carrying somebody else's key
    /// makes the two sides derive different keys and the handshake fails as a
    /// wrong code. That turns a swapped invite into a clean fail-closed rather
    /// than a joiner importing a key log under an attacker's key. It is also
    /// what the joiner authenticates the host's key log with afterwards.
    pub host_key: [u8; 32],
}

impl Invite {
    /// Mint a fresh invitation for a host.
    pub fn generate(relay: &str, host_key: [u8; 32]) -> Self {
        use rand::RngCore;
        let mut rendezvous = [0u8; RENDEZVOUS_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut rendezvous);
        Invite {
            rendezvous,
            relay: relay.trim_end_matches('/').to_string(),
            host_key,
        }
    }

    /// The rendezvous id as the relay sees it: 43 characters of base64url, the
    /// same shape and charset as every other id the relay routes on.
    pub fn rendezvous_id(&self) -> String {
        B64URL.encode(self.rendezvous)
    }

    /// Base64-of-JSON, for a QR or a copy-paste. Carries no secret.
    pub fn encode(&self) -> String {
        B64URL.encode(serde_json::to_vec(self).expect("Invite serializes"))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bytes = B64URL.decode(s.trim()).context("decode invite base64")?;
        serde_json::from_slice(&bytes).context("decode invite json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invite_round_trips() {
        let invite = Invite::generate("https://relay.example/", [9u8; 32]);
        let decoded = Invite::decode(&invite.encode()).expect("decode");
        assert_eq!(decoded, invite);
        // The trailing slash is trimmed at mint, so a client can concatenate
        // paths without producing a double slash the relay would 404 on.
        assert_eq!(decoded.relay, "https://relay.example");
    }

    #[test]
    fn decoding_garbage_fails_rather_than_producing_a_default() {
        assert!(Invite::decode("not-an-invite!!!").is_err());
    }

    #[test]
    fn the_rendezvous_id_is_a_valid_relay_id() {
        // The relay validates ids against `^[A-Za-z0-9_-]+$` with a length cap
        // before they reach the filesystem. An id that fails that check is a
        // 400 on every request, which presents as pairing simply never working.
        let id = Invite::generate("https://relay.example", [0u8; 32]).rendezvous_id();
        assert_eq!(id.len(), 43, "32 bytes of base64url is 43 characters");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "rendezvous id {id} is outside the charset the relay accepts"
        );
    }

    #[test]
    fn two_invites_do_not_share_a_rendezvous() {
        // A fixed or predictable rendezvous would let anyone find live sessions,
        // which is the entire failure this design exists to avoid.
        let a = Invite::generate("https://relay.example", [0u8; 32]);
        let b = Invite::generate("https://relay.example", [0u8; 32]);
        assert_ne!(a.rendezvous, b.rendezvous);
    }

    /// The invite is the thing an app puts in a QR, so its size is a real
    /// constraint. It should be comfortably smaller than the bearer token it
    /// replaces, since it carries no address list.
    #[test]
    fn an_invite_is_small_enough_to_scan() {
        let invite = Invite::generate("https://relay.roam.example/some/path", [7u8; 32]);
        let len = invite.encode().len();
        assert!(len <= 400, "an invite is {len} bytes, larger than expected");
    }
}
