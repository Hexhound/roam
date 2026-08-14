//! LocalSend-style sharing over iroh, authenticated by a short typed code.
//!
//! This is the wiring that F2(b) was missing: `roam-share` says *what* is
//! transferred, `roam-pake` says *who may*, and this crate puts them on a QUIC
//! stream.
//!
//! # Roles
//!
//! The **sender** holds the files, displays a six-digit code, and waits. The
//! **receiver** finds it on the LAN (see `roam_transport_iroh::discovery`),
//! types the code, and dials.
//!
//! That maps onto the PAKE's roles exactly: the receiver dials, so it is the
//! PAKE *initiator*; the sender shows the code and owns the attempt budget, so
//! it is the *responder*. The side that displays the secret is the side that
//! must be able to say "you have guessed too many times".
//!
//! # Wire flow
//!
//! ```text
//!   Receiver                                Sender
//!   --------                                ------
//!   dial + open bi ──── PakeMsg1 ─────────▶  spends one attempt
//!                  ◀─── PakeMsg2 ─────────
//!   ─────────────────── Confirm ──────────▶  verify, else drop the connection
//!                  ◀─── Confirm ──────────
//!   ============ everything below is sealed under the PAKE key =============
//!                  ◀─── Offer ────────────   what is on offer
//!   ─── Accept{streams} | Decline ────────▶   the human's decision
//!                  ◀─── Chunk … Done ─────
//! ```
//!
//! Nothing is offered before the code is proved: a wrong code learns not even
//! the filenames.
//!
//! # No vault
//!
//! This crate depends on `roam-share`, `roam-pake` and `iroh` — not on
//! `roam-storage` or `roam-sync-core`. A share is a one-shot transfer between
//! devices that may never meet again, and it must not be able to touch a vault.

mod endpoint;
mod receive;
mod send;
mod wire;

pub use endpoint::bind_share_endpoint;
pub use receive::{receive_share, Received};
pub use send::{offer_paths, ShareSender, SourceMap};
pub use wire::SHARE_ALPN;

/// Bytes of file payload per sealed chunk.
///
/// Kept well under QUIC's datagram concerns and small enough that a stalled
/// transfer wastes little, while large enough that per-chunk sealing overhead
/// (16-byte tag + framing) stays negligible.
pub const CHUNK_BYTES: usize = 64 * 1024;

/// Refuse an offer whose *claimed* total exceeds this unless the caller opts in.
///
/// A sender can claim any size it likes, so this is the default guard against
/// "accept" meaning "fill my disk". It bounds the claim, and the receiver
/// separately enforces the per-file length as bytes actually arrive.
pub const DEFAULT_MAX_ACCEPT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
