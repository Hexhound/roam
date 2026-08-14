//! Ephemeral LAN sharing — send files, folders, text or a contact to a nearby
//! device, once.
//!
//! Sharing is not syncing. There is no vault, no roster, no CRDT and no epoch
//! key here, and this crate deliberately depends on none of them: a share is a
//! one-shot transfer between two devices that may never meet again.
//!
//! # What is here, and what is not
//!
//! * [`payload`] — the typed payload model and wire frames.
//! * [`name`] — filenames that are safe to write after a *stranger* chose them.
//!   This is the part that carries real risk: a receiver creates files with
//!   attacker-supplied names, so validation is enforced by newtype construction
//!   (including on `Deserialize`, or the wire would bypass it).
//!
//! **Not here yet: authentication.** These frames define *what* is transferred,
//! not who is allowed to. The auth handshake is a separate, still-open decision
//! — see the F2 security section of `docs/wasm_localsend_handoff.md`. In short:
//! reusing the existing full-entropy token model (QR / copy-paste) needs no new
//! crypto, whereas a short human-typed code requires a PAKE and must not be a
//! bare `sign(code)`. Nothing in this crate presumes either, and nothing in it
//! should be exposed on a network until that lands.

pub mod name;
pub mod payload;

pub use name::{NameError, RelPath, SafeName};
pub use payload::{Contact, FileMeta, Payload, ShareFrame, ShareOffer, StreamRef};
