//! Zero-knowledge encrypted backend sync for roam.
//!
//! Owns the encrypt/decrypt boundary, opaque id derivation, and a stateless
//! manifest set-diff sync loop against an HTTP store that never sees plaintext.
pub mod crypto;
pub mod entries;
pub mod http;
pub mod sync;
pub mod transport;
