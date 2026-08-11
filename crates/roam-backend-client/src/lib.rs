//! Zero-knowledge encrypted backend sync for roam.
//!
//! Owns the encrypt/decrypt boundary, opaque id derivation, and a stateless
//! RBSR-discovery sync loop against an HTTP store that never sees plaintext.
pub mod crypto;
pub mod entries;
pub mod http;
pub mod snapshot_msg;
pub mod sync;
pub mod transport;
