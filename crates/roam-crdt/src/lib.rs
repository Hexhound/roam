//! roam-crdt — the Loro CRDT wrapper. The only crate that depends on `loro`.

mod doc;
mod error;

pub use doc::{Document, Version};
pub use error::CrdtError;
