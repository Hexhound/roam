//! roam-crdt — the Loro CRDT wrapper. The only crate that depends on `loro`.

mod doc;
mod error;
mod history_types;

pub use doc::{Document, Frontier, Version};
pub use error::CrdtError;
pub use history_types::{ChangeInfo, TextDiff, TextSpan};
