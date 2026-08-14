//! The typed share payload and its wire frames.
//!
//! LocalSend-style sharing is a *transfer*, not sync: no vault, no roster, no
//! CRDT, no epoch keys. That is why this crate depends on none of them, and why
//! these frames are a separate protocol from `roam_sync_core::Frame` rather than
//! new variants on it.
//!
//! Adding a kind later is one [`Payload`] variant.

use crate::name::{RelPath, SafeName};
use serde::{Deserialize, Serialize};

/// One file's metadata within an offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    /// Where the file goes, relative to the destination directory. Validated on
    /// decode, so it can never escape it.
    pub path: RelPath,
    /// Length in bytes, as claimed by the sender.
    ///
    /// ADVISORY ONLY. The receiver must enforce it as a *ceiling* while bytes
    /// arrive and must not, for example, pre-allocate this much: a sender can
    /// claim 100 GiB. See [`ShareOffer::total_len`].
    pub len: u64,
}

/// What is on offer. One variant per shareable kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    /// A single file.
    File(FileMeta),
    /// A directory tree. `name` is the folder itself; `files` are its contents,
    /// each with a path relative to that folder.
    Folder {
        name: SafeName,
        files: Vec<FileMeta>,
    },
    /// A note typed by the sender.
    Text(String),
    /// The sender's clipboard.
    Clipboard(String),
    /// A contact card.
    Contact(Contact),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub display_name: String,
    pub fields: Vec<(String, String)>,
}

/// A byte stream inside an offer, addressed by a single flat index.
///
/// Folders would otherwise need two-level addressing (`item`, then `file`) in
/// every chunk. Flattening once here keeps [`ShareFrame::Chunk`] a single `u32`
/// and puts the index arithmetic in one tested place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRef {
    /// Index into [`ShareOffer::items`].
    pub item: usize,
    /// Destination path relative to the download directory, folder name
    /// included.
    pub path: RelPath,
    pub len: u64,
}

/// The sender's opening message: everything it wants to transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareOffer {
    /// The sending device's self-declared name. UNTRUSTED — shown to a human,
    /// never used to make a decision.
    pub from: String,
    pub items: Vec<Payload>,
}

impl ShareOffer {
    /// Every byte stream in the offer, in a fixed order.
    ///
    /// Both sides derive this from the same offer, so the `stream` index in a
    /// [`ShareFrame::Chunk`] means the same thing to each without any extra
    /// negotiation. Text, clipboard and contact payloads carry their content
    /// inline and contribute no streams.
    pub fn streams(&self) -> Vec<StreamRef> {
        let mut out = Vec::new();
        for (item, payload) in self.items.iter().enumerate() {
            match payload {
                Payload::File(meta) => out.push(StreamRef {
                    item,
                    path: meta.path.clone(),
                    len: meta.len,
                }),
                Payload::Folder { name, files } => {
                    for meta in files {
                        // Prefix with the folder's own name so a folder lands as
                        // a folder rather than spilling its contents into the
                        // download directory.
                        let path = RelPath::new(&format!("{name}/{}", meta.path))
                            .expect("both parts are already validated components");
                        out.push(StreamRef {
                            item,
                            path,
                            len: meta.len,
                        });
                    }
                }
                Payload::Text(_) | Payload::Clipboard(_) | Payload::Contact(_) => {}
            }
        }
        out
    }

    /// Total bytes the sender claims it will send.
    ///
    /// Saturating: a hostile offer can claim `u64::MAX` per file, and this must
    /// report an absurd total rather than wrapping to a small, plausible one.
    /// Use it to ask the user and to bound the transfer — never to allocate.
    pub fn total_len(&self) -> u64 {
        self.streams()
            .iter()
            .fold(0u64, |acc, s| acc.saturating_add(s.len))
    }
}

/// Wire messages for one ephemeral share session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareFrame {
    /// Sender → receiver: here is what I have.
    Offer(ShareOffer),
    /// Receiver → sender: send these stream indices (into
    /// [`ShareOffer::streams`]). An empty list accepts only the inline payloads.
    Accept { streams: Vec<u32> },
    /// Receiver → sender: no.
    Decline,
    /// One chunk of one stream. `offset` is the byte offset within that stream.
    ///
    /// Chunks may arrive in any order, which is why the offset is explicit
    /// rather than implied by arrival order.
    Chunk {
        stream: u32,
        offset: u64,
        bytes: Vec<u8>,
    },
    /// Sender → receiver: every accepted stream has been sent.
    Done,
}

impl ShareFrame {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard encode of ShareFrame is infallible")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }

    /// Short label for diagnostics; never includes payload content.
    pub fn kind(&self) -> &'static str {
        match self {
            ShareFrame::Offer(_) => "Offer",
            ShareFrame::Accept { .. } => "Accept",
            ShareFrame::Decline => "Decline",
            ShareFrame::Chunk { .. } => "Chunk",
            ShareFrame::Done => "Done",
        }
    }
}
