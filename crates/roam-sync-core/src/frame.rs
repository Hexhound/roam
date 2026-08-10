use serde::{Deserialize, Serialize};

/// Sync wire messages. Encoded with postcard; the transport is responsible for
/// any length framing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    /// First frame on every connection; identifies the vault.
    Hello { vault: [u8; 32] },
    /// The sender's merged-document version vector (`roam_crdt::Version` bytes).
    Have { doc_version: Vec<u8> },
    /// Signed oplog lines authored by `author` (whole log or an appended suffix).
    Ops { author: u64, jsonl: Vec<u8> },
    /// Per roster author, how many entries the sender holds.
    RosterHave { authors: Vec<(u64, u64)> },
    /// Signed roster lines authored by `author`.
    RosterOps { author: u64, jsonl: Vec<u8> },
    /// Keepalive.
    Ping,
    // ---- Blob transfer (WS-D4). APPENDED at the END of the enum so existing
    // postcard variant indices (Hello=0 … Ping=5) are unchanged on the wire; a
    // peer built before D4 keeps decoding all older frames byte-for-byte. ----
    /// Pull request: "please send me the bytes for this content hash." Driven
    /// off the synced file-set map — a peer that learned a `Blob` entry-ref but
    /// lacks the bytes asks a peer that has them.
    BlobWant { hash: String },
    /// The bytes for `hash`, served in response to a [`Frame::BlobWant`].
    /// Whole-blob, single frame; the receiver re-hashes `bytes` and rejects any
    /// mismatch (a peer must not be able to poison a hash with wrong bytes).
    BlobData { hash: String, bytes: Vec<u8> },
    /// Per key-log author, how many entries the sender holds (mirrors RosterHave).
    KeylogHave { authors: Vec<(u64, u64)> },
    /// Signed key-log lines authored by `author` (mirrors RosterOps).
    KeylogOps { author: u64, jsonl: Vec<u8> },
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard encode of Frame is infallible for our types")
    }

    pub fn decode(bytes: &[u8]) -> Result<Frame, postcard::Error> {
        postcard::from_bytes(bytes)
    }

    /// A short static label for diagnostics/logging (no payload).
    pub fn kind(&self) -> &'static str {
        match self {
            Frame::Hello { .. } => "Hello",
            Frame::Have { .. } => "Have",
            Frame::Ops { .. } => "Ops",
            Frame::RosterHave { .. } => "RosterHave",
            Frame::RosterOps { .. } => "RosterOps",
            Frame::Ping => "Ping",
            Frame::BlobWant { .. } => "BlobWant",
            Frame::BlobData { .. } => "BlobData",
            Frame::KeylogHave { .. } => "KeylogHave",
            Frame::KeylogOps { .. } => "KeylogOps",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_through_postcard() {
        let frames = vec![
            Frame::Hello { vault: [7u8; 32] },
            Frame::Have { doc_version: vec![1, 2, 3] },
            Frame::Ops { author: 42, jsonl: b"{\"peer\":42}\n".to_vec() },
            Frame::RosterHave { authors: vec![(1, 3), (2, 0)] },
            Frame::RosterOps { author: 1, jsonl: vec![9, 9] },
            Frame::Ping,
            Frame::BlobWant { hash: "ab".repeat(32) },
            Frame::BlobData { hash: "cd".repeat(32), bytes: vec![0, 1, 2, 255] },
        ];
        for f in frames {
            let bytes = f.encode();
            assert_eq!(Frame::decode(&bytes).unwrap(), f);
        }
    }

    #[test]
    fn keylog_frames_roundtrip_through_postcard() {
        let have = Frame::KeylogHave { authors: vec![(7, 3), (9, 1)] };
        assert_eq!(Frame::decode(&have.encode()).unwrap(), have);
        let ops = Frame::KeylogOps { author: 7, jsonl: vec![1, 2, 3] };
        assert_eq!(Frame::decode(&ops.encode()).unwrap(), ops);
        assert_eq!(have.kind(), "KeylogHave");
        assert_eq!(ops.kind(), "KeylogOps");
    }
}
