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
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard encode of Frame is infallible for our types")
    }

    pub fn decode(bytes: &[u8]) -> Result<Frame, postcard::Error> {
        postcard::from_bytes(bytes)
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
        ];
        for f in frames {
            let bytes = f.encode();
            assert_eq!(Frame::decode(&bytes).unwrap(), f);
        }
    }
}
