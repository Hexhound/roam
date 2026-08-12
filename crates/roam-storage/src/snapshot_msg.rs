//! The signed sidecar manifest that travels with every backend snapshot.
//!
//! The backend is zero-knowledge: it cannot read a snapshot to learn which
//! op-log entries it subsumes or which blobs it references. The uploading Admin
//! therefore ships this manifest alongside the snapshot ciphertext. It is opaque
//! id lists plus a signature — no plaintext — so it preserves zero knowledge
//! while giving the retention sweep (Elixir side) the data it needs to prune.
//!
//! The signature binds the covered frontier, the snapshot ciphertext hash, and
//! both id lists together, so a peer can verify — before adopting a snapshot and
//! before trusting a prune — that an authorized author produced exactly this
//! artifact.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use crate::{Identity, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Domain separator so a snapshot-manifest signature can never be replayed as a
/// signature over any other roam artifact.
const MANIFEST_DOMAIN: &[u8] = b"roam-snapshot-manifest-v1";

/// Signed metadata describing one backend snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// blake3 of the snapshot's covered frontier bytes.
    pub frontier_digest: [u8; 32],
    /// blake3 of the sealed snapshot ciphertext (binds the sig to these bytes).
    pub snapshot_ct_hash: [u8; 32],
    /// Backend entry-ids this snapshot replaces (the retention sweep may delete
    /// these once past the grace window).
    pub subsumed_entry_ids: Vec<String>,
    /// Backend blob-ids this snapshot's state references (keep-alive set for the
    /// blob GC).
    pub blob_ref_ids: Vec<String>,
    /// peer_id of the authoring Admin.
    pub author: u64,
    /// base64url (no-pad) of the 64-byte ed25519 signature over [`signing_bytes`].
    pub sig: String,
}

impl SnapshotManifest {
    /// Canonical bytes the signature covers. Deterministic: id lists are sorted
    /// and length-delimited so serialization order can never change the digest.
    /// The `sig` field is deliberately excluded.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(MANIFEST_DOMAIN);
        m.extend_from_slice(&self.frontier_digest);
        m.extend_from_slice(&self.snapshot_ct_hash);
        m.extend_from_slice(&self.author.to_le_bytes());
        append_id_list(&mut m, &self.subsumed_entry_ids);
        append_id_list(&mut m, &self.blob_ref_ids);
        m
    }

    /// Return a copy signed by `author`, filling `sig`. The caller is
    /// responsible for setting `author` to `author.peer_id()`.
    pub fn signed(mut self, author: &Identity) -> Self {
        self.author = author.peer_id();
        self.sig = String::new();
        let sig = author.sign_bytes(&self.signing_bytes());
        self.sig = B64URL.encode(sig);
        self
    }

    /// Verify the signature under `key` (the author's verifying key, looked up
    /// from the roster). Returns false on a malformed or non-matching signature.
    pub fn verify(&self, key: &VerifyingKey) -> bool {
        let Some(sig_bytes) = decode_sig(&self.sig) else {
            return false;
        };
        // Recompute over the same canonical bytes (sig excluded).
        let mut probe = self.clone();
        probe.sig = String::new();
        key.verify_bytes(&probe.signing_bytes(), &sig_bytes)
    }
}

/// Append a sorted, length-delimited id list so the encoding is order-independent
/// and unambiguous (a `||` join could otherwise let two lists collide).
fn append_id_list(out: &mut Vec<u8>, ids: &[String]) {
    let mut sorted: Vec<&String> = ids.iter().collect();
    sorted.sort();
    out.extend_from_slice(&(sorted.len() as u64).to_le_bytes());
    for id in sorted {
        out.extend_from_slice(&(id.len() as u64).to_le_bytes());
        out.extend_from_slice(id.as_bytes());
    }
}

fn decode_sig(s: &str) -> Option<[u8; 64]> {
    B64URL.decode(s).ok()?.try_into().ok()
}

/// Frame a snapshot object stored under one backend id: the PLAINTEXT manifest
/// JSON followed by the SEALED snapshot ciphertext, length-prefixed. One object
/// (backend ids are a restricted charset — no room for a `.manifest` sibling),
/// yet the zero-knowledge backend can read the manifest prefix (opaque id lists)
/// for its retention sweep without ever touching the key.
///
/// Layout: `u32-LE manifest_len ‖ manifest_json ‖ sealed_ct`.
pub fn frame(manifest_json: &[u8], sealed_ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + manifest_json.len() + sealed_ct.len());
    out.extend_from_slice(&(manifest_json.len() as u32).to_le_bytes());
    out.extend_from_slice(manifest_json);
    out.extend_from_slice(sealed_ct);
    out
}

/// Split a framed snapshot object back into `(manifest_json, sealed_ct)`.
/// Returns `None` on a truncated/malformed frame.
pub fn unframe(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    if bytes.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(bytes[..4].try_into().ok()?) as usize;
    let rest = &bytes[4..];
    if rest.len() < len {
        return None;
    }
    Some((&rest[..len], &rest[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> SnapshotManifest {
        SnapshotManifest {
            frontier_digest: [7u8; 32],
            snapshot_ct_hash: [8u8; 32],
            subsumed_entry_ids: vec!["a".into(), "b".into()],
            blob_ref_ids: vec!["c".into()],
            author: 0,
            sig: String::new(),
        }
    }

    #[test]
    fn manifest_signs_and_verifies_and_rejects_tamper() {
        let author = Identity::generate();
        let signed = manifest().signed(&author);
        assert_eq!(signed.author, author.peer_id());
        assert!(signed.verify(&author.verifying_key()));

        // Tamper the subsumed set -> signature no longer matches.
        let mut bad = signed.clone();
        bad.subsumed_entry_ids.push("x".into());
        assert!(!bad.verify(&author.verifying_key()));

        // Tamper the ciphertext hash -> rejected.
        let mut bad2 = signed.clone();
        bad2.snapshot_ct_hash = [9u8; 32];
        assert!(!bad2.verify(&author.verifying_key()));

        // A different key must not verify.
        let other = Identity::generate();
        assert!(!signed.verify(&other.verifying_key()));
    }

    #[test]
    fn id_list_order_does_not_change_the_signature() {
        let author = Identity::generate();
        let mut a = manifest();
        a.subsumed_entry_ids = vec!["a".into(), "b".into()];
        let mut b = manifest();
        b.subsumed_entry_ids = vec!["b".into(), "a".into()];
        // Same content in a different order verifies against the same signature.
        let signed_a = a.signed(&author);
        let mut b_with_a_sig = b;
        b_with_a_sig.author = signed_a.author;
        b_with_a_sig.sig = signed_a.sig.clone();
        assert!(b_with_a_sig.verify(&author.verifying_key()));
    }

    #[test]
    fn frame_roundtrips_and_rejects_truncation() {
        let m = b"{\"manifest\":true}";
        let ct = b"sealed-ciphertext-bytes";
        let framed = frame(m, ct);
        let (got_m, got_ct) = unframe(&framed).unwrap();
        assert_eq!(got_m, m);
        assert_eq!(got_ct, ct);
        // A frame claiming more manifest bytes than present is rejected.
        assert!(unframe(&framed[..6]).is_none());
        assert!(unframe(&[1, 0]).is_none());
    }

    #[test]
    fn malformed_signature_is_rejected_not_panicking() {
        let author = Identity::generate();
        let mut m = manifest().signed(&author);
        m.sig = "!!!not-base64!!!".into();
        assert!(!m.verify(&author.verifying_key()));
        m.sig = B64URL.encode([0u8; 10]); // wrong length
        assert!(!m.verify(&author.verifying_key()));
    }
}
