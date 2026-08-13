//! Transport-agnostic snapshot verify + adopt. One copy of the receiver-side
//! Admin gate, called by BOTH the backend HTTP loop and the P2P Engine.
//!
//! Adoption injects state via an additive `doc.import` that bypasses the per-op
//! Reader-content-drop rule (CR4), so a non-Admin author must NEVER be adopted,
//! even with a valid self-signature. Producer-side gating is voluntary; THIS
//! receiver-side gate is what actually enforces Admin-only authorship.
use crate::roster::{PeerStatus, Role};
use crate::snapshot_msg::{unframe, SnapshotManifest};
use crate::{Keychain, StorageError, Store, VerifyingKey};
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub enum AdoptOutcome {
    Adopted { id: String, subsumed: Vec<String> },
    Undecryptable,
    Rejected(&'static str),
}

/// Verifying keys trusted to author a snapshot: ADMIN roster peers that are
/// Active, plus self iff this device is an Admin.
pub fn admin_author_keys(store: &Store) -> HashMap<u64, VerifyingKey> {
    let mut m = HashMap::new();
    for r in store.roster() {
        if r.role == Role::Admin && r.status == PeerStatus::Active {
            if let Ok(k) = VerifyingKey::from_bytes(&r.verifying_key) {
                m.insert(r.peer_id, k);
            }
        }
    }
    if store.self_role() == Some(Role::Admin) {
        if let Ok(k) = VerifyingKey::from_bytes(&store.identity_verifying_bytes()) {
            m.insert(store.peer_id(), k);
        }
    }
    m
}

/// Open an epoch-classified sealed payload through the keychain read rule.
/// Returns `Ok(None)` when the epoch key is not yet available (self-heals).
pub fn open_classified(kc: &Keychain, payload: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
    let plan = kc.classify(payload);
    let Some(key) = plan.key else {
        return Ok(None);
    };
    match crate::epoch_crypto::open_epoch(key.expose(), &payload[plan.body_offset..]) {
        Ok(pt) => Ok(Some(pt)),
        Err(_) => Ok(None),
    }
}

/// Verify one framed snapshot object and, if trusted+decryptable, adopt it
/// additively and persist it for re-serving. Every guard returns BEFORE any
/// store mutation, so a failed check never touches the doc.
pub fn verify_and_adopt_snapshot(
    store: &mut Store,
    kc: &Keychain,
    author_keys: &HashMap<u64, VerifyingKey>,
    id: &str,
    framed: &[u8],
) -> Result<AdoptOutcome, StorageError> {
    let Some((manifest_json, sealed)) = unframe(framed) else {
        return Ok(AdoptOutcome::Rejected("malformed frame"));
    };
    let manifest: SnapshotManifest = match serde_json::from_slice(manifest_json) {
        Ok(m) => m,
        Err(_) => return Ok(AdoptOutcome::Rejected("manifest parse")),
    };
    let Some(vk) = author_keys.get(&manifest.author) else {
        return Ok(AdoptOutcome::Rejected("author not admin"));
    };
    if !manifest.verify(vk) {
        return Ok(AdoptOutcome::Rejected("bad signature"));
    }
    if <[u8; 32]>::from(blake3::hash(sealed)) != manifest.snapshot_ct_hash {
        return Ok(AdoptOutcome::Rejected("ct hash mismatch"));
    }
    let Some(plaintext) = open_classified(kc, sealed)? else {
        return Ok(AdoptOutcome::Undecryptable);
    };
    store.adopt_snapshot(&plaintext)?;
    store.record_held_snapshot(id, &manifest.subsumed_entry_ids)?;
    store.persist_snapshot_object(id, framed)?;
    Ok(AdoptOutcome::Adopted {
        id: id.to_string(),
        subsumed: manifest.subsumed_entry_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_frame() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path(), crate::Identity::generate()).unwrap();
        let kc = store.keychain(&[0u8; 32], &[0u8; 32]).unwrap();
        let keys = admin_author_keys(&store);
        let out = verify_and_adopt_snapshot(&mut store, &kc, &keys, "x", b"\x00").unwrap();
        assert_eq!(out, AdoptOutcome::Rejected("malformed frame"));
    }
}
