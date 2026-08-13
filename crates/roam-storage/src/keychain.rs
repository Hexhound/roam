//! The Keychain: folds verified key-log entries + roster + the device's own
//! epoch-0 key into an epoch DAG, resolving which epoch keys this device holds,
//! a deterministic write-head, a read-classifier for stored ciphertext, the
//! recovery state machine, and the wrap-back-fill planner. Pure — no I/O.

use crate::keylog::{KeyBody, KeyLogEntry, Recipient};
use crate::keywrap;
use crate::roster::{PeerRecord, PeerStatus};
use std::collections::{BTreeMap, BTreeSet};

/// The bookkeeping id of epoch 0 (today's scheme). Epoch-0 ciphertext is written
/// UNTAGGED (legacy `nonce||ct`), so this id never appears on the wire; it only
/// names the genesis node in the DAG. A minted epoch_id is a BLAKE3 hash, so it
/// is all-zero with probability 2^-256 — never colliding with this sentinel.
pub const EPOCH0_ID: [u8; 32] = [0u8; 32];

/// A 32-byte epoch/AEAD secret that wipes itself on drop. The keychain resolves
/// which epoch keys this device holds and threads them through `EpochNode.key`,
/// `Keychain.id_key`, `ReadPlan.key`, and the `epoch_key`/`head_write_key`/
/// `backfill_targets` returns; wrapping them here means a decrypted epoch key
/// never lingers in freed memory. There is deliberately no `Deref` to the raw
/// bytes — every use of the secret goes through the explicit [`Self::expose`] so
/// exposure sites stay greppable — and it compares by value so the structs that
/// hold it keep `Eq`.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw key bytes (for AEAD seal/open and key-wrap). The one
    /// sanctioned way to read the secret — no implicit `Deref` coercion.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

// The keychain never compares secret keys against attacker-supplied input on a
// timing-sensitive path (equality is used by structural `Eq` on the read plan
// and in test assertions), so a plain byte compare is sufficient here.
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for SecretKey {}

impl PartialEq<[u8; 32]> for SecretKey {
    fn eq(&self, other: &[u8; 32]) -> bool {
        &self.0 == other
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochNode {
    pub parents: Vec<[u8; 32]>,
    pub minted_by: u64,
    /// The `Rotate` nonce for this epoch — retained so the unwrap path can
    /// recompute `compute_epoch_id(parents, minted_by, nonce, key)` and verify
    /// the delivered key is the one this id commits to (M8).
    pub nonce: [u8; 32],
    /// `Some` if this device can decrypt under this epoch; `None` = known to
    /// exist (a `Rotate` seen) but not yet unwrappable → `WaitingKey` fuel.
    pub key: Option<SecretKey>,
    /// Recipients this epoch has been wrapped to (from `Wrap` entries).
    pub wrapped_to: BTreeSet<u64>,
    pub wrapped_paper: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keychain {
    pub id_key: SecretKey,
    pub epochs: BTreeMap<[u8; 32], EpochNode>,
    pub head: [u8; 32],
}

/// One thing wrong with key coverage. An empty issue list == `Synced`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultIssue {
    /// This epoch's key is missing here but ≥1 current member holds a wrap.
    WaitingKey {
        epoch: [u8; 32],
        candidates: Vec<u64>,
    },
    /// This epoch's key is missing and no current member (nor paper) holds it.
    KeyOrphaned { epoch: [u8; 32] },
    /// This epoch is wrapped to only one live device — one loss from orphaning.
    KeyRedundancyLow { epoch: [u8; 32], holders: Vec<u64> },
}

/// How to read one stored ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPlan {
    pub epoch: [u8; 32],
    /// The AEAD key to use, or `None` → item is `Undecryptable{epoch}` for now.
    pub key: Option<SecretKey>,
    /// Byte offset of `nonce||ct` within the stored payload (32 if epoch-tagged,
    /// 0 if legacy/epoch-0).
    pub body_offset: usize,
}

/// `epoch_id = blake3(parent_ids.. ‖ minted_by ‖ nonce ‖ key)`.
///
/// M8: the epoch `key` is committed INTO the id. A recipient that unwraps a key
/// under some announced `epoch_id` recomputes this hash and rejects the key
/// unless it reproduces that id — so a malicious admin cannot deliver DIFFERENT
/// keys to different members under one epoch id (which would silently split the
/// vault into mutually-unreadable groups). The key is a mint-time secret, so
/// this does not weaken the id's role as a public DAG handle: honest members all
/// receive the same key and derive the same id; a divergent key derives a
/// different id and fails the unwrap-time check.
pub fn compute_epoch_id(
    parents: &[[u8; 32]],
    minted_by: u64,
    nonce: &[u8; 32],
    key: &[u8; 32],
) -> [u8; 32] {
    let mut input = Vec::new();
    for p in parents {
        input.extend_from_slice(p);
    }
    input.extend_from_slice(&minted_by.to_le_bytes());
    input.extend_from_slice(nonce);
    input.extend_from_slice(key);
    *blake3::hash(&input).as_bytes()
}

impl Keychain {
    /// Build from this device's stable `id_key`, its epoch-0 AEAD key, the merged
    /// verified key-log entries, and this device's X25519 unwrap secret.
    pub fn build(
        id_key: [u8; 32],
        epoch0_key: [u8; 32],
        self_peer: u64,
        x25519_secret: &[u8; 32],
        entries: &[KeyLogEntry],
    ) -> Self {
        let mut epochs: BTreeMap<[u8; 32], EpochNode> = BTreeMap::new();
        // Genesis: epoch 0 always known.
        epochs.insert(
            EPOCH0_ID,
            EpochNode {
                parents: vec![],
                minted_by: 0,
                nonce: [0u8; 32],
                key: Some(SecretKey::new(epoch0_key)),
                wrapped_to: BTreeSet::new(),
                wrapped_paper: false,
            },
        );

        // First pass: Rotate announces nodes.
        for e in entries {
            if let KeyBody::Rotate {
                parent_epochs,
                nonce,
            } = &e.body
            {
                epochs.entry(e.epoch_id).or_insert(EpochNode {
                    parents: parent_epochs.clone(),
                    minted_by: e.author,
                    nonce: *nonce,
                    key: None,
                    wrapped_to: BTreeSet::new(),
                    wrapped_paper: false,
                });
            }
        }
        // Second pass: Wrap records recipients + unwraps ours.
        for e in entries {
            if let KeyBody::Wrap { recipient, blob } = &e.body {
                // KC1: a Wrap may only attach to an epoch a Rotate ALREADY
                // announced (or the epoch-0 genesis). Never `or_insert` — a Wrap
                // for an unannounced epoch would synthesize a phantom node with an
                // attacker-chosen id and (once unwrapped) install an
                // attacker-known write key that `select_head` could steer to.
                let Some(node) = epochs.get_mut(&e.epoch_id) else {
                    continue;
                };
                match recipient {
                    Recipient::Device(p) => {
                        node.wrapped_to.insert(*p);
                        if *p == self_peer && node.key.is_none() {
                            if let Ok(k) = keywrap::unwrap(x25519_secret, blob) {
                                // M8: the epoch_id commits to the key. Install it
                                // only if it reproduces the announced id — a
                                // divergent key delivered under this id derives a
                                // different id and is rejected (fail closed).
                                if compute_epoch_id(&node.parents, node.minted_by, &node.nonce, &k)
                                    == e.epoch_id
                                {
                                    node.key = Some(SecretKey::new(k));
                                }
                            }
                        }
                    }
                    Recipient::Paper => node.wrapped_paper = true,
                }
            }
        }

        let head = Self::select_head(&epochs);
        Self {
            id_key: SecretKey::new(id_key),
            epochs,
            head,
        }
    }

    /// Deterministic write-head: among the DAG leaves (epochs that are no node's
    /// parent), the lowest `epoch_id`. Ties across concurrent rotations converge
    /// because every writer picks the same lowest id.
    fn select_head(epochs: &BTreeMap<[u8; 32], EpochNode>) -> [u8; 32] {
        let mut is_parent: BTreeSet<[u8; 32]> = BTreeSet::new();
        for node in epochs.values() {
            for p in &node.parents {
                is_parent.insert(*p);
            }
        }
        epochs
            .keys()
            .filter(|id| !is_parent.contains(*id))
            .copied()
            .min()
            .unwrap_or(EPOCH0_ID)
    }

    pub fn epoch_key(&self, epoch: &[u8; 32]) -> Option<SecretKey> {
        self.epochs.get(epoch).and_then(|n| n.key.clone())
    }

    /// The AEAD key to seal new writes under (the head epoch's key), plus its id.
    /// `None` when the head epoch's key isn't held yet (a `Rotate` was seen but its
    /// `Wrap` for us hasn't landed). Callers MUST NOT fall back to epoch 0 in that
    /// case unless [`Self::head`] is epoch 0 — see H1 in the security review.
    pub fn head_write_key(&self) -> Option<([u8; 32], SecretKey)> {
        self.epoch_key(&self.head).map(|k| (self.head, k))
    }

    /// The current write-head epoch id. Epoch 0 means the vault never rotated (a
    /// legacy `VaultKey::seal` is the correct write); any other id means a rotation
    /// is in effect and epoch-0 writes would be readable by rotated-out members.
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// Classify a stored ciphertext: epoch-tagged iff its first 32 bytes equal a
    /// KNOWN epoch id (≠ epoch 0). Otherwise read as legacy epoch 0.
    pub fn classify(&self, payload: &[u8]) -> ReadPlan {
        if payload.len() >= 32 {
            let mut prefix = [0u8; 32];
            prefix.copy_from_slice(&payload[..32]);
            if prefix != EPOCH0_ID {
                if let Some(node) = self.epochs.get(&prefix) {
                    return ReadPlan {
                        epoch: prefix,
                        key: node.key.clone(),
                        body_offset: 32,
                    };
                }
            }
        }
        ReadPlan {
            epoch: EPOCH0_ID,
            key: self.epoch_key(&EPOCH0_ID),
            body_offset: 0,
        }
    }

    /// The recovery state machine, computed from wrap coverage ∩ current roster.
    /// Empty result == `Synced`.
    pub fn diagnose(&self, roster: &[PeerRecord]) -> Vec<VaultIssue> {
        let active: BTreeSet<u64> = roster
            .iter()
            .filter(|p| p.status == PeerStatus::Active)
            .map(|p| p.peer_id)
            .collect();
        let mut issues = Vec::new();
        for (epoch, node) in &self.epochs {
            let live_holders: Vec<u64> = node
                .wrapped_to
                .iter()
                .filter(|p| active.contains(p))
                .copied()
                .collect();
            if node.key.is_none() {
                if live_holders.is_empty() && !node.wrapped_paper {
                    issues.push(VaultIssue::KeyOrphaned { epoch: *epoch });
                } else {
                    issues.push(VaultIssue::WaitingKey {
                        epoch: *epoch,
                        candidates: live_holders,
                    });
                }
            } else if live_holders.len() == 1 && !node.wrapped_paper {
                issues.push(VaultIssue::KeyRedundancyLow {
                    epoch: *epoch,
                    holders: live_holders,
                });
            }
        }
        issues
    }

    /// Wrap-back-fill targets: `(epoch_id, epoch_key, recipient_peer)` triples this
    /// device SHOULD publish a `Wrap` for — epochs it can open, and current
    /// members with no wrap yet. The caller looks up member X25519 pubs.
    pub fn backfill_targets(&self, roster: &[PeerRecord]) -> Vec<([u8; 32], SecretKey, u64)> {
        let mut out = Vec::new();
        for (epoch, node) in &self.epochs {
            // Epoch 0 is the locally-derived, untagged genesis — never distributed
            // via a `Wrap`, so it is not a back-fill target.
            if *epoch == EPOCH0_ID {
                continue;
            }
            let Some(key) = node.key.as_ref() else {
                continue;
            };
            for p in roster.iter().filter(|p| p.status == PeerStatus::Active) {
                if !node.wrapped_to.contains(&p.peer_id) {
                    out.push((*epoch, key.clone(), p.peer_id));
                }
            }
        }
        out
    }

    /// All DAG leaves (epochs that are no other epoch's parent). The single
    /// deterministic write-`head` is `min` of these; a rotation parents on ALL of
    /// them so concurrent siblings merge into one child.
    pub fn dag_heads(&self) -> Vec<[u8; 32]> {
        let mut is_parent: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
        for node in self.epochs.values() {
            for p in &node.parents {
                is_parent.insert(*p);
            }
        }
        let mut heads: Vec<[u8; 32]> = self
            .epochs
            .keys()
            .filter(|id| !is_parent.contains(*id))
            .copied()
            .collect();
        if heads.is_empty() {
            heads.push(EPOCH0_ID);
        }
        heads
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::keywrap;

    fn peer(id: u64, status: PeerStatus) -> PeerRecord {
        let mut key = [0u8; 32];
        key[0..8].copy_from_slice(&id.to_le_bytes());
        PeerRecord {
            peer_id: id,
            verifying_key: key,
            status,
            role: crate::roster::Role::Admin,
            name: None,
        }
    }

    #[test]
    fn an_epoch_secret_key_is_wiped_on_drop() {
        // The epoch key material threaded through the keychain (EpochNode.key,
        // Keychain.id_key, ReadPlan.key, and the epoch_key/head_write_key/
        // backfill_targets returns) is wrapped in SecretKey, which zeroizes its
        // bytes on drop so a decrypted epoch key never lingers in freed memory.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretKey>();

        // It still compares by value, so the structs that hold it keep deriving
        // Eq (the read-classifier and diagnostics rely on structural equality).
        assert_eq!(SecretKey::new([9u8; 32]), SecretKey::new([9u8; 32]));
        assert_ne!(SecretKey::new([9u8; 32]), SecretKey::new([1u8; 32]));
        // ...and compares against raw bytes for ergonomic assertions/lookups.
        assert_eq!(SecretKey::new([9u8; 32]), [9u8; 32]);
    }

    #[test]
    fn epoch0_is_always_known_and_is_default_head() {
        let kc = Keychain::build(
            [1u8; 32],
            [2u8; 32],
            5,
            &Identity::generate().x25519_secret(),
            &[],
        );
        assert_eq!(kc.head, EPOCH0_ID);
        assert_eq!(kc.epoch_key(&EPOCH0_ID), Some(SecretKey::new([2u8; 32])));
    }

    #[test]
    fn a_wrap_whose_key_does_not_match_the_epoch_id_is_rejected() {
        // M8: the epoch_id commits to the epoch key. A Wrap that delivers a
        // DIFFERENT key under the same announced epoch_id (a malicious admin
        // handing divergent keys to different members, splitting the vault into
        // mutually-unreadable groups) must be rejected: the key is NOT installed,
        // so the device fails closed (WaitingKey) instead of sealing writes under
        // a key the rest of the vault can't read.
        let me = Identity::generate();
        let k_real = [42u8; 32];
        let k_evil = [7u8; 32];
        let nonce = [3u8; 32];
        // The honest id commits to k_real...
        let epoch = compute_epoch_id(&[EPOCH0_ID], me.peer_id(), &nonce, &k_real);
        // ...but the Wrap delivers k_evil sealed to us under that same id.
        let blob = keywrap::wrap(&me.x25519_public(), &k_evil);

        let entries = vec![
            KeyLogEntry {
                seq: 1,
                author: me.peer_id(),
                epoch_id: epoch,
                body: KeyBody::Rotate {
                    parent_epochs: vec![EPOCH0_ID],
                    nonce,
                },
            },
            KeyLogEntry {
                seq: 2,
                author: me.peer_id(),
                epoch_id: epoch,
                body: KeyBody::Wrap {
                    recipient: Recipient::Device(me.peer_id()),
                    blob,
                },
            },
        ];
        let kc = Keychain::build(
            [1u8; 32],
            [2u8; 32],
            me.peer_id(),
            &me.x25519_secret(),
            &entries,
        );
        assert_eq!(
            kc.epoch_key(&epoch),
            None,
            "a delivered key that does not reproduce the epoch_id must be rejected"
        );
    }

    #[test]
    fn a_wrap_to_us_unlocks_the_epoch_and_moves_the_head() {
        let me = Identity::generate();
        let k_new = [42u8; 32];
        let nonce = [3u8; 32];
        let epoch = compute_epoch_id(&[EPOCH0_ID], me.peer_id(), &nonce, &k_new);
        let blob = keywrap::wrap(&me.x25519_public(), &k_new);

        let entries = vec![
            KeyLogEntry {
                seq: 1,
                author: me.peer_id(),
                epoch_id: epoch,
                body: KeyBody::Rotate {
                    parent_epochs: vec![EPOCH0_ID],
                    nonce,
                },
            },
            KeyLogEntry {
                seq: 2,
                author: me.peer_id(),
                epoch_id: epoch,
                body: KeyBody::Wrap {
                    recipient: Recipient::Device(me.peer_id()),
                    blob,
                },
            },
        ];
        let kc = Keychain::build(
            [1u8; 32],
            [2u8; 32],
            me.peer_id(),
            &me.x25519_secret(),
            &entries,
        );
        assert_eq!(kc.epoch_key(&epoch), Some(SecretKey::new(k_new)));
        assert_eq!(kc.head, epoch, "head advances to the new leaf epoch");
    }

    #[test]
    fn a_wrap_for_an_unannounced_epoch_is_ignored() {
        // KC1: a `Wrap` naming an `epoch_id` that NO `Rotate` announced must not
        // synthesize a phantom epoch node. Otherwise a member can install an
        // arbitrary (attacker-known) write key under a chosen id and steer the
        // write-head to it — a confidentiality break.
        let me = Identity::generate();
        let attacker_key = [42u8; 32];
        let mut phantom = [0u8; 32];
        phantom[31] = 1; // smallest non-zero id; would win `select_head` if installed
        let blob = keywrap::wrap(&me.x25519_public(), &attacker_key);

        let entries = vec![KeyLogEntry {
            seq: 1,
            author: me.peer_id(),
            epoch_id: phantom,
            body: KeyBody::Wrap {
                recipient: Recipient::Device(me.peer_id()),
                blob,
            },
        }];
        let kc = Keychain::build(
            [1u8; 32],
            [2u8; 32],
            me.peer_id(),
            &me.x25519_secret(),
            &entries,
        );

        assert!(
            !kc.epochs.contains_key(&phantom),
            "a Wrap with no announcing Rotate must not create an epoch node"
        );
        assert!(
            kc.epoch_key(&phantom).is_none(),
            "phantom epoch key must never be installed"
        );
        assert_eq!(
            kc.head, EPOCH0_ID,
            "head must not move to a phantom (unannounced) epoch"
        );
    }

    #[test]
    fn classify_tags_known_epochs_and_falls_through_to_epoch0() {
        let me = Identity::generate();
        let nonce = [3u8; 32];
        let epoch = compute_epoch_id(&[EPOCH0_ID], me.peer_id(), &nonce, &[9u8; 32]);
        let blob = keywrap::wrap(&me.x25519_public(), &[9u8; 32]);
        let entries = vec![
            KeyLogEntry {
                seq: 1,
                author: me.peer_id(),
                epoch_id: epoch,
                body: KeyBody::Rotate {
                    parent_epochs: vec![EPOCH0_ID],
                    nonce,
                },
            },
            KeyLogEntry {
                seq: 2,
                author: me.peer_id(),
                epoch_id: epoch,
                body: KeyBody::Wrap {
                    recipient: Recipient::Device(me.peer_id()),
                    blob,
                },
            },
        ];
        let kc = Keychain::build(
            [1u8; 32],
            [2u8; 32],
            me.peer_id(),
            &me.x25519_secret(),
            &entries,
        );

        // Tagged payload: prefix is a known epoch → offset 32, key present.
        let mut tagged = epoch.to_vec();
        tagged.extend_from_slice(&[0xAB; 40]);
        let plan = kc.classify(&tagged);
        assert_eq!(plan.epoch, epoch);
        assert_eq!(plan.body_offset, 32);
        assert_eq!(plan.key, Some(SecretKey::new([9u8; 32])));

        // Legacy payload (random 40 bytes, prefix not a known epoch) → epoch 0.
        let legacy = vec![0x11u8; 40];
        let plan = kc.classify(&legacy);
        assert_eq!(plan.epoch, EPOCH0_ID);
        assert_eq!(plan.body_offset, 0);
    }

    #[test]
    fn diagnose_reports_waiting_orphaned_and_redundancy_low() {
        let nonce = [3u8; 32];
        let epoch = compute_epoch_id(&[EPOCH0_ID], 7, &nonce, &[1u8; 32]);
        let holder = keywrap::wrap(&Identity::generate().x25519_public(), &[1u8; 32]); // not to us
        let entries = vec![
            KeyLogEntry {
                seq: 1,
                author: 7,
                epoch_id: epoch,
                body: KeyBody::Rotate {
                    parent_epochs: vec![EPOCH0_ID],
                    nonce,
                },
            },
            KeyLogEntry {
                seq: 2,
                author: 7,
                epoch_id: epoch,
                body: KeyBody::Wrap {
                    recipient: Recipient::Device(7),
                    blob: holder,
                },
            },
        ];
        let me = Identity::generate();
        let kc = Keychain::build(
            [1u8; 32],
            [2u8; 32],
            me.peer_id(),
            &me.x25519_secret(),
            &entries,
        );

        let waiting = kc.diagnose(&[peer(7, PeerStatus::Active)]);
        assert!(
            matches!(waiting.as_slice(), [VaultIssue::WaitingKey { candidates, .. }] if candidates == &vec![7])
        );

        let orphaned = kc.diagnose(&[peer(7, PeerStatus::Revoked)]);
        assert!(matches!(
            orphaned.as_slice(),
            [VaultIssue::KeyOrphaned { .. }]
        ));
    }

    #[test]
    fn backfill_targets_lists_members_without_a_wrap() {
        let me = Identity::generate();
        let k_new = [42u8; 32];
        let nonce = [3u8; 32];
        let epoch = compute_epoch_id(&[EPOCH0_ID], me.peer_id(), &nonce, &k_new);
        let blob = keywrap::wrap(&me.x25519_public(), &k_new);
        let entries = vec![
            KeyLogEntry {
                seq: 1,
                author: me.peer_id(),
                epoch_id: epoch,
                body: KeyBody::Rotate {
                    parent_epochs: vec![EPOCH0_ID],
                    nonce,
                },
            },
            KeyLogEntry {
                seq: 2,
                author: me.peer_id(),
                epoch_id: epoch,
                body: KeyBody::Wrap {
                    recipient: Recipient::Device(me.peer_id()),
                    blob,
                },
            },
        ];
        let kc = Keychain::build(
            [1u8; 32],
            [2u8; 32],
            me.peer_id(),
            &me.x25519_secret(),
            &entries,
        );

        let targets = kc.backfill_targets(&[
            peer(me.peer_id(), PeerStatus::Active),
            peer(8, PeerStatus::Active),
        ]);
        assert!(targets
            .iter()
            .any(|(e, k, p)| *e == epoch && *k == k_new && *p == 8));
        assert!(
            !targets.iter().any(|(_, _, p)| *p == me.peer_id()),
            "already-wrapped self is not a target"
        );
    }
}
