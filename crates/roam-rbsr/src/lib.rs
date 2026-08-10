//! Range-based set reconciliation (RBSR) over sets of 32-byte ids, wrapping the
//! `negentropy` crate. Pure bytes-in/bytes-out: no IO, no async. The identical
//! code runs on the Rust client and (via a Rustler NIF) the Elixir backend, so
//! the additive fingerprint matches byte-for-byte — wire-compatible for free.

use negentropy::{Id, Negentropy, NegentropyStorageVector};

/// Which id-set a reconcile session covers. Entries and blobs are reconciled
/// independently: a recovered id alone does not say which endpoint fetches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetKind {
    Entries,
    Blobs,
}

impl SetKind {
    /// URL path segment for this kind (matches the backend route).
    pub fn as_str(self) -> &'static str {
        match self {
            SetKind::Entries => "entries",
            SetKind::Blobs => "blobs",
        }
    }
}

/// A sorted, de-duplicated set of 32-byte ids to reconcile.
pub struct ItemSet {
    ids: Vec<[u8; 32]>,
}

impl ItemSet {
    /// Build from any id iterator; sorts + dedups (negentropy requires sorted,
    /// unique items, and our transfer order is independent of this).
    pub fn from_ids(ids: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let mut ids: Vec<[u8; 32]> = ids.into_iter().collect();
        ids.sort_unstable();
        ids.dedup();
        Self { ids }
    }
}

/// Outcome of folding one server message on the client side.
pub struct Reconciled {
    /// The next message to POST, or `None` when the session has converged.
    pub next_msg: Option<Vec<u8>>,
    /// Ids the SERVER lacks — the client uploads these.
    pub have: Vec<[u8; 32]>,
    /// Ids the CLIENT lacks — the client fetches these.
    pub need: Vec<[u8; 32]>,
}

/// Errors from the underlying negentropy engine (malformed/oversized messages,
/// unsealed storage, etc.).
#[derive(Debug, thiserror::Error)]
#[error("rbsr error: {0}")]
pub struct RbsrError(String);

impl From<negentropy::Error> for RbsrError {
    fn from(e: negentropy::Error) -> Self {
        RbsrError(e.to_string())
    }
}

/// Build a sealed negentropy storage from 32-byte ids. All timestamps are 0, so
/// ordering is purely id-ascending (our ids are timestamp-less keyed hashes).
fn sealed_storage(ids: &[[u8; 32]]) -> Result<NegentropyStorageVector, negentropy::Error> {
    let mut storage = NegentropyStorageVector::new();
    for id in ids {
        storage.insert(0, Id::from_byte_array(*id))?;
    }
    storage.seal()?;
    Ok(storage)
}

fn ids_to_bytes(ids: Vec<Id>) -> Vec<[u8; 32]> {
    ids.into_iter().map(|i| i.to_bytes()).collect()
}

/// Client side: the first message of a session (frame size unlimited = 0).
pub fn initiate(items: &ItemSet) -> Vec<u8> {
    let storage = sealed_storage(&items.ids).expect("sealing an in-memory id set cannot fail");
    let mut neg = Negentropy::borrowed(&storage, 0).expect("negentropy init");
    neg.initiate().expect("initiate")
}

/// Client side: fold a server reply, extracting have/need and the next message.
pub fn reconcile(items: &ItemSet, msg: &[u8]) -> Result<Reconciled, RbsrError> {
    let storage = sealed_storage(&items.ids)?;
    let mut neg = Negentropy::borrowed(&storage, 0)?;
    // Each call builds a fresh, stateless engine; `reconcile_with_ids` requires
    // the initiator flag that `initiate()` set on the (now-dropped) first engine.
    neg.set_initiator();
    let mut have_ids = Vec::new();
    let mut need_ids = Vec::new();
    let next = neg.reconcile_with_ids(msg, &mut have_ids, &mut need_ids)?;
    Ok(Reconciled {
        next_msg: next,
        have: ids_to_bytes(have_ids),
        need: ids_to_bytes(need_ids),
    })
}

/// Server side (stateless): fold a client message, return the reply.
pub fn reconcile_server(items: &ItemSet, msg: &[u8]) -> Result<Vec<u8>, RbsrError> {
    let storage = sealed_storage(&items.ids)?;
    let mut neg = Negentropy::borrowed(&storage, 0)?;
    let reply = neg.reconcile(msg)?;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn id(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }

    /// Drive a full client↔server session to convergence, returning the client's
    /// final (have, need). `have` = ids the server lacks; `need` = ids the client
    /// lacks. Round-capped so a bug can't loop forever.
    fn run_session(client_ids: &[[u8; 32]], server_ids: &[[u8; 32]]) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let client_set = ItemSet::from_ids(client_ids.iter().copied());
        let server_set = ItemSet::from_ids(server_ids.iter().copied());

        let mut have = Vec::new();
        let mut need = Vec::new();
        let mut msg = initiate(&client_set);

        for _ in 0..64 {
            let reply = reconcile_server(&server_set, &msg).unwrap();
            let out = reconcile(&client_set, &reply).unwrap();
            have.extend(out.have);
            need.extend(out.need);
            match out.next_msg {
                Some(next) => msg = next,
                None => return (have, need),
            }
        }
        panic!("session did not converge within the round cap");
    }

    fn sorted(mut v: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
        v.sort();
        v
    }

    #[test]
    fn disjoint_sets_each_learn_the_others_ids() {
        let (have, need) = run_session(&[id(1), id(2)], &[id(3), id(4)]);
        assert_eq!(sorted(have), vec![id(1), id(2)]);
        assert_eq!(sorted(need), vec![id(3), id(4)]);
    }

    #[test]
    fn subset_client_only_needs_the_extra_server_ids() {
        let (have, need) = run_session(&[id(1)], &[id(1), id(2), id(3)]);
        assert!(have.is_empty(), "server already has id 1");
        assert_eq!(sorted(need), vec![id(2), id(3)]);
    }

    #[test]
    fn equal_sets_transfer_nothing() {
        let (have, need) = run_session(&[id(1), id(2)], &[id(2), id(1)]);
        assert!(have.is_empty() && need.is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        /// For ANY two id sets, a full session leaves the client with have == the
        /// ids only it holds and need == the ids only the server holds (the exact
        /// symmetric difference, split by side).
        #[test]
        fn convergence_equals_symmetric_difference(
            client_raw in prop::collection::vec(any::<[u8; 32]>(), 0..40),
            server_raw in prop::collection::vec(any::<[u8; 32]>(), 0..40),
        ) {
            let client: BTreeSet<[u8; 32]> = client_raw.into_iter().collect();
            let server: BTreeSet<[u8; 32]> = server_raw.into_iter().collect();

            let client_v: Vec<[u8; 32]> = client.iter().copied().collect();
            let server_v: Vec<[u8; 32]> = server.iter().copied().collect();
            let (have, need) = run_session(&client_v, &server_v);

            let expect_have: BTreeSet<[u8; 32]> = client.difference(&server).copied().collect();
            let expect_need: BTreeSet<[u8; 32]> = server.difference(&client).copied().collect();

            prop_assert_eq!(have.into_iter().collect::<BTreeSet<_>>(), expect_have);
            prop_assert_eq!(need.into_iter().collect::<BTreeSet<_>>(), expect_need);
        }
    }
}
