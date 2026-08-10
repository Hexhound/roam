//! Range-based set reconciliation (RBSR) over sets of 32-byte ids, wrapping the
//! `negentropy` crate. Pure bytes-in/bytes-out: no IO, no async. The identical
//! code runs on the Rust client and (via a Rustler NIF) the Elixir backend, so
//! the additive fingerprint matches byte-for-byte — wire-compatible for free.

use negentropy::{Id, Negentropy, NegentropyStorageVector};

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

#[cfg(test)]
mod api_smoke {
    use super::*;

    #[test]
    fn negentropy_api_compiles_and_round_trips_empty() {
        let client_storage = sealed_storage(&[]).unwrap();
        let server_storage = sealed_storage(&[]).unwrap();

        let mut client = Negentropy::borrowed(&client_storage, 0).unwrap();
        let mut server = Negentropy::borrowed(&server_storage, 0).unwrap();

        let msg0 = client.initiate().unwrap();
        let reply = server.reconcile(&msg0).unwrap();

        let mut have = Vec::new();
        let mut need = Vec::new();
        let next = client
            .reconcile_with_ids(&reply, &mut have, &mut need)
            .unwrap();

        assert!(next.is_none(), "empty vs empty converges in one round");
        assert!(have.is_empty() && need.is_empty());
    }
}
