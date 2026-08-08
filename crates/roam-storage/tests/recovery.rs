//! Property: a Store reopened from disk (after an arbitrary edit sequence,
//! with snapshots taken at arbitrary points) always yields the same content
//! as the live store — proving op-log-is-truth.

use proptest::prelude::*;
use roam_storage::{Identity, Store};
use tempfile::tempdir;

proptest! {
    #[test]
    fn reopen_matches_live(
        chunks in prop::collection::vec(("[a-z]{1,5}", any::<bool>()), 1..20)
    ) {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let id = Identity::generate();

        let live_text;
        {
            let mut store = Store::open(&vault, id.clone()).unwrap();
            for (text, snap) in &chunks {
                let end = store.text("note").chars().count();
                store.edit_text("note", end, text).unwrap();
                if *snap {
                    store.write_snapshot().unwrap();
                }
            }
            live_text = store.text("note");
        }

        let reopened = Store::open(&vault, id).unwrap();
        prop_assert_eq!(reopened.text("note"), live_text);
    }
}
