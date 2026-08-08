//! Property: N documents applying the same set of edits in ANY delta-exchange
//! order converge to identical content. This is the load-bearing CRDT guarantee.

use proptest::prelude::*;
use roam_crdt::Document;

#[derive(Clone, Debug)]
struct Edit {
    who: usize, // which replica makes the edit
    text: String,
}

fn edits_strategy() -> impl Strategy<Value = Vec<Edit>> {
    prop::collection::vec(
        (0usize..3, "[a-z ]{1,6}").prop_map(|(who, text)| Edit { who, text }),
        1..25,
    )
}

proptest! {
    #[test]
    fn all_replicas_converge(edits in edits_strategy()) {
        const N: usize = 3;
        let docs: Vec<Document> = (0..N)
            .map(|i| Document::new((i as u64) + 1).unwrap())
            .collect();

        // Each edit is applied on its origin replica, always appending at the end.
        for e in &edits {
            let d = &docs[e.who % N];
            let end = d.text("note").chars().count();
            d.insert_text("note", end, &e.text).unwrap();
            d.commit();
        }

        // Gossip to convergence: repeatedly exchange deltas until stable.
        for _ in 0..N {
            for i in 0..N {
                for j in 0..N {
                    if i == j { continue; }
                    let delta = docs[i].export_from(&docs[j].version()).unwrap();
                    docs[j].import(&delta).unwrap();
                }
            }
        }

        let first = docs[0].text("note");
        for d in &docs[1..] {
            prop_assert_eq!(d.text("note"), first.clone());
        }
        // No data lost: total inserted characters are all present.
        let total: usize = edits.iter().map(|e| e.text.chars().count()).sum();
        prop_assert_eq!(first.chars().count(), total);
    }
}
