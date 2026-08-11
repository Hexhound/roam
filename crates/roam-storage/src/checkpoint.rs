//! Pure checkpoint planning: given a chosen history marker and the set of blob
//! hashes still referenced across the retained range, compute what a checkpoint
//! would keep and how many bytes it frees. No IO — the store executes the plan.

use crate::history::Marker;
use std::collections::{BTreeMap, HashSet};

/// A resolved, executable checkpoint decision.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckpointPlan {
    /// Base64 frontier to shallow-snapshot at (from the chosen marker).
    pub frontier: String,
    /// Per-peer op-log line counts to DROP from the head of each log.
    pub drop_lines: BTreeMap<u64, u64>,
}

/// Build the plan from the chosen marker. The marker's `log_lens` are exactly
/// the number of leading lines that fold into the shallow base, so they are the
/// lines to drop.
pub fn plan_from_marker(marker: &Marker) -> CheckpointPlan {
    CheckpointPlan {
        frontier: marker.frontier.clone(),
        drop_lines: marker.log_lens.clone(),
    }
}

/// Bytes reclaimable = sum of sizes of on-disk blobs NOT in `referenced`.
/// `on_disk` is `(hash, size_bytes)`; `referenced` is every hash still reachable
/// in the retained range.
pub fn reclaimable_blob_bytes(on_disk: &[(String, u64)], referenced: &HashSet<String>) -> u64 {
    on_disk
        .iter()
        .filter(|(h, _)| !referenced.contains(h))
        .map(|(_, sz)| *sz)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker() -> Marker {
        let mut log_lens = BTreeMap::new();
        log_lens.insert(1u64, 3);
        log_lens.insert(2u64, 5);
        Marker {
            ts_ms: 42,
            frontier: "FRONT".into(),
            log_lens,
        }
    }

    #[test]
    fn plan_drops_exactly_the_marker_line_counts() {
        let plan = plan_from_marker(&marker());
        assert_eq!(plan.frontier, "FRONT");
        assert_eq!(plan.drop_lines.get(&1), Some(&3));
        assert_eq!(plan.drop_lines.get(&2), Some(&5));
    }

    #[test]
    fn reclaimable_sums_only_unreferenced_blobs() {
        let on_disk = vec![
            ("a".to_string(), 100),
            ("b".to_string(), 200),
            ("c".to_string(), 50),
        ];
        let referenced: HashSet<String> = ["b".to_string()].into_iter().collect();
        assert_eq!(reclaimable_blob_bytes(&on_disk, &referenced), 150);
    }
}
