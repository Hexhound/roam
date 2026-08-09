//! Operational-transform rebase of a local text delta into the store's live
//! coordinates.
//!
//! [`FolderBridge::import_file`](crate::FolderBridge::import_file) computes a
//! local edit as the diff between the sidecar ancestor `A`
//! (`last_synced_text`, the disk text at the last sync) and the current disk
//! text `L`. Those char offsets are only valid while the store still reads
//! exactly `A`. Once the sync engine merges a remote peer's edits into the same
//! container, the store reads `R != A`, and the `A`-space offsets land at the
//! wrong char position.
//!
//! [`merge_local_onto_remote`] rebases the local delta (`A -> L`) into the
//! store's `R`-space and returns the 3-way merged text: `R` with the local
//! edits re-applied at their transformed positions. It is **lossless** — remote
//! edits already present in `R` are preserved, and local edits are layered on
//! top; nothing is dropped diff3-style. The caller then diffs `R -> merged` to
//! obtain a clean op sequence for the store, and independently re-derives
//! `merged` here as the desync guard.
//!
//! The rebase is defined entirely in **unicode-char** units (matching the
//! storage layer's char-offset edit API), so multi-byte content stays correct.

use similar::{ChangeTag, TextDiff};

/// A concurrent-edit conflict surfaced by [`merge_local_onto_remote`].
///
/// Records a contested ancestor char range that BOTH the local and remote sides
/// edited (their edits touch overlapping ancestor content — e.g. both replaced
/// the same region). This is a pure SIGNAL: the merge result is unchanged (the
/// lossless OT union stays authoritative), the conflict just describes where the
/// two sides collided so a caller can surface it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// Start (inclusive) of the contested range in ancestor char coordinates.
    pub ancestor_start: usize,
    /// End (exclusive) of the contested range in ancestor char coordinates.
    pub ancestor_end: usize,
    /// The ancestor text in `[ancestor_start, ancestor_end)` — the content both
    /// sides changed.
    pub ancestor_text: String,
}

/// A local edit expressed in **clean ancestor (`A`) char coordinates**.
///
/// Unlike [`crate::textdiff::diff_to_ops`] (whose positions are relative to the
/// progressively-mutated string), these positions are pure indices into the
/// original ancestor, which is what the `A -> R` position map is keyed on.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalEdit {
    /// Insert `s` at the ancestor boundary before char index `a_pos`.
    Insert { a_pos: usize, s: String },
    /// Delete the ancestor chars in `[start, end)`.
    Delete { start: usize, end: usize },
}

/// Rebase the local delta `A -> L` onto the remote/store text `R` and return
/// the 3-way merged text.
///
/// `a` is the ancestor (last-synced disk text), `l` is the current disk text,
/// and `r` is the store's current text (which may already contain concurrent
/// remote edits merged on top of `a`). The result is `r` with every local edit
/// re-expressed in `r`-space and applied:
///
/// - a local **insert** lands at the `r` position its ancestor boundary maps to
///   (accounting for remote insertions/deletions before it);
/// - a local **delete** removes only the ancestor chars that are *still present*
///   in `r` (chars a remote peer already deleted are skipped — no double delete,
///   no out-of-bounds), at their mapped `r` positions.
///
/// When `r == a` this returns exactly `l`; when there are no local edits it
/// returns exactly `r`.
///
/// # Conflict semantics
///
/// The merge is a **lossless union**: it never drops a side's edit and never
/// emits a conflict marker. On genuine conflicts that produces defined but
/// sometimes surprising artifacts:
///
/// - **Local delete over a remote insert inside the deleted range** → the
///   remote-inserted text survives "orphaned". `A = "abc"`, `L = ""` (local
///   deleted everything), `R = "aXbc"` (remote inserted `X`) → `"X"`. The local
///   delete only removes ancestor chars still present in `R`; the remote insert
///   was never part of the ancestor range, so it is not deleted.
/// - **Both sides replace the same region** → both replacements are
///   concatenated, no marker. `A = "abc"`, `L = "aYc"`, `R = "aZc"` → `"aZYc"`
///   (the remote replacement, then the local one).
/// - **Co-located inserts at the same boundary** → the local insert lands
///   AFTER the remote insert, a deterministic tie-break. `A = "abc"`,
///   `L = "LOCabc"`, `R = "REMabc"` → `"REMLOCabc"`.
///
/// # Conflict signal
///
/// Alongside the merged string this returns a `Vec<Conflict>` describing genuine
/// 3-way overlaps: ancestor ranges that BOTH sides edited (a local edit and a
/// remote edit whose ancestor footprints overlap by at least one char — i.e.
/// both replaced/removed the same region). Non-overlapping concurrent edits
/// (each side changed a DIFFERENT region) produce NO conflict. The merged string
/// is IDENTICAL to what a conflict-unaware merge would produce; the conflicts are
/// purely additive information.
pub fn merge_local_onto_remote(a: &str, l: &str, r: &str) -> (String, Vec<Conflict>) {
    let local_edits = local_edits(a, l);
    let remote_edits = self::local_edits(a, r);
    let conflicts = detect_conflicts(a, &local_edits, &remote_edits);
    let (a_to_r, present) = position_map(a, r);

    // Mutate a char model of `r`. Local edits are ordered front-to-back in
    // ancestor space and `a_to_r` is monotonic, so a running `shift` (net chars
    // inserted minus deleted so far) keeps each subsequent mapped position
    // correct without any reverse-order bookkeeping.
    let mut chars: Vec<char> = r.chars().collect();
    let mut shift: isize = 0;

    for edit in &local_edits {
        match edit {
            LocalEdit::Insert { a_pos, s } => {
                let r_pos = (a_to_r[*a_pos] as isize + shift) as usize;
                let insert: Vec<char> = s.chars().collect();
                let count = insert.len();
                chars.splice(r_pos..r_pos, insert);
                shift += count as isize;
            }
            LocalEdit::Delete { start, end } => {
                for a_idx in *start..*end {
                    // Skip chars a remote peer already removed from `r`.
                    if present[a_idx] {
                        let r_pos = (a_to_r[a_idx] as isize + shift) as usize;
                        chars.remove(r_pos);
                        shift -= 1;
                    }
                }
            }
        }
    }

    (chars.into_iter().collect(), conflicts)
}

/// Detect genuine 3-way conflicts: ancestor ranges edited by BOTH sides.
///
/// Each edit has an **ancestor footprint**: a delete occupies its `[start, end)`
/// range; an insert is a zero-width point `[a_pos, a_pos)` (it adds content
/// without removing any ancestor char). Two footprints CONFLICT when they
/// overlap by a positive-width span (`ls < re && rs < le`). Because inserts are
/// zero-width, this fires only when both sides removed/replaced at least one
/// shared ancestor char — the "both replaced the same region" case — and never
/// for co-located inserts or edits to disjoint regions.
///
/// Ancestor char indices map to byte ranges once (via `char_indices`) so the
/// contested substring is sliced without re-walking per pair.
fn detect_conflicts(a: &str, local: &[LocalEdit], remote: &[LocalEdit]) -> Vec<Conflict> {
    let mut conflicts: Vec<Conflict> = Vec::new();
    for le in local {
        let (ls, lend) = footprint(le);
        if ls == lend {
            continue; // zero-width local insert can never positive-overlap.
        }
        for re in remote {
            let (rs, rend) = footprint(re);
            // Positive-width overlap of the two half-open ancestor ranges.
            if ls < rend && rs < lend {
                let start = ls.max(rs);
                let end = lend.min(rend);
                let conflict = Conflict {
                    ancestor_start: start,
                    ancestor_end: end,
                    ancestor_text: char_slice(a, start, end),
                };
                // Coalesce duplicates (one local delete can overlap several
                // remote edits producing the same contested span).
                if !conflicts.contains(&conflict) {
                    conflicts.push(conflict);
                }
            }
        }
    }
    conflicts
}

/// The ancestor footprint `[start, end)` of an edit: a delete's range, or a
/// zero-width point at an insert's boundary.
fn footprint(edit: &LocalEdit) -> (usize, usize) {
    match edit {
        LocalEdit::Delete { start, end } => (*start, *end),
        LocalEdit::Insert { a_pos, .. } => (*a_pos, *a_pos),
    }
}

/// The substring of `a` covering ancestor chars `[start, end)`.
fn char_slice(a: &str, start: usize, end: usize) -> String {
    a.chars().skip(start).take(end - start).collect()
}

/// Walk the `A -> L` diff into clean ancestor-coordinate edits.
///
/// Equal chars advance the ancestor cursor; a delete run records the ancestor
/// range it removes (and advances the cursor past it); an insert records the
/// text at the current ancestor boundary (leaving the cursor put, since inserted
/// chars do not consume ancestor positions).
fn local_edits(a: &str, l: &str) -> Vec<LocalEdit> {
    let diff = TextDiff::from_chars(a, l);
    let mut edits: Vec<LocalEdit> = Vec::new();
    let mut a_idx: usize = 0;

    for change in diff.iter_all_changes() {
        let value = change.value();
        let count = value.chars().count();
        match change.tag() {
            ChangeTag::Equal => a_idx += count,
            ChangeTag::Delete => {
                // Coalesce into a contiguous ancestor range where possible.
                if let Some(LocalEdit::Delete { end, .. }) = edits.last_mut() {
                    if *end == a_idx {
                        *end = a_idx + count;
                        a_idx += count;
                        continue;
                    }
                }
                edits.push(LocalEdit::Delete {
                    start: a_idx,
                    end: a_idx + count,
                });
                a_idx += count;
            }
            ChangeTag::Insert => {
                if let Some(LocalEdit::Insert { a_pos, s }) = edits.last_mut() {
                    if *a_pos == a_idx {
                        s.push_str(value);
                        continue;
                    }
                }
                edits.push(LocalEdit::Insert {
                    a_pos: a_idx,
                    s: value.to_string(),
                });
            }
        }
    }

    edits
}

/// Build the ancestor→remote position map and per-ancestor-char presence flags
/// from the `A -> R` (remote) diff.
///
/// Returns `(a_to_r, present)` where `a_to_r` has length `a.len_chars() + 1`:
/// `a_to_r[i]` is the `r` char index the ancestor boundary before char `i` maps
/// to (`a_to_r[a_len]` is `r`'s length). `present[i]` is `true` when ancestor
/// char `i` still exists in `r` (an `Equal` run) and `false` when a remote peer
/// deleted it. Remote insertions advance the `r` cursor without consuming an
/// ancestor position, so ancestor boundaries after them map to shifted `r`
/// positions.
fn position_map(a: &str, r: &str) -> (Vec<usize>, Vec<bool>) {
    let a_len = a.chars().count();
    let mut a_to_r = vec![0usize; a_len + 1];
    let mut present = vec![false; a_len];

    let diff = TextDiff::from_chars(a, r);
    let mut a_idx: usize = 0;
    let mut r_idx: usize = 0;

    for change in diff.iter_all_changes() {
        let count = change.value().chars().count();
        match change.tag() {
            ChangeTag::Equal => {
                for _ in 0..count {
                    a_to_r[a_idx] = r_idx;
                    present[a_idx] = true;
                    a_idx += 1;
                    r_idx += 1;
                }
            }
            ChangeTag::Delete => {
                // Ancestor char removed by remote: it maps to the deletion point
                // in `r` and is not present.
                for _ in 0..count {
                    a_to_r[a_idx] = r_idx;
                    present[a_idx] = false;
                    a_idx += 1;
                }
            }
            ChangeTag::Insert => {
                // Remote-inserted chars advance `r` only.
                r_idx += count;
            }
        }
    }

    // Final boundary maps end-of-A to end-of-R.
    a_to_r[a_idx] = r_idx;
    (a_to_r, present)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::textdiff::{diff_to_ops, TextOp};
    use proptest::prelude::*;

    /// Apply char-offset ops left-to-right under a `Vec<char>` splice model —
    /// the same model the storage layer effectively realizes.
    fn apply_ops(base: &str, ops: &[TextOp]) -> String {
        let mut chars: Vec<char> = base.chars().collect();
        for op in ops {
            match op {
                TextOp::Insert { pos, s } => {
                    let insert: Vec<char> = s.chars().collect();
                    chars.splice(*pos..*pos, insert);
                }
                TextOp::Delete { pos, len } => {
                    chars.drain(*pos..*pos + *len);
                }
            }
        }
        chars.into_iter().collect()
    }

    /// The store's op sequence (`diff_to_ops(R, merged)`) applied to `R` must
    /// reproduce the merged text `merge_local_onto_remote` computes — the exact
    /// invariant `import_file` relies on.
    fn assert_store_ops_reach_merge(a: &str, l: &str, r: &str, expected: &str) {
        let (merged, _conflicts) = merge_local_onto_remote(a, l, r);
        assert_eq!(merged, expected, "merge {a:?}+{l:?} onto {r:?}");
        let ops = diff_to_ops(r, &merged);
        assert_eq!(
            apply_ops(r, &ops),
            merged,
            "diff_to_ops(R, merged) must roundtrip R -> merged"
        );
    }

    #[test]
    fn no_remote_edit_returns_local_text() {
        // R == A: rebase is a no-op, merged is exactly L.
        assert_store_ops_reach_merge("hello\n", "hello world\n", "hello\n", "hello world\n");
    }

    #[test]
    fn no_local_edit_returns_remote_text() {
        // L == A: nothing to apply, merged is exactly R.
        assert_store_ops_reach_merge("hello\n", "hello\n", "XYZ hello\n", "XYZ hello\n");
    }

    #[test]
    fn remote_prefix_local_suffix() {
        // Remote inserted a front prefix, local inserted a suffix: both survive.
        assert_store_ops_reach_merge(
            "hello world\n",
            "hello world END\n",
            "XYZ hello world\n",
            "XYZ hello world END\n",
        );
    }

    #[test]
    fn remote_deleted_region_local_untouched() {
        // Remote deleted "world", local appended " END" before the newline.
        assert_store_ops_reach_merge(
            "hello world\n",
            "hello world END\n",
            "hello \n",
            "hello  END\n",
        );
    }

    #[test]
    fn local_delete_of_partially_remote_deleted_run() {
        // Remote deleted "wor"; local deletes the whole "world" run. Only the
        // still-present chars ("ld") are removed — no double delete, no panic.
        assert_store_ops_reach_merge("hello world\n", "hello \n", "hello ld\n", "hello \n");
    }

    #[test]
    fn multibyte_remote_prefix_local_edit_after() {
        // Remote inserted a CJK + emoji prefix; local appends after it. Offsets
        // stay char-correct across multi-byte scalars.
        assert_store_ops_reach_merge(
            "café\n",
            "café latte\n",
            "世界🚀 café\n",
            "世界🚀 café latte\n",
        );
    }

    #[test]
    fn overlapping_local_and_remote_insert_at_same_boundary() {
        // Co-located inserts: local lands AFTER the remote insert at the same
        // boundary — a deterministic tie-break. Pin the EXACT ordered result so
        // a future change to that tie-break is caught.
        let (merged, conflicts) = merge_local_onto_remote("abc", "LOCabc", "REMabc");
        assert_eq!(merged, "REMLOCabc");
        // Co-located inserts (no ancestor char removed) are NOT a conflict.
        assert!(conflicts.is_empty(), "co-located inserts must not conflict: {conflicts:?}");
    }

    #[test]
    fn overlapping_replacements_report_a_conflict_without_changing_merge() {
        // E3: both sides REPLACE the same region (A="abc", L="aYc", R="aZc").
        // The merged string is byte-identical to the documented union
        // ("aZYc") AND a conflict over the shared "b" region is reported.
        let (merged, conflicts) = merge_local_onto_remote("abc", "aYc", "aZc");
        assert_eq!(merged, "aZYc", "merge output must be unchanged");
        assert_eq!(conflicts.len(), 1, "one overlapping region: {conflicts:?}");
        assert_eq!(
            conflicts[0],
            Conflict {
                ancestor_start: 1,
                ancestor_end: 2,
                ancestor_text: "b".to_string(),
            }
        );
    }

    #[test]
    fn non_overlapping_concurrent_edits_report_no_conflict() {
        // E3: local changes the START, remote changes the END — disjoint
        // ancestor regions. Both survive AND no conflict is flagged.
        let (merged, conflicts) = merge_local_onto_remote("abcd", "Xbcd", "abcY");
        assert_eq!(merged, "XbcY");
        assert!(conflicts.is_empty(), "disjoint edits must not conflict: {conflicts:?}");
    }

    #[test]
    fn no_remote_edit_reports_no_conflict() {
        // R == A: only the local side edited, so there is nothing to conflict
        // with even though the local edit replaces a region.
        let (_merged, conflicts) = merge_local_onto_remote("abc", "aYc", "abc");
        assert!(conflicts.is_empty(), "single-sided edit is never a conflict: {conflicts:?}");
    }

    // --- Independent-oracle losslessness proptest -------------------------
    //
    // The properties below verify the merge with an oracle that does NOT reuse
    // `merge_local_onto_remote` (nor `diff_to_ops(R, merged)`), so a
    // wrong-but-self-consistent merge (dropped insert, mis-anchored delete,
    // lost survivor) FAILS. The trick is three DISJOINT alphabets: the ancestor
    // uses one set, each side's insertions use a set unique to that side. That
    // lets us read the merged output back apart: filter to the ancestor
    // alphabet to recover exactly the surviving ancestor chars, and search each
    // side's alphabet-tagged runs independently.

    /// Apply an edit plan (`keep[i]` per ancestor char, `inserts[i]` at each of
    /// the `a.len()+1` boundaries) to `a`, returning the produced string and the
    /// non-empty inserted runs in order. This is the oracle's independent model
    /// of "an edit script against the ancestor".
    fn apply_edit_plan(a: &[char], keep: &[bool], inserts: &[String]) -> (String, Vec<String>) {
        let mut out = String::new();
        let mut runs: Vec<String> = Vec::new();
        for i in 0..a.len() {
            if !inserts[i].is_empty() {
                out.push_str(&inserts[i]);
                runs.push(inserts[i].clone());
            }
            if keep[i] {
                out.push(a[i]);
            }
        }
        if !inserts[a.len()].is_empty() {
            out.push_str(&inserts[a.len()]);
            runs.push(inserts[a.len()].clone());
        }
        (out, runs)
    }

    /// Whether every run in `runs` occurs in `haystack` in order (each run found
    /// at or after the end of the previous match). A lossless merge that never
    /// reorders a side's insertions must satisfy this greedy left-to-right match.
    fn contains_runs_in_order(haystack: &str, runs: &[String]) -> bool {
        let mut cursor = 0usize;
        for run in runs {
            match haystack[cursor..].find(run.as_str()) {
                Some(idx) => cursor += idx + run.len(),
                None => return false,
            }
        }
        true
    }

    /// The ancestor chars kept by BOTH sides, in ancestor order — the exact set
    /// that must survive into the merge (either side deleting a char removes it).
    fn survivors(a: &[char], keep_l: &[bool], keep_r: &[bool]) -> String {
        a.iter()
            .enumerate()
            .filter(|(i, _)| keep_l[*i] && keep_r[*i])
            .map(|(_, c)| *c)
            .collect()
    }

    /// Keep only chars from `alphabet` (used to read the ancestor-alphabet
    /// subsequence back out of the merged output).
    fn filter_alphabet(s: &str, alphabet: &[char]) -> String {
        s.chars().filter(|c| alphabet.contains(c)).collect()
    }

    /// Assert the losslessness invariants for one concrete `(A, plans)` triple,
    /// given the disjoint ancestor alphabet. Returns nothing; panics via
    /// `prop_assert!` semantics are inlined by the caller, so this uses plain
    /// `assert!` and is called from within `proptest!` bodies.
    fn check_lossless_union(
        a: &[char],
        keep_l: &[bool],
        ins_l: &[String],
        keep_r: &[bool],
        ins_r: &[String],
        ancestor_alpha: &[char],
    ) {
        let (l, local_runs) = apply_edit_plan(a, keep_l, ins_l);
        let (r, remote_runs) = apply_edit_plan(a, keep_r, ins_r);
        let a_str: String = a.iter().collect();
        let (merged, _conflicts) = merge_local_onto_remote(&a_str, &l, &r);

        // (a) every LOCAL-inserted run survives, in order.
        assert!(
            contains_runs_in_order(&merged, &local_runs),
            "lost/reordered a local insert: A={a_str:?} L={l:?} R={r:?} merged={merged:?} runs={local_runs:?}"
        );
        // (b) every REMOTE-inserted run survives, in order.
        assert!(
            contains_runs_in_order(&merged, &remote_runs),
            "lost/reordered a remote insert: A={a_str:?} L={l:?} R={r:?} merged={merged:?} runs={remote_runs:?}"
        );
        // (e) exactly the both-kept ancestor chars survive, in ancestor order —
        // read back via the disjoint ancestor alphabet (insert runs can't leak
        // into this filter).
        assert_eq!(
            filter_alphabet(&merged, ancestor_alpha),
            survivors(a, keep_l, keep_r),
            "ancestor survivors wrong: A={a_str:?} L={l:?} R={r:?} merged={merged:?}"
        );
        // (c) determinism: pure function, identical output on a second call.
        assert_eq!(
            merged,
            merge_local_onto_remote(&a_str, &l, &r).0,
            "merge is not deterministic"
        );
        // (d) degenerate boundaries: no-remote → local-applied; no-local → remote.
        assert_eq!(merge_local_onto_remote(&a_str, &l, &a_str).0, l, "no-remote boundary");
        assert_eq!(merge_local_onto_remote(&a_str, &a_str, &r).0, r, "no-local boundary");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Losslessness over ASCII. The ancestor is a DISTINCT-char subsequence
        /// of an 8-char pool [a-h] (a mask picks which pool chars appear), so the
        /// `A -> L`/`A -> R` diffs attribute each keep/delete unambiguously and
        /// the generated plan is authoritative. Local inserts draw from [X-Z],
        /// remote inserts from [P-R] — three disjoint alphabets.
        #[test]
        fn prop_lossless_union_ascii(
            (a, keep_l, ins_l, keep_r, ins_r) in
                prop::collection::vec(any::<bool>(), 8).prop_flat_map(|mask| {
                    const POOL: [char; 8] = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
                    let a: Vec<char> = POOL
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| mask[*i])
                        .map(|(_, c)| *c)
                        .collect();
                    let n = a.len();
                    (
                        Just(a),
                        prop::collection::vec(any::<bool>(), n),
                        prop::collection::vec("[X-Z]{0,3}", n + 1),
                        prop::collection::vec(any::<bool>(), n),
                        prop::collection::vec("[P-R]{0,3}", n + 1),
                    )
                }),
        ) {
            check_lossless_union(
                &a,
                &keep_l,
                &ins_l,
                &keep_r,
                &ins_r,
                &['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'],
            );
        }

        /// Losslessness over unicode. The ancestor is a DISTINCT-char subsequence
        /// of a 6-char multi-byte pool {a, b, é, 世, ć, ñ}; local inserts draw from
        /// {🚀, α}, remote inserts from {β, γ} — three disjoint alphabets that
        /// exercise multi-byte scalars (incl. the astral 🚀) through the rebase.
        #[test]
        fn prop_lossless_union_unicode(
            (a, keep_l, ins_l, keep_r, ins_r) in
                prop::collection::vec(any::<bool>(), 6).prop_flat_map(|mask| {
                    const POOL: [char; 6] =
                        ['a', 'b', '\u{00e9}', '\u{4e16}', '\u{0107}', '\u{00f1}'];
                    let a: Vec<char> = POOL
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| mask[*i])
                        .map(|(_, c)| *c)
                        .collect();
                    let n = a.len();
                    (
                        Just(a),
                        prop::collection::vec(any::<bool>(), n),
                        prop::collection::vec("[\u{1F680}\u{03B1}]{0,3}", n + 1),
                        prop::collection::vec(any::<bool>(), n),
                        prop::collection::vec("[\u{03B2}\u{03B3}]{0,3}", n + 1),
                    )
                }),
        ) {
            check_lossless_union(
                &a,
                &keep_l,
                &ins_l,
                &keep_r,
                &ins_r,
                &['a', 'b', '\u{00e9}', '\u{4e16}', '\u{0107}', '\u{00f1}'],
            );
        }

        /// When there are no remote edits (R == A) the merge must equal L
        /// exactly — the fast path's result.
        #[test]
        fn prop_no_remote_edit_equals_local(a in "[a-d]{0,10}", l in "[a-d]{0,10}") {
            prop_assert_eq!(merge_local_onto_remote(&a, &l, &a).0, l);
        }

        /// When there are no local edits (L == A) the merge must equal R
        /// exactly — remote edits are preserved untouched.
        #[test]
        fn prop_no_local_edit_equals_remote(a in "[a-d]{0,10}", r in "[a-d]{0,10}") {
            prop_assert_eq!(merge_local_onto_remote(&a, &a, &r).0, r);
        }
    }
}
