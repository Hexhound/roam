//! Text diffing that emits edit operations in **unicode char** units.
//!
//! The storage layer edits documents by unicode character offset:
//! `Store::edit_text(id, pos, s)` inserts `s` at char position `pos`, and
//! `Store::delete_text(id, pos, len)` removes `len` chars starting at char
//! position `pos`. This module turns an `old`/`new` string pair into a
//! sequence of [`TextOp`]s whose `pos`/`len` are char offsets and which,
//! applied left-to-right to `old`, reproduce `new` exactly.
//!
//! Ops are emitted **front-to-back**. A running cursor tracks the position
//! in the *current* (being-mutated) string: an `Equal` char advances the
//! cursor, a `Delete` removes the char at the cursor (so the cursor stays
//! put as later chars shift left into it), and an `Insert` places a char at
//! the cursor and advances past it. This mirrors applying each op the
//! instant it is produced, which keeps the offsets valid for sequential
//! application without any reverse-order bookkeeping.

use similar::{ChangeTag, TextDiff};

/// A single edit operation over a document, in unicode-char units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextOp {
    /// Insert `s` so that its first char lands at char position `pos`.
    Insert {
        /// Char offset at which the inserted text begins.
        pos: usize,
        /// The text to insert.
        s: String,
    },
    /// Delete `len` chars starting at char position `pos`.
    Delete {
        /// Char offset of the first deleted char.
        pos: usize,
        /// Number of chars to delete.
        len: usize,
    },
}

/// Upper bound on the char length of either side before [`diff_to_ops`] falls
/// back to a coarse whole-container replace.
///
/// `similar::TextDiff::from_chars` is Myers diff with `O(n·m)` memory in the two
/// char counts, which blows up on large files (a 1M-char pair is ~10^12 cells).
/// Above this bound we trade a minimal diff for an `O(1)`-memory replace that is
/// still a CORRECT op sequence (see [`coarse_replace`]).
pub(crate) const DIFF_MAX_CHARS: usize = 1_000_000;

/// Compute the char-offset [`TextOp`]s that transform `old` into `new`.
///
/// The returned ops are ordered for left-to-right application: folding them
/// over `old` (splicing chars at each `pos`) yields `new`. When `old == new`
/// the result is empty. Adjacent same-kind changes are coalesced into a
/// single op.
///
/// When either side exceeds [`DIFF_MAX_CHARS`] chars this falls back to a
/// coarse whole-container replace to bound memory (see [`coarse_replace`]);
/// below the threshold it returns the exact `similar` char diff.
pub fn diff_to_ops(old: &str, new: &str) -> Vec<TextOp> {
    diff_to_ops_bounded(old, new, DIFF_MAX_CHARS)
}

/// The coarse fallback: delete every old char then insert `new` at pos 0. This
/// is `O(1)` in memory (no diff matrix) and applies correctly front-to-back
/// under the splice model — `Delete{0, old_len}` empties the container, then
/// `Insert{0, new}` writes the new text. `old_len` is the OLD char count.
fn coarse_replace(old_len: usize, new: &str) -> Vec<TextOp> {
    let mut ops = Vec::new();
    if old_len > 0 {
        ops.push(TextOp::Delete { pos: 0, len: old_len });
    }
    if !new.is_empty() {
        ops.push(TextOp::Insert {
            pos: 0,
            s: new.to_string(),
        });
    }
    ops
}

/// [`diff_to_ops`] with an injectable threshold so tests can exercise the
/// boundary without allocating a real multi-megabyte string.
pub(crate) fn diff_to_ops_bounded(old: &str, new: &str, max_chars: usize) -> Vec<TextOp> {
    let old_len = old.chars().count();
    let new_len = new.chars().count();
    if old_len > max_chars || new_len > max_chars {
        return coarse_replace(old_len, new);
    }

    let diff = TextDiff::from_chars(old, new);

    let mut ops: Vec<TextOp> = Vec::new();
    // Cursor into the *current* (being-mutated) string, in char units.
    let mut cursor: usize = 0;
    // Pending insert text being accumulated at the current cursor.
    let mut pending_insert = String::new();
    // Start position of a pending insert run.
    let mut insert_pos: usize = 0;
    // Pending delete run length starting at the current cursor.
    let mut delete_len: usize = 0;

    // Flush an accumulated insert run into a single op.
    fn flush_insert(ops: &mut Vec<TextOp>, pending_insert: &mut String, insert_pos: usize) {
        if !pending_insert.is_empty() {
            ops.push(TextOp::Insert {
                pos: insert_pos,
                s: std::mem::take(pending_insert),
            });
        }
    }
    // Flush an accumulated delete run into a single op.
    fn flush_delete(ops: &mut Vec<TextOp>, delete_len: &mut usize, cursor: usize) {
        if *delete_len > 0 {
            ops.push(TextOp::Delete {
                pos: cursor,
                len: *delete_len,
            });
            *delete_len = 0;
        }
    }

    for change in diff.iter_all_changes() {
        // `from_chars` tokenizes by char, so each change value is one char;
        // counting chars keeps us correct even if a value ever spans more.
        let value = change.value();
        let char_count = value.chars().count();

        match change.tag() {
            ChangeTag::Equal => {
                flush_insert(&mut ops, &mut pending_insert, insert_pos);
                flush_delete(&mut ops, &mut delete_len, cursor);
                cursor += char_count;
            }
            ChangeTag::Delete => {
                // A delete run continues at the same cursor; inserts must be
                // flushed first so their position stays anchored.
                flush_insert(&mut ops, &mut pending_insert, insert_pos);
                delete_len += char_count;
            }
            ChangeTag::Insert => {
                // Inserts land at the current cursor and advance it. Flush
                // any pending delete first so ordering stays stable.
                flush_delete(&mut ops, &mut delete_len, cursor);
                if pending_insert.is_empty() {
                    insert_pos = cursor;
                }
                pending_insert.push_str(value);
                cursor += char_count;
            }
        }
    }

    flush_insert(&mut ops, &mut pending_insert, insert_pos);
    flush_delete(&mut ops, &mut delete_len, cursor);

    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Apply ops left-to-right to `old` using a `Vec<char>` splice model,
    /// mirroring how the storage layer consumes char-offset ops.
    fn apply(old: &str, ops: &[TextOp]) -> String {
        let mut chars: Vec<char> = old.chars().collect();
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

    /// Assert the ops reproduce `new` from `old` under the splice model.
    fn assert_roundtrip(old: &str, new: &str) -> Vec<TextOp> {
        let ops = diff_to_ops(old, new);
        assert_eq!(apply(old, &ops), new, "roundtrip failed: {old:?} -> {new:?}");
        ops
    }

    #[test]
    fn no_op_is_empty() {
        assert!(diff_to_ops("abc", "abc").is_empty());
        assert!(diff_to_ops("", "").is_empty());
    }

    #[test]
    fn pure_append() {
        let ops = assert_roundtrip("abc", "abcXY");
        assert_eq!(
            ops,
            vec![TextOp::Insert {
                pos: 3,
                s: "XY".to_string()
            }]
        );
    }

    #[test]
    fn pure_prefix_insert() {
        let ops = assert_roundtrip("abc", "XYabc");
        assert_eq!(
            ops,
            vec![TextOp::Insert {
                pos: 0,
                s: "XY".to_string()
            }]
        );
    }

    #[test]
    fn pure_mid_insert() {
        let ops = assert_roundtrip("abc", "aXYbc");
        assert_eq!(
            ops,
            vec![TextOp::Insert {
                pos: 1,
                s: "XY".to_string()
            }]
        );
    }

    #[test]
    fn whole_delete() {
        let ops = assert_roundtrip("abc", "");
        assert_eq!(ops, vec![TextOp::Delete { pos: 0, len: 3 }]);
    }

    #[test]
    fn partial_delete_suffix() {
        let ops = assert_roundtrip("abcde", "abc");
        assert_eq!(ops, vec![TextOp::Delete { pos: 3, len: 2 }]);
    }

    #[test]
    fn partial_delete_prefix() {
        let ops = assert_roundtrip("abcde", "cde");
        assert_eq!(ops, vec![TextOp::Delete { pos: 0, len: 2 }]);
    }

    #[test]
    fn mid_string_delete() {
        let ops = assert_roundtrip("abcde", "ade");
        assert_eq!(ops, vec![TextOp::Delete { pos: 1, len: 2 }]);
    }

    #[test]
    fn replace_in_middle() {
        // "abcde" -> "aXYe": delete "bcd", insert "XY".
        assert_roundtrip("abcde", "aXYe");
    }

    #[test]
    fn multibyte_append_accent() {
        // "é" is a single char; the inserted "s" must land at char pos 4.
        let ops = assert_roundtrip("café", "cafés");
        assert_eq!(
            ops,
            vec![TextOp::Insert {
                pos: 4,
                s: "s".to_string()
            }]
        );
    }

    #[test]
    fn multibyte_emoji_replace() {
        // "a🌍b" -> "a🌏b": the emoji counts as ONE char position.
        let ops = assert_roundtrip("a🌍b", "a🌏b");
        // Whatever the exact op shape, the emoji sits at char position 1.
        for op in &ops {
            match op {
                TextOp::Insert { pos, .. } => assert!(*pos <= 2),
                TextOp::Delete { pos, len } => {
                    assert_eq!(*pos, 1);
                    assert_eq!(*len, 1);
                }
            }
        }
    }

    #[test]
    fn coarse_fallback_above_threshold_round_trips() {
        // A4: with a tiny injected threshold, a pair that exceeds it takes the
        // coarse path (whole-container replace) and still round-trips exactly.
        let old = "hello world";
        let new = "goodbye world!";
        let ops = diff_to_ops_bounded(old, new, 3);
        // Coarse shape: delete-all then insert-all.
        assert_eq!(
            ops,
            vec![
                TextOp::Delete {
                    pos: 0,
                    len: old.chars().count()
                },
                TextOp::Insert {
                    pos: 0,
                    s: new.to_string()
                },
            ]
        );
        assert_eq!(apply(old, &ops), new);
    }

    #[test]
    fn coarse_fallback_multibyte_uses_char_len_and_round_trips() {
        // The coarse delete length is in CHARS, not bytes, so multibyte content
        // still round-trips under the splice model.
        let old = "café 世界";
        let new = "🚀 nouveau";
        let ops = diff_to_ops_bounded(old, new, 2);
        assert_eq!(ops[0], TextOp::Delete { pos: 0, len: old.chars().count() });
        assert_eq!(apply(old, &ops), new);
    }

    #[test]
    fn below_threshold_uses_precise_diff() {
        // A4: small inputs stay on the precise `similar` path — a single-char
        // append is exactly one minimal insert, NOT a whole-container replace.
        let ops = diff_to_ops_bounded("abc", "abcd", DIFF_MAX_CHARS);
        assert_eq!(
            ops,
            vec![TextOp::Insert {
                pos: 3,
                s: "d".to_string()
            }]
        );
        // And it equals the public entry point at the same (default) threshold.
        assert_eq!(diff_to_ops("abc", "abcd"), ops);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn prop_roundtrip_ascii(old in "[a-e]{0,12}", new in "[a-e]{0,12}") {
            prop_assert_eq!(apply(&old, &diff_to_ops(&old, &new)), new);
        }

        #[test]
        fn prop_roundtrip_unicode(
            old in "[a-c\u{00e9}\u{1F30D}\u{1F30F}\u{6f22}]{0,10}",
            new in "[a-c\u{00e9}\u{1F30D}\u{1F30F}\u{6f22}]{0,10}",
        ) {
            prop_assert_eq!(apply(&old, &diff_to_ops(&old, &new)), new);
        }

        #[test]
        fn prop_roundtrip_arbitrary(old in ".*", new in ".*") {
            prop_assert_eq!(apply(&old, &diff_to_ops(&old, &new)), new);
        }
    }
}
