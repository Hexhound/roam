# Security notes

Living record of accepted risks. Fixed findings live in the git history
(security-review commit chain, most recently `ad44250`); this file tracks only
what was reviewed and deliberately **not** fixed.

## WONTFIX

### keyless-Rotate head-poison (admin-only availability DoS)

**Where:** `crates/roam-storage/src/keychain.rs` — `select_head` / `head_write_key`.

**What.** Epoch selection picks the write-head from the epoch DAG's leaves. A
`Rotate` parented on the current head turns that head into a non-leaf, so the
new epoch becomes the sole leaf and therefore the head. If a malicious **Admin**
mints such a `Rotate` but wraps the new epoch key **only to itself** (or to
nobody), every other member's `head_write_key()` returns `None`: they see a head
whose key they cannot unwrap, and — per H1 — must fail closed rather than fall
back to the old key. The vault goes write-only for the attacker.

**Why WONTFIX.**

1. **Admin-only.** The Rotate fold (N5) accepts only Admin-authored rotations. A
   non-admin cannot trigger this.
2. **Inherent admin power.** An Admin can cause the identical outage the
   legitimate way — perform a *real* rotation and wrap the key only to itself.
   You cannot remove rotation authority from Admins without removing rotation.
3. **Recoverable.** Any honest Admin rotates again, parenting on the poison
   epoch. That supersedes it and writes resume. No data is lost.
4. **The obvious fix reopens H1 (confidentiality).** "Refuse to treat an epoch
   as head unless you hold its key" would make an honest but lagging member (key
   Wrap not yet delivered) fall back to the old head and seal writes under the
   old key — which a just-revoked member still holds. That leaks new writes to a
   removed member: a confidentiality break, strictly worse than a recoverable,
   admin-only availability glitch.

**Accepted risk.** Trading a recoverable admin-only DoS for a confidentiality
regression is a bad trade. Left as-is.

**If ever revisited.** Not a local patch. Requires a consensus-layer change —
epoch ratification / quorum on head selection so peers reject an unratified head
without the confidentiality fallback. Scope as its own project.
