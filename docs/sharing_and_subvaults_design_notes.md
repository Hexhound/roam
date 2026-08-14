# Design notes: folder sharing and sub-vault permissions

**Status: DISCUSSION ONLY — nothing here is implemented, and no decision is
final.** Written 2026-08-14 from a design conversation. This supersedes the
short F1 sketch in `wasm_localsend_handoff.md:559`, which assumed a share model
we have since rejected.

Read this before starting F1 or any share-link work. Two conclusions here reverse
assumptions baked into the older doc, and one of them removes a dependency the
roadmap was sequenced around.

---

## 1. What exists today

Three facts define the problem space. All three are load-bearing.

1. **One key per vault.** `vault_key` derives exactly two subkeys — a stable id
   key and an AEAD key (`crates/roam-storage/src/vault_key.rs:24`). Epochs rotate
   the AEAD key, but there is exactly one live key at a time, wrapped to every
   device. **Any roster member can decrypt everything in the vault.**
2. **One document.** `Store` holds a single `Document` (one `LoroDoc`); all
   content lives in it as path-keyed containers. Per-peer op-logs are the truth,
   the doc is derived by replay.
3. **Vault-wide roles, enforced receiver-side.** `Role::{Reader, Writer, Admin}`
   is a single value per peer (`roster.rs:124`), and enforcement is honest peers
   refusing to import — see the Reader-drop in `Store::import_peer`
   (`store.rs:1234`).

There is nowhere for a scoped grant to attach, no way to ask what containers an
op touched, and no key that unlocks less than the whole vault.

## 2. The distinction that governs everything

"Granular permissions" is **two features** with very different costs. Conflating
them is the main way this goes wrong.

**Write-scoping** is a *policy* question — "may Bob's ops touch `personal/`?" It
can be enforced by honest replicas rejecting ops, exactly like the existing
Reader-drop. Bob still *sees* `personal/`; he just can't change it, and if he
tries, nobody accepts it.

**Read-hiding** is a *cryptographic* question — "can Bob decrypt `personal/`?"
No receiver-side policy helps, because Bob holds the vault key. If he can obtain
the ciphertext he can read it. The only enforcement is not giving him the key,
which means `personal/` must be encrypted under a key he lacks, which means it is
a separate cryptographic domain, which cascades into nearly every subsystem.

Write-scoping is a contained slice. Read-hiding is a re-architecture.

---

## 3. Write-scoping (the old "Phase A") — still viable, unchanged

Scope primitive = path prefix on the container id, which is already a
vault-relative path (`roam-files/src/path.rs:41`). No new naming layer:
`prescriptions/` is literally a prefix of `prescriptions/2026/jan.md`.

### The changes

**Scope on the grant.** `RosterOp::Add`/`SetRole` (`roster.rs:24`) gain
`scope: Vec<String>`; `canonical_bytes` moves to a `roam.roster.v4` tag with the
scope inside the signed bytes. v3 entries fold to empty scope = unrestricted, so
existing vaults keep working.

> *Example:* `roam add-peer --role writer --scope prescriptions/ --scope notes/`.
> The restriction is covered by the admin's signature, so it cannot be stripped
> in transit.

*Risk:* the usual signing-domain hazard — if any path signs v4 and verifies v3,
grants silently stop verifying and devices fall out of the roster. Needs a test
that both encodings coexist in one log.

**Folding scope through `merge_roster`** (`roster.rs:137`). Scope must ride with
the winning role op, not fold separately, or role and scope come from different
decisions.

> *Example of the trap:* admin A grants `Writer{scope: notes/}` at lamport 4;
> admin B grants `Writer{scope: prescriptions/}` at lamport 5. Union yields both
> prefixes — the opposite of B's intent. Correct rule: whichever grant wins the
> role fold supplies the scope, so Bob ends with `prescriptions/` only.

The existing full-tie rule is least privilege; the scope analogue is
**intersection, not union**. Write that down or someone will "fix" it later.

**`Document::containers_touched`** — a new `roam-crdt` function reporting which
containers an update blob modifies, without importing into the live doc.

**This is the riskiest unknown in the whole slice.** The existing authorship
check has the right shape — probe doc, inspect, reject before touching real state
(`doc.rs:186`) — but note what it handles: `status.pending`. Ops whose
dependencies are missing don't apply; they buffer. For *authorship* that's fine,
the peer id is in the pending metadata. For *containers* it may not be.

> *Example of the failure:* Bob writes `notes/a.md` then `personal/secret.md`. We
> receive only the second (the first is still in flight). It lands pending. If
> `containers_touched` returns "unknown" for pending ops, we either reject a
> legitimate op or accept an illegitimate one — and "unknown means reject" turns
> ordinary out-of-order sync into spurious rejections.

**Answer this against real Loro before writing anything else.** If containers are
not reliably attributable while pending, the enforcement point moves out of
`import_peer` to wherever ops actually apply, and the design changes shape.

**Enforcement in `import_peer`.** Same fail-closed pattern as the Reader-drop.
But op-logs import whole: `import_peer` verifies every entry, writes the whole
log file, and a no-shrink invariant guards truncation (`store.rs:1284`). Per-op
filtering breaks byte-prefix consistency across the fleet. So the choice is
**reject the entire log on the first out-of-scope op**.

> *Example of the cliff:* Bob is scoped to `notes/`. On Tuesday he touches
> `personal/` once — by accident, or because his roster copy hadn't yet received
> the scope change. From then on his log is permanently unimportable. Every
> legitimate note he writes afterward is invisible to everyone forever, because
> it sits behind the poisoned entry in the same log. No recovery short of a new
> identity.

Options: accept it, and have the CLI refuse out-of-scope local writes hard so it
only fires on genuine misbehaviour; or add a per-log quarantine offset (import
the prefix up to the bad entry, record the offset, keep no-shrink relative to
it) — more code, no permanent loss. **Decide before building.**

**Local authoring guard.** `Store::may_write` becomes scope-aware so a restricted
device refuses out-of-scope edits locally instead of writing ops nobody accepts.
Cheap, and it keeps the cliff from firing on honest users.

### Write-scoping's honest guarantee

Scope lives in the roster and the roster propagates asynchronously, so two honest
peers can disagree about whether an op is admissible.

> *Example:* Alice has the entry restricting Bob; Carol doesn't yet. Bob writes to
> `personal/`. Carol accepts it; Alice rejects Bob's whole log. Carol's doc now
> contains an op Alice's never will — and if Carol (as an Admin) later publishes a
> checkpoint snapshot, it launders Bob's op into adopted state past Alice's
> rejection. Same shape as the snapshot-adoption bypass we already found and fixed
> once.

So this is **eventually consistent enforcement**, not a hard boundary — the same
guarantee the Reader-drop already gives. Document it that way; do not sell it as
"Bob cannot write there."

---

## 4. Sharing: three designs, and why we changed our mind twice

### The requirements (from the product side)

- Sharing must be **backend-mediated, not P2P.** A third-party recipient opening
  a share when the sharing device happens to be online is unusable. P2P sharing
  only makes sense when both ends belong to the same person.
- A share is a **folder**, and it is **live**: file additions, edits, and removals
  inside it must be reflected, like Dropbox/OneDrive.
- It should be shareable **as reader or as writer** — i.e. **two-way**.

### Design A — sealed snapshot (REJECTED)

Export a subtree, encrypt under a fresh key, put the key in a URL fragment.

**Rejected:** point-in-time. It doesn't reflect later changes, so it isn't a
folder share — it's an attachment with extra steps.

### Design B — projection / mirror (REJECTED, but instructive)

The folder stays in the main vault under the vault key; a device additionally
maintains an encrypted mirror in a separate bucket under a separate share key.
The recipient is anonymous — no identity, no roster, just a URL.

Useful findings from this design, which survive its rejection:

- **The backend already serves this for free.** `/b/:bucket/*` passes through the
  `:raw` pipeline only — no authentication whatsoever
  (`sync/lib/sync_web/router.ex:65`). An anonymous third party can already GET
  from a bucket if they know its id. The recipient path needs **zero new backend
  routes**.
- **Unauthenticated PUT is the flip side.** Blobs are content-addressed and
  first-write-wins, so they self-protect. A mutable manifest pointer does not —
  it must be signed, or a leaked link becomes a way to *write* to the recipient.
  Residual: rollback (serve an old manifest) is detectable only after a higher
  generation has been seen.
- **A manifest must be authoritative and complete** to express removal; a purely
  additive content-addressed scheme cannot say "this file is gone."
- **Share definitions should be vault state, not device state**, so any online
  device can keep the mirror fresh rather than only the device that created it.

**Rejected because it is one-way by construction.** An anonymous recipient cannot
author signed ops, so writer-mode is inexpressible. It also duplicates storage
(see §5).

### Design C — the shared folder is its own vault (CURRENT DIRECTION)

The folder lives in its own cryptographic domain, with its own key and its own
roster. Sharing = adding the recipient to that roster at Reader or Writer.

This collapses most of the invented machinery back onto things already built and
tested:

- **Roles already exist** — sharing "as reader or writer" is literally
  `Role::Reader` / `Role::Writer`, with the Reader-drop already enforcing it.
- **Revocation already exists** — removing one recipient is a roster `Revoke`
  plus an epoch rotation. Per-recipient, with one copy of the data.
- **Key distribution already exists** — the recipient receives epoch keys as
  keylog wraps (`keylog.rs`, `keywrap.rs`), like any other device.
- **No manifest format, no publisher loop, no projection.** All of it disappears.

Two variants:

- **C1 — separate vaults.** Works *today*, zero new code. Cost: your devices pair
  into each vault independently, and you manage N rosters.
- **C2 — true sub-vaults** (the old "Phase B"): main and shared domains share one
  roster and one device set. Nicer product; this is the bulk of the invasive work.

---

## 5. Storage: is duplication unavoidable? No.

The question was: if a 1 GB folder is shared, does the backend hold 2 GB (and 3 GB
for a second share)?

**In Design B, yes** — and that is a fair criticism of it. Copies scale with the
number of *independently revocable grants*, not with recipients: handing the same
link to five people costs one copy; you pay again only to revoke one recipient
without affecting the others.

**In Design C, no.** There is exactly one copy, because the folder *lives* in the
shared vault. The main vault holds none of it.

### How Dropbox/OneDrive actually do it

They don't copy. Files are stored encrypted at rest with **provider-held keys**,
so the server can decrypt and re-serve the same bytes to anyone passing an ACL
check, with block-level dedup across the whole service. That works because the
server is a trusted party that can make authorization decisions about plaintext.

We can't do that — the backend is deliberately zero-knowledge. But duplication is
**not** the price of E2EE. Proton Drive, Tresorit and Cryptomator all use
**per-folder keys wrapped to each recipient's public key**: one copy of the
ciphertext, a small wrapped key per recipient, access managed by managing wraps.

That is exactly what `keywrap.rs` already does (sealed-box wrap of a 32-byte key
to an X25519 recipient) and what `keylog.rs` already distributes with signatures
and epoch rotation. Built for vault epoch keys; same primitive.

**Duplication is the price of sharing-by-copy, not of encryption.**

---

## 6. One home per file — do NOT dual-write

A tempting model is that main and shared vaults both contain the folder, and an
edit generates an op in each. **Avoid this.** Two vaults holding the same file
means two independent CRDT histories under different keys with no merge path.

> *Example:* you edit `recipes/bread.md` offline. The op lands in the shared
> vault's log but the main vault's write fails (disk full, process killed). The
> two vaults now disagree permanently — they're different documents, and nothing
> reconciles them. Worse, a recipient later edits the same file in the shared
> vault; there is no operation that merges that back.

Correct shape: the folder lives in **exactly one** vault — the shared one — and
the main vault does not contain it. What links them is the *filesystem view*:
`roam-files` materializes `~/roam/notes/` from the main vault and
`~/roam/notes/recipes/` from the shared vault, so it looks like one tree on disk.
One op, one history, one key. This is what the original F1 note meant by
"partition, NOT duplication."

**Cost:** moving an *existing* folder into a shared vault is a re-key, and its
edit history does not come along — it lives in the main vault's op-log under the
main vault's key. Users will experience this as "my version history vanished when
I shared this folder." Folders created shared from the start have no such problem,
which argues for making "share" an early decision, or for a blunt warning.

---

## 7. The hard problem two-way introduces: offline admission

Reading is fine while the sharer is offline — the backend serves ciphertext
regardless. **Joining is not.** A roster entry must be signed by an admin, and an
admin is one of the sharer's devices.

> *Example:* you send the link Friday evening and close the laptop. Bob clicks it
> Saturday. His browser mints a keypair — but nobody can sign a roster entry
> admitting it, so he decrypts nothing until one of your devices returns.

Two ways out:

- **Accept an online moment.** Bob's join request sits pending; your device admits
  him on next sync. Simple, no new crypto, and it doubles as an approval step
  (arguably a feature). Cost: the share isn't instant.
- **Pre-authorized bearer grant.** Sign an invitation granting a role to *whoever
  proves possession of this token*. Bob redeems it by posting his public key with
  a proof; the signed token plus his bound self-add becomes a roster entry every
  device can verify offline.

The bearer grant is a **genuine extension to the trust model**: `merge_roster`
currently requires every grant to name a concrete `subject_key` and validates that
the peer id derives from it (`roster.rs:137`). Bearer grants break that assumption
and need their own fold rules and security analysis. Not enormous — the F2 token
flow has bearer semantics to borrow — but it deserves the same scrutiny the roster
fold has already had.

---

## 8. Which of the six apps need this

The six: Obsidian clone, Caremate medical journal, RPG helper, Dropbox alt,
LocalSend alt, org-mode calendar. No per-app requirements are recorded anywhere;
the following is inference from the app concepts.

**Core product:**
- **Dropbox alt** — sharing a folder with a third party at reader or writer *is*
  the app.
- **RPG helper** — inherently multi-user with asymmetric visibility. Players are
  third parties, not your devices, and a GM whose private notes are player-readable
  has no game. Needs both sharing *and* hiding-from-members.

**Real but secondary:**
- **Caremate** — sharing with a doctor or caregiver, plausibly writer if a
  caregiver logs entries; wants the doctor to see prescriptions but not the
  personal journal.
- **org-mode calendar** — a shared family calendar is a two-way writer share. The
  app works without it; it's noticeably better with it.

**Marginal:**
- **Obsidian clone** — mostly personal and multi-device, already handled. "Publish
  a note" is plausible but nothing is blocked without it.

**Explicitly not:**
- **LocalSend alt** — `wasm_localsend_handoff.md:275`: "needs NONE of the vault /
  roster / CRDT". Ephemeral LAN device-to-device transfer, already shipped as F2.
  Different feature; the backend-hosted share must not absorb it.

**Key observation:** the two apps needing hiding-from-members (RPG helper,
Caremate) are both satisfiable with **separate vaults** — GM-notes vault plus
campaign vault; prescriptions vault plus journal vault. **None of the six requires
sub-vaults for correctness.** What C2 buys is ergonomics: one roster, one device
set, one pairing, instead of N. RPG helper is where that bites hardest — a GM
juggling several visibility domains, asking every player to pair into each
separately.

---

## 9. What changed versus the older doc

1. **Share links are not blocked on read-scoping.** `wasm_localsend_handoff.md`
   states in several places that the M3 share-link half depends on F1 read-scoping
   (lines 127, 260, 264, 607). That was based on the sealed-fragment model. Under
   Design C a share is a vault and the recipient is a member, so the dependency is
   on the *invitation flow*, not on partitioning a document.
2. **"Sub-vault permissions" and "sharing" are not the same feature.** Sharing is
   satisfiable today with separate vaults (C1). Sub-vaults (C2) are an ergonomics
   improvement on top. The roadmap previously treated them as one item.
3. **Read-hiding lost its headline justification.** Its main stated purpose was
   unblocking share links. What remains is vault members who shouldn't see
   everything — real, but narrower, and covered by separate vaults with a strictly
   stronger guarantee.

---

## 10. Open questions, in the order they need answering

1. **C1 or C2 — separate vaults or true sub-vaults?** C1 ships against existing
   machinery and would tell us whether two-roster ergonomics are actually painful
   before we spend C2's complexity budget on a problem we've only assumed.
2. **Online admission or bearer grants?** Decides whether the invitation flow is a
   weekend or a reviewed addition to the trust model.
3. **Can Loro attribute containers on a *pending* update?** Blocks all of
   write-scoping; worth an afternoon probe against real Loro before any test is
   written.
4. **Whole-log rejection or quarantine offset?** A product decision about an
   availability cliff, and it determines how much of `import_peer` changes.
5. **Should "may publish / may share" be its own permission?** Under any
   backend-hosted share model, publishing is the only operation that moves data
   outside the vault's trust boundary. Today a **Reader** — explicitly trusted not
   to modify anything — could expose an entire vault via a link. That is an
   exfiltration channel that fits in a text message, and it is a stronger argument
   for scoped grants than anything in the original F1 sketch.

## 11. Suggested sequencing (not decided)

Nothing here is on the critical path for any shipped feature, and no app is
blocked. When it is picked up:

1. Answer Q3 (Loro pending-container probe) — cheap, and it can invalidate a
   design.
2. C1 sharing with online admission — shippable against existing roster, roles,
   epochs and keywrap; validates the product shape.
3. Write-scoping as its own slice, with "may publish" designed in from the start
   rather than bolted on.
4. Revisit C2 only if C1's multi-roster ergonomics prove genuinely painful in use.

## References

- `crates/roam-storage/src/roster.rs` — `Role` (13), `RosterOp` (24),
  `PeerRecord` (118), `merge_roster` (137)
- `crates/roam-storage/src/store.rs` — `import_peer` + Reader-drop (1234),
  no-shrink invariant (1284)
- `crates/roam-storage/src/vault_key.rs:24` — `vault_subkeys`
- `crates/roam-storage/src/keywrap.rs`, `keylog.rs` — per-recipient key wrapping
- `crates/roam-crdt/src/doc.rs:186` — `import_authored_by`, the probe pattern
- `crates/roam-backend-client/src/crypto.rs:37` — `bucket_id` derivation
- `sync/lib/sync_web/router.ex:65` — `/b/:bucket/*` is unauthenticated
- `docs/wasm_localsend_handoff.md:559` — the superseded F1 sketch
