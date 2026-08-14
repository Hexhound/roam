---
name: roam-sync-overview
description: Read FIRST whenever a feature involves syncing a user's data across their own devices, offline-first / local-first storage, end-to-end encrypted sync, "works with no internet", peer-to-peer data sync, conflict-free multi-device editing, a folder that mirrors between devices like Dropbox but private, pairing a second device, or replacing a cloud database with something the server cannot read. Decides whether roam-sync fits, then routes to roam-embed-rust, roam-cli, roam-wasm-browser, or roam-lan-share. Also states plainly what roam does NOT do yet (sharing with other people, granular per-folder permissions) so it is not proposed for the wrong job.
---

# roam-sync: what it is, and when to reach for it

roam-sync is a **domain-agnostic sync kernel**. It moves opaque documents between
the devices of **one owner**, end-to-end encrypted, with no server that can read
them. It knows nothing about notes, Markdown, medical records or calendars — an
app supplies meaning, roam supplies convergence.

Repo: `Hexhound/roam` (Rust workspace, `crates/`).

## Decide first: is this actually roam-shaped?

roam **fits** when all of these hold:

- The data belongs to **one person** who has **several devices**.
- Every device should hold a **full local copy** and keep working offline.
- The server (if any) must be **unable to read** the data.
- Concurrent edits on two devices must **merge**, not clobber.

roam is the **wrong tool** when:

| Requirement | Why roam is wrong | Use instead |
|---|---|---|
| Share a folder with **another person** | Not built. See `docs/sharing_and_subvaults_design_notes.md` — designed, deliberately unimplemented. | A normal backend, for now |
| Per-folder or per-file **permissions** | Roles are **vault-wide** (`Reader`/`Writer`/`Admin`). There is no sub-vault scoping yet. | — |
| Server-side **query / search / aggregation** | The server holds ciphertext under opaque ids. It cannot index anything. | A normal database |
| Multi-tenant app data, analytics, feeds | Not a general datastore. | A normal backend |
| A **browser-only** app with no backend | A browser cannot open QUIC, so it can only sync via the relay. No relay, no web sync. | Run the relay |

If the ask is "let users share with each other", say so plainly rather than
bending roam into it — the two-way sharing design exists but ships nothing today.

## The mental model (five facts that explain everything else)

1. **The op log is the truth.** Every device appends to its own ed25519-signed,
   append-only log. Files on disk, materialised documents and sidecars are all
   *rebuildable projections* of that log. Never treat the working folder as
   authoritative.
2. **Loro CRDT does the merging.** Text merges character-wise; the document set
   is a map/tree. Two devices that see the same ops reach byte-identical state,
   in any order. Conflicts are not resolved by a "last write wins" heuristic on
   text.
3. **A vault is one key.** A 32-byte vault key derives the content keys *and*
   the backend bucket id. Two devices holding the same key address the same
   data. Losing the key loses the vault; leaking it leaks the whole vault.
4. **Membership is a signed roster.** A device joins by being vouched for by an
   Admin during pairing. Its ops are rejected until that vouch folds in. Removal
   is `revoke` + an epoch rotation so the revoked device cannot read *future*
   writes.
5. **Two transports, same bytes.** P2P over iroh/QUIC (direct, hole-punched,
   relay-fallback) and/or a **zero-knowledge HTTP backend** that stores only
   ciphertext under opaque ids. The backend is an always-on fallback for "both
   devices are never online at once", not a source of truth.

## Which surface to use

| You are building | Surface | Skill |
|---|---|---|
| A native app (desktop, CLI, daemon) in **Rust** | the crates directly | `roam-embed-rust` |
| An app in **another language**, or a script / prototype / manual test | the `roam` binary | `roam-cli` |
| A **browser / web** client | `roam-wasm` + the relay | `roam-wasm-browser` |
| **Send a file to a nearby device once** (no vault, no account) | `roam-share-iroh` | `roam-lan-share` |

Note the last row is a *different feature*: sharing is not syncing. It has no
vault, no roster, no CRDT and no epoch key, and deliberately depends on none of
them.

## The crates

| Crate | Purpose |
|---|---|
| `roam-crdt` | Loro wrapper — `Document`, `Frontier`, `Version`. The only crate that touches `loro`. |
| `roam-storage` | The core. `Store`, op-log persistence, identity, roster, epoch keys, snapshots, checkpoints, `VaultFs` seam. |
| `roam-files` | Filesystem bridge — `FolderBridge` maps a real folder onto the CRDT (import/project/scan/rename/delete/restore). |
| `roam-sync-core` | `Transport` trait + the `Engine` that runs delta sync. |
| `roam-transport-iroh` | iroh/QUIC transport, LAN discovery (mDNS), token pairing and six-digit LAN pairing. |
| `roam-backend-client` | Encrypt/decrypt boundary + RBSR reconciliation against the zero-knowledge HTTP store. |
| `roam-rbsr` | Range-based set reconciliation (what makes "which ops are you missing" cheap). |
| `roam-pake` | SPAKE2 — turns a six-digit code into a session key without ever putting the code on the wire. |
| `roam-share` / `roam-share-iroh` | One-shot nearby sharing: payload model + safe filenames / the QUIC wiring. |
| `roam-wasm` | Browser façade over `roam-crdt` and a whole `Vault`. |
| `roam-cli` | The `roam` binary. Also the best worked reference for embedding. |

## Onboarding a second device (the flow every app needs)

Every roam app has to answer "how does device 2 get in". Three options, in order
of how much you should prefer them:

1. **Six-digit LAN pairing** — device 1 shows a code, device 2 types it. Uses
   SPAKE2, so the code never crosses the wire and cannot be brute-forced
   offline. Three wrong guesses retire the code. Best UX; needs both devices on
   one network, briefly.
2. **Pairing token** — a full-entropy token moved out of band (QR, paste). Works
   over the internet. Safe to display, but it *is* the credential.
3. **Vault key transfer** — only for "same person, controlled channel". Never in
   a URL fragment, never in `localStorage`.

Both pairing flows end the same way: the host vouches for the joiner in the
roster, and the joiner receives the vault.

## Non-negotiables when building on roam

- **Never persist the vault key in `localStorage` or a URL.** It is the whole
  vault.
- **Never treat the projected folder as the source of truth.** Delete the folder,
  not the log, if you want to test recovery.
- **Do not assume the backend authenticates anything.** The bucket routes are
  unauthenticated by design; possession of the key is the authorisation. Anything
  mutable that a server holds must be signed.
- **Roles are enforced receiver-side.** A peer that ignores its own role is
  caught when its ops are imported, not when it writes them. Do not build UI that
  relies on a peer policing itself.
- **`SystemTime::now()` traps on wasm32.** Use `roam_storage::wallclock`.

## Reference docs in the repo

- `docs/security.md` — threat model and the three review passes.
- `docs/sharing_and_subvaults_design_notes.md` — why third-party sharing is not
  built, and what it would cost.
- `docs/wasm_localsend_handoff.md` — the wasm and LAN-share work, plus the QUIC
  liveness audit (a recurring bug class: one side blocked on a peer that is
  never coming).
