# roam-sync

Domain-agnostic **sync kernel** — the reusable core of the roam ecosystem. Syncs a set of documents between a user's own devices, end-to-end encrypted, peer-to-peer and/or through a backend that never sees plaintext. Knows nothing about notes, Markdown or Org — it moves opaque documents, so it can be reused by other apps (e.g. medical-data sync, an Emacs org-calendar sync app).

**Open source** (open-core: the sync layer is open; roam's app/backend/paid features are closed).

## Design

- **CRDT:** [Loro](https://github.com/loro-dev/loro) — text CRDT over document content + a small map/tree for the document set.
- **Source of truth:** op-log-is-truth. Files, materialized documents and sidecars are all rebuildable projections of a per-device append-only, ed25519-signed op log.
- **Transport:** a trait. The default impl is [iroh](https://github.com/n0-computer/iroh) (QUIC, key-addressed, hole-punch + relay fallback, E2E TLS 1.3). A zero-knowledge HTTP backend slots in beside it as an always-on fallback for when two devices are never online together.
- **Conflicts:** version vectors detect; Loro merges; the full op-log history is the no-data-loss safety net.
- **Membership:** a signed roster. A device joins by being vouched for by an Admin during pairing; roles (`Reader`/`Writer`/`Admin`) are vault-wide and enforced receiver-side, on import.
- **Revocation:** `revoke` plus an epoch rotation, so a removed device cannot read anything written afterwards. Rotation protects the future — existing data is not re-encrypted.

## Crates (Cargo workspace)

| Crate | Purpose |
|---|---|
| `roam-crdt` | Loro document + op model — the only crate that depends on `loro` |
| `roam-storage` | op-log persistence, identity, signed ops, roster, epoch keys, snapshots, checkpoints, the `VaultFs` seam |
| `roam-files` | maps a real folder onto the CRDT — import, project, scan, rename, delete, restore |
| `roam-sync-core` | transport trait + the delta / vector-clock sync engine |
| `roam-transport-iroh` | iroh implementation of the transport trait, mDNS LAN discovery, device pairing |
| `roam-backend-client` | encrypt/decrypt boundary + RBSR sync against the zero-knowledge HTTP store |
| `roam-rbsr` | range-based set reconciliation |
| `roam-pake` | SPAKE2 — proves a six-digit code without putting it on the wire |
| `roam-share` / `roam-share-iroh` | one-shot nearby sharing (not sync): payload model + QUIC wiring |
| `roam-wasm` | browser façade — a whole vault, syncing through the relay |
| `roam-cli` | the `roam` binary; also the worked reference for embedding |

## Features

- **Folder sync** — a real directory mirrored live between devices: create, edit, delete, rename. Files are classified by *content*, not extension: UTF-8 syncs as a mergeable text document, everything else as a whole-file blob fetched on demand.
- **Device pairing** — a six-digit LAN code (SPAKE2; three wrong guesses retire it) or a full-entropy token that works over the internet.
- **History** — per-file version history, revert, restore of deleted files, and `checkpoint` to reclaim disk by compacting retained history.
- **Key rotation and paper recovery** — rotate epochs, wrap to active members, recover with a printed phrase.
- **Nearby sharing** — LocalSend-style one-shot transfer to a device across the room. No vault, no account, no server.
- **Browser client** — a vault in wasm, syncing through the relay. (A browser cannot open QUIC, so it is a relay leaf, never a P2P peer.)

## Not built

Sharing a folder **with another person**, and per-folder/per-file permissions. Both are designed and deliberately unimplemented — see `docs/sharing_and_subvaults_design_notes.md` for the design and what it would cost.

## Getting started

```bash
cargo build -p roam-cli --release

roam init --vault ./vault --identity ./id.key
roam sync --vault ./vault --identity ./id.key --folder ~/Notes
```

Adding a second device, inspecting state, rotating keys and the rest: see `skills/roam-cli/SKILL.md`.

## Correctness

Proven headless by Rust unit + property tests (random op orderings converge to identical state). No app required. Liveness — the recurring "blocked on a peer that is never coming" class — is covered by cross-process tests; see the audit section of `docs/wasm_localsend_handoff.md`.

Set `ROAM_DEBUG=1` for `[engine]` and `[transport]` traces on stderr.

## Docs

- `docs/security.md` — threat model and review passes.
- `docs/sharing_and_subvaults_design_notes.md` — third-party sharing and sub-vaults: the design, and why it is not built.
- `docs/wasm_localsend_handoff.md` — the wasm and LAN-share work, plus the QUIC liveness audit.

## Agent skills

`skills/` ships this repo as a Claude Code plugin (`roam-dev`), so an agent working in *another* project knows how to build on roam: `roam-sync-overview` (does roam fit, and which surface), `roam-embed-rust`, `roam-cli`, `roam-wasm-browser`, `roam-lan-share`.
