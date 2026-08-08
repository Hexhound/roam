# roam-sync

Domain-agnostic **sync kernel** — the reusable core of the [roam](../roam-docs) ecosystem. Syncs a set of documents between a user's own devices, peer-to-peer, end-to-end encrypted, with **no central server storing data**. Knows nothing about notes, Markdown, or Org — it moves opaque documents, so it can be reused by other apps (e.g. medical-data sync, an Emacs org-calendar sync app).

**Open source** (open-core: the sync layer is open; roam's app/backend/paid features are closed).

## Design

- **CRDT:** [Loro](https://github.com/loro-dev/loro) — text CRDT over document content + a small map/tree for the document set.
- **Source of truth:** op-log-is-truth. Files, materialized documents, and sidecars are all rebuildable projections of a per-device append-only, ed25519-signed op log.
- **Transport:** a trait; default impl is [iroh](https://github.com/n0-computer/iroh) (QUIC, key-addressed, hole-punch + relay fallback, E2E TLS 1.3). Encrypted-backend and file transports slot in beside it.
- **Conflicts:** version vectors detect; Loro merges; full op-log history is the no-data-loss safety net.

## Crates (Cargo workspace)

| Crate | Purpose |
|---|---|
| `roam-crdt` | Loro document + op model |
| `roam-storage` | op-log persistence, per-actor append files, snapshots, identity, signed ops |
| `roam-sync-core` | transport trait + delta / vector-clock sync |
| `roam-transport-iroh` | iroh implementation of the transport trait |

> Stub — implementation lands via the Slice-1 plan. See the spec in `roam-docs`.

## Correctness

Proven headless by Rust unit + property tests (random op orderings converge to identical state). No app required.
