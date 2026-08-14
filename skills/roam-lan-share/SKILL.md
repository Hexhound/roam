---
name: roam-lan-share
description: One-shot nearby sharing over the LAN, LocalSend/AirDrop-style — send files, folders, text, clipboard or a contact card to a device across the room, authenticated by a six-digit code, with no account, no vault and no server. Covers roam-share (payload model, attacker-supplied filename safety) and roam-share-iroh (the QUIC wiring, SPAKE2 handshake, offer/accept/decline flow, timeouts) plus mDNS LAN discovery. Use when asked to send a file to a nearby device, transfer between phones or laptops on one network, build an AirDrop-like or LocalSend-like feature, or find devices on the local network. This is NOT sync — for multi-device sync read roam-sync-overview instead.
---

# One-shot LAN sharing

**Sharing is not syncing.** There is no vault, no roster, no CRDT and no epoch
key here, and `roam-share` deliberately depends on none of them. A share is a
single transfer between two devices that may never meet again.

If the ask is "keep these devices in step", this is the wrong skill — read
`roam-sync-overview`.

Two crates:

- **`roam-share`** — *what* is transferred. Payload model, wire frames, and
  filenames that are safe to write after a **stranger** chose them.
- **`roam-share-iroh`** — *who may*, and the QUIC stream. The PAKE handshake and
  the offer/accept flow.

## The flow

```
  Receiver                                Sender
  --------                                ------
  dial + open bi ──── PakeMsg1 ─────────▶  costs nothing
                 ◀─── PakeMsg2 ─────────
  ─────────────────── Confirm ──────────▶  verify; a WRONG one spends an
                                           attempt, else drop the connection
                 ◀─── Confirm ──────────
  ============ everything below is sealed under the PAKE key =============
                 ◀─── Offer ────────────   what is on offer
  ─── Accept{streams} | Decline ────────▶   the human's decision
                 ◀─── Chunk … Done ─────
```

**Nothing is offered before the code is proved — a wrong code learns not even
the filenames.** Preserve that ordering in anything you build on top; showing a
file list before the handshake completes silently removes the whole guarantee.

Roles map onto the PAKE exactly: the **sender** holds the files, shows the code
and is the PAKE *responder* (it owns the attempt budget); the **receiver** types
the code and dials, so it is the *initiator*. The side that displays the secret
is the side that must be able to say "you have guessed too many times".

## Sending

```rust
use roam_share_iroh::{bind_share_endpoint, offer_paths, ShareSender};

let endpoint = bind_share_endpoint().await?;
let (offer, sources) = offer_paths("my laptop", &paths)?;
let (sender, code) = ShareSender::new(endpoint, offer, sources);

println!("code: {code}");        // show these six digits to the human
sender.serve_one().await?;       // serves exactly one successful transfer
```

`serve_one` keeps listening across failed attempts: a wrong code, a stall or a
malformed frame drops **that one connection** and leaves the sender available.
Only a successful transfer, or an exhausted attempt budget, ends it.

`with_handshake_timeout` overrides the bound on reads from an unproven peer.

## Receiving

```rust
use roam_share_iroh::{receive_share, receive_share_with, ReceiveTimeouts};

let received = receive_share(&endpoint, sender_addr, &code, dest, |offer| {
    // Called AFTER the code is proved and BEFORE any bytes move.
    // Show the human what is coming. Return false to decline.
    prompt_user(offer)
}).await?;

received.files;   // Vec<PathBuf>, in offer order
received.texts;   // inline Text / Clipboard payloads, which are never files
```

`receive_share_with` takes explicit `ReceiveTimeouts` — a test seam, so proving a
silent sender is survivable does not mean sitting out the production bound.

Two separate bounds, because the phases differ:

- `handshake` (default 10s) — reads from a peer that has proved nothing.
- `data` (default 30s) — **per frame**, not per transfer, so a legitimately slow
  link is never mistaken for a stall and a large download is never cut off as
  long as it keeps moving.

**Declining is an answer, not a disconnect.** The receiver sends `Decline` and
then waits for the sender's `Done` acknowledging it, so the sender sees a refusal
rather than a bare "connection lost".

## Discovery

```rust
use roam_transport_iroh::discovery::{browse_lan, LanDiscovery, advertise_name};

let peers = browse_lan(Duration::from_secs(5)).await?;   // passive: announces nothing
let discovery = LanDiscovery::attach(&endpoint, /* advertise */ true)?;
```

`browse_lan` is deliberately passive — browsing must not make the browsing device
visible. `attach(.., advertise: false)` is the same choice at the endpoint level.

## Security properties, and how to not break them

Everything the receiver gets comes from a peer that has proved exactly one thing:
that it knows six digits. Sizes, names and chunk offsets are all
attacker-controlled and are treated that way.

- **Filenames are validated by newtype construction** — `SafeName` / `RelPath`
  enforce on `Deserialize` too, or the wire would bypass validation.
  `RelPath::resolve_under(dest)` cannot escape `dest` by construction. Do not
  build a path from raw offer strings.
- **The declared length is a contract.** The receiver holds each stream to the
  length the offer declared, with overflow-safe arithmetic, so an accepted
  transfer cannot flood past what the user approved.
- **`DEFAULT_MAX_ACCEPT_BYTES` (8 GiB)** bounds the *claimed* total before
  anything is accepted.
- **A guess costs an attempt; starting a run does not.** Merely connecting and
  sending garbage must never spend the budget, or any device on the network
  retires the code with three junk packets. The budget is charged on a failed
  *confirmation*.
- **The sender runs under a throwaway identity.** A share must not be able to
  touch a vault, and the crate cannot: it does not depend on `roam-storage` or
  `roam-sync-core`.

## Known gaps — do not claim these are handled

- **The receiver buffers the whole transfer in RAM** (up to
  `DEFAULT_MAX_ACCEPT_BYTES`). Streaming to disk is not implemented; it changes
  how partial transfers are cleaned up.
- **There is no integrity check on received content.** The offer declares lengths
  but no hashes, so a sender that sends `Done` early leaves zero-filled gaps that
  get written out as file content. Fixing it is a wire-format change.

If a use case depends on either, say so rather than assuming.

## Liveness: the recurring bug class

Every bug this code has had was the same shape — **one side blocked on a peer
that was never coming.** When touching any path here, ask all three:

1. *Who tells the peer I am leaving?* Every exit path needs
   `endpoint.close().await`, unconditionally — not after a `?`, where only
   success reaches it.
2. *What bounds this read if the peer never speaks?* `open_bi` is lazy in QUIC,
   so an unbounded `accept_bi()` parks forever on a peer that connects and
   writes nothing.
3. *Who can end this session by any route?* An attempt budget, a fatal-error
   classification and an unflushed close are the same bug in different clothes.

Sweep **both directions** of the protocol, not just the one a bug report named —
the sender was fixed once while the receiver stayed unbounded, and the crate
looked swept. These never fail in library tests where both sides share a process;
test across two real processes and assert timing, not just correctness.

## CLI equivalent

```bash
roam share ./file.pdf ./folder --from "my laptop"
roam receive --from <sender-id> --code 123456 --into ./inbox
roam lan-peers --seconds 5
```
