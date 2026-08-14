---
name: roam-cli
description: Drive the `roam` command-line binary — create a vault, pair a second device (six-digit LAN code or token), sync a real folder between devices, inspect roster/status, rotate keys, recover with a paper key, browse and restore file history, checkpoint to reclaim disk. Use when integrating roam from a non-Rust language via a subprocess, scripting or automating roam, prototyping the flow before embedding the library, reproducing a sync bug by hand, or when the user names a roam command (init, pair-lan, join-lan, sync, status, rotate, recover, checkpoint, restore, history, grant, revert). Read roam-sync-overview first if it is not yet clear that roam fits.
---

# Driving the `roam` CLI

`crates/roam-cli` builds the `roam` binary. It is both a real tool and the best
worked reference for embedding the library — every command is a short function
in `crates/roam-cli/src/main.rs` that calls the same public API a host app would.

Build: `cargo build -p roam-cli --release` → `target/release/roam`.

> In this repo, always build with `CARGO_BUILD_JOBS=1 ... -j1` — parallel builds
> exhaust memory and disk.

## The two files every command needs

Nearly every subcommand takes `--vault <dir>` and `--identity <keyfile>`.

- **`--vault`** is the store directory: op logs, roster, key log, snapshots,
  sidecars, blob markers. This is the source of truth. Back *this* up.
- **`--identity`** is this device's ed25519 keyfile. One per device. Two devices
  must never share one, or their logs collide.

Note that the *synced folder* (`--folder`) is separate from the vault dir on
purpose: roam's internal metadata is kept out of the user's folder.

## Getting started: one device

```bash
roam init --vault ./vault --identity ./id.key            # founds a vault, prints the peer id
roam sync --vault ./vault --identity ./id.key --folder ~/Notes
```

`init` takes `--role` (default `admin`). The founder must be `admin` — it has to
be able to vouch for the devices that join later.

`sync` runs until Ctrl-C. It connects to every active roster peer and syncs the
folder live in both directions: create, edit, delete, rename. Add
`--backend <url>` to also push/pull ciphertext through the zero-knowledge relay,
which is what makes sync work when the two devices are never online together.

Without `--folder`, `sync` drops into a legacy interactive note REPL (kept for
backward compatibility) — pass `--folder` for anything real.

**How files are classified: by content, not extension.** Any UTF-8 file (any
extension, or none) syncs as a mergeable text document. Any non-UTF-8 file syncs
as a whole-file binary blob, pulled on demand. Dotfiles and dot-dirs are ignored.

## Adding a second device

The joining device needs an identity but **must not** found a vault — its vault
arrives from the host during pairing. That is what `new-identity` is for.

```bash
# on device 2
roam new-identity --out ./id2.key
```

### Six-digit LAN code (preferred)

```bash
# device 1 — shows a code, waits for one join
roam pair-lan --vault ./vault --identity ./id.key --name "laptop"

# device 2 — types the code it can see on device 1's screen
roam join-lan --vault ./vault2 --identity ./id2.key --host <host-id> --code 123456
```

The code is proved with SPAKE2, so it never crosses the wire and cannot be
tested offline. **Three wrong guesses retire the code** — show a fresh one, do
not retry the same one. `--role` on `pair-lan` sets the role granted to the
joiner.

Find `<host-id>` with:

```bash
roam lan-peers --seconds 5     # passive browse; announces nothing itself
```

### Token pairing (works over the internet)

```bash
roam pair-token --vault ./vault --identity ./id.key      # prints a token, waits for one join
roam pair --vault ./vault2 --identity ./id2.key --token <token>
```

The token is full-entropy and is the credential — move it over a channel you
trust (QR, paste), not a public one.

## Inspecting

```bash
roam status --vault ./vault --identity ./id.key
```

Roster and document state. `--identity` is optional: the roster and documents
read back without it, but the key-rotation section needs the real identity to
open this device's key log and unwrap the epoch keys it holds.

```bash
roam set-name --vault ./vault --identity ./id.key "kitchen laptop"
```

Self-asserted, gossips with the roster. Useful so a pairing prompt can say
*which* device is asking.

## Membership and keys

```bash
roam grant --vault ./vault --identity ./id.key <peer-id> writer --key <base64-verifying-key>
```

Admin only. Roles are `reader | writer | admin`, and **vault-wide** — there is no
per-folder scoping. `--key` is required because the grant binds the role to the
peer-id ↔ key pair, not to the id alone.

```bash
roam rotate --vault ./vault --identity ./id.key --generate-paper
roam recover --vault ./vault --identity ./id.key --paper "<the exact phrase>"
```

`rotate` mints a fresh epoch key wrapped to every *active* member, so a revoked
device can never read anything written afterwards. **Existing backend data is
not re-encrypted** — rotation protects future writes, it does not retroactively
lock the past. `--generate-paper` prints a recovery phrase (or pass your own with
`--paper`); `recover` uses that phrase to regain read access to rotated epochs
on a device that joined late or after every key-holding device was lost. Recovery
is local — it re-wraps the recovered keys to this device.

## History, restore, disk

```bash
roam history --vault ./vault --identity ./id.key
```

Retained markers (time points) plus files currently deleted that `restore` can
bring back.

```bash
roam restore --vault ./vault --identity ./id.key --folder ~/Notes            # every deleted file
roam restore --vault ./vault --identity ./id.key --folder ~/Notes a.md b.md  # just these
```

```bash
roam text-history --vault ./vault --identity ./id.key --folder ~/Notes note.md
roam revert      --vault ./vault --identity ./id.key --folder ~/Notes note.md --to 3
```

`text-history` lists versions newest-first with an index; `--to` takes that index.

```bash
roam checkpoint --vault ./vault --identity ./id.key --before latest --dry-run
```

Reclaims space: shallow-snapshot at the newest point at or before `--before`
(`latest` or epoch-millis), truncate op logs to the retained tail, drop blobs
unreferenced in the retained range. `--dry-run` reports bytes and changes
nothing. **Local only, and it destroys history** — run the dry run first.

> Known interaction: a local checkpoint fights backend RBSR sync. Do not
> checkpoint a vault that syncs through `--backend`.

## One-shot sharing (not sync)

```bash
roam share ./file.pdf ./folder --from "my laptop"
roam receive --from <sender-id> --code 123456 --into ./inbox
```

This does **not** touch a vault. It runs under a throwaway identity, and nothing
about the files — not even their names — crosses the wire before the receiver
proves the six-digit code. See the `roam-lan-share` skill.

## Debugging

Set `ROAM_DEBUG=1` for `[engine]` and `[transport]` traces on stderr. It costs one
env lookup when off.

## Calling the CLI from another language

This is a legitimate integration path — no FFI, no Rust in the host app.

- `sync` is **long-running**: spawn it, keep it alive, and stop it with SIGINT
  (not SIGKILL) so it closes its QUIC connections. Killing it hard leaves every
  peer holding a dead connection until a ~30s idle timeout.
- Pairing commands **wait for exactly one join** and then exit. Treat them as a
  request/response with a human in the middle, and give them a timeout.
- Parse stdout for the ids and codes these commands print; there is no
  `--json` flag today, so if you need one, add it rather than scraping loosely.
