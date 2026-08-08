# roam-cli

A manual harness (`roam`) for driving roam-sync over real iroh. It is an
operator tool, not a product surface — use it to pair two vaults and watch them
converge by hand. The automated two-endpoint check lives in
`crates/roam-transport-iroh/tests/e2e.rs`.

## Commands

- `roam init --vault <dir> --identity <keyfile>` — generate an identity + vault
  id, print the peer id.
- `roam pair-token --vault <dir> --identity <keyfile>` — print a base64 pairing
  token, then wait for one join with a `y/N` approval prompt.
- `roam pair --vault <dir> --identity <keyfile> --token <token>` — join a vault
  using a token.
- `roam sync --vault <dir> --identity <keyfile>` — connect to every active
  roster peer and run the sync loop until Ctrl-C.
- `roam status --vault <dir>` — print the roster and document status
  (read-only).

The identity keyfile MUST live OUTSIDE the vault directory (a duplicated
identity means two devices share a peer id and silently lose data).

## Manual two-vault smoke test

Open two terminals. `A` hosts and approves; `B` joins.

```sh
# --- terminal A (host) ---
roam init  --vault /tmp/roam-a --identity /tmp/id-a.key
# note A's peer_id from the output.
roam pair-token --vault /tmp/roam-a --identity /tmp/id-a.key
# copy the printed token, then leave this waiting at the y/N prompt.

# --- terminal B (joiner) ---
roam init --vault /tmp/roam-b --identity /tmp/id-b.key
roam pair --vault /tmp/roam-b --identity /tmp/id-b.key --token <PASTE_TOKEN>
# prints "paired with host peer: <A peer_id>".

# --- back in terminal A ---
# answer `y` at the prompt; it prints "paired peer: <B peer_id>".

# --- now sync both (each in its own terminal) ---
roam sync --vault /tmp/roam-a --identity /tmp/id-a.key
roam sync --vault /tmp/roam-b --identity /tmp/id-b.key
# both print "connected to peer <n>" and a periodic "note len=<n> bytes".

# --- inspect either vault ---
roam status --vault /tmp/roam-a
```

Both vaults should list each other as `active` peers and, once edits flow,
report the same `note` length.
