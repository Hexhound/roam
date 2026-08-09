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
# both print "connected to peer <n>", then drop into the interactive REPL.
# type a line in either terminal; it appears under "--- note ---" in the other.

# --- inspect either vault ---
roam status --vault /tmp/roam-a
```

Both vaults should list each other as `active` peers and, once edits flow,
report the same `note` length.

## Cross-network live sync demo

The same flow works across NATs/networks — the two machines never need to be on
the same LAN or exchange IP addresses.

```sh
# machine 1
roam init --vault ./vault1 --identity ./id1.key
roam pair-token --vault ./vault1 --identity ./id1.key   # prints a token, waits for approval
# (paste token to machine 2, then type y here once it joins)

# machine 2 (different network)
roam init --vault ./vault2 --identity ./id2.key
roam pair --vault ./vault2 --identity ./id2.key --token <PASTE_TOKEN>

# both machines
roam sync --vault ./vaultN --identity ./idN.key
# now type lines on either machine; they appear under "--- note ---" on the other
```

How it works across networks: the pairing token carries the host's relay
address, its iroh NodeId, the vault id, and a one-time pairing secret. After
pairing, `sync` only knows the peer by NodeId — it configures *no* IP
addresses. iroh's n0 discovery (n0 DNS/pkarr) plus the relay resolve the NodeId
and hole-punch (or fall back to relaying) a connection, so two machines behind
different NATs converge without any manual address exchange or port forwarding.

The REPL is interactive: each line you type is appended to a shared `note` text
container and live-pushed to connected peers; a 500ms poll reprints the whole
note under a `--- note ---` separator whenever it changes (yours or the peer's
edits). Showing the entire note is a demo convenience — there is no file bridge
yet (`roam-files` is a later slice), so this exercises the sync engine directly
rather than mirroring real files on disk.
