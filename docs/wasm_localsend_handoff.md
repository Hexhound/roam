# Handoff: WASM web client (F3) + LocalSend share (F2)

Load this in the **roam-sync devenv** to continue. Work was scoped in the funsy
devenv; moving here so wasm toolchain + JS e2e infra live in roam's own devenv.

## Decision context

Goal: make roam-sync back six apps (Obsidian clone, Caremate medical journal,
RPG helper, Dropbox alt, LocalSend alt, org-mode calendar). Three roam-CORE
features were planned. User picked build order:

1. **WASM web client (F3)** — do first, cheapest, de-risks loro-on-wasm.
2. **LocalSend share (F2)** — do second, self-contained.
3. **Sub-vault granular permissions (F1)** — discuss later, most involved.

All work is **TDD** (Iron Law: failing test first, watch it fail for the right
reason, minimal code to green). No git writes — user commits/adds/pushes
themselves. Check `git status` before staging; never `add -A`.

## Environment setup needed in this devenv (was the blocker in funsy)

- wasm32 std IS available with the nix rustc (confirmed:
  `rustc --print sysroot`/lib/rustlib has `wasm32-unknown-unknown`).
- MISSING and needed here: `wasm-bindgen-cli`, `wasm-pack` (or
  `wasm-bindgen-test-runner`), and `nodejs` for the JS "client" e2e.
- Add these to the roam devenv (devenv.nix/flake `packages` + a rust wasm
  toolchain). Then `cargo build --target wasm32-unknown-unknown` works offline.
- Build constraints carried from before: roam-sync builds OOM / fill disk under
  parallelism — always `CARGO_BUILD_JOBS=1 ... -j1`, `TMPDIR=$PWD/target/tmp`.
  Funsy disk was at 98% (3.1G free, 26G target); that pressure is why we moved.

## STATUS (updated 2026-08-13, in the roam devenv)

Env setup **DONE** and the M1 probe is **GREEN** — details below; the rest of
this section is kept for historical context.

- devenv now provides `wasm-bindgen-cli` (PINNED 0.2.126), `wasm-pack` 0.15.0,
  `nodejs` 24.18.1 (`.nix/devenv.nix`). devkit input bumped
  `bedb73b` → `1b004ae`.
- **M1 GATE PASSED.** `cargo check -p roam-crdt --target wasm32-unknown-unknown`
  → `Finished dev profile in 1m10s`, exit 0, zero warnings. loro 1.13.9 and its
  whole tree (loro-internal, loro-kv-store, loro-delta, generic-btree,
  loro_fractional_index, …) compile to wasm32 unmodified.
- **No getrandom shim needed.** getrandom 0.2.17 IS in the wasm32 tree, but its
  `js` feature is already enabled transitively (it pulls js-sys/wasm-bindgen),
  which is why it builds. The feared `getrandom = { features=["js"] }` shim is
  NOT required. Re-check this if the dep graph changes — without `js`, getrandom
  0.2 hard-fails to compile on wasm32-unknown-unknown.
- **M1 IMPLEMENTED AND GREEN.** `crates/roam-wasm` exists; JS↔native CRDT
  interop proven in BOTH directions against committed fixture bytes:
  `tests/fixtures/native_snapshot.loro` (Rust-written, JS-read) and
  `js_snapshot.loro` (wasm-written, Rust-read), plus a merge check that imports
  both into one doc and asserts neither side's content is lost. 3 native tests +
  4 JS checks. Run the JS half with `crates/roam-wasm/tests/js/run.sh`.
  - Crate layout: `Doc` (plain Rust, `CrdtError`, natively tested) + `bindings`
    (`#[wasm_bindgen]`, wasm32-only, pure delegation). wasm-bindgen is a
    target-gated dep, so a native build CANNOT pull it in — the handoff's
    "don't drag wasm-bindgen into the CLI" concern is now structural, not a
    convention.
  - JS gotcha: `peerId` is a `u64`, so JS must pass a **BigInt** (`new Doc(42n)`).
- **`lld` is required and was missing.** The nix rustc bundles NO `rust-lld`
  (sysroot has only `rust-lldb`, a debugger), so linking a wasm32 cdylib dies
  with "linker `lld` not found". `cargo check` does NOT catch this — there is no
  link step — so the M1 probe passed while the real build was still broken.
  `pkgs.lld` added to the devenv.
- **Version-pin trap found (would have bitten at first wasm-bindgen use).**
  wasm-bindgen glue is schema-versioned: the CLI rejects a .wasm built against a
  different crate version. The tree resolved to wasm-bindgen 0.2.127, but
  nixpkgs has NO 0.2.127 (versioned attrs stop at 0.2.126; the unversioned attr
  is 0.2.121). Resolution: pin the crate DOWN to `=0.2.126` in
  `[workspace.dependencies]` and use `pkgs.wasm-bindgen-cli_0_2_126`. Verified
  this backtracks js-sys 0.3.104 → 0.3.103 (js-sys pins wasm-bindgen exactly)
  and wasm-bindgen-test → 0.3.76. **Bump the nix package and all three crate
  pins together, never independently.**

## FIRST probe (was about to run when we switched devenv)

The true unknown for the whole web thesis: **does `loro` compile to wasm32?**
Run this BEFORE writing any crate (exploration, not production — no TDD gate):

```
cd /home/sezdocs/projects/roam/roam-sync && mkdir -p target/tmp && \
CARGO_BUILD_JOBS=1 TMPDIR=$PWD/target/tmp \
  cargo check -p roam-crdt --target wasm32-unknown-unknown -j1
```

If loro pulls `getrandom` without the `js` feature, or `mio`/native-only deps,
this fails — that failure mode IS the M1 finding. roam-crdt itself uses ZERO
randomness (`Document::new(peer_id)` takes the id as an arg), so any getrandom
need comes from loro internals; fix is a `getrandom = { features=["js"] }` shim
or a wasm-only dep tweak in the new wasm crate.

## Feature 3 — WASM web client, three milestones (TDD)

roam-crdt + roam-rbsr are portable now. Plan:

**M1 (cheap, no keys, DO FIRST).** New crate `crates/roam-wasm` (cdylib) —
NOT `wasm-bindgen` on roam-crdt directly (would drag wasm-bindgen into the
native CLI build). Thin wasm-bindgen façade over `roam-crdt/src/doc.rs`
`Document` (API surface confirmed this session: `new(peer_id)`, `insert_text`,
`delete_text`, `text`, `set_entry`/`get_entry`/`entries`/`remove_entry`,
`commit`, `snapshot`, `export_from`/`import`, `version`/`Version::to_bytes`).
Goal: prove **JS↔native CRDT interop** via committed fixture bytes AND prove
loro builds for wasm32.

TDD shape for M1:
- Native test (cheap, run first): a `Document`, insert text, `snapshot()` →
  write bytes as a committed fixture file under `crates/roam-wasm/tests/fixtures/`.
- JS test (wasm-bindgen-test or a node harness added to e2e): load fixture
  bytes, `import`, assert `text(id)` == expected. Reverse direction too (wasm
  produces a snapshot, a native test imports it and asserts equal). This is the
  "javascript client in our e2e tests" the user asked for.

**M2 (riskiest).** Extract a `VaultFs` trait in roam-storage. All persistence is
hardcoded `std::fs` today, no trait; sites: oplog / keylog / history / blob /
founder / snapshot / roster + `truncate_leading_lines` (store.rs:1841).
`NativeFs` must be **byte-identical** to today; browser impl = IndexedDB/OPFS.
Pure refactor → write characterization / golden-byte tests FIRST (all ~150
storage tests must stay green), one module per commit.

**M3 — DONE for transport; see the "M3 status" section below.** Original plan:
Browser transport via the backend relay (the `Backend` trait is already
the seam, `roam-backend-client/src/transport.rs:33`; drop rustls-tls, use
`fetch`) + `roam-sync-core` drop `tokio` `rt-multi-thread`. SECURITY: keys are
XSS-exposed in a browser — OPFS + session-derive, never persist the root secret.
The "client is a web link" share URL fragment must carry ONLY a reader-scoped
share key, never `vault_key`/identity — **M3 DEPENDS ON F1 read-scoping** so a
leaked link ≠ whole-vault compromise. (So M3 waits until after F1.)

## M2 status — `VaultFs` extraction (IN PROGRESS)

Safety net and trait are in place; migration is module-by-module, full test run
green after each. `crates/roam-storage/src/vfs.rs` holds the trait, `NativeFs`,
and `MemFs`.

**Two decisions worth not re-litigating:**

1. **The trait is SYNCHRONOUS, and that constrains M3.** IndexedDB is async-only,
   so an IndexedDB backend would force `async fn` through every persistence call
   and up through `Store` — a huge change for an IO detail. OPFS instead offers
   *synchronous* access handles (`createSyncAccessHandle`) available **only
   inside a Web Worker**. Keeping the trait sync + running roam in a worker is
   the cheap path and the proven one (SQLite's official wasm build does exactly
   this). Consequence: **the browser client cannot run roam on the main thread.**
2. **`append` and `append_sync` are separate methods.** The op-log did
   `write_all` + `sync_all` + a parent-directory fsync on create. Routing it
   through a plain `append` would have silently dropped durability on the
   source-of-truth log, and *no test can observe that*. Hence a distinct method
   with the guarantee in its name, rather than a flag.

**Safety net (written FIRST, `tests/fs_characterization.rs`).** The ~150 existing
tests all go through the `Store` API and would stay green through a moved file,
a dropped `0600`, or a lost atomic rename. So these assert the filesystem
directly: golden layout (`tests/golden/vault_layout.txt`, regen with
`ROAM_REGEN_GOLDEN=1`), no surviving `.tmp`/`.part`, identity key is `0600`,
and reopen-only-appends (byte-prefix invariant). Verified the golden actually
fails on drift — a net that cannot fail is worthless.

**Conformance suite.** One `conformance()` function in `vfs.rs` runs against both
`NativeFs` and `MemFs`. A browser backend must pass the same function; that is
how it gets validated without a browser.

**MIGRATION COMPLETE.** All ten modules are on `VaultFs` — `founder`,
`snapshot`, `history`, `history_util`, `oplog`, `identity`, `keylog`, `roster`,
`blob`, `store`. **Zero production `std::fs` remains in roam-storage outside
`NativeFs` itself** (verified by audit; remaining hits are test code that pokes
the real disk deliberately, e.g. corruption tests).

**Acceptance test — `tests/vault_on_memfs.rs`.** A complete vault lifecycle
(founder pin, op-log, roster, blob put/get, snapshot, history) runs on `MemFs`
at `/vault`, a path that exists on no disk, and **survives a reopen** from the
same backend. Every other test would still pass if `VaultFs` secretly reached
for `std::fs`; this one cannot. It also asserts the expected paths appear in the
backend, no `.tmp` debris is left, and two backends at the same root stay
isolated. **Swap `MemFs` for OPFS and this is the browser's acceptance test.**

**Pattern used throughout.** Public API preserved: `X::new(..)` keeps working on
`NativeFs`, with `X::new_with_fs(.., Arc<dyn VaultFs>)` beside it. `Store` holds
`fs: Arc<dyn VaultFs>` (NOT a `Store<F>` type parameter — that would ripple
through every caller for no gain) and passes it down. Entry point for a browser:
`Store::open_with_fs(root, identity, fs)`.

**Trait surface** (evidence-based, from an audit of every call site — not
guessed): `read`, `read_range`, `write`, `append`, `append_sync`, `create_sized`,
`write_range`, `create_dir_all`, `rename`, `remove_file`, `read_dir`,
`file_len`, `exists`, `is_dir`, `set_owner_only`, plus a provided
`read_to_string`. Deliberately no "open file handle" method — handing out `File`
objects would not port; the one streaming need (chunked blob transfer) is
`read_range`, and out-of-order chunk receipt is `create_sized` + `write_range`,
both of which map directly onto OPFS sync access handles.

**One `MemFs` bug the tests caught, worth knowing when writing the OPFS
backend:** permissions must follow a file across `rename` (they live on the inode
natively). The identity secret is published by write-tmp → chmod → rename, so a
backend that drops the flag on rename silently publishes a world-readable secret
key.

### What M2 does NOT cover

`roam-storage` is clean, but other crates still touch the disk directly
(audited, production code only, test code excluded):

- **`roam-files` — 18 sites.** This is the real remaining blocker for a browser
  client that syncs a folder. It is also arguably the *right* place to stop:
  a browser has no folder to mirror, so the OPFS client may simply not use
  `roam-files` rather than port it. Decide that before porting anything.
- **`roam-cli` — 11 sites.** Native-only by definition; no need to port.
- `roam-sync-core`, `roam-backend-client`, `roam-transport-iroh`, `roam-crdt`,
  `roam-rbsr` — **0 sites**, already portable.

So the vault core is done; what remains is a product question (does the web
client mirror a folder?) rather than a mechanical one.

## M3 status — browser transport (TRANSPORT DONE, share-link deliberately NOT)

A wasm vault syncs end-to-end through the relay over `fetch`, proven in a JS
runtime. `crates/roam-wasm` now exposes `Vault` (storage on `VaultFs`, sync via
`Backend`) alongside the M1 `Doc`.

**Four findings worth not rediscovering:**

1. **`SystemTime::now()` TRAPS on wasm32** — `RuntimeError: unreachable`, not a
   wrong value. Confirmed empirically. `cargo check` cannot see it, and neither
   could the first version of the JS harness, because the only call sites are in
   `Store::write_snapshot` (history marker) and snapshot production. All
   wall-clock reads now go through `roam_storage::wallclock::now_ms`
   (`Date.now()` on wasm32). The harness gained a `writeSnapshot` check
   *specifically* to cover this — verified by reintroducing the trap and
   watching it fail. Do not delete that check.
2. **`reqwest` needs no replacement.** On wasm32 reqwest 0.12.28 compiles to a
   `fetch` client with no TLS stack, and its fallback path is a bare global
   `fetch(request)` — so it works in a Window, in a **Web Worker** (which is
   where M2 requires roam to run), and in node. `HttpBackend` is unchanged and
   is now the browser's backend too: ONE implementation, not two.
3. **`tokio`'s `rt-multi-thread` cannot be a workspace default.** tokio
   hard-errors on wasm32 for any feature outside `sync,macros,io-util,rt,time`,
   and a workspace default leaks into every crate. Workspace tokio is now
   `["rt","macros","sync","time"]`; roam-cli and dev-deps opt in themselves.
4. **`Backend`'s `Send` bound is cfg'd, not removed.** A fetch backend holds JS
   values, so its futures are irreducibly `!Send`. Native builds keep the full
   `Send + Sync` guarantee via the `MaybeSendSync` supertrait; only wasm relaxes
   it. This is sound ONLY because `Backend` is always used as `B: Backend`
   (supertrait bounds elaborate for type parameters) and never as `dyn Backend`
   (auto traits do NOT leak onto a trait object through a named supertrait). If
   a `dyn Backend` ever appears, spell out `dyn Backend + Send + Sync` there.

**Tests.** `crates/roam-wasm/tests/vault_sync.rs` (3 native, against
`MemoryBackend`) holds the logic; `tests/js/sync.mjs` (6 checks, run by
`tests/js/run.sh`) proves real HTTP in a real JS runtime. Every assertion in both
was mutation-checked. The JS relay is `TestRelay`, a `#[wasm_bindgen]` wrapper
over the already-tested `MemoryBackend`, behind the `test-relay` cargo feature so
the shipped artifact cannot contain it — writing a JS negentropy server would
have meant debugging the harness instead of the client. The real Elixir backend
stays covered by `roam-backend-client/tests/e2e_backend.rs`; the two are
complementary.

### What M3 deliberately does NOT include

- **No share link, and no key persistence.** The URL-fragment share flow still
  depends on **F1 read-scoping**: without a reader-scoped key there is nothing to
  put in a fragment except the vault key, and a leaked link would be a
  whole-vault compromise. `Vault` therefore exposes no link helper, and the
  binding's doc comment says why. Unchanged from the original plan — this was
  always gated on F1.
- **Storage is `MemFs`, so a browser vault dies with the tab.** Durability needs
  an OPFS `VaultFs`. Note one thing M2 did not have to face: `VaultFs: Send +
  Sync`, and OPFS sync access handles are JS values. Either wrap them (sound on
  wasm32 — no threads) or cfg the bound as `Backend` now does. `Vault::open`
  already takes the backend as an argument so the swap is one line.
- **No `roam-files`**, so no folder mirroring in the browser (18 fs sites,
  still a product question — see "What M2 does NOT cover").

## Feature 2 — LocalSend share (share, NOT sync)

LocalSend is a **share** app, not sync — needs NONE of the vault / roster / CRDT
/ epoch stack. Three independent parts (split from the original plan):

- **(a) LAN discovery.** iroh 1.0.3 `presets::N0` = pkarr/DNS/relay only, **NO
  mDNS** (the `endpoint.rs:19` comment claiming mDNS is WRONG;
  `iroh-mdns-address-lookup` is not even a dep). Add `iroh-mdns-address-lookup`
  + a `lan_peers()` browser (swarm-discovery) + a roam UserData marker (new
  `discovery.rs`). iroh `AddressLookup` is resolve-on-dial only (no enumeration).
- **(b) Ephemeral code-authenticated blob send.** A typed payload frame:
  `{kind: File | Folder | Clipboard | Text | Contact, ...}`. Folder = manifest +
  chunked blob stream (reuse existing chunked blob transfer + FolderBridge path
  model). Text/clipboard/contact = small inline payloads. New kinds later = one
  enum variant. No vault touched.
- (c) Full LAN pairing-INTO-a-vault is the SEPARATE F2-pairing concern for the
  sync apps — see security note below. NOT needed for LocalSend share.

**SECURITY — REVIEWED 2026-08-14. The review changed the conclusion; read this
before acting on the older text.**

The previous note claimed the current `sign(code)` scheme was UNSAFE because a
6-digit code is ~20 bits. **That premise is wrong: there is no 6-digit code
anywhere in roam.** `pairing.rs` mints its secret with `VaultId::generate()`,
which is 32 bytes straight from `OsRng` — 256 bits, not 20. Grepping the whole
workspace finds no short-code path at all. The cited lines (401/504) are the
sign/verify of that 256-bit secret.

Consequences for the three specific claims:

- **"Unbounded guessing oracle" (the non-consuming retry loop, now ~line 330).**
  The loop is real, but against a 256-bit secret it is not an oracle worth the
  name. It is also *deliberate* and documented as P2 anti-DoS: a hostile peer
  connecting first with a garbage proof must not burn the single-use secret and
  force the user to restart. Adding the recommended "bounded per-session attempt
  budget" would **reintroduce that DoS**. Do not do it while the secret is
  full-entropy.
- **"No NodeId binding = same-LAN MITM".** MITM is already prevented by iroh:
  the joiner dials `token.addr`, and QUIC/TLS authenticates the remote against
  that `EndpointId`, so an interceptor cannot impersonate the host without its
  private key.
- **A real gap was found, and fixed.** A token made two *independent* identity
  claims — `addr.id` (authenticated by QUIC) and `verifying_key` (trusted to
  authenticate the host's key-log) — and nothing required them to be the same
  device. `PairingToken::check_host_identity_is_consistent` now binds them,
  checked before the joiner dials so a mismatched token never even receives its
  proof-of-secret. This does not close the bearer model (whoever can swap the
  whole token can mint a self-consistent one); it removes a confusion.

**A PAKE was therefore NOT implemented.** Rewriting proven, security-critical
pairing code and adding a crypto dependency to fix a misdiagnosed weakness would
have been a net loss in safety.

**Where a PAKE genuinely IS required — an open decision for F2(b).** The ~20-bit
argument becomes correct the moment a *human-typed short code* exists. So the
choice for LocalSend's ephemeral send is a product one:

- **QR / copy-paste of a full-entropy secret** (what pairing does today): reuse
  the existing, tested model. No PAKE, no new crypto dependency.
- **A short typed code** (classic LocalSend UX): then the original advice
  applies in full — CPace/SPAKE2 keyed by the code, a NodeId-bound
  key-confirmation MAC, and a bounded attempt budget (safe here, because with a
  low-entropy code the guessing risk outweighs the DoS risk).

Pick the UX first; the crypto follows from it. Do not ship a short code with
bare `sign(code)` — that part of the original warning stands.

### DECIDED 2026-08-14: QR for internet pairing, short typed code for LAN

Both are implemented.

**Internet → QR of the existing full-entropy token.** No new crypto: the token
was always a 256-bit bearer secret, and a QR is just a second way to carry the
same base64. `roam pair-token` now prints one (`qrcode`, `default-features =
false` — the default `image` feature pulls in the whole image crate).

Two things that were measured rather than assumed:

- A realistic worst-case token (4 direct addresses + a relay URL) is **~740
  bytes**, a comfortable QR at EC level L. `pairing.rs` has a test holding it
  under 1200 bytes, because a field added to `PairingToken` without thought
  would otherwise degrade the QR silently — the failure mode is "scanning just
  doesn't work", which nobody would trace back to a struct change.
- That renders **85 columns wide**, which *wraps in an 80-column terminal* and
  destroys the code while still looking like a QR. The CLI now prints the
  required width alongside it.

**LAN → 6-digit code over SPAKE2**, in the new `crates/roam-pake` (no roam
dependencies, so it is unit-testable with no network and reusable by both LAN
pairing and LocalSend share). All three legs of the original advice are there:
SPAKE2 so a run leaks nothing about the code, both endpoint ids bound into the
SPAKE2 identities (this is what closes same-LAN MITM), and a 3-attempt budget.

The two non-obvious parts:

- **An attempt is spent when a run STARTS, not when it fails.** Counting
  failures would let an attacker guess forever by disconnecting as soon as they
  learned the guess was wrong. There is a test for exactly this.
- **This deliberately reverses the P2 anti-DoS trade** made for token pairing.
  With a 256-bit secret, refusing to consume the session on failure is right;
  with 20 bits it is not, and an attacker being able to burn the budget and
  force a fresh code is the correct cost.

Caveat recorded in the crate docs: `spake2` (RustCrypto/PAKEs) is **not
independently audited**. It is the best-maintained Rust option and what
magic-wormhole uses, but the composition was kept deliberately standard so
nothing bespoke is doing security work.

### F2(b) COMPLETE — the share is on the wire

`crates/roam-share-iroh` puts `roam-share`'s frames on a QUIC stream under
`roam/share/1`, authenticated by `roam-pake`. It depends on `roam-share`,
`roam-pake` and `iroh` — **not** on `roam-storage` or `roam-sync-core`, so a
share structurally cannot touch a vault.

Roles map onto the PAKE exactly: the **sender** holds the files and shows the
code (PAKE responder, owns the attempt budget), the **receiver** dials (PAKE
initiator). The side displaying the secret is the side that must be able to say
"too many guesses".

Nothing is revealed before the code is proved — not even filenames. There are
two tests for that, and the weaker one was not enough: asserting the receiver's
*callback* never fired passes even if the sender puts the offer on the wire,
because a hostile peer does not run our callback. The real test speaks the
protocol by hand with a wrong code and asserts no emitted byte contains the
filename. Verified by making the sender leak the offer early: the raw test
fails, the callback test does not.

**Two real bugs the tests caught**, both in shutdown rather than crypto:

1. Declining dropped the connection with the `Decline` frame still unflushed, so
   the sender saw "connection lost" instead of an answer.
2. Fixing that naively made the receiver wait a **30-second idle timeout**:
   `serve_one` consumes the sender, so its `Endpoint` is dropped the moment it
   returns, often before a bare close is flushed — and with the endpoint gone
   nothing retransmits. The sender now acknowledges a decline with `Done` and
   the receiver closes in both paths, so shutdown no longer depends on drop
   ordering. Suite went 35s → 0.15s.

Also hardened along the way: `SessionKey` was single-use with a fixed nonce,
which a real stream would have broken catastrophically on the second message. It
now splits into per-direction keys with per-message counters, so replay,
reordering and reflection all fail to open. Sending symlinks is refused rather
than followed — otherwise "share this folder" could exfiltrate anything the
sender can read.

### F2(c) COMPLETE — LAN pairing into a vault with a typed code

`crates/roam-transport-iroh/src/pairing_lan.rs`, ALPN `roam/pair-lan/1`. The host
shows six digits; the joiner types them; the vault key, transitive roster,
key-log and founder pin travel over the SPAKE2 session key. Everything the token
flow delivers, with the bearer proof replaced by a PAKE.

Three things bind the exchange to the right devices:

1. the human reading the code off the intended screen,
2. the endpoint ids, bound into the SPAKE2 run as its identity strings,
3. **a check that the key a joiner claims equals the endpoint id iroh already
   authenticated.** Proving the code proves only that *this connection* knows six
   digits, not which long-term identity is behind it. Without (3), a joiner shown
   a legitimate code could enrol a third party's key into the host's roster. That
   is `a_joiner_cannot_enrol_a_key_that_is_not_its_own`, mutation-verified.

Deliberately unlike the token flow, the accept loop is **bounded in attempts**.
The token flow's loop is unbounded on purpose (P2: a hostile first connection
must not burn a 256-bit single-use secret). An unbounded loop around six digits
would be a brute-force oracle instead. Same code shape, opposite correct answer,
because the secret's entropy differs by 236 bits.

**No vault cross-check, and this is a real difference.** The token names the
vault out of band, so the joiner can catch a host that answers with a different
one. A code names nothing — the joiner learns the vault *from* the accept.
`LanJoined` therefore returns the vault id so a caller that knows which vault it
meant to join can check; this layer has nothing to check against.

### F2 CLI — `roam share` / `roam receive`, `roam pair-lan` / `roam join-lan`

`roam share <paths>` prints a device id and six digits and waits;
`roam receive --from <id> --code <digits> --into <dir>` shows the offer, asks,
and writes. `roam lan-peers` lists who is announcing. Covered end-to-end by
`crates/roam-cli/tests/share_cli_e2e.rs`, which runs two real processes and
passes nothing between them but those two printed lines.

Two privacy decisions live in the CLI layer:

* A share binds a **fresh random key** per run (`bind_share_endpoint`), so
  announcing it on mDNS does not broadcast a stable device identifier. Pairing
  cannot do this — it must use the device identity — so `pair-lan` advertises
  only while the code is up, and stops when the host drops.
* `browse_lan` (behind `roam lan-peers`) binds a throwaway endpoint and
  publishes nothing. Asking who is nearby costs the asker no privacy.

`pair-lan` deliberately has **no y/N prompt**, unlike `pair-token`: typing the
code is the approval, and a second confirmation would only train the user to
accept a dialog they did not read.

`roam new-identity --out <file>` exists because writing the CLI e2e for
`join-lan` surfaced a hole that also affected the pre-existing `pair`: a joiner
needs a device identity but must NOT found a vault, and `init` was the only way
to mint a key. It refuses to overwrite an existing keyfile — the key IS the
device identity on every roster it has been added to, and a fresh one silently
orphans it from all of them.

The LAN-facing tests (`lan_discovery.rs`, `share_cli_e2e.rs`,
`lan_pairing_cli_e2e.rs`) are `#[ignore]`d because they need real multicast;
they pass here with `--ignored`. `share_cli_e2e` runs in ~1s alone but has been
seen taking ~35s when the whole `--ignored` suite runs together — mDNS
resolution under contention, not a hang, but worth watching if it ever fails.

Still open: F1 (below), and the share-link half of M3, which depends on it.

## Feature 1 — Sub-vault granular permissions (LATER, for reference)

Scope primitive = path-prefix on the loro container-id string (container_id =
vault-relative NFC path, `roam-files/src/path.rs:41`), so `prescriptions/` is
literally a prefix; no new naming layer.

- **Phase A = WRITE-scoping, enforcement-only, no crypto.** Add
  `scope: Vec<String>` to `RosterOp::Add`/`SetRole` (roster.rs:24), sign in a new
  `roam.roster.v4` domain tag (v3 folds to empty=unrestricted, back-compat),
  fold into `PeerRecord` (roster.rs:118), enforce receiver-side in `import_peer`
  (store.rs:1220/1281) by dropping any author log touching an out-of-scope
  container — same fail-closed pattern as the existing Reader-drop. Needs a new
  `Document::containers_touched` in roam-crdt/doc.rs.
- **Phase B = READ-hiding = hard.** Per-domain epoch keys; internally splits the
  single LoroDoc toward one doc per domain (partition, NOT duplication — each
  container/op lives in exactly one domain; roster/keylog/founder are SHARED, one
  copy). Backend is a dumb encrypted store with no per-account auth (intentional),
  so restricting downloads needs separate buckets per domain. RISKIEST decision:
  op-logs import whole (byte-prefix / no-shrink invariant store.rs:1250) → must
  REJECT-WHOLE-LOG on first out-of-scope op (availability cliff) vs per-op filter
  (breaks invariant). Moving data between domains = re-key (expensive) — pick
  domain boundaries where data rarely crosses.

## On-disk layout (confirmed this session, store.rs:118-217)

One Store rooted at `<root>`: `ops/` (one OpLog per peer, keyed by peer_id — the
ops ARE the data, the LoroDoc is derived by replay), `roster/`, `snapshots/
snapshot.loro`, `assets/` (content-addressed blob bytes, beside the CRDT),
`history/history.jsonl`, `founder` file, keylog. ONE Document (LoroDoc) holds all
content as path-keyed loro containers.

## Existing e2e infra to extend (all green)

- `crates/roam-cli/tests/cli_operator_e2e.rs` — drives the real `roam` binary.
- `crates/roam-backend-client/tests/full_feature_e2e.rs` — `#[ignore]`, real
  Phoenix on PORT 4578; KV/text/blob/snapshot-bootstrap/rotate+revocation.
- `crates/roam-cli/tests/pairing_e2e.rs` — live iroh loopback pairing.
- `crates/roam-cli/tests/chunked_blob_e2e.rs` — multi-chunk blob over iroh.
- Add the JS/wasm client harness alongside these for F3 M1.

## Immediate next steps in this devenv

1. ~~Add wasm toolchain to the roam devenv.~~ **DONE** (see STATUS).
2. ~~Run the loro-wasm32 probe; record pass/fail.~~ **DONE — GREEN** (see STATUS).
3. ~~Scaffold `crates/roam-wasm`, TDD native fixture then JS interop.~~
   **DONE — M1 COMPLETE** (see STATUS).
4. ~~M2 — `VaultFs` extraction.~~ **DONE** (see "M2 status").
5. ~~M3 — browser transport.~~ **DONE for transport** (see "M3 status"); the
   share-link half remains gated on F1 read-scoping, as originally planned.
6. Next: F2 LocalSend parts (a)+(b), PAKE-first for the code auth. The other
   open threads are an OPFS `VaultFs` (durability in the browser) and F1.

Note on M3 (browser transport), confirmed by reading
`roam-backend-client/src/transport.rs`: the `Backend` trait is a clean
get/put/reconcile over *already-encrypted* bytes ("this layer never encrypts or
decrypts"), so a `fetch` implementation is a drop-in and keeps E2EE intact. But
a browser CANNOT be an iroh peer (no raw UDP/QUIC), so the web client is a
relay leaf, not a mesh peer — it always requires a running backend. The backend
does have a perimeter accounts/API-key layer (`sync/lib/sync/accounts/api_key.ex`);
the doc's "no per-account auth" note refers only to per-bucket scoping *inside*
a vault, which is still true and is what F1 Phase B has to solve.

See also (funsy memory, for the author's own reference — not in this repo):
project_roam_app_enablement_plans, project_roam_e2e_feature_sweep,
project_roam_security_review, feedback_no_git_writes.
