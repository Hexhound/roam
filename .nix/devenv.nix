{
  inputs,
  pkgs,
  ...
}: {
  imports = [
    inputs.devkit.devenvModule
  ];

  # cargo-nextest: compact, per-test-isolated runner. Far quieter output than
  # `cargo test` (one line/test, filter expressions) — cuts context/token cost.
  # Project-scoped for now; promote to the devkit rust module if funsy wants it.
  #
  # WASM web-client (F3) toolchain: wasm-bindgen-cli generates the JS/TS glue for
  # the `roam-wasm` cdylib façade, wasm-pack drives the wasm build + npm packaging,
  # nodejs runs the JS "client" interop e2e. The wasm32-unknown-unknown std ships
  # with the devkit rustc already (rustlib has the target), so no target install
  # needed — just `cargo build --target wasm32-unknown-unknown`. Project-scoped for
  # now; will move to the devkit rust module as a `wasm.enable` config option later.
  #
  # wasm-bindgen-cli is version-PINNED and must match the `wasm-bindgen` crate
  # version in [workspace.dependencies] exactly — the CLI refuses a .wasm whose
  # embedded schema version differs ("rust wasm file schema version: X, this
  # binary schema version: Y"). nixpkgs tops out at 0.2.126 (no 0.2.127), so the
  # crate is pinned DOWN to "=0.2.126" in the root Cargo.toml. Keep the two in
  # lockstep when bumping. The unversioned `pkgs.wasm-bindgen-cli` is 0.2.121
  # here — do not use it, it would silently drift from the crate.
  # `lld` is REQUIRED for the wasm build, not optional: the nix rustc ships no
  # bundled `rust-lld` (its sysroot has only `rust-lldb`, a debugger), so linking
  # a wasm32 cdylib fails with "linker `lld` not found". `cargo check` passes
  # without it — the gap only appears at link time — so leaving it out looks fine
  # right up until the first real wasm artifact.
  # `cargo-sweep` is a disk-space necessity here, not a convenience. Cargo keeps
  # target/ as a CACHE: artifact filenames are fingerprint-hashed (rustc version,
  # features, profile, dep versions) and old generations are never collected, and
  # stable cargo has no age-based GC for the target dir. This workspace links ~55
  # separate test/bench binaries, each statically linking the whole iroh + loro +
  # rustls tree at ~150-400 MB (77% of which is DWARF), so every rebuild that
  # changes a fingerprint leaves another full set behind. Measured 2026-08-14:
  # 244 executables, only 55 distinct targets — 33 GB of pure stale duplicates,
  # which filled the disk and failed a link with ENOSPC.
  #
  #   cargo sweep --installed    # drop artifacts from toolchains no longer here
  #   cargo sweep --time 7       # drop anything untouched for a week
  #
  # Pruning stale generations does NOT invalidate the live build (unlike
  # `cargo clean`), so it is cheap to run often. The remaining ~7.5 GB floor is
  # mostly debug info; `[profile.dev] debug = "line-tables-only"` would cut most
  # of it at the cost of debugger variable inspection.
  # `chromium` is a TEST DEPENDENCY, not a convenience. The OPFS storage backend
  # can only be exercised where OPFS exists, and node has no OPFS at all — so the
  # `tests/js` node harness that proves M1 interop and M3 transport structurally
  # cannot cover it. Measured in Chromium 150 (see docs/browser_storage_opfs.md):
  # `createSyncAccessHandle` is *absent* on the main thread and present in a
  # dedicated worker, so the harness has to be a real browser running a real
  # worker. It must also be served over `http://127.0.0.1` rather than `file://`
  # — OPFS needs a secure context with a real storage key, and a `file://` page
  # is an opaque origin.
  #
  # Pinned via nixpkgs like everything else here so the harness does not silently
  # depend on whatever browser happens to be in the developer's user profile.
  packages = [
    pkgs.cargo-nextest
    pkgs.cargo-sweep
    pkgs.wasm-bindgen-cli_0_2_126
    pkgs.wasm-pack
    pkgs.nodejs
    pkgs.lld
    pkgs.chromium
  ];

  # Claude Code CLI + agent-acp, sourced from the shared devkit. Pins
  # CLAUDE_CONFIG_DIR under DEVENV_STATE so per-project memory/config is
  # isolated. hexdocs/mempalace/postgres MCP left off — Rust-first workspace.
  modules.claude.enable = true;

  # Rust toolchain (rustc/cargo/rustfmt) + Tauri GUI system libs, sourced from
  # the shared devkit. CARGO_HOME is pinned under DEVENV_STATE by the module.
  modules.rust.enable = true;

  # Elixir/Erlang for the `sync/` Phoenix+Ash backend (Slice-4 RBSR). Phoenix
  # tooling enabled for the generated project + the ported controller.
  modules.elixir = {
    enable = true;
    phoenix.enable = true;
  };

  # Postgres for the `sync/` Phoenix+Ash project (igniter --setup + AshPostgres
  # Repo boot at test/e2e time). Local dev service under DEVENV_STATE.
  modules.postgresql = {
    enable = true;
    port = 5432;
  };
}
