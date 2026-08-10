{
  inputs,
  ...
}: {
  imports = [
    inputs.devkit.devenvModule
  ];

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
