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

  # Elixir/Erlang for the `roam-backend` server (roam-backend/server.exs is a
  # standalone Mix.install script; only needs `elixir` on PATH — no Phoenix).
  modules.elixir.enable = true;
}
