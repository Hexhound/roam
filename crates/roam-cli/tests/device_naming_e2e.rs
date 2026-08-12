//! End-to-end (no network): drive the `set-name` subcommand against the real
//! built binary and assert the self-asserted device name surfaces in `status`.
//!
//! Mirrors the harness style of `text_rollback_e2e.rs`/`roles_cli.rs`: a tempdir
//! vault + identity file, an Admin founder created via the real `init` command,
//! and the binary invoked via `env!("CARGO_BIN_EXE_roam")` with stdout captured.

use std::process::Command;

/// Run the `roam` binary with the given args; return (stdout, success).
fn run_roam(args: &[&str]) -> (String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_roam"))
        .args(args)
        .output()
        .expect("spawn roam binary");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        eprintln!(
            "roam {args:?} failed:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    (stdout, out.status.success())
}

#[test]
fn set_name_surfaces_in_status() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let id_path = dir.path().join("id.key");

    let vault_s = vault.to_str().unwrap();
    let id_s = id_path.to_str().unwrap();

    // 1. init an Admin founder (mirrors the other e2e tests' init invocation).
    let (_out, ok) = run_roam(&[
        "init",
        "--vault",
        vault_s,
        "--identity",
        id_s,
        "--role",
        "admin",
    ]);
    assert!(ok, "init should succeed");

    // 2. set this device's display name.
    let (_out, ok) = run_roam(&[
        "set-name",
        "--vault",
        vault_s,
        "--identity",
        id_s,
        "My Device",
    ]);
    assert!(ok, "set-name should succeed");

    // 3. status must print the name (robust to the exact status line format).
    let (status, ok) = run_roam(&["status", "--vault", vault_s, "--identity", id_s]);
    assert!(ok, "status should succeed");
    assert!(
        status.contains("My Device"),
        "status should show the device name, got:\n{status}"
    );
}
