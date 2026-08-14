//! End-to-end over the real network: pair a second device into a vault using
//! only the two lines `roam pair-lan` prints — a device id and six digits.
//!
//! The library-level tests in `roam-transport-iroh/tests/lan_pairing.rs` drive
//! the handshake directly and hand the joiner a loopback address. This is the
//! only test that covers the operator's actual path: two processes, the joiner
//! finding the host by multicast, and the vault id / vault key landing on the
//! joiner's disk where `sync` will look for them.
//!
//! `#[ignore]` because it needs real multicast — same policy as
//! `share_cli_e2e.rs`. Run with `--ignored`.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

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

/// Pull `device id:` and `pairing code:` out of the host's output.
///
/// Read incrementally: `pair-lan` blocks until someone types the code, so its
/// output only exists while it is still running.
fn host_details(stdout: &mut impl BufRead) -> (String, String) {
    let (mut id, mut code) = (None, None);
    let mut line = String::new();
    while id.is_none() || code.is_none() {
        line.clear();
        let read = stdout.read_line(&mut line).expect("read host output");
        assert!(read > 0, "pair-lan exited before printing its id and code");
        if let Some(rest) = line.strip_prefix("device id:") {
            id = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("pairing code:") {
            code = Some(rest.trim().to_string());
        }
    }
    (id.unwrap(), code.unwrap())
}

#[test]
#[ignore = "needs real multicast on the local network; run with --ignored"]
fn a_second_device_joins_a_vault_over_the_lan_with_six_digits() {
    let dir = tempfile::tempdir().unwrap();
    let host_vault = dir.path().join("host-vault");
    let host_identity = dir.path().join("host.key");
    let joiner_vault = dir.path().join("joiner-vault");
    let joiner_identity = dir.path().join("joiner.key");

    let (_out, ok) = run_roam(&[
        "init",
        "--vault",
        host_vault.to_str().unwrap(),
        "--identity",
        host_identity.to_str().unwrap(),
        "--role",
        "admin",
    ]);
    assert!(ok, "init the host vault");

    // A joiner needs a device identity but must NOT found a vault — `init` does
    // both, so it is the wrong tool here.
    let (_out, ok) = run_roam(&["new-identity", "--out", joiner_identity.to_str().unwrap()]);
    assert!(ok, "mint a joiner identity");

    let mut host = Command::new(env!("CARGO_BIN_EXE_roam"))
        .args([
            "pair-lan",
            "--vault",
            host_vault.to_str().unwrap(),
            "--identity",
            host_identity.to_str().unwrap(),
            "--role",
            "writer",
            "--name",
            "host-laptop",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn roam pair-lan");
    let mut host_out = BufReader::new(host.stdout.take().unwrap());
    let (host_id, code) = host_details(&mut host_out);
    assert_eq!(code.len(), 6, "expected six digits, got {code:?}");

    let (join_out, ok) = run_roam(&[
        "join-lan",
        "--vault",
        joiner_vault.to_str().unwrap(),
        "--identity",
        joiner_identity.to_str().unwrap(),
        "--host",
        &host_id,
        "--code",
        &code,
    ]);
    assert!(ok, "join over the LAN:\n{join_out}");
    assert!(
        join_out.contains("founder peer:"),
        "join should report the pinned founder:\n{join_out}"
    );

    let host_status = host.wait().expect("pair-lan finished");
    assert!(host_status.success(), "pair-lan exited unhappily");

    // The joiner persisted what `sync` will need: without vault-id and
    // vault-key on disk, pairing succeeded and the device is still unusable.
    assert!(
        joiner_vault.join("vault-id").exists(),
        "joiner did not persist the vault id"
    );
    assert!(
        joiner_vault.join("vault-key").exists(),
        "joiner did not persist the vault key"
    );

    // Both sides agree on the roles the host granted.
    let (host_view, ok) = run_roam(&[
        "status",
        "--vault",
        host_vault.to_str().unwrap(),
        "--identity",
        host_identity.to_str().unwrap(),
    ]);
    assert!(ok, "host status");
    let (joiner_view, ok) = run_roam(&[
        "status",
        "--vault",
        joiner_vault.to_str().unwrap(),
        "--identity",
        joiner_identity.to_str().unwrap(),
    ]);
    assert!(ok, "joiner status");

    assert!(
        host_view.to_lowercase().contains("writer"),
        "host does not show the joiner as a writer:\n{host_view}"
    );
    assert!(
        joiner_view.to_lowercase().contains("admin"),
        "joiner does not see the host as admin:\n{joiner_view}"
    );
    assert!(
        joiner_view.to_lowercase().contains("writer"),
        "joiner did not materialize its own granted role:\n{joiner_view}"
    );
}

/// Regenerating a device identity over an existing keyfile would silently orphan
/// the device from every roster it has been added to — the key IS the identity.
/// No network needed, so this one always runs.
#[test]
fn new_identity_refuses_to_overwrite_an_existing_keyfile() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("device.key");

    let (out, ok) = run_roam(&["new-identity", "--out", key.to_str().unwrap()]);
    assert!(ok, "first mint should succeed");
    assert!(out.contains("peer_id:"), "should print the new peer id: {out}");
    let original = std::fs::read(&key).unwrap();

    let (_out, ok) = run_roam(&["new-identity", "--out", key.to_str().unwrap()]);
    assert!(!ok, "minting over an existing identity must fail");
    assert_eq!(
        std::fs::read(&key).unwrap(),
        original,
        "the existing identity was clobbered"
    );
}
