//! Operator-surface end-to-end: drive the REAL compiled `roam` binary through a
//! full single-vault operator lifecycle as an external process, asserting on its
//! real stdout. This is the acceptance sweep for the CLI commands that manage a
//! vault (init, set-name, status, rotate, checkpoint, history) — every step is a
//! fresh `roam` process reopening the on-disk vault the previous step wrote, so a
//! green run proves the persisted state round-trips across process boundaries the
//! way an operator actually uses it.
//!
//! Data-path features (P2P transfer, roster/role enforcement, folder sync) are
//! covered by the library/iroh-loopback e2e tests (roles_e2e, folder_sync_e2e)
//! and the backend sweep (roam-backend-client/tests/full_feature_e2e.rs); this
//! file deliberately stays single-vault + no-network so it needs no backend and
//! never flakes on timing.

use std::path::Path;
use std::process::Command;

/// Run the `roam` binary with the given args; return (stdout, stderr, success).
/// Cargo injects `CARGO_BIN_EXE_roam` for the `[[bin]] name = "roam"`, so the
/// test always runs the freshly-built binary from this workspace.
fn run_roam(args: &[&str]) -> (String, String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_roam"))
        .args(args)
        .output()
        .expect("spawn roam binary");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        eprintln!("roam {args:?} failed:\nstdout:\n{stdout}\nstderr:\n{stderr}");
    }
    (stdout, stderr, out.status.success())
}

/// Convenience: run and assert the process exited 0, returning stdout.
fn ok_roam(args: &[&str]) -> String {
    let (stdout, _stderr, ok) = run_roam(args);
    assert!(ok, "expected `roam {args:?}` to succeed");
    stdout
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn operator_lifecycle_over_the_real_binary() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let id_path = dir.path().join("id.key");
    let (vault_s, id_s) = (s(&vault), s(&id_path));

    // --- init -------------------------------------------------------------
    // Genesis: a fresh admin founder. Writes vault-id + vault-key + the store.
    let out = ok_roam(&[
        "init",
        "--vault",
        vault_s,
        "--identity",
        id_s,
        "--role",
        "admin",
    ]);
    assert!(
        out.contains("initialized vault"),
        "init banner missing: {out}"
    );
    assert!(out.contains("peer_id:"), "init should print peer_id: {out}");
    assert!(
        out.contains("founder role: admin"),
        "founder role wrong: {out}"
    );

    // Re-init must REFUSE (overwriting vault-id would orphan paired peers).
    let (_o, _e, ok) = run_roam(&[
        "init",
        "--vault",
        vault_s,
        "--identity",
        id_s,
        "--role",
        "admin",
    ]);
    assert!(!ok, "re-init over an existing vault must fail");

    // --- set-name ---------------------------------------------------------
    let out = ok_roam(&["set-name", "--vault", vault_s, "--identity", id_s, "laptop"]);
    assert!(out.contains("device name set to"), "set-name output: {out}");
    assert!(
        out.contains("laptop"),
        "set-name should echo the name: {out}"
    );

    // --- status (pre-rotation) -------------------------------------------
    // A fresh process reopens the vault: the roster, the just-set device name,
    // and the key-rotation section must all round-trip from disk.
    let out = ok_roam(&["status", "--vault", vault_s, "--identity", id_s]);
    assert!(
        out.contains("role=admin"),
        "status should show admin role: {out}"
    );
    assert!(
        out.contains("name=laptop"),
        "status should show device name: {out}"
    );
    assert!(
        out.contains("epochs:"),
        "status should show the epoch section: {out}"
    );
    // No rotation yet → the write-head is still the legacy epoch 0.
    assert!(
        out.contains("write-head epoch-0 (legacy)"),
        "pre-rotation write-head should be epoch 0: {out}"
    );
    // Single admin holds every key it needs → no vault-key issues.
    assert!(
        out.contains("vault key state: synced"),
        "key state should be synced: {out}"
    );

    // --- rotate (with a generated paper-recovery phrase) ------------------
    let out = ok_roam(&[
        "rotate",
        "--vault",
        vault_s,
        "--identity",
        id_s,
        "--generate-paper",
    ]);
    assert!(
        out.contains("rotated to epoch"),
        "rotate banner missing: {out}"
    );
    assert!(
        out.contains("PAPER RECOVERY PHRASE"),
        "generate-paper should print a phrase: {out}"
    );
    assert!(
        out.contains("new writes seal under this epoch"),
        "rotate should note new writes seal under the new epoch: {out}"
    );

    // --- recover (paper phrase round-trips through the CLI) --------------
    // Pull the generated phrase out of the rotate output and feed it back to
    // `roam recover`. This single-admin vault already holds its own epoch key,
    // so recovery finds nothing to restore — but the command must parse the
    // phrase, open the vault, and exit 0. (Data-level recovery, where a device
    // that CANNOT decrypt regains access, is proven end-to-end against the real
    // backend in roam-backend-client/tests/full_feature_e2e.rs.)
    let phrase = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .skip_while(|l| !l.contains("PAPER RECOVERY PHRASE"))
        .nth(1)
        .expect("rotate output must contain the paper phrase line")
        .to_string();
    let rec = ok_roam(&[
        "recover",
        "--vault",
        vault_s,
        "--identity",
        id_s,
        "--paper",
        &phrase,
    ]);
    assert!(
        rec.contains("no epochs recovered"),
        "a single admin already holds its own epoch key: {rec}"
    );

    // --- status (post-rotation) ------------------------------------------
    // The write-head must have advanced off epoch 0 to a real (hex-prefixed)
    // epoch, and the sole admin still holds the head key → still synced.
    let out = ok_roam(&["status", "--vault", vault_s, "--identity", id_s]);
    assert!(
        !out.contains("write-head epoch-0 (legacy)"),
        "post-rotation write-head must not be epoch 0: {out}"
    );
    assert!(
        out.contains("write-head") && out.contains('…'),
        "post-rotation write-head should render a hex epoch prefix: {out}"
    );
    assert!(
        out.contains("vault key state: synced"),
        "post-rotation single admin should still be synced: {out}"
    );

    // --- checkpoint (dry-run then real) ----------------------------------
    let out = ok_roam(&[
        "checkpoint",
        "--vault",
        vault_s,
        "--identity",
        id_s,
        "--dry-run",
    ]);
    assert!(
        out.contains("would free"),
        "dry-run should report freeable bytes: {out}"
    );
    assert!(
        out.contains("No changes made"),
        "dry-run must not mutate: {out}"
    );

    let out = ok_roam(&["checkpoint", "--vault", vault_s, "--identity", id_s]);
    assert!(
        out.contains("checkpoint done"),
        "checkpoint should report completion: {out}"
    );

    // --- history ----------------------------------------------------------
    // Read-only recovery listing. No files were deleted, so the deleted list is
    // empty, but the command must still succeed and print both section headers.
    let out = ok_roam(&["history", "--vault", vault_s, "--identity", id_s]);
    assert!(
        out.contains("retained history points:"),
        "history header missing: {out}"
    );
    assert!(
        out.contains("recoverable deleted files:"),
        "deleted header missing: {out}"
    );
}
