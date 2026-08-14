//! End-to-end over the real network: `roam share` on one process, `roam
//! receive` on another, with nothing passed between them but the two lines the
//! sender prints — a device id and six digits.
//!
//! This is the whole point of the command, and it is the only test that covers
//! it: the library-level tests in `roam-share-iroh` hand the receiver a loopback
//! `EndpointAddr`, sidestepping discovery. Here the receiver is given an id and
//! has to find the sender by multicast, exactly as a human would.
//!
//! `#[ignore]` because it needs real multicast on the local network — same
//! policy as `roam-transport-iroh`'s `lan_discovery.rs`. Run with `--ignored`.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// Pull the `share id:` and `code:` lines out of the sender's output.
///
/// Reads incrementally rather than waiting for exit: `roam share` blocks until a
/// receiver shows up, so its output is only available while it is still running.
fn share_details(stdout: &mut impl BufRead) -> (String, String) {
    let mut id = None;
    let mut code = None;
    let mut line = String::new();
    while id.is_none() || code.is_none() {
        line.clear();
        let read = stdout.read_line(&mut line).expect("read sender output");
        assert!(read > 0, "sender exited before printing its id and code");
        if let Some(rest) = line.strip_prefix("share id:") {
            id = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("code:") {
            code = Some(rest.trim().to_string());
        }
    }
    (id.unwrap(), code.unwrap())
}

#[test]
#[ignore = "needs real multicast on the local network; run with --ignored"]
fn sharing_a_file_between_two_processes_needs_only_an_id_and_six_digits() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("holiday-plans.txt");
    let dest = dir.path().join("inbox");
    std::fs::write(&source, b"meet at the pier at six").unwrap();
    std::fs::create_dir(&dest).unwrap();

    let mut sender = Command::new(env!("CARGO_BIN_EXE_roam"))
        .args(["share", source.to_str().unwrap(), "--from", "alice-laptop"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn roam share");
    let mut sender_out = BufReader::new(sender.stdout.take().unwrap());
    let (share_id, code) = share_details(&mut sender_out);
    assert_eq!(code.len(), 6, "the code should be six digits, got {code:?}");

    let mut receiver = Command::new(env!("CARGO_BIN_EXE_roam"))
        .args([
            "receive",
            "--from",
            &share_id,
            "--code",
            &code,
            "--into",
            dest.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn roam receive");
    // The receiver shows the offer and asks before writing anything.
    receiver
        .stdin
        .take()
        .unwrap()
        .write_all(b"y\n")
        .expect("answer the prompt");

    let receiver_out = receiver.wait_with_output().expect("receiver finished");
    let receiver_stdout = String::from_utf8_lossy(&receiver_out.stdout).into_owned();
    assert!(
        receiver_out.status.success(),
        "receive failed:\n{receiver_stdout}\n{}",
        String::from_utf8_lossy(&receiver_out.stderr)
    );
    // The offer is shown before the decision, so the human knows what they said
    // yes to.
    assert!(
        receiver_stdout.contains("holiday-plans.txt"),
        "the receiver never showed the offer:\n{receiver_stdout}"
    );

    assert_eq!(
        std::fs::read(dest.join("holiday-plans.txt")).unwrap(),
        b"meet at the pier at six"
    );

    // The transfer is done, so the sender has nothing left to do but exit. If it
    // lingers here it is sitting out a QUIC idle timeout waiting for a close
    // that will never arrive — the receiver process is already gone. Measured:
    // this was a reliable 30s before the receiver learned to flush its close.
    let waited = std::time::Instant::now();
    let sender_status = sender.wait().expect("sender finished");
    let lingered = waited.elapsed();
    assert!(sender_status.success(), "sender exited unhappily");
    assert!(
        lingered < std::time::Duration::from_secs(10),
        "sender took {lingered:?} to exit after the transfer completed — \
         that is an idle timeout, not work"
    );
}
