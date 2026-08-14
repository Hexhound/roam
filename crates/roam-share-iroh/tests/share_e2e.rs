//! End-to-end: a real transfer between two real iroh endpoints, authenticated
//! by a six-digit code.
//!
//! `presets::Minimal` throughout — no relay, no pkarr, no DNS. Everything here
//! happens over loopback, which is what a LAN share has to work on.

use iroh::{Endpoint, EndpointAddr};
use roam_pake::PairingCode;
use roam_share::{Payload, ShareOffer};
use roam_share_iroh::{bind_share_endpoint, offer_paths, receive_share, ShareSender, SHARE_ALPN};
use std::path::PathBuf;

async fn endpoint() -> Endpoint {
    // Deliberately the real production binder, so every test below also covers
    // that it binds the right ALPN and preset.
    bind_share_endpoint().await.expect("bind share endpoint")
}

/// A share is announced to everyone on the LAN. If it ran under the device's
/// long-term key, the endpoint id — which *is* that key — would be a stable
/// identifier broadcast on every network the device ever shares from.
#[tokio::test(flavor = "multi_thread")]
async fn every_share_gets_a_fresh_identity() {
    let first = endpoint().await;
    let second = endpoint().await;
    assert_ne!(
        first.id(),
        second.id(),
        "two shares reused one identity — that is a device fingerprint"
    );
}

/// Loopback address for a bound endpoint. Discovery is out of scope here; on a
/// real LAN this comes from `roam_transport_iroh::discovery`.
///
/// A bare post-bind `addr()` typically has no direct addresses yet, and with no
/// relay configured that address is undialable — so wait for one to appear, the
/// same way `pairing.rs` does before minting a token.
async fn addr_of(endpoint: &Endpoint) -> EndpointAddr {
    for _ in 0..400 {
        if endpoint.addr().ip_addrs().next().is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    endpoint.addr()
}

fn write(dir: &std::path::Path, rel: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn a_folder_and_a_file_transfer_with_the_right_code() {
    let source = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();

    let single = write(source.path(), "notes.txt", b"hello from the sender");
    write(source.path(), "holiday/beach.jpg", b"\xff\xd8jpeg-ish bytes");
    write(source.path(), "holiday/raw/DSC_0001.arw", &vec![7u8; 200_000]);
    let folder = source.path().join("holiday");

    let (mut offer, sources) =
        offer_paths("alice-laptop", &[single.clone(), folder]).expect("build offer");
    offer.items.push(Payload::Text("and a note".into()));

    let sender_endpoint = endpoint().await;
    let receiver_endpoint = endpoint().await;
    let sender_addr = addr_of(&sender_endpoint).await;

    let (sender, code) = ShareSender::new(sender_endpoint, offer, sources);
    let serve = tokio::spawn(sender.serve_one());

    let received = receive_share(
        &receiver_endpoint,
        sender_addr,
        &code,
        dest.path(),
        |offer: &ShareOffer| {
            // The receiver sees what is coming before accepting.
            assert_eq!(offer.from, "alice-laptop");
            true
        },
    )
    .await
    .expect("receive the share");

    serve.await.unwrap().expect("sender completed");

    assert_eq!(
        std::fs::read(dest.path().join("notes.txt")).unwrap(),
        b"hello from the sender"
    );
    // Folder structure survives, nested directories included.
    assert_eq!(
        std::fs::read(dest.path().join("holiday/beach.jpg")).unwrap(),
        b"\xff\xd8jpeg-ish bytes"
    );
    // Multi-chunk file (200 KB over a 64 KB chunk size) reassembles exactly.
    assert_eq!(
        std::fs::read(dest.path().join("holiday/raw/DSC_0001.arw")).unwrap(),
        vec![7u8; 200_000]
    );
    assert_eq!(received.texts, vec!["and a note".to_string()]);
    assert_eq!(received.files.len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_code_transfers_nothing_and_reveals_nothing() {
    let source = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let secret_file = write(source.path(), "salary-2026.pdf", b"confidential");

    let (offer, sources) = offer_paths("alice-laptop", &[secret_file]).unwrap();
    let sender_endpoint = endpoint().await;
    let receiver_endpoint = endpoint().await;
    let sender_addr = addr_of(&sender_endpoint).await;

    let (sender, _real_code) = ShareSender::new(sender_endpoint, offer, sources);
    let serve = tokio::spawn(sender.serve_one());

    let mut saw_offer = false;
    let result = receive_share(
        &receiver_endpoint,
        sender_addr,
        &PairingCode::parse("000000").unwrap(),
        dest.path(),
        |_| {
            saw_offer = true;
            true
        },
    )
    .await;

    assert!(result.is_err(), "a wrong code must not complete a transfer");
    assert!(
        !saw_offer,
        "the offer was revealed to a peer that had not proved the code — \
         a wrong guess must not even learn the filenames"
    );
    assert!(
        std::fs::read_dir(dest.path()).unwrap().next().is_none(),
        "files were written despite a wrong code"
    );

    serve.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn declining_writes_nothing() {
    let source = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let file = write(source.path(), "unwanted.bin", b"do not want");

    let (offer, sources) = offer_paths("alice-laptop", &[file]).unwrap();
    let sender_endpoint = endpoint().await;
    let receiver_endpoint = endpoint().await;
    let sender_addr = addr_of(&sender_endpoint).await;

    let (sender, code) = ShareSender::new(sender_endpoint, offer, sources);
    let serve = tokio::spawn(sender.serve_one());

    let received = receive_share(&receiver_endpoint, sender_addr, &code, dest.path(), |_| false)
        .await
        .expect("declining is not an error");

    assert!(received.files.is_empty());
    assert!(std::fs::read_dir(dest.path()).unwrap().next().is_none());
    serve.await.unwrap().expect("sender handles a decline cleanly");
}

/// A symlink inside a shared folder must not be followed — otherwise "share this
/// folder" could exfiltrate anything the sender can read.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn symlinks_inside_a_shared_folder_are_not_followed() {
    let source = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = write(outside.path(), "id_ed25519", b"PRIVATE KEY MATERIAL");

    write(source.path(), "shared/ok.txt", b"fine");
    std::os::unix::fs::symlink(&secret, source.path().join("shared/leaked.txt")).unwrap();

    let (offer, sources) = offer_paths("alice", &[source.path().join("shared")]).unwrap();

    let names: Vec<String> = offer.streams().iter().map(|s| s.path.to_string()).collect();
    assert!(
        names.contains(&"shared/ok.txt".to_string()),
        "the ordinary file should still be shared: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("leaked")),
        "a symlink was followed out of the shared folder: {names:?}"
    );
    assert!(!sources.keys().any(|k| k.to_string().contains("leaked")));
}

/// The stronger form of the wrong-code test.
///
/// `a_wrong_code_transfers_nothing_and_reveals_nothing` asserts the receiver's
/// *callback* never fired — but a hostile peer does not run our callback, it
/// just reads the socket. So this speaks the wire protocol by hand with a wrong
/// code and asserts that **no bytes the sender emits contain the filename**,
/// sealed or otherwise. This is what backs the claim that a wrong guess learns
/// not even what is on offer.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_code_never_puts_the_filenames_on_the_wire() {
    use roam_pake::Initiator;

    const SECRET_NAME: &str = "salary-2026-confidential.pdf";

    let source = tempfile::tempdir().unwrap();
    let file = write(source.path(), SECRET_NAME, b"confidential");
    let (offer, sources) = offer_paths("alice-laptop", &[file]).unwrap();

    let sender_endpoint = endpoint().await;
    let attacker_endpoint = endpoint().await;
    let sender_addr = addr_of(&sender_endpoint).await;
    let sender_id = sender_addr.id;

    let (sender, _real_code) = ShareSender::new(sender_endpoint, offer, sources);
    let serve = tokio::spawn(sender.serve_one());

    // A hostile client: guess a code, then hoover up everything sent back.
    let conn = attacker_endpoint
        .connect(sender_addr, SHARE_ALPN)
        .await
        .expect("attacker connects");
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let (initiator, msg1) = Initiator::start(
        &PairingCode::parse("000000").unwrap(),
        *attacker_endpoint.id().as_bytes(),
        *sender_id.as_bytes(),
    );
    write_len_prefixed(&mut send, &msg1).await;

    let mut seen = Vec::new();
    if let Some(msg2) = read_len_prefixed(&mut recv).await {
        seen.extend_from_slice(&msg2);
        if let Ok((_, confirm)) = initiator.accept(&msg2) {
            write_len_prefixed(&mut send, &confirm).await;
        }
        // Whatever else the sender is willing to say to us.
        while let Some(frame) = read_len_prefixed(&mut recv).await {
            seen.extend_from_slice(&frame);
        }
    }

    assert!(
        !seen
            .windows(SECRET_NAME.len())
            .any(|w| w == SECRET_NAME.as_bytes()),
        "the sender leaked a filename to a peer that never proved the code"
    );

    serve.abort();
}

async fn write_len_prefixed(send: &mut iroh::endpoint::SendStream, bytes: &[u8]) {
    let len = (bytes.len() as u32).to_le_bytes();
    let _ = send.write_all(&len).await;
    let _ = send.write_all(bytes).await;
}

async fn read_len_prefixed(recv: &mut iroh::endpoint::RecvStream) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
    recv.read_exact(&mut body).await.ok()?;
    Some(body)
}

/// A peer that connects and then says nothing must not be able to park the
/// sender.
///
/// `serve_one` handles connections one at a time, and until this test there was
/// no timeout anywhere in this crate — so a hostile device on the LAN could open
/// a connection, send nothing, and block every legitimate receiver until QUIC's
/// ~30s idle timeout fired. Repeat that in a loop and no share ever completes.
/// The pairing protocol already bounded its handshake reads; this one did not.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_connects_and_stalls_does_not_block_a_real_receiver() {
    let source = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let file = write(source.path(), "wanted.txt", b"the real transfer");

    let (offer, sources) = offer_paths("alice-laptop", &[file]).unwrap();
    let sender_endpoint = endpoint().await;
    let stall_endpoint = endpoint().await;
    let receiver_endpoint = endpoint().await;
    let sender_addr = addr_of(&sender_endpoint).await;

    let (sender, code) = ShareSender::new(sender_endpoint, offer, sources);
    // A short budget so the test does not have to sit out the production one.
    // The bug is "no bound at all"; the exact value is policy.
    let sender = sender.with_handshake_timeout(std::time::Duration::from_millis(300));
    let serve = tokio::spawn(sender.serve_one());

    // The staller: connect, open a stream, then go quiet forever.
    let stall_conn = stall_endpoint
        .connect(sender_addr.clone(), SHARE_ALPN)
        .await
        .expect("staller connects");
    let _stall_stream = stall_conn.open_bi().await.unwrap();

    // The real receiver must still get through, and quickly.
    let started = std::time::Instant::now();
    let received = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        receive_share(
            &receiver_endpoint,
            sender_addr,
            &code,
            dest.path(),
            |_| true,
        ),
    )
    .await
    .expect("a stalled peer blocked the sender past any reasonable bound")
    .expect("receive the share");

    assert_eq!(received.files.len(), 1);
    assert_eq!(
        std::fs::read(dest.path().join("wanted.txt")).unwrap(),
        b"the real transfer"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "took {:?} — the staller was still costing us an idle timeout",
        started.elapsed()
    );

    serve.await.unwrap().expect("sender completed");
}

/// The companion to the stall test, and a hole it did not cover.
///
/// `serve_one`'s rule is that nothing a peer does may end the session — only our
/// own failure to read a file does. Bounding the handshake reads enforced that
/// for a peer that says *nothing*. A peer that says *rubbish* got through by a
/// different door: the responder spent an attempt the moment a run started,
/// before parsing, so three unparseable messages exhausted `MAX_ATTEMPTS` and
/// `serve_one` bailed with "the share code is used up" — the session killed by a
/// peer, with no guessing and no knowledge of the code.
///
/// The endpoint is announced over mDNS, so the attacker is any device on the
/// network. The budget is now charged on a failed *confirmation*, so guessing is
/// still bounded at three (`roam_pake::tests::the_attempt_budget_is_enforced`)
/// while rubbish costs nothing.
#[tokio::test(flavor = "multi_thread")]
async fn junk_connections_cannot_retire_the_share_code() {
    let source = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let file = write(source.path(), "wanted.txt", b"the real transfer");

    let (offer, sources) = offer_paths("alice-laptop", &[file]).unwrap();
    let sender_endpoint = endpoint().await;
    let receiver_endpoint = endpoint().await;
    let sender_addr = addr_of(&sender_endpoint).await;

    let (sender, code) = ShareSender::new(sender_endpoint, offer, sources);
    let serve = tokio::spawn(sender.serve_one());

    // More junk runs than the whole budget, each a complete, well-framed
    // message that is simply not a SPAKE2 one.
    for attempt in 0..roam_pake::MAX_ATTEMPTS + 2 {
        let junk_endpoint = endpoint().await;
        let conn = junk_endpoint
            .connect(sender_addr.clone(), SHARE_ALPN)
            .await
            .unwrap_or_else(|e| panic!("junk connection {attempt} could not connect: {e}"));
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        let garbage = b"not a spake2 message";
        // The share wire is little-endian length-prefixed (see `wire.rs`).
        send.write_all(&(garbage.len() as u32).to_le_bytes())
            .await
            .unwrap();
        send.write_all(garbage).await.unwrap();
        send.finish().unwrap();
        // Let the sender consume this run before opening the next, so the
        // attempts land one at a time rather than racing the accept loop.
        conn.closed().await;
    }

    // The code must still be good.
    let received = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        receive_share(
            &receiver_endpoint,
            sender_addr,
            &code,
            dest.path(),
            |_| true,
        ),
    )
    .await
    .expect("the sender stopped listening after junk connections")
    .expect("the share code was retired by peers that never guessed it");

    assert_eq!(received.files.len(), 1);
    assert_eq!(
        std::fs::read(dest.path().join("wanted.txt")).unwrap(),
        b"the real transfer"
    );

    serve.await.unwrap().expect("sender completed");
}
