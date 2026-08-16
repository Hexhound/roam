//! The handshake over real HTTP, against a relay that answers exactly as the
//! Elixir one does.
//!
//! [`mailbox_pairing`](../mailbox_pairing.rs) covers the protocol over an
//! in-process mailbox, which proves the cryptography and none of the wiring.
//! What is untested by that, and is the part most likely to be silently wrong,
//! is the seam: the URL shape, the verbs, and the status codes that
//! [`HttpMailbox`] maps back into [`SlotOutcome`]. A 409 read as an error rather
//! than "already taken" would turn the squat defence into a crash; a path that
//! disagrees with the router by one segment is a 404 on every request, which
//! presents as pairing hanging with nothing in the log.
//!
//! So this runs the whole thing over a socket. The server is written out by
//! hand rather than mocked, because the point is to answer the way
//! `Sync.Backend.Mailbox` and `SyncWeb.RendezvousController` answer — write-once
//! with 409, absent with 404, and a JSON session listing — and a mock would only
//! answer the way this file already believes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use roam_pairing::handshake::testing::join_via_mailbox_with_timeouts;
use roam_pairing::{host_via_mailbox, HttpMailbox, Invite};
use roam_storage::{Identity, PeerStatus, Role, Store, VaultId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const STEP: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(20);

type Slots = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// A relay speaking the same contract as the Elixir one, on a real port.
/// Returns its base URL; it serves until the test ends.
async fn serve_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let slots: Slots = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let slots = slots.clone();
            tokio::spawn(async move {
                let _ = handle(&mut socket, slots).await;
            });
        }
    });

    format!("http://{addr}")
}

async fn handle(socket: &mut tokio::net::TcpStream, slots: Slots) -> std::io::Result<()> {
    // Read until the headers end, then take exactly Content-Length more. Enough
    // HTTP to be honest about this protocol and no more.
    let mut buffer = Vec::new();
    let header_end = loop {
        let mut chunk = [0u8; 4096];
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };

    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let content_length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    while buffer.len() < header_end + content_length {
        let mut chunk = [0u8; 4096];
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = buffer[header_end..].to_vec();

    let response = route(&method, &path, body, &slots);
    socket.write_all(&response).await?;
    socket.flush().await
}

fn route(method: &str, path: &str, body: Vec<u8>, slots: &Slots) -> Vec<u8> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match (method, segments.as_slice()) {
        // GET /rendezvous/:rendezvous/sessions
        ("GET", ["rendezvous", _rendezvous, "sessions"]) => {
            let slots = slots.lock().unwrap();
            let mut sessions: Vec<&str> = slots
                .keys()
                .filter_map(|key| key.split('/').next())
                .collect();
            sessions.sort_unstable();
            sessions.dedup();
            let json = format!(
                "{{\"sessions\":[{}]}}",
                sessions
                    .iter()
                    .map(|s| format!("\"{s}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            respond(200, "application/json", json.into_bytes())
        }

        // GET /rendezvous/:rendezvous/:session/:slot
        ("GET", ["rendezvous", _rendezvous, session, slot]) => {
            match slots.lock().unwrap().get(&format!("{session}/{slot}")) {
                // Absent is 404, which the client must read as "not written
                // yet", not as a failure.
                None => respond(404, "text/plain", Vec::new()),
                Some(bytes) => respond(200, "application/octet-stream", bytes.clone()),
            }
        }

        // PUT /rendezvous/:rendezvous/:session/:slot — write-once.
        ("PUT", ["rendezvous", _rendezvous, session, slot]) => {
            let mut slots = slots.lock().unwrap();
            match slots.entry(format!("{session}/{slot}")) {
                // Taken: 409, and the stored body is left alone. Same answer the
                // Elixir relay gives, and the client must map it to
                // `SlotOutcome::AlreadyTaken` rather than to an error.
                std::collections::hash_map::Entry::Occupied(_) => {
                    respond(409, "text/plain", Vec::new())
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(body);
                    respond(201, "text/plain", Vec::new())
                }
            }
        }

        _ => respond(404, "text/plain", Vec::new()),
    }
}

fn respond(status: u16, content_type: &str, body: Vec<u8>) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(&body);
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_joins_a_vault_over_http() {
    let relay = serve_relay().await;

    let (host_dir, joiner_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (host_identity, joiner_identity) = (Identity::generate(), Identity::generate());
    let mut host_store = Store::open(host_dir.path(), host_identity.clone()).unwrap();
    host_store.declare_founder(Role::Admin).unwrap();
    let mut joiner_store = Store::open(joiner_dir.path(), joiner_identity.clone()).unwrap();

    let invite = Invite::generate(&relay, host_identity.verifying_key().to_bytes());
    let vault = VaultId::generate();
    let vault_key = [42u8; 32];

    let (code, host) = host_via_mailbox(
        &host_identity,
        vault,
        vault_key,
        Role::Writer,
        &mut host_store,
        HttpMailbox::for_invite(&invite),
        invite.clone(),
    );
    let host = host.with_timeouts(STEP, POLL);

    // The joiner reaches the relay through the invite alone — which is all a
    // browser would have.
    let joiner_mailbox = HttpMailbox::for_invite(&invite);

    let (host_result, join_result) =
        tokio::join!(host.accept_for(Duration::from_secs(20)), async {
            join_via_mailbox_with_timeouts(
                &joiner_identity,
                &mut joiner_store,
                &joiner_mailbox,
                &invite,
                &code,
                STEP,
                POLL,
            )
            .await
        });

    assert_eq!(
        host_result.expect("host accepts over HTTP"),
        joiner_identity.peer_id()
    );
    let joined = join_result.expect("joiner joins over HTTP");
    assert_eq!(*joined.vault_key, vault_key);
    assert_eq!(joined.vault, vault);
    assert_eq!(joiner_store.self_role(), Some(Role::Writer));
    assert!(
        host_store
            .roster()
            .iter()
            .any(|p| p.peer_id == joiner_identity.peer_id() && p.status == PeerStatus::Active),
        "the host must trust the joiner it paired over HTTP"
    );
}

/// A 409 must come back as [`SlotOutcome::AlreadyTaken`], not as an error.
///
/// The distinction is the whole squat defence: the handshake reads "taken" as
/// "this session is not mine to finish" and abandons it without spending an
/// attempt. Mapped as an error it would still abandon the session — but the
/// status mapping is a single match arm, and getting it wrong the other way
/// (treating 409 as success) would let a host carry on against a transcript it
/// did not write.
#[tokio::test(flavor = "multi_thread")]
async fn the_relays_write_once_refusal_arrives_as_already_taken() {
    use roam_pairing::mailbox::{Mailbox, Slot};
    use roam_pairing::SlotOutcome;

    let relay = serve_relay().await;
    let mailbox = HttpMailbox::new(&relay, &"R".repeat(43));
    let session = "S".repeat(43);

    assert_eq!(
        mailbox
            .put(&session, Slot::Msg1, b"first".to_vec())
            .await
            .unwrap(),
        SlotOutcome::Written
    );
    assert_eq!(
        mailbox
            .put(&session, Slot::Msg1, b"second".to_vec())
            .await
            .unwrap(),
        SlotOutcome::AlreadyTaken
    );
    assert_eq!(
        mailbox.get(&session, Slot::Msg1).await.unwrap(),
        Some(b"first".to_vec()),
        "the refused write must not have replaced the body"
    );
}

/// An unwritten slot is the normal case while polling, so a 404 must read as
/// `None`. As an error it would abort the handshake on the first poll — before
/// the other device had a chance to answer at all.
#[tokio::test(flavor = "multi_thread")]
async fn an_unwritten_slot_reads_as_absent_rather_than_failing() {
    use roam_pairing::mailbox::{Mailbox, Slot};

    let relay = serve_relay().await;
    let mailbox = HttpMailbox::new(&relay, &"R".repeat(43));

    assert_eq!(
        mailbox.get(&"S".repeat(43), Slot::Accept).await.unwrap(),
        None
    );
}
