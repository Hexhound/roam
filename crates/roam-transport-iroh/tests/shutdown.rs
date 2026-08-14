//! Shutting down must tell the peers, not just stop talking to them.
//!
//! QUIC has no "the other end went away" signal other than a CONNECTION_CLOSE
//! frame or a ~30-second idle timeout. Every place in this codebase that got
//! this wrong looked identical: one side finished, dropped its state, and left
//! the other side blocked on a timeout for a peer that no longer existed. It has
//! now happened three times (share decline, share success, and — this file —
//! sync shutdown), so it gets a dedicated test file rather than a comment.
//!
//! These bind real endpoints on loopback and are cheap; no `#[ignore]`.

use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use roam_storage::Identity;
use roam_sync_core::{Frame, Transport};
use roam_transport_iroh::{IrohTransport, SYNC_ALPN};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Anything above this and we are sitting out an idle timeout, not working.
/// The real timeout is ~30s, so this leaves plenty of headroom for a slow box
/// while still failing loudly on the actual bug.
const PROMPT: Duration = Duration::from_secs(10);

/// A plain iroh endpoint standing in for a peer, so the test can observe the
/// connection state directly. Using a second `IrohTransport` would hide exactly
/// what is being measured behind its own reconnect logic.
async fn observer() -> (Endpoint, Identity) {
    let identity = Identity::generate();
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&identity.secret_bytes()))
        .alpns(vec![SYNC_ALPN.to_vec()])
        .bind()
        .await
        .expect("bind observer endpoint");
    // A bare post-bind addr has no direct addresses and is undialable with no
    // relay configured.
    for _ in 0..400 {
        if endpoint.addr().ip_addrs().next().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (endpoint, identity)
}

#[tokio::test(flavor = "multi_thread")]
async fn shutting_down_a_transport_closes_its_peers_connections_promptly() {
    let (peer_endpoint, peer_identity) = observer().await;
    let peer_id = peer_identity.peer_id();

    let identity = Identity::generate();
    let mut routes = HashMap::new();
    routes.insert(peer_id, peer_identity.verifying_key().to_bytes());
    let transport = IrohTransport::spawn(&identity, routes)
        .await
        .expect("spawn transport");
    transport.add_addr(peer_id, peer_endpoint.addr()).await;

    // Make the transport dial: `send` establishes the connection as a side
    // effect, which is the state a running `roam sync` is in.
    let accepting = tokio::spawn(async move {
        let incoming = peer_endpoint.accept().await.expect("inbound connection");
        let conn = incoming.accept().unwrap().await.expect("accept");
        // Hold the endpoint alive for the lifetime of the connection; dropping
        // it here would tear down the very thing under observation.
        (conn, peer_endpoint)
    });
    transport
        .send(peer_id, Frame::Ping)
        .await
        .expect("send establishes a connection");
    let (conn, _peer_endpoint) = accepting.await.expect("peer accepted");

    // The peer is connected and idle — exactly where a `roam sync` peer sits.
    assert!(
        conn.close_reason().is_none(),
        "connection should still be open before shutdown"
    );

    let started = Instant::now();
    transport.shutdown().await;
    tokio::time::timeout(PROMPT, conn.closed())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "peer never learned the transport shut down; it is waiting out a \
                 QUIC idle timeout ({:?} elapsed)",
                started.elapsed()
            )
        });
}
