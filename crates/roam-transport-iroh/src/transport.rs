//! `IrohTransport` — a dumb pipe over real iroh QUIC.
//!
//! One endpoint per identity accepts inbound connections and forwards every
//! framed [`Frame`] to a shared inbound channel; outbound sends dial the peer
//! (idempotently, reusing an open stream) and write length-prefixed frames.

use crate::endpoint::{build_endpoint, SYNC_ALPN};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use iroh::endpoint::{Connection, Incoming, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use roam_storage::Identity;
use roam_sync_core::frame::Frame;
use roam_sync_core::transport::{Transport, TransportError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;

/// Hard cap on a single frame's length prefix, to refuse an alloc-bomb from a
/// hostile 4-byte length (64 MiB is far above any real sync frame).
const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

/// How long `spawn` waits for the endpoint to discover at least one direct
/// address, so [`IrohTransport::endpoint_addr`] hands a peer something dialable
/// before n0 discovery has propagated (loopback / same-LAN tests).
const ADDR_READY_TIMEOUT: Duration = Duration::from_secs(8);

/// A per-peer cached send stream, wrapped so writes serialize without holding
/// the connection map lock across the network write.
type PeerStream = Arc<AsyncMutex<SendStream>>;

/// peer_id -> node key (== ed25519 verifying key == iroh NodeId).
type Routes = Arc<Mutex<HashMap<u64, [u8; 32]>>>;

/// Inbound frame sender, cloned into every accept/dial task.
type InboundTx = mpsc::UnboundedSender<(u64, Frame)>;

/// The paired inbound receiver, taken once by [`IrohTransport::incoming`].
type InboundRx = Arc<Mutex<Option<mpsc::UnboundedReceiver<(u64, Frame)>>>>;

/// peer_id -> the peer's currently-open inbound connection. Kept so a revoke
/// (`remove_route`) can force-close a formerly-roster peer's reader (T2).
type InboundConns = Arc<Mutex<HashMap<u64, Connection>>>;

/// iroh QUIC transport implementing [`Transport`].
pub struct IrohTransport {
    endpoint: Endpoint,
    /// peer_id -> node key (== ed25519 verifying key == iroh NodeId).
    routes: Routes,
    /// Optional direct addresses for dialing before discovery propagates
    /// (pairing / test seam).
    addrs: Arc<Mutex<HashMap<u64, EndpointAddr>>>,
    /// Cloned into every accept/dial task; forwards `(peer_id, frame)` inbound.
    inbound_tx: InboundTx,
    /// The paired receiver, taken once by [`IrohTransport::incoming`].
    inbound_rx: InboundRx,
    /// Per-peer open send stream, so `send` reuses one dial.
    conns: Arc<AsyncMutex<HashMap<u64, PeerStream>>>,
    /// Per-peer open INBOUND connection, so a revoke tears the reader down (T2).
    inbound_conns: InboundConns,
    /// Per-peer dial lock, so concurrent dials to the same peer open exactly one
    /// connection (and spawn exactly one reader) instead of racing.
    dialing: Arc<Mutex<HashMap<u64, Arc<AsyncMutex<()>>>>>,
    /// Handle to the accept loop, aborted on drop so a dropped transport does
    /// not leak the task (and its `Endpoint` clone).
    accept_task: tokio::task::JoinHandle<()>,
}

impl IrohTransport {
    /// Build the endpoint, store `routes`, and start the accept loop.
    pub async fn spawn(identity: &Identity, routes: HashMap<u64, [u8; 32]>) -> Result<Self> {
        let endpoint = build_endpoint(identity).await?;
        // Wait (bounded) for the endpoint to discover a direct address so that a
        // later `endpoint_addr()` is dialable on loopback before discovery lags.
        wait_for_direct_addr(&endpoint).await;
        crate::dlog!(
            "spawn: my addr={:?} routes={:?}",
            endpoint.addr(),
            routes.keys().collect::<Vec<_>>()
        );

        let routes = Arc::new(Mutex::new(routes));
        let inbound_conns: InboundConns = Arc::new(Mutex::new(HashMap::new()));
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();

        // Accept loop: one task per inbound connection.
        let accept_ep = endpoint.clone();
        let accept_routes = routes.clone();
        let accept_tx = inbound_tx.clone();
        let accept_conns = inbound_conns.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = accept_ep.accept().await {
                let routes = accept_routes.clone();
                let tx = accept_tx.clone();
                let inbound_conns = accept_conns.clone();
                tokio::spawn(async move {
                    // A teardown error (peer disconnect, reset) is expected and
                    // only ends this one connection's reader.
                    let _ = handle_conn(incoming, routes, tx, inbound_conns).await;
                });
            }
        });

        Ok(Self {
            endpoint,
            routes,
            addrs: Arc::new(Mutex::new(HashMap::new())),
            inbound_tx,
            inbound_rx: Arc::new(Mutex::new(Some(inbound_rx))),
            conns: Arc::new(AsyncMutex::new(HashMap::new())),
            inbound_conns,
            dialing: Arc::new(Mutex::new(HashMap::new())),
            accept_task,
        })
    }

    /// Seed a direct address for `peer` (dial before discovery propagates).
    pub async fn add_addr(&self, peer: u64, addr: EndpointAddr) {
        self.addrs.lock().unwrap().insert(peer, addr);
    }

    /// This endpoint's own address, to hand to a peer.
    ///
    /// iroh 1.0.0 CORRECTION vs the plan snippet: the method is `Endpoint::addr`
    /// (not `node_addr` / `endpoint_addr`).
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Resolve `peer` to a node key from the routes map.
    fn node_key(&self, peer: u64) -> Option<[u8; 32]> {
        self.routes.lock().unwrap().get(&peer).copied()
    }
}

impl Drop for IrohTransport {
    fn drop(&mut self) {
        // Abort the accept loop, which drops its `Endpoint` clone, so a dropped
        // transport does not leak the task or keep the endpoint alive. The
        // transport is not `Clone`, so this owner is the only one and aborts once.
        self.accept_task.abort();
    }
}

#[async_trait]
impl Transport for IrohTransport {
    async fn send(&self, peer: u64, frame: Frame) -> Result<(), TransportError> {
        self.dial(peer).await?;
        // Clone the per-peer stream handle, then drop the map lock before the
        // network write so a slow write never blocks other peers' sends.
        let stream = {
            let conns = self.conns.lock().await;
            conns.get(&peer).cloned()
        }
        .ok_or(TransportError::Unreachable(peer))?;

        let mut send = stream.lock().await;
        match write_frame(&mut send, &frame).await {
            Ok(()) => {
                crate::dlog!("send peer={peer} frame={}: ok", frame.kind());
                Ok(())
            }
            Err(e) => {
                crate::dlog!(
                    "send peer={peer} frame={}: FAILED ({e}); evicting conn",
                    frame.kind()
                );
                // The cached stream is dead (idle timeout, reset, peer restart).
                // Evict it so the NEXT `dial` opens a fresh connection instead of
                // reusing this corpse forever — otherwise a long-running daemon
                // silently stops syncing after any transient drop. Drop the send
                // guard before taking the map lock to avoid a lock-order inversion.
                drop(send);
                self.conns.lock().await.remove(&peer);
                Err(TransportError::Io(e.to_string()))
            }
        }
    }

    async fn dial(&self, peer: u64) -> Result<(), TransportError> {
        // Fast path: reuse a cached open stream (drop the map guard first).
        if self.conns.lock().await.contains_key(&peer) {
            return Ok(());
        }

        // Serialize dials to THIS peer so concurrent callers (e.g. the engine's
        // `connect` and a live-push `send`) open exactly one connection and spawn
        // exactly one reader. The std map lock is held only to clone the Arc.
        let dial_lock = {
            let mut dialing = self.dialing.lock().unwrap();
            dialing
                .entry(peer)
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let _dial_guard = dial_lock.lock().await;

        // Re-check under the per-peer dial lock: a concurrent dial may have
        // finished while we waited.
        if self.conns.lock().await.contains_key(&peer) {
            return Ok(());
        }

        let key = self
            .node_key(peer)
            .ok_or(TransportError::Unreachable(peer))?;
        let node_id =
            EndpointId::from_bytes(&key).map_err(|e| TransportError::Io(e.to_string()))?;
        // Prefer a seeded direct address; fall back to a bare node id (discovery).
        let seeded = self.addrs.lock().unwrap().get(&peer).cloned();
        let via = if seeded.is_some() {
            "seeded-addr"
        } else {
            "discovery"
        };
        let target = seeded.unwrap_or_else(|| EndpointAddr::new(node_id));
        crate::dlog!("dial peer={peer} via={via} node={node_id}: connecting…");

        let conn = match self.endpoint.connect(target, SYNC_ALPN).await {
            Ok(conn) => conn,
            Err(e) => {
                crate::dlog!("dial peer={peer} via={via}: connect FAILED: {e}");
                return Err(TransportError::Io(e.to_string()));
            }
        };
        let (send, recv) = match conn.open_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                crate::dlog!("dial peer={peer}: open_bi FAILED: {e}");
                return Err(TransportError::Io(e.to_string()));
            }
        };
        crate::dlog!("dial peer={peer} via={via}: connected, stream open");

        // Drain any frames the peer sends back on this connection.
        let tx = self.inbound_tx.clone();
        tokio::spawn(async move {
            let _ = read_loop(recv, peer, tx).await;
        });

        // Cache the send half; the per-peer dial lock guarantees no racing insert.
        self.conns
            .lock()
            .await
            .insert(peer, Arc::new(AsyncMutex::new(send)));
        Ok(())
    }

    fn incoming(&self) -> BoxStream<'static, (u64, Frame)> {
        let rx = self
            .inbound_rx
            .lock()
            .unwrap()
            .take()
            .expect("incoming() called once");
        futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        })
        .boxed()
    }

    async fn add_route(&self, peer: u64, key: [u8; 32]) {
        self.routes.lock().unwrap().insert(peer, key);
    }

    async fn remove_route(&self, peer: u64) {
        // Drop the route and any seeded direct address so a later `dial` cannot
        // resolve the peer, and drop our cached send half so we stop pushing to
        // it.
        self.routes.lock().unwrap().remove(&peer);
        self.addrs.lock().unwrap().remove(&peer);
        self.conns.lock().await.remove(&peer);

        // T2: force-close the revoked peer's still-open INBOUND connection so its
        // reader task ends. Without this, a peer that was in the roster when it
        // connected keeps its accepted connection alive and can keep flooding the
        // unbounded inbound channel with frames — the app layer discards them,
        // but the transport still decodes and enqueues each. Closing the
        // connection makes its `read_loop` error out and stop; a later reconnect
        // is refused at the accept-time roster gate (the route is gone). All
        // peer->this frames arrive on this inbound connection (a dialed
        // connection's reverse stream is unused), so this is the whole vector.
        if let Some(conn) = self.inbound_conns.lock().unwrap().remove(&peer) {
            conn.close(0u32.into(), b"revoked");
        }
    }
}

/// Handle one inbound connection: resolve its peer id, accept the bi stream,
/// and forward every frame it sends.
async fn handle_conn(
    incoming: Incoming,
    routes: Routes,
    tx: InboundTx,
    inbound_conns: InboundConns,
) -> Result<()> {
    let conn = incoming
        .accept()
        .context("accept inbound connection")?
        .await
        .context("complete inbound handshake")?;
    let remote = conn.remote_id();

    // Roster gate (spec §6): only accept inbound SYNC connections from a NodeId
    // already in `routes`. A stranger's key is refused HERE — before a reader
    // task is spawned or a single frame is forwarded — so a non-roster peer
    // cannot pin an accept task or flood the unbounded inbound channel with
    // frames the app layer would only discard after decoding. Confidentiality
    // never depended on this (replies route by NodeId and ops verify against
    // roster keys); this closes the DoS surface. Pairing runs on its own
    // endpoint over PAIRING_ALPN and never reaches this sync accept loop.
    if conn.alpn() != SYNC_ALPN || !routes_contains_key(&routes, remote.as_bytes()) {
        crate::dlog!("accept: REFUSED non-roster inbound (node={remote})");
        conn.close(0u32.into(), b"not in roster");
        return Ok(());
    }

    let peer = peer_id_for(&routes, &remote);
    crate::dlog!("accept: inbound connection from peer={peer} (node={remote})");

    // Register this connection so `remove_route` (revoke) can force-close it and
    // end this reader (T2). If the peer's route was concurrently removed, this
    // self-evicts and we stop before spawning the reader (see the fn).
    if !register_inbound_conn(peer, remote.as_bytes(), &conn, &routes, &inbound_conns) {
        return Ok(());
    }

    let (_send, recv) = conn.accept_bi().await.context("accept inbound bi stream")?;
    let result = read_loop(recv, peer, tx).await;
    crate::dlog!("accept: reader for peer={peer} ended ({result:?})");

    // Deregister — but only if we are still the current connection for this peer
    // (a reconnect or a revoke may have replaced/removed it already).
    {
        let mut map = inbound_conns.lock().unwrap();
        if map.get(&peer).map(Connection::stable_id) == Some(conn.stable_id()) {
            map.remove(&peer);
        }
    }
    result
}

/// Read length-prefixed frames until the stream closes, forwarding each with
/// its `peer` id to the inbound channel.
async fn read_loop(mut recv: RecvStream, peer: u64, tx: InboundTx) -> Result<()> {
    // A read error (clean EOF or reset) or a dropped receiver ends the loop.
    while let Ok(frame) = read_frame(&mut recv).await {
        crate::dlog!("recv peer={peer} frame={}", frame.kind());
        if tx.send((peer, frame)).is_err() {
            break;
        }
    }
    Ok(())
}

/// Whether `key` (a remote NodeId's 32 bytes) is a known route — i.e. the peer
/// is in this device's roster. The accept loop uses this to refuse strangers.
fn routes_contains_key(routes: &Routes, key: &[u8]) -> bool {
    routes
        .lock()
        .unwrap()
        .values()
        .any(|node_key| node_key.as_slice() == key)
}

/// Register `conn` as `peer`'s current inbound connection so a later
/// `remove_route` (revoke) can force-close it (T2). A reconnect supersedes and
/// closes the prior connection so a peer can't hold two live readers. Returns
/// `true` if the caller should keep reading; `false` if it must drop `conn`.
fn register_inbound_conn(
    peer: u64,
    remote_key: &[u8],
    conn: &Connection,
    routes: &Routes,
    inbound_conns: &InboundConns,
) -> bool {
    if let Some(old) = inbound_conns.lock().unwrap().insert(peer, conn.clone()) {
        if old.stable_id() != conn.stable_id() {
            old.close(0u32.into(), b"superseded by reconnect");
        }
    }
    // M-B: revoke-vs-reconnect TOCTOU. A reconnect can pass the accept-time gate
    // just before `remove_route` drops the route, then land this insert just
    // after `remove_route` scanned `inbound_conns` — surviving revoke with a live
    // reader. `remove_route` removes the route BEFORE it scans the map, so if that
    // scan missed our insert, the route is already gone: recheck here and
    // self-evict, closing the window.
    if !routes_contains_key(routes, remote_key) {
        let mut map = inbound_conns.lock().unwrap();
        if map.get(&peer).map(Connection::stable_id) == Some(conn.stable_id()) {
            map.remove(&peer);
        }
        conn.close(0u32.into(), b"revoked (raced reconnect)");
        return false;
    }
    true
}

/// Map an authenticated remote [`EndpointId`] back to a loro `peer_id`.
///
/// Prefer the routes map (the authoritative peer_id -> key mapping); fall back
/// to the first 8 little-endian bytes of the node key, matching how
/// `Identity::generate` derives a peer id from its verifying key.
fn peer_id_for(routes: &Routes, remote: &EndpointId) -> u64 {
    let key = remote.as_bytes();
    if let Some((peer, _)) = routes
        .lock()
        .unwrap()
        .iter()
        .find(|(_, node_key)| node_key.as_slice() == key.as_slice())
    {
        return *peer;
    }
    u64::from_le_bytes(key[0..8].try_into().expect("node key is 32 bytes"))
}

/// Write a frame as `len(4, big-endian) || postcard(frame)`.
async fn write_frame(send: &mut SendStream, frame: &Frame) -> Result<()> {
    let body = frame.encode();
    let len = u32::try_from(body.len())
        .context("frame too large to length-prefix")?
        .to_be_bytes();
    send.write_all(&len).await.context("write frame length")?;
    send.write_all(&body).await.context("write frame body")?;
    Ok(())
}

/// Read one length-prefixed, postcard-encoded frame.
async fn read_frame(recv: &mut RecvStream) -> Result<Frame> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("read frame length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(len <= MAX_FRAME_LEN, "frame length {len} exceeds cap");
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .context("read frame body")?;
    Frame::decode(&body).context("decode postcard frame")
}

/// Best-effort wait for the endpoint to discover a direct address.
async fn wait_for_direct_addr(endpoint: &Endpoint) {
    let deadline = tokio::time::Instant::now() + ADDR_READY_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        if endpoint.addr().ip_addrs().next().is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use roam_storage::Identity;
    use roam_sync_core::{Frame, Transport};
    use std::collections::HashMap;

    #[tokio::test(flavor = "multi_thread")]
    async fn two_iroh_transports_exchange_a_frame() {
        let id_a = Identity::generate();
        let id_b = Identity::generate();

        // Roster maps peer_id -> (verifying_key == NodeId). Both know each other.
        let mut routes_a = HashMap::new();
        routes_a.insert(id_b.peer_id(), id_b.verifying_key().to_bytes());
        let mut routes_b = HashMap::new();
        routes_b.insert(id_a.peer_id(), id_a.verifying_key().to_bytes());

        let ta = IrohTransport::spawn(&id_a, routes_a).await.unwrap();
        let tb = IrohTransport::spawn(&id_b, routes_b).await.unwrap();
        // Seed each other's direct addr (discovery may lag in-test).
        ta.add_addr(id_b.peer_id(), tb.endpoint_addr()).await;
        tb.add_addr(id_a.peer_id(), ta.endpoint_addr()).await;

        let mut b_in = tb.incoming();
        ta.dial(id_b.peer_id()).await.unwrap();
        ta.send(id_b.peer_id(), Frame::Ping).await.unwrap();

        let (from, frame) = tokio::time::timeout(std::time::Duration::from_secs(10), b_in.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from, id_a.peer_id());
        assert_eq!(frame, Frame::Ping);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_inbound_sync_connection_from_a_non_roster_peer_is_refused() {
        // Transport DoS (spec §6): the accept loop must reject inbound SYNC
        // connections whose NodeId is not in `routes`. Otherwise any stranger who
        // learns the NodeId can open a connection, pin an accept task, and flood
        // the unbounded inbound channel with frames the app layer only discards
        // later. Gating at accept — before a reader is spawned — closes that.
        let host = Identity::generate();
        let stranger = Identity::generate();

        // Host knows NOBODY. The stranger knows the host (so it can dial).
        let host_t = IrohTransport::spawn(&host, HashMap::new()).await.unwrap();
        let mut routes_s = HashMap::new();
        routes_s.insert(host.peer_id(), host.verifying_key().to_bytes());
        let stranger_t = IrohTransport::spawn(&stranger, routes_s).await.unwrap();
        stranger_t
            .add_addr(host.peer_id(), host_t.endpoint_addr())
            .await;

        let mut host_in = host_t.incoming();
        // The stranger dials the host and pushes a frame.
        stranger_t.dial(host.peer_id()).await.unwrap();
        let _ = stranger_t.send(host.peer_id(), Frame::Ping).await;

        // The host must NOT surface the stranger's frame — the connection was
        // refused at accept, so nothing reaches the inbound channel.
        let got = tokio::time::timeout(Duration::from_secs(2), host_in.next()).await;
        assert!(
            got.is_err(),
            "a frame from a non-roster peer must not reach the inbound channel: {got:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn revoking_a_peer_tears_down_its_still_open_inbound_reader() {
        // T2: `remove_route` must force-close a formerly-roster peer's inbound
        // connection, ending its reader task. Otherwise a revoked peer keeps its
        // accepted connection open and can keep flooding the unbounded inbound
        // channel with frames — the app layer discards them, but the transport
        // still pays to decode and enqueue each one (the same DoS the accept-time
        // roster gate closes for strangers, but reachable by a peer that was in
        // the roster when it connected).
        let host = Identity::generate();
        let peer = Identity::generate();

        let mut routes_host = HashMap::new();
        routes_host.insert(peer.peer_id(), peer.verifying_key().to_bytes());
        let mut routes_peer = HashMap::new();
        routes_peer.insert(host.peer_id(), host.verifying_key().to_bytes());

        let host_t = IrohTransport::spawn(&host, routes_host).await.unwrap();
        let peer_t = IrohTransport::spawn(&peer, routes_peer).await.unwrap();
        peer_t
            .add_addr(host.peer_id(), host_t.endpoint_addr())
            .await;

        let mut host_in = host_t.incoming();
        // The peer (still in the roster) dials and pushes a frame; the host's
        // inbound reader is now live and surfaces it.
        peer_t.dial(host.peer_id()).await.unwrap();
        peer_t.send(host.peer_id(), Frame::Ping).await.unwrap();
        let first = tokio::time::timeout(Duration::from_secs(10), host_in.next())
            .await
            .expect("the first frame from a roster peer must arrive")
            .unwrap();
        assert_eq!(first, (peer.peer_id(), Frame::Ping));

        // Revoke the peer: this must tear the inbound connection down.
        host_t.remove_route(peer.peer_id()).await;

        // The peer keeps pushing on its cached stream, but the host's reader is
        // gone (connection closed) and a fresh dial would be refused at accept —
        // so nothing more reaches the inbound channel.
        for _ in 0..5 {
            let _ = peer_t.send(host.peer_id(), Frame::Ping).await;
        }
        let after = tokio::time::timeout(Duration::from_secs(2), host_in.next()).await;
        assert!(
            after.is_err(),
            "a revoked peer's frames must not reach the inbound channel: {after:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn registering_an_inbound_conn_whose_route_was_removed_self_evicts() {
        // M-B: revoke-vs-reconnect TOCTOU. A reconnect can pass the accept-time
        // roster gate just BEFORE `remove_route` drops the route, then register
        // its connection just AFTER `remove_route` scanned `inbound_conns` —
        // leaving a live reader for a revoked peer (the exact flood T2 closes).
        // Because `remove_route` removes the route before it scans the map, a
        // post-insert route recheck catches the race. Drive that recheck directly:
        // a real connection registered while the peer is NOT in `routes` must be
        // closed and never retained.
        use std::sync::{Arc, Mutex};

        let host = Identity::generate();
        let peer = Identity::generate();
        let mut routes_host = HashMap::new();
        routes_host.insert(peer.peer_id(), peer.verifying_key().to_bytes());
        let mut routes_peer = HashMap::new();
        routes_peer.insert(host.peer_id(), host.verifying_key().to_bytes());
        let host_t = IrohTransport::spawn(&host, routes_host).await.unwrap();
        let peer_t = IrohTransport::spawn(&peer, routes_peer).await.unwrap();
        peer_t
            .add_addr(host.peer_id(), host_t.endpoint_addr())
            .await;

        let mut host_in = host_t.incoming();
        peer_t.dial(host.peer_id()).await.unwrap();
        peer_t.send(host.peer_id(), Frame::Ping).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(10), host_in.next())
            .await
            .expect("the peer's first frame must arrive")
            .unwrap();

        // Grab the real inbound Connection the host registered for the peer.
        let conn = host_t
            .inbound_conns
            .lock()
            .unwrap()
            .get(&peer.peer_id())
            .cloned()
            .expect("peer's inbound conn is registered");

        // Simulate the raced final state: the route is already gone when the
        // late reconnect registers into a fresh map.
        let empty_routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let empty_inbound: InboundConns = Arc::new(Mutex::new(HashMap::new()));
        let keep = register_inbound_conn(
            peer.peer_id(),
            &peer.verifying_key().to_bytes(),
            &conn,
            &empty_routes,
            &empty_inbound,
        );
        assert!(!keep, "a conn whose route is gone must not keep reading");
        assert!(
            empty_inbound.lock().unwrap().is_empty(),
            "the raced conn must be evicted, not left as a live reader"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn add_route_makes_a_peer_dialable_and_remove_route_undoes_it() {
        let id = Identity::generate();
        let peer = Identity::generate();
        // Spawn with EMPTY routes: the peer is unknown to the transport.
        let transport = IrohTransport::spawn(&id, HashMap::new()).await.unwrap();

        // No route yet → dial is refused immediately with Unreachable.
        assert!(matches!(
            transport.dial(peer.peer_id()).await,
            Err(TransportError::Unreachable(_))
        ));

        // Learn the route: dial now resolves the peer and attempts a real connect
        // (which never completes here — no address is seeded and discovery finds
        // nothing), so it must NOT be an immediate Unreachable. A bounded timeout
        // distinguishes "got past route resolution" (pending or a slow connect
        // error) from the instant Unreachable refusal.
        transport
            .add_route(peer.peer_id(), peer.verifying_key().to_bytes())
            .await;
        let dial =
            tokio::time::timeout(Duration::from_millis(300), transport.dial(peer.peer_id())).await;
        match dial {
            // Still attempting to connect ⇒ the route resolved. Good.
            Err(_elapsed) => {}
            Ok(Err(TransportError::Unreachable(_))) => {
                panic!("route was added but dial still returned Unreachable")
            }
            // A non-Unreachable connect error also means we got past resolution.
            Ok(other) => {
                let _ = other;
            }
        }

        // Forget the route: dial is refused with Unreachable again.
        transport.remove_route(peer.peer_id()).await;
        let after =
            tokio::time::timeout(Duration::from_millis(300), transport.dial(peer.peer_id())).await;
        assert!(
            matches!(after, Ok(Err(TransportError::Unreachable(_)))),
            "remove_route did not undo the route: {after:?}"
        );
    }
}
