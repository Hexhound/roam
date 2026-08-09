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
use iroh::endpoint::{Incoming, RecvStream, SendStream};
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

        let routes = Arc::new(Mutex::new(routes));
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();

        // Accept loop: one task per inbound connection.
        let accept_ep = endpoint.clone();
        let accept_routes = routes.clone();
        let accept_tx = inbound_tx.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = accept_ep.accept().await {
                let routes = accept_routes.clone();
                let tx = accept_tx.clone();
                tokio::spawn(async move {
                    // A teardown error (peer disconnect, reset) is expected and
                    // only ends this one connection's reader.
                    let _ = handle_conn(incoming, routes, tx).await;
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
        write_frame(&mut send, &frame)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))
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

        let key = self.node_key(peer).ok_or(TransportError::Unreachable(peer))?;
        let node_id =
            EndpointId::from_bytes(&key).map_err(|e| TransportError::Io(e.to_string()))?;
        // Prefer a seeded direct address; fall back to a bare node id (discovery).
        let target = self
            .addrs
            .lock()
            .unwrap()
            .get(&peer)
            .cloned()
            .unwrap_or_else(|| EndpointAddr::new(node_id));

        let conn = self
            .endpoint
            .connect(target, SYNC_ALPN)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;

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
        // resolve the peer, then tear down the cached send stream so the revoked
        // peer's live stream is closed.
        self.routes.lock().unwrap().remove(&peer);
        self.addrs.lock().unwrap().remove(&peer);
        self.conns.lock().await.remove(&peer);
    }
}

/// Handle one inbound connection: resolve its peer id, accept the bi stream,
/// and forward every frame it sends.
async fn handle_conn(incoming: Incoming, routes: Routes, tx: InboundTx) -> Result<()> {
    let conn = incoming
        .accept()
        .context("accept inbound connection")?
        .await
        .context("complete inbound handshake")?;
    let remote = conn.remote_id();
    let peer = peer_id_for(&routes, &remote);
    let (_send, recv) = conn.accept_bi().await.context("accept inbound bi stream")?;
    read_loop(recv, peer, tx).await
}

/// Read length-prefixed frames until the stream closes, forwarding each with
/// its `peer` id to the inbound channel.
async fn read_loop(mut recv: RecvStream, peer: u64, tx: InboundTx) -> Result<()> {
    // A read error (clean EOF or reset) or a dropped receiver ends the loop.
    while let Ok(frame) = read_frame(&mut recv).await {
        if tx.send((peer, frame)).is_err() {
            break;
        }
    }
    Ok(())
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

        let (from, frame) =
            tokio::time::timeout(std::time::Duration::from_secs(10), b_in.next())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(from, id_a.peer_id());
        assert_eq!(frame, Frame::Ping);
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
        let dial = tokio::time::timeout(
            Duration::from_millis(300),
            transport.dial(peer.peer_id()),
        )
        .await;
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
        let after = tokio::time::timeout(
            Duration::from_millis(300),
            transport.dial(peer.peer_id()),
        )
        .await;
        assert!(
            matches!(after, Ok(Err(TransportError::Unreachable(_)))),
            "remove_route did not undo the route: {after:?}"
        );
    }
}
