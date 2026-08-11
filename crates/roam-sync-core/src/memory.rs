use crate::frame::Frame;
use crate::transport::{Transport, TransportError};
use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// One demuxed inbound frame: `(sender_peer_id, frame)`.
type Inbound = (u64, Frame);
/// Shared map from a registered peer to the sender feeding its inbox.
type Inboxes = Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<Inbound>>>>;

/// In-process transport for tests: a shared switchboard routes frames between
/// registered peers with no network. Deliberately not a `Transport` for the
/// switchboard itself — each peer gets an [`Endpoint`] handle that is.
#[derive(Clone, Default)]
pub struct MemorySwitchboard {
    inbounds: Inboxes,
}

impl MemorySwitchboard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `peer` and get its transport endpoint.
    ///
    /// Permissive mode: routes are ignored (the switchboard is a pure
    /// switchboard), so `send`/`dial` reach any registered peer.
    pub fn endpoint(&self, peer: u64) -> MemoryTransport {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inbounds.lock().unwrap().insert(peer, tx);
        MemoryTransport {
            me: peer,
            board: self.clone(),
            rx: Arc::new(Mutex::new(Some(rx))),
            known: None,
        }
    }

    /// Register `peer` and get a route-enforcing (strict) transport endpoint.
    ///
    /// Opt-in seam for testing the engine's route wiring: `send`/`dial` to a
    /// peer NOT in the endpoint's `known` set return
    /// [`TransportError::Unreachable`]. `known` is seeded with `known` and grows
    /// only via [`Transport::add_route`] (shrinks via [`Transport::remove_route`]).
    pub fn strict_endpoint(&self, peer: u64, known: &[u64]) -> MemoryTransport {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inbounds.lock().unwrap().insert(peer, tx);
        MemoryTransport {
            me: peer,
            board: self.clone(),
            rx: Arc::new(Mutex::new(Some(rx))),
            known: Some(Arc::new(Mutex::new(known.iter().copied().collect()))),
        }
    }
}

pub struct MemoryTransport {
    me: u64,
    board: MemorySwitchboard,
    rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<Inbound>>>>,
    /// Reachable-peer set in strict mode; `None` = permissive (reach anyone).
    known: Option<Arc<Mutex<HashSet<u64>>>>,
}

impl MemoryTransport {
    /// In strict mode, whether `peer` is currently reachable. Permissive mode
    /// reaches everyone.
    fn reachable(&self, peer: u64) -> bool {
        match &self.known {
            None => true,
            Some(known) => known.lock().unwrap().contains(&peer),
        }
    }
}

#[async_trait]
impl Transport for MemoryTransport {
    async fn send(&self, peer: u64, frame: Frame) -> Result<(), TransportError> {
        if !self.reachable(peer) {
            return Err(TransportError::Unreachable(peer));
        }
        let tx = {
            let map = self.board.inbounds.lock().unwrap();
            map.get(&peer)
                .cloned()
                .ok_or(TransportError::Unreachable(peer))?
        };
        tx.send((self.me, frame))
            .map_err(|_| TransportError::Closed)
    }

    async fn dial(&self, peer: u64) -> Result<(), TransportError> {
        if !self.reachable(peer) {
            return Err(TransportError::Unreachable(peer));
        }
        if self.board.inbounds.lock().unwrap().contains_key(&peer) {
            Ok(())
        } else {
            Err(TransportError::Unreachable(peer))
        }
    }

    fn incoming(&self) -> BoxStream<'static, (u64, Frame)> {
        let rx = self
            .rx
            .lock()
            .unwrap()
            .take()
            .expect("incoming() called once");
        tokio_stream_wrapper(rx).boxed()
    }

    async fn add_route(&self, peer: u64, key: [u8; 32]) {
        let _ = key;
        if let Some(known) = &self.known {
            known.lock().unwrap().insert(peer);
        }
    }

    async fn remove_route(&self, peer: u64) {
        if let Some(known) = &self.known {
            known.lock().unwrap().remove(&peer);
        }
    }
}

fn tokio_stream_wrapper(
    rx: mpsc::UnboundedReceiver<Inbound>,
) -> impl futures::Stream<Item = Inbound> {
    futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delivers_frames_between_two_endpoints() {
        let board = MemorySwitchboard::new();
        let a = board.endpoint(1);
        let b = board.endpoint(2);
        let mut b_in = b.incoming();

        a.dial(2).await.unwrap();
        a.send(2, Frame::Ping).await.unwrap();

        let (from, frame) = b_in.next().await.unwrap();
        assert_eq!(from, 1);
        assert_eq!(frame, Frame::Ping);
    }

    #[tokio::test]
    async fn send_to_unknown_peer_errors() {
        let board = MemorySwitchboard::new();
        let a = board.endpoint(1);
        assert!(matches!(
            a.send(99, Frame::Ping).await,
            Err(TransportError::Unreachable(99))
        ));
    }
}
