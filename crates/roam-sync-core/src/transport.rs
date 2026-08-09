use crate::frame::Frame;
use async_trait::async_trait;
use futures::stream::BoxStream;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("peer not reachable: {0}")]
    Unreachable(u64),
    #[error("transport closed")]
    Closed,
    #[error("io error: {0}")]
    Io(String),
}

/// A dumb pipe between paired peers. All sync logic lives above this in the
/// engine; a transport only moves framed messages and manages connections.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send one frame to `peer`, connecting if necessary.
    async fn send(&self, peer: u64, frame: Frame) -> Result<(), TransportError>;

    /// Ensure a connection to `peer` exists (idempotent).
    async fn dial(&self, peer: u64) -> Result<(), TransportError>;

    /// Inbound frames from all peers, demuxed with their peer id.
    fn incoming(&self) -> BoxStream<'static, (u64, Frame)>;

    /// Learn how to reach `peer` (its node key). Idempotent. Default: no-op.
    async fn add_route(&self, peer: u64, key: [u8; 32]) {
        let _ = (peer, key);
    }

    /// Forget `peer` (revoked / gone): stop dialing it and drop any cached
    /// connection. Default: no-op.
    async fn remove_route(&self, peer: u64) {
        let _ = peer;
    }
}
