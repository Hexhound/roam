//! iroh QUIC implementation of the `roam-sync-core` `Transport` trait.

/// Opt-in diagnostics: prints to stderr with a `[transport]` prefix only when
/// the `ROAM_DEBUG` env var is set. Zero cost (one env lookup) when off.
#[macro_export]
macro_rules! dlog {
    ($($arg:tt)*) => {
        if ::std::env::var_os("ROAM_DEBUG").is_some() {
            ::std::eprintln!("[transport] {}", format!($($arg)*));
        }
    };
}

pub mod discovery;
pub mod endpoint;
pub mod pairing;
pub mod pairing_lan;
pub mod transport;

pub use endpoint::{
    build_endpoint, build_endpoint_with, BoundEndpoint, EndpointConfig, LanMode, RelayChoice,
    PAIRING_ALPN, SYNC_ALPN,
};
pub use pairing::{host_pairing, join_pairing, PairingToken};
pub use pairing_lan::{host_lan_pairing, join_lan_pairing, PAIRING_LAN_ALPN};
pub use transport::IrohTransport;
