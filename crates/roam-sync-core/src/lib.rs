/// Opt-in diagnostics: prints to stderr with an `[engine]` prefix only when the
/// `ROAM_DEBUG` env var is set. Zero cost (one env lookup) when off.
#[macro_export]
macro_rules! dlog {
    ($($arg:tt)*) => {
        if ::std::env::var_os("ROAM_DEBUG").is_some() {
            ::std::eprintln!("[engine] {}", format!($($arg)*));
        }
    };
}

pub mod engine;
pub mod frame;
pub mod memory;
pub mod transport;

pub use frame::Frame;
pub use transport::{Transport, TransportError};
