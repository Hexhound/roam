//! Joining a device into a vault, independent of what moves the bytes.
//!
//! roam has three pairing flows and they differ only in their channel and their
//! authenticator:
//!
//! | flow | channel | authenticated by |
//! |---|---|---|
//! | token (`roam-transport-iroh::pairing`) | QUIC, dialled | a 256-bit bearer secret in a QR |
//! | LAN (`roam-transport-iroh::pairing_lan`) | QUIC, found over mDNS | a six-digit code, via SPAKE2 |
//! | mailbox ([`handshake`]) | HTTP through the relay | a six-digit code, via SPAKE2 |
//!
//! Everything they have in common lives here: the [`JoinAccept`] payload, the
//! order it must be applied in ([`adopt_accept`]), the host-side enrolment that
//! must precede it ([`enrol_joiner`]), and — for the third flow, which has no
//! transport to dial — the whole handshake.
//!
//! The mailbox flow is the one that lets a browser join a vault at all. A tab
//! cannot open a UDP socket, so it can never be an iroh peer; without a
//! relay-carried handshake a web client could hold a vault and sync it but could
//! never be let into one in the first place.
//!
//! # Deliberately not iroh
//!
//! This crate has no iroh dependency and compiles for `wasm32`. That is the
//! whole point: the join *algorithm* was never network-specific, only the
//! rendezvous was, and keeping the algorithm in one wasm-portable place is what
//! stops the browser from growing a second, subtly different one.

pub mod accept;
pub mod handshake;
pub mod invite;
pub mod mailbox;

pub use accept::{adopt_accept, enrol_joiner, JoinAccept, Joined};
pub use handshake::{host_via_mailbox, join_via_mailbox, MailboxHost, PakeError};
pub use invite::Invite;
pub use mailbox::{Mailbox, MemoryMailbox, Slot, SlotOutcome};
pub use roam_pake::{PairingCode, MAX_ATTEMPTS};

use std::time::Duration;

/// `Send + Sync` natively, no bound at all on wasm32.
///
/// Same reasoning as `roam_backend_client::transport::MaybeSendSync`: a browser
/// mailbox drives `fetch`, so it holds `JsValue`s and its futures are
/// unavoidably `!Send`. Native builds keep the full guarantee. This works
/// because [`Mailbox`] is used through a generic parameter, never as
/// `dyn Mailbox` — auto traits do not leak through a named supertrait onto a
/// trait object, so if a `dyn Mailbox` ever appears the bound must be spelled
/// out there rather than removed here.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSendSync: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> MaybeSendSync for T {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSendSync {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSendSync for T {}

/// Wait, portably.
///
/// `tokio::time` is not available on the bare wasm target, and neither is
/// `std::time::Instant` — see [`roam_storage::wallclock`] for the same problem
/// with the clock. The browser answer is `setTimeout`, which exists in a page
/// and in a worker alike.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn sleep(duration: Duration) {
    use wasm_bindgen::prelude::*;
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        // `setTimeout` is on the global in both a window and a worker, but it is
        // reached through different web-sys types. Going through the global by
        // name avoids having to know which one we are in.
        let set_timeout = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .expect("a JS host without setTimeout cannot run roam");
        let set_timeout: js_sys::Function = set_timeout.unchecked_into();
        let _ = set_timeout.call2(
            &global,
            &resolve,
            &JsValue::from_f64(duration.as_millis() as f64),
        );
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// A deadline `window` from now, in epoch milliseconds.
///
/// This is a *wall* clock, because the bare wasm target has no monotonic one.
/// The consequence is honest and small: a clock step during a pairing shortens
/// or lengthens the window. Nothing security-critical rests on it — the attempt
/// budget is what bounds guessing, and it is a count, not a duration. A window
/// that ends early shows the user a timeout; one that ends late leaves a code
/// showing slightly longer, still capped at three guesses.
pub(crate) fn deadline_from_now(window: Duration) -> i64 {
    roam_storage::wallclock::now_ms().saturating_add(window.as_millis() as i64)
}

pub(crate) fn past(deadline_ms: i64) -> bool {
    roam_storage::wallclock::now_ms() >= deadline_ms
}
