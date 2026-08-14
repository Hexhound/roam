//! roam-wasm — the browser-facing façade over `roam-crdt`.
//!
//! Two layers, deliberately split:
//!
//! * [`Doc`] — plain Rust, no `wasm_bindgen`, returns `CrdtError`. This is the
//!   real logic and the thing native tests exercise.
//! * `bindings` — the `#[wasm_bindgen]` shim, compiled only for wasm32. It is
//!   pure delegation to [`Doc`]; it holds no logic of its own so that nothing
//!   interesting can only be tested through a browser.

mod doc;
mod vault;

pub use doc::Doc;
pub use vault::Vault;

#[cfg(target_arch = "wasm32")]
mod bindings;

// Test double for the node acceptance harness; never in a shipped build.
#[cfg(all(target_arch = "wasm32", feature = "test-relay"))]
mod relay;
