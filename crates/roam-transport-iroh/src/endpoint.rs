//! The single iroh endpoint per device identity.

use anyhow::{Context, Result};
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use roam_storage::Identity;

/// The sync ALPN. A pairing ALPN is added in the pairing task.
pub const SYNC_ALPN: &[u8] = b"roam/sync/1";

/// Build the ONE iroh endpoint for this device, bound to the SAME ed25519 key
/// as `identity` (so the iroh `NodeId` equals the ed25519 verifying key), with
/// iroh's default n0 discovery (mDNS + n0 DNS/pkarr + relay).
///
/// **Exactly one endpoint per identity.** iroh keeps a single
/// `node_id -> endpoint` route at the relay, so a second endpoint bound to the
/// same key hijacks that route and silently kills inbound sync on the first.
pub async fn build_endpoint(identity: &Identity) -> Result<Endpoint> {
    // `SecretKey::from_bytes` is infallible in iroh 1.0.0 (it clamps the
    // scalar), so the SAME 32 secret bytes always yield the SAME NodeId.
    let secret = SecretKey::from_bytes(&identity.secret_bytes());
    // iroh 1.0.0 CORRECTION vs the plan snippet: there is no `Endpoint::builder()`
    // zero-arg constructor nor a `.discovery_n0()` method. Discovery is selected
    // via a preset passed to `Endpoint::builder(..)`; `presets::N0` wires the
    // full n0 discovery + relay stack (see the outl reference `bind.rs`).
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(vec![SYNC_ALPN.to_vec()])
        .bind()
        .await
        .context("bind roam sync endpoint")?;
    Ok(endpoint)
}
