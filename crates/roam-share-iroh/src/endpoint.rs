//! The endpoint a share runs over.

use crate::wire::SHARE_ALPN;
use anyhow::{Context, Result};
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};

/// Bind a one-shot endpoint for a single share, under a **fresh random key**.
///
/// Two decisions worth stating:
///
/// * **Not the device identity.** An iroh endpoint id *is* the key it was bound
///   to, and a share is announced on the local network for anyone to see. Using
///   the device's long-term key would turn every "send my colleague a photo"
///   into a broadcast of a stable, linkable device identifier. A share needs no
///   long-term identity — the code authenticates it — so it gets none.
/// * **`presets::Minimal`.** No relay, no pkarr, no DNS. Sharing is a same-room
///   activity and must work with the internet unplugged; anything else would
///   make a LAN transfer depend on servers that need not be involved.
pub async fn bind_share_endpoint() -> Result<Endpoint> {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(vec![SHARE_ALPN.to_vec()])
        .bind()
        .await
        .context("bind share endpoint")
}
