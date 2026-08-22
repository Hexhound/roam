//! The single iroh endpoint per device identity.

use anyhow::{Context, Result};
use iroh::endpoint::presets;
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey};
use roam_storage::Identity;

use crate::discovery::LanDiscovery;

/// The sync ALPN — long-lived op/roster gossip.
pub const SYNC_ALPN: &[u8] = b"roam/sync/1";

/// The pairing ALPN — the one-shot trust-bootstrap handshake (see
/// [`crate::pairing`]). Bound alongside [`SYNC_ALPN`] so a single live endpoint
/// can also serve pairing (the GUI path), while the CLI/test path binds a
/// one-shot endpoint that happens to carry both ALPNs.
pub const PAIRING_ALPN: &[u8] = b"roam/pair/1";

/// How much of the local network this endpoint takes part in.
///
/// mDNS is the only way two devices on the same Wi-Fi reach each other with no
/// internet at all: `presets::N0` resolves through pkarr, DNS and relays, every
/// one of which needs the public internet.
///
/// ## Which one an app should pick
///
/// **[`LanMode::Advertise`] whenever sync is on.** Choosing between LAN, relay
/// and direct internet is iroh's job, not the user's: a device announces itself,
/// the other one resolves it, and iroh takes the best path it can find. Making
/// that a setting would ask the user to answer a question they have no way to
/// evaluate ("is this network one where mDNS helps?") and would leave sync
/// mysteriously slow, or dead offline, whenever they guessed wrong.
///
/// The other two levels exist for the case where an app has a *reason* to hold
/// back, because browsing and advertising have different costs. An iroh
/// `EndpointId` **is** the device's long-term ed25519 public key, so advertising
/// republishes a stable, unique device identifier to every machine on the
/// network — on a home network that is the point; on café Wi-Fi it is a beacon
/// that links the device (and its owner) across every network it ever joins.
/// [`LanMode::Browse`] is the middle ground: it publishes nothing, and is
/// useful for looking at what is on a network without joining it. What it
/// cannot do is make this device reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LanMode {
    /// No mDNS at all. Discovery is whatever the relay/pkarr stack provides.
    #[default]
    Off,

    /// Listen for other roam devices, publish nothing about this one.
    ///
    /// Passive and leak-free, but note what it cannot do: a peer is only
    /// *reachable* over the LAN if it advertises its own addresses, so two
    /// devices that both merely browse will never connect.
    Browse,

    /// Browse *and* publish this device's endpoint id and addresses.
    ///
    /// Required on both sides for a LAN-direct connection, and the level a
    /// syncing app should run at: with it, two devices on one Wi-Fi take the
    /// direct path and fall back to a relay elsewhere, without anyone choosing.
    Advertise,
}

impl LanMode {
    /// Whether this mode runs mDNS at all.
    fn is_on(self) -> bool {
        !matches!(self, LanMode::Off)
    }

    /// Whether this mode publishes anything about the device.
    fn advertises(self) -> bool {
        matches!(self, LanMode::Advertise)
    }
}

/// Which iroh relays this endpoint uses for hole-punching and fallback.
///
/// Relays carry no roam plaintext: they introduce two QUIC endpoints to each
/// other and ferry packets when no direct path can be established. Everything
/// roam sends is sealed before it reaches one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RelayChoice {
    /// n0's public relays — iroh's default, and what runs until roam has its
    /// own.
    #[default]
    N0,

    /// Self-hosted relays, preferred in the order given.
    Custom(Vec<RelayUrl>),

    /// No relays: direct paths only. Combined with [`LanMode::Advertise`] this
    /// is a configuration that never touches the public internet.
    Disabled,
}

/// Everything about an endpoint a caller might reasonably want to choose.
#[derive(Debug, Clone, Default)]
pub struct EndpointConfig {
    pub lan: LanMode,
    pub relay: RelayChoice,
}

impl EndpointConfig {
    /// n0 relays, no mDNS — what [`build_endpoint`] has always done.
    pub fn n0() -> Self {
        Self::default()
    }

    /// Same-network operation with no internet: mDNS both ways, no relays.
    pub fn lan_only() -> Self {
        Self {
            lan: LanMode::Advertise,
            relay: RelayChoice::Disabled,
        }
    }

    /// Relays *and* LAN, so a pair on one Wi-Fi takes the direct path while the
    /// same pair on different networks still connects. What a consumer app
    /// wants once the user has opted into local discovery.
    pub fn n0_with_lan() -> Self {
        Self {
            lan: LanMode::Advertise,
            relay: RelayChoice::N0,
        }
    }

    pub fn with_lan(mut self, lan: LanMode) -> Self {
        self.lan = lan;
        self
    }

    pub fn with_relay(mut self, relay: RelayChoice) -> Self {
        self.relay = relay;
        self
    }
}

/// A bound endpoint, plus whatever LAN discovery was attached to it.
///
/// The [`LanDiscovery`] handle is kept here on purpose: dropping it stops the
/// mDNS service, which silently ends both advertising and LAN resolution.
/// Holding this value for as long as the endpoint is in use is the contract.
pub struct BoundEndpoint {
    pub endpoint: Endpoint,

    /// `None` when [`LanMode::Off`] was asked for — **or** when mDNS could not
    /// start; see [`build_endpoint_with`].
    pub lan: Option<LanDiscovery>,
}

impl BoundEndpoint {
    /// Whether mDNS is actually running, as opposed to having been requested.
    pub fn has_lan(&self) -> bool {
        self.lan.is_some()
    }
}

/// Build the ONE iroh endpoint for this device, bound to the SAME ed25519 key
/// as `identity` (so the iroh `NodeId` equals the ed25519 verifying key), with
/// iroh's default n0 discovery: pkarr publish + pkarr/DNS resolve + relay.
///
/// No mDNS, so no LAN-direct path and nothing works without the public
/// internet. Kept as the bare default only because it is what this function has
/// always done and roam-cli/share-iroh rely on it; **a syncing app should call
/// [`build_endpoint_with`] with [`EndpointConfig::n0_with_lan`]**, which adds
/// local discovery and leaves the LAN-vs-relay choice to iroh.
///
/// **Exactly one endpoint per identity.** iroh keeps a single
/// `node_id -> endpoint` route at the relay, so a second endpoint bound to the
/// same key hijacks that route and silently kills inbound sync on the first.
pub async fn build_endpoint(identity: &Identity) -> Result<Endpoint> {
    Ok(build_endpoint_with(identity, &EndpointConfig::n0())
        .await?
        .endpoint)
}

/// [`build_endpoint`], with the local-network and relay choices spelled out.
///
/// ## mDNS is attached after `bind`, deliberately
///
/// On Android the multicast socket can fail to bind without a
/// `WifiManager.MulticastLock`, and iroh folds an address-lookup failure into
/// the endpoint build — so passing mDNS into `.bind()` would turn "no multicast
/// permission" into "no iroh at all". Attached afterwards, the same failure
/// costs only the LAN path: relays and pkarr still work, and
/// [`BoundEndpoint::has_lan`] reports what actually happened rather than what
/// was requested.
pub async fn build_endpoint_with(
    identity: &Identity,
    config: &EndpointConfig,
) -> Result<BoundEndpoint> {
    // `SecretKey::from_bytes` is infallible in iroh 1.0.0 (it clamps the
    // scalar), so the SAME 32 secret bytes always yield the SAME NodeId.
    let secret = SecretKey::from_bytes(&identity.secret_bytes());

    // `Minimal` when there is no relay to reach: it also drops pkarr and DNS,
    // which are just as internet-bound, leaving a stack that can only use
    // addresses it was handed directly or learned over mDNS.
    let builder = match &config.relay {
        RelayChoice::Disabled => Endpoint::builder(presets::Minimal),
        _ => Endpoint::builder(presets::N0),
    };

    let builder = match &config.relay {
        RelayChoice::N0 => builder.relay_mode(RelayMode::Default),
        RelayChoice::Custom(urls) => {
            anyhow::ensure!(
                !urls.is_empty(),
                "RelayChoice::Custom needs at least one relay url; use \
                 RelayChoice::Disabled to turn relaying off"
            );
            builder.relay_mode(RelayMode::Custom(RelayMap::from_iter(urls.iter().cloned())))
        }
        RelayChoice::Disabled => builder.relay_mode(RelayMode::Disabled),
    };

    let endpoint = builder
        .secret_key(secret)
        .alpns(vec![SYNC_ALPN.to_vec(), PAIRING_ALPN.to_vec()])
        .bind()
        .await
        .context("bind roam sync endpoint")?;

    let lan = if config.lan.is_on() {
        match LanDiscovery::attach(&endpoint, config.lan.advertises()) {
            Ok(discovery) => Some(discovery),
            Err(error) => {
                // Best-effort by design — see the doc comment above. On a
                // relayed configuration this costs a direct path; on a
                // `Disabled`-relay one it costs everything, so it is worth
                // finding in a log, but never worth failing the bind.
                crate::dlog!("mDNS unavailable, continuing without LAN discovery: {error:#}");
                None
            }
        }
    } else {
        None
    };

    Ok(BoundEndpoint { endpoint, lan })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_runs_no_mdns() {
        assert!(!LanMode::Off.is_on());
        assert!(!LanMode::Off.advertises());
    }

    #[test]
    fn browse_listens_without_publishing() {
        assert!(LanMode::Browse.is_on());
        assert!(!LanMode::Browse.advertises());
    }

    #[test]
    fn advertise_does_both() {
        assert!(LanMode::Advertise.is_on());
        assert!(LanMode::Advertise.advertises());
    }

    #[test]
    fn defaults_match_the_historical_build_endpoint() {
        let config = EndpointConfig::default();
        assert_eq!(config.lan, LanMode::Off);
        assert_eq!(config.relay, RelayChoice::N0);
    }

    #[test]
    fn lan_only_advertises_and_drops_relays() {
        let config = EndpointConfig::lan_only();
        assert_eq!(config.lan, LanMode::Advertise);
        assert_eq!(config.relay, RelayChoice::Disabled);
    }

    #[tokio::test]
    async fn custom_relay_needs_a_url() {
        let identity = Identity::generate();
        let config = EndpointConfig::n0().with_relay(RelayChoice::Custom(vec![]));

        // Matched rather than `expect_err`d: `BoundEndpoint` owns a live mDNS
        // handle and is deliberately not `Debug`.
        let error = match build_endpoint_with(&identity, &config).await {
            Ok(_) => panic!("an empty custom relay list is a configuration error"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("at least one relay url"),
            "unhelpful message: {error}"
        );
    }
}
