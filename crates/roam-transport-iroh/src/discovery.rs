//! LAN peer discovery over mDNS.
//!
//! # Why this module exists at all
//!
//! iroh's `presets::N0` does **not** include mDNS. It wires a pkarr publisher, a
//! pkarr resolver, a DNS lookup and a relay — all of which need the public
//! internet. Verified by reading `iroh-1.0.3/src/endpoint/presets.rs`; iroh does
//! not even depend on an mDNS crate. Anything that wants to find a device on the
//! same Wi-Fi with no internet has to add it, which is what this does.
//!
//! # Discovery is OPT-IN, and that is a privacy decision
//!
//! An iroh `EndpointId` *is* the device's long-term ed25519 public key. Turning
//! on mDNS advertising therefore broadcasts a **stable, unique device
//! identifier** to every other machine on the network, and [`advertise_name`]
//! broadcasts a human-readable label alongside it, in cleartext.
//!
//! On a home network that is exactly what the user wants. On café or hotel
//! Wi-Fi it is a tracking beacon: the same identifier reappearing on different
//! networks links a device (and its owner) across all of them.
//!
//! So [`LanDiscovery::attach`] takes `advertise` explicitly and
//! [`build_endpoint`](crate::endpoint::build_endpoint) does **not** call it.
//! Advertising should follow a deliberate user action ("share over LAN"), not
//! the app being open. Browsing with `advertise: false` is passive and leaks
//! nothing.

use anyhow::{Context, Result};
use futures::StreamExt;
use iroh::Endpoint;
use iroh::endpoint_info::UserData;
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use std::collections::BTreeMap;
use std::time::Duration;

/// The mDNS service name roam advertises under.
///
/// Deliberately NOT iroh's default (`irohv1`): that would surface every
/// unrelated iroh application on the network as a candidate roam peer, and show
/// roam devices to them. A private service name is a cheaper and stricter filter
/// than tagging records and filtering after the fact.
pub const ROAM_MDNS_SERVICE: &str = "roam1";

/// A roam device seen on the local network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanPeer {
    /// The device's iroh endpoint id, which equals its ed25519 verifying key.
    ///
    /// Seeing it here means only that the device is on this network. It carries
    /// **no** authorisation: it is not a roster member, and it has proven
    /// nothing. Anything acted on must still be authenticated.
    pub endpoint_id: iroh::EndpointId,
    /// The self-declared display name, if the device published one.
    ///
    /// UNTRUSTED and unauthenticated — any device on the LAN can claim any
    /// name, including a name identical to another device's. Show it to a human
    /// for recognition; never key a decision on it.
    pub name: Option<String>,
}

/// A live mDNS browser bound to one endpoint.
pub struct LanDiscovery {
    mdns: MdnsAddressLookup,
}

impl LanDiscovery {
    /// Start mDNS on `endpoint`.
    ///
    /// `advertise: true` publishes this device's endpoint id (and any name set
    /// with [`advertise_name`]) to the local network; `false` browses passively,
    /// publishing nothing. See the module docs before defaulting this to `true`.
    ///
    /// Registering the lookup also lets iroh *resolve* a known endpoint id over
    /// the LAN when dialling, so sync works with no internet at all.
    ///
    /// Must be called from within a tokio runtime (the underlying builder
    /// panics otherwise).
    pub fn attach(endpoint: &Endpoint, advertise: bool) -> Result<Self> {
        let mdns = MdnsAddressLookup::builder()
            .service_name(ROAM_MDNS_SERVICE)
            .advertise(advertise)
            .build(endpoint.id())
            .context("start mDNS address lookup")?;
        endpoint
            .address_lookup()
            .context("endpoint has no address lookup to register mDNS with")?
            .add(mdns.clone());
        Ok(Self { mdns })
    }

    /// Collect the roam devices seen on the LAN over `window`.
    ///
    /// mDNS is announcement-driven, not request/response: peers are learned as
    /// their announcements arrive, so this necessarily waits. `window` is a
    /// budget, not a timeout — it always waits the full duration, because
    /// returning early would silently under-report a slow-to-announce device.
    ///
    /// A peer that announces and then expires within the window is not
    /// reported.
    pub async fn peers(&self, window: Duration) -> Vec<LanPeer> {
        let mut events = self.mdns.subscribe().await;
        // Keyed by endpoint id so a device that re-announces (or updates its
        // name) is one entry, with the latest name, rather than several.
        let mut seen: BTreeMap<iroh::EndpointId, Option<String>> = BTreeMap::new();

        let deadline = tokio::time::sleep(window);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                event = events.next() => match event {
                    Some(DiscoveryEvent::Discovered { endpoint_info, .. }) => {
                        let name = endpoint_info
                            .data
                            .user_data()
                            .map(|user_data| user_data.to_string());
                        seen.insert(endpoint_info.endpoint_id, name);
                    }
                    Some(DiscoveryEvent::Expired { endpoint_id }) => {
                        seen.remove(&endpoint_id);
                    }
                    // An event kind we do not model yet. Ignore it and keep
                    // listening: treating it as end-of-stream (as this did) means
                    // one new variant in a future iroh silently truncates every
                    // browse, reporting a partial peer list as if it were
                    // complete. `window` is the budget; only the stream actually
                    // ending should cut it short.
                    Some(_) => continue,
                    // The service stopped; nothing more will ever arrive.
                    None => break,
                },
            }
        }

        seen.into_iter()
            .map(|(endpoint_id, name)| LanPeer { endpoint_id, name })
            .collect()
    }
}

/// Look at who is on the network, without joining it in any sense.
///
/// Binds a throwaway endpoint under a **fresh random key**, browses for
/// `window`, and closes. Nothing about this device is published — not its
/// long-term identity, not a name, not even a stable id across two calls — so
/// "who is nearby?" costs the asker no privacy.
pub async fn browse_lan(window: Duration) -> Result<Vec<LanPeer>> {
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(iroh::SecretKey::generate())
        .bind()
        .await
        .context("bind a throwaway endpoint to browse the LAN")?;
    let discovery = LanDiscovery::attach(&endpoint, false)?;
    let peers = discovery.peers(window).await;
    drop(discovery);
    endpoint.close().await;
    Ok(peers)
}

/// Publish a display name alongside this device's mDNS announcements.
///
/// Broadcast in cleartext to everyone on the network, so it must not contain
/// anything private — no vault id, no account, no real name the user has not
/// chosen to show. Pass `None` to stop publishing a name.
///
/// Errors if the name exceeds [`UserData::MAX_LENGTH`] (245 bytes).
pub fn advertise_name(endpoint: &Endpoint, name: Option<&str>) -> Result<()> {
    let user_data = name
        .map(|name| name.parse::<UserData>())
        .transpose()
        .map_err(|_| {
            anyhow::anyhow!(
                "device name is longer than the {} bytes mDNS allows",
                UserData::MAX_LENGTH
            )
        })?;
    endpoint.set_user_data_for_address_lookup(user_data);
    Ok(())
}
