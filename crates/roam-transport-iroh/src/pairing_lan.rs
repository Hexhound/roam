//! F2(c): pairing a device into a vault over the LAN with a short typed code.
//!
//! ## Why a second pairing flow
//!
//! [`crate::pairing`] is a **bearer-token** flow: the host mints a 256-bit
//! random secret, and whoever presents a signature over it gets the vault key.
//! That is the right shape when the token can travel over a channel the human
//! already trusts — a QR code scanned off the other device's screen, say — and
//! the wrong shape entirely for "read six digits off my laptop and type them
//! into my phone". Six digits as a bearer secret is a lock with a million keys.
//!
//! So the LAN flow authenticates with a **PAKE** ([`roam_pake`], SPAKE2)
//! instead. The host shows a code; the joiner types it. Neither side ever puts
//! the code, or anything derived from it offline-testable, on the wire. A wrong
//! guess costs one of [`roam_pake::MAX_ATTEMPTS`] attempts and learns nothing —
//! not the vault key, not the roster, not even that it was close.
//!
//! ## Handshake
//!
//! One QUIC bidirectional stream on [`PAIRING_LAN_ALPN`]. The joiner opens it
//! and speaks first, so the stream cannot deadlock (same asymmetry as the token
//! flow).
//!
//! ```text
//! joiner (initiator, types the code)      host (responder, shows the code)
//!   -- spake msg1 ------------------------->
//!   <------------------------- spake msg2 --
//!   -- initiator confirmation ------------->   verify; a wrong code stops here
//!   <---------------- host confirmation ----
//!   == both sides now hold a session key; everything below is sealed ==
//!   -- LanJoinRequest{key, peer_id} ------->   check key == authenticated id,
//!                                              add_peer, backfill wraps
//!   <------------------------- JoinAccept --   vault key, rosters, key-log,
//!                                              founder pin
//! ```
//!
//! ## What binds this to the right devices
//!
//! Three things, all load-bearing:
//!
//! 1. **The code**, typed by a human who is looking at the host's screen. This
//!    is the root of the trust; nothing below can substitute for it.
//! 2. **The endpoint ids**, bound into the SPAKE2 run as its identity strings.
//!    iroh authenticates both ids during the QUIC handshake, so a key agreed
//!    with one device cannot be replayed at another, and a relayed handshake
//!    (attacker in the middle of two honest runs) does not agree on a key.
//! 3. **The claimed key equals the authenticated id**. Proving the code proves
//!    only that *this connection* saw six digits — not which long-term identity
//!    the peer is. Both sides therefore refuse any key that is not the endpoint
//!    id QUIC already authenticated. Without this check a joiner who was shown a
//!    legitimate code could enrol a third party's key into the host's roster.
//!
//! ## No vault cross-check, on purpose
//!
//! The token flow has the joiner verify `accept.vault == token.vault`: the token
//! named the vault out of band, so a host that answers with a different one is
//! caught. A six-digit code names nothing. The joiner here learns the vault id
//! *from* the accept, and its assurance that it is the right vault comes from
//! (1) and (2) above — the human read the code off the intended device, and the
//! endpoint id is bound into the exchange. A caller with an expected vault id in
//! hand should still check it; there is nothing for this layer to check against.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use roam_pake::{Initiator, PairingCode, Responder, Side};
use roam_storage::{vault_subkeys, Identity, Role, Store, VaultId, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::pairing::JoinAccept;

/// The LAN pairing ALPN. Distinct from [`crate::PAIRING_ALPN`] so a code-
/// authenticated connection can never be fed to the token handshake, or the
/// reverse — the two have different authentication and different guarantees.
pub const PAIRING_LAN_ALPN: &[u8] = b"roam/pair-lan/1";

/// How long one handshake read may take before we abandon that connection.
///
/// `accept_for` serves connections ONE AT A TIME, so this is also how long a
/// peer that connects and then says nothing can block a legitimate joiner. It
/// was 30s, which is QUIC's own idle timeout and therefore no bound at all in
/// practice; 10s still covers a human on a slow link while cutting what a
/// staller can waste. `accept_for` already keeps listening after a failed
/// connection, so a staller costs time, never the session.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded wait for a direct address before publishing one for discovery.
const ADDR_READY_TIMEOUT: Duration = Duration::from_secs(8);

/// Cap on a single length-prefixed frame (refuses an alloc bomb from a hostile
/// 4-byte length).
const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Joiner → host, sealed: who the joiner claims to be.
///
/// There is no proof here, and none is needed: the sealing key already proves
/// the code, and the host cross-checks these fields against the endpoint id
/// iroh authenticated. A signature would prove only what QUIC already did.
#[derive(Serialize, Deserialize)]
struct LanJoinRequest {
    verifying_key: [u8; 32],
    peer_id: u64,
}

/// What a joiner walks away with.
///
/// A struct rather than a tuple because the caller has to persist most of it
/// (`<vault>/vault-id`, `<vault>/vault-key`) and a four-tuple of two 32-byte
/// blobs and a u64 is exactly the shape that gets silently mis-ordered.
pub struct LanJoined {
    /// The joiner's store, with the host's roster and key-log already imported.
    pub store: Store,
    /// The vault just joined. Learned from the accept — the code named no vault,
    /// so a caller that knows which vault it *meant* to join should check this.
    pub vault: VaultId,
    /// The shared backend decryption secret, wiped when this drops.
    pub vault_key: zeroize::Zeroizing<[u8; 32]>,
    /// The pinned founder's peer id (already written to the store).
    pub founder: u64,
}

/// The armed host: a code is showing and one device may claim it.
pub struct LanPairingHost<'a> {
    endpoint: Endpoint,
    addr: EndpointAddr,
    responder: Responder,
    identity: &'a Identity,
    vault: VaultId,
    vault_key: [u8; 32],
    role: Role,
    store: &'a mut Store,
    /// Held, not used: the mDNS browser stops announcing the moment it drops, so
    /// the host must own it for as long as the code is showing.
    mdns: Option<crate::discovery::LanDiscovery>,
    handshake_timeout: Duration,
}

impl Drop for LanPairingHost<'_> {
    /// Wipe the vault key when the host drops, so it does not linger in freed
    /// memory after pairing. (`LanPairingHost` holds borrows, so this is a
    /// manual `Drop` rather than the `ZeroizeOnDrop` derive.)
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.vault_key.zeroize();
    }
}

/// Arm a LAN pairing host: bind a one-shot endpoint, generate a code, and wait
/// to be told to accept.
///
/// Returns the code to show the human and the armed host. The host's
/// [`addr`](LanPairingHost::addr) is what the joiner dials; on a real LAN the
/// joiner gets it from [`crate::discovery`] rather than out of band.
pub async fn host_lan_pairing<'a>(
    identity: &'a Identity,
    vault: VaultId,
    vault_key: [u8; 32],
    role: Role,
    store: &'a mut Store,
) -> Result<(PairingCode, LanPairingHost<'a>)> {
    let endpoint = bind_lan_endpoint(identity)
        .await
        .context("bind one-shot LAN pairing endpoint")?;
    let addr = ready_addr(&endpoint).await;
    let code = PairingCode::generate();
    let responder = Responder::new(code.clone(), *endpoint.id().as_bytes());
    Ok((
        code,
        LanPairingHost {
            endpoint,
            addr,
            responder,
            identity,
            vault,
            vault_key,
            role,
            store,
            mdns: None,
            handshake_timeout: HANDSHAKE_TIMEOUT,
        },
    ))
}

impl LanPairingHost<'_> {
    /// The address a joiner dials. Snapshotted at arm time with a direct address
    /// already present where possible — a bare post-bind `addr()` is typically
    /// empty and undialable on a LAN with no relay.
    pub fn addr(&self) -> EndpointAddr {
        self.addr.clone()
    }

    /// This host's endpoint id — what the joiner needs to find it over mDNS, and
    /// what [`crate::discovery`] reports on the other device.
    pub fn endpoint_id(&self) -> iroh::EndpointId {
        self.endpoint.id()
    }

    /// Announce this host on the local network for as long as the code is up.
    ///
    /// Advertising broadcasts a stable device identifier (the endpoint id *is*
    /// the device's public key) and, with `name`, a cleartext label — see the
    /// privacy note in [`crate::discovery`]. It is off unless asked for, and it
    /// stops when the host drops, which is the end of this pairing session.
    pub fn advertise_on_lan(&mut self, name: Option<&str>) -> Result<()> {
        let mdns = crate::discovery::LanDiscovery::attach(&self.endpoint, true)?;
        crate::discovery::advertise_name(&self.endpoint, name)?;
        self.mdns = Some(mdns);
        Ok(())
    }

    /// Override [`HANDSHAKE_TIMEOUT`]. A test seam, so proving that a stalled
    /// peer is survivable does not require sitting out the production bound.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// The code's remaining guess budget. Reaches zero and the code is dead.
    pub fn attempts_left(&self) -> u32 {
        self.responder.attempts_left()
    }

    /// Accept one join, or give up when the guess budget is spent.
    ///
    /// Consumes `self`, so a code is good for exactly one successful pairing.
    pub async fn accept_auto(self) -> Result<u64> {
        self.accept_for(Duration::from_secs(300)).await
    }

    /// [`accept_auto`](Self::accept_auto) with an explicit window, so tests (and
    /// a UI with its own cancel button) need not wait out the default.
    ///
    /// Returns the joined peer's loro id. A wrong code drops that connection and
    /// keeps listening — the human gets to retype — but each wrong code spends
    /// an attempt, and the session ends when the budget is gone. This is the
    /// deliberate difference from the token flow, whose accept loop is unbounded
    /// in attempts (there a hostile first connection burning the session would
    /// be a DoS; here an unbounded loop would be a brute-force oracle).
    pub async fn accept_for(mut self, window: Duration) -> Result<u64> {
        let deadline = tokio::time::Instant::now() + window;
        let result = loop {
            if self.responder.attempts_left() == 0 {
                break Err(anyhow::anyhow!(
                    "too many wrong codes — this pairing code is used up, show a fresh one"
                ));
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let incoming = match tokio::time::timeout(remaining, self.endpoint.accept()).await {
                Err(_elapsed) => {
                    break Err(anyhow::anyhow!(
                        "timed out waiting for a device to type the pairing code"
                    ))
                }
                Ok(None) => {
                    break Err(anyhow::anyhow!(
                        "pairing endpoint closed before a device joined"
                    ))
                }
                Ok(Some(incoming)) => incoming,
            };
            let conn = match incoming.accept() {
                Ok(connecting) => match connecting.await {
                    Ok(conn) => conn,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            match self.handshake(&conn).await {
                Ok(peer) => {
                    // We wrote last; let the joiner read the accept before the
                    // connection (and the endpoint) go away.
                    conn.closed().await;
                    break Ok(peer);
                }
                Err(_rejected) => {
                    conn.close(0u32.into(), b"lan pairing rejected");
                    continue;
                }
            }
        };
        self.endpoint.close().await;
        result
    }

    async fn handshake(&mut self, conn: &iroh::endpoint::Connection) -> Result<u64> {
        // iroh authenticated this during the QUIC handshake: it is the peer's
        // real public key, not a self-claim.
        let joiner_id = conn.remote_id();
        // Bounded like every other read here: `open_bi` is lazy in QUIC, so a peer
        // that connects and never writes leaves this pending forever. Unbounded,
        // it parked the host on the FIRST stalled connection and no later joiner
        // was ever accepted.
        let (mut send, mut recv) = tokio::time::timeout(self.handshake_timeout, conn.accept_bi())
            .await
            .context("peer connected but never opened a pairing stream")?
            .context("accept LAN pairing bi stream")?;

        // --- prove the code before anything is revealed ------------------
        let msg1 = timeout_read(&mut recv, self.handshake_timeout).await?;
        let (pending, msg2) = self
            .responder
            .respond(*joiner_id.as_bytes(), &msg1)
            .map_err(anyhow::Error::from)?;
        write_frame(&mut send, &msg2).await?;

        let their_confirm: [u8; 32] = timeout_read(&mut recv, self.handshake_timeout)
            .await?
            .try_into()
            .map_err(|_| anyhow::anyhow!("malformed confirmation"))?;
        // Charged here, not at `respond`: only a peer that committed to a guess
        // and got it wrong spends the budget. Charging at `respond` let three
        // connections sending rubbish retire the code without guessing at all.
        let (key, our_confirm) = self
            .responder
            .verify(pending, &their_confirm)
            .map_err(anyhow::Error::from)?;
        write_frame(&mut send, &our_confirm).await?;
        let (mut sealer, mut opener) = key.split(Side::Responder);

        // --- authenticated; the joiner may now name itself ---------------
        let request: LanJoinRequest =
            serde_json::from_slice(&opener.open(&timeout_read(&mut recv, self.handshake_timeout).await?)?)
                .context("decode the joiner's request")?;

        // IDENTITY BINDING: the code proves this connection knows six digits,
        // not which key is behind it. Refuse to enrol anything but the key iroh
        // authenticated, or a joiner shown a legitimate code could smuggle a
        // third party into the roster.
        if &request.verifying_key != joiner_id.as_bytes() {
            bail!(
                "joiner claims a key that is not the device we authenticated — refusing to pair"
            );
        }

        let founder = self
            .store
            .founder_pin()
            .context("host is not founded — cannot deliver a founder pin to the joiner")?;
        self.store
            .add_peer(request.peer_id, request.verifying_key, self.role)
            .context("add paired peer to roster")?;
        // Wrap every epoch we can open to the newcomer, so it starts Synced
        // rather than WaitingKey. No-op for an un-rotated vault.
        let (id_key, epoch0) = vault_subkeys(&self.vault_key);
        self.store
            .backfill_wraps(&id_key, &epoch0)
            .context("wrap epochs to the new joiner")?;

        let accept = JoinAccept {
            vault: self.vault.0,
            vault_key: self.vault_key,
            rosters: self
                .store
                .export_all_rosters()
                .context("export transitive roster")?,
            keylog_author: self.identity.peer_id(),
            keylog_jsonl: self.store.export_own_keylog().context("export own keylog")?,
            founder,
        };
        let bytes = serde_json::to_vec(&accept).context("serialize LAN pairing accept")?;
        write_frame(&mut send, &sealer.seal(&bytes)).await?;
        send.finish().context("finish LAN pairing send")?;
        Ok(request.peer_id)
    }
}

/// Type the code and join. `host` is the address discovery (or a test) produced.
///
/// Opens the joiner's store at `vault_root`, runs the PAKE, and on success
/// imports the host's founder pin, transitive roster and key-log — exactly what
/// [`crate::pairing::join_pairing`] does, with the token proof replaced by the
/// code. Returns the store, the shared vault key, and the founder's peer id.
///
/// Takes owned arguments so callers can `tokio::spawn` it.
pub async fn join_lan_pairing(
    identity: Identity,
    vault_root: PathBuf,
    host: EndpointAddr,
    code: PairingCode,
) -> Result<LanJoined> {
    join_lan_pairing_inner(identity, vault_root, host, code, false, None).await
}

/// [`join_lan_pairing`] when all you have is the host's endpoint id — which is
/// all [`crate::discovery`] reports.
///
/// Attaches mDNS in **browse-only** mode (it publishes nothing about this
/// device) purely so iroh can turn the id into an address on the local network.
pub async fn join_lan_pairing_by_id(
    identity: Identity,
    vault_root: PathBuf,
    host_id: iroh::EndpointId,
    code: PairingCode,
) -> Result<LanJoined> {
    join_lan_pairing_inner(
        identity,
        vault_root,
        EndpointAddr::from(host_id),
        code,
        true,
        None,
    )
    .await
}

/// Seams that exist only so tests can drive dishonest behaviour. Not for
/// production callers — every entry point here deliberately breaks a rule the
/// honest path enforces.
pub mod testing {
    use super::*;

    /// [`join_lan_pairing`] that claims a key and peer id other than its own.
    ///
    /// A well-behaved joiner cannot do this, which is exactly why the host's
    /// identity-binding check needs a test that can.
    pub async fn join_lan_pairing_claiming(
        identity: Identity,
        vault_root: PathBuf,
        host: EndpointAddr,
        code: PairingCode,
        claimed_key: [u8; 32],
        claimed_peer_id: u64,
    ) -> Result<LanJoined> {
        join_lan_pairing_inner(
            identity,
            vault_root,
            host,
            code,
            false,
            Some((claimed_key, claimed_peer_id)),
        )
        .await
    }
}

async fn join_lan_pairing_inner(
    identity: Identity,
    vault_root: PathBuf,
    host: EndpointAddr,
    code: PairingCode,
    resolve_over_mdns: bool,
    claim_instead: Option<([u8; 32], u64)>,
) -> Result<LanJoined> {
    let mut store =
        Store::open(&vault_root, identity.clone()).context("open joiner store for LAN pairing")?;
    let endpoint = bind_lan_endpoint(&identity)
        .await
        .context("bind one-shot LAN pairing endpoint")?;
    // Held for the duration of the dial: dropping the browser would take iroh's
    // only way of turning the host's endpoint id into an address with it.
    let _mdns = if resolve_over_mdns {
        Some(crate::discovery::LanDiscovery::attach(&endpoint, false)?)
    } else {
        None
    };
    let result = run_lan_join(&endpoint, &identity, host, &code, claim_instead, &mut store).await;
    endpoint.close().await;
    let (vault, vault_key, founder) = result?;
    Ok(LanJoined {
        store,
        vault,
        vault_key,
        founder,
    })
}

async fn run_lan_join(
    endpoint: &Endpoint,
    identity: &Identity,
    host: EndpointAddr,
    code: &PairingCode,
    claim_instead: Option<([u8; 32], u64)>,
    store: &mut Store,
) -> Result<(VaultId, zeroize::Zeroizing<[u8; 32]>, u64)> {
    // The host's long-term key IS the endpoint id we are about to dial, and QUIC
    // authenticates that id. So unlike the token flow — where two independent
    // fields could name two different devices — there is nothing here to
    // cross-check: the key we will hand to `import_keylog` is by construction the
    // device we talked to.
    let host_id = host.id;
    let host_key =
        VerifyingKey::from_bytes(host_id.as_bytes()).context("host endpoint id is not a valid key")?;

    let conn = endpoint
        .connect(host, PAIRING_LAN_ALPN)
        .await
        .context("connect to LAN pairing host")?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("open LAN pairing bi stream")?;

    let (initiator, msg1) = Initiator::start(
        code,
        *endpoint.id().as_bytes(),
        *host_id.as_bytes(),
    );
    write_frame(&mut send, &msg1).await?;

    let msg2 = timeout_read(&mut recv, HANDSHAKE_TIMEOUT).await?;
    let (pending, our_confirm) = initiator.accept(&msg2).map_err(anyhow::Error::from)?;
    write_frame(&mut send, &our_confirm).await?;

    let their_confirm: [u8; 32] = timeout_read(&mut recv, HANDSHAKE_TIMEOUT)
        .await?
        .try_into()
        .map_err(|_| anyhow::anyhow!("malformed confirmation"))?;
    let key = pending.verify(&their_confirm).map_err(anyhow::Error::from)?;
    let (mut sealer, mut opener) = key.split(Side::Initiator);

    let (verifying_key, peer_id) = claim_instead.unwrap_or((
        identity.verifying_key().to_bytes(),
        identity.peer_id(),
    ));
    let request = serde_json::to_vec(&LanJoinRequest {
        verifying_key,
        peer_id,
    })
    .context("serialize LAN join request")?;
    write_frame(&mut send, &sealer.seal(&request)).await?;

    let mut accept: JoinAccept =
        serde_json::from_slice(&opener.open(&timeout_read(&mut recv, HANDSHAKE_TIMEOUT).await?)?)
            .context("decode the host's accept")?;

    // Same import order as the token flow: pin the founder first so the roster
    // fold has an anchor, then the transitive roster, then the key-log.
    store
        .pin_founder(accept.founder)
        .context("pin founder delivered by host")?;
    store
        .import_roster_bundle(std::mem::take(&mut accept.rosters))
        .context("import host transitive roster")?;
    if !accept.keylog_jsonl.is_empty() {
        store
            .import_keylog(
                accept.keylog_author,
                &host_key,
                std::mem::take(&mut accept.keylog_jsonl),
            )
            .context("import host keylog")?;
    }

    conn.close(0u32.into(), b"paired");
    Ok((
        VaultId(accept.vault),
        zeroize::Zeroizing::new(accept.vault_key),
        accept.founder,
    ))
}

/// A one-shot endpoint for LAN pairing.
///
/// `presets::N0` deliberately NOT used: this flow must work with no internet at
/// all, and N0 is pkarr + DNS + relay. Pairing needs only the address the joiner
/// already has (from mDNS discovery, or a test), so a minimal endpoint with no
/// outside dependencies is both sufficient and the honest thing to bind.
async fn bind_lan_endpoint(identity: &Identity) -> Result<Endpoint> {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&identity.secret_bytes()))
        .alpns(vec![PAIRING_LAN_ALPN.to_vec()])
        .bind()
        .await
        .context("bind LAN pairing endpoint")
}

/// Snapshot a dialable address, waiting (bounded) for a direct one to appear.
async fn ready_addr(endpoint: &Endpoint) -> EndpointAddr {
    let deadline = tokio::time::Instant::now() + ADDR_READY_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        if endpoint.addr().ip_addrs().next().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    endpoint.addr()
}

async fn write_frame(send: &mut iroh::endpoint::SendStream, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).context("frame too large to length-prefix")?;
    send.write_all(&len.to_be_bytes())
        .await
        .context("write frame length")?;
    send.write_all(bytes).await.context("write frame body")?;
    Ok(())
}

async fn read_frame(recv: &mut iroh::endpoint::RecvStream) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    recv.read_exact(&mut len_bytes)
        .await
        .context("read frame length")?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    anyhow::ensure!(
        len <= MAX_FRAME_LEN,
        "peer announced a {len}-byte pairing frame, over the limit"
    );
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .context("read frame body")?;
    Ok(body)
}

/// [`read_frame`] under [`HANDSHAKE_TIMEOUT`], so a peer that connects and then
/// goes quiet cannot pin either side open.
async fn timeout_read(
    recv: &mut iroh::endpoint::RecvStream,
    timeout: Duration,
) -> Result<Vec<u8>> {
    tokio::time::timeout(timeout, read_frame(recv))
        .await
        .context("timed out reading a pairing frame")?
}

/// Surfaced so callers can distinguish "wrong code, try again" from a real
/// failure without string-matching.
pub use roam_pake::PakeError as LanPakeError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lan_alpn_is_distinct_from_every_other_roam_protocol() {
        // A code-authenticated connection and a token-authenticated one have
        // different guarantees; ALPN is what keeps them from being confused.
        assert_ne!(PAIRING_LAN_ALPN, crate::PAIRING_ALPN);
        assert_ne!(PAIRING_LAN_ALPN, crate::SYNC_ALPN);
    }

    #[test]
    fn a_pake_error_is_reported_as_itself() {
        // `accept_for` distinguishes a bad code from a broken peer by downcast,
        // which only works if the error is not flattened into a string.
        let err: anyhow::Error = roam_pake::PakeError::BadCode.into();
        assert_eq!(
            err.downcast_ref::<roam_pake::PakeError>(),
            Some(&roam_pake::PakeError::BadCode)
        );
    }
}
