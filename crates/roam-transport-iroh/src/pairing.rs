//! Device pairing over the [`PAIRING_ALPN`] protocol — trust bootstrap.
//!
//! Pairing teaches two devices to trust each other so future op/roster sync
//! (over [`crate::SYNC_ALPN`]) is accepted. It is **security-critical** and
//! fails closed everywhere: no peer is ever added to a roster before a
//! cryptographic proof verifies.
//!
//! ## Token (the out-of-band ticket)
//!
//! The trusted device A shows the joiner B a base64-JSON [`PairingToken`]. It
//! carries A's dialable [`iroh::EndpointAddr`] (discovery may lag), A's key +
//! loro peer id, the vault B is joining, and a fresh random **single-use
//! secret**. Whoever holds the token can prove they saw it by signing the
//! secret — that binds the join to an explicit, out-of-band handoff.
//!
//! ## Handshake (single bi stream, deadlock-free)
//!
//! One QUIC bidirectional stream carries exactly two length-prefixed JSON
//! messages. The read/write order is **asymmetric** so the stream never
//! deadlocks — the side that OPENED the stream speaks first:
//!
//! - **Join (B)**: opens the stream, *writes* [`JoinRequest`] (its key + a
//!   signature over `token.secret`), then *reads* [`JoinAccept`].
//! - **Host (A)**: accepts the stream, *reads* the [`JoinRequest`] first,
//!   **verifies the proof**, and only then adds B and *writes* [`JoinAccept`]
//!   (its vault, the shared **vault key**, and a snapshot of A's signed roster,
//!   so B learns A's siblings transitively).
//!
//! ## Vault key (backend decryption secret)
//!
//! The vault key is the symmetric secret every device needs to decrypt the
//! zero-knowledge backend store. It travels ONLY inside [`JoinAccept`] — which
//! the host writes exclusively after the joiner's proof verifies, over the
//! QUIC-encrypted+authenticated pairing stream. It is deliberately NOT placed in
//! the [`PairingToken`]: the token is shown out of band (copy-paste, QR, chat)
//! and could be logged or screenshotted, so it must never carry a long-lived
//! decryption secret.
//!
//! ## Security properties (all enforced + tested)
//!
//! - **Proof before trust**: a `JoinRequest` whose proof does not verify against
//!   the presented key over the exact `secret` bytes is rejected; the peer is
//!   NOT added to the host roster.
//! - **Single-use secret**: [`PairingHost::accept_auto`] consumes `self`,
//!   accepts exactly one join, then drops the secret and closes the endpoint —
//!   a second join cannot reuse it.
//! - **Bounded token lifetime (P1)**: the token carries a host-authoritative
//!   expiry ([`PAIRING_TOKEN_TTL`]); `accept_auto` accepts only within the
//!   remaining window and an honest joiner refuses an expired token. This bounds
//!   how long a *leaked* token stays usable but does not close the bearer model —
//!   an attacker who redeems the token inside the window still succeeds.
//! - **Vault match**: the joiner aborts if `accept.vault != token.vault`.
//! - **Fail-closed**: any malformed message or verify error aborts pairing
//!   without mutating trust.
//!
//! ## One endpoint per identity (load-bearing)
//!
//! [`host_pairing`] / [`join_pairing`] bind a **one-shot endpoint** and
//! `close()` it before returning — this is the CLI/test path, which has no
//! running transport to reuse. GUI clients keep a live sync endpoint up and
//! MUST instead drive pairing through it (its `PAIRING_ALPN` router handler),
//! never binding a second endpoint for the same key (that hijacks the relay
//! route and kills inbound sync). That live-endpoint path is out of scope here.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::Signature;
use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use roam_storage::{vault_subkeys, Identity, Role, Store, VaultId, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::endpoint::{build_endpoint, PAIRING_ALPN};

/// How long a minted pairing token stays valid (P1). The token is a *bearer*
/// secret — whoever holds it can prove the secret and obtain the vault key — so
/// its lifetime is a security parameter: it bounds how long a LEAKED token
/// (screenshot, chat log, shoulder-surf) stays usable. The host enforces this
/// deadline against ITS OWN clock (the `expires_at` it minted), never the
/// attacker-editable field carried in the token. Kept short; pairing is an
/// interactive, user-present action.
///
/// This does NOT close the bearer model: an attacker who obtains the token and
/// races the real joiner *within* the window still wins (its proof is valid).
/// The window only bounds the exposure; unforgeable device-to-device
/// confirmation (a human-compared short authentication string) is an app-layer
/// concern, out of scope here.
const PAIRING_TOKEN_TTL: Duration = Duration::from_secs(120);

/// How long a single handshake half may take once the connection is up, before
/// we abort it — a peer that connects and then stalls must not park the host
/// forever holding its single-use secret.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long we wait for the endpoint to discover a direct address before
/// snapshotting the token's [`EndpointAddr`]. A bare post-bind `addr()` is
/// typically empty, so a token minted from it would be undialable on loopback /
/// same-LAN; we still proceed on timeout (relay-only reachability).
const ADDR_READY_TIMEOUT: Duration = Duration::from_secs(8);

/// Cap on a single length-prefixed pairing message (refuses an alloc bomb from a
/// hostile 4-byte length; real messages are a few hundred bytes to a few KiB).
const MAX_MSG_LEN: usize = 1024 * 1024;

/// Signature domain tag for the pairing proof (M1: cross-protocol reuse guard).
/// Distinct from [`roam_storage::oplog::OPLOG_SIG_DOMAIN`] so a pairing proof
/// (a signature over the token secret) can never be replayed as an op-log
/// signature attributed to the same key, or vice versa. Fixed length.
const PAIRING_PROOF_DOMAIN: &[u8] = b"roam-pairing-proof-v1\x00";

/// The out-of-band token the trusted device A shows the joiner B.
///
/// The single-use `secret` is wiped on drop; the other fields are public
/// (address, keys, opaque ids) and skipped.
#[derive(Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
pub struct PairingToken {
    /// How to reach A right now (discovery may lag, so carry the full addr).
    #[zeroize(skip)]
    pub addr: EndpointAddr,
    /// A's ed25519 verifying key == A's iroh `NodeId`.
    #[zeroize(skip)]
    pub verifying_key: [u8; 32],
    /// A's loro peer id.
    #[zeroize(skip)]
    pub peer_id: u64,
    /// The vault B is joining.
    #[zeroize(skip)]
    pub vault: [u8; 32],
    /// One-time nonce; B proves it saw the token by signing these bytes.
    pub secret: [u8; 32],
    /// Wall-clock expiry (seconds since the Unix epoch), set at mint to
    /// `now + PAIRING_TOKEN_TTL`. Advisory for an honest joiner (it refuses to
    /// act on an expired token); the host enforces its OWN copy, not this field
    /// (an attacker could edit it, since the token is unsigned).
    #[zeroize(skip)]
    pub expires_at_unix_secs: u64,
}

impl PairingToken {
    /// Base64-of-JSON, for copy-paste out of band.
    pub fn encode(&self) -> String {
        B64.encode(serde_json::to_vec(self).expect("PairingToken serializes"))
    }

    /// Refuse a token that names one device to TALK TO and another to TRUST.
    ///
    /// A token carries two independent identity claims about the host:
    ///
    /// * `addr.id` — the iroh `EndpointId` the joiner dials. QUIC/TLS
    ///   authenticates this one: connecting proves the remote holds its secret
    ///   key.
    /// * `verifying_key` — the key the joiner later hands to `import_keylog` to
    ///   authenticate the host's key-log.
    ///
    /// The host mints both from one identity (its `EndpointId` *is* its ed25519
    /// verifying key), so honestly they are always equal. Nothing checked it,
    /// which left the two claims free to diverge: authenticate device X on the
    /// wire, then trust device Y's signatures. Binding them collapses that to a
    /// single identity, fail-closed.
    ///
    /// This does not, and cannot, fix the bearer model — anyone who can swap
    /// the whole token can mint a self-consistent one for a vault they control.
    /// It removes a confusion, not the need for the token to arrive over a
    /// trusted out-of-band channel.
    pub fn check_host_identity_is_consistent(&self) -> Result<()> {
        if self.addr.id.as_bytes() != &self.verifying_key {
            bail!(
                "pairing token names two different devices (dial target {} vs trusted key {}) \
                 — refusing to pair",
                self.addr.id,
                B64.encode(self.verifying_key)
            );
        }
        Ok(())
    }

    /// Decode a token string (whitespace-trimmed) back into a [`PairingToken`].
    pub fn decode(s: &str) -> Result<Self> {
        let bytes = B64
            .decode(s.trim())
            .context("decode pairing token base64")?;
        serde_json::from_slice(&bytes).context("decode pairing token json")
    }
}

/// B → A over the pairing stream: a proof-of-secret join request.
#[derive(Serialize, Deserialize)]
pub struct JoinRequest {
    /// B's ed25519 verifying key == B's iroh `NodeId`.
    pub verifying_key: [u8; 32],
    /// B's loro peer id.
    pub peer_id: u64,
    /// `sign(token.secret)` under B's key — proves B saw the token. A 64-byte
    /// ed25519 signature; carried as `Vec<u8>` because serde has no derive for
    /// `[u8; 64]`. The host validates the length before verifying.
    pub proof: Vec<u8>,
}

/// A → B: accepted; here is the vault, the shared vault key, and A's signed
/// roster snapshot.
///
/// The `vault_key` (the backend decryption secret) is wiped on drop; every other
/// field is public roster/key-log material and skipped.
#[derive(Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
pub struct JoinAccept {
    /// The vault B is joining (B re-validates it against its token).
    #[zeroize(skip)]
    pub vault: [u8; 32],
    /// The shared vault key (backend decryption secret). Only ever sent here,
    /// after the joiner's proof verifies, over the encrypted pairing stream.
    pub vault_key: [u8; 32],
    /// A's TRANSITIVE roster: every roster log the host holds, keyed by author
    /// peer id. This includes the founder chain the host received when it joined
    /// (e.g. `roster-<founder>.jsonl`) plus the host's own log, so a joiner behind
    /// a non-founder admin folds the full founder->host->joiner chain. Verified
    /// per-author during the joiner's roster fold, not here.
    #[zeroize(skip)]
    pub rosters: Vec<(u64, Vec<u8>)>,
    /// The host's signed key-log (author = `keylog_author`), so the joiner learns
    /// the epoch DAG and any wraps addressed to it. Empty for an un-rotated vault.
    #[zeroize(skip)]
    pub keylog_author: u64,
    #[zeroize(skip)]
    pub keylog_jsonl: Vec<u8>,
    /// The pinned vault founder's `peer_id`. The joiner writes this to its own
    /// `<vault>/founder` pin so its roster fold seeds `ever_admin` and it can
    /// materialize the role the host just granted (without it a Reader/Writer
    /// joiner folds NO role and is inert). Delivered ONLY here, over the proven
    /// stream — never in the out-of-band token.
    #[zeroize(skip)]
    pub founder: u64,
}

/// The armed host side of a pairing exchange.
///
/// Holds the one-shot endpoint, the single-use `secret`, and a mutable handle to
/// the store it will add the approved joiner to. Created by [`host_pairing`];
/// [`accept_auto`](PairingHost::accept_auto) consumes it to accept exactly one
/// join, so the secret cannot be reused.
pub struct PairingHost<'a> {
    endpoint: Endpoint,
    secret: [u8; 32],
    identity: &'a Identity,
    vault: VaultId,
    /// The shared vault key, handed to every proven joiner via [`JoinAccept`].
    vault_key: [u8; 32],
    /// The role this host grants the joiner it approves (applied in the host's
    /// `add_peer`). Admin-gated: the host must itself be an admin.
    role: Role,
    /// Host-authoritative token expiry (Unix secs). This is the value the host
    /// minted, held in the host's own memory — NOT read back from the token — so
    /// an attacker who edits the token's field cannot extend the accept window.
    expires_at_unix_secs: u64,
    store: &'a mut Store,
}

impl Drop for PairingHost<'_> {
    /// Wipe the single-use secret and the shared vault key when the host is
    /// dropped, so neither lingers in freed memory after pairing (`PairingHost`
    /// holds borrows, so it uses a manual `Drop` rather than the derive).
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
        self.vault_key.zeroize();
    }
}

/// The generating (host) side of pairing.
///
/// Binds a one-shot endpoint, mints a fresh single-use `secret`, and returns the
/// base64 token to show the joiner plus an armed [`PairingHost`] whose
/// [`accept_auto`](PairingHost::accept_auto) awaits exactly one join.
pub async fn host_pairing<'a>(
    identity: &'a Identity,
    vault: VaultId,
    vault_key: [u8; 32],
    role: Role,
    store: &'a mut Store,
) -> Result<(String, PairingHost<'a>)> {
    host_pairing_with_ttl(identity, vault, vault_key, role, store, PAIRING_TOKEN_TTL).await
}

/// [`host_pairing`] with an explicit token time-to-live. Production callers use
/// [`host_pairing`] (the default [`PAIRING_TOKEN_TTL`]); this seam lets tests
/// arm a token that is already expired without waiting out the real window.
pub async fn host_pairing_with_ttl<'a>(
    identity: &'a Identity,
    vault: VaultId,
    vault_key: [u8; 32],
    role: Role,
    store: &'a mut Store,
    ttl: Duration,
) -> Result<(String, PairingHost<'a>)> {
    let endpoint = build_endpoint(identity)
        .await
        .context("bind one-shot pairing endpoint")?;
    // Snapshot a dialable address (relay + direct) before minting the token; a
    // bare post-bind addr would be undialable on loopback / same-LAN.
    let addr = ready_addr(&endpoint).await;

    // A fresh, single-use random nonce. `VaultId::generate` is just a 32-byte
    // OS-random helper; reuse it rather than pulling in `rand` here.
    let secret = VaultId::generate().0;
    let expires_at_unix_secs = now_unix_secs().saturating_add(ttl.as_secs());

    let token = PairingToken {
        addr,
        verifying_key: identity.verifying_key().to_bytes(),
        peer_id: identity.peer_id(),
        vault: vault.0,
        secret,
        expires_at_unix_secs,
    };
    let token_str = token.encode();

    Ok((
        token_str,
        PairingHost {
            endpoint,
            secret,
            identity,
            vault,
            vault_key,
            role,
            expires_at_unix_secs,
            store,
        },
    ))
}

impl PairingHost<'_> {
    /// Accept exactly one inbound join, auto-approving it (the CLI wraps a y/n
    /// prompt around this; tests use it directly). Consumes `self`, so the
    /// single-use secret is dropped after one attempt.
    ///
    /// Verifies the joiner's proof-of-secret BEFORE adding it to the roster;
    /// a bad or absent proof returns `Err` and leaves the roster untouched.
    /// Returns the added peer's loro id on success.
    ///
    /// The accept window is the token's remaining lifetime (P1): once the
    /// host-minted expiry lapses the window is zero and no join is accepted, so
    /// a leaked token cannot be redeemed after the host's own deadline.
    pub async fn accept_auto(self) -> Result<u64> {
        let window = Duration::from_secs(self.expires_at_unix_secs.saturating_sub(now_unix_secs()));
        self.accept_for(window).await
    }

    /// Accept joins for at most `window`, returning the first that proves the
    /// secret. Split out so tests can drive a short window without waiting the
    /// full [`PAIRING_TOKEN_TTL`]; production calls [`accept_auto`].
    pub async fn accept_for(mut self, window: Duration) -> Result<u64> {
        // P2 (pairing DoS): keep accepting until a proof VERIFIES or the accept
        // window closes. A hostile peer that connects first with a garbage proof
        // must not burn the single-use secret and force the user to restart —
        // only a successful join consumes the session. Each failed handshake
        // closes just that connection and we loop for the next one.
        let deadline = tokio::time::Instant::now() + window;
        let result = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let incoming = match tokio::time::timeout(remaining, self.endpoint.accept()).await {
                Err(_elapsed) => {
                    break Err(anyhow::anyhow!(
                        "timed out waiting for a device to pair (no valid proof arrived)"
                    ))
                }
                Ok(None) => {
                    break Err(anyhow::anyhow!(
                        "pairing endpoint closed before a valid join arrived"
                    ))
                }
                Ok(Some(incoming)) => incoming,
            };

            let conn = match incoming
                .accept()
                .context("accept inbound pairing connection")
            {
                Ok(connecting) => match connecting.await {
                    Ok(conn) => conn,
                    // A connection that never completes its handshake is not a
                    // reason to abort the whole session — wait for another.
                    Err(_) => continue,
                },
                Err(_) => continue,
            };

            match self.handshake(&conn).await {
                Ok(peer) => {
                    // The host wrote LAST, so let the joiner read our accept
                    // before we tear the connection (and endpoint) down.
                    conn.closed().await;
                    break Ok(peer);
                }
                // Reject THIS connection only; the secret is still unspent.
                Err(_rejected) => {
                    conn.close(0u32.into(), b"pairing rejected");
                    continue;
                }
            }
        };

        // The secret is consumed exactly once — on success, or when the window
        // closes with no valid join. Close the one-shot endpoint either way.
        self.endpoint.close().await;
        result
    }

    /// The host half of the handshake over an accepted connection: read the
    /// join request, verify the proof, add the peer, write the accept.
    async fn handshake(&mut self, conn: &iroh::endpoint::Connection) -> Result<u64> {
        let (mut send, mut recv) = conn.accept_bi().await.context("accept pairing bi stream")?;

        // The joiner opened the stream, so it speaks first: read its request.
        let req: JoinRequest = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_msg(&mut recv))
            .await
            .context("timed out reading the joiner's request")??;

        // PROOF BEFORE TRUST: verify the joiner signed the exact secret bytes
        // with the key it presents. verify() uses verify_strict (rejects
        // malleable signatures). On failure, abort WITHOUT touching the roster.
        let joiner_key = VerifyingKey::from_bytes(&req.verifying_key)
            .context("joiner presented a malformed verifying key")?;
        let proof_bytes: [u8; 64] = req
            .proof
            .as_slice()
            .try_into()
            .context("proof must be a 64-byte ed25519 signature")?;
        let proof = Signature::from_bytes(&proof_bytes);
        if !joiner_key.verify_in_domain(PAIRING_PROOF_DOMAIN, &self.secret, &proof) {
            bail!("pairing proof did not verify — rejecting join (peer not added)");
        }

        // The founder pin the joiner needs to seed its roster fold. The host is
        // founded (it authored the vault), so this is `Some`; a `None` here is a
        // host misconfiguration — fail closed rather than shipping a bogus 0.
        let founder = self
            .store
            .founder_pin()
            .context("host is not founded — cannot deliver a founder pin to the joiner")?;

        // Proof holds: add the joiner to our roster with the invitee role, then
        // vouch back with our vault + signed roster so it can reach our siblings
        // transitively.
        self.store
            .add_peer(req.peer_id, req.verifying_key, self.role)
            .context("add paired peer to roster")?;
        // Wrap every epoch the host can open to the freshly-added joiner, so the
        // newcomer starts Synced instead of WaitingKey. (No-op for an un-rotated
        // vault: only epoch 0 exists and it is never wrapped.)
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
            keylog_jsonl: self
                .store
                .export_own_keylog()
                .context("export own keylog")?,
            founder,
        };
        write_msg(&mut send, &accept)
            .await
            .context("send pairing accept")?;
        send.finish().context("finish pairing send")?;

        Ok(req.peer_id)
    }
}

/// The joining side of pairing.
///
/// Decodes the token, opens the joiner's store at `vault_root`, connects to the
/// host on [`PAIRING_ALPN`], proves it saw the token, adds the host to its own
/// roster, and imports the host's roster (learning the host's siblings). Returns
/// the store and the shared vault key delivered in the host's [`JoinAccept`]
/// (the caller persists it for backend sync). Closes the one-shot endpoint
/// before returning.
///
/// Takes owned args (not borrows) so callers can `tokio::spawn` it.
pub async fn join_pairing(
    identity: Identity,
    vault_root: PathBuf,
    token_str: String,
) -> Result<(Store, zeroize::Zeroizing<[u8; 32]>, u64)> {
    let token = PairingToken::decode(&token_str).context("decode pairing token")?;

    let mut store =
        Store::open(&vault_root, identity.clone()).context("open joiner store for pairing")?;

    let endpoint = build_endpoint(&identity)
        .await
        .context("bind one-shot pairing endpoint")?;

    let result = run_join(&endpoint, &identity, &token, &mut store).await;
    endpoint.close().await;
    let (vault_key, founder) = result?;
    Ok((store, vault_key, founder))
}

/// The joiner half of the handshake, dialing out over `endpoint`. Split out so
/// the endpoint is always closed by [`join_pairing`] even on error.
async fn run_join(
    endpoint: &Endpoint,
    identity: &Identity,
    token: &PairingToken,
    store: &mut Store,
) -> Result<(zeroize::Zeroizing<[u8; 32]>, u64)> {
    // P1: an honest joiner refuses an expired token before dialing, so it never
    // leaks its proof-of-secret to a stale or replayed token. (This does not
    // constrain an attacker — who skips the check — but the host enforces its own
    // deadline in `accept_auto`; that is the authoritative bound.)
    if now_unix_secs() >= token.expires_at_unix_secs {
        bail!("pairing token has expired — ask the other device for a fresh one");
    }

    // Before dialing, so a token naming two different devices never gets our
    // proof-of-secret either.
    token.check_host_identity_is_consistent()?;

    let conn = endpoint
        .connect(token.addr.clone(), PAIRING_ALPN)
        .await
        .context("connect to pairing host")?;
    let (mut send, mut recv) = conn.open_bi().await.context("open pairing bi stream")?;

    // We opened the stream, so we speak first: prove we saw the token by signing
    // its secret, then read the host's accept.
    let proof = identity
        .sign_in_domain(PAIRING_PROOF_DOMAIN, &token.secret)
        .to_bytes()
        .to_vec();
    let req = JoinRequest {
        verifying_key: identity.verifying_key().to_bytes(),
        peer_id: identity.peer_id(),
        proof,
    };
    write_msg(&mut send, &req)
        .await
        .context("send pairing request")?;
    send.finish().context("finish pairing send")?;

    let mut accept: JoinAccept = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_msg(&mut recv))
        .await
        .context("timed out reading the host's accept")??;

    // VAULT MATCH: refuse to join a different vault than the token named.
    if accept.vault != token.vault {
        bail!("pairing vault mismatch — refusing to join a different vault");
    }

    // Pin the founder the host delivered over the proven stream FIRST, so the
    // roster fold seeds `ever_admin` with it. Without this pin a Reader/Writer
    // joiner (which cannot author roster ops, and is not admin) would materialize
    // NO role at all and be inert. We do NOT author our own `add_peer` for the
    // host — that is admin-gated and we may be a mere Reader; trust in the host
    // (and our own granted role) both fall out of the founder-seeded fold over
    // the host's imported roster.
    store
        .pin_founder(accept.founder)
        .context("pin founder delivered by host")?;
    // Import the host's TRANSITIVE roster so we learn the founder's self-`Add`
    // (proves its admin role and anchors the fold), the host's own log, and the
    // `Add{role}` the host authored for us — the full founder->host->joiner chain.
    // Each author's log is verified against the roster-vouched key during our fold
    // (`rebuild_peers`); the founder pin above anchors trust in the founder.
    let host_key = VerifyingKey::from_bytes(&token.verifying_key)
        .context("token carried a malformed host key")?;
    // `JoinAccept` wipes its `vault_key` on drop (`ZeroizeOnDrop`), so its fields
    // can't be moved out by value — take the owned Vecs with `mem::take`, leaving
    // empties the Drop can harmlessly run over.
    store
        .import_roster_bundle(std::mem::take(&mut accept.rosters))
        .context("import host transitive roster")?;
    // Import the host's key-log so we learn the epoch DAG and any wraps addressed
    // to us (the host published them via backfill during accept). Authenticated by
    // the same host key as the roster.
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
    // Copy the vault key out of the `ZeroizeOnDrop` `JoinAccept` into a
    // `Zeroizing` wrapper so the caller's copy is wiped on drop too (the accept
    // itself wipes its field when it drops at the end of this fn).
    Ok((zeroize::Zeroizing::new(accept.vault_key), accept.founder))
}

/// Snapshot a dialable [`EndpointAddr`], waiting (bounded) for a direct address
/// to appear first. On timeout we return whatever the endpoint knows — enough
/// for a relay-reachable peer, and usually the LAN direct addr is already in.
async fn ready_addr(endpoint: &Endpoint) -> EndpointAddr {
    let deadline = tokio::time::Instant::now() + ADDR_READY_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        if endpoint.addr().ip_addrs().next().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    endpoint.addr()
}

/// Seconds since the Unix epoch, saturating to 0 before it (clock skew guard).
/// Used only for the pairing-token TTL, where second granularity is ample.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write a value as `len(4, big-endian) || json`.
async fn write_msg<T: Serialize>(send: &mut SendStream, msg: &T) -> Result<()> {
    let json = serde_json::to_vec(msg).context("serialize pairing message")?;
    let len = u32::try_from(json.len())
        .context("pairing message too large to length-prefix")?
        .to_be_bytes();
    send.write_all(&len).await.context("write message length")?;
    send.write_all(&json).await.context("write message body")?;
    Ok(())
}

/// Read one length-prefixed JSON value off a stream.
async fn read_msg<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("read message length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(
        len <= MAX_MSG_LEN,
        "pairing message too large ({len} bytes)"
    );
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .context("read message body")?;
    serde_json::from_slice(&body).context("decode pairing message")
}

#[cfg(test)]
mod tests {
    use super::*;
    use roam_storage::PeerStatus;
    use tempfile::tempdir;

    #[test]
    fn a_pairing_proof_cannot_be_forged_from_an_oplog_signature() {
        // M1: an op-log signature captured off the wire/backend must not verify
        // as a pairing proof over the same secret bytes, even if the attacker
        // sets the secret == an op-log update they authored. Distinct domain
        // tags on each protocol's signature make the two mutually unverifiable.
        use roam_storage::OPLOG_SIG_DOMAIN;
        let victim = roam_storage::Identity::generate();
        let secret = [9u8; 32];

        // A signature the victim made in the OP-LOG domain over `secret`.
        let oplog_sig = victim.sign_in_domain(OPLOG_SIG_DOMAIN, &secret);
        // Replayed as a pairing proof: MUST be rejected by the pairing verify.
        assert!(!victim.verifying_key().verify_in_domain(
            PAIRING_PROOF_DOMAIN,
            &secret,
            &oplog_sig
        ));

        // And the reverse: a genuine pairing proof must not verify as an op.
        let pairing_proof = victim.sign_in_domain(PAIRING_PROOF_DOMAIN, &secret);
        assert!(!victim.verifying_key().verify_in_domain(
            OPLOG_SIG_DOMAIN,
            &secret,
            &pairing_proof
        ));

        // Sanity: each still verifies in its own domain.
        assert!(victim.verifying_key().verify_in_domain(
            PAIRING_PROOF_DOMAIN,
            &secret,
            &pairing_proof
        ));
    }

    #[test]
    fn pairing_secrets_are_wiped_on_drop() {
        // The pairing token's single-use secret and the vault key delivered in a
        // JoinAccept are the two most sensitive bytes crossing this crate — the
        // vault key decrypts the whole backend store. Both structs must wipe
        // their secret on drop rather than leave it in freed memory.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<PairingToken>();
        assert_zeroize_on_drop::<JoinAccept>();
    }

    #[test]
    fn token_roundtrips_through_base64() {
        let secret = iroh::SecretKey::generate();
        let token = PairingToken {
            addr: EndpointAddr::new(secret.public()),
            verifying_key: [3u8; 32],
            peer_id: 42,
            vault: [7u8; 32],
            secret: [9u8; 32],
            expires_at_unix_secs: 1_700_000_000,
        };
        let decoded = PairingToken::decode(&token.encode()).expect("decode");
        assert_eq!(decoded.verifying_key, token.verifying_key);
        assert_eq!(decoded.peer_id, token.peer_id);
        assert_eq!(decoded.vault, token.vault);
        assert_eq!(decoded.secret, token.secret);
        assert_eq!(decoded.addr.id, token.addr.id);
        assert_eq!(decoded.expires_at_unix_secs, token.expires_at_unix_secs);
    }

    /// A pairing token makes TWO independent identity claims about the host:
    /// `addr.id`, which iroh's QUIC/TLS authenticates on connect, and
    /// `verifying_key`, which the joiner later trusts to authenticate the
    /// host's key-log. Nothing forced them to describe the same device, so a
    /// token could name one device to talk to and a different one to trust.
    /// They are bound now, and this asserts the mismatch is refused *before*
    /// the joiner dials — so it never leaks its proof-of-secret either.
    #[test]
    fn a_token_naming_two_different_hosts_is_refused() {
        let host = iroh::SecretKey::generate();
        let other = Identity::generate();
        let token = PairingToken {
            // Talk to `host`...
            addr: EndpointAddr::new(host.public()),
            // ...but trust `other`'s key for the roster/key-log import.
            verifying_key: other.verifying_key().to_bytes(),
            peer_id: 42,
            vault: [7u8; 32],
            secret: [9u8; 32],
            expires_at_unix_secs: u64::MAX,
        };
        let err = token
            .check_host_identity_is_consistent()
            .expect_err("a token naming two different hosts must be refused");
        assert!(
            err.to_string().contains("two different devices"),
            "unhelpful error: {err}"
        );
    }

    /// The honest case must still pass, or the check above would be satisfied
    /// by refusing everything.
    #[test]
    fn a_token_naming_one_host_consistently_is_accepted() {
        let host = iroh::SecretKey::generate();
        let token = PairingToken {
            addr: EndpointAddr::new(host.public()),
            verifying_key: *host.public().as_bytes(),
            peer_id: 42,
            vault: [7u8; 32],
            secret: [9u8; 32],
            expires_at_unix_secs: u64::MAX,
        };
        token
            .check_host_identity_is_consistent()
            .expect("a consistent token must be accepted");
    }

    /// P1 (leaked-token bearer window): a pairing token carries a
    /// host-authoritative expiry. Once it lapses the armed host refuses every
    /// join — even one that could prove the secret — so a token that leaks
    /// (screenshot, chat log) is only usable inside the short mint window, not
    /// indefinitely while the host process stays up.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_expired_pairing_session_refuses_all_joins() {
        let da = tempdir().unwrap();
        let ia = Identity::generate();
        let vault = VaultId::generate();
        let mut sa = Store::open(da.path(), ia.clone()).unwrap();
        sa.declare_founder(Role::Admin).unwrap();

        // Arm with a zero TTL: the token is already expired the instant it is
        // minted, so the host's own deadline (not the attacker-editable token
        // field) has already lapsed before any join can arrive.
        let (_token, host) =
            host_pairing_with_ttl(&ia, vault, [42u8; 32], Role::Admin, &mut sa, Duration::ZERO)
                .await
                .unwrap();
        let res = host.accept_auto().await;
        assert!(res.is_err(), "an expired session must accept no join");
        // The founder self-entry is expected; no OTHER peer may be added.
        assert!(
            sa.roster().iter().all(|p| p.peer_id == ia.peer_id()),
            "no foreign peer may be added by an expired pairing session"
        );
    }

    /// P1: an honest joiner refuses a token whose expiry has already passed — so
    /// it never leaks its proof to a stale or replayed token — and does so
    /// without dialing the host at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_joiner_refuses_an_expired_token() {
        let db = tempdir().unwrap();
        let ib = Identity::generate();
        let secret = iroh::SecretKey::generate();
        let token = PairingToken {
            addr: EndpointAddr::new(secret.public()),
            verifying_key: [3u8; 32],
            peer_id: 42,
            vault: [7u8; 32],
            secret: [9u8; 32],
            expires_at_unix_secs: 1, // one second past the epoch — long expired
        };
        let res = join_pairing(ib.clone(), db.path().to_path_buf(), token.encode()).await;
        assert!(
            res.is_err(),
            "an honest joiner must refuse an already-expired token"
        );
    }

    #[test]
    fn decode_token_rejects_garbage() {
        assert!(PairingToken::decode("not-a-real-token!!!").is_err());
    }

    /// Happy path: host arms a token and auto-approves one join; afterwards A's
    /// roster contains B Active AND B's roster contains A Active.
    #[tokio::test(flavor = "multi_thread")]
    async fn pairing_establishes_mutual_trust() {
        let da = tempdir().unwrap();
        let db = tempdir().unwrap();
        let ia = Identity::generate();
        let ib = Identity::generate();
        let vault = VaultId::generate();

        let mut sa = Store::open(da.path(), ia.clone()).unwrap();
        // Host must be founded (admin) to vouch joiners and to deliver a founder pin.
        sa.declare_founder(Role::Admin).unwrap();

        // Host A: create a token, then accept one join (auto-approve).
        let vault_key = [42u8; 32];
        let (token, host) = host_pairing(&ia, vault, vault_key, Role::Admin, &mut sa)
            .await
            .unwrap();
        let db_root = db.path().to_path_buf();
        let join = tokio::spawn(join_pairing(ib.clone(), db_root, token));

        let approved = host.accept_auto().await.unwrap();
        assert_eq!(approved, ib.peer_id(), "host approves B's peer id");

        let (sb, joiner_vault_key, joiner_founder) = join.await.unwrap().unwrap();
        assert_eq!(
            *joiner_vault_key, vault_key,
            "the joiner must receive the host's shared vault key"
        );
        assert_eq!(
            joiner_founder,
            ia.peer_id(),
            "the joiner must learn the host's founder pin"
        );

        assert!(
            sa.roster()
                .iter()
                .any(|p| p.peer_id == ib.peer_id() && p.status == PeerStatus::Active),
            "A must trust B after pairing"
        );
        assert!(
            sb.roster()
                .iter()
                .any(|p| p.peer_id == ia.peer_id() && p.status == PeerStatus::Active),
            "B must trust A after pairing"
        );
    }

    /// An admin host founds the vault and pairs in a joiner with `Role::Reader`.
    /// Both the invitee role AND the founder pin must ride the proven stream, so
    /// the joiner's persisted vault materializes exactly that role.
    #[tokio::test(flavor = "multi_thread")]
    async fn pairing_delivers_the_invitee_role_and_founder_pin() {
        let da = tempdir().unwrap();
        let db = tempdir().unwrap();
        let ia = Identity::generate();
        let ib = Identity::generate();
        let vault = VaultId::generate();

        let mut sa = Store::open(da.path(), ia.clone()).unwrap();
        sa.declare_founder(Role::Admin).unwrap();
        let host_founder_peer_id = ia.peer_id();

        let (token, host) = host_pairing(&ia, vault, [42u8; 32], Role::Reader, &mut sa)
            .await
            .unwrap();
        let joiner_vault_path = db.path().to_path_buf();
        let join = tokio::spawn(join_pairing(ib.clone(), joiner_vault_path.clone(), token));

        host.accept_auto().await.unwrap();
        let (sb, _vk, founder) = join.await.unwrap().unwrap();
        assert_eq!(founder, host_founder_peer_id);
        assert_eq!(sb.self_role(), Some(Role::Reader));
        assert_eq!(sb.founder_pin(), Some(host_founder_peer_id));

        // Reopening the persisted vault yields the same folded role + pin.
        let joiner = Store::open(&joiner_vault_path, ib.clone()).unwrap();
        assert_eq!(joiner.self_role(), Some(Role::Reader));
        assert_eq!(joiner.founder_pin(), Some(host_founder_peer_id));
    }

    /// The host rotates BEFORE pairing; the joiner must come away able to open the
    /// rotated epoch (the host wrapped it to the joiner during accept).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_joiner_receives_the_keylog_and_can_open_a_rotated_epoch() {
        let da = tempdir().unwrap();
        let db = tempdir().unwrap();
        let ia = Identity::generate();
        let ib = Identity::generate();
        let vault = VaultId::generate();
        let vault_key = [42u8; 32];
        let (id_key, epoch0) = vault_subkeys(&vault_key);

        let mut sa = Store::open(da.path(), ia.clone()).unwrap();
        sa.declare_founder(Role::Admin).unwrap();
        // Host rotates while alone -> mints epoch 1, wrapped to itself.
        let rotated = sa.rotate_epoch(&id_key, &epoch0, None).unwrap();
        assert!(sa
            .keychain(&id_key, &epoch0)
            .unwrap()
            .epoch_key(&rotated)
            .is_some());

        let (token, host) = host_pairing(&ia, vault, vault_key, Role::Admin, &mut sa)
            .await
            .unwrap();
        let db_root = db.path().to_path_buf();
        let join = tokio::spawn(join_pairing(ib.clone(), db_root, token));

        host.accept_auto().await.unwrap();
        let (sb, _vk, _founder) = join.await.unwrap().unwrap();

        // The joiner can open the epoch the host minted before B existed.
        let kc_b = sb.keychain(&id_key, &epoch0).unwrap();
        assert!(
            kc_b.epoch_key(&rotated).is_some(),
            "joiner must recover the rotated epoch key via the seeded key-log + wrap"
        );
        assert_eq!(
            kc_b.epoch_key(&rotated),
            sa.keychain(&id_key, &epoch0).unwrap().epoch_key(&rotated),
            "same epoch key on both sides"
        );
    }

    /// P2 (pairing DoS): a hostile peer that connects FIRST with a garbage proof
    /// must not burn the single-use secret. The host keeps accepting until a
    /// valid proof arrives (or the accept window closes), so the real joiner —
    /// arriving after the attacker is rejected — still pairs successfully.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bad_proof_does_not_consume_the_pairing_session() {
        let da = tempdir().unwrap();
        let db = tempdir().unwrap();
        let ia = Identity::generate();
        let attacker = Identity::generate();
        let ib = Identity::generate();
        let vault = VaultId::generate();

        let mut sa = Store::open(da.path(), ia.clone()).unwrap();
        sa.declare_founder(Role::Admin).unwrap();

        let vault_key = [42u8; 32];
        let attacker_peer = attacker.peer_id();
        let (token, host) = host_pairing(&ia, vault, vault_key, Role::Admin, &mut sa)
            .await
            .unwrap();
        let token_decoded = PairingToken::decode(&token).unwrap();
        let attacker_addr = token_decoded.addr.clone();
        let db_path = db.path().to_path_buf();

        // `PairingHost` borrows the store, so it cannot be spawned; run it inline
        // via `join!` alongside the joiners, which are chained attacker-then-real
        // so the host provably handles (and rejects) the bad proof first.
        let joiners = async {
            // Attacker connects FIRST, signs the wrong bytes.
            let bad = async {
                let endpoint = build_endpoint(&attacker).await?;
                let conn = endpoint.connect(attacker_addr, PAIRING_ALPN).await?;
                let (mut send, mut recv) = conn.open_bi().await?;
                let proof = attacker.sign(b"not the pairing secret").to_bytes().to_vec();
                let req = JoinRequest {
                    verifying_key: attacker.verifying_key().to_bytes(),
                    peer_id: attacker.peer_id(),
                    proof,
                };
                write_msg(&mut send, &req).await?;
                send.finish()?;
                let accepted: Result<JoinAccept> = read_msg(&mut recv).await;
                endpoint.close().await;
                anyhow::Ok(accepted.is_ok())
            }
            .await
            .unwrap_or(false);
            // Then the real joiner — the session must have survived the rejection.
            let real = join_pairing(ib.clone(), db_path, token).await;
            (bad, real)
        };

        let (host_res, (attacker_got_accept, real)) = tokio::join!(host.accept_auto(), joiners);

        assert!(!attacker_got_accept, "attacker must not be accepted");
        let (sb, joiner_vault_key, _founder) = real.unwrap();
        assert_eq!(*joiner_vault_key, vault_key);
        assert_eq!(
            host_res.unwrap(),
            ib.peer_id(),
            "host pairs the real joiner despite the earlier bad proof"
        );

        assert!(
            sa.roster()
                .iter()
                .any(|p| p.peer_id == ib.peer_id() && p.status == PeerStatus::Active),
            "the real joiner must be trusted"
        );
        assert!(
            !sa.roster().iter().any(|p| p.peer_id == attacker_peer),
            "the attacker must never be added"
        );
        let _ = &sb;
    }

    /// Fail-closed: a joiner whose proof signs the WRONG bytes is rejected, and
    /// A's roster does NOT gain B.
    #[tokio::test(flavor = "multi_thread")]
    async fn pairing_rejects_a_forged_proof() {
        let da = tempdir().unwrap();
        let ia = Identity::generate();
        let ib = Identity::generate();
        let vault = VaultId::generate();

        let mut sa = Store::open(da.path(), ia.clone()).unwrap();
        let (token, host) = host_pairing(&ia, vault, [0u8; 32], Role::Admin, &mut sa)
            .await
            .unwrap();
        let token_decoded = PairingToken::decode(&token).unwrap();
        let b_peer = ib.peer_id();

        // Malicious joiner: sign the WRONG bytes, so the proof cannot verify.
        let bad_join = tokio::spawn(async move {
            let endpoint = build_endpoint(&ib).await?;
            let conn = endpoint
                .connect(token_decoded.addr.clone(), PAIRING_ALPN)
                .await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            let proof = ib.sign(b"not the pairing secret").to_bytes().to_vec();
            let req = JoinRequest {
                verifying_key: ib.verifying_key().to_bytes(),
                peer_id: ib.peer_id(),
                proof,
            };
            write_msg(&mut send, &req).await?;
            send.finish()?;
            // The host rejects, so a JoinAccept never arrives (read fails/EOF).
            let accepted: Result<JoinAccept> = read_msg(&mut recv).await;
            endpoint.close().await;
            anyhow::Ok(accepted.is_ok())
        });

        // Only a malicious joiner connects; accept over a short window so the
        // test does not wait the full interactive timeout for the Err.
        let host_res = host.accept_for(Duration::from_secs(5)).await;
        assert!(host_res.is_err(), "forged proof must be rejected");

        // The joiner must not have received an accept.
        let joiner_got_accept = bad_join.await.unwrap().unwrap_or(false);
        assert!(
            !joiner_got_accept,
            "rejected joiner must not receive a JoinAccept"
        );

        assert!(
            !sa.roster().iter().any(|p| p.peer_id == b_peer),
            "a peer with a forged proof must NOT be added to the roster"
        );
    }

    /// Fail-closed: a joiner that presents a VALID key + proof but a `peer_id`
    /// that does not derive from that key (first 8 LE bytes) is rejected at the
    /// storage chokepoint, and A's roster does NOT gain it. Without the binding
    /// the joiner could poison op attribution (`key_for(peer_id)` maps wrong).
    #[tokio::test(flavor = "multi_thread")]
    async fn pairing_rejects_a_mismatched_peer_id() {
        let da = tempdir().unwrap();
        let ia = Identity::generate();
        let ib = Identity::generate();
        let vault = VaultId::generate();

        let mut sa = Store::open(da.path(), ia.clone()).unwrap();
        let (token, host) = host_pairing(&ia, vault, [0u8; 32], Role::Admin, &mut sa)
            .await
            .unwrap();
        let token_decoded = PairingToken::decode(&token).unwrap();
        // A peer_id that does NOT match ib's key.
        let bad_peer_id = ib.peer_id().wrapping_add(1);

        // Malicious joiner: a VALID proof over the real secret, but a peer_id
        // that does not derive from the presented key.
        let bad_join = tokio::spawn(async move {
            let endpoint = build_endpoint(&ib).await?;
            let conn = endpoint
                .connect(token_decoded.addr.clone(), PAIRING_ALPN)
                .await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            let proof = ib
                .sign_in_domain(PAIRING_PROOF_DOMAIN, &token_decoded.secret)
                .to_bytes()
                .to_vec();
            let req = JoinRequest {
                verifying_key: ib.verifying_key().to_bytes(),
                peer_id: bad_peer_id,
                proof,
            };
            write_msg(&mut send, &req).await?;
            send.finish()?;
            let accepted: Result<JoinAccept> = read_msg(&mut recv).await;
            endpoint.close().await;
            anyhow::Ok(accepted.is_ok())
        });

        // Only a malicious joiner connects; accept over a short window so the
        // test does not wait the full interactive timeout for the Err.
        let host_res = host.accept_for(Duration::from_secs(5)).await;
        assert!(host_res.is_err(), "a mismatched peer_id must be rejected");

        let joiner_got_accept = bad_join.await.unwrap().unwrap_or(false);
        assert!(
            !joiner_got_accept,
            "rejected joiner must not receive a JoinAccept"
        );

        assert!(
            sa.roster().is_empty(),
            "a peer whose peer_id != derived(key) must NOT be added to the roster"
        );
    }
}
