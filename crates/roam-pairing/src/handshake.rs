//! Pairing a device into a vault through a relay mailbox, authenticated by a
//! six-digit code.
//!
//! ## Why this flow exists
//!
//! The other two flows both need to dial: the token flow opens a QUIC connection
//! to an [`iroh::EndpointAddr`], and the LAN flow finds its peer over mDNS. A
//! browser tab can do neither — it has no UDP socket and never will — so a web
//! client could hold a vault but could never *join* one. That is the gap this
//! closes, and it closes it without inventing a new trust model: the
//! authentication is the same SPAKE2 handshake the LAN flow uses, the payload is
//! the same [`JoinAccept`], and the import order is the same
//! [`adopt_accept`](crate::adopt_accept).
//!
//! What changes is only what carries the bytes, and the honest consequence of
//! that change is written out under "What the relay can do" below.
//!
//! ## Handshake
//!
//! Six write-once slots in one mailbox session. Nobody dials anybody; each side
//! polls for the slot it is waiting on.
//!
//! ```text
//! joiner (initiator, types the code)      host (responder, shows the code)
//!   -- msg1 ------------------------------>
//!   <------------------------------ msg2 --
//!   -- confirm-joiner -------------------->  verify; a wrong code stops here
//!   <-------------------- confirm-host ----
//!   == both sides now hold a session key; everything below is sealed ==
//!   -- request{key, peer_id} ------------->  add_peer, backfill wraps
//!   <---------------------------- accept --  vault key, rosters, key log,
//!                                            founder pin
//! ```
//!
//! The joiner proves first, exactly as in the LAN flow, so the host never hands
//! its confirmation — the only oracle a guesser has — to a peer that has not
//! already committed to a guess.
//!
//! ## The SPAKE2 identities, and why they are what they are
//!
//! SPAKE2 binds two identity strings into the exchange so that a key agreed with
//! one party is worthless when replayed at another. The LAN flow uses the two
//! iroh endpoint ids, which QUIC has already authenticated. Here there is no
//! transport authentication at all — the relay authenticates nobody — so the
//! choice has to be made on other grounds. It is:
//!
//! * **initiator** — the 32 bytes of the **session id**, which is the mailbox
//!   path the joiner minted.
//! * **responder** — the **host's verifying key**, which the joiner has from the
//!   [`Invite`].
//!
//! Two properties fall out, and both were the reason for picking these:
//!
//! 1. **A substituted invite fails as a wrong code.** An attacker who hands the
//!    joiner an invite naming its own key makes the joiner bind a different
//!    responder identity than the real host binds. The two runs cannot agree on
//!    a key, so the handshake dies at the confirmation rather than at some later
//!    point where the joiner has already imported an attacker's key log. The
//!    host key in the invite is therefore *checked*, not merely *trusted* — by
//!    the code, which is the only thing here that authenticates anything.
//! 2. **Nothing new is disclosed to the relay.** Both identities are values the
//!    relay either routes on already (the session id) or never receives at all
//!    (the host key, which is mixed in but not sent). An earlier sketch put the
//!    joiner's public key in `msg1` so it could be bound the way the LAN flow
//!    binds it; that would have handed the relay a stable device identifier for
//!    every join, in exchange for nothing — see the next section.
//!
//! ## Why the joiner's key is not bound into the transcript
//!
//! The LAN flow checks that the key a joiner claims equals the endpoint id QUIC
//! authenticated, because there it *is* possible for two identities to disagree:
//! proving the code proves this connection saw six digits, not which long-term
//! key sits behind it. Here there is no second, independently authenticated
//! identity for the claim to disagree with. The claim arrives inside
//! [`Slot::Request`](crate::Slot::Request), sealed under a key that only a holder
//! of the code can produce — so the claim already carries exactly the assurance
//! the LAN check manufactures, and binding it into the transcript as well would
//! add nothing but a disclosure.
//!
//! The claim is still not taken on faith: `Store::add_peer` refuses any
//! `peer_id` that is not the first eight little-endian bytes of the key, which is
//! the chokepoint that keeps op attribution honest.
//!
//! ## What the relay can do
//!
//! It can **drop** — that is denial of service, and it is unavoidable for any
//! party that carries the bytes. It can **read**, and sees two SPAKE2 messages
//! (which reveal nothing testable), two MACs, and two ciphertexts. It can
//! **substitute**, and every substitution fails: the confirmations are MACs over
//! the whole transcript, and the payloads are sealed.
//!
//! What it learns is that *someone* paired at rendezvous R at a given time. Not
//! which vault — the bucket id never appears in this protocol — and not which
//! devices.
//!
//! ## The attempt budget, and what an attacker gets for burning it
//!
//! [`roam_pake::MAX_ATTEMPTS`] wrong confirmations retire the code, exactly as on
//! the LAN, and for the same reason: twenty bits is only safe if guesses are
//! countable. The difference from the LAN flow is reach — an attacker there had
//! to be on the same network, and an attacker here needs only the rendezvous id.
//! That is why the rendezvous id is 32 random bytes and not a function of the
//! code; see [`crate::invite`]. An attacker who somehow *has* the rendezvous id
//! can burn three attempts and force the user to start over. That is a denial of
//! service against one pairing session, and it is the same trade the LAN flow
//! already makes deliberately.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use roam_pake::{Initiator, PairingCode, Responder, Side};
use roam_storage::{Identity, Role, Store, VaultId, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::accept::{adopt_accept, enrol_joiner, JoinAccept, Joined};
use crate::invite::Invite;
use crate::mailbox::{Mailbox, Slot, SlotOutcome};
use crate::sleep;

/// How long either side waits for one slot to appear before abandoning the
/// session. Long enough for a human on a slow link, short enough that a peer
/// which writes `msg1` and vanishes cannot park the host for long — and the host
/// serves sessions one at a time, so this is exactly what a staller costs.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(20);

/// How often to re-read a slot that is not there yet. A pairing is an
/// interactive, user-present action, so a handful of round trips at this cadence
/// is well inside what a human reads as "immediate", and it keeps a waiting
/// device from hammering the relay.
pub const POLL_INTERVAL: Duration = Duration::from_millis(400);

/// How long a host keeps a code showing if nothing happens.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Joiner → host, sealed: which device is asking to be enrolled.
///
/// No proof accompanies it, and none would mean anything: the sealing key
/// already proves the code, and `add_peer` binds `peer_id` to `verifying_key`.
#[derive(Serialize, Deserialize)]
struct MailboxJoinRequest {
    verifying_key: [u8; 32],
    peer_id: u64,
}

/// A host with a code showing, waiting for one device to claim it.
pub struct MailboxHost<'a, M: Mailbox> {
    mailbox: M,
    invite: Invite,
    responder: Responder,
    identity: &'a Identity,
    vault: VaultId,
    vault_key: [u8; 32],
    role: Role,
    store: &'a mut Store,
    step_timeout: Duration,
    poll_interval: Duration,
}

impl<M: Mailbox> Drop for MailboxHost<'_, M> {
    /// Wipe the vault key when the host drops. (`MailboxHost` holds borrows, so
    /// this is a manual `Drop` rather than the `ZeroizeOnDrop` derive.)
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.vault_key.zeroize();
    }
}

/// Arm a host: mint an invite and a code, and stand ready to accept one join.
///
/// Returns the code to show the human and the armed host. The [`Invite`] —
/// which carries no secret — is available from
/// [`MailboxHost::invite`](MailboxHost::invite) and is what the joiner needs in
/// order to find the mailbox.
///
/// Nothing is published to the relay yet: a host writes its first slot only in
/// response to a joiner's `msg1`, so an armed-but-unused invite leaves no trace
/// on the relay at all.
pub fn host_via_mailbox<'a, M: Mailbox>(
    identity: &'a Identity,
    vault: VaultId,
    vault_key: [u8; 32],
    role: Role,
    store: &'a mut Store,
    mailbox: M,
    invite: Invite,
) -> (PairingCode, MailboxHost<'a, M>) {
    let code = PairingCode::generate();
    let responder = Responder::new(code.clone(), invite.host_key);
    (
        code,
        MailboxHost {
            mailbox,
            invite,
            responder,
            identity,
            vault,
            vault_key,
            role,
            store,
            step_timeout: STEP_TIMEOUT,
            poll_interval: POLL_INTERVAL,
        },
    )
}

impl<M: Mailbox> MailboxHost<'_, M> {
    /// The public invitation to hand the joiner.
    pub fn invite(&self) -> &Invite {
        &self.invite
    }

    /// The code's remaining guess budget. At zero the code is dead.
    pub fn attempts_left(&self) -> u32 {
        self.responder.attempts_left()
    }

    /// Test seam: shorten the per-slot wait so proving that a stalled session is
    /// survivable does not require sitting out [`STEP_TIMEOUT`].
    pub fn with_timeouts(mut self, step: Duration, poll: Duration) -> Self {
        self.step_timeout = step;
        self.poll_interval = poll;
        self
    }

    /// Accept one join, or give up when the window closes or the guess budget is
    /// spent. Consumes `self`, so a code is good for exactly one pairing.
    pub async fn accept_auto(self) -> Result<u64> {
        self.accept_for(DEFAULT_WINDOW).await
    }

    /// [`accept_auto`](Self::accept_auto) with an explicit window, so a test — or
    /// a UI with its own cancel button — need not wait out the default.
    ///
    /// Sessions are served **one at a time**, in the order they appear. That
    /// mirrors both other flows, and it has the same consequence: a session that
    /// stalls costs every later joiner [`STEP_TIMEOUT`] of waiting. It costs them
    /// nothing else — a stalled or wrong session is abandoned and the loop moves
    /// on, and only a wrong *confirmation* spends an attempt.
    pub async fn accept_for(mut self, window: Duration) -> Result<u64> {
        let deadline = crate::deadline_from_now(window);
        let mut served: Vec<String> = Vec::new();

        loop {
            if self.responder.attempts_left() == 0 {
                bail!("too many wrong codes — this pairing code is used up, show a fresh one");
            }
            if crate::past(deadline) {
                bail!("timed out waiting for a device to type the pairing code");
            }

            let sessions = self
                .mailbox
                .sessions()
                .await
                .context("list pairing sessions")?;
            let mut worked = false;
            for session in sessions {
                if served.iter().any(|s| s == &session) {
                    continue;
                }
                // A session with no `msg1` yet is one a joiner is still writing;
                // leave it for the next tick rather than burning a step timeout.
                let Some(msg1) = self.mailbox.get(&session, Slot::Msg1).await? else {
                    continue;
                };
                served.push(session.clone());
                worked = true;
                match self.serve(&session, &msg1).await {
                    Ok(peer_id) => return Ok(peer_id),
                    // This session only. The code survives unless `verify`
                    // charged for it, and the next joiner gets a clean run.
                    Err(_rejected) => continue,
                }
            }
            if !worked {
                sleep(self.poll_interval).await;
            }
        }
    }

    /// One session, start to finish. Any error abandons just this session.
    async fn serve(&mut self, session: &str, msg1: &[u8]) -> Result<u64> {
        // The initiator identity is the session id itself — a value the relay
        // already routes on, so binding it discloses nothing new, and one the
        // joiner cannot vary after the fact because it *is* the path its
        // messages are at.
        let initiator_id = decode_session_id(session)?;

        let (pending, msg2) = self
            .responder
            .respond(initiator_id, msg1)
            .map_err(anyhow::Error::from)?;
        self.write(session, Slot::Msg2, msg2).await?;

        let their_confirm: [u8; 32] = self
            .read(session, Slot::ConfirmJoiner)
            .await?
            .try_into()
            .map_err(|_| anyhow::anyhow!("malformed confirmation"))?;
        // The budget is charged here and nowhere else — only by a peer that
        // committed to a guess and got it wrong.
        let (key, our_confirm) = self
            .responder
            .verify(pending, &their_confirm)
            .map_err(anyhow::Error::from)?;
        self.write(session, Slot::ConfirmHost, our_confirm.to_vec())
            .await?;
        let (mut sealer, mut opener) = key.split(Side::Responder);

        // --- authenticated; the joiner may now name itself ------------------
        let request: MailboxJoinRequest =
            serde_json::from_slice(&opener.open(&self.read(session, Slot::Request).await?)?)
                .context("decode the joiner's request")?;

        let accept = enrol_joiner(
            self.store,
            self.identity,
            self.vault,
            &self.vault_key,
            self.role,
            request.verifying_key,
            request.peer_id,
        )?;
        let sealed = sealer.seal(&serde_json::to_vec(&accept).context("serialize accept")?);
        self.write(session, Slot::Accept, sealed).await?;
        Ok(request.peer_id)
    }

    /// Write a slot, refusing to continue if somebody wrote there first — a
    /// taken slot means this session is not ours to finish.
    async fn write(&self, session: &str, slot: Slot, body: Vec<u8>) -> Result<()> {
        match self.mailbox.put(session, slot, body).await? {
            SlotOutcome::Written => Ok(()),
            SlotOutcome::AlreadyTaken => {
                bail!(
                    "pairing slot {} was already written — abandoning",
                    slot.as_str()
                )
            }
        }
    }

    async fn read(&self, session: &str, slot: Slot) -> Result<Vec<u8>> {
        await_slot(
            &self.mailbox,
            session,
            slot,
            self.step_timeout,
            self.poll_interval,
        )
        .await
    }
}

/// Type the code and join, through the mailbox the invite names.
///
/// The joiner's store must already be open — a browser has no filesystem path to
/// hand this function, so opening is the caller's job on every platform rather
/// than one platform's job.
///
/// On success the store holds the founder pin, the host's transitive roster and
/// its key log; the returned [`Joined`] carries the vault id and the vault key
/// the caller must persist.
pub async fn join_via_mailbox<M: Mailbox>(
    identity: &Identity,
    store: &mut Store,
    mailbox: &M,
    invite: &Invite,
    code: &PairingCode,
) -> Result<Joined> {
    join_via_mailbox_inner(
        identity,
        store,
        mailbox,
        invite,
        code,
        STEP_TIMEOUT,
        POLL_INTERVAL,
        None,
    )
    .await
}

/// Seams that exist only so tests can drive dishonest behaviour. Every entry
/// point here breaks a rule the honest path enforces; none is for production.
pub mod testing {
    use super::*;

    /// [`join_via_mailbox`] with the waits shortened, so a test need not sit out
    /// the production timeouts.
    #[allow(clippy::too_many_arguments)]
    pub async fn join_via_mailbox_with_timeouts<M: Mailbox>(
        identity: &Identity,
        store: &mut Store,
        mailbox: &M,
        invite: &Invite,
        code: &PairingCode,
        step: Duration,
        poll: Duration,
    ) -> Result<Joined> {
        join_via_mailbox_inner(identity, store, mailbox, invite, code, step, poll, None).await
    }

    /// [`join_via_mailbox`] that claims a key and peer id other than its own —
    /// something an honest joiner cannot do, which is exactly why the binding
    /// `add_peer` enforces needs a test that can.
    #[allow(clippy::too_many_arguments)]
    pub async fn join_via_mailbox_claiming<M: Mailbox>(
        identity: &Identity,
        store: &mut Store,
        mailbox: &M,
        invite: &Invite,
        code: &PairingCode,
        step: Duration,
        poll: Duration,
        claimed: ([u8; 32], u64),
    ) -> Result<Joined> {
        join_via_mailbox_inner(
            identity,
            store,
            mailbox,
            invite,
            code,
            step,
            poll,
            Some(claimed),
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn join_via_mailbox_inner<M: Mailbox>(
    identity: &Identity,
    store: &mut Store,
    mailbox: &M,
    invite: &Invite,
    code: &PairingCode,
    step: Duration,
    poll: Duration,
    claim_instead: Option<([u8; 32], u64)>,
) -> Result<Joined> {
    // The key the host's key log will be authenticated with. It is only as good
    // as the invite — and that is fine, because binding it into the SPAKE2 run
    // below means a wrong key cannot survive the confirmation.
    let host_key = VerifyingKey::from_bytes(&invite.host_key)
        .context("invite carried a malformed host key")?;

    let (session, session_bytes) = new_session_id();
    let (initiator, msg1) = Initiator::start(code, session_bytes, invite.host_key);

    // A session id we minted a moment ago cannot be taken; if it is, something
    // is badly wrong and continuing would be talking to whoever took it.
    if mailbox.put(&session, Slot::Msg1, msg1).await? != SlotOutcome::Written {
        bail!("pairing session id collided — retry");
    }

    let msg2 = await_slot(mailbox, &session, Slot::Msg2, step, poll).await?;
    let (pending, our_confirm) = initiator.accept(&msg2).map_err(anyhow::Error::from)?;
    if mailbox
        .put(&session, Slot::ConfirmJoiner, our_confirm.to_vec())
        .await?
        != SlotOutcome::Written
    {
        bail!("pairing confirmation slot was already written — abandoning");
    }

    // A joiner CANNOT be told its code was wrong, and that is not an oversight:
    // the host's confirmation is the only value a guesser could test candidates
    // against, so the host withholds it from anyone who has not already proved
    // the code. The observable result of a wrong code is therefore silence, and
    // silence is indistinguishable from a host that closed the window or went
    // offline.
    //
    // Nothing can be done about the ambiguity without handing over the oracle.
    // What can be done is to stop reporting the most likely cause as an
    // inscrutable protocol timeout — "waiting for the other device to write
    // `confirm-host`" is true and useless to the person who mistyped a digit.
    let their_confirm: [u8; 32] = await_slot(mailbox, &session, Slot::ConfirmHost, step, poll)
        .await
        .context(
            "the other device did not answer — most likely the code was wrong, \
             or its pairing window has closed. Ask for a fresh code and try again",
        )?
        .try_into()
        .map_err(|_| anyhow::anyhow!("malformed confirmation"))?;
    // Mutual authentication completes here. Nothing above this line may be
    // acted on, and nothing below it is sent before it.
    let key = pending
        .verify(&their_confirm)
        .map_err(anyhow::Error::from)?;
    let (mut sealer, mut opener) = key.split(Side::Initiator);

    let (verifying_key, peer_id) =
        claim_instead.unwrap_or((identity.verifying_key().to_bytes(), identity.peer_id()));
    let request = serde_json::to_vec(&MailboxJoinRequest {
        verifying_key,
        peer_id,
    })
    .context("serialize join request")?;
    if mailbox
        .put(&session, Slot::Request, sealer.seal(&request))
        .await?
        != SlotOutcome::Written
    {
        bail!("pairing request slot was already written — abandoning");
    }

    let accept: JoinAccept = serde_json::from_slice(
        &opener.open(&await_slot(mailbox, &session, Slot::Accept, step, poll).await?)?,
    )
    .context("decode the host's accept")?;

    adopt_accept(store, accept, &host_key)
}

/// Poll a slot until it holds something, or `timeout` elapses.
async fn await_slot<M: Mailbox>(
    mailbox: &M,
    session: &str,
    slot: Slot,
    timeout: Duration,
    poll: Duration,
) -> Result<Vec<u8>> {
    let deadline = crate::deadline_from_now(timeout);
    loop {
        if let Some(body) = mailbox.get(session, slot).await? {
            return Ok(body);
        }
        if crate::past(deadline) {
            bail!(
                "timed out waiting for the other device to write `{}`",
                slot.as_str()
            );
        }
        sleep(poll).await;
    }
}

/// A fresh session id: 32 random bytes, as base64url and as bytes. The bytes are
/// the SPAKE2 initiator identity, so they must be unpredictable for the same
/// reason the rendezvous id must be.
fn new_session_id() -> (String, [u8; 32]) {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    (B64URL.encode(bytes), bytes)
}

/// A session id is only a valid identity if it really is 32 bytes of base64url.
/// A host that accepted anything else would bind a different identity than the
/// joiner did, and every such session would fail at the confirmation with a
/// message blaming the code.
fn decode_session_id(session: &str) -> Result<[u8; 32]> {
    let bytes = B64URL
        .decode(session)
        .context("pairing session id is not base64url")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("pairing session id is not 32 bytes"))
}

/// Surfaced so callers can tell "wrong code, try again" from a real failure
/// without matching on strings.
pub use roam_pake::PakeError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_id_round_trips_and_a_bad_one_is_refused() {
        let (session, bytes) = new_session_id();
        assert_eq!(decode_session_id(&session).unwrap(), bytes);
        assert!(decode_session_id("not base64!!").is_err());
        // Right charset, wrong length: this is the case that would otherwise
        // silently bind a different identity on each side.
        assert!(decode_session_id(&B64URL.encode([0u8; 31])).is_err());
    }

    #[test]
    fn a_pake_error_survives_as_itself() {
        // `accept_for` and its callers distinguish a wrong code from a broken
        // peer by downcast, which only works if the error is not flattened.
        let err: anyhow::Error = PakeError::BadCode.into();
        assert_eq!(err.downcast_ref::<PakeError>(), Some(&PakeError::BadCode));
    }
}
