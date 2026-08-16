//! End-to-end mailbox pairing, including the ways it must fail.
//!
//! These run over [`MemoryMailbox`], which is a faithful stand-in for the relay
//! in the one respect that matters here — write-once slots, no authentication,
//! everything visible to whoever holds it. Where a test needs the relay to
//! misbehave it wraps the mailbox in one that lies, which is the one thing a
//! conforming mailbox promises never to do.

use std::time::Duration;

use roam_pairing::handshake::testing::{join_via_mailbox_claiming, join_via_mailbox_with_timeouts};
use roam_pairing::mailbox::{Mailbox, Slot};
use roam_pairing::{host_via_mailbox, Invite, MemoryMailbox, PairingCode};
use roam_storage::{vault_subkeys, Identity, PeerStatus, Role, Store, VaultId};
use tempfile::TempDir;

/// Short enough that a failing handshake does not sit out the production wait.
const STEP: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(5);
const WINDOW: Duration = Duration::from_secs(10);

struct Fixture {
    host_store: Store,
    host_identity: Identity,
    joiner_store: Store,
    joiner_identity: Identity,
    invite: Invite,
    mailbox: MemoryMailbox,
    _dirs: (TempDir, TempDir),
}

fn fixture() -> Fixture {
    let (host_dir, joiner_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (host_identity, joiner_identity) = (Identity::generate(), Identity::generate());
    let mut host_store = Store::open(host_dir.path(), host_identity.clone()).unwrap();
    host_store.declare_founder(Role::Admin).unwrap();
    let joiner_store = Store::open(joiner_dir.path(), joiner_identity.clone()).unwrap();
    let invite = Invite::generate(
        "https://relay.example",
        host_identity.verifying_key().to_bytes(),
    );

    Fixture {
        host_store,
        host_identity,
        joiner_store,
        joiner_identity,
        invite,
        mailbox: MemoryMailbox::new(),
        _dirs: (host_dir, joiner_dir),
    }
}

/// A code that is definitely not `code`, without a one-in-a-million flake.
fn a_different_code(code: &PairingCode) -> PairingCode {
    let wrong = (code.as_str().parse::<u32>().unwrap() + 1) % 1_000_000;
    PairingCode::parse(&format!("{wrong:06}")).unwrap()
}

const VAULT_KEY: [u8; 32] = [42u8; 32];

#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_that_types_the_code_ends_up_in_the_roster_with_the_vault_key() {
    let mut fixture = fixture();
    let vault = VaultId::generate();

    let (code, host) = host_via_mailbox(
        &fixture.host_identity,
        vault,
        VAULT_KEY,
        Role::Writer,
        &mut fixture.host_store,
        fixture.mailbox.clone(),
        fixture.invite.clone(),
    );
    let host = host.with_timeouts(STEP, POLL);

    let (host_result, join_result) = tokio::join!(host.accept_for(WINDOW), async {
        join_via_mailbox_with_timeouts(
            &fixture.joiner_identity,
            &mut fixture.joiner_store,
            &fixture.mailbox,
            &fixture.invite,
            &code,
            STEP,
            POLL,
        )
        .await
    });

    assert_eq!(
        host_result.expect("host accepts"),
        fixture.joiner_identity.peer_id()
    );
    let joined = join_result.expect("joiner joins");
    assert_eq!(
        joined.vault, vault,
        "the joiner learns which vault it joined"
    );
    assert_eq!(*joined.vault_key, VAULT_KEY);
    assert_eq!(joined.founder, fixture.host_identity.peer_id());

    assert_eq!(
        fixture.joiner_store.self_role(),
        Some(Role::Writer),
        "the joiner must materialise the role the host granted"
    );
    assert!(
        fixture
            .host_store
            .roster()
            .iter()
            .any(|p| p.peer_id == fixture.joiner_identity.peer_id()
                && p.status == PeerStatus::Active),
        "the host must trust the joiner"
    );
    assert!(
        fixture
            .joiner_store
            .roster()
            .iter()
            .any(|p| p.peer_id == fixture.host_identity.peer_id()
                && p.status == PeerStatus::Active),
        "the joiner must trust the host"
    );
}

/// The property the whole design rests on: the relay carries every byte, and
/// none of them is the vault key.
///
/// Asserted by searching the entire transcript for the key rather than by
/// inspecting one slot — a leak through a field nobody thought to check is
/// exactly the kind this should catch.
#[tokio::test(flavor = "multi_thread")]
async fn the_vault_key_never_appears_anywhere_in_the_mailbox() {
    let mut fixture = fixture();
    // A key with no structure a search could miss, and one that cannot occur by
    // chance in a 32-byte-aligned transcript.
    let vault_key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));

    let (code, host) = host_via_mailbox(
        &fixture.host_identity,
        VaultId::generate(),
        vault_key,
        Role::Admin,
        &mut fixture.host_store,
        fixture.mailbox.clone(),
        fixture.invite.clone(),
    );
    let host = host.with_timeouts(STEP, POLL);

    let (host_result, join_result) = tokio::join!(host.accept_for(WINDOW), async {
        join_via_mailbox_with_timeouts(
            &fixture.joiner_identity,
            &mut fixture.joiner_store,
            &fixture.mailbox,
            &fixture.invite,
            &code,
            STEP,
            POLL,
        )
        .await
    });
    host_result.expect("host accepts");
    let joined = join_result.expect("joiner joins");
    assert_eq!(*joined.vault_key, vault_key, "the joiner did receive it");

    for session in fixture.mailbox.sessions().await.unwrap() {
        for slot in Slot::ALL {
            let Some(body) = fixture.mailbox.get(&session, slot).await.unwrap() else {
                continue;
            };
            assert!(
                !body.windows(vault_key.len()).any(|w| w == vault_key),
                "the vault key is sitting in plaintext in slot {}",
                slot.as_str()
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_code_learns_nothing_and_enrols_nobody() {
    let mut fixture = fixture();

    let (code, host) = host_via_mailbox(
        &fixture.host_identity,
        VaultId::generate(),
        VAULT_KEY,
        Role::Admin,
        &mut fixture.host_store,
        fixture.mailbox.clone(),
        fixture.invite.clone(),
    );
    let wrong = a_different_code(&code);
    let host = host.with_timeouts(STEP, POLL);

    // The host's window closes with no valid join, so it errors too.
    let (host_result, join_result) = tokio::join!(host.accept_for(Duration::from_secs(3)), async {
        join_via_mailbox_with_timeouts(
            &fixture.joiner_identity,
            &mut fixture.joiner_store,
            &fixture.mailbox,
            &fixture.invite,
            &wrong,
            STEP,
            POLL,
        )
        .await
    });

    assert!(join_result.is_err(), "a wrong code must not join");
    assert!(host_result.is_err(), "a wrong code must not be accepted");
    assert!(
        !fixture
            .host_store
            .roster()
            .iter()
            .any(|p| p.peer_id == fixture.joiner_identity.peer_id()),
        "a peer that could not prove the code must never reach the roster"
    );
    assert_eq!(
        fixture.joiner_store.self_role(),
        None,
        "the joiner must not come away believing it is a member"
    );
}

/// Twenty bits is only safe if guesses are counted. Three wrong ones retire the
/// code — after which even the *right* code is refused, because the session the
/// code belonged to is over.
#[tokio::test(flavor = "multi_thread")]
async fn three_wrong_codes_retire_the_session() {
    let mut fixture = fixture();

    let (code, host) = host_via_mailbox(
        &fixture.host_identity,
        VaultId::generate(),
        VAULT_KEY,
        Role::Admin,
        &mut fixture.host_store,
        fixture.mailbox.clone(),
        fixture.invite.clone(),
    );
    let wrong = a_different_code(&code);
    let host = host.with_timeouts(STEP, POLL);
    let mailbox = fixture.mailbox.clone();
    let invite = fixture.invite.clone();
    let real_code = PairingCode::parse(code.as_str()).unwrap();

    // A short step, because a guesser that got it wrong waits out its OWN
    // timeout: the host refuses to write `confirm-host` to a peer that failed,
    // since that value is the only oracle a guesser would have. So each wrong
    // guess costs the guesser a full step and the window has to cover all three.
    let step = Duration::from_millis(500);

    let guessers = async {
        // Each guesser needs its own store; a joiner store is mutated on success
        // and these must be independent attempts.
        for _ in 0..roam_pairing::MAX_ATTEMPTS {
            let dir = tempfile::tempdir().unwrap();
            let identity = Identity::generate();
            let mut store = Store::open(dir.path(), identity.clone()).unwrap();
            let _ = join_via_mailbox_with_timeouts(
                &identity, &mut store, &mailbox, &invite, &wrong, step, POLL,
            )
            .await;
        }
        // Now the honest user types the RIGHT code — too late.
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::generate();
        let mut store = Store::open(dir.path(), identity.clone()).unwrap();
        join_via_mailbox_with_timeouts(
            &identity, &mut store, &mailbox, &invite, &real_code, step, POLL,
        )
        .await
    };

    let (host_result, honest_result) = tokio::join!(host.accept_for(WINDOW), guessers);

    let err = host_result.expect_err("a used-up code must accept nobody");
    assert!(
        err.to_string().contains("used up"),
        "the user needs to be told to show a fresh code, got: {err}"
    );
    assert!(
        honest_result.is_err(),
        "once the budget is spent even the right code must be refused"
    );
    assert_eq!(
        fixture.host_store.roster().len(),
        1,
        "only the founder's own entry may remain"
    );
}

/// The claim the identity binding makes: an attacker who substitutes the invite
/// — naming its own key as the host — cannot get a joiner to pair with it, even
/// though the invite carries no signature and no secret.
///
/// The failure is at the confirmation, not later: the joiner must never reach
/// the point of importing anything under the attacker's key.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_naming_the_wrong_host_key_fails_as_a_wrong_code() {
    let mut fixture = fixture();

    let (code, host) = host_via_mailbox(
        &fixture.host_identity,
        VaultId::generate(),
        VAULT_KEY,
        Role::Admin,
        &mut fixture.host_store,
        fixture.mailbox.clone(),
        fixture.invite.clone(),
    );
    let host = host.with_timeouts(STEP, POLL);

    // Same rendezvous and same relay — only the host key is swapped, which is
    // all a tampering relay or a swapped QR could change.
    let impostor = Identity::generate();
    let mut tampered = fixture.invite.clone();
    tampered.host_key = impostor.verifying_key().to_bytes();

    let (host_result, join_result) = tokio::join!(host.accept_for(Duration::from_secs(3)), async {
        join_via_mailbox_with_timeouts(
            &fixture.joiner_identity,
            &mut fixture.joiner_store,
            &fixture.mailbox,
            &tampered,
            // The RIGHT code. Only the invite is wrong.
            &code,
            STEP,
            POLL,
        )
        .await
    });

    assert!(
        join_result.is_err(),
        "a joiner must not pair through an invite naming a key the host does not hold"
    );
    assert!(host_result.is_err());
    assert_eq!(
        fixture.joiner_store.self_role(),
        None,
        "nothing may have been imported"
    );
    assert_eq!(
        fixture.joiner_store.founder_pin(),
        None,
        "not even the founder pin — the handshake must die before any import"
    );
}

/// A relay that flips a byte of whichever slot it is pointed at, on the way out.
///
/// Deterministic where a racing task is not: the joiner cannot read the honest
/// bytes first, because the honest bytes are never what it is handed. That is
/// also the stronger attack — a relay does not have to win a race to corrupt
/// what it serves.
struct TamperingMailbox {
    inner: MemoryMailbox,
    corrupt: Slot,
}

#[async_trait::async_trait]
impl Mailbox for TamperingMailbox {
    async fn put(
        &self,
        session: &str,
        slot: Slot,
        body: Vec<u8>,
    ) -> anyhow::Result<roam_pairing::SlotOutcome> {
        self.inner.put(session, slot, body).await
    }

    async fn get(&self, session: &str, slot: Slot) -> anyhow::Result<Option<Vec<u8>>> {
        let body = self.inner.get(session, slot).await?;
        Ok(body.map(|mut bytes| {
            if slot == self.corrupt && !bytes.is_empty() {
                bytes[0] ^= 0xff;
            }
            bytes
        }))
    }

    async fn sessions(&self) -> anyhow::Result<Vec<String>> {
        self.inner.sessions().await
    }
}

/// Write-once keeps an *honest* relay from splitting the transcript; the
/// confirmations are what keep a dishonest one from doing it. Corrupting either
/// SPAKE2 message must end the handshake, not merely be noticed later.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_that_rewrites_a_handshake_message_breaks_the_handshake() {
    for corrupt in [Slot::Msg1, Slot::Msg2, Slot::ConfirmHost] {
        let mut fixture = fixture();

        let (code, host) = host_via_mailbox(
            &fixture.host_identity,
            VaultId::generate(),
            VAULT_KEY,
            Role::Admin,
            &mut fixture.host_store,
            TamperingMailbox {
                inner: fixture.mailbox.clone(),
                corrupt,
            },
            fixture.invite.clone(),
        );
        let host = host.with_timeouts(Duration::from_millis(500), POLL);
        let joiner_view = TamperingMailbox {
            inner: fixture.mailbox.clone(),
            corrupt,
        };

        let (host_result, join_result) =
            tokio::join!(host.accept_for(Duration::from_secs(3)), async {
                join_via_mailbox_with_timeouts(
                    &fixture.joiner_identity,
                    &mut fixture.joiner_store,
                    &joiner_view,
                    &fixture.invite,
                    &code,
                    Duration::from_millis(500),
                    POLL,
                )
                .await
            });

        assert!(
            join_result.is_err(),
            "a corrupted {} must not produce a session",
            corrupt.as_str()
        );
        assert!(host_result.is_err(), "corrupted {}", corrupt.as_str());
        assert!(
            !fixture
                .host_store
                .roster()
                .iter()
                .any(|p| p.peer_id == fixture.joiner_identity.peer_id()),
            "nobody may be enrolled off a transcript corrupted at {}",
            corrupt.as_str()
        );
        assert_eq!(
            fixture.joiner_store.founder_pin(),
            None,
            "the joiner must import nothing when {} was corrupted",
            corrupt.as_str()
        );
    }
}

/// Proving the code proves a peer knows six digits, not which key it holds. The
/// chokepoint that stops a code-holder smuggling a third party into the roster
/// is `add_peer`'s binding of `peer_id` to the key it derives from.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_cannot_enrol_a_peer_id_that_does_not_match_its_key() {
    let mut fixture = fixture();

    let (code, host) = host_via_mailbox(
        &fixture.host_identity,
        VaultId::generate(),
        VAULT_KEY,
        Role::Admin,
        &mut fixture.host_store,
        fixture.mailbox.clone(),
        fixture.invite.clone(),
    );
    let host = host.with_timeouts(STEP, POLL);
    let bogus_peer_id = fixture.joiner_identity.peer_id().wrapping_add(1);

    let (host_result, join_result) = tokio::join!(host.accept_for(Duration::from_secs(3)), async {
        join_via_mailbox_claiming(
            &fixture.joiner_identity,
            &mut fixture.joiner_store,
            &fixture.mailbox,
            &fixture.invite,
            &code,
            STEP,
            POLL,
            (
                fixture.joiner_identity.verifying_key().to_bytes(),
                bogus_peer_id,
            ),
        )
        .await
    });

    assert!(host_result.is_err(), "a mismatched peer_id must be refused");
    assert!(join_result.is_err());
    assert_eq!(
        fixture.host_store.roster().len(),
        1,
        "only the founder's own entry may remain"
    );
}

/// A session that opens and then goes quiet must cost later joiners time and
/// nothing else — not the code, not the host's willingness to keep listening.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_session_does_not_stop_the_next_joiner() {
    let mut fixture = fixture();

    let (code, host) = host_via_mailbox(
        &fixture.host_identity,
        VaultId::generate(),
        VAULT_KEY,
        Role::Admin,
        &mut fixture.host_store,
        fixture.mailbox.clone(),
        fixture.invite.clone(),
    );
    // A very short step timeout so the stalled session is abandoned quickly;
    // that is the production behaviour, just not the production duration.
    let host = host.with_timeouts(Duration::from_millis(200), POLL);

    // A session with a msg1 the host will answer, and then silence forever.
    fixture
        .mailbox
        .put("A".repeat(43).as_str(), Slot::Msg1, vec![0u8; 33])
        .await
        .unwrap();

    let (host_result, join_result) = tokio::join!(host.accept_for(WINDOW), async {
        join_via_mailbox_with_timeouts(
            &fixture.joiner_identity,
            &mut fixture.joiner_store,
            &fixture.mailbox,
            &fixture.invite,
            &code,
            STEP,
            POLL,
        )
        .await
    });

    assert_eq!(
        host_result.expect("the honest joiner must still get through"),
        fixture.joiner_identity.peer_id()
    );
    join_result.expect("the honest joiner must still get through");
}

/// Squatting the host's slot must not cost the host an attempt.
///
/// This is what write-once buys, and it is not obvious. A third party that knows
/// the rendezvous can open a session, write a well-formed `msg1`, and *also*
/// write the `msg2` the host was going to write, plus a garbage
/// `confirm-joiner`. If the host shrugged at the taken slot and carried on, it
/// would then verify a confirmation against a transcript it did not write —
/// which fails, and spends one of three attempts. Three of those retire the code
/// without the squatter ever guessing a digit.
///
/// Refusing to continue past a taken slot is what makes that free instead of
/// fatal. Mutation-checked: with the refusal removed, the honest joiner below is
/// turned away because the budget is already gone.
#[tokio::test(flavor = "multi_thread")]
async fn squatting_a_slot_costs_the_host_no_attempts() {
    let mut fixture = fixture();

    let (code, host) = host_via_mailbox(
        &fixture.host_identity,
        VaultId::generate(),
        VAULT_KEY,
        Role::Admin,
        &mut fixture.host_store,
        fixture.mailbox.clone(),
        fixture.invite.clone(),
    );
    let host = host.with_timeouts(Duration::from_millis(500), POLL);

    // One squatted session per attempt in the budget, so if any of them charged
    // one the honest joiner at the end would be refused.
    for index in 0..roam_pairing::MAX_ATTEMPTS {
        let session_bytes = [index as u8 + 1; 32];
        let session = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            session_bytes,
        );
        // Well-formed, under a code of the squatter's own choosing — a garbage
        // msg1 would be rejected before the host ever reached the taken slot,
        // and would prove nothing.
        let (_initiator, msg1) = roam_pake::Initiator::start(
            &PairingCode::parse("111111").unwrap(),
            session_bytes,
            fixture.invite.host_key,
        );
        fixture
            .mailbox
            .put(&session, Slot::Msg1, msg1)
            .await
            .unwrap();
        // The squat: the host's own slot, taken before the host can write it.
        fixture
            .mailbox
            .put(&session, Slot::Msg2, vec![7u8; 33])
            .await
            .unwrap();
        // And something for the host to verify, if it were foolish enough to.
        fixture
            .mailbox
            .put(&session, Slot::ConfirmJoiner, vec![0u8; 32])
            .await
            .unwrap();
    }

    let (host_result, join_result) = tokio::join!(host.accept_for(WINDOW), async {
        join_via_mailbox_with_timeouts(
            &fixture.joiner_identity,
            &mut fixture.joiner_store,
            &fixture.mailbox,
            &fixture.invite,
            &code,
            STEP,
            POLL,
        )
        .await
    });

    assert_eq!(
        host_result.expect("squatted sessions must not retire the code"),
        fixture.joiner_identity.peer_id()
    );
    join_result.expect("the honest joiner must still get in");
}

/// A host that rotated before pairing must leave the joiner able to open the
/// epoch it minted — the wraps are backfilled during enrolment, and a joiner
/// that arrives in `WaitingKey` has no way out but another rotation.
#[tokio::test(flavor = "multi_thread")]
async fn a_joiner_can_open_an_epoch_minted_before_it_existed() {
    let mut fixture = fixture();
    let (id_key, epoch0) = vault_subkeys(&VAULT_KEY);
    let rotated = fixture
        .host_store
        .rotate_epoch(&id_key, &epoch0, None)
        .unwrap();

    let (code, host) = host_via_mailbox(
        &fixture.host_identity,
        VaultId::generate(),
        VAULT_KEY,
        Role::Admin,
        &mut fixture.host_store,
        fixture.mailbox.clone(),
        fixture.invite.clone(),
    );
    let host = host.with_timeouts(STEP, POLL);

    let (host_result, join_result) = tokio::join!(host.accept_for(WINDOW), async {
        join_via_mailbox_with_timeouts(
            &fixture.joiner_identity,
            &mut fixture.joiner_store,
            &fixture.mailbox,
            &fixture.invite,
            &code,
            STEP,
            POLL,
        )
        .await
    });
    host_result.expect("host accepts");
    join_result.expect("joiner joins");

    let joiner_keychain = fixture.joiner_store.keychain(&id_key, &epoch0).unwrap();
    assert_eq!(
        joiner_keychain.epoch_key(&rotated),
        fixture
            .host_store
            .keychain(&id_key, &epoch0)
            .unwrap()
            .epoch_key(&rotated),
        "the joiner must recover the epoch key the host minted before it existed"
    );
    assert!(
        joiner_keychain.epoch_key(&rotated).is_some(),
        "and it must actually be present, not equally absent on both sides"
    );
}
