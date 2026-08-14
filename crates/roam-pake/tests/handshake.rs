//! The properties that make a 6-digit code safe. If any of these stops holding,
//! the code becomes a ~20-bit secret on the wire and the flow must not ship.

use roam_pake::{Initiator, PairingCode, PakeError, Responder, SessionKey, Side, MAX_ATTEMPTS};

const HOST_ID: [u8; 32] = [1u8; 32];
const JOINER_ID: [u8; 32] = [2u8; 32];

/// Drive a full run. Returns both session keys, or the first error.
fn run(
    initiator_code: &PairingCode,
    responder: &mut Responder,
    initiator_id: [u8; 32],
    responder_id: [u8; 32],
) -> Result<(SessionKey, SessionKey), PakeError> {
    let (initiator, msg1) = Initiator::start(initiator_code, initiator_id, responder_id);
    let (pending_responder, msg2) = responder.respond(initiator_id, &msg1)?;
    let (pending_initiator, initiator_confirm) = initiator.accept(&msg2)?;
    let (responder_key, responder_confirm) = responder.verify(pending_responder, &initiator_confirm)?;
    let initiator_key = pending_initiator.verify(&responder_confirm)?;
    Ok((initiator_key, responder_key))
}

#[test]
fn the_right_code_pairs_and_both_sides_agree_on_a_key() {
    let code = PairingCode::generate();
    let mut responder = Responder::new(code.clone(), HOST_ID);

    let (initiator_key, responder_key) =
        run(&code, &mut responder, JOINER_ID, HOST_ID).expect("the correct code must pair");

    // Agreeing on "a key" is not enough — it has to be the SAME key.
    let (mut responder_send, _) = responder_key.split(Side::Responder);
    let (_, mut initiator_recv) = initiator_key.split(Side::Initiator);
    let sealed = responder_send.seal(b"the vault key");
    assert_eq!(initiator_recv.open(&sealed).unwrap(), b"the vault key");
}

#[test]
fn a_wrong_code_is_refused() {
    let real = PairingCode::parse("123456").unwrap();
    let wrong = PairingCode::parse("123457").unwrap();
    let mut responder = Responder::new(real, HOST_ID);

    assert_eq!(
        run(&wrong, &mut responder, JOINER_ID, HOST_ID).unwrap_err(),
        PakeError::BadCode
    );
}

/// The identity binding, which is what closes same-LAN MITM. A handshake meant
/// for one device must not verify when replayed against another, even with the
/// correct code.
#[test]
fn a_run_bound_to_one_device_does_not_verify_against_another() {
    let code = PairingCode::generate();
    let impostor_id = [9u8; 32];

    // The joiner believes it is talking to HOST_ID...
    let (initiator, msg1) = Initiator::start(&code, JOINER_ID, HOST_ID);
    // ...but the run is answered by a different device, which knows the code.
    let mut impostor = Responder::new(code.clone(), impostor_id);
    let (pending_responder, msg2) = impostor.respond(JOINER_ID, &msg1).unwrap();
    let (_, initiator_confirm) = initiator.accept(&msg2).unwrap();

    assert_eq!(
        impostor.verify(pending_responder, &initiator_confirm).unwrap_err(),
        PakeError::BadCode,
        "a key bound to one endpoint id verified against another — MITM is open"
    );
}

/// The budget is what turns "one guess per run" into a real bound. Without it a
/// million runs breaks a six-digit code.
#[test]
fn the_attempt_budget_is_enforced() {
    let real = PairingCode::parse("000000").unwrap();
    let wrong = PairingCode::parse("999999").unwrap();
    let mut responder = Responder::new(real.clone(), HOST_ID);
    assert_eq!(responder.attempts_left(), MAX_ATTEMPTS);

    for attempt in 0..MAX_ATTEMPTS {
        assert_eq!(
            run(&wrong, &mut responder, JOINER_ID, HOST_ID).unwrap_err(),
            PakeError::BadCode,
            "guess {attempt} should be a wrong-code failure"
        );
    }

    // Budget exhausted: even the CORRECT code is now refused. The user has to
    // ask for a fresh one.
    assert_eq!(
        run(&real, &mut responder, JOINER_ID, HOST_ID).unwrap_err(),
        PakeError::NoAttemptsLeft
    );
}

/// An attempt is spent by a GUESS, and a guess is a confirmation we reject —
/// not the mere act of starting a run.
///
/// This reverses an earlier decision here, which charged at `respond` on the
/// reasoning that otherwise an attacker could "start a run, learn from the
/// responder's reply whether the guess was right, disconnect, and repeat".
/// That reasoning does not hold: `msg2` carries no information an initiator can
/// test a password against — withholding the responder's confirmation until the
/// initiator proves first is exactly what makes the guess *online*, and being
/// unable to test offline is the defining property of a PAKE. So an abandoned
/// run reveals nothing and must cost nothing.
///
/// Charging at `respond` was not merely unnecessary, it was exploitable: see
/// [`garbage_from_a_stranger_cannot_burn_the_guess_budget`].
#[test]
fn an_abandoned_run_does_not_spend_an_attempt() {
    let code = PairingCode::generate();
    let mut responder = Responder::new(code.clone(), HOST_ID);

    let (_initiator, msg1) = Initiator::start(&code, JOINER_ID, HOST_ID);
    let _ = responder.respond(JOINER_ID, &msg1).unwrap();
    // Walk away without ever confirming: no guess was made.

    assert_eq!(
        responder.attempts_left(),
        MAX_ATTEMPTS,
        "starting a run is not a guess and must not cost one"
    );
}

/// The budget exists to bound *guessing*. If unparseable bytes spend it, then
/// anyone who can reach the endpoint — no code, no guess — can retire the code
/// by sending rubbish three times, killing a share or a pairing session
/// outright. The endpoint is announced over mDNS, so "anyone" means any device
/// on the network.
#[test]
fn garbage_from_a_stranger_cannot_burn_the_guess_budget() {
    let code = PairingCode::generate();
    let mut responder = Responder::new(code, HOST_ID);

    for _ in 0..MAX_ATTEMPTS + 5 {
        assert_eq!(
            responder
                .respond(JOINER_ID, b"not a spake2 message")
                .unwrap_err(),
            PakeError::MalformedMessage
        );
    }

    assert_eq!(
        responder.attempts_left(),
        MAX_ATTEMPTS,
        "rubbish is not a guess; a stranger must not be able to retire the code"
    );
}

/// The responder must not hand its confirmation to a peer that failed, or that
/// value becomes an oracle to test guesses against.
#[test]
fn a_failed_initiator_learns_nothing_from_the_responder() {
    let code = PairingCode::parse("111111").unwrap();
    let mut responder = Responder::new(code, HOST_ID);
    let (_, msg1) = Initiator::start(&PairingCode::parse("222222").unwrap(), JOINER_ID, HOST_ID);
    let (pending, _msg2) = responder.respond(JOINER_ID, &msg1).unwrap();

    // `verify` returns Result<(SessionKey, confirm)> — an error yields NEITHER,
    // so there is no path that leaks the confirmation on failure. The type
    // signature is the guarantee; this asserts the error case is taken.
    assert!(responder.verify(pending, &[0u8; 32]).is_err());
}

#[test]
fn a_replayed_confirmation_from_the_wrong_role_is_refused() {
    let code = PairingCode::generate();
    let mut responder = Responder::new(code.clone(), HOST_ID);

    let (initiator, msg1) = Initiator::start(&code, JOINER_ID, HOST_ID);
    let (pending_responder, msg2) = responder.respond(JOINER_ID, &msg1).unwrap();
    let (pending_initiator, initiator_confirm) = initiator.accept(&msg2).unwrap();
    let (_key, _responder_confirm) = responder.verify(pending_responder, &initiator_confirm).unwrap();

    // Echo the initiator's own confirmation back at it instead of the
    // responder's. Role tagging must make these different values.
    assert_eq!(
        pending_initiator.verify(&initiator_confirm).unwrap_err(),
        PakeError::BadCode,
        "confirmations are not role-separated; one can be reflected"
    );
}

#[test]
fn a_malformed_message_is_rejected_rather_than_panicking() {
    let code = PairingCode::generate();
    let mut responder = Responder::new(code.clone(), HOST_ID);
    assert_eq!(
        responder.respond(JOINER_ID, b"not a spake2 message").unwrap_err(),
        PakeError::MalformedMessage
    );

    let (initiator, _msg1) = Initiator::start(&code, JOINER_ID, HOST_ID);
    assert_eq!(
        initiator.accept(b"garbage").unwrap_err(),
        PakeError::MalformedMessage
    );
}

#[test]
fn a_tampered_sealed_payload_is_refused() {
    let code = PairingCode::generate();
    let mut responder = Responder::new(code.clone(), HOST_ID);
    let (initiator_key, responder_key) = run(&code, &mut responder, JOINER_ID, HOST_ID).unwrap();

    let (mut responder_send, _) = responder_key.split(Side::Responder);
    let (_, mut initiator_recv) = initiator_key.split(Side::Initiator);
    let mut sealed = responder_send.seal(b"the vault key");
    let last = sealed.len() - 1;
    sealed[last] ^= 0x01;
    assert_eq!(
        initiator_recv.open(&sealed).unwrap_err(),
        PakeError::Undecryptable
    );
}

#[test]
fn codes_are_six_digits_and_parse_strictly() {
    let generated = PairingCode::generate();
    assert_eq!(generated.as_str().len(), 6);
    assert!(generated.as_str().chars().all(|c| c.is_ascii_digit()));

    assert!(PairingCode::parse("012345").is_ok());
    assert!(PairingCode::parse("  012345  ").is_ok(), "whitespace is trimmed");
    assert!(PairingCode::parse("12345").is_err(), "too short");
    assert!(PairingCode::parse("1234567").is_err(), "too long");
    assert!(PairingCode::parse("12345a").is_err(), "not all digits");
    assert!(PairingCode::parse("12 345").is_err(), "inner space");
}

/// Leading zeros must survive: "000123" and "123" are different codes, and a
/// generator that dropped the padding would shrink the space.
#[test]
fn generated_codes_keep_their_leading_zeros() {
    for _ in 0..2_000 {
        assert_eq!(PairingCode::generate().as_str().len(), 6);
    }
}

/// A code must never reach a log.
#[test]
fn debug_output_redacts_the_code() {
    let code = PairingCode::parse("424242").unwrap();
    let shown = format!("{code:?}");
    assert!(!shown.contains("424242"), "Debug leaked the code: {shown}");
}

/// The reason `SessionKey` is not a single fixed-nonce sealer any more. Two
/// messages with identical plaintext must produce different ciphertext; if they
/// did not, the nonce is being reused and ChaCha20-Poly1305 loses both
/// confidentiality and authenticity.
#[test]
fn sealing_twice_does_not_reuse_the_nonce() {
    let code = PairingCode::generate();
    let mut responder = Responder::new(code.clone(), HOST_ID);
    let (initiator_key, responder_key) = run(&code, &mut responder, JOINER_ID, HOST_ID).unwrap();
    let (mut send, _) = responder_key.split(Side::Responder);
    let (_, mut recv) = initiator_key.split(Side::Initiator);

    let first = send.seal(b"same plaintext");
    let second = send.seal(b"same plaintext");
    assert_ne!(first, second, "identical plaintext sealed to identical bytes");

    // ...and they still open, in order.
    assert_eq!(recv.open(&first).unwrap(), b"same plaintext");
    assert_eq!(recv.open(&second).unwrap(), b"same plaintext");
}

/// Messages must arrive in order. A repeat is a replay and a skip is a gap;
/// both fail to open rather than being silently tolerated.
#[test]
fn a_replayed_or_reordered_message_does_not_open() {
    let code = PairingCode::generate();
    let mut responder = Responder::new(code.clone(), HOST_ID);
    let (initiator_key, responder_key) = run(&code, &mut responder, JOINER_ID, HOST_ID).unwrap();
    let (mut send, _) = responder_key.split(Side::Responder);
    let (_, mut recv) = initiator_key.split(Side::Initiator);

    let first = send.seal(b"one");
    let second = send.seal(b"two");

    // Out of order: the second message does not open in the first slot.
    assert_eq!(recv.open(&second).unwrap_err(), PakeError::Undecryptable);
    // Recover by taking them in order...
    assert_eq!(recv.open(&first).unwrap(), b"one");
    assert_eq!(recv.open(&second).unwrap(), b"two");
    // ...and a replay of an already-consumed message is refused.
    assert_eq!(recv.open(&first).unwrap_err(), PakeError::Undecryptable);
}

/// Directions use separate keys, so a message cannot be reflected back at the
/// party that sent it.
#[test]
fn a_message_cannot_be_reflected_back_at_its_sender() {
    let code = PairingCode::generate();
    let mut responder = Responder::new(code.clone(), HOST_ID);
    let (initiator_key, responder_key) = run(&code, &mut responder, JOINER_ID, HOST_ID).unwrap();
    let (mut initiator_send, mut initiator_recv) = initiator_key.split(Side::Initiator);
    let (_responder_send, mut responder_recv) = responder_key.split(Side::Responder);

    let sealed = initiator_send.seal(b"from the initiator");
    // The responder can read it, as intended.
    assert_eq!(responder_recv.open(&sealed).unwrap(), b"from the initiator");

    // Bounce the very same bytes back: the initiator must not accept its own
    // message as though the responder had sent it.
    assert_eq!(
        initiator_recv.open(&sealed).unwrap_err(),
        PakeError::Undecryptable,
        "directions share a key; a message can be reflected"
    );
}
