//! The mailbox: six write-once slots per session, and nothing else.
//!
//! Pairing needs a two-way channel between devices that may never be able to
//! reach each other directly — a browser tab and a phone, say. The relay already
//! stands between them, so it can carry the handshake, but only if it is given a
//! shape that keeps it as ignorant as it is for everything else it stores.
//!
//! That shape is this: a **rendezvous** (named by 32 unguessable bytes the host
//! mints) holds **sessions** (named by 32 bytes a joiner mints), and each session
//! holds six named slots. A slot is written once. There is no delete, no list of
//! slot contents, no way to ask the relay anything about a body it holds.
//!
//! # What write-once actually buys, which is not what it looks like
//!
//! The obvious answer is that it stops a relay rewriting a handshake message to
//! split the two sides' views of the transcript. That is *not* what is doing the
//! work: the confirmations in [`roam_pake`] are MACs over both SPAKE2 messages,
//! so a rewritten message fails the confirmation whether or not the write was
//! allowed. Tampering is caught by the MACs, and it is caught with a dishonest
//! relay too — which write-once could never help with, since a relay that is
//! willing to rewrite is willing to ignore its own rule.
//!
//! What write-once actually buys is that **squatting is free rather than
//! fatal**. Anyone who knows the rendezvous can open a session and write the slot
//! the *host* was going to write, plus a garbage confirmation. A host that
//! shrugged at the taken slot and carried on would then verify a confirmation
//! against a transcript it never wrote — which fails, and spends one of three
//! attempts. Three of those retire the code without the squatter guessing a
//! single digit. Refusing to continue past a taken slot is what makes that cost
//! nothing. See `squatting_a_slot_costs_the_host_no_attempts`, which fails if
//! either half of that (the relay's refusal or the host's) is removed.
//!
//! It also means a session is *consumed*: a peer that grabs a session id and
//! writes rubbish into it has spoiled that session and no other. The joiner mints
//! a fresh one and tries again, which is why sessions exist at all rather than
//! the six slots living directly under the rendezvous.
//!
//! # What the relay learns
//!
//! A rendezvous id, some session ids, and six opaque bodies per session. Not the
//! bucket, not the vault, not either device's key: the SPAKE2 identities are the
//! session and rendezvous ids the relay already routes on, and everything after
//! the handshake is sealed under a key derived from a code the relay never sees.
//! See [`crate::handshake`] for why that particular choice of identity strings.

use crate::MaybeSendSync;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

/// The six messages one handshake exchanges, and the only slot names a relay
/// accepts.
///
/// An enum rather than a free string so the wire names live in one place and a
/// caller cannot invent a seventh — the relay enforces the same allowlist, and
/// two allowlists that can drift are one allowlist too many.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    /// Joiner → host: the SPAKE2 first message.
    Msg1,
    /// Host → joiner: the SPAKE2 second message.
    Msg2,
    /// Joiner → host: the joiner's key confirmation. It proves first.
    ConfirmJoiner,
    /// Host → joiner: the host's key confirmation, withheld until the joiner's
    /// verifies — it is the only oracle a guesser would have.
    ConfirmHost,
    /// Joiner → host, sealed: which device it is asking to enrol.
    Request,
    /// Host → joiner, sealed: the vault key, rosters, key log and founder pin.
    Accept,
}

impl Slot {
    pub fn as_str(self) -> &'static str {
        match self {
            Slot::Msg1 => "msg1",
            Slot::Msg2 => "msg2",
            Slot::ConfirmJoiner => "confirm-joiner",
            Slot::ConfirmHost => "confirm-host",
            Slot::Request => "request",
            Slot::Accept => "accept",
        }
    }

    /// Every slot, so a relay implementation (or a test double) can build its
    /// allowlist from the protocol rather than from a copied list.
    pub const ALL: [Slot; 6] = [
        Slot::Msg1,
        Slot::Msg2,
        Slot::ConfirmJoiner,
        Slot::ConfirmHost,
        Slot::Request,
        Slot::Accept,
    ];

    pub fn parse(name: &str) -> Option<Slot> {
        Slot::ALL.into_iter().find(|slot| slot.as_str() == name)
    }
}

/// What a write met when it landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotOutcome {
    Written,
    /// Somebody wrote here first. The caller's message did NOT land, and the
    /// slot still holds whatever it held — this is never "close enough".
    AlreadyTaken,
}

/// A rendezvous, as seen by one device. The rendezvous id is fixed when the
/// implementation is constructed, so it cannot vary per call.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait Mailbox: MaybeSendSync {
    /// Write a slot. Must not overwrite: a slot that already holds bytes returns
    /// [`SlotOutcome::AlreadyTaken`] and the stored body is untouched.
    async fn put(&self, session: &str, slot: Slot, body: Vec<u8>) -> anyhow::Result<SlotOutcome>;

    /// Read a slot, or `None` if it has not been written yet. Absence is the
    /// normal case while polling, not an error.
    async fn get(&self, session: &str, slot: Slot) -> anyhow::Result<Option<Vec<u8>>>;

    /// Session ids present under this rendezvous. The host polls this to notice
    /// a joiner; the joiner never needs it.
    async fn sessions(&self) -> anyhow::Result<Vec<String>>;
}

/// An in-process mailbox, for tests and for a same-device flow.
///
/// Shared by cloning: every clone addresses the same slots, which is what lets a
/// test hand one end to a host and the other to a joiner without a relay.
type Slots = std::sync::Arc<Mutex<HashMap<(String, Slot), Vec<u8>>>>;

#[derive(Clone, Default)]
pub struct MemoryMailbox {
    slots: Slots,
}

impl MemoryMailbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Overwrite a slot regardless of whether it is taken — the one thing the
    /// trait promises never to do, exposed so a test can play a relay that
    /// breaks its promise. Not available to protocol code.
    #[doc(hidden)]
    pub fn force(&self, session: &str, slot: Slot, body: Vec<u8>) {
        self.slots
            .lock()
            .expect("mailbox mutex poisoned")
            .insert((session.to_string(), slot), body);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Mailbox for MemoryMailbox {
    async fn put(&self, session: &str, slot: Slot, body: Vec<u8>) -> anyhow::Result<SlotOutcome> {
        let mut slots = self.slots.lock().expect("mailbox mutex poisoned");
        let key = (session.to_string(), slot);
        if slots.contains_key(&key) {
            return Ok(SlotOutcome::AlreadyTaken);
        }
        slots.insert(key, body);
        Ok(SlotOutcome::Written)
    }

    async fn get(&self, session: &str, slot: Slot) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .slots
            .lock()
            .expect("mailbox mutex poisoned")
            .get(&(session.to_string(), slot))
            .cloned())
    }

    async fn sessions(&self) -> anyhow::Result<Vec<String>> {
        let slots = self.slots.lock().expect("mailbox mutex poisoned");
        let mut names: Vec<String> = slots.keys().map(|(session, _)| session.clone()).collect();
        names.sort();
        names.dedup();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_slot_round_trips_through_its_wire_name() {
        // The relay parses these names from a URL path and this enum writes
        // them. A name that serialises to something `parse` does not accept is a
        // slot the two halves disagree about, which shows up as a hung
        // handshake rather than an error.
        for slot in Slot::ALL {
            assert_eq!(Slot::parse(slot.as_str()), Some(slot));
        }
    }

    #[test]
    fn slot_names_are_all_distinct() {
        // Two slots sharing a name would silently alias, so the host would read
        // its own message back as the joiner's.
        let mut names: Vec<&str> = Slot::ALL.iter().map(|slot| slot.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two slots share a wire name");
    }

    #[tokio::test]
    async fn a_written_slot_refuses_a_second_write_and_keeps_the_first() {
        // Write-once is what stops a relay rewriting a handshake message after
        // the other side has already read and MAC'd it. "Refused" is not enough
        // on its own — the original bytes must still be what a reader gets.
        let mailbox = MemoryMailbox::new();
        assert_eq!(
            mailbox
                .put("s", Slot::Msg1, b"first".to_vec())
                .await
                .unwrap(),
            SlotOutcome::Written
        );
        assert_eq!(
            mailbox
                .put("s", Slot::Msg1, b"second".to_vec())
                .await
                .unwrap(),
            SlotOutcome::AlreadyTaken
        );
        assert_eq!(
            mailbox.get("s", Slot::Msg1).await.unwrap(),
            Some(b"first".to_vec())
        );
    }

    #[tokio::test]
    async fn slots_and_sessions_do_not_bleed_into_each_other() {
        let mailbox = MemoryMailbox::new();
        mailbox.put("a", Slot::Msg1, b"a1".to_vec()).await.unwrap();
        mailbox.put("a", Slot::Msg2, b"a2".to_vec()).await.unwrap();
        mailbox.put("b", Slot::Msg1, b"b1".to_vec()).await.unwrap();

        assert_eq!(
            mailbox.get("a", Slot::Msg1).await.unwrap(),
            Some(b"a1".to_vec())
        );
        assert_eq!(
            mailbox.get("b", Slot::Msg1).await.unwrap(),
            Some(b"b1".to_vec())
        );
        assert_eq!(mailbox.get("b", Slot::Msg2).await.unwrap(), None);
        assert_eq!(
            mailbox.sessions().await.unwrap(),
            vec!["a".to_string(), "b".to_string()]
        );
    }
}
