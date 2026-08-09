use crate::frame::Frame;
use crate::transport::Transport;
use futures::StreamExt;
use roam_storage::{Identity, PeerStatus, Store, VaultId, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Drives sync for one device over a [`Transport`]. Owns the [`Store`]; local
/// edits go through the engine so it can live-push.
pub struct Engine<T: Transport> {
    identity: Identity,
    vault: VaultId,
    store: Arc<Mutex<Store>>,
    transport: Arc<T>,
    /// Per-peer byte offset of our own oplog already pushed to that peer.
    sent_offsets: Arc<Mutex<HashMap<u64, usize>>>,
    /// Peers we have already answered with our own `Hello` bundle. Guards the
    /// one-time reverse handshake so two peers that both connect (and both see
    /// each other's `Hello`) never trade `Hello`s forever.
    connected: Arc<Mutex<HashSet<u64>>>,
}

/// Everything we offer a peer on connect or in a `Hello` reply, gathered under a
/// single store lock so the transport sends happen lock-free afterwards.
struct Offer {
    doc_version: Vec<u8>,
    roster_have: Vec<(u64, u64)>,
    own_log: Vec<u8>,
    own_roster: Vec<u8>,
    /// Held third-party logs to relay: `(author, jsonl)`.
    peer_logs: Vec<(u64, Vec<u8>)>,
}

impl<T: Transport + 'static> Engine<T> {
    pub fn new(identity: Identity, vault: VaultId, store: Store, transport: Arc<T>) -> Self {
        Self {
            identity,
            vault,
            store: Arc::new(Mutex::new(store)),
            transport,
            sent_offsets: Arc::new(Mutex::new(HashMap::new())),
            connected: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn store(&self) -> Arc<Mutex<Store>> {
        self.store.clone()
    }

    fn peer_id(&self) -> u64 {
        self.identity.peer_id()
    }

    /// Open a connection: send Hello, RosterHave, Have, offer our logs and
    /// roster. Idempotent enough for the mesh — resent logs are deduped on
    /// import.
    pub async fn connect(&self, peer: u64) -> anyhow::Result<()> {
        self.transport.dial(peer).await?;
        self.send_bundle(peer).await;
        Ok(())
    }

    /// Apply a local text edit and live-push it to all connected peers.
    pub async fn edit_text(&self, id: &str, pos: usize, s: &str) -> anyhow::Result<()> {
        let own_log = {
            let mut store = self.store.lock().await;
            store.edit_text(id, pos, s)?;
            store.export_own_log()?
        };

        // Compute per-peer suffixes and advance offsets under the offsets lock
        // only (no store lock, no transport await held).
        let pushes: Vec<(u64, Vec<u8>)> = {
            let mut offsets = self.sent_offsets.lock().await;
            offsets
                .iter_mut()
                .filter_map(|(&peer, offset)| {
                    let start = (*offset).min(own_log.len());
                    let suffix = own_log[start..].to_vec();
                    *offset = own_log.len();
                    (!suffix.is_empty()).then_some((peer, suffix))
                })
                .collect()
        };

        for (peer, jsonl) in pushes {
            self.send(
                peer,
                Frame::Ops {
                    author: self.peer_id(),
                    jsonl,
                },
            )
            .await;
        }
        Ok(())
    }

    /// Vouch for `peer` (holding `key`) locally, then gossip the updated roster
    /// to every connected peer so they learn the new device (transitive mesh).
    pub async fn add_peer(&self, peer: u64, key: [u8; 32]) -> anyhow::Result<()> {
        {
            let mut store = self.store.lock().await;
            store.add_peer(peer, key)?;
        }
        // Teach the transport how to reach the new device before we gossip.
        self.transport.add_route(peer, key).await;
        self.broadcast_own_roster().await;
        Ok(())
    }

    /// Revoke `peer` locally, then gossip the updated roster. The `Revoke` entry
    /// is authored by an already-trusted device, so honest peers converge to
    /// `Revoked` and `import_peer` refuses the revoked peer's later ops (the
    /// stop-the-op behaviour comes for free from that existing guard). Full
    /// defense against a malicious revoked peer is deferred (Slice-2 = basic
    /// revoke).
    pub async fn revoke_peer(&self, peer: u64, key: [u8; 32]) -> anyhow::Result<()> {
        {
            let mut store = self.store.lock().await;
            store.revoke_peer(peer, key)?;
        }
        // Forget the route so we stop dialing (and tear down any cached
        // connection to) the revoked device.
        self.transport.remove_route(peer).await;
        self.broadcast_own_roster().await;
        Ok(())
    }

    /// Ship our own signed roster log to every currently-connected peer.
    ///
    /// Follows the no-lock-across-await rule: gather the roster bytes and the
    /// connected-peer list under their respective locks, drop both guards, then
    /// perform the transport sends.
    async fn broadcast_own_roster(&self) {
        let jsonl = {
            let store = self.store.lock().await;
            store.export_own_roster().unwrap_or_default()
        };
        let peers: Vec<u64> = {
            let connected = self.connected.lock().await;
            connected.iter().copied().collect()
        };
        for peer in peers {
            self.send(
                peer,
                Frame::RosterOps {
                    author: self.peer_id(),
                    jsonl: jsonl.clone(),
                },
            )
            .await;
        }
    }

    /// Handle one inbound frame from `peer`.
    pub async fn handle(&self, peer: u64, frame: Frame) -> anyhow::Result<()> {
        match frame {
            Frame::Hello { vault } => {
                // Mismatched vault: not our mesh — ignore the connection entirely.
                if vault != self.vault.0 {
                    return Ok(());
                }
                // Read-side revoke gate: never serve a bundle to a peer we do not
                // currently vouch for as Active (spec §9.6).
                if !self.is_active(peer).await {
                    return Ok(());
                }
                // Ensure we track an offset for this peer (default: nothing sent).
                self.ensure_offset(peer).await;

                // Bootstrap the reverse direction exactly once: only a Hello
                // triggers a Hello, and only if we have not already answered
                // this peer. This is the sole place we ever initiate a Hello in
                // response to a frame.
                let first_time = self.connected.lock().await.insert(peer);
                if first_time {
                    self.send_bundle(peer).await;
                }
            }
            Frame::Have { doc_version } => {
                // A decodable version tells us the peer may be behind. The
                // simplest correct response is to offer everything we hold; loro
                // dedups on import. We never answer Ops with Have, so there is no
                // ping-pong.
                if roam_crdt::Version::from_bytes(&doc_version).is_err() {
                    return Ok(());
                }
                // Read-side revoke gate: a revoked peer must not pull the document.
                if !self.is_active(peer).await {
                    return Ok(());
                }
                self.push_logs(peer).await;
            }
            Frame::Ops { author, jsonl } => {
                if author == self.peer_id() {
                    return Ok(());
                }
                let Some(key) = self.key_for(author).await else {
                    // Untrusted author (not in our roster): drop.
                    return Ok(());
                };
                let mut store = self.store.lock().await;
                if let Err(err) = store.apply_peer_ops(author, &key, &jsonl) {
                    // Revoked/unknown/verify failures: drop the frame, never crash.
                    let _ = err;
                }
            }
            Frame::RosterOps { author, jsonl } => {
                if author == self.peer_id() {
                    return Ok(());
                }
                let Some(key) = self.key_for(author).await else {
                    // Author not yet trusted in our roster: drop. Trust is only
                    // ever extended transitively via an ALREADY-trusted author's
                    // signed roster (below), never by an unknown peer.
                    return Ok(());
                };
                // Import the roster, then — still under the store lock — collect
                // any newly-Active peer we are not yet connected to. We DROP the
                // guard before dialing, because `connect` itself sends frames and
                // must never run while holding the store lock (deadlock rule).
                let new_peers: Vec<(u64, [u8; 32])> = {
                    let mut store = self.store.lock().await;
                    if let Err(err) = store.import_roster(author, &key, jsonl) {
                        // Verify/shrink failures: drop the frame, never crash.
                        let _ = err;
                        Vec::new()
                    } else {
                        let connected = self.connected.lock().await;
                        store
                            .roster()
                            .into_iter()
                            .filter(|p| {
                                p.status == PeerStatus::Active
                                    && p.peer_id != self.peer_id()
                                    && !connected.contains(&p.peer_id)
                            })
                            .map(|p| (p.peer_id, p.verifying_key))
                            .collect()
                    }
                };
                // Transitive mesh: teach the transport how to reach every
                // freshly-learned peer, then dial it. Route + dial happen AFTER
                // the store guard is dropped (no lock held across an await). A
                // peer the transport cannot reach (e.g. an offline sibling)
                // returns an error from `connect` — treat it as non-fatal so one
                // unreachable peer does not abort the loop. The `!connected` guard
                // above prevents re-connect loops and self-connects.
                for (new_peer, new_key) in new_peers {
                    self.transport.add_route(new_peer, new_key).await;
                    if let Err(err) = self.connect(new_peer).await {
                        let _ = err;
                    }
                }
            }
            Frame::RosterHave { .. } => {
                // Read-side revoke gate: a revoked peer must not pull our roster.
                if !self.is_active(peer).await {
                    return Ok(());
                }
                // Reply with our whole roster; the peer merges + dedups.
                let own_roster = {
                    let store = self.store.lock().await;
                    store.export_own_roster().unwrap_or_default()
                };
                self.send(
                    peer,
                    Frame::RosterOps {
                        author: self.peer_id(),
                        jsonl: own_roster,
                    },
                )
                .await;
            }
            Frame::Ping => {}
        }
        Ok(())
    }

    /// Run the receive loop until the transport closes.
    pub async fn run(self: Arc<Self>) {
        let mut incoming = self.transport.incoming();
        while let Some((peer, frame)) = incoming.next().await {
            let _ = self.handle(peer, frame).await;
        }
    }

    /// Send our full handshake bundle to `peer`: Hello, RosterHave, Have, our own
    /// log (recording the sent offset), every held peer log, then our roster.
    async fn send_bundle(&self, peer: u64) {
        let offer = self.gather_offer().await;

        // Record how much of our own log this peer now has, so live-push only
        // ships the suffix.
        {
            let mut offsets = self.sent_offsets.lock().await;
            offsets.insert(peer, offer.own_log.len());
        }
        self.connected.lock().await.insert(peer);

        self.send(peer, Frame::Hello { vault: self.vault.0 }).await;
        self.send(
            peer,
            Frame::RosterHave {
                authors: offer.roster_have,
            },
        )
        .await;
        self.send(
            peer,
            Frame::Have {
                doc_version: offer.doc_version,
            },
        )
        .await;
        self.send(
            peer,
            Frame::Ops {
                author: self.peer_id(),
                jsonl: offer.own_log,
            },
        )
        .await;
        for (author, jsonl) in offer.peer_logs {
            self.send(peer, Frame::Ops { author, jsonl }).await;
        }
        self.send(
            peer,
            Frame::RosterOps {
                author: self.peer_id(),
                jsonl: offer.own_roster,
            },
        )
        .await;
    }

    /// Push all logs we hold (own + held peer logs) to `peer` in response to a
    /// `Have`. Does not touch the handshake/offset bookkeeping.
    async fn push_logs(&self, peer: u64) {
        let (own_log, peer_logs) = {
            let store = self.store.lock().await;
            let own_log = store.export_own_log().unwrap_or_default();
            let peer_logs = Self::held_peer_logs(&store, self.peer_id());
            (own_log, peer_logs)
        };
        self.send(
            peer,
            Frame::Ops {
                author: self.peer_id(),
                jsonl: own_log,
            },
        )
        .await;
        for (author, jsonl) in peer_logs {
            self.send(peer, Frame::Ops { author, jsonl }).await;
        }
    }

    /// Snapshot everything needed for a handshake under a single store lock.
    async fn gather_offer(&self) -> Offer {
        let store = self.store.lock().await;
        let roster = store.roster();
        let roster_have = roster.iter().map(|p| (p.peer_id, 0u64)).collect();
        Offer {
            doc_version: store.doc_version_bytes(),
            roster_have,
            own_log: store.export_own_log().unwrap_or_default(),
            own_roster: store.export_own_roster().unwrap_or_default(),
            peer_logs: Self::held_peer_logs(&store, self.peer_id()),
        }
    }

    /// Every third-party (non-self) active peer log we currently hold.
    fn held_peer_logs(store: &Store, me: u64) -> Vec<(u64, Vec<u8>)> {
        store
            .roster()
            .into_iter()
            .filter(|p| p.status == PeerStatus::Active && p.peer_id != me)
            .filter_map(|p| {
                let jsonl = store.export_peer_log(p.peer_id).ok()?;
                (!jsonl.is_empty()).then_some((p.peer_id, jsonl))
            })
            .collect()
    }

    /// Ensure `sent_offsets` has an entry for `peer` (default 0).
    async fn ensure_offset(&self, peer: u64) {
        self.sent_offsets.lock().await.entry(peer).or_insert(0);
    }

    /// Send a frame, ignoring transport errors (a transient unreachable peer must
    /// not crash the engine loop).
    async fn send(&self, peer: u64, frame: Frame) {
        let _ = self.transport.send(peer, frame).await;
    }

    /// Whether `peer` is currently listed in our roster with
    /// [`PeerStatus::Active`]. Note `key_for` returns `Some` for a *Revoked* peer
    /// too (the roster still lists it), so the read-side gate must check the
    /// status specifically, not mere presence.
    async fn is_active(&self, peer: u64) -> bool {
        let store = self.store.lock().await;
        store
            .roster()
            .into_iter()
            .any(|p| p.peer_id == peer && p.status == PeerStatus::Active)
    }

    // Helper: verifying key for a peer from the roster.
    async fn key_for(&self, peer: u64) -> Option<VerifyingKey> {
        let store = self.store.lock().await;
        store
            .roster()
            .into_iter()
            .find(|p| p.peer_id == peer)
            .and_then(|p| VerifyingKey::from_bytes(&p.verifying_key).ok())
    }
}
