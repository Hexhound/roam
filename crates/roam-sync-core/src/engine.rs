use crate::frame::Frame;
use crate::transport::Transport;
use futures::StreamExt;
use roam_files::{EntryKind, EntryStatus, FileEntry, FILESET_MAP_ID};
use roam_storage::{BlobStore, Identity, PeerStatus, Store, VaultId, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Upper bound on the blob-bytes payload this slice transfers in ONE
/// [`Frame::BlobData`]. The iroh transport caps a whole encoded frame at 64 MiB
/// (`MAX_FRAME_LEN`); we stay a comfortable margin below it so the hash string +
/// postcard framing overhead still fit. A blob larger than this is NOT served
/// (the server skips it with a log line) — chunked transfer is deferred.
///
/// TODO(blob-chunking): lift this cap by splitting an oversized blob into
/// offset-tagged `BlobData` chunks reassembled + full-hash-verified by the
/// receiver. Until then a >`MAX_BLOB_BYTES` blob simply does not transfer.
pub const MAX_BLOB_BYTES: usize = 60 * 1024 * 1024;

/// Whether a blob of `byte_len` bytes fits in a single [`Frame::BlobData`] under
/// [`MAX_BLOB_BYTES`]. Pulled out as a pure predicate so the size boundary is
/// unit-testable without allocating tens of MiB.
fn blob_fits_frame(byte_len: usize) -> bool {
    byte_len <= MAX_BLOB_BYTES
}

/// Drives sync for one device over a [`Transport`]. Owns the [`Store`]; local
/// edits go through the engine so it can live-push.
pub struct Engine<T: Transport> {
    identity: Identity,
    vault: VaultId,
    store: Arc<Mutex<Store>>,
    transport: Arc<T>,
    /// Per-peer byte offset of our own oplog already pushed to that peer.
    sent_offsets: Arc<Mutex<HashMap<u64, usize>>>,
    /// Per-peer LAST-ACKED document version vector (`roam_crdt::Version` bytes),
    /// learned from each inbound [`Frame::Have`]. This is what the peer has told
    /// us it holds — the ground truth for "has peer P observed op X?" that the
    /// causally-stable tombstone GC predicate consumes. Distinct from
    /// `sent_offsets`, which only tracks what WE pushed (never what the peer
    /// APPLIED). Updates are monotonic: a Have is recorded only when it
    /// causally dominates the version we already had for that peer, so an
    /// out-of-order/stale Have can never lower a peer's acked version.
    acked_versions: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
    /// Peers we have already answered with our own `Hello` bundle. Guards the
    /// one-time reverse handshake so two peers that both connect (and both see
    /// each other's `Hello`) never trade `Hello`s forever.
    connected: Arc<Mutex<HashSet<u64>>>,
    /// Fired after a REMOTE change lands (an inbound `Frame::Ops` that actually
    /// advances the document). A single consumer (the CLI) awaits this to know
    /// when to re-project the store to disk. `notify_waiters` is used, so it only
    /// wakes waiters already awaiting — no permit is stored for future awaits.
    changed: Arc<tokio::sync::Notify>,
    /// Fired after [`flush_local`](Self::flush_local) runs (any local or
    /// remote-projected change that produced ops). The backend sync task awaits
    /// this to upload promptly instead of waiting for its next poll tick.
    local_flush: Arc<tokio::sync::Notify>,
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
    own_keylog: Vec<u8>,
    /// Held third-party key-logs to relay: `(author, jsonl)`.
    keylogs: Vec<(u64, Vec<u8>)>,
}

impl<T: Transport + 'static> Engine<T> {
    pub fn new(identity: Identity, vault: VaultId, store: Store, transport: Arc<T>) -> Self {
        Self {
            identity,
            vault,
            store: Arc::new(Mutex::new(store)),
            transport,
            sent_offsets: Arc::new(Mutex::new(HashMap::new())),
            acked_versions: Arc::new(Mutex::new(HashMap::new())),
            connected: Arc::new(Mutex::new(HashSet::new())),
            changed: Arc::new(tokio::sync::Notify::new()),
            local_flush: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// A handle to the local-flush signal, fired after every `flush_local`. The
    /// backend sync task awaits this to upload changes promptly instead of
    /// waiting out its poll interval. `notify_waiters` semantics: register the
    /// waiter (build the `Notified` and `enable()` it) before awaiting.
    pub fn local_flushed(&self) -> Arc<tokio::sync::Notify> {
        self.local_flush.clone()
    }

    /// The shared store handle. The backend sync task MUST use this exact
    /// `Arc<Mutex<Store>>` so its apply path and the iroh apply path serialize
    /// on one lock (spec §8.1).
    pub fn store(&self) -> Arc<Mutex<Store>> {
        self.store.clone()
    }

    /// A handle to the remote-change signal. Fired via `notify_waiters` after a
    /// successful inbound `Frame::Ops` apply that advanced the document, so a
    /// consumer can `.notified().await` to learn when remote data landed.
    ///
    /// Single-consumer (CLI) use: `notify_waiters` wakes whoever is currently
    /// awaiting and stores no permit, so register the waiter before awaiting a
    /// change. Roster changes (`Frame::RosterOps`) deliberately do NOT fire this
    /// — only document ops project to disk for the CLI.
    pub fn changed(&self) -> Arc<tokio::sync::Notify> {
        self.changed.clone()
    }

    pub fn peer_id(&self) -> u64 {
        self.identity.peer_id()
    }

    /// Snapshot of every peer's last-acked document version (`Version` bytes),
    /// learned from inbound [`Frame::Have`]s (see [`Engine::acked_versions`]).
    /// This is the per-peer view the causally-stable tombstone GC predicate
    /// consumes: a peer ABSENT from this map has never told us what it holds, so
    /// GC must treat it as not-yet-observed (never GC on its behalf).
    pub async fn acked_versions(&self) -> HashMap<u64, Vec<u8>> {
        self.acked_versions.lock().await.clone()
    }

    /// Open a connection: send Hello, RosterHave, Have, offer our logs and
    /// roster. Idempotent enough for the mesh — resent logs are deduped on
    /// import.
    pub async fn connect(&self, peer: u64) -> anyhow::Result<()> {
        self.transport.dial(peer).await?;
        self.send_bundle(peer).await;
        Ok(())
    }

    /// Re-dial + re-offer every active, non-self roster peer. Idempotent and
    /// self-healing: a live connection's `dial` is a cheap no-op reused stream,
    /// and `send_bundle` re-ships the full log (loro dedups on import), so a peer
    /// that was unreachable at startup — or whose connection dropped and was
    /// evicted by a failed send — is reconnected and caught up on the next call.
    /// Meant to be driven periodically by a long-running daemon.
    pub async fn reconnect_active(&self) {
        let peers: Vec<u64> = {
            let store = self.store.lock().await;
            let me = self.peer_id();
            store
                .roster()
                .into_iter()
                .filter(|p| p.status == PeerStatus::Active && p.peer_id != me)
                .map(|p| p.peer_id)
                .collect()
        };
        crate::dlog!("reconnect_active: active peers={peers:?}");
        for peer in peers {
            // Only re-offer if the (re)dial succeeds; a still-unreachable peer is
            // skipped silently and retried on the next tick.
            match self.transport.dial(peer).await {
                Ok(()) => {
                    crate::dlog!("reconnect_active: peer={peer} dial ok, re-offering bundle");
                    self.send_bundle(peer).await;
                }
                Err(e) => crate::dlog!("reconnect_active: peer={peer} dial failed: {e:?}"),
            }
        }
    }

    /// Apply a local text edit and live-push it to all connected peers.
    ///
    /// The push is delegated to [`flush_local`](Self::flush_local): apply the
    /// edit under the store lock, drop the guard, then flush. Behaviour is
    /// identical to computing+sending the suffix inline (the convergence tests
    /// prove it); factoring the push out lets store-bypassing writers (e.g. a
    /// folder scan) gossip via the same path.
    pub async fn edit_text(&self, id: &str, pos: usize, s: &str) -> anyhow::Result<()> {
        {
            let mut store = self.store.lock().await;
            store.edit_text(id, pos, s)?;
        }
        self.flush_local().await;
        Ok(())
    }

    /// Recompute each connected peer's unsent own-log suffix and send it as
    /// `Frame::Ops`. Reusable local-op gossip for any caller that mutated the
    /// store directly (bypassing [`edit_text`](Self::edit_text)), e.g. a folder
    /// scan writing import ops straight to the store.
    ///
    /// Same lock discipline as `edit_text`: read the own log under the store
    /// lock, compute per-peer suffixes + advance offsets under the offsets lock,
    /// drop both guards, then await the transport sends (never hold a lock across
    /// a transport await).
    ///
    /// Idempotent: each peer's offset is clamped/advanced to `own_log.len()`, so
    /// with no connected peers, or when every offset already covers the whole own
    /// log, no non-empty suffix is produced and nothing is sent. This preserves
    /// the `sent_offsets` bookkeeping that stops already-sent ops being resent
    /// (the guard against peer-log duplication).
    pub async fn flush_local(&self) {
        let own_log = {
            let store = self.store.lock().await;
            store.export_own_log().unwrap_or_default()
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

        if pushes.is_empty() {
            crate::dlog!(
                "flush_local: nothing to push (own_log={} bytes)",
                own_log.len()
            );
        }
        for (peer, jsonl) in pushes {
            crate::dlog!(
                "flush_local: pushing {} op-bytes to peer={peer}",
                jsonl.len()
            );
            self.send(
                peer,
                Frame::Ops {
                    author: self.peer_id(),
                    jsonl,
                },
            )
            .await;
        }

        // Wake the backend sync task (if any) so it uploads this flush's ops
        // immediately rather than on its next poll tick. Cheap no-op when no one
        // is awaiting. Fired unconditionally: even a "nothing to push to peers"
        // flush may carry new own-log ops the backend still needs.
        self.local_flush.notify_waiters();
    }

    /// Pull every blob the synced file-set map references but whose bytes we
    /// lack: send a [`Frame::BlobWant`] for each missing hash to every connected,
    /// trusted-Active peer.
    ///
    /// A peer learns a `Blob` entry-ref through the ordinary map sync (the ref
    /// rides the op-log); the BYTES live outside the CRDT, so this pull fetches
    /// them. Enumeration reads `store.entries(FILESET_MAP_ID)`, keeps only
    /// `kind == Blob, status == Live` entries whose `content_hash` is absent from
    /// our local [`BlobStore`], and de-duplicates hashes referenced by several
    /// entries.
    ///
    /// Lock discipline: gather the missing-hash list AND the target peer set
    /// under their locks, DROP every guard, THEN await the transport sends (never
    /// a lock held across an await).
    ///
    /// Idempotent, so a caller may drive it on a cadence (e.g. after each inbound
    /// `changed()` in the D5 reconcile loop, or a CLI timer): re-requesting an
    /// in-flight hash is harmless — the server just re-serves and the receiver
    /// drops the duplicate (it already has, or already stored, the bytes). A
    /// dedicated in-flight set is deferred; presence-based idempotence suffices.
    pub async fn request_missing_blobs(&self) {
        // 1. Missing hashes + the trusted-Active roster, under the store lock.
        let (wanted, active): (Vec<String>, HashSet<u64>) = {
            let store = self.store.lock().await;
            let wanted = Self::missing_blob_hashes(&store);
            let active = store
                .roster()
                .into_iter()
                .filter(|p| p.status == PeerStatus::Active && p.peer_id != self.peer_id())
                .map(|p| p.peer_id)
                .collect();
            (wanted, active)
        };
        if wanted.is_empty() {
            return;
        }
        // 2. Connected ∩ Active, under the connected lock (store guard dropped).
        let peers: Vec<u64> = {
            let connected = self.connected.lock().await;
            connected
                .iter()
                .copied()
                .filter(|p| active.contains(p))
                .collect()
        };
        // 3. Sends happen lock-free.
        for peer in peers {
            for hash in &wanted {
                self.send(peer, Frame::BlobWant { hash: hash.clone() })
                    .await;
            }
        }
    }

    /// De-duplicated blob hashes referenced by a `Live` `Blob` file-set entry
    /// whose bytes are NOT present in the local [`BlobStore`].
    fn missing_blob_hashes(store: &Store) -> Vec<String> {
        let mut seen = HashSet::new();
        store
            .entries(FILESET_MAP_ID)
            .into_iter()
            .filter_map(|(_key, value)| FileEntry::from_value(&value).ok())
            .filter(|entry| entry.kind == EntryKind::Blob && entry.status == EntryStatus::Live)
            .map(|entry| entry.content_hash)
            .filter(|hash| !store.blobs().has(hash))
            .filter(|hash| seen.insert(hash.clone()))
            .collect()
    }

    /// Whether the file-set map has a `Live` `Blob` entry referencing `hash` —
    /// i.e. whether inbound bytes for `hash` are SOLICITED. Guards the receive
    /// path against an active peer spamming unsolicited blobs onto our disk.
    fn fileset_wants(store: &Store, hash: &str) -> bool {
        store
            .entries(FILESET_MAP_ID)
            .into_iter()
            .filter_map(|(_key, value)| FileEntry::from_value(&value).ok())
            .any(|entry| {
                entry.kind == EntryKind::Blob
                    && entry.status == EntryStatus::Live
                    && entry.content_hash == hash
            })
    }

    /// The set of peers with a live session right now (distinct from roster
    /// membership). For consumers building a member table alongside `Store::roster()`.
    pub async fn connected_peers(&self) -> std::collections::HashSet<u64> {
        self.connected.lock().await.clone()
    }

    /// Vouch for `peer` (holding `key`) locally, then gossip the updated roster
    /// to every connected peer so they learn the new device (transitive mesh).
    pub async fn add_peer(
        &self,
        peer: u64,
        key: [u8; 32],
        role: roam_storage::Role,
    ) -> anyhow::Result<()> {
        {
            let mut store = self.store.lock().await;
            store.add_peer(peer, key, role)?;
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
        // Prune our per-peer bookkeeping so the revoked device no longer lingers
        // in the broadcast set or the offset map. Each map is locked, mutated,
        // and released on its own (no store lock held across it).
        self.connected.lock().await.remove(&peer);
        self.sent_offsets.lock().await.remove(&peer);
        // Drop the revoked peer's acked version too: a revoked peer is no longer
        // a trusted witness, so GC must not count it as having observed anything.
        self.acked_versions.lock().await.remove(&peer);
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
                let Ok(incoming) = roam_crdt::Version::from_bytes(&doc_version) else {
                    return Ok(());
                };
                // Read-side revoke gate: a revoked peer must not pull the document.
                if !self.is_active(peer).await {
                    return Ok(());
                }
                // C1 — record this peer's acked version (what it has told us it
                // holds), MONOTONICALLY: only overwrite when the incoming version
                // causally dominates the one we already have, so a reordered or
                // stale Have can never REGRESS a peer's acked version (which would
                // be unsafe for GC — it could make an offline peer look caught-up).
                {
                    let mut acked = self.acked_versions.lock().await;
                    let replace = match acked.get(&peer) {
                        None => true,
                        Some(prev) => match roam_crdt::Version::from_bytes(prev) {
                            Ok(prev) => incoming.includes(&prev),
                            // Corrupt stored bytes: replace with the decodable one.
                            Err(_) => true,
                        },
                    };
                    if replace {
                        acked.insert(peer, doc_version.clone());
                    }
                }
                self.push_logs(peer).await;
            }
            Frame::Ops { author, jsonl } => {
                crate::dlog!(
                    "handle Ops from peer={peer} author={author} ({} bytes)",
                    jsonl.len()
                );
                if author == self.peer_id() {
                    return Ok(());
                }
                let Some(key) = self.key_for(author).await else {
                    // Untrusted author (not in our roster): drop.
                    crate::dlog!("handle Ops author={author}: DROPPED (untrusted/not in roster)");
                    return Ok(());
                };
                // Apply under the store lock; note whether the document actually
                // advanced (empty/duplicate resends return Ok but change
                // nothing). Compare doc versions under the lock, then drop the
                // guard BEFORE firing the change signal.
                let changed = {
                    let mut store = self.store.lock().await;
                    let before = store.doc_version_bytes();
                    match store.apply_peer_ops(author, &key, &jsonl) {
                        Ok(()) => store.doc_version_bytes() != before,
                        Err(err) => {
                            // Revoked/unknown/verify failures: drop, never crash.
                            let _ = err;
                            false
                        }
                    }
                };
                // Fire the remote-change Notify outside the lock, only when the
                // apply advanced the document. `notify_waiters` wakes whoever is
                // currently awaiting `changed()`. RosterOps deliberately does not
                // fire this — only doc ops project to disk for the CLI.
                crate::dlog!("handle Ops author={author}: applied, doc_advanced={changed}");
                if changed {
                    self.changed.notify_waiters();
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
            Frame::KeylogOps { author, jsonl } => {
                if author == self.peer_id() {
                    return Ok(());
                }
                // Trust gate: only a roster-vouched author's key-log is accepted,
                // exactly like RosterOps. An unknown author is dropped.
                let Some(key) = self.key_for(author).await else {
                    return Ok(());
                };
                let mut store = self.store.lock().await;
                // Verify/shrink failures: drop the frame, never crash.
                let _ = store.import_keylog(author, &key, jsonl);
            }
            Frame::KeylogHave { .. } => {
                // Read-side revoke gate: a revoked peer must not pull our key-log.
                if !self.is_active(peer).await {
                    return Ok(());
                }
                let (own_keylog, keylogs) = {
                    let store = self.store.lock().await;
                    (
                        store.export_own_keylog().unwrap_or_default(),
                        Self::held_keylogs(&store, self.peer_id()),
                    )
                };
                self.send(
                    peer,
                    Frame::KeylogOps {
                        author: self.peer_id(),
                        jsonl: own_keylog,
                    },
                )
                .await;
                for (author, jsonl) in keylogs {
                    self.send(peer, Frame::KeylogOps { author, jsonl }).await;
                }
            }
            Frame::BlobWant { hash } => {
                // Read-side revoke gate: only ever serve a blob to a peer we
                // currently vouch for as Active — identical to the Have/RosterHave
                // serving paths (spec §9.6). A revoked/untrusted peer gets nothing.
                if !self.is_active(peer).await {
                    return Ok(());
                }
                // Look the bytes up under the store lock, DROP the guard, then
                // send. Absent blob → send nothing, no error.
                let bytes = {
                    let store = self.store.lock().await;
                    // `get` verifies on-disk integrity; a corrupt/missing blob
                    // yields None here and we simply do not serve it.
                    store.blobs().get(&hash).ok().flatten()
                };
                if let Some(bytes) = bytes {
                    if blob_fits_frame(bytes.len()) {
                        self.send(peer, Frame::BlobData { hash, bytes }).await;
                    }
                    // else: oversized for a single frame this slice — skip
                    // serving it (chunking deferred; see `MAX_BLOB_BYTES`).
                }
            }
            Frame::BlobData { hash, bytes } => {
                // Poison guard (critical): the bytes MUST hash to the claimed
                // hash, or a peer could store wrong bytes under a good hash and
                // corrupt our content-addressed store. Reject the mismatch.
                if BlobStore::hash(&bytes) != hash {
                    return Ok(());
                }
                // Store under the lock only if we (a) don't already hold it
                // (idempotent) and (b) actually solicited it — a `Live` `Blob`
                // file-set entry references this hash (anti-spam). Drop the guard
                // before firing the change signal.
                let stored = {
                    let store = self.store.lock().await;
                    if store.blobs().has(&hash) || !Self::fileset_wants(&store, &hash) {
                        false
                    } else {
                        store.blobs().put(&bytes).is_ok()
                    }
                };
                // Signal the reconcile/projection (D5) that new blob bytes
                // landed, so it can project them to disk. Only fire on a real
                // store (not on a dropped duplicate/unsolicited/failed put).
                if stored {
                    self.changed.notify_waiters();
                }
            }
            // P2P snapshot-serving frames (Task 4 wire types). Serve/adopt logic
            // lands in Tasks 5/6; these no-op arms exist only to keep the
            // exhaustive match compiling now that the variants exist.
            Frame::SnapshotHave { .. } => {}
            Frame::SnapshotWant { .. } => {}
            Frame::SnapshotData { .. } => {}
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
        crate::dlog!(
            "send_bundle -> peer={peer}: own_log={} bytes, {} peer-logs",
            offer.own_log.len(),
            offer.peer_logs.len()
        );

        // Record how much of our own log this peer now has, so live-push only
        // ships the suffix.
        {
            let mut offsets = self.sent_offsets.lock().await;
            offsets.insert(peer, offer.own_log.len());
        }
        self.connected.lock().await.insert(peer);

        self.send(
            peer,
            Frame::Hello {
                vault: self.vault.0,
            },
        )
        .await;
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

        // Key-log gossip (mirrors the roster block above). Announce our per-author
        // counts, then ship our own key-log and every held peer key-log; the
        // receiver merges prefix-aware and length-guards the import.
        let keylog_have: Vec<(u64, u64)> = std::iter::once((self.peer_id(), 0u64))
            .chain(offer.keylogs.iter().map(|(a, _)| (*a, 0u64)))
            .collect();
        self.send(
            peer,
            Frame::KeylogHave {
                authors: keylog_have,
            },
        )
        .await;
        self.send(
            peer,
            Frame::KeylogOps {
                author: self.peer_id(),
                jsonl: offer.own_keylog,
            },
        )
        .await;
        for (author, jsonl) in offer.keylogs {
            self.send(peer, Frame::KeylogOps { author, jsonl }).await;
        }
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
            own_keylog: store.export_own_keylog().unwrap_or_default(),
            keylogs: Self::held_keylogs(&store, self.peer_id()),
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

    /// Every third-party (non-self) active peer key-log we currently hold.
    fn held_keylogs(store: &Store, me: u64) -> Vec<(u64, Vec<u8>)> {
        store
            .roster()
            .into_iter()
            .filter(|p| p.status == PeerStatus::Active && p.peer_id != me)
            .filter_map(|p| {
                let jsonl = store.export_keylog(p.peer_id).ok()?;
                if jsonl.is_empty() {
                    None
                } else {
                    Some((p.peer_id, jsonl))
                }
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

#[cfg(test)]
mod tests {
    use super::{blob_fits_frame, Engine, MAX_BLOB_BYTES};
    use crate::memory::MemorySwitchboard;
    use roam_storage::{Identity, Store, VaultId};
    use std::sync::Arc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn connected_peers_starts_empty_and_is_exposed() {
        // Construct an Engine exactly as the integration engine tests do
        // (MemoryTransport endpoint + a freshly opened store). A brand-new
        // engine has established no sessions, so its connected set is empty.
        let board = MemorySwitchboard::new();
        let vault = VaultId::generate();
        let dir = tempdir().unwrap();
        let identity = Identity::generate();
        let store = Store::open(dir.path(), identity.clone()).unwrap();
        let engine = Engine::new(
            identity.clone(),
            vault,
            store,
            Arc::new(board.endpoint(identity.peer_id())),
        );
        assert!(engine.connected_peers().await.is_empty());
    }

    #[test]
    fn blob_fits_frame_decides_at_the_cap_boundary() {
        // Boundary is exercised via the pure predicate, WITHOUT allocating a
        // 60 MiB blob: exactly at the cap fits; one byte over does not.
        assert!(blob_fits_frame(0));
        assert!(blob_fits_frame(MAX_BLOB_BYTES - 1));
        assert!(blob_fits_frame(MAX_BLOB_BYTES));
        assert!(!blob_fits_frame(MAX_BLOB_BYTES + 1));
    }
}
