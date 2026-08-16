//! The command protocol the browser worker speaks.
//!
//! # Why this is plain Rust
//!
//! roam cannot run on a browser's main thread: OPFS sync access handles do not
//! exist there (measured, see `docs/browser_storage_opfs.md`). So the browser
//! client is necessarily split across a `postMessage` boundary, and *something*
//! has to turn messages into vault operations.
//!
//! That something is here, in ordinary Rust, for the same reason `Doc` is:
//! anything that lives in the JS worker can only be tested in a browser. The
//! worker script is left with no decisions at all — it forwards bytes both ways.
//! Everything below is exercised by `tests/session.rs` against `MemFs` and a
//! `MemoryBackend`, including a real two-device sync.
//!
//! # Wire format
//!
//! A request is one JSON object, tagged by `command`:
//!
//! ```json
//! { "id": 7, "command": "setEntry", "container": "meta", "key": "title", "value": "Hi" }
//! ```
//!
//! and the reply echoes `id` with exactly one of `ok` / `error`:
//!
//! ```json
//! { "id": 7, "ok": null }
//! { "id": 7, "error": "…" }
//! ```
//!
//! Two encoding rules, both load-bearing:
//!
//! * **Peer ids cross as strings.** A peer id is a `u64` and JSON numbers are
//!   doubles, so ids above 2^53 would arrive silently rounded — and a rounded
//!   peer id is not a wrong number, it is a different device.
//! * **Keys cross as base64url, unpadded**, matching how roam already encodes
//!   entry and blob ids.
//!
//! and one naming rule: the envelope owns `id`, so a text container is named by
//! `textId`. JSON silently keeps one value for a duplicated key, so the
//! collision would not have been an error, it would have been a wrong answer.
//!
//! # Binary rides beside the JSON, not inside it
//!
//! Attachments are megabytes. Base64 inside the envelope would cost a third
//! more bytes and — worse — force the whole payload through a JSON parser on
//! both sides, twice, for data that is opaque anyway. So [`Session::handle`]
//! takes and returns an optional byte buffer *alongside* the envelope, and the
//! worker moves it as a transferable. Blobs are the only thing this carries,
//! which is exactly right: blob bytes live outside the CRDT already, with only
//! a hash-reference on the op log.
//!
//! # Changes ride on the reply, and there is no push channel
//!
//! An embedder projecting a vault into its own database needs to be told what
//! moved. The obvious design is an unsolicited worker-to-page channel — but it
//! is unnecessary here, because **nothing changes a vault except a command**. A
//! local edit is a command; pulling a peer's ops is `sync`, also a command. So
//! every reply carries the map delta its own command produced, under `changes`,
//! omitted when empty. This keeps ordering trivially correct: a caller can
//! never observe a change before the reply that caused it.
//!
//! Text containers are not in `changes` — `map_delta` is key-level over maps. A
//! caller projecting text re-reads it after a `sync`.

use crate::vault::Vault;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use roam_backend_client::transport::Backend;
use roam_crdt::MapChange;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(
    tag = "command",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Command {
    PeerId,
    VerifyingKey,
    AddPeer {
        peer_id: String,
        verifying_key: String,
    },
    SetEntry {
        container: String,
        key: String,
        value: String,
    },
    GetEntry {
        container: String,
        key: String,
    },
    RemoveEntry {
        container: String,
        key: String,
    },
    /// Every key in a container, as an object. For the bootstrap projection a
    /// freshly paired device makes before incremental `changes` mean anything.
    Entries {
        container: String,
    },
    // `textId`, not `id`: the envelope already owns `id`, and a request object
    // cannot carry the key twice. JSON does not reject the duplicate — parsers
    // silently keep one of them — so the collision would surface as a text
    // container named "7".
    EditText {
        text_id: String,
        at: usize,
        text: String,
    },
    Text {
        text_id: String,
    },
    WriteSnapshot,
    Sync,
    /// The bytes come from the request's binary payload, not from this object —
    /// see the module note on why. Replies with the content hash.
    PutBlob,
    /// Replies with `{ "len": n }` and the bytes as the reply's payload, or a
    /// bare `null` when this device does not hold them. The distinction matters:
    /// a zero-length blob is present and answers `{ "len": 0 }`, so a caller
    /// must not read "no bytes" as "missing".
    GetBlob {
        hash: String,
    },
    HasBlob {
        hash: String,
    },
    RemoveBlob {
        hash: String,
    },
    BucketId,

    // -- membership and maintenance ------------------------------------------
    /// The roster, as an array. `peerId` crosses as a string and `verifyingKey`
    /// as base64url, matching every other id on this protocol.
    Roster,
    /// This device's role: `"admin"`, `"writer"`, `"reader"`, or `null` when it
    /// is in no roster at all — which is what a revoked device looks like.
    SelfRole,
    RevokePeer {
        peer_id: String,
        verifying_key: String,
    },
    DataSize,
    /// `beforeMs` is a wall-clock millisecond timestamp, passed in rather than
    /// read here: the cutoff is a user's choice, and a browser tab's clock is
    /// the only one available anyway.
    CompactDryRun {
        before_ms: i64,
    },
    Compact {
        before_ms: i64,
    },
    RotateEpoch,
}

/// One reply: the JSON envelope, plus binary that deliberately did not go
/// through it.
pub struct Reply {
    pub json: String,
    pub bytes: Option<Vec<u8>>,
}

/// One open vault, plus the relay it syncs against.
///
/// The backend is fixed at construction rather than passed per `sync` command
/// on purpose: a browser client is a relay leaf by construction (it cannot open
/// QUIC, so it can never be an iroh peer), and letting a message name the relay
/// would make the endpoint an attacker-controlled input from inside the page.
pub struct Session<B: Backend> {
    vault: Vault,
    backend: Arc<B>,
}

impl<B: Backend> Session<B> {
    pub fn new(vault: Vault, backend: Arc<B>) -> Self {
        Self { vault, backend }
    }

    /// The vault this session drives. Exposed so the binding layer can hand a
    /// freshly-joined device its vault key — a joiner does not have that key
    /// until pairing succeeds, and without it the next page load could not
    /// reopen the vault it just joined.
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Handle one request that carries no binary, returning just the JSON.
    ///
    /// Equivalent to [`handle`] with no payload — and the reply bytes it drops
    /// are necessarily absent, since only `getBlob` produces any.
    ///
    /// [`handle`]: Session::handle
    pub async fn handle_json(&self, request: &str) -> String {
        self.handle(request, None).await.json
    }

    /// Handle one request, returning the reply envelope and any binary that
    /// deliberately did not go through it.
    ///
    /// This is infallible by design. A worker that cannot answer leaves the page
    /// waiting forever on a promise that never settles, which is a far worse
    /// failure than an error reply — so every path, including "that isn't JSON",
    /// produces an envelope.
    pub async fn handle(&self, request: &str, payload: Option<Vec<u8>>) -> Reply {
        let parsed: Value = match serde_json::from_str(request) {
            Ok(value) => value,
            // No `id` is recoverable here: there is no request to read one from.
            // The caller sees a rejected promise rather than a hung one.
            Err(e) => {
                return Reply {
                    json: envelope(Value::Null, Err(format!("malformed request: {e}")), &[]),
                    bytes: None,
                }
            }
        };

        // Read the id BEFORE the command parses, so a request naming a command
        // this build does not have still gets a reply the caller can match up.
        let id = parsed.get("id").cloned().unwrap_or(Value::Null);

        let command: Command = match serde_json::from_value(parsed) {
            Ok(command) => command,
            Err(e) => {
                return Reply {
                    json: envelope(id, Err(format!("unrecognized command: {e}")), &[]),
                    bytes: None,
                }
            }
        };

        // Taken before the command and compared after, so `changes` describes
        // exactly what this command did. Sound only because `handle` is not
        // re-entrant — with two commands in flight the window would span both,
        // and each would claim the other's changes as its own.
        let before = self.vault.frontier().await;

        let outcome = self.run(command, payload).await;

        // A failed command may still have changed the document before it
        // failed, so the delta is read on both paths. On the error path it is
        // dropped rather than reported: an envelope carries `ok` or `error`,
        // never both, and a caller that is being told a write failed should not
        // simultaneously be handed its partial effects.
        let (value, bytes, result) = match outcome {
            Ok((value, bytes)) => (value, bytes, Ok(())),
            Err(e) => (Value::Null, None, Err(format!("{e:#}"))),
        };

        // Falling back to "nothing changed" is wrong, but failing the command
        // the caller asked for — which by now has already happened — is worse.
        let changes = self.vault.changes_since(&before).await.unwrap_or_default();

        match result {
            Ok(()) => Reply {
                json: envelope(id, Ok(value), &changes),
                bytes,
            },
            Err(message) => Reply {
                json: envelope(id, Err(message), &changes),
                bytes: None,
            },
        }
    }

    /// The command's value, plus any binary that must bypass the envelope.
    ///
    /// The three blob commands are handled ahead of the rest because they are
    /// the only ones that touch the payload at all; everything after them is a
    /// plain value.
    async fn run(
        &self,
        command: Command,
        payload: Option<Vec<u8>>,
    ) -> anyhow::Result<(Value, Option<Vec<u8>>)> {
        match command {
            Command::PutBlob => {
                let bytes = payload.ok_or_else(|| {
                    anyhow::anyhow!("putBlob needs its bytes as the request's binary payload")
                })?;
                return Ok((json!(self.vault.put_blob(&bytes).await?), None));
            }

            Command::GetBlob { hash } => {
                return Ok(match self.vault.get_blob(&hash).await? {
                    Some(bytes) => (json!({ "len": bytes.len() }), Some(bytes)),
                    None => (Value::Null, None),
                });
            }

            Command::HasBlob { hash } => {
                return Ok((json!(self.vault.has_blob(&hash).await), None));
            }

            _ => {}
        }

        Ok((
            match command {
                Command::PeerId => json!(self.vault.peer_id().await.to_string()),

                Command::VerifyingKey => json!(B64.encode(self.vault.verifying_key().await)),

                Command::AddPeer {
                    peer_id,
                    verifying_key,
                } => {
                    let peer_id: u64 = peer_id
                        .parse()
                        .map_err(|_| anyhow::anyhow!("peerId must be a u64 written as a string"))?;
                    self.vault
                        .add_peer(peer_id, decode_key(&verifying_key)?)
                        .await?;
                    Value::Null
                }

                Command::SetEntry {
                    container,
                    key,
                    value,
                } => {
                    self.vault.set_entry(&container, &key, &value).await?;
                    Value::Null
                }

                Command::GetEntry { container, key } => {
                    json!(self.vault.get_entry(&container, &key).await)
                }

                Command::RemoveEntry { container, key } => {
                    self.vault.remove_entry(&container, &key).await?;
                    Value::Null
                }

                Command::Entries { container } => {
                    let entries: serde_json::Map<String, Value> = self
                        .vault
                        .entries(&container)
                        .await
                        .into_iter()
                        .map(|(key, value)| (key, Value::String(value)))
                        .collect();
                    Value::Object(entries)
                }

                Command::RemoveBlob { hash } => {
                    self.vault.remove_blob(&hash).await?;
                    Value::Null
                }

                Command::Roster => {
                    let listed: Vec<Value> = self
                        .vault
                        .roster()
                        .await
                        .into_iter()
                        .map(|peer| {
                            json!({
                                // A u64 through a JSON double would round, and a
                                // rounded peer id is a different device.
                                "peerId": peer.peer_id.to_string(),
                                "verifyingKey": B64.encode(peer.verifying_key),
                                "name": peer.name,
                                "role": peer.role.to_string(),
                                "active": peer.active,
                                "isSelf": peer.is_self,
                            })
                        })
                        .collect();
                    Value::Array(listed)
                }

                Command::SelfRole => match self.vault.self_role().await {
                    Some(role) => json!(role.to_string()),
                    None => Value::Null,
                },

                Command::RevokePeer {
                    peer_id,
                    verifying_key,
                } => {
                    let peer_id: u64 = peer_id
                        .parse()
                        .map_err(|_| anyhow::anyhow!("peerId must be a u64 written as a string"))?;
                    self.vault
                        .revoke_peer(peer_id, decode_key(&verifying_key)?)
                        .await?;
                    Value::Null
                }

                Command::DataSize => {
                    let size = self.vault.data_size().await?;
                    // Byte counts are u64 and could in principle exceed 2^53,
                    // but a browser origin's quota is orders of magnitude below
                    // that, so these cross as numbers rather than strings.
                    json!({
                        "blobs": size.blobs,
                        "oplog": size.oplog,
                        "meta": size.meta,
                        "total": size.total,
                    })
                }

                Command::CompactDryRun { before_ms } => {
                    json!(self.vault.compact_dry_run(before_ms).await?)
                }

                Command::Compact { before_ms } => json!(self.vault.compact(before_ms).await?),

                Command::RotateEpoch => {
                    self.vault.rotate_epoch().await?;
                    Value::Null
                }

                Command::EditText { text_id, at, text } => {
                    self.vault.edit_text(&text_id, at, &text).await?;
                    Value::Null
                }

                Command::Text { text_id } => json!(self.vault.text(&text_id).await),

                Command::WriteSnapshot => {
                    self.vault.write_snapshot().await?;
                    Value::Null
                }

                Command::Sync => {
                    self.vault.sync(&self.backend).await?;
                    Value::Null
                }

                Command::BucketId => json!(self.vault.bucket_id()),

                // Answered above, before the payload was consumed.
                Command::PutBlob | Command::GetBlob { .. } | Command::HasBlob { .. } => {
                    unreachable!("blob commands return early")
                }
            },
            None,
        ))
    }
}

fn decode_key(encoded: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = B64
        .decode(encoded)
        .map_err(|e| anyhow::anyhow!("verifyingKey is not base64url: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("verifyingKey must decode to exactly 32 bytes"))
}

/// `ok` and `error` are mutually exclusive, and `ok` is always present on
/// success even when it is `null` — so a caller distinguishes the two by which
/// key exists, never by whether a value is falsy.
///
/// `changes` is omitted entirely when empty, which is the common case: most
/// commands are reads. A caller therefore treats an absent key and an empty
/// array identically.
fn envelope(id: Value, result: Result<Value, String>, changes: &[MapChange]) -> String {
    let mut body = match result {
        Ok(value) => json!({ "id": id, "ok": value }),
        Err(message) => json!({ "id": id, "error": message }),
    };
    if !changes.is_empty() {
        let listed: Vec<Value> = changes
            .iter()
            .map(|change| {
                json!({
                    "container": change.container,
                    "key": change.key,
                    // `null` is a deletion, and is why this cannot simply be a
                    // map of surviving keys.
                    "value": change.value,
                })
            })
            .collect();
        body["changes"] = Value::Array(listed);
    }
    // Serializing a `Value` built from strings and nulls cannot fail.
    body.to_string()
}
