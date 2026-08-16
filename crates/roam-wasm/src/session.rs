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

use crate::vault::Vault;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use roam_backend_client::transport::Backend;
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

    /// Handle one request, returning the reply as a JSON string.
    ///
    /// This is infallible by design. A worker that cannot answer leaves the page
    /// waiting forever on a promise that never settles, which is a far worse
    /// failure than an error reply — so every path, including "that isn't JSON",
    /// produces an envelope.
    pub async fn handle(&self, request: &str) -> String {
        let parsed: Value = match serde_json::from_str(request) {
            Ok(value) => value,
            // No `id` is recoverable here: there is no request to read one from.
            // The caller sees a rejected promise rather than a hung one.
            Err(e) => return envelope(Value::Null, Err(format!("malformed request: {e}"))),
        };

        // Read the id BEFORE the command parses, so a request naming a command
        // this build does not have still gets a reply the caller can match up.
        let id = parsed.get("id").cloned().unwrap_or(Value::Null);

        let command: Command = match serde_json::from_value(parsed) {
            Ok(command) => command,
            Err(e) => return envelope(id, Err(format!("unrecognized command: {e}"))),
        };

        envelope(id, self.run(command).await.map_err(|e| format!("{e:#}")))
    }

    async fn run(&self, command: Command) -> anyhow::Result<Value> {
        Ok(match command {
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
        })
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
fn envelope(id: Value, result: Result<Value, String>) -> String {
    let body = match result {
        Ok(value) => json!({ "id": id, "ok": value }),
        Err(message) => json!({ "id": id, "error": message }),
    };
    // Serializing a `Value` built from strings and nulls cannot fail.
    body.to_string()
}
