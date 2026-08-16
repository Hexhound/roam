//! The worker's command protocol, tested without a worker.
//!
//! Everything a browser client does to its vault goes through
//! `Session::handle`, so this is the surface that decides whether the web
//! client works. It is deliberately reachable from an ordinary `cargo test`:
//! the JS worker holds no logic, so if these pass, the only thing left for a
//! browser to prove is that messages arrive.

use roam_backend_client::transport::MemoryBackend;
use roam_wasm::{Session, Vault};
use serde_json::{json, Value};
use std::sync::Arc;

const VAULT_KEY: [u8; 32] = [7u8; 32];
const TEXT_ID: &str = "notes/hello.md";

fn session() -> Session<MemoryBackend> {
    Session::new(
        Vault::in_memory(VAULT_KEY).unwrap(),
        Arc::new(MemoryBackend::default()),
    )
}

async fn call(session: &Session<MemoryBackend>, request: Value) -> Value {
    serde_json::from_str(&session.handle(&request.to_string()).await).expect("reply is JSON")
}

/// The happy path of every command that carries data, in one go: a reply's `ok`
/// has to round-trip what the vault actually holds.
#[tokio::test]
async fn commands_read_back_what_they_wrote() {
    let session = session();

    let set = call(
        &session,
        json!({"id": 1, "command": "setEntry", "container": "meta", "key": "title", "value": "Hello"}),
    )
    .await;
    assert_eq!(set, json!({"id": 1, "ok": null}));

    let got = call(
        &session,
        json!({"id": 2, "command": "getEntry", "container": "meta", "key": "title"}),
    )
    .await;
    assert_eq!(got, json!({"id": 2, "ok": "Hello"}));

    let edit = call(
        &session,
        json!({"id": 3, "command": "editText", "textId": TEXT_ID, "at": 0, "text": "written from a worker"}),
    )
    .await;
    assert_eq!(edit, json!({"id": 3, "ok": null}));

    let text = call(
        &session,
        json!({"id": 4, "command": "text", "textId": TEXT_ID}),
    )
    .await;
    assert_eq!(text["ok"], json!("written from a worker"));

    let missing = call(
        &session,
        json!({"id": 5, "command": "getEntry", "container": "meta", "key": "absent"}),
    )
    .await;
    assert_eq!(
        missing,
        json!({"id": 5, "ok": null}),
        "an absent entry is a successful null, not an error"
    );

    let snapshot = call(&session, json!({"id": 6, "command": "writeSnapshot"})).await;
    assert_eq!(snapshot, json!({"id": 6, "ok": null}));
}

/// The envelope owns `id`, so a text container is named by `textId`. Sending
/// both keys is not a parse error — JSON keeps one of them — so without a
/// distinct name this would quietly edit a container called "1".
#[tokio::test]
async fn the_envelope_id_is_not_mistaken_for_a_text_container() {
    let session = session();
    call(
        &session,
        json!({"id": 1, "command": "editText", "textId": TEXT_ID, "at": 0, "text": "body"}),
    )
    .await;

    let by_envelope_id = call(&session, json!({"id": 2, "command": "text", "textId": "1"})).await;
    assert_eq!(
        by_envelope_id["ok"],
        json!(""),
        "the envelope's id leaked into the vault as a container name"
    );
}

/// A peer id is a `u64`; JSON numbers are doubles. Sending one as a number
/// would round it above 2^53, and a rounded peer id is not an approximate
/// device, it is a different device.
#[tokio::test]
async fn peer_ids_cross_the_boundary_as_strings() {
    let session = session();
    let reply = call(&session, json!({"id": 1, "command": "peerId"})).await;

    let peer_id = reply["ok"].as_str().expect("peerId must be a JSON string");
    assert!(
        peer_id.parse::<u64>().is_ok(),
        "peerId {peer_id:?} does not parse as a u64"
    );
}

/// Two sessions, vouching for each other purely over the protocol, converging
/// through a relay. This is the whole browser client in miniature.
#[tokio::test]
async fn two_sessions_converge_over_the_protocol_alone() {
    let backend = Arc::new(MemoryBackend::default());
    let a = Session::new(Vault::in_memory(VAULT_KEY).unwrap(), backend.clone());
    let b = Session::new(Vault::in_memory(VAULT_KEY).unwrap(), backend.clone());

    for (left, right) in [(&a, &b), (&b, &a)] {
        let peer_id = call(right, json!({"id": 1, "command": "peerId"})).await["ok"].clone();
        let verifying_key =
            call(right, json!({"id": 2, "command": "verifyingKey"})).await["ok"].clone();
        let vouched = call(
            left,
            json!({"id": 3, "command": "addPeer", "peerId": peer_id, "verifyingKey": verifying_key}),
        )
        .await;
        assert_eq!(vouched, json!({"id": 3, "ok": null}), "addPeer failed");
    }

    call(
        &a,
        json!({"id": 4, "command": "editText", "textId": TEXT_ID, "at": 0, "text": "sent"}),
    )
    .await;
    call(&a, json!({"id": 5, "command": "sync"})).await;
    call(&b, json!({"id": 6, "command": "sync"})).await;

    let text = call(&b, json!({"id": 7, "command": "text", "textId": TEXT_ID})).await;
    assert_eq!(text["ok"], json!("sent"));
}

/// Every bad input still produces a reply. A worker that stays silent leaves the
/// page holding a promise that never settles — a hang is a much worse failure
/// than an error, and much harder to diagnose from a UI.
#[tokio::test]
async fn nothing_a_caller_can_send_produces_silence() {
    let session = session();

    let bad_json = session.handle("{not json").await;
    let bad_json: Value = serde_json::from_str(&bad_json).expect("even this reply is JSON");
    assert!(bad_json["error"].is_string());

    for request in [
        json!({"id": 1, "command": "noSuchCommand"}),
        json!({"id": 2, "command": "setEntry", "container": "meta"}),
        json!({"id": 3, "command": "addPeer", "peerId": "not-a-number", "verifyingKey": "AAAA"}),
        json!({"id": 4, "command": "addPeer", "peerId": "1", "verifyingKey": "!!!not-base64"}),
        json!({"id": 5, "command": "addPeer", "peerId": "1", "verifyingKey": "AAAA"}),
    ] {
        let id = request["id"].clone();
        let reply = call(&session, request.clone()).await;
        assert!(
            reply["error"].is_string(),
            "{request} should have failed, got {reply}"
        );
        assert_eq!(reply["id"], id, "the id must survive a failure: {reply}");
        assert!(
            reply.get("ok").is_none(),
            "a failure must not also report ok: {reply}"
        );
    }
}

/// An unparseable request has no id to echo, and must say so explicitly rather
/// than inventing one — a caller matching replies to requests would otherwise
/// settle the wrong promise.
#[tokio::test]
async fn a_request_with_no_id_replies_with_a_null_one() {
    let session = session();
    let reply = call(&session, json!({"command": "peerId"})).await;
    assert_eq!(reply["id"], Value::Null);
    assert!(reply["ok"].is_string());
}
