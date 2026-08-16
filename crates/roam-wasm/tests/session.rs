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
    serde_json::from_str(&session.handle_json(&request.to_string()).await).expect("reply is JSON")
}

/// The binary leg: a request that carries bytes, and a reply that may.
async fn call_with_bytes(
    session: &Session<MemoryBackend>,
    request: Value,
    payload: Option<Vec<u8>>,
) -> (Value, Option<Vec<u8>>) {
    let reply = session.handle(&request.to_string(), payload).await;
    (
        serde_json::from_str(&reply.json).expect("reply is JSON"),
        reply.bytes,
    )
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
    assert_eq!(
        set,
        json!({
            "id": 1,
            "ok": null,
            "changes": [{"container": "meta", "key": "title", "value": "Hello"}],
        })
    );

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

    let bad_json = session.handle_json("{not json").await;
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

/// Blob bytes travel beside the envelope, never inside it. Round-tripping a
/// payload that is not valid UTF-8 is the point: anything that quietly routed
/// these through JSON would corrupt them here rather than at some customer's
/// attachment.
#[tokio::test]
async fn blob_bytes_never_go_through_the_json() {
    let session = session();
    let payload: Vec<u8> = (0..=255u8).chain([0, 0, 0xff, 0xfe]).collect();

    let (put, no_bytes) = call_with_bytes(
        &session,
        json!({"id": 1, "command": "putBlob"}),
        Some(payload.clone()),
    )
    .await;
    let hash = put["ok"].as_str().expect("putBlob replies with a hash");
    assert!(no_bytes.is_none(), "putBlob has nothing to send back");

    let (got, bytes) = call_with_bytes(
        &session,
        json!({"id": 2, "command": "getBlob", "hash": hash}),
        None,
    )
    .await;
    assert_eq!(got["ok"], json!({"len": payload.len()}));
    assert_eq!(bytes.as_deref(), Some(payload.as_slice()));

    let (has, _) = call_with_bytes(
        &session,
        json!({"id": 3, "command": "hasBlob", "hash": hash}),
        None,
    )
    .await;
    assert_eq!(has["ok"], json!(true));
}

/// A zero-length blob is *present*. It answers with a length of 0 and no
/// payload, which is byte-for-byte what a missing blob would look like if the
/// two were not distinguished — so a caller reading "no bytes" as "not here"
/// would re-fetch an attachment that is already local, forever.
#[tokio::test]
async fn an_empty_blob_is_present_and_a_missing_one_is_not() {
    let session = session();

    let (put, _) = call_with_bytes(
        &session,
        json!({"id": 1, "command": "putBlob"}),
        Some(Vec::new()),
    )
    .await;
    let hash = put["ok"].as_str().unwrap().to_string();

    let (empty, bytes) = call_with_bytes(
        &session,
        json!({"id": 2, "command": "getBlob", "hash": hash}),
        None,
    )
    .await;
    assert_eq!(
        empty["ok"],
        json!({"len": 0}),
        "an empty blob is still here"
    );
    assert_eq!(bytes.as_deref(), Some(&[][..]));

    let absent = call(
        &session,
        json!({"id": 3, "command": "getBlob", "hash": "0".repeat(64)}),
    )
    .await;
    assert_eq!(absent, json!({"id": 3, "ok": null}), "missing is a null ok");

    let never_stored = call(
        &session,
        json!({"id": 4, "command": "hasBlob", "hash": "0".repeat(64)}),
    )
    .await;
    assert_eq!(never_stored["ok"], json!(false));
}

/// `putBlob` with no payload is a caller error, not a panic and not an empty
/// blob — writing zero bytes under a hash nobody asked for would be silent
/// corruption of the caller's reference.
#[tokio::test]
async fn put_blob_without_bytes_is_an_error() {
    let session = session();
    let reply = call(&session, json!({"id": 1, "command": "putBlob"})).await;
    assert!(reply["error"].is_string(), "got {reply}");
}

/// The reason there is no push channel: a pull brings a peer's writes in, and
/// the `sync` reply is where a caller learns about them. If this were empty, an
/// embedder projecting into its own database would silently miss every remote
/// change and only notice on a full re-read.
#[tokio::test]
async fn a_sync_reports_the_peers_changes_on_its_own_reply() {
    let backend = Arc::new(MemoryBackend::default());
    let a = Session::new(Vault::in_memory(VAULT_KEY).unwrap(), backend.clone());
    let b = Session::new(Vault::in_memory(VAULT_KEY).unwrap(), backend.clone());

    for (left, right) in [(&a, &b), (&b, &a)] {
        let peer_id = call(right, json!({"id": 1, "command": "peerId"})).await["ok"].clone();
        let verifying_key =
            call(right, json!({"id": 2, "command": "verifyingKey"})).await["ok"].clone();
        call(
            left,
            json!({"id": 3, "command": "addPeer", "peerId": peer_id, "verifyingKey": verifying_key}),
        )
        .await;
    }

    call(
        &a,
        json!({"id": 4, "command": "setEntry", "container": "meta", "key": "title", "value": "from A"}),
    )
    .await;
    call(&a, json!({"id": 5, "command": "sync"})).await;

    let pulled = call(&b, json!({"id": 6, "command": "sync"})).await;
    assert_eq!(
        pulled["changes"],
        json!([{"container": "meta", "key": "title", "value": "from A"}]),
        "a sync must report what it pulled: {pulled}"
    );

    // A second sync reports only what moved *since the last one* — a caller
    // replaying the whole map on every sync would grow linearly in vault size.
    //
    // (`value: null` means a deletion, which this protocol cannot yet produce:
    // there is no delete command. The encoding is in place for when there is.)
    call(
        &a,
        json!({"id": 7, "command": "setEntry", "container": "meta", "key": "title", "value": ""}),
    )
    .await;
    call(&a, json!({"id": 8, "command": "sync"})).await;
    let updated = call(&b, json!({"id": 9, "command": "sync"})).await;
    assert_eq!(
        updated["changes"],
        json!([{"container": "meta", "key": "title", "value": ""}]),
    );
}

/// Reads must not claim to have changed anything. An embedder that re-projected
/// on every reply would do the work of a full sync on each `getEntry`.
#[tokio::test]
async fn a_read_reports_no_changes_at_all() {
    let session = session();
    call(
        &session,
        json!({"id": 1, "command": "setEntry", "container": "meta", "key": "title", "value": "Hi"}),
    )
    .await;

    for request in [
        json!({"id": 2, "command": "getEntry", "container": "meta", "key": "title"}),
        json!({"id": 3, "command": "peerId"}),
        json!({"id": 4, "command": "bucketId"}),
    ] {
        let reply = call(&session, request.clone()).await;
        assert!(
            reply.get("changes").is_none(),
            "{request} reported changes: {reply}"
        );
    }
}

/// `bucketId` is asked once at open and cached, because on the Dart side it is
/// a synchronous getter. So it has to be stable, and it has to be the same value
/// the sync path addresses — otherwise a caller would label a vault with one
/// bucket while its data went to another.
#[tokio::test]
async fn the_bucket_id_is_derived_from_the_key_and_stable() {
    let first = call(&session(), json!({"id": 1, "command": "bucketId"})).await["ok"].clone();
    let again = call(&session(), json!({"id": 2, "command": "bucketId"})).await["ok"].clone();
    assert_eq!(first, again, "two vaults on one key must share a bucket");

    let other = Session::new(
        Vault::in_memory([9u8; 32]).unwrap(),
        Arc::new(MemoryBackend::default()),
    );
    let elsewhere = call(&other, json!({"id": 3, "command": "bucketId"})).await["ok"].clone();
    assert_ne!(
        first, elsewhere,
        "a different key must be a different bucket"
    );
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
