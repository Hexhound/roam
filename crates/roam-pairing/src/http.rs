//! The mailbox over HTTP, against a real relay.
//!
//! Six routes' worth of surface, and no state beyond the base URL and the
//! rendezvous id. `reqwest` because it is the one HTTP stack in this workspace
//! that compiles for both native and `wasm32` — the same reason
//! `roam_backend_client::http` uses it, and the reason a browser can run this
//! module unchanged.

use crate::mailbox::{Mailbox, Slot, SlotOutcome};
use crate::Invite;
use async_trait::async_trait;

/// Ceiling on a slot body this client will hold in memory.
///
/// Matched to the relay's own cap (`Sync.Backend.Mailbox`, 4 MB): a body larger
/// than the relay is willing to accept cannot be something that relay
/// legitimately stored, so refusing it turns nothing away and bounds what a
/// hostile — or merely broken — one can make a client allocate. The declared
/// length is checked because it is free; it is not *trusted*, because a chunked
/// response declares nothing.
const MAX_SLOT_BYTES: u64 = 4_000_000;

/// One rendezvous on one relay.
pub struct HttpMailbox {
    base: String,
    rendezvous: String,
    client: reqwest::Client,
}

impl HttpMailbox {
    /// Address the rendezvous an [`Invite`] names, on the relay it names.
    pub fn for_invite(invite: &Invite) -> Self {
        Self::new(&invite.relay, &invite.rendezvous_id())
    }

    pub fn new(relay_base_url: &str, rendezvous_id: &str) -> Self {
        Self {
            base: relay_base_url.trim_end_matches('/').to_string(),
            rendezvous: rendezvous_id.to_string(),
            client: reqwest::Client::new(),
        }
    }

    fn slot_url(&self, session: &str, slot: Slot) -> String {
        format!(
            "{}/rendezvous/{}/{session}/{}",
            self.base,
            self.rendezvous,
            slot.as_str()
        )
    }
}

/// Read a response body, refusing to buffer more than [`MAX_SLOT_BYTES`].
///
/// The wasm build gets the declared-length check and nothing more: `chunk` does
/// not exist there, because the fetch backend hands over a body it has already
/// buffered itself, so there is no point at which this code could stop reading.
/// Stated rather than papered over — on wasm an endless body is bounded by the
/// browser, not by us. Same split, and same honesty, as the backend client.
async fn read_capped(resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    if let Some(declared) = resp.content_length() {
        anyhow::ensure!(
            declared <= MAX_SLOT_BYTES,
            "relay declares a {declared}-byte slot, over the {MAX_SLOT_BYTES} cap"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut resp = resp;
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            anyhow::ensure!(
                body.len() as u64 + chunk.len() as u64 <= MAX_SLOT_BYTES,
                "relay slot body exceeded the {MAX_SLOT_BYTES} byte cap"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    #[cfg(target_arch = "wasm32")]
    Ok(resp.bytes().await?.to_vec())
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Mailbox for HttpMailbox {
    async fn put(&self, session: &str, slot: Slot, body: Vec<u8>) -> anyhow::Result<SlotOutcome> {
        let resp = self
            .client
            .put(self.slot_url(session, slot))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body)
            .send()
            .await?;

        match resp.status() {
            reqwest::StatusCode::CREATED | reqwest::StatusCode::OK => Ok(SlotOutcome::Written),
            // The write-once refusal. Reported rather than raised, because the
            // handshake treats it as "this session is not mine to finish" and
            // abandons it — which is what keeps a squatter from costing the host
            // one of its three attempts.
            reqwest::StatusCode::CONFLICT => Ok(SlotOutcome::AlreadyTaken),
            reqwest::StatusCode::TOO_MANY_REQUESTS => Err(anyhow::anyhow!(
                "this rendezvous has too many pairing sessions in flight — ask for a fresh invite"
            )),
            other => Err(anyhow::anyhow!(
                "unexpected relay status {other} writing a pairing slot"
            )),
        }
    }

    async fn get(&self, session: &str, slot: Slot) -> anyhow::Result<Option<Vec<u8>>> {
        let resp = self.client.get(self.slot_url(session, slot)).send().await?;
        // A slot the other side has not written yet. This is the normal case
        // while polling, so it must not be an error.
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp.error_for_status()?;
        Ok(Some(read_capped(resp).await?))
    }

    async fn sessions(&self) -> anyhow::Result<Vec<String>> {
        #[derive(serde::Deserialize)]
        struct Sessions {
            sessions: Vec<String>,
        }

        let url = format!("{}/rendezvous/{}/sessions", self.base, self.rendezvous);
        let resp = self.client.get(url).send().await?.error_for_status()?;
        // Through the same cap as everything else: `json` reads to EOF exactly
        // like `bytes` does, so leaving it alone would leave the bound
        // bypassable by the request a host makes most often.
        let listing: Sessions = serde_json::from_slice(&read_capped(resp).await?)?;
        Ok(listing.sessions)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn slot_urls_match_the_relay_routes() {
        // These strings are the contract with `SyncWeb.Router`. A drift here is
        // a 404 on every request, which presents as pairing simply hanging.
        let mailbox = HttpMailbox::new("https://relay.example/", "RENDEZVOUS");
        assert_eq!(
            mailbox.slot_url("SESSION", Slot::ConfirmJoiner),
            "https://relay.example/rendezvous/RENDEZVOUS/SESSION/confirm-joiner"
        );
    }

    #[test]
    fn a_trailing_slash_on_the_relay_url_does_not_double_up() {
        // An invite minted from a user-typed URL is the common case, and a
        // double slash is a 404 the user would have no way to diagnose.
        for base in ["https://relay.example", "https://relay.example/"] {
            let url = HttpMailbox::new(base, "R").slot_url("S", Slot::Msg1);
            assert!(!url.contains("//rendezvous"), "double slash in {url}");
        }
    }

    #[test]
    fn an_invite_addresses_its_own_rendezvous() {
        let invite = Invite::generate("https://relay.example", [3u8; 32]);
        let mailbox = HttpMailbox::for_invite(&invite);
        assert!(mailbox
            .slot_url("S", Slot::Msg1)
            .contains(&invite.rendezvous_id()));
    }
}
