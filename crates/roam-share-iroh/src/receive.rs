//! The receiving half: type a code, dial, decide, write files.
//!
//! Everything here comes from a peer that has proved only one thing — that it
//! knows a six-digit code. Sizes, names and chunk offsets are all attacker
//! controlled, and are treated that way.

use crate::wire::{read_frame, write_frame, SHARE_ALPN};
use crate::DEFAULT_MAX_ACCEPT_BYTES;
use anyhow::{bail, Context, Result};
use iroh::{Endpoint, EndpointAddr};
use roam_pake::{Initiator, PairingCode, Side};
use roam_share::{Payload, ShareFrame, ShareOffer};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// What a completed transfer produced.
#[derive(Debug, Default)]
pub struct Received {
    /// Files written, in offer order.
    pub files: Vec<PathBuf>,
    /// Inline text payloads (`Text` / `Clipboard`), which are never files.
    pub texts: Vec<String>,
}

/// Dial a sender, prove the code, and accept everything on offer.
///
/// `dest` must already exist. Every file lands inside it — the paths in an offer
/// are `roam_share::RelPath`s, which cannot escape their base by construction.
///
/// `decide` is called with the offer once the code is proved and before any
/// bytes move, so a UI can show the human what is coming. Returning `false`
/// declines.
pub async fn receive_share<F>(
    endpoint: &Endpoint,
    sender: EndpointAddr,
    code: &PairingCode,
    dest: &Path,
    decide: F,
) -> Result<Received>
where
    F: FnOnce(&ShareOffer) -> bool,
{
    let sender_id = sender.id;
    let conn = endpoint
        .connect(sender, SHARE_ALPN)
        .await
        .context("connect to share sender")?;
    let (mut send, mut recv) = conn.open_bi().await.context("open share stream")?;

    // --- prove the code before anything is revealed to us ----------------
    let (initiator, msg1) = Initiator::start(
        code,
        *endpoint.id().as_bytes(),
        *sender_id.as_bytes(),
    );
    write_frame(&mut send, &msg1).await?;

    let msg2 = read_frame(&mut recv).await?;
    let (pending, our_confirm) = initiator.accept(&msg2).map_err(anyhow::Error::from)?;
    write_frame(&mut send, &our_confirm).await?;

    let their_confirm = read_frame(&mut recv).await?;
    let their_confirm: [u8; 32] = their_confirm
        .try_into()
        .map_err(|_| anyhow::anyhow!("malformed confirmation"))?;
    let key = pending.verify(&their_confirm).map_err(anyhow::Error::from)?;
    let (mut sealer, mut opener) = key.split(Side::Initiator);

    // --- authenticated; the offer is now trustworthy-ish -----------------
    let offer = match ShareFrame::decode(&opener.open(&read_frame(&mut recv).await?)?)
        .context("decode the offer")?
    {
        ShareFrame::Offer(offer) => offer,
        other => bail!("expected an Offer, got {}", other.kind()),
    };

    let claimed = offer.total_len();
    if claimed > DEFAULT_MAX_ACCEPT_BYTES {
        write_frame(&mut send, &sealer.seal(&ShareFrame::Decline.encode())).await?;
        bail!("offer claims {claimed} bytes, over the {DEFAULT_MAX_ACCEPT_BYTES} limit");
    }

    if !decide(&offer) {
        write_frame(&mut send, &sealer.seal(&ShareFrame::Decline.encode())).await?;
        // Declining is an answer, not a disconnect. Returning here without
        // waiting would drop the connection with the Decline still unflushed,
        // and the sender would see a bare "connection lost" instead. Wait for
        // the sender's Done, which acknowledges the Decline arrived, then close
        // — the same direction as the success path.
        let ack = ShareFrame::decode(&opener.open(&read_frame(&mut recv).await?)?)
            .context("decode the sender's acknowledgement")?;
        if !matches!(ack, ShareFrame::Done) {
            bail!("expected Done after declining, got {}", ack.kind());
        }
        conn.close(0u32.into(), b"share declined");
        return Ok(Received::default());
    }

    let streams = offer.streams();
    let wanted: Vec<u32> = (0..streams.len() as u32).collect();
    write_frame(
        &mut send,
        &sealer.seal(&ShareFrame::Accept { streams: wanted }.encode()),
    )
    .await?;

    // --- receive ---------------------------------------------------------
    // Assembled in memory keyed by stream, then written once each stream is
    // complete. Bounded by the size check above.
    let mut buffers: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    loop {
        let frame = ShareFrame::decode(&opener.open(&read_frame(&mut recv).await?)?)
            .context("decode a share frame")?;
        match frame {
            ShareFrame::Chunk {
                stream,
                offset,
                bytes,
            } => {
                let meta = streams
                    .get(stream as usize)
                    .with_context(|| format!("chunk for unknown stream {stream}"))?;
                let offset = usize::try_from(offset).context("chunk offset does not fit in memory")?;
                // The sender declared a length; hold it to that. Without this a
                // sender could accept-then-flood far past what the user
                // approved. Checked with saturating/overflow-safe arithmetic
                // because both values come from the peer.
                let end = offset
                    .checked_add(bytes.len())
                    .context("chunk offset + length overflows")?;
                if end as u64 > meta.len {
                    bail!(
                        "stream {stream} sent {end} bytes but declared {}",
                        meta.len
                    );
                }
                let buffer = buffers.entry(stream).or_insert_with(|| vec![0u8; meta.len as usize]);
                buffer[offset..end].copy_from_slice(&bytes);
            }
            ShareFrame::Done => break,
            other => bail!("unexpected {} during transfer", other.kind()),
        }
    }

    let mut received = Received::default();
    for (stream, bytes) in buffers {
        let meta = &streams[stream as usize];
        // `resolve_under` is safe by construction: every component of a RelPath
        // is a validated SafeName, so the result is always inside `dest`.
        let path = meta.path.resolve_under(dest);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        std::fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;
        received.files.push(path);
    }

    for item in &offer.items {
        match item {
            Payload::Text(text) | Payload::Clipboard(text) => received.texts.push(text.clone()),
            _ => {}
        }
    }

    conn.close(0u32.into(), b"share complete");
    Ok(received)
}
