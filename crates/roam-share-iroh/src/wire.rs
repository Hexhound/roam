//! Length-prefixed framing over a QUIC bidirectional stream.

use anyhow::{bail, Context, Result};
use iroh::endpoint::{RecvStream, SendStream};

/// The share ALPN. Distinct from the sync and pairing ALPNs so a share
/// connection can never be mistaken for one that may touch a vault.
pub const SHARE_ALPN: &[u8] = b"roam/share/1";

/// Cap on a single framed message.
///
/// The length prefix arrives from an unauthenticated peer, so without this a
/// hostile 4-byte header would have us allocate up to 4 GiB. Large enough for a
/// chunk plus its seal and an offer listing many files.
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

pub async fn write_frame(send: &mut SendStream, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).context("frame too large to length-prefix")?;
    send.write_all(&len.to_le_bytes())
        .await
        .context("write frame length")?;
    send.write_all(bytes).await.context("write frame body")?;
    Ok(())
}

pub async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    recv.read_exact(&mut len_bytes)
        .await
        .context("read frame length")?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        // Fail rather than truncate: a peer sending an over-long frame is either
        // broken or hostile, and neither deserves a partial read.
        bail!("peer announced a {len}-byte frame, over the {MAX_FRAME_BYTES} limit");
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .context("read frame body")?;
    Ok(body)
}
