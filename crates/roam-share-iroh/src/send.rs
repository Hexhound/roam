//! The sending half: hold the files, show a code, serve one receiver.

use crate::wire::{read_frame, write_frame};
use crate::CHUNK_BYTES;
use anyhow::{bail, Context, Result};
use iroh::Endpoint;
use roam_pake::{PairingCode, Responder, Side};
use roam_share::{FileMeta, Payload, RelPath, SafeName, ShareFrame, ShareOffer};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where the bytes for each offered stream actually live on this machine.
///
/// Kept separate from the [`ShareOffer`] on purpose: the offer crosses the wire
/// and must not carry local absolute paths, which would leak the sender's
/// directory layout (and username) to anyone who connects.
pub type SourceMap = BTreeMap<RelPath, PathBuf>;

/// Build an offer from real paths on disk.
///
/// Files become [`Payload::File`]; directories are walked and become
/// [`Payload::Folder`]. Symlinks are **not** followed: a link inside a shared
/// folder could otherwise pull in a file from anywhere the sender can read,
/// which is not what "share this folder" means to anyone.
pub fn offer_paths(from: &str, paths: &[PathBuf]) -> Result<(ShareOffer, SourceMap)> {
    let mut items = Vec::new();
    let mut sources = SourceMap::new();

    for path in paths {
        let metadata =
            std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .context("path has no usable final component")?;
        let name = SafeName::new(name)
            .map_err(|e| anyhow::anyhow!("cannot share {}: {e}", path.display()))?;

        if metadata.is_symlink() {
            bail!("refusing to share the symlink {} directly", path.display());
        }
        if metadata.is_dir() {
            let mut files = Vec::new();
            collect_dir(path, path, &mut files, &mut sources, &name)?;
            items.push(Payload::Folder { name, files });
        } else {
            let rel = RelPath::new(name.as_str()).expect("a SafeName is a valid one-part RelPath");
            sources.insert(rel.clone(), path.clone());
            items.push(Payload::File(FileMeta {
                path: rel,
                len: metadata.len(),
            }));
        }
    }

    Ok((
        ShareOffer {
            from: from.to_string(),
            items,
        },
        sources,
    ))
}

fn collect_dir(
    root: &Path,
    dir: &Path,
    files: &mut Vec<FileMeta>,
    sources: &mut SourceMap,
    folder_name: &SafeName,
) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        // Skip rather than fail: one symlink should not make a whole folder
        // unshareable, but it must not be followed either.
        if metadata.is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_dir(root, &path, files, sources, folder_name)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .expect("walked paths are always under the root");
        let text = relative
            .to_str()
            .with_context(|| format!("{} is not valid UTF-8", relative.display()))?
            // Windows separators would be rejected by RelPath, and the wire
            // format is `/`-separated regardless of host.
            .replace('\\', "/");
        let rel = RelPath::new(&text)
            .map_err(|e| anyhow::anyhow!("cannot share {}: {e}", path.display()))?;
        files.push(FileMeta {
            path: rel.clone(),
            len: metadata.len(),
        });
        // The key must match what `ShareOffer::streams()` produces, which
        // prefixes folder contents with the folder's own name.
        let keyed = RelPath::new(&format!("{folder_name}/{rel}"))
            .expect("both halves are already validated");
        sources.insert(keyed, path);
    }
    Ok(())
}

/// A failure that is OUR fault rather than the peer's.
///
/// The distinction is load-bearing in [`ShareSender::serve_one`]: a peer-caused
/// failure drops one connection and we keep listening, but retrying cannot fix
/// a file we cannot read, so that ends the session and is reported to the user.
#[derive(Debug)]
struct LocalFailure(String);

impl std::fmt::Display for LocalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LocalFailure {}

/// How long one handshake read may take before the connection is abandoned.
///
/// `serve_one` handles connections ONE AT A TIME, so a peer that connects and
/// then says nothing would block every legitimate receiver. Before this bound
/// existed there was no timeout in this crate at all, and the only thing ending
/// such a connection was QUIC's ~30s idle timeout — repeat that in a loop and
/// no share ever completes. Generous for a human on a slow link, far below the
/// idle timeout.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// An armed sender: a code is showing and one receiver may claim it.
pub struct ShareSender {
    endpoint: Endpoint,
    offer: ShareOffer,
    sources: SourceMap,
    responder: Responder,
    handshake_timeout: Duration,
}

impl ShareSender {
    /// Arm a sender on `endpoint`. Returns the code to display.
    pub fn new(endpoint: Endpoint, offer: ShareOffer, sources: SourceMap) -> (Self, PairingCode) {
        let code = PairingCode::generate();
        let responder = Responder::new(code.clone(), *endpoint.id().as_bytes());
        (
            ShareSender {
                endpoint,
                offer,
                sources,
                responder,
                handshake_timeout: HANDSHAKE_TIMEOUT,
            },
            code,
        )
    }

    /// Override [`HANDSHAKE_TIMEOUT`]. A test seam: production callers want the
    /// default, and tests should not sit out a ten-second stall to prove a
    /// stall is survivable.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Run `future` under [`Self::with_handshake_timeout`].
    ///
    /// Every read from an unproven peer goes through here. The outer `Result`
    /// is the timeout, the inner one is whatever the read itself returned.
    async fn bounded<T>(&self, future: impl std::future::Future<Output = T>) -> Result<T> {
        tokio::time::timeout(self.handshake_timeout, future)
            .await
            .context("peer stalled during the share handshake")
    }

    /// Serve until one transfer completes or the attempt budget runs out.
    ///
    /// A wrong code costs one attempt and drops that connection only — the user
    /// gets to retype it — but the budget is finite, unlike token pairing's.
    pub async fn serve_one(mut self) -> Result<()> {
        loop {
            if self.responder.attempts_left() == 0 {
                bail!("too many wrong codes — the share code is used up");
            }
            let Some(incoming) = self.endpoint.accept().await else {
                bail!("share endpoint closed before a receiver arrived");
            };
            let conn = match incoming.accept() {
                Ok(connecting) => match connecting.await {
                    Ok(conn) => conn,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            match self.serve_connection(&conn).await {
                Ok(()) => {
                    // Either the receiver closes (transfer completed) or we
                    // already closed it ourselves (declined); both resolve this.
                    conn.closed().await;
                    return Ok(());
                }
                Err(err) => {
                    conn.close(0u32.into(), b"share rejected");
                    // Only OUR OWN failures end the session. Everything a peer
                    // can cause — a wrong code, a stall, a malformed frame — must
                    // drop that one connection and leave us listening, or any
                    // device on the network could kill a share just by
                    // connecting and misbehaving. Previously only `BadCode` was
                    // treated as recoverable, so a peer that connected and said
                    // nothing terminated the sender outright.
                    if err.downcast_ref::<LocalFailure>().is_some() {
                        return Err(err);
                    }
                    continue;
                }
            }
        }
    }

    async fn serve_connection(&mut self, conn: &iroh::endpoint::Connection) -> Result<()> {
        // iroh authenticates the remote endpoint id during the QUIC handshake,
        // so this is the peer's real public key, not a self-claim. Binding it
        // into the PAKE is what stops a relayed handshake.
        let receiver_id = conn.remote_id();
        // Bounded from the very first read: a peer that connects and never opens
        // a stream is just as effective a blocker as one that opens a stream and
        // never writes.
        let (mut send, mut recv) = self.bounded(conn.accept_bi()).await??;

        // --- authenticate before anything is revealed --------------------
        let msg1 = self.bounded(read_frame(&mut recv)).await??;
        let (pending, msg2) = self
            .responder
            .respond(*receiver_id.as_bytes(), &msg1)
            .map_err(anyhow::Error::from)?;
        write_frame(&mut send, &msg2).await?;

        let confirm = self.bounded(read_frame(&mut recv)).await??;
        let confirm: [u8; 32] = confirm
            .try_into()
            .map_err(|_| anyhow::anyhow!("malformed confirmation"))?;
        // Charged here, not at `respond`: this is the point the peer committed
        // to a guess. Before, an unparseable msg1 spent an attempt, so three
        // junk connections retired the code and ended the share — the exact
        // "a peer must never end the session" rule this loop enforces.
        let (key, our_confirm) = self
            .responder
            .verify(pending, &confirm)
            .map_err(anyhow::Error::from)?;
        write_frame(&mut send, &our_confirm).await?;

        let (mut sealer, mut opener) = key.split(Side::Responder);

        // --- authenticated; now the offer may be revealed ----------------
        let offer_frame = ShareFrame::Offer(self.offer.clone());
        write_frame(&mut send, &sealer.seal(&offer_frame.encode())).await?;

        let reply = ShareFrame::decode(&opener.open(&self.bounded(read_frame(&mut recv)).await??)?)
            .context("decode the receiver's reply")?;
        let accepted = match reply {
            ShareFrame::Accept { streams } => streams,
            ShareFrame::Decline => {
                // Acknowledge positively rather than just closing. `serve_one`
                // consumes the sender, so our Endpoint is dropped the moment we
                // return — a bare close would often not be flushed before that,
                // leaving the receiver to sit out a 30s idle timeout. A Done
                // frame also makes the receiver the closer in BOTH paths, so
                // shutdown no longer depends on drop ordering.
                write_frame(&mut send, &sealer.seal(&ShareFrame::Done.encode())).await?;
                send.finish().context("finish share stream")?;
                conn.closed().await;
                return Ok(());
            }
            other => bail!("expected Accept or Decline, got {}", other.kind()),
        };

        let streams = self.offer.streams();
        for index in accepted {
            let stream = streams
                .get(index as usize)
                .with_context(|| format!("receiver accepted unknown stream {index}"))?;
            // These two are ours, not the peer's: the offer we built names a
            // file we cannot produce. Another receiver would hit exactly the
            // same wall, so `serve_one` must stop and say so rather than
            // silently wait for someone else to connect.
            let source = self
                .sources
                .get(&stream.path)
                .ok_or_else(|| LocalFailure(format!("no local file backs {}", stream.path)))?;
            let bytes = std::fs::read(source)
                .map_err(|e| LocalFailure(format!("read {}: {e}", source.display())))?;
            for (chunk_index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
                let frame = ShareFrame::Chunk {
                    stream: index,
                    offset: (chunk_index * CHUNK_BYTES) as u64,
                    bytes: chunk.to_vec(),
                };
                write_frame(&mut send, &sealer.seal(&frame.encode())).await?;
            }
        }

        write_frame(&mut send, &sealer.seal(&ShareFrame::Done.encode())).await?;
        send.finish().context("finish share stream")?;
        Ok(())
    }
}
