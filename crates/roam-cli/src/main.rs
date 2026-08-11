//! `roam` — a manual harness CLI for driving roam-sync over real iroh.
//!
//! This is an operator tool, not a product surface: it wires the storage,
//! sync-engine, and iroh-transport crates together so two vaults can be paired
//! and synced by hand. Each subcommand is a small `async fn`; the only unit test
//! here covers [`append_position`] (see `crates/roam-transport-iroh/tests/e2e.rs`
//! for the automated two-endpoint check).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use roam_files::{FilesError, FolderBridge, GcContext, SyncOutcome};
use roam_storage::{Identity, PeerStatus, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_transport_iroh::{host_pairing, join_pairing, IrohTransport, PairingToken};
use tokio::io::{AsyncBufReadExt, BufReader, Lines, Stdin};
use tokio::sync::mpsc;

/// Debounce window for coalescing a burst of filesystem events (an editor save
/// is typically write + rename + chmod + temp-file churn) into a single scan.
const FS_DEBOUNCE: Duration = Duration::from_millis(200);

#[derive(Parser)]
#[command(
    name = "roam",
    about = "Manual harness for roam-sync over iroh",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a fresh identity + vault, printing the new peer id.
    Init {
        /// Vault directory (created if missing).
        #[arg(long)]
        vault: PathBuf,
        /// Identity keyfile (stored OUTSIDE the vault).
        #[arg(long)]
        identity: PathBuf,
        /// Founder's self-declared role: reader|writer|admin.
        #[arg(long, default_value = "admin")]
        role: String,
    },
    /// Host a pairing exchange: print a token, wait for one join to approve.
    PairToken {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        /// Role to grant the invitee (chosen by the host): reader|writer|admin.
        #[arg(long, default_value = "admin")]
        role: String,
    },
    /// Join another vault using a pairing token.
    Pair {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        /// The base64 pairing token shown by the host.
        #[arg(long)]
        token: String,
    },
    /// Connect to every active roster peer and run the sync loop until Ctrl-C.
    Sync {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        /// Sync a real folder instead of the interactive "note" REPL. Files are
        /// classified by CONTENT, not extension: any UTF-8 text file (any
        /// extension, or none) syncs as a mergeable text note; any non-UTF-8
        /// file syncs as a whole-file binary blob (bytes transfer pull-based,
        /// fetched on demand). Dotfiles/dot-dirs and our own internal metadata
        /// are ignored. Files are imported, projected, created, edited, deleted,
        /// and renamed live in both directions. Internal sidecars/blob markers
        /// are kept OUTSIDE this folder, under the `--vault` store dir. When
        /// absent, the legacy REPL runs (backward compatible).
        #[arg(long)]
        folder: Option<PathBuf>,
        /// Optional backend URL. When set, sync also pushes/pulls encrypted ops
        /// to this zero-knowledge store as an always-on fallback.
        #[arg(long)]
        backend: Option<String>,
    },
    /// Print roster + document status for a vault (read-only).
    Status {
        #[arg(long)]
        vault: PathBuf,
        /// Identity keyfile. Optional: roster + doc read back without it, but the
        /// key-rotation section needs the real identity to open this device's own
        /// key-log and unwrap the epoch keys it holds.
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Rotate the payload key: mint a fresh epoch parented on the current
    /// write-head, wrapping its key to every active member (and, with `--paper`,
    /// a paper-recovery key). Existing backend data is NOT re-encrypted; only new
    /// writes seal under the new epoch. Revoked peers are excluded, so they can
    /// never read anything written after this rotation.
    Rotate {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        /// Also wrap the new epoch to a paper-recovery key derived from this
        /// passphrase. Guard the passphrase: it recovers the epoch if every
        /// device is lost.
        #[arg(long)]
        paper: Option<String>,
    },
    /// List recoverable history: retained markers (time points) and currently
    /// deleted files that `restore` can bring back.
    History {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        identity: PathBuf,
    },
    /// Reclaim space by compacting local history: shallow-snapshot at the newest
    /// point at/before `--before` (`latest` or epoch-millis), truncate op-logs to
    /// the retained tail, drop blobs unreferenced in the retained range. Local
    /// only. `--dry-run` reports bytes without changing anything.
    Checkpoint {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long, default_value = "latest")]
        before: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Recover deleted data from retained history. No paths => restore every
    /// deleted file (whole-vault); with paths => restore just those.
    Restore {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        folder: PathBuf,
        paths: Vec<PathBuf>,
    },
    /// Change a peer's role (admin only).
    Grant {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        /// Target peer id.
        peer: u64,
        /// New role: reader|writer|admin.
        role: String,
        /// The target's verifying key (base64 standard), for the peer_id<->key binding.
        #[arg(long)]
        key: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init {
            vault,
            identity,
            role,
        } => init(&vault, &identity, &role).await,
        Command::PairToken {
            vault,
            identity,
            role,
        } => pair_token(&vault, &identity, &role).await,
        Command::Pair {
            vault,
            identity,
            token,
        } => pair(&vault, &identity, token).await,
        Command::Sync {
            vault,
            identity,
            folder,
            backend,
        } => sync(&vault, &identity, folder, backend).await,
        Command::Status { vault, identity } => status(&vault, identity).await,
        Command::Rotate {
            vault,
            identity,
            paper,
        } => rotate(&vault, &identity, paper).await,
        Command::History { vault, identity } => history(&vault, &identity).await,
        Command::Checkpoint {
            vault,
            identity,
            before,
            dry_run,
        } => checkpoint(&vault, &identity, &before, dry_run).await,
        Command::Restore {
            vault,
            identity,
            folder,
            paths,
        } => restore(&vault, &identity, &folder, paths).await,
        Command::Grant {
            vault,
            identity,
            peer,
            role,
            key,
        } => grant(&vault, &identity, peer, &role, &key).await,
    }
}

/// Parse a role string into a [`Role`].
fn parse_role(s: &str) -> anyhow::Result<Role> {
    match s.to_ascii_lowercase().as_str() {
        "reader" => Ok(Role::Reader),
        "writer" => Ok(Role::Writer),
        "admin" => Ok(Role::Admin),
        other => anyhow::bail!("unknown role '{other}' (reader|writer|admin)"),
    }
}

/// Render a 32-byte epoch id for humans: the all-zero id is epoch 0 (the legacy
/// scheme, written untagged); any other is a readable hex prefix.
fn fmt_epoch(epoch: &[u8; 32]) -> String {
    if *epoch == roam_storage::EPOCH0_ID {
        return "epoch-0 (legacy)".to_string();
    }
    let hex: String = epoch.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{hex}…")
}

/// `<vault>/vault-id` — the raw 32-byte vault id, persisted so later `sync` /
/// `pair-token` can reload it.
fn vault_id_path(vault: &Path) -> PathBuf {
    vault.join("vault-id")
}

/// Persist a [`VaultId`] as its raw 32 bytes next to the vault.
fn save_vault_id(vault: &Path, id: &VaultId) -> Result<()> {
    std::fs::create_dir_all(vault).context("create vault dir")?;
    std::fs::write(vault_id_path(vault), id.0).context("write vault-id")
}

/// Reload a [`VaultId`] previously written by [`save_vault_id`].
fn load_vault_id(vault: &Path) -> Result<VaultId> {
    let bytes =
        std::fs::read(vault_id_path(vault)).context("read vault-id (run `roam init` first)")?;
    let raw: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("vault-id file is not 32 bytes")?;
    Ok(VaultId(raw))
}

/// `<vault>/vault-key` — the raw 32-byte shared vault key (backend decryption
/// secret). Minted at `init`, delivered to joiners over the proven pairing
/// stream, and persisted next to the vault so `sync --backend` can load it.
fn vault_key_path(vault: &Path) -> PathBuf {
    vault.join("vault-key")
}

/// Persist the raw 32-byte vault key next to the vault. This is a SECRET; it
/// lives in the vault dir alongside the store (same trust boundary).
fn save_vault_key(vault: &Path, key: &[u8; 32]) -> Result<()> {
    std::fs::create_dir_all(vault).context("create vault dir")?;
    std::fs::write(vault_key_path(vault), key).context("write vault-key")
}

/// Reload the raw 32-byte vault key previously written by [`save_vault_key`].
fn load_vault_key(vault: &Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(vault_key_path(vault))
        .context("read vault-key (run `roam init`, or re-pair to receive it)")?;
    bytes
        .as_slice()
        .try_into()
        .context("vault-key file is not 32 bytes")
}

async fn init(vault: &Path, identity_path: &Path, role: &str) -> Result<()> {
    // Refuse to re-init: overwriting `vault-id` would orphan already-paired
    // peers (their roster + ops are keyed to the original vault).
    if vault_id_path(vault).exists() {
        anyhow::bail!("vault already initialized (vault-id exists); refusing to overwrite");
    }
    let founder_role = parse_role(role)?;
    let identity = Identity::generate();
    identity.save(identity_path).context("save identity")?;
    // Opening the store materializes the vault directory + peers/oplog files.
    let mut store = Store::open(vault, identity.clone()).context("open vault store")?;
    // Genesis: pin ourselves as founder + self-vouch with the chosen role.
    store
        .declare_founder(founder_role)
        .context("declare founder")?;
    let vault_id = VaultId::generate();
    save_vault_id(vault, &vault_id)?;
    // Mint the shared vault key (backend decryption secret). Reuse
    // `VaultId::generate` as a 32-byte OS-random source — the value is an opaque
    // key, not a vault id. Delivered to every paired device over the pairing
    // stream so all devices agree on it (retires the old blake3(vault_id)
    // placeholder that could not be shared across independently-init'd devices).
    let vault_key = VaultId::generate().0;
    save_vault_key(vault, &vault_key)?;
    println!("initialized vault at {}", vault.display());
    println!("peer_id: {}", identity.peer_id());
    println!(
        "founder role: {}",
        format!("{founder_role:?}").to_lowercase()
    );
    Ok(())
}

async fn pair_token(vault: &Path, identity_path: &Path, role: &str) -> Result<()> {
    let invitee_role = parse_role(role)?;
    let identity = Identity::load(identity_path).context("load identity")?;
    let vault_id = load_vault_id(vault)?;
    let vault_key = load_vault_key(vault)?;
    let mut store = Store::open(vault, identity.clone()).context("open vault store")?;

    let (token, host) = host_pairing(&identity, vault_id, vault_key, invitee_role, &mut store)
        .await
        .context("start pairing host")?;
    println!("pairing token (share out of band):\n{token}");
    print!("approve the next device that joins? [y/N] ");
    use std::io::Write;
    std::io::stdout().flush().ok();

    let mut line = String::new();
    BufReader::new(tokio::io::stdin())
        .read_line(&mut line)
        .await
        .context("read approval")?;
    if !line.trim().eq_ignore_ascii_case("y") {
        println!("pairing declined; no device added.");
        return Ok(());
    }

    let peer = host.accept_auto().await.context("accept join")?;
    println!("paired peer: {peer}");
    Ok(())
}

async fn pair(vault: &Path, identity_path: &Path, token: String) -> Result<()> {
    let identity = Identity::load(identity_path).context("load identity")?;
    // The vault id travels inside the token; capture it before we consume the
    // token string so we can persist `<vault>/vault-id` for later `sync`.
    let decoded = PairingToken::decode(&token).context("decode pairing token")?;
    let host_peer = decoded.peer_id;
    let vault_id = VaultId(decoded.vault);

    // Pairing already persisted `<vault>/founder` itself, so we just consume the
    // founder peer_id from the tuple (bound but otherwise unused here).
    let (_store, vault_key, _founder) = join_pairing(identity, vault.to_path_buf(), token)
        .await
        .context("join pairing")?;
    save_vault_id(vault, &vault_id)?;
    // Persist the shared vault key the host delivered over the proven pairing
    // stream, so this device can decrypt the backend store on `sync --backend`.
    save_vault_key(vault, &vault_key)?;
    println!("paired with host peer: {host_peer}");
    Ok(())
}

/// Dispatch `sync`: `--folder` runs the real-folder sync loop; without it the
/// legacy interactive "note" REPL runs (backward compatible). Both share the
/// transport/engine setup via [`setup_engine`].
async fn sync(
    vault: &Path,
    identity_path: &Path,
    folder: Option<PathBuf>,
    backend: Option<String>,
) -> Result<()> {
    // Honor Ctrl-C from a dedicated task so the signal interrupts even a
    // long-running dial/scan inside the select loop (see `spawn_ctrl_c_exit`).
    spawn_ctrl_c_exit();
    let engine = setup_engine(vault, identity_path).await?;
    spawn_backend_sync(&engine, backend, vault)?;
    match folder {
        Some(folder) => sync_folder(engine, vault, folder).await,
        None => sync_repl(engine).await,
    }
}

/// When `--backend <url>` is set, spawn a periodic task that reconciles the
/// vault against the zero-knowledge backend store, using the Engine's OWN
/// `Arc<Mutex<Store>>` (via `store()`) so the backend-apply and
/// iroh-apply paths serialize on one lock (spec §8.1). Runs regardless of
/// whether `--folder` is set, so it covers both the folder-sync and REPL
/// paths (both are dispatched from `sync` right after this call).
fn spawn_backend_sync(
    engine: &Arc<Engine<IrohTransport>>,
    backend: Option<String>,
    vault: &Path,
) -> Result<()> {
    let Some(backend_url) = backend else {
        return Ok(());
    };
    use roam_backend_client::crypto::VaultKey;
    use roam_backend_client::http::HttpBackend;
    use roam_backend_client::sync::reconcile_once;

    // The shared vault key delivered over the proven pairing stream (minted at
    // `init`, received in `pair`). All devices of a vault hold the SAME key, so
    // their bucket/entry/blob ids agree — the requirement the old
    // blake3(vault_id) placeholder could not meet across separately-init'd
    // devices. A hard error here is correct: `--backend` was explicitly asked
    // for, so a missing key must not silently fall back to an unshared one.
    let vault_key = VaultKey(load_vault_key(vault)?);
    let backend = Arc::new(HttpBackend::new(&backend_url));
    let store = engine.store();
    let flushed = engine.local_flushed();

    tokio::spawn(async move {
        // Poll every 2s to PULL remote changes; additionally wake immediately on
        // a local flush to PUSH local changes without waiting for the next tick.
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            // Register the local-flush waiter BEFORE reconciling, so a flush that
            // races this pass still wakes the next one (notify_waiters stores no
            // permit; `enable()` registers the waiter eagerly, now).
            let wake = flushed.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();

            tokio::select! {
                _ = tick.tick() => {}
                _ = &mut wake => {}
            }
            if let Err(err) = reconcile_once(&store, &backend, &vault_key).await {
                eprintln!("backend sync error: {err}");
            }
            // Opportunistic wrap-back-fill: publish any missing epoch wraps for
            // members we can now see (convergent, idempotent). Best-effort; a
            // failure here must not kill the sync loop.
            if let Err(err) = store
                .lock()
                .await
                .backfill_wraps(&vault_key.id_key(), &vault_key.epoch0_key())
            {
                eprintln!("backend sync backfill error: {err}");
            }
        }
    });
    println!("backend sync enabled: {backend_url}");
    Ok(())
}

/// Build the transport + engine, spawn its receive loop, and connect to every
/// active roster peer. Shared by both the REPL and the folder-sync paths.
async fn setup_engine(vault: &Path, identity_path: &Path) -> Result<Arc<Engine<IrohTransport>>> {
    let identity = Identity::load(identity_path).context("load identity")?;
    let vault_id = load_vault_id(vault)?;
    let store = Store::open(vault, identity.clone()).context("open vault store")?;

    // Build iroh routes from the active roster in a single pass, then derive the
    // connect list from its keys, before the store is moved into the engine.
    // Skip our own self-entry (the roster seeds `{self -> self_key}`): dialing
    // ourselves is unsupported and just prints noise in the demo.
    let me = identity.peer_id();
    let routes: HashMap<u64, [u8; 32]> = store
        .roster()
        .into_iter()
        .filter(|p| p.status == PeerStatus::Active && p.peer_id != me)
        .map(|p| (p.peer_id, p.verifying_key))
        .collect();
    let active: Vec<u64> = routes.keys().copied().collect();

    let transport = IrohTransport::spawn(&identity, routes)
        .await
        .context("spawn iroh transport")?;
    let engine = Arc::new(Engine::new(identity, vault_id, store, Arc::new(transport)));
    tokio::spawn(engine.clone().run());

    // Connect in the BACKGROUND: an unreachable peer's dial blocks ~15s (iroh's
    // default connect timeout), and awaiting it here would stall startup — and,
    // more importantly, delay the backend sync task and folder loop that the
    // caller spawns right after. The periodic reconnect task (spawned by the
    // folder loop) keeps retrying, so a peer that is not up yet still connects.
    println!(
        "connecting to {} active peer(s) in background...",
        active.len()
    );
    {
        let engine = engine.clone();
        tokio::spawn(async move {
            for peer in active {
                match engine.connect(peer).await {
                    Ok(()) => println!("connected to peer {peer}"),
                    Err(e) => println!("connect to peer {peer} failed: {e}"),
                }
            }
        });
    }
    Ok(engine)
}

/// Reconcile the whole vault folder against the store on a blocking thread.
///
/// Lock discipline (CRITICAL): the store mutex is acquired with `blocking_lock()`
/// INSIDE `spawn_blocking`, so it never runs on a runtime worker and the guard is
/// released on the blocking thread before this async task resumes — the guard
/// never crosses a transport `.await`. `scan` performs synchronous disk IO with
/// the store locked and returns before any gossip happens.
///
/// A `spawn_blocking` panic surfaces as a `JoinError` → `anyhow` via `?`; a
/// `scan` failure surfaces as `FilesError` → `anyhow` via `map_err`. The caller
/// treats BOTH as non-fatal (log + continue), so one bad file never kills the
/// daemon.
async fn run_scan(
    engine: &Arc<Engine<IrohTransport>>,
    bridge: &FolderBridge,
    hint: Option<HashSet<PathBuf>>,
) -> anyhow::Result<Vec<(PathBuf, SyncOutcome)>> {
    let store = engine.store(); // Arc<Mutex<Store>>
    let bridge = bridge.clone(); // FolderBridge is just a PathBuf (derives Clone).
                                 // Gather the causally-stable-GC inputs BEFORE the blocking closure: the
                                 // per-peer acked versions are behind their own async mutex (fetched here,
                                 // never across the store guard), and `self_peer` is cheap. The trusted-peer
                                 // roster is read inside the closure from the already-held store guard.
    let self_peer = engine.peer_id();
    let acked_versions = engine.acked_versions().await;
    tokio::task::spawn_blocking(move || {
        let mut guard = store.blocking_lock(); // OK on a blocking thread.
                                               // Trusted, non-revoked peers (a roster snapshot). A tombstone may only be
                                               // GC'd once EVERY one of these has acked past it; a peer absent from
                                               // `acked_versions` (never heard from) keeps the tombstone alive.
        let trusted_peers = guard
            .roster()
            .into_iter()
            .filter(|p| p.status == PeerStatus::Active)
            .map(|p| p.peer_id)
            .collect();
        let gc = GcContext {
            self_peer,
            trusted_peers,
            acked_versions,
        };
        // `hint = None` walks + imports the whole vault (the poll fallback);
        // `Some(set)` limits the read+diff to the watcher's changed paths. The
        // GC sweep runs as a final step and drops only causally-stable tombstones.
        bridge.scan_gc(&mut guard, hint.as_ref(), Some(&gc)) // sync disk IO, store locked.
    })
    .await? // JoinError (panic) -> anyhow.
    .map_err(Into::into) // FilesError -> anyhow.
}

/// Coalesce a batch of filesystem-event paths into a deduplicated dirty-set to
/// hand to `scan_hinted`. Pure (no IO / no timing) so the "N events in → 1
/// coalesced set out" contract is unit-testable.
fn coalesce_paths<I: IntoIterator<Item = PathBuf>>(paths: I) -> HashSet<PathBuf> {
    paths.into_iter().collect()
}

/// Create a recursive filesystem watcher over `vault_root` that forwards every
/// changed path into `tx`. Returns `Err` if the watcher cannot initialize (e.g.
/// inotify limit, or the path does not exist); the caller degrades to poll-only
/// rather than aborting. The returned watcher must be kept alive for watching to
/// continue — dropping it stops the watch.
fn spawn_vault_watcher(
    vault_root: &Path,
    tx: mpsc::UnboundedSender<PathBuf>,
) -> notify::Result<RecommendedWatcher> {
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        // A failed event is dropped: the 500ms poll is the guaranteed catch-up,
        // so a missed watcher event only costs latency, never correctness.
        if let Ok(event) = res {
            for path in event.paths {
                // Send failures mean the receiver is gone (loop exiting); ignore.
                let _ = tx.send(path);
            }
        }
    })?;
    watcher.watch(vault_root, RecursiveMode::Recursive)?;
    Ok(watcher)
}

/// The real-folder sync loop (Tasks c + d). Imports local disk edits and projects
/// remote edits, in both directions, until Ctrl-C.
async fn sync_folder(
    engine: Arc<Engine<IrohTransport>>,
    store_dir: &Path,
    folder: PathBuf,
) -> Result<()> {
    // Ensure the vault folder exists before anything reads or watches it: a
    // fresh `--folder` path is created on first run (matching the note REPL,
    // which needs no pre-existing files). Without this the fs watcher fails to
    // attach ("No such file or directory") and every scan walks nothing.
    std::fs::create_dir_all(&folder)
        .with_context(|| format!("create vault folder {}", folder.display()))?;

    // Internal sidecars/blob-markers live under the STORE dir (the `--vault`
    // arg), NOT in the user's `--folder`, so they never pollute the notes dir.
    // `Sidecar::store` / `write_blob_marker` create the nested parents lazily,
    // so simply pointing the bridge at `<store>/filemeta` is enough.
    let meta_dir = store_dir.join("filemeta");
    let bridge = FolderBridge::new(&folder, &meta_dir);

    // Initial publish: import the current vault contents into the store, then
    // gossip to peers. A failing initial scan is logged, not fatal — the poll
    // below retries.
    scan_and_maybe_flush(&engine, &bridge, None).await;
    // Always flush once at startup even if the scan changed nothing locally, so a
    // freshly-connected peer receives whatever the store already held.
    engine.flush_local().await;

    // Low-latency filesystem watcher: forward changed paths over an mpsc channel
    // into the async `select!`. Kept as a variable so the watcher lives for the
    // whole loop (dropping it stops watching). If it fails to initialize (e.g.
    // inotify limit), warn and continue POLL-ONLY — correctness never depends on
    // the watcher, only latency does.
    let (fs_tx, mut fs_rx) = mpsc::unbounded_channel::<PathBuf>();
    // Retain our OWN sender for the loop's lifetime so the channel never closes,
    // even if the watcher fails to start (it moves+drops the sender it is given).
    // A closed channel makes `fs_rx.recv()` return `None` immediately on every
    // iteration, hot-spinning the `select!` and starving the Ctrl-C branch — the
    // daemon would then refuse to stop. Holding this sender keeps the fs branch
    // pending in poll-only mode instead.
    let _fs_tx_keepalive = fs_tx.clone();
    let _watcher = match spawn_vault_watcher(&folder, fs_tx) {
        Ok(watcher) => {
            println!("fs watcher active (low-latency); 500ms poll is the fallback.");
            Some(watcher)
        }
        Err(err) => {
            eprintln!("warning: fs watcher unavailable ({err}); running poll-only.");
            None
        }
    };

    println!("watching {} for changes; Ctrl-C to stop.", folder.display());
    let mut interval = tokio::time::interval(Duration::from_millis(500));

    // Self-healing reconnect runs in its OWN task, NOT in the select loop below.
    // `reconnect_active` dials each unreachable peer sequentially, and each dial
    // blocks ~15s on iroh's connect timeout; running it inline would stall local
    // scans + disk projection for that whole time (a file created mid-dial would
    // not sync until the dial gave up). Isolated here, dial latency never touches
    // the local sync path. Cheap no-op for live connections; reconnects dead ones.
    {
        let engine = engine.clone();
        tokio::spawn(async move {
            let mut reconnect = tokio::time::interval(Duration::from_secs(5));
            // Skip the immediate first tick: setup_engine already kicked off a connect.
            reconnect.reset();
            loop {
                reconnect.tick().await;
                roam_sync_core::dlog!("cli: reconnect tick");
                engine.reconnect_active().await;
            }
        });
    }

    loop {
        // Re-acquire the Notify handle and build a FRESH `Notified` future each
        // iteration: `notify_waiters` only wakes CURRENTLY-registered waiters and
        // stores no permit, so a future from a prior iteration is useless here.
        //
        // Registration ordering: `Notified` registers as a waiter on first poll,
        // not at creation, which would leave a gap between building it and the
        // `select!`'s first poll. `enable()` registers the waiter eagerly, right
        // now, closing that gap for the duration of this iteration's await.
        //
        // A residual gap remains WHILE a branch body is awaiting (e.g. inside
        // `run_scan`'s `spawn_blocking`): a `notify_waiters` firing then is not
        // caught by this future. That is acceptable — the 500ms poll is the
        // GUARANTEED fallback that reconciles remote state regardless, so the
        // notify is purely a latency optimization for the common idle case.
        let changed = engine.changed();
        let notified = changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        tokio::select! {
            // Local-change poll: guaranteed fallback for both directions. Runs a
            // FULL scan (`None` hint) so a missed/coalesced-away watcher event
            // (editor atomic-rename quirks, inotify overflow) is always caught.
            _ = interval.tick() => {
                scan_and_maybe_flush(&engine, &bridge, None).await;
            }
            // Inbound remote change: project remote state to disk promptly.
            _ = &mut notified => {
                roam_sync_core::dlog!("cli: remote change signal → scanning + projecting");
                scan_and_maybe_flush(&engine, &bridge, None).await;
            }
            // Local filesystem change (low latency). Debounce the burst: collect
            // the first path, then keep draining until the channel goes quiet for
            // FS_DEBOUNCE, so one editor save (write + rename + chmod + temp file)
            // becomes ONE hinted scan over the union of changed paths.
            first = fs_rx.recv() => {
                if let Some(first) = first {
                    let mut batch = vec![first];
                    let debounce = tokio::time::sleep(FS_DEBOUNCE);
                    tokio::pin!(debounce);
                    loop {
                        tokio::select! {
                            _ = &mut debounce => break,
                            more = fs_rx.recv() => match more {
                                Some(path) => batch.push(path),
                                None => break, // watcher dropped; scan what we have.
                            },
                        }
                    }
                    let dirty = coalesce_paths(batch);
                    scan_and_maybe_flush(&engine, &bridge, Some(dirty)).await;
                }
                // `None` = watcher channel closed; the poll keeps the loop alive.
            }
        }
    }
}

/// Run one reconcile scan and, if anything changed, gossip local ops to peers.
///
/// Task (d) error handling lives here: a `run_scan` error NEVER propagates — it is
/// logged and the loop continues. `DirtyFile` is classified as a benign
/// per-file condition (quieter note); anything else (including a `spawn_blocking`
/// panic surfaced as a non-`FilesError` `anyhow`) gets a louder warning. Either
/// way the daemon keeps running.
async fn scan_and_maybe_flush(
    engine: &Arc<Engine<IrohTransport>>,
    bridge: &FolderBridge,
    hint: Option<HashSet<PathBuf>>,
) {
    let hint_dbg = hint
        .as_ref()
        .map(|h| {
            format!(
                "hinted {:?}",
                h.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
            )
        })
        .unwrap_or_else(|| "full-poll".to_string());
    match run_scan(engine, bridge, hint).await {
        Ok(outcomes) => {
            let changed = outcomes.iter().filter(|(_, o)| o.changed).count();
            roam_sync_core::dlog!(
                "cli: scan ({hint_dbg}) → {} outcome(s), {changed} changed",
                outcomes.len(),
            );
            report_scan(&outcomes);
            if outcomes.iter().any(|(_, outcome)| outcome.changed) {
                let changed_paths: Vec<_> = outcomes
                    .iter()
                    .filter(|(_, o)| o.changed)
                    .map(|(p, _)| p.display().to_string())
                    .collect();
                roam_sync_core::dlog!(
                    "cli: local scan changed {} file(s) {:?} → flush_local",
                    changed_paths.len(),
                    changed_paths,
                );
                // A remote-driven scan that only projected to disk still calls
                // this; `flush_local` is idempotent (no unsent suffix -> no-op),
                // so the harmless extra flush is fine.
                engine.flush_local().await;
            }
        }
        Err(err) => match err.downcast_ref::<FilesError>() {
            Some(files_err) if is_benign_scan_error(files_err) => {
                eprintln!("note: skipping file: {files_err}");
            }
            Some(files_err) => eprintln!("warning: scan failed, continuing: {files_err}"),
            None => eprintln!("warning: scan task failed, continuing: {err}"),
        },
    }

    // Pull-based blobs: gossip carries only the Blob file-set entry (the
    // blob-ref), never the bytes. After every reconcile, ask connected peers for
    // the bytes of any Live Blob entry we still lack (BlobWant → BlobData). When
    // the reply lands the engine fires `changed()`, waking the loop so the NEXT
    // scan projects the now-local bytes to disk (D5). Idempotent + cheap: sends
    // nothing when no blob is missing, and only to connected active peers.
    engine.request_missing_blobs().await;
}

/// Print a concise, legible line per changed file so the demo shows what moved.
/// A file that also carried concurrent-edit conflicts gets an extra `conflict:`
/// line (non-fatal — the merge already kept both sides; this just informs).
fn report_scan(outcomes: &[(PathBuf, SyncOutcome)]) {
    for (path, outcome) in outcomes {
        if let Some(line) = describe_outcome(path, outcome, path.exists()) {
            println!("{line}");
        }
        if let Some(line) = conflict_line(path, outcome) {
            println!("{line}");
        }
    }
}

/// A `conflict:` line for an outcome that surfaced concurrent-edit conflicts, or
/// `None` when there were none. Pure (no IO) so it is unit-testable.
///
/// The merge is authoritative and lossless (both sides survive); this line only
/// tells the user that two peers changed overlapping regions of the same file.
fn conflict_line(path: &Path, outcome: &SyncOutcome) -> Option<String> {
    if outcome.conflicts.is_empty() {
        return None;
    }
    let n = outcome.conflicts.len();
    let regions = outcome
        .conflicts
        .iter()
        .map(|c| format!("{}..{}", c.ancestor_start, c.ancestor_end))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "  conflict: {} — {n} overlapping edit region(s) [{regions}] (both kept)",
        path.display()
    ))
}

/// A human-readable action for a single scan outcome, or `None` when nothing
/// changed. `exists` = whether the path is present on disk after the scan, which
/// distinguishes a projection/creation (`exists`) from a deletion (`!exists`) when
/// no edit ops were applied (both report `ops_applied == 0, changed == true`).
///
/// Pure (no IO): the caller supplies `exists`, so this is unit-testable.
fn describe_outcome(path: &Path, outcome: &SyncOutcome, exists: bool) -> Option<String> {
    if !outcome.changed {
        return None;
    }
    let action = if outcome.ops_applied > 0 {
        format!("imported ({} op(s))", outcome.ops_applied)
    } else if exists {
        "projected".to_string()
    } else {
        "deleted".to_string()
    };
    Some(format!("  {action}: {}", path.display()))
}

/// Whether a scan error is a known-benign, per-file condition. Both benign and
/// non-benign scan errors are non-fatal to the loop; this only picks the log
/// verbosity. `DirtyFile` is expected during normal use (a file with un-imported
/// local edits mid-project).
fn is_benign_scan_error(err: &FilesError) -> bool {
    matches!(err, FilesError::DirtyFile(_))
}

/// Install a Ctrl-C handler that hard-exits from a DEDICATED task.
///
/// A `tokio::select!` only races its branch GUARDS, not the futures the winning
/// branch then awaits. So an in-loop `ctrl_c()` branch cannot interrupt a
/// long-running branch body already in progress — e.g. the ~10s iroh dial
/// timeout inside `reconnect_active`, or a `spawn_blocking` scan. During that
/// window the loop is not awaiting `ctrl_c()` at all, so the daemon ignores
/// the signal until the dial finally returns. A separate task is always being
/// polled and honors the signal immediately.
///
/// The exit is hard (`process::exit`) rather than an unwind to `main`: iroh
/// spawns background driver tasks/threads (magicsock, relay, discovery) that do
/// not all wind down on drop, so `Runtime::drop` blocks and the daemon would
/// hang after "stopping." The store is committed+persisted on every scan/apply,
/// so a hard exit loses no state.
fn spawn_ctrl_c_exit() {
    tokio::spawn(async {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("\nstopping.");
            std::process::exit(0);
        }
    });
}

/// The legacy interactive "note" REPL (backward compatible). Type lines to append
/// to the shared "note" container and watch the peer's edits land.
async fn sync_repl(engine: Arc<Engine<IrohTransport>>) -> Result<()> {
    println!("running; type a line to append, Ctrl-C to stop.");

    // Interactive REPL: type lines to append to the shared "note" container and
    // watch the peer's edits land. Three concurrent branches under one select!.
    //
    // stdin is an Option so we can disable it on EOF (piped input / non-TTY)
    // without exiting — the change watcher must keep running so the peer stays
    // visible even after our own input stream closes.
    let mut lines: Option<Lines<BufReader<Stdin>>> =
        Some(BufReader::new(tokio::io::stdin()).lines());
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    let mut last_seen = String::new();

    loop {
        tokio::select! {
            // stdin line -> append at the current end of the note.
            //
            // Concurrency note: two machines appending at their local
            // end-position can interleave (the position is computed before a
            // peer's edit lands), but Loro merges both inserts — no data is
            // lost, only the interleaving order may vary. Fine for a demo.
            line = read_next(&mut lines), if lines.is_some() => {
                match line {
                    Some(line) => {
                        let pos = append_position(&engine.store().lock().await.text("note"));
                        engine
                            .edit_text("note", pos, &format!("{line}\n"))
                            .await
                            .context("append edit")?;
                        println!("you> {line}");
                    }
                    // EOF: stop reading stdin but keep syncing.
                    None => lines = None,
                }
            }
            // Poll the note for changes (peer edits + our own applied edits).
            // Lock -> clone the String -> drop the guard, then compare/print;
            // never hold the store mutex across an await or I/O.
            _ = ticker.tick() => {
                let text = {
                    let store = engine.store();
                    let guard = store.lock().await;
                    guard.text("note")
                };
                if text != last_seen {
                    println!("--- note ---\n{text}");
                    last_seen = text;
                }
            }
        }
    }
}

/// Read the next stdin line, or `None` on EOF/error.
///
/// Split out so the `select!` branch stays a plain expression; the caller
/// guards it with `if lines.is_some()` and only reaches here with `Some`.
async fn read_next(lines: &mut Option<Lines<BufReader<Stdin>>>) -> Option<String> {
    match lines {
        Some(l) => l.next_line().await.ok().flatten(),
        None => None,
    }
}

/// Append position for a text container: the count of unicode codepoints, which
/// is Loro's position unit. Using `.len()` (bytes) would corrupt positions for
/// any non-ASCII text (e.g. inserting after "café" needs pos 4, not 5).
fn append_position(text: &str) -> usize {
    text.chars().count()
}

async fn status(vault: &Path, identity_path: Option<PathBuf>) -> Result<()> {
    // Roster + doc are shared vault state, read back regardless of which identity
    // opens the store. The key-rotation section, however, needs THIS device's
    // real identity: only it can read the device's own key-log and unwrap the
    // epoch keys wrapped to it. Absent `--identity`, we open with an ephemeral id
    // (roster/doc still valid) and skip the epoch section.
    let identity = match &identity_path {
        Some(path) => Some(Identity::load(path).context("load identity")?),
        None => None,
    };
    let store = Store::open(vault, identity.clone().unwrap_or_else(Identity::generate))
        .context("open vault store")?;
    let roster = store.roster();
    println!("roster ({} peer(s)):", roster.len());
    for peer in &roster {
        let status = match peer.status {
            PeerStatus::Active => "active",
            PeerStatus::Revoked => "revoked",
        };
        let role = format!("{:?}", peer.role).to_lowercase();
        println!("  peer {} [{}] role={}", peer.peer_id, status, role);
    }
    println!("note: {} bytes", store.text("note").len());
    println!("doc version: {} bytes", store.doc_version_bytes().len());

    // Key-rotation state needs BOTH the real identity (to open own key-log +
    // unwrap epochs) and the vault key (to derive the id + epoch-0 keys). Missing
    // either → skip the section rather than fail; status is a read-only peek.
    match (identity.is_some(), load_vault_key(vault)) {
        (false, _) => {
            println!("epochs: (pass --identity to inspect key-rotation state)")
        }
        (true, Err(_)) => {
            println!("epochs: (no vault-key present — init or pair to inspect key state)")
        }
        (true, Ok(raw)) => {
            use roam_backend_client::crypto::VaultKey;
            let vault_key = VaultKey(raw);
            let keychain = store
                .keychain(&vault_key.id_key(), &vault_key.epoch0_key())
                .context("build keychain")?;
            println!(
                "epochs: {} (write-head {})",
                keychain.epochs.len(),
                fmt_epoch(&keychain.head)
            );
            let heads = keychain.dag_heads();
            if heads.len() > 1 {
                let rendered: Vec<String> = heads.iter().map(fmt_epoch).collect();
                println!("  concurrent heads: {}", rendered.join(", "));
            }
            let issues = keychain.diagnose(&roster);
            if issues.is_empty() {
                println!("vault key state: synced");
            } else {
                println!("vault key state: {} issue(s):", issues.len());
                for issue in &issues {
                    println!("  {}", fmt_issue(issue));
                }
            }
        }
    }
    Ok(())
}

/// One-line human rendering of a [`roam_storage::VaultIssue`].
fn fmt_issue(issue: &roam_storage::VaultIssue) -> String {
    use roam_storage::VaultIssue::*;
    match issue {
        WaitingKey { epoch, candidates } => format!(
            "waiting for key to epoch {} (held by peer(s) {:?})",
            fmt_epoch(epoch),
            candidates
        ),
        KeyOrphaned { epoch } => format!(
            "epoch {} ORPHANED — no current member nor paper key holds it",
            fmt_epoch(epoch)
        ),
        KeyRedundancyLow { epoch, holders } => format!(
            "epoch {} low redundancy — only peer(s) {:?} hold it (one loss from orphaned)",
            fmt_epoch(epoch),
            holders
        ),
    }
}

/// Mint a fresh epoch and wrap its key to every active member (+ optional paper
/// key). Requires the real identity: the new key-log entries are signed by it.
async fn rotate(vault: &Path, identity_path: &Path, paper: Option<String>) -> Result<()> {
    use roam_backend_client::crypto::VaultKey;
    use roam_storage::PaperKey;

    let identity = Identity::load(identity_path).context("load identity")?;
    let vault_key = VaultKey(load_vault_key(vault)?);
    let mut store = Store::open(vault, identity).context("open vault store")?;

    let paper_public = paper
        .as_deref()
        .map(|passphrase| PaperKey::from_passphrase(passphrase).public());

    let epoch = store
        .rotate_epoch(&vault_key.id_key(), &vault_key.epoch0_key(), paper_public)
        .context("rotate epoch")?;

    println!("rotated to epoch {}", fmt_epoch(&epoch));
    if paper_public.is_some() {
        println!("wrapped to paper-recovery key (keep the passphrase safe)");
    }
    println!("new writes seal under this epoch; existing data is unchanged.");
    Ok(())
}

/// Resolve `--before` to an epoch-millis cutoff. `latest` => i64::MAX; an integer
/// => epoch millis.
fn parse_before(before: &str) -> anyhow::Result<i64> {
    if before == "latest" {
        return Ok(i64::MAX);
    }
    before
        .parse::<i64>()
        .map_err(|_| anyhow::anyhow!("--before must be 'latest' or epoch-millis, got {before:?}"))
}

/// List recoverable history for a vault (read-only): the retained history markers
/// (time points a checkpoint could land on) and the currently-deleted files that
/// `restore` can bring back. The bridge's folder root is the `--vault` dir (the
/// working root `list_deleted` maps stored keys back onto); internal sidecars live
/// under `<vault>/filemeta`, the same meta-dir convention `sync` uses.
async fn history(vault: &Path, identity_path: &Path) -> Result<()> {
    let identity = Identity::load(identity_path).context("load identity")?;
    let store = Store::open(vault, identity).context("open vault store")?;
    let idx = roam_storage::HistoryIndex::new(&vault.join("history"));
    let markers = idx.markers().context("read history")?;
    println!("retained history points: {}", markers.len());
    for m in &markers {
        println!("  ts={} peers={}", m.ts_ms, m.log_lens.len());
    }
    let bridge = FolderBridge::new(vault, &vault.join("filemeta"));
    let deleted = bridge.list_deleted(&store);
    println!("recoverable deleted files: {}", deleted.len());
    for p in &deleted {
        println!("  {}", p.display());
    }
    Ok(())
}

/// Compact local history to reclaim space. Local-only: shallow-snapshots at the
/// newest point at/before `--before`, truncates op-logs, and drops blobs
/// unreferenced in the retained range. `--dry-run` reports the freeable bytes
/// without touching anything.
async fn checkpoint(vault: &Path, identity_path: &Path, before: &str, dry_run: bool) -> Result<()> {
    let cutoff = parse_before(before)?;
    let identity = Identity::load(identity_path).context("load identity")?;
    let mut store = Store::open(vault, identity).context("open vault store")?;
    if dry_run {
        let bytes = store.checkpoint_dry_run(cutoff).context("dry-run")?;
        println!(
            "checkpoint --before {before}: would free {bytes} bytes (blobs). No changes made."
        );
    } else {
        let freed = store.checkpoint(cutoff).context("checkpoint")?;
        println!("checkpoint done: freed {freed} bytes; op history compacted. Local only.");
    }
    Ok(())
}

/// Recover deleted data from retained history into `--folder`. No paths => restore
/// every currently-deleted file (whole-vault); with paths => restore just those.
/// The bridge uses `--folder` as its working root and `<vault>/filemeta` as its
/// meta-dir, matching `sync`. The restored projection is persisted with
/// `write_snapshot` before returning.
async fn restore(
    vault: &Path,
    identity_path: &Path,
    folder: &Path,
    paths: Vec<PathBuf>,
) -> Result<()> {
    let identity = Identity::load(identity_path).context("load identity")?;
    let mut store = Store::open(vault, identity).context("open vault store")?;
    let bridge = FolderBridge::new(folder, &vault.join("filemeta"));
    let outcomes = if paths.is_empty() {
        bridge.restore_all(&mut store).context("restore all")?
    } else {
        bridge
            .restore_paths(&mut store, &paths)
            .context("restore paths")?
    };
    store.write_snapshot().context("persist after restore")?;
    println!("restored {} file(s):", outcomes.len());
    for (p, _) in &outcomes {
        println!("  {}", p.display());
    }
    Ok(())
}

/// Change a peer's role (admin only). Binds the target's peer_id to its verifying
/// key and records a signed `SetRole` under our own admin authority.
async fn grant(
    vault: &Path,
    identity_path: &Path,
    peer: u64,
    role: &str,
    key_b64: &str,
) -> anyhow::Result<()> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let identity = Identity::load(identity_path).context("load identity")?;
    let mut store = Store::open(vault, identity).context("open vault store")?;
    let key_bytes: [u8; 32] = B64
        .decode(key_b64)
        .context("decode key")?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
    store
        .set_role(peer, key_bytes, parse_role(role)?)
        .context("set role")?;
    println!("granted peer {peer} role {role}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        append_position, coalesce_paths, conflict_line, describe_outcome, is_benign_scan_error,
        spawn_vault_watcher,
    };
    use roam_files::{Conflict, FilesError, SyncOutcome};
    use std::path::{Path, PathBuf};
    use tokio::sync::mpsc;

    #[test]
    fn coalesce_paths_dedups_a_burst_into_one_set() {
        // A2: N events (with duplicates, as an editor save produces) collapse to
        // ONE dirty-set of the distinct changed paths.
        let a = PathBuf::from("/vault/a.md");
        let b = PathBuf::from("/vault/b.md");
        let burst = vec![a.clone(), a.clone(), b.clone(), a.clone(), b.clone()];
        let set = coalesce_paths(burst);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&a));
        assert!(set.contains(&b));
    }

    #[test]
    fn coalesce_paths_empty_is_empty() {
        assert!(coalesce_paths(Vec::<PathBuf>::new()).is_empty());
    }

    #[test]
    fn fmt_epoch_labels_legacy_and_hex_prefixes_others() {
        // The all-zero id is epoch 0 (legacy, untagged ciphertext).
        assert_eq!(super::fmt_epoch(&[0u8; 32]), "epoch-0 (legacy)");
        // Anything else renders an 8-byte hex prefix with an ellipsis.
        let rendered = super::fmt_epoch(&[0xab_u8; 32]);
        assert!(rendered.starts_with("abababababababab"));
        assert!(rendered.ends_with('…'));
    }

    #[test]
    fn watcher_initializes_over_real_dir_but_fails_on_missing_path() {
        // A1 fallback decision: a real directory yields Ok (watcher active); a
        // non-existent path yields Err (caller degrades to poll-only). This
        // exercises both inputs of the `match` that picks watcher-vs-poll-only.
        let dir = tempfile::tempdir().unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(spawn_vault_watcher(dir.path(), tx).is_ok());

        let missing = dir.path().join("does-not-exist");
        let (tx2, _rx2) = mpsc::unbounded_channel();
        assert!(spawn_vault_watcher(&missing, tx2).is_err());
    }

    #[test]
    fn describe_outcome_classifies_import_project_delete() {
        let p = Path::new("note.md");

        // ops_applied > 0 -> imported (regardless of existence).
        let imported = SyncOutcome {
            ops_applied: 3,
            changed: true,
            conflicts: Vec::new(),
        };
        let line = describe_outcome(p, &imported, true).unwrap();
        assert!(line.contains("imported (3 op(s))"));
        assert!(line.contains("note.md"));

        // 0 ops + present -> projected.
        let projected = SyncOutcome {
            ops_applied: 0,
            changed: true,
            conflicts: Vec::new(),
        };
        assert!(describe_outcome(p, &projected, true)
            .unwrap()
            .contains("projected"));

        // 0 ops + absent -> deleted.
        assert!(describe_outcome(p, &projected, false)
            .unwrap()
            .contains("deleted"));

        // Nothing changed -> None (no noise printed).
        let unchanged = SyncOutcome {
            ops_applied: 0,
            changed: false,
            conflicts: Vec::new(),
        };
        assert!(describe_outcome(p, &unchanged, true).is_none());
    }

    #[test]
    fn conflict_line_reports_conflicts_and_is_none_when_empty() {
        let p = Path::new("note.md");

        // An outcome carrying a conflict yields a `conflict:` line naming the path.
        let with_conflict = SyncOutcome {
            ops_applied: 2,
            changed: true,
            conflicts: vec![Conflict {
                ancestor_start: 1,
                ancestor_end: 2,
                ancestor_text: "b".to_string(),
            }],
        };
        let line = conflict_line(p, &with_conflict).unwrap();
        assert!(line.contains("conflict:"), "line was: {line}");
        assert!(line.contains("note.md"));
        assert!(line.contains("1..2"));

        // No conflicts -> no line.
        let clean = SyncOutcome {
            ops_applied: 2,
            changed: true,
            conflicts: Vec::new(),
        };
        assert!(conflict_line(p, &clean).is_none());
    }

    #[test]
    fn benign_scan_errors_are_dirty_file() {
        assert!(is_benign_scan_error(&FilesError::DirtyFile(PathBuf::from(
            "x.md"
        ))));
        // A desync is unexpected and must NOT be treated as benign.
        assert!(!is_benign_scan_error(&FilesError::Desync("boom".into())));
    }

    #[test]
    fn append_position_counts_codepoints_not_bytes() {
        // "café": 4 codepoints but 5 bytes (é is 2 bytes in UTF-8).
        assert_eq!(append_position("café"), 4);
        assert_eq!("café".len(), 5);
        // A multi-byte emoji still counts as one codepoint position.
        assert_eq!(append_position("a🌍b"), 3);
        // Empty text appends at the start.
        assert_eq!(append_position(""), 0);
    }
}
