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
use roam_storage::{Identity, PeerStatus, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_transport_iroh::{host_pairing, join_pairing, IrohTransport, PairingToken};
use tokio::io::{AsyncBufReadExt, BufReader, Lines, Stdin};
use tokio::sync::mpsc;

/// Debounce window for coalescing a burst of filesystem events (an editor save
/// is typically write + rename + chmod + temp-file churn) into a single scan.
const FS_DEBOUNCE: Duration = Duration::from_millis(200);

#[derive(Parser)]
#[command(name = "roam", about = "Manual harness for roam-sync over iroh", version)]
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
    },
    /// Host a pairing exchange: print a token, wait for one join to approve.
    PairToken {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        identity: PathBuf,
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
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init { vault, identity } => init(&vault, &identity).await,
        Command::PairToken { vault, identity } => pair_token(&vault, &identity).await,
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
        Command::Status { vault } => status(&vault).await,
    }
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
    let bytes = std::fs::read(vault_id_path(vault)).context("read vault-id (run `roam init` first)")?;
    let raw: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("vault-id file is not 32 bytes")?;
    Ok(VaultId(raw))
}

async fn init(vault: &Path, identity_path: &Path) -> Result<()> {
    // Refuse to re-init: overwriting `vault-id` would orphan already-paired
    // peers (their roster + ops are keyed to the original vault).
    if vault_id_path(vault).exists() {
        anyhow::bail!("vault already initialized (vault-id exists); refusing to overwrite");
    }
    let identity = Identity::generate();
    identity.save(identity_path).context("save identity")?;
    // Opening the store materializes the vault directory + peers/oplog files.
    Store::open(vault, identity.clone()).context("open vault store")?;
    let vault_id = VaultId::generate();
    save_vault_id(vault, &vault_id)?;
    println!("initialized vault at {}", vault.display());
    println!("peer_id: {}", identity.peer_id());
    Ok(())
}

async fn pair_token(vault: &Path, identity_path: &Path) -> Result<()> {
    let identity = Identity::load(identity_path).context("load identity")?;
    let vault_id = load_vault_id(vault)?;
    let mut store = Store::open(vault, identity.clone()).context("open vault store")?;

    let (token, host) = host_pairing(&identity, vault_id, &mut store)
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

    join_pairing(identity, vault.to_path_buf(), token)
        .await
        .context("join pairing")?;
    save_vault_id(vault, &vault_id)?;
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
    spawn_backend_sync(&engine, backend);
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
fn spawn_backend_sync(engine: &Arc<Engine<IrohTransport>>, backend: Option<String>) {
    let Some(backend_url) = backend else {
        return;
    };
    use roam_backend_client::crypto::VaultKey;
    use roam_backend_client::http::HttpBackend;
    use roam_backend_client::sync::reconcile_once;

    // TODO(pairing slice): replace with the vault key delivered over the
    // proven pairing stream. For now, derive deterministically from the vault
    // id so a single vault's devices agree on bucket/entry ids.
    let vault_key = VaultKey(blake3::hash(engine.vault_id_bytes().as_slice()).into());
    let backend = Arc::new(HttpBackend::new(&backend_url));
    let store = engine.store();

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            if let Err(err) = reconcile_once(&store, &backend, &vault_key).await {
                eprintln!("backend sync error: {err}");
            }
        }
    });
    println!("backend sync enabled: {backend_url}");
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

    println!("syncing {} active peer(s)...", active.len());
    for peer in &active {
        match engine.connect(*peer).await {
            Ok(()) => println!("connected to peer {peer}"),
            Err(e) => println!("connect to peer {peer} failed: {e}"),
        }
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

    println!(
        "watching {} for changes; Ctrl-C to stop.",
        folder.display()
    );
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    // Self-healing reconnect: a peer unreachable at startup (discovery lag, the
    // other side not up yet) or a connection that later drops is retried here.
    // `reconnect_active` re-dials + re-offers every active peer; it is a cheap
    // no-op for a live connection and reconnects an evicted/dead one.
    let mut reconnect = tokio::time::interval(Duration::from_secs(5));
    // Skip the immediate first tick: setup_engine already connected once.
    reconnect.reset();

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
            // Periodic self-healing reconnect to any active peer (see above).
            _ = reconnect.tick() => {
                roam_sync_core::dlog!("cli: reconnect tick");
                engine.reconnect_active().await;
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
    match run_scan(engine, bridge, hint).await {
        Ok(outcomes) => {
            report_scan(&outcomes);
            if outcomes.iter().any(|(_, outcome)| outcome.changed) {
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
    let mut lines: Option<Lines<BufReader<Stdin>>> = Some(BufReader::new(tokio::io::stdin()).lines());
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

async fn status(vault: &Path) -> Result<()> {
    // Read-only inspection still needs an identity to open the store; a status
    // peek should not mint a durable one, so use an ephemeral generated id. The
    // roster + doc are shared vault state and read back regardless of which
    // identity opens them.
    let store = Store::open(vault, Identity::generate()).context("open vault store")?;
    let roster = store.roster();
    println!("roster ({} peer(s)):", roster.len());
    for peer in &roster {
        let status = match peer.status {
            PeerStatus::Active => "active",
            PeerStatus::Revoked => "revoked",
        };
        println!("  peer {} [{}]", peer.peer_id, status);
    }
    println!("note: {} bytes", store.text("note").len());
    println!("doc version: {} bytes", store.doc_version_bytes().len());
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
