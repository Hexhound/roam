//! `roam` — a manual harness CLI for driving roam-sync over real iroh.
//!
//! This is an operator tool, not a product surface: it wires the storage,
//! sync-engine, and iroh-transport crates together so two vaults can be paired
//! and synced by hand. Each subcommand is a small `async fn`; there are no unit
//! tests here (see `crates/roam-transport-iroh/tests/e2e.rs` for the automated
//! two-endpoint check).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use roam_storage::{Identity, PeerStatus, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_transport_iroh::{host_pairing, join_pairing, IrohTransport, PairingToken};
use tokio::io::{AsyncBufReadExt, BufReader};

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
        Command::Sync { vault, identity } => sync(&vault, &identity).await,
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

async fn sync(vault: &Path, identity_path: &Path) -> Result<()> {
    let identity = Identity::load(identity_path).context("load identity")?;
    let vault_id = load_vault_id(vault)?;
    let store = Store::open(vault, identity.clone()).context("open vault store")?;

    // Build iroh routes + the connect list from the active roster before the
    // store is moved into the engine.
    let active: Vec<u64> = store
        .roster()
        .into_iter()
        .filter(|p| p.status == PeerStatus::Active)
        .map(|p| p.peer_id)
        .collect();
    let routes: HashMap<u64, [u8; 32]> = store
        .roster()
        .into_iter()
        .filter(|p| p.status == PeerStatus::Active)
        .map(|p| (p.peer_id, p.verifying_key))
        .collect();

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
    println!("running; press Ctrl-C to stop.");

    // Print a heartbeat of the document state as frames flow, until Ctrl-C.
    let mut ticker = tokio::time::interval(Duration::from_secs(3));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nstopping.");
                return Ok(());
            }
            _ = ticker.tick() => {
                let text = engine.store().lock().await.text("note");
                println!("note len={} bytes", text.len());
            }
        }
    }
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
