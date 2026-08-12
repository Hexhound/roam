//! End-to-end P2P file-transfer benchmark.
//!
//! Stands up two roam devices on ONE host, wires them together over the real
//! iroh transport on loopback (no pairing — roster seeded programmatically,
//! exactly as the `roam-transport-iroh` e2e test does), then measures the
//! wall-clock from "files land on device A" to "byte-identical on device B".
//! That end-to-end number folds in CRDT encode + AEAD + QUIC + decode + disk
//! projection — the latency a user actually feels, not a raw wire figure.
//!
//! LOOPBACK CAVEAT: this measures OUR stack's overhead on a single warm host,
//! not internet/LAN throughput. Treat it as a floor (best case), not a promise.
//!
//! BLOBS: the sync engine transfers a blob as a stream of offset-tagged
//! `BlobChunk` frames (`BLOB_CHUNK_SIZE`, `engine.rs`) reassembled and
//! full-hash-verified by the receiver, so blob size is unbounded by the wire.
//!
//! Run: `cargo run -j 1 --release -p roam-cli --bin roam-bench`
//! (release matters — debug AEAD/CRDT is far slower and not representative.)

use roam_files::FolderBridge;
use roam_storage::{Identity, Role, Store, VaultId};
use roam_sync_core::engine::Engine;
use roam_transport_iroh::IrohTransport;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Runs per scenario; report the median (with min/max) to blunt one-off noise.
const RUNS_PER_SCENARIO: usize = 3;
/// Give up on a run that hasn't converged by here — a stuck transfer (e.g. a
/// blob over the frame cap) must fail loudly, never hang or report a bogus 0.
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(180);
/// How often to re-project device B and re-check for byte-identity. Blob
/// transfer is a multi-step Have/Want/Data exchange, so we poll rather than
/// trust a single change notification.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// One file to plant in device A's vault: relative name + exact bytes.
struct FileSpec {
    name: String,
    bytes: Vec<u8>,
}

struct Scenario {
    name: &'static str,
    note: &'static str,
    files: Vec<FileSpec>,
}

/// Deterministic, incompressible-ish payload from a seeded LCG. Compressible
/// zeros would make AEAD + transfer look artificially fast, so we fill with
/// pseudo-random bytes. `text` maps every byte into printable ASCII so the file
/// is valid UTF-8 (bridge classifies it as a Text/CRDT entry); otherwise we
/// force a lone `0xFF` so the file is invalid UTF-8 and takes the Blob path.
fn payload(len: usize, seed: u64, text: bool) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        // Numerical Recipes LCG constants.
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let byte = (state >> 33) as u8;
        if text {
            // Map into printable ASCII [33, 126] — always valid UTF-8.
            out.push(33 + (byte % 94));
        } else {
            out.push(byte);
        }
    }
    if !text && len >= 2 {
        // Guarantee invalid UTF-8 → Blob path, regardless of LCG output.
        out[0] = 0xFF;
        out[1] = 0xFF;
    }
    out
}

fn text_scenario_many() -> Scenario {
    let files = (0..1000)
        .map(|i| FileSpec {
            name: format!("note-{i:04}.md"),
            bytes: payload(4 * 1024, 0xA000 + i as u64, true),
        })
        .collect();
    Scenario {
        name: "1000 x 4 KB text",
        note: "per-file / per-op overhead (CRDT text path)",
        files,
    }
}

fn blob_scenario_large() -> Scenario {
    Scenario {
        name: "1 x 50 MiB blob",
        note: "binary throughput ceiling (chunked blob path)",
        files: vec![FileSpec {
            name: "big.bin".to_string(),
            bytes: payload(50 * 1024 * 1024, 0xB10B, false),
        }],
    }
}

fn mixed_scenario() -> Scenario {
    let mut files = vec![FileSpec {
        name: "media.bin".to_string(),
        bytes: payload(20 * 1024 * 1024, 0xB0BB1E, false),
    }];
    for i in 0..200 {
        files.push(FileSpec {
            name: format!("doc-{i:03}.md"),
            bytes: payload(4 * 1024, 0xC000 + i as u64, true),
        });
    }
    Scenario {
        name: "mixed (1x20 MiB blob + 200x4 KB text)",
        note: "realistic vault",
        files,
    }
}

/// Unique scratch dir under the system temp dir. `tempfile` is only a
/// dev-dependency (unavailable to a bin), so we roll our own with pid + a
/// monotonic counter + wall-clock nanos to avoid collisions across runs.
fn scratch(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "roam-bench-{}-{}-{}-{}",
        std::process::id(),
        tag,
        n,
        nanos
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// True when every expected file exists under `dir` with byte-identical
/// content. This is the convergence gate: a fast-but-wrong transfer is not a
/// valid measurement.
fn all_converged(dir: &Path, files: &[FileSpec]) -> bool {
    files.iter().all(|f| {
        std::fs::read(dir.join(&f.name))
            .map(|got| got == f.bytes)
            .unwrap_or(false)
    })
}

struct RunResult {
    wall: Duration,
    bytes: u64,
    n_files: usize,
}

/// One full run: fresh identities, stores, transports, engines, and vault dirs;
/// plant the scenario's files on A; measure until B is byte-identical.
async fn run_once(scenario: &Scenario) -> anyhow::Result<RunResult> {
    // --- Per-device scratch: store dir, vault dir, and store-owned meta dir. ---
    let store_a_dir = scratch("store-a");
    let store_b_dir = scratch("store-b");
    let vault_a = scratch("vault-a");
    let vault_b = scratch("vault-b");
    let meta_a = scratch("meta-a");
    let meta_b = scratch("meta-b");

    let ia = Identity::generate();
    let ib = Identity::generate();
    let vault = VaultId::generate();

    let mut sa = Store::open(&store_a_dir, ia.clone())?;
    let mut sb = Store::open(&store_b_dir, ib.clone())?;
    // Each device founds its own vault as Admin so its own add_peer vouches fold
    // (mirrors the e2e test — no interactive pairing).
    sa.declare_founder(Role::Admin)?;
    sb.declare_founder(Role::Admin)?;
    sa.add_peer(ib.peer_id(), ib.verifying_key().to_bytes(), Role::Admin)?;
    sb.add_peer(ia.peer_id(), ia.verifying_key().to_bytes(), Role::Admin)?;

    let mut ra = HashMap::new();
    ra.insert(ib.peer_id(), ib.verifying_key().to_bytes());
    let mut rb = HashMap::new();
    rb.insert(ia.peer_id(), ia.verifying_key().to_bytes());
    let ta = IrohTransport::spawn(&ia, ra).await?;
    let tb = IrohTransport::spawn(&ib, rb).await?;
    ta.add_addr(ib.peer_id(), tb.endpoint_addr()).await;
    tb.add_addr(ia.peer_id(), ta.endpoint_addr()).await;

    let ea = Arc::new(Engine::new(ia.clone(), vault, sa, Arc::new(ta), [0u8; 32]));
    let eb = Arc::new(Engine::new(ib.clone(), vault, sb, Arc::new(tb), [0u8; 32]));
    tokio::spawn(ea.clone().run());
    tokio::spawn(eb.clone().run());
    ea.connect(ib.peer_id()).await?;
    eb.connect(ia.peer_id()).await?;

    let bridge_a = FolderBridge::new(&vault_a, &meta_a);
    let bridge_b = FolderBridge::new(&vault_b, &meta_b);

    // Wait for the mesh to be live BEFORE timing — we measure transfer, not dial.
    let connect_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let a_ready = !ea.connected_peers().await.is_empty();
        let b_ready = !eb.connected_peers().await.is_empty();
        if a_ready && b_ready {
            break;
        }
        if Instant::now() > connect_deadline {
            anyhow::bail!("peers never connected");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // Plant every file on device A's disk (NOT timed — raw disk writes aren't
    // "our system"). Timing starts at the import.
    let mut total_bytes = 0u64;
    for f in &scenario.files {
        std::fs::write(vault_a.join(&f.name), &f.bytes)?;
        total_bytes += f.bytes.len() as u64;
    }

    let start = Instant::now();
    // Import A's disk edits into the CRDT, then push to the connected peer.
    {
        let store = ea.store();
        let mut guard = store.lock().await;
        bridge_a.scan(&mut guard)?;
    }
    ea.flush_local().await;

    // Poll device B: pull any blob bytes it lacks (blob transfer is pull-based —
    // learning the entry-ref does NOT auto-fetch the bytes), project received
    // state to disk, then check byte-identity.
    loop {
        eb.request_missing_blobs().await;
        {
            let store = eb.store();
            let mut guard = store.lock().await;
            bridge_b.scan(&mut guard)?;
        }
        if all_converged(&vault_b, &scenario.files) {
            break;
        }
        if start.elapsed() > CONVERGE_TIMEOUT {
            anyhow::bail!(
                "did not converge within {:?} (blob over frame cap? stuck transfer?)",
                CONVERGE_TIMEOUT
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    let wall = start.elapsed();

    // Best-effort cleanup — a failed remove must not fail the bench.
    for d in [
        &store_a_dir, &store_b_dir, &vault_a, &vault_b, &meta_a, &meta_b,
    ] {
        let _ = std::fs::remove_dir_all(d);
    }

    Ok(RunResult {
        wall,
        bytes: total_bytes,
        n_files: scenario.files.len(),
    })
}

fn fmt_mib(bytes: u64) -> String {
    format!("{:.2}", bytes as f64 / (1024.0 * 1024.0))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    println!("roam P2P file-transfer benchmark");
    println!("  path: P2P over iroh, loopback (single host) — measures OUR stack overhead, not internet/LAN");
    println!("  metric: end-to-end convergence — write on A -> byte-identical on B (CRDT + AEAD + QUIC + project)");
    println!("  blobs: chunked transfer (BlobChunk frames, engine.rs), reassembled + hash-verified; size unbounded by the wire");
    println!("  runs/scenario: {RUNS_PER_SCENARIO} (median reported)\n");

    let scenarios = [
        blob_scenario_large(),
        text_scenario_many(),
        mixed_scenario(),
    ];

    println!(
        "{:<40} {:>6} {:>10} {:>10} {:>9} {:>10}",
        "scenario", "files", "MiB", "median_ms", "MiB/s", "files/s"
    );
    println!("{}", "-".repeat(90));

    for scenario in &scenarios {
        let mut wall_ms = Vec::new();
        let mut bytes = 0u64;
        let mut n_files = 0usize;
        for _ in 0..RUNS_PER_SCENARIO {
            let r = run_once(scenario).await?;
            wall_ms.push(r.wall.as_secs_f64() * 1000.0);
            bytes = r.bytes;
            n_files = r.n_files;
        }
        wall_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = wall_ms[wall_ms.len() / 2];
        let min = wall_ms[0];
        let max = wall_ms[wall_ms.len() - 1];
        let secs = median / 1000.0;
        let mib_s = (bytes as f64 / (1024.0 * 1024.0)) / secs;
        let files_s = n_files as f64 / secs;
        println!(
            "{:<40} {:>6} {:>10} {:>10.1} {:>9.1} {:>10.1}",
            scenario.name,
            n_files,
            fmt_mib(bytes),
            median,
            mib_s,
            files_s
        );
        println!(
            "  └ {}  (min {:.1} ms, max {:.1} ms)",
            scenario.note, min, max
        );
    }

    Ok(())
}
