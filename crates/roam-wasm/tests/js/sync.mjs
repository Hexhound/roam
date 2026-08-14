// M3 acceptance: two browser vaults converge over REAL HTTP, in a JS runtime.
//
// What this proves that the native tests (`tests/vault_sync.rs`) cannot:
//
//   1. The client's `fetch` transport works — the wasm build talks HTTP through
//      the host's global `fetch`, over a real TCP socket, with no reqwest/rustls
//      native stack anywhere.
//   2. Nothing in the sync path traps at runtime on wasm32. `cargo check`
//      cannot see this class of bug: `SystemTime::now()` compiles fine for
//      wasm32 and then dies with `RuntimeError: unreachable` the first time a
//      history marker is written. Only executing it catches that.
//
// The server side uses `TestRelay` (the already-tested `MemoryBackend`) rather
// than a hand-written JS reimplementation of negentropy — see `src/relay.rs`.
// The production Elixir backend is covered separately by
// `roam-backend-client/tests/e2e_backend.rs`.

import { createServer } from "node:http";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const wasm = require(path.join(here, "..", "..", "pkg", "roam_wasm.js"));

const VAULT_KEY = new Uint8Array(32).fill(7);
const TEXT_ID = "notes/hello.md";

// --- the relay, served over a real socket -----------------------------------

const relay = new wasm.TestRelay();

// Routes mirror the real backend's spec §5 table, which is what `HttpBackend`
// builds its URLs against.
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    const parts = url.pathname.split("/").filter(Boolean); // b/:bucket/:what/...
    assert.equal(parts[0], "b", `unexpected route ${url.pathname}`);
    const bucket = parts[1];
    const what = parts[2];

    if (what === "manifest") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(await relay.manifest(bucket));
      return;
    }

    const body = Buffer.concat(await collect(req));

    if (what === "reconcile") {
      const reply = await relay.reconcile(bucket, parts[3], body);
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(Buffer.from(reply));
      return;
    }

    // entries | blobs | snapshots
    const id = decodeURIComponent(parts[3]);
    if (req.method === "GET") {
      const found = await relay.get(bucket, what, id);
      if (found === undefined) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(Buffer.from(found));
      return;
    }
    if (req.method === "PUT") {
      const created = await relay.put(bucket, what, id, body);
      // 409 on a duplicate id is what `PutOutcome::Exists` reads as.
      res.writeHead(created ? 201 : 409).end();
      return;
    }
    res.writeHead(405).end();
  } catch (err) {
    // Never let a harness bug masquerade as a client-side sync failure.
    console.error("relay error:", err);
    res.writeHead(500).end(String(err));
  }
});

async function collect(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  return chunks;
}

const baseUrl = await new Promise((resolve) => {
  server.listen(0, "127.0.0.1", () =>
    resolve(`http://127.0.0.1:${server.address().port}`),
  );
});

// --- the test ---------------------------------------------------------------

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (err) {
    failures++;
    console.error(`FAIL  ${name}\n      ${err.message}`);
  }
}

console.log(`relay listening on ${baseUrl}`);

const a = new wasm.Vault(VAULT_KEY);
const b = new wasm.Vault(VAULT_KEY);

// Introduce the devices, as pairing does natively.
await a.addPeer(await b.peerId(), await b.verifyingKey());
await b.addPeer(await a.peerId(), await a.verifyingKey());

await a.setEntry("files", "k", "v1");
await a.editText(TEXT_ID, 0, "hello from the browser");

await check("a vault syncs to the relay over fetch", async () => {
  await a.sync(baseUrl);
  const bucket = wasm.bucketId(VAULT_KEY);
  const count = await relay.entryCount(bucket);
  assert.ok(count > 0, "the relay received nothing, so the rest is vacuous");
});

await check("a second vault converges through the relay alone", async () => {
  await b.sync(baseUrl);
  assert.equal(await b.getEntry("files", "k"), "v1");
  assert.equal(await b.text(TEXT_ID), "hello from the browser");
});

await check("edits flow back the other way", async () => {
  await b.editText(TEXT_ID, 0, "B says: ");
  await b.sync(baseUrl);
  await a.sync(baseUrl);
  assert.equal(await a.text(TEXT_ID), "B says: hello from the browser");
});

// This is the check that exercises the wall clock. `write_snapshot` stamps a
// history marker, and `SystemTime::now()` traps on wasm32 (`RuntimeError:
// unreachable`) instead of returning something wrong — a failure mode no
// `cargo check` and no native test can reach. Removing this check makes the
// `wallclock` shim untested; it was added precisely because the rest of the
// harness did not catch a deliberately reintroduced trap.
await check("writing a checkpoint reads the clock without trapping", async () => {
  await a.writeSnapshot();
  assert.equal(await a.text(TEXT_ID), "B says: hello from the browser");
});

await check("the relay never holds plaintext", async () => {
  const bucket = wasm.bucketId(VAULT_KEY);
  const manifest = JSON.parse(await relay.manifest(bucket));
  assert.ok(manifest.entry_ids.length > 0);
  for (const id of manifest.entry_ids) {
    const ct = Buffer.from(await relay.get(bucket, "entries", id));
    assert.ok(
      !ct.includes(Buffer.from("hello from the browser")),
      "plaintext found in a payload the relay stores",
    );
    // The bucket and ids are derived through the vault key, so they leak
    // neither the container name nor the document name.
    assert.ok(!id.includes("notes") && !bucket.includes("notes"));
  }
});

await check("a vault without the key learns nothing", async () => {
  const intruder = new wasm.Vault(new Uint8Array(32).fill(9));
  await intruder.sync(baseUrl);
  assert.equal(await intruder.text(TEXT_ID), "");
});

server.close();
console.log(failures === 0 ? "\nsync.mjs: all checks passed" : `\nsync.mjs: ${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
