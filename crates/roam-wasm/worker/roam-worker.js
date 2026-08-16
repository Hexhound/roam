// The Web Worker that hosts roam in a browser.
//
// This file is a shipped artifact, not test scaffolding. It exists because roam
// *cannot* run on a page's main thread: OPFS sync access handles are absent
// there — the property is `undefined`, so it is not a permission that can be
// granted (measured in Chromium 150 and 151; see
// `docs/browser_storage_opfs.md`). Storage is what forces the worker, and the
// worker is what forces a message protocol.
//
// It deliberately holds no logic. Every decision about what a command means
// lives in `roam_wasm::session`, which is plain Rust and covered by
// `tests/session.rs` — because anything implemented here could only ever be
// tested in a browser. What is left below is transport: parse, forward,
// serialize, reply.
//
// Protocol, page -> worker:
//
//   { id, type: 'open', modulePath, vaultKey: [32 bytes], relayUrl }
//   { id, type: 'join', modulePath, invite, code }       // pair into a vault
//   { id, command: 'setEntry', container, key, value }   // any session command
//   { id, command: 'putBlob', bytes: Uint8Array }        // binary rides beside
//
// and worker -> page, always exactly one reply per request:
//
//   { id, ok: <value>, changes?: [...], bytes?: Uint8Array } | { id, error: '…' }
//
// `bytes` never goes through JSON: attachments are megabytes, and base64 would
// cost a third more of them plus two parses of data that is opaque anyway. It
// travels as a transferable instead, so the buffer is moved rather than copied.
//
// `changes` is the map delta this command produced, absent when empty. There is
// no separate push channel because nothing changes a vault except a command —
// a local edit is one, and pulling a peer's ops is `sync`.
//
// A worker -> page message with no `id` is unsolicited: `{ panic }`.

let session = null;

// Panic text has to reach the page the instant it is produced. A wasm32 panic
// is an ABORT: it kills this worker outright, so nothing accumulated here
// survives to be reported, and every in-flight reply is lost with it. The Rust
// panic hook writes the message to console.error just before the trap, which is
// the only moment the text exists anywhere.
const realConsoleError = console.error.bind(console);
console.error = (...args) => {
  self.postMessage({ panic: args.join(' ') });
  realConsoleError(...args);
};

// Commands run strictly one at a time.
//
// This is not throughput caution, it is correctness: `Session.handle` tops the
// slot pool up before dispatching, and topping up reads the pool's capacity and
// then awaits `createSyncAccessHandle`. Two overlapping calls would both read
// the same capacity and both try to open the same slot index — and OPFS
// enforces exclusivity, so the second fails with `NoModificationAllowedError`.
// The queue is here rather than in Rust because this is where requests arrive;
// `Session.handle` documents that it must not be called re-entrantly.
let queue = Promise.resolve();

const enqueue = (work) => {
  const result = queue.then(work);
  // Keep the chain alive: an unhandled rejection would poison every later
  // command, turning one failure into a permanently dead worker.
  queue = result.catch(() => {});
  return result;
};

// Answers with the two identifiers a caller needs to have on hand
// *synchronously* afterwards. The bucket id in particular: on the Dart side it
// is a plain getter on the port, and it cannot become a Future just because one
// platform computes it in another agent. Both are fixed for the life of the
// session, so the caller caches them here and never asks again.
const identifiers = async () => {
  const ask = async (command) => {
    const reply = JSON.parse(await session.handle(JSON.stringify({ command })));
    if (reply.error) throw new Error(reply.error);
    return reply.ok;
  };
  return { bucketId: await ask('bucketId'), peerId: await ask('peerId') };
};

// Imported dynamically so the page decides where the wasm bundle lives: Flutter
// web serves assets from a path that is not known at build time here.
const loadWasm = async (modulePath) => {
  const wasm = await import(modulePath);
  await wasm.default();
  return wasm;
};

const open = async ({ modulePath, vaultKey, relayUrl }) => {
  const wasm = await loadWasm(modulePath);
  session = await wasm.Session.openOnOpfs(new Uint8Array(vaultKey), relayUrl);
  return identifiers();
};

// Pair into somebody else's vault. This is the only way a browser gets INTO a
// vault: it has no UDP socket, so it can never be an iroh peer, and both other
// pairing flows require being dialled.
//
// The reply carries `vaultKey`, which `open` does not, because the direction is
// reversed — a founder passes the key in, a joiner does not have it until the
// handshake succeeds. The page MUST keep it, or the next load cannot reopen the
// vault this just joined; and it is the entire vault, so the security note on
// `Session` applies to it in full. It is sent as a transferable, so the worker's
// own copy is detached rather than lingering in a second heap.
const join = async ({ modulePath, invite, code }) => {
  const wasm = await loadWasm(modulePath);
  session = await wasm.Session.joinOnOpfs(invite, code);
  return { ...(await identifiers()), vaultKey: session.vaultKey() };
};

self.onmessage = (event) => {
  const request = event.data;
  const id = request?.id ?? null;

  enqueue(async () => {
    try {
      if (request?.type === 'open') {
        self.postMessage({ id, ok: await open(request) });
        return;
      }
      if (request?.type === 'join') {
        const ok = await join(request);
        // The vault key moves rather than being copied, so the worker is not
        // left holding a second reachable copy of the whole vault.
        self.postMessage({ id, ok }, [ok.vaultKey.buffer]);
        return;
      }
      if (session === null) {
        throw new Error("send { type: 'open' } or { type: 'join' } before any command");
      }

      // `bytes` is the one field that must not reach the JSON encoder — strip
      // it out and hand it over as a payload instead.
      const { bytes, ...envelope } = request;
      const json = await session.handleWithBytes(
        JSON.stringify(envelope),
        bytes ? new Uint8Array(bytes) : undefined,
      );

      // Already a JSON envelope carrying this id; parse it back so the page
      // gets structured data rather than a string.
      const reply = JSON.parse(json);
      const replyBytes = session.takeReplyBytes();
      if (replyBytes === undefined) {
        self.postMessage(reply);
      } else {
        // Transferred, not copied. Safe because Rust already handed ownership
        // of a fresh buffer over — nothing on this side reads it again.
        reply.bytes = replyBytes;
        self.postMessage(reply, [replyBytes.buffer]);
      }
    } catch (e) {
      // Never leave a request unanswered. A page awaiting a promise that never
      // settles has no timeout and no error to show — strictly worse than a
      // failure it can report.
      self.postMessage({ id, error: String(e?.message ?? e) });
    }
  });
};
