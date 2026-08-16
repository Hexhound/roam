// Drives `worker/roam-worker.js` the way a page actually would.
//
// The Rust side of the protocol is already covered natively by
// `tests/session.rs`, so nothing here re-tests what a command means. These
// checks cover only what needs a browser:
//
//   * that the shipped worker file loads, initialises the wasm module, and
//     mounts OPFS at all,
//   * that a **terminated** worker releases its sync access handles, which is
//     the one thing standing between "reload the tab" and a vault that is
//     permanently locked by `NoModificationAllowedError`,
//   * that a vault opened by a later worker is the same vault, seen by the same
//     device.
//
// Runs on the page, not in a worker: the page is where a real app lives, and
// none of this touches OPFS directly.

const WORKER_URL = '/worker/roam-worker.js';
const MODULE_PATH = '/pkg/roam_wasm.js';
const RELAY_URL = 'http://127.0.0.1:1/unused';
const TEXT_ID = 'notes/hello.md';

// The pool directory is derived from the vault key, so the key decides which
// vault a worker opens. Each check therefore gets its OWN key: sharing one made
// the checks share a vault, and since they all insert text at position 0 their
// writes interleaved into a single string. Durability made the checks couple to
// each other, which is exactly the failure mode a durable backend introduces
// and `MemFs` never could.
const vaultKey = (nth) => Array.from({ length: 32 }, (_, i) => (i * 7 + nth) & 0xff);

/// A worker plus a promise-per-request, so checks read as ordinary awaits.
class Client {
  constructor(key) {
    this.key = key;
    this.worker = new Worker(WORKER_URL, { type: 'module' });
    this.pending = new Map();
    this.panics = [];
    this.nextId = 1;

    this.worker.onmessage = ({ data }) => {
      if (data.panic !== undefined) {
        this.panics.push(data.panic);
        return;
      }
      const settle = this.pending.get(data.id);
      if (!settle) return;
      this.pending.delete(data.id);
      if (data.error !== undefined) settle.reject(new Error(data.error));
      else settle.resolve(data);
    };
    // A worker that dies takes every in-flight reply with it. Fail the pending
    // requests loudly rather than letting the run hang to its timeout.
    this.worker.onerror = (e) => {
      const why = new Error(
        `worker crashed: ${e.message}` +
          this.panics.map((p) => `\n      ${p}`).join('')
      );
      for (const settle of this.pending.values()) settle.reject(why);
      this.pending.clear();
    };
  }

  /// The whole reply message, for the checks that care about `bytes` or
  /// `changes` and not just `ok`.
  sendRaw(request, transfer = []) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ ...request, id }, transfer);
    });
  }

  send(request) {
    return this.sendRaw(request).then((reply) => reply.ok);
  }

  open() {
    return this.sendRaw({
      type: 'open',
      modulePath: MODULE_PATH,
      vaultKey: this.key,
      relayUrl: RELAY_URL,
    });
  }

  terminate() {
    this.worker.terminate();
  }
}

/// Open a worker on `key`'s vault, run `body`, and always terminate it — a
/// leaked worker keeps its OPFS handles, and the next mount of the same vault
/// would then fail with `NoModificationAllowedError` for a reason that has
/// nothing to do with what it was testing.
const withWorker = async (key, body) => {
  const client = new Client(key);
  try {
    // The open reply is passed through rather than dropped: it carries the ids
    // a caller caches, and opening a second time would remount a pool whose
    // handles are still held — `NoModificationAllowedError`, not a fresh start.
    const opened = await client.open();
    return await body(client, opened);
  } finally {
    client.terminate();
  }
};

const expect = (condition, message) => {
  if (!condition) throw new Error(message);
};

const checks = [
  [
    'a worker opens a vault on OPFS and reads back what it wrote',
    async (key) =>
      withWorker(key, async (client) => {
        await client.send({
          command: 'setEntry',
          container: 'meta',
          key: 'title',
          value: 'Hello',
        });
        await client.send({
          command: 'editText',
          textId: TEXT_ID,
          at: 0,
          text: 'written in a worker',
        });

        const title = await client.send({
          command: 'getEntry',
          container: 'meta',
          key: 'title',
        });
        expect(title === 'Hello', `entry read back as ${JSON.stringify(title)}`);

        const peerId = await client.send({ command: 'peerId' });
        expect(typeof peerId === 'string', 'peerId must cross as a string');
        return `peer ${peerId}`;
      }),
  ],

  [
    'a terminated worker releases its OPFS handles',
    async (key) => {
      // The check that a tab close is survivable. `terminate()` does NOT run
      // Rust's `Drop`, so nothing calls `close()` on any sync access handle —
      // the browser has to release them when it tears the agent down. If it did
      // not, this second mount would fail with `NoModificationAllowedError` and
      // the vault would be unopenable until the browser reaped the worker.
      const first = new Client(key);
      await first.open();
      await first.send({
        command: 'editText',
        textId: TEXT_ID,
        at: 0,
        text: 'before the tab closed',
      });
      first.terminate();

      return withWorker(key, async () => 'remounted after an abrupt terminate');
    },
  ],

  [
    'the vault outlives the worker that created it',
    async (key) => {
      const before = await withWorker(key, async (client) => {
        await client.send({
          command: 'editText',
          textId: TEXT_ID,
          at: 0,
          text: 'persisted',
        });
        await client.send({ command: 'writeSnapshot' });
        return client.send({ command: 'peerId' });
      });

      return withWorker(key, async (client) => {
        const text = await client.send({ command: 'text', textId: TEXT_ID });
        expect(
          text === 'persisted',
          `text came back as ${JSON.stringify(text)}`
        );
        const after = await client.send({ command: 'peerId' });
        expect(
          after === before,
          `identity changed across the reopen: ${before} -> ${after}`
        );
        return `same device (${after}) and same text`;
      });
    },
  ],

  [
    'overlapping commands are serialized, not raced',
    async (key) =>
      withWorker(key, async (client) => {
        // Fired without awaiting in between, which is what a UI does. The
        // worker's queue is what stops two pool top-ups opening the same slot
        // index and colliding on OPFS exclusivity.
        const writes = Array.from({ length: 24 }, (_, i) =>
          client.send({
            command: 'setEntry',
            container: 'meta',
            key: `k${i}`,
            value: `v${i}`,
          })
        );
        await Promise.all(writes);

        for (let i = 0; i < 24; i++) {
          const value = await client.send({
            command: 'getEntry',
            container: 'meta',
            key: `k${i}`,
          });
          expect(value === `v${i}`, `k${i} read back as ${JSON.stringify(value)}`);
        }
        return '24 concurrent writes, all landed';
      }),
  ],

  [
    'blob bytes cross the boundary as transferables, intact and durable',
    async (key) => {
      // Non-UTF-8 on purpose, and big enough that a transfer is worth making:
      // anything that quietly routed these through JSON or through a string
      // would corrupt them here rather than in someone's attachment.
      const payload = new Uint8Array(1 << 20);
      for (let i = 0; i < payload.length; i++) payload[i] = (i * 31 + 7) & 0xff;

      const hash = await withWorker(key, async (client) => {
        // `payload.buffer` is handed over, not copied — after this the page's
        // view is detached, which is the observable proof the transfer happened
        // rather than a structured clone.
        const put = await client.sendRaw(
          { command: 'putBlob', bytes: payload },
          [payload.buffer]
        );
        expect(
          payload.byteLength === 0,
          'the payload was copied, not transferred — its buffer is still attached'
        );
        return put.ok;
      });

      // A second worker, so this also proves the bytes reached OPFS rather than
      // living in the first session's memory.
      return withWorker(key, async (client) => {
        const got = await client.sendRaw({ command: 'getBlob', hash });
        expect(got.ok?.len === 1 << 20, `got back ${JSON.stringify(got.ok)}`);
        expect(
          got.bytes instanceof Uint8Array,
          `reply bytes arrived as ${got.bytes?.constructor?.name}`
        );
        for (let i = 0; i < got.bytes.length; i++) {
          expect(
            got.bytes[i] === ((i * 31 + 7) & 0xff),
            `byte ${i} came back as ${got.bytes[i]}`
          );
        }
        return `1 MiB round-tripped through OPFS as ${hash.slice(0, 12)}…`;
      });
    },
  ],

  [
    'open reports the ids a caller has to hold synchronously',
    async (key) =>
      withWorker(key, async (client, opened) => {
        // `bucketId` is a plain getter on the Dart port, so it cannot become a
        // Future just because this platform computes it in another agent. It is
        // fixed for the session, so `open` hands it over once.
        expect(
          typeof opened.ok?.bucketId === 'string' && opened.ok.bucketId.length > 0,
          `open gave no bucketId: ${JSON.stringify(opened.ok)}`
        );
        const asked = await client.send({ command: 'bucketId' });
        expect(
          asked === opened.ok.bucketId,
          `open said ${opened.ok.bucketId}, the command says ${asked}`
        );

        // And a write reports what it changed on its own reply — the reason
        // there is no separate push channel.
        const wrote = await client.sendRaw({
          command: 'setEntry',
          container: 'meta',
          key: 'title',
          value: 'Hi',
        });
        expect(
          JSON.stringify(wrote.changes) ===
            JSON.stringify([{ container: 'meta', key: 'title', value: 'Hi' }]),
          `changes came back as ${JSON.stringify(wrote.changes)}`
        );
        return `bucket ${opened.ok.bucketId.slice(0, 12)}…`;
      }),
  ],

  [
    'a failing command rejects without killing the worker',
    async (key) =>
      withWorker(key, async (client) => {
        let rejected = false;
        try {
          await client.send({ command: 'noSuchCommand' });
        } catch {
          rejected = true;
        }
        expect(rejected, 'an unknown command resolved instead of rejecting');

        // The point of the check: the session is still usable afterwards.
        const peerId = await client.send({ command: 'peerId' });
        expect(typeof peerId === 'string', 'the worker stopped answering');
        return 'still answering afterwards';
      }),
  ],
];

export const runSessionChecks = async () => {
  const results = [];
  let failed = 0;

  for (const [index, [name, check]] of checks.entries()) {
    try {
      const detail = await check(vaultKey(index + 1));
      results.push(`ok    ${name}${detail ? ' — ' + detail : ''}`);
    } catch (e) {
      failed++;
      results.push(`FAIL  ${name}: ${e.message ?? e}`);
    }
  }

  return { failed, results };
};
