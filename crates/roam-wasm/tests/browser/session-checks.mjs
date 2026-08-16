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
  /// `relayUrl` defaults to an address nothing listens on, because no check
  /// syncs — except the pairing one, whose host mints an invite naming this
  /// relay and would otherwise send the joiner to a dead port.
  constructor(key, relayUrl = RELAY_URL) {
    this.key = key;
    this.relayUrl = relayUrl;
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
      // A message carrying neither `ok` nor `error` is progress, not a reply —
      // `hostInvite`'s invite and code. The request stays pending.
      if (data.ok === undefined && data.error === undefined) {
        settle.onProgress?.(data);
        return;
      }
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
  ///
  /// `onProgress` exists for `hostInvite` alone, which speaks twice: once with
  /// the invite and code — inputs the joiner needs before this request can
  /// finish — and once with the reply.
  sendRaw(request, transfer = [], onProgress = null) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, onProgress });
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
      relayUrl: this.relayUrl,
    });
  }

  terminate() {
    this.worker.terminate();
  }
}

/// The joining device: the same shipped worker, driven through an iframe on a
/// second origin.
///
/// The second origin is not incidental — see `joiner.html`. Host and joiner end
/// up sharing a vault key, hence a bucket id, hence a pool directory, and one
/// origin cannot hold both.
class RemoteClient {
  constructor(frame) {
    this.frame = frame;
    this.pending = new Map();
    this.nextId = 1;
    this.onMessage = ({ data }) => {
      if (data?.ready) return;
      const settle = this.pending.get(data.id);
      if (!settle) return;
      if (data.ok === undefined && data.error === undefined) {
        settle.onProgress?.(data);
        return;
      }
      this.pending.delete(data.id);
      if (data.error !== undefined) settle.reject(new Error(data.error));
      else settle.resolve(data);
    };
    window.addEventListener('message', this.onMessage);
  }

  /// Load the frame and wait for it to say its script is running. Posting
  /// before that point silently goes nowhere.
  static async open() {
    const frame = document.createElement('iframe');
    const ready = new Promise((resolve) => {
      const listen = ({ data }) => {
        if (data?.ready) {
          window.removeEventListener('message', listen);
          resolve();
        }
      };
      window.addEventListener('message', listen);
    });
    // `localhost` rather than `127.0.0.1`: the same server, a different origin.
    frame.src = `http://localhost:${location.port}/joiner.html`;
    document.body.appendChild(frame);
    await ready;
    return new RemoteClient(frame);
  }

  sendRaw(request, onProgress = null) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, onProgress });
      this.frame.contentWindow.postMessage({ ...request, id }, '*');
    });
  }

  send(request) {
    return this.sendRaw(request).then((reply) => reply.ok);
  }

  close() {
    window.removeEventListener('message', this.onMessage);
    this.frame.remove();
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
    'two browser devices pair over a relay mailbox, and the joiner keeps its vault',
    async (key) => {
      // The check this whole harness exists for. Everything about the mailbox
      // handshake is covered natively in `roam-pairing`; what is not, and can
      // only be checked here, is the ORDER a browser joiner has to work in: the
      // pool it stores into is named after the bucket id, the bucket id comes
      // from the vault key, and the vault key arrives inside the accept. So the
      // handshake completes before there is anywhere to put a store — and
      // whether that mount then actually lands is a browser question.
      // The host's relay is this harness's own server, which serves the
      // mailbox routes as well as the files. The invite the host mints names
      // it, so the joiner reaches the same mailbox from its own origin.
      const host = new Client(key, location.origin);
      const joiner = await RemoteClient.open();
      try {
        await host.open();
        await host.send({
          command: 'setEntry',
          container: 'meta',
          key: 'title',
          value: 'hosted in a tab',
        });

        await joiner.send({ control: 'newWorker' });

        // The invite and code arrive on a progress message, which is what lets
        // the joiner start at all: the host is still waiting at this point.
        let handOver;
        const credentials = new Promise((resolve) => (handOver = resolve));
        const enrolled = host.sendRaw(
          { type: 'hostInvite', role: 'writer', seconds: 60 },
          [],
          ({ invite, code }) => handOver({ invite, code })
        );

        const { invite, code } = await credentials;
        expect(
          typeof invite === 'string' && /^\d{6}$/.test(code),
          `the host produced invite=${typeof invite} code=${JSON.stringify(code)}`
        );

        const joined = await joiner.send({
          type: 'join',
          modulePath: `http://localhost:${location.port}${MODULE_PATH}`,
          invite,
          code,
        });
        const enrolledPeer = await enrolled.then((reply) => reply.ok);

        expect(
          joined.peerId === enrolledPeer,
          `the host enrolled ${enrolledPeer} but the joiner is ${joined.peerId}`
        );
        // Same bucket means the mount was named from the key the accept
        // carried. A joiner that got this wrong would store its vault where
        // nothing else will ever look, and look like it worked.
        expect(
          joined.bucketId === (await host.send({ command: 'bucketId' })),
          `joiner addresses ${joined.bucketId}, host does not`
        );
        expect(
          joined.vaultKey?.length === 32,
          `the joiner came away with ${joined.vaultKey?.length} key bytes`
        );

        // And the vault it just created is durable. This is the half a native
        // test structurally cannot reach: terminate the worker, mount the pool
        // again from a second one, and see the same device.
        const vaultKey = Array.from(joined.vaultKey);
        await joiner.send({ control: 'newWorker' });
        const reopened = await joiner.send({
          type: 'open',
          modulePath: `http://localhost:${location.port}${MODULE_PATH}`,
          vaultKey,
          relayUrl: location.origin,
        });
        expect(
          reopened.peerId === joined.peerId,
          `the joined vault reopened as a different device: ${joined.peerId} -> ${reopened.peerId}`
        );
        expect(
          reopened.bucketId === joined.bucketId,
          'the reopened vault addresses a different bucket'
        );

        return `admitted ${joined.peerId}, durable across a remount`;
      } finally {
        await joiner.send({ control: 'terminate' }).catch(() => {});
        joiner.close();
        host.terminate();
      }
    },
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
