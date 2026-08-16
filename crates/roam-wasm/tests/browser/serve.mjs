// Serves the harness over http://127.0.0.1 and exits with the checks' verdict.
//
// A file:// page would be simpler and does not work: OPFS needs a secure
// context with a real storage key, and a file:// page is an opaque origin.
// http://127.0.0.1 counts as secure without a certificate, which is why the
// runner goes to this trouble rather than serving over TLS.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const rootDir = path.dirname(new URL(import.meta.url).pathname);
// The shipped worker lives outside the harness, and is served FROM ITS SOURCE
// rather than copied in. A copy is a second thing to keep in step, and a stale
// one would let the checks pass against a worker nobody ships.
const workerDir = path.resolve(rootDir, '../../worker');
const port = Number(process.env.PORT ?? 8732);
const timeoutMs = Number(process.env.TIMEOUT_MS ?? 120000);

const contentTypes = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.wasm': 'application/wasm',
};

const timer = setTimeout(() => {
  console.error('TIMED OUT waiting for the browser to report');
  process.exit(1);
}, timeoutMs);

// The pairing mailbox, in memory, keyed `rendezvous/session/slot`.
//
// A stand-in for the Elixir relay's `/rendezvous/...` routes, and it mirrors the
// two behaviours the handshake actually depends on: a missing slot is 404 (the
// normal case while polling, not an error), and a slot is WRITE-ONCE — a second
// write gets 409 rather than overwriting. The second is what keeps a squatter
// from making the host verify against a transcript it never wrote.
//
// It is a double, and the protocol is already tested against the real relay
// natively. What is being checked here is browser-shaped: that two workers can
// pair, and that a joiner mounts OPFS in the right order afterwards.
const slots = new Map();

// The same headers `SyncWeb.Router` sets, and for the same reason: a relay is
// never same-origin with the app that uses it, so without these every browser
// request fails before it is sent. `*` is honest here — the mailbox holds opaque
// handshake bytes, authenticates nobody, and possession of the rendezvous id IS
// the access control. `Allow-Credentials` is deliberately absent.
//
// It is also load-bearing for this harness specifically: the joiner runs on a
// different origin from the host (see `joiner.html`), so its own pairing traffic
// is cross-origin too.
const cors = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, PUT, POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
};

const mailbox = (req, res, url) => {
  const parts = url.split('/').filter(Boolean).slice(1); // drop 'rendezvous'

  // The preflight a PUT with a content-type triggers. Answered before anything
  // else parses the path: a 404 here carries no CORS headers, and the browser
  // reports that as a CORS failure rather than a missing route.
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { ...cors, 'access-control-max-age': '86400' });
    res.end();
    return true;
  }

  if (req.method === 'GET' && parts.length === 2 && parts[1] === 'sessions') {
    const prefix = `${parts[0]}/`;
    const sessions = new Set();
    for (const key of slots.keys()) {
      if (key.startsWith(prefix)) sessions.add(key.slice(prefix.length).split('/')[0]);
    }
    res.writeHead(200, { ...cors, 'content-type': 'application/json' });
    res.end(JSON.stringify({ sessions: [...sessions] }));
    return true;
  }

  if (parts.length !== 3) return false;
  const key = parts.join('/');

  if (req.method === 'GET') {
    const body = slots.get(key);
    if (body === undefined) {
      res.writeHead(404, cors);
      res.end();
    } else {
      res.writeHead(200, { ...cors, 'content-type': 'application/octet-stream' });
      res.end(body);
    }
    return true;
  }

  if (req.method === 'PUT') {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      // Check and set in one synchronous block, so write-once holds even with
      // both sides polling: node runs this to completion before the next
      // request's handler starts.
      if (slots.has(key)) {
        res.writeHead(409, cors);
        res.end();
        return;
      }
      slots.set(key, Buffer.concat(chunks));
      res.writeHead(201, cors);
      res.end();
    });
    return true;
  }

  return false;
};

const server = http.createServer((req, res) => {
  // Not `path` — that is the node module this file imports, and shadowing it
  // turns every static request into `String.prototype.normalize`.
  const route = req.url.split('?')[0];
  if (route.startsWith('/rendezvous/') && mailbox(req, res, route)) return;

  if (req.method === 'POST' && req.url === '/report') {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      res.writeHead(204);
      res.end();
      clearTimeout(timer);

      const { failed, results } = JSON.parse(body);
      for (const line of results) console.log(line);
      console.log(
        failed
          ? `\n${failed} OPFS check(s) failed`
          : `\nall ${results.length} OPFS checks passed`
      );
      server.close();
      process.exit(failed ? 1 : 0);
    });
    return;
  }

  const requested = req.url === '/' ? '/index.html' : req.url.split('?')[0];
  // Serve only from under the harness directory, plus the crate's `worker/`;
  // a traversal here would expose the whole repo to a page.
  const [baseDir, relative] = requested.startsWith('/worker/')
    ? [workerDir, requested.slice('/worker'.length)]
    : [rootDir, requested];
  const target = path.join(baseDir, path.normalize(relative));
  if (!target.startsWith(baseDir)) {
    res.writeHead(403);
    res.end('forbidden');
    return;
  }

  try {
    const body = fs.readFileSync(target);
    res.writeHead(200, {
      'content-type':
        contentTypes[path.extname(target)] ?? 'application/octet-stream',
    });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end(`no such file: ${requested}`);
  }
});

server.listen(port, '127.0.0.1', () => console.error(`serving on ${port}`));
