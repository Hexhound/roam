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

const server = http.createServer((req, res) => {
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
  // Serve only from under the harness directory; a traversal here would expose
  // the whole repo to a page.
  const target = path.join(rootDir, path.normalize(requested));
  if (!target.startsWith(rootDir)) {
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
