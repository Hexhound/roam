// The OPFS checks run HERE, in a dedicated worker, and nowhere else.
//
// Measured in Chromium 150: `createSyncAccessHandle` is absent on a document's
// main thread — the property is `undefined`, so this is not a permission that
// can be granted. Moving these calls to the page would not fail slowly, it would
// fail immediately with "is not a function".

// wasm32 panics are ABORTS, and that shapes this whole file.
//
// A failed assert inside the Rust conformance suite does not reject a promise —
// it traps, killing the worker outright, so the `try/catch` around each check
// below never runs for that case. roam-wasm installs a panic hook that writes
// the real message to console.error just before the trap, which is the only
// moment the text exists. Forward it to the page *immediately*: anything merely
// accumulated here dies with the worker, and the page is left reporting
// "RuntimeError: unreachable" with no clue which assertion broke. Verified by
// mutating the OPFS offset handling and watching the named assertion appear.
const panics = [];
const realError = console.error.bind(console);
console.error = (...args) => {
  const text = args.join(' ');
  panics.push(text);
  self.postMessage({ panic: text });
  realError(...args);
};

import init, {
  opfs_conformance,
  opfs_survives_a_remount,
  opfs_presizes_with_zeroes,
  opfs_grows_after_mount,
} from './pkg/roam_wasm.js';

const CHECKS = [
  ['conformance', opfs_conformance],
  ['survives a remount', opfs_survives_a_remount],
  ['pre-sizes with zeroes', opfs_presizes_with_zeroes],
  ['grows after mount', opfs_grows_after_mount],
];

(async () => {
  const results = [];
  let failed = 0;

  try {
    await init();
  } catch (e) {
    self.postMessage({ failed: 1, results: ['init: FAIL ' + e] });
    return;
  }

  for (const [name, check] of CHECKS) {
    panics.length = 0;
    try {
      const detail = await check();
      results.push(`ok    ${name}${detail ? ' — ' + detail : ''}`);
    } catch (e) {
      failed++;
      const because = panics.length ? '\n      ' + panics.join('\n      ') : '';
      results.push(`FAIL  ${name}: ${e}${because}`);
    }
  }

  self.postMessage({ failed, results });
})();
