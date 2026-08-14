// M1 gate, JS half: the "javascript client" in our e2e suite.
//
// Proves interop in BOTH directions against committed bytes:
//   native -> JS : load `native_snapshot.loro` (written by Rust), assert content.
//   JS -> native : produce `js_snapshot.loro` here, which the Rust test
//                  `js_produced_fixture_decodes_to_canonical_content` asserts.
//
// Run via `tests/js/run.sh`, which builds the wasm package first.

import { strict as assert } from "node:assert";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "fixtures");

const { Doc } = await import(join(here, "..", "..", "pkg", "roam_wasm.js"));

// Mirrors the constants in `tests/interop_fixture.rs`. Kept in lockstep by hand
// — that duplication IS the test: if the two sides drift, interop is broken.
const NATIVE = {
  textId: "notes/hello.md",
  textBody: "hello from native",
  mapId: "meta",
  mapKey: "title",
  mapValue: "Hello",
};
const JS = {
  peerId: 42n,
  textId: "notes/from-js.md",
  textBody: "hello from javascript",
  mapId: "meta",
  mapKey: "author",
  mapValue: "browser",
};

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`not ok - ${name}\n    ${error.message}`);
  }
}

check("wasm imports a snapshot produced by a native peer", () => {
  const bytes = readFileSync(join(fixtures, "native_snapshot.loro"));
  // A browser is always a different replica than the peer that wrote the bytes.
  const doc = new Doc(1001n);
  doc.import(bytes);

  assert.equal(doc.text(NATIVE.textId), NATIVE.textBody);
  assert.equal(doc.getEntry(NATIVE.mapId, NATIVE.mapKey), NATIVE.mapValue);
});

check("wasm round-trips its own snapshot", () => {
  const source = new Doc(JS.peerId);
  source.insertText(JS.textId, 0, JS.textBody);
  source.setEntry(JS.mapId, JS.mapKey, JS.mapValue);
  source.commit();

  const target = new Doc(1002n);
  target.import(source.snapshot());

  assert.equal(target.text(JS.textId), JS.textBody);
  assert.equal(target.getEntry(JS.mapId, JS.mapKey), JS.mapValue);
});

check("wasm publishes a snapshot for the native side to read", () => {
  const doc = new Doc(JS.peerId);
  doc.insertText(JS.textId, 0, JS.textBody);
  doc.setEntry(JS.mapId, JS.mapKey, JS.mapValue);
  doc.commit();

  writeFileSync(join(fixtures, "js_snapshot.loro"), doc.snapshot());
});

// Merging both directions must converge: a doc holding native bytes that then
// imports JS bytes has to end up with both sides' content intact.
check("native and JS snapshots merge without conflict", () => {
  const doc = new Doc(1003n);
  doc.import(readFileSync(join(fixtures, "native_snapshot.loro")));
  doc.import(readFileSync(join(fixtures, "js_snapshot.loro")));

  assert.equal(doc.text(NATIVE.textId), NATIVE.textBody);
  assert.equal(doc.text(JS.textId), JS.textBody);
  assert.equal(doc.getEntry(NATIVE.mapId, NATIVE.mapKey), NATIVE.mapValue);
  assert.equal(doc.getEntry(JS.mapId, JS.mapKey), JS.mapValue);
});

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall JS interop checks passed");
