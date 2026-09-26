// SPDX-License-Identifier: MIT
//
// JS smoke test for quad-fast-node. NOT part of the cargo gate: the Rust
// unit tests in src/tests.rs cover the conversion layer without a Node
// runtime; this file only proves the built .node addon loads and the four
// bindings behave end to end inside Node.
//
// How to run (from cartridges/semantic-dataplane/dataplane-rs/quad-fast-node):
//
//   Option A - napi CLI (mirrors office-parsers-rs/json-fast-node):
//     npm install @napi-rs/cli --no-save
//     npx napi build --platform --release
//     node smoke.test.mjs
//
//   Option B - plain cargo (no npm needed):
//     cargo build -p quad-fast-node --release
//     cp ../target/release/libquad_fast_node.dylib ./quad_fast_node.node
//       (Linux: libquad_fast_node.so; Windows: quad_fast_node.dll)
//     node smoke.test.mjs

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  version,
  quadsToIpc,
  ipcToQuads,
  quadsToJellyFrames,
  jellyFramesToQuads,
} = require('./index.js');

const quads = [
  {
    subject: { kind: 'iri', value: 'http://example.com/s' },
    predicate: 'http://example.com/p',
    object: {
      kind: 'literal',
      value: '42',
      datatype: 'http://www.w3.org/2001/XMLSchema#integer',
    },
    graph: { kind: 'iri', value: 'http://example.com/g' },
  },
  {
    subject: { kind: 'bnode', value: 'b0' },
    predicate: 'http://example.com/p',
    object: { kind: 'literal', value: 'ola', language: 'pt' },
    graph: { kind: 'default' },
  },
];

// version() returns a semver-ish string.
assert.match(version(), /^\d+\.\d+\.\d+/);

// Arrow IPC round trip preserves every term.
const ipc = quadsToIpc(quads);
assert.ok(Buffer.isBuffer(ipc) && ipc.length > 0);
assert.deepEqual(ipcToQuads(ipc), quads);

// Jelly frame round trip preserves every term.
const frames = quadsToJellyFrames(quads, { quadsPerFrame: 1 });
assert.ok(Buffer.isBuffer(frames) && frames.length > 0);
assert.deepEqual(jellyFramesToQuads(frames), quads);

// Fail-closed: unknown option keys are typed errors, not silent no-ops.
assert.throws(() => quadsToIpc(quads, { maxQauds: 1 }), /input:.*maxQauds/);

// Fail-closed: quad budget.
assert.throws(() => quadsToIpc(quads, { maxQuads: 1 }), /resource_limit:/);

// Fail-closed: provenance cannot ride Jelly without explicit consent.
const withProvenance = [
  {
    ...quads[0],
    provenance: { sourceArtifactIri: 'http://example.com/doc' },
  },
];
assert.throws(() => quadsToJellyFrames(withProvenance), /unsupported:/);
const lossy = quadsToJellyFrames(withProvenance, { allowProvenanceLoss: true });
assert.equal(jellyFramesToQuads(lossy)[0].provenance, undefined);

console.log('quad-fast-node smoke test: all assertions passed');
