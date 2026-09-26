#!/usr/bin/env node
// Load-and-parse smoke for the Node bindings in dataplane-rs.
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import path from 'node:path';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const mod = require(path.join(root, 'quad-fast-node'));
const {
  version,
  quadsToIpc,
  ipcToQuads,
  quadsToJellyFrames,
  jellyFramesToQuads,
} = mod;

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

assert.match(version(), /^\d+\.\d+\.\d+/);

const ipc = quadsToIpc(quads);
assert.ok(Buffer.isBuffer(ipc) && ipc.length > 0);
assert.deepEqual(ipcToQuads(ipc), quads);

const frames = quadsToJellyFrames(quads, { quadsPerFrame: 1 });
assert.ok(Buffer.isBuffer(frames) && frames.length > 0);
assert.deepEqual(jellyFramesToQuads(frames), quads);

// Fail-closed options check
assert.throws(() => quadsToIpc(quads, { maxQauds: 1 }), /input:.*maxQauds/);
assert.throws(() => quadsToIpc(quads, { maxQuads: 1 }), /resource_limit:/);

console.log(`ok quad-fast-node: version ${version()}, IPC and Jelly roundtrips verified`);
console.log('all dataplane-rs node-binding smoke checks passed');
