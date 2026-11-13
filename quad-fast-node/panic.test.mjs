// SPDX-License-Identifier: MIT
//
// A Rust panic inside a binding call must reach JS as a thrown Error, and the
// Node process must keep running. Without `#[napi(catch_unwind)]` the panic
// unwinds into the `extern "C"` callback and Rust aborts the process.
//
// Needs the addon built with the `panic-probe` feature, which exports
// `panicProbe()`:
//
//   NODE_CARGO_FEATURES=quad-fast-node/panic-probe ./scripts/build-node.sh quad-fast-node
//   node quad-fast-node/panic.test.mjs
//
// The probe runs in a child process, so an abort is observed as the child's
// exit status instead of killing this test.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const addon = join(dirname(fileURLToPath(import.meta.url)), 'quad_fast_node.node');

const child = `
const native = require(${JSON.stringify(addon)});
if (typeof native.panicProbe !== 'function') {
  console.error('the addon was built without the panic-probe feature');
  process.exit(3);
}
try {
  native.panicProbe();
  console.error('panicProbe returned instead of throwing');
  process.exit(4);
} catch (error) {
  if (!(error instanceof Error)) process.exit(5);
  console.log('caught: ' + error.message);
}
// The process is still alive and the binding still answers.
console.log('alive: ' + native.version());
`;

const result = spawnSync(process.execPath, ['-e', child], { encoding: 'utf8' });
assert.equal(
  result.status,
  0,
  `child exited with status ${result.status} signal ${result.signal}\n${result.stderr}`,
);
assert.match(result.stdout, /caught: .*panic-probe: deliberate panic/);
assert.match(result.stdout, /alive: \d+\.\d+\.\d+/);
console.log('ok panic surfaces as a thrown Error');
