# quad-fast-node

Node.js N-API bindings for [`quad-fast-core`](../quad-fast-core) (the
`UnsignedQuadStream` v1 Arrow contract) and [`jelly-fast-core`](../jelly-fast-core)
(the Jelly RDF frame codec). Mirrors the `office-parsers-rs/json-fast-node`
house pattern: napi 2 + napi-derive 2, cdylib, `napi_build::setup()`.

Everything this binding produces is **unsigned by construction** (Atlas
product invariant 7): the Arrow schema carries `atlas.assurance = "unsigned"`
and nothing here attaches, claims, or upgrades assurance. All entry points
are fail-closed with explicit resource limits; malformed input and unknown
option keys are typed errors, never silent drops.

## Surface

| Function | Direction |
| --- | --- |
| `quadsToIpc(quads, options?)` | JS quad objects → Arrow IPC stream bytes |
| `ipcToQuads(ipc, options?)` | Arrow IPC stream bytes → JS quad objects |
| `quadsToJellyFrames(quads, options?)` | JS quad objects → length-delimited Jelly frames |
| `jellyFramesToQuads(frames, options?)` | length-delimited Jelly frames → JS quad objects |
| `version()` | binding version string |

See `index.d.ts` for the quad object shape and the per-function option keys.
Jelly 1.1.1 carries no per-quad provenance: encoding quads that carry
provenance is refused unless `allowProvenanceLoss: true` is set explicitly.

## Build

```bash
cd cartridges/semantic-dataplane/dataplane-rs/quad-fast-node
npm install @napi-rs/cli --no-save
npx napi build --platform --release
```

## Test

The conversion layer is covered by Rust unit tests that need no Node runtime
or built `.node` artifact:

```bash
cargo test -p quad-fast-node
```

The JS smoke test (`smoke.test.mjs`, run instructions in its header) proves
the built addon end to end inside Node; it is deliberately not wired into
the cargo gate.
