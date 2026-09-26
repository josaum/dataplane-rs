# dataplane-rs

High-performance semantic dataplane, streaming linked data runtime, and Arrow Flight / Jelly RDF engine in pure Rust with Python and Node-API native bindings.

Every repository in the sovereign workspace ecosystem lives under `https://github.com/josaum/`.

## Architecture & Crates

| Crate | Purpose | Language / Tier |
|---|---|---|
| [`quad-fast-core`](file:///Users/josaum/projects/dataplane-rs/quad-fast-core) | Zero-copy Arrow IPC UnsignedQuadStream v1 contract and dataset model | Pure Rust |
| [`jelly-fast-core`](file:///Users/josaum/projects/dataplane-rs/jelly-fast-core) | Jelly RDF frame encoder, decoder, patch codec, and RDF-Star streaming | Pure Rust |
| [`jelly-fast-grpc`](file:///Users/josaum/projects/dataplane-rs/jelly-fast-grpc) | Tonic gRPC streaming service for Jelly RDF frames | Async Rust (`tonic`/`tokio`) |
| [`jsonld-fast-core`](file:///Users/josaum/projects/dataplane-rs/jsonld-fast-core) | Deterministic fail-closed JSON-LD 1.1 / W3C RDF streaming processor | Pure Rust |
| [`cborld-fast-core`](file:///Users/josaum/projects/dataplane-rs/cborld-fast-core) | CBOR-LD binary linked data codec with deterministic table compression | Pure Rust |
| [`quad-fast-flight`](file:///Users/josaum/projects/dataplane-rs/quad-fast-flight) | Arrow Flight RPC service for high-throughput dataset exchange | Async Rust (`arrow-flight`) |
| [`flight-auth`](file:///Users/josaum/projects/dataplane-rs/flight-auth) | ES256 / HS256 JWT claims verifier and bearer token middleware for Flight | Pure Rust |
| [`quad-fast-py`](file:///Users/josaum/projects/dataplane-rs/quad-fast-py) | Python `quad_fast` extension module (`abi3-py38`) for IPC, Jelly, and JSON-LD | Python / PyO3 |
| [`quad-fast-node`](file:///Users/josaum/projects/dataplane-rs/quad-fast-node) | Node-API bindings for quad batches and Jelly frame streaming | Node.js / Node-API |

## Sovereign Invariants

1. **Deterministic & Fail-Closed**: No unbudgeted recursion, no silent error dropping, no dynamic network resolution without explicit opt-in.
2. **Cryptographic Provenance**: Every artifact is stamped into `release-manifest.json` with its SHA-256 digest, exact Git commit, and author signature (`Dionisio Chiuratto Agourakis`).
3. **Strict Namespace**: Managed under `josaum/` (`https://github.com/josaum/dataplane-rs`).

## Verification

```bash
# 1. Check workspace
cargo check --workspace --all-targets

# 2. Run full Rust test suite
cargo test --workspace

# 3. Build and test Node bindings
./scripts/build-node.sh
node scripts/smoke-node.mjs

# 4. Test Python bindings
cd quad-fast-py && uv run pytest tests/
```
