# dataplane-rs

High-performance semantic dataplane, streaming linked data runtime, and Arrow Flight / Jelly RDF engine in pure Rust with Python (`abi3-py38`) and Node-API (`napi-2`) native bindings across macOS, Linux, and Windows.

**Core rule:** *One source, one version, one artifact, with cryptographic provenance.*

Every repository in the sovereign workspace ecosystem lives under `https://github.com/fast-parser-inc/`. Every published wheel and Node tarball is bound by `release-manifest.json` and `SHA256SUMS` to its exact source commit, SHA-256 digest, build toolchain, native binary header (`Mach-O ARM64`, `ELF64 x86_64/AArch64`, or `PE32+ AMD64`), and embedded CycloneDX SBOM.

---

## Architecture & Crates (9 Crates)

| Crate | Purpose | Language / Tier |
| :--- | :--- | :--- |
| [`quad-fast-core`](./quad-fast-core) | Zero-copy Arrow IPC `UnsignedQuadStream` v1 contract and dataset model | Pure Rust |
| [`jelly-fast-core`](./jelly-fast-core) | Jelly RDF frame encoder, decoder, patch codec, and RDF-Star streaming | Pure Rust |
| [`jelly-fast-grpc`](./jelly-fast-grpc) | Tonic gRPC streaming service for Jelly RDF frames and patch pub/sub | Async Rust (`tonic`/`tokio`) |
| [`jsonld-fast-core`](./jsonld-fast-core) | Deterministic fail-closed JSON-LD 1.1 / YAML-LD / W3C RDF streaming processor | Pure Rust |
| [`cborld-fast-core`](./cborld-fast-core) | CBOR-LD binary linked data codec with deterministic table compression | Pure Rust |
| [`quad-fast-flight`](./quad-fast-flight) | Arrow Flight RPC service for high-throughput dataset exchange | Async Rust (`arrow-flight`) |
| [`flight-auth`](./flight-auth) | ES256 / HS256 JWT claims verifier and bearer token middleware for Flight | Pure Rust |
| [`quad-fast-py`](./quad-fast-py) | Python `quad_fast` extension module (`abi3-py38`) for IPC, Jelly, CBOR-LD, and JSON-LD | Python / PyO3 |
| [`quad-fast-node`](./quad-fast-node) | Node-API bindings for quad batches, Jelly frame streaming, CBOR-LD, and JSON-LD | Node.js / Node-API |

---

## Sovereign Invariants

1. **Deterministic & Fail-Closed**: No unbudgeted recursion, no silent error dropping, and no dynamic network resolution without explicit opt-in.
2. **Cryptographic Provenance**: Every artifact is stamped into `release-manifest.json` with its SHA-256 digest, exact Git commit, and author signature (`Dionisio Chiuratto Agourakis`).
3. **Pinned Arrow Wire Format**: Every batch is stamped `dataplane.arrow_version = "58.3.0"`, the Arrow contract version that downstream readers check exactly; it changes only in step with them. The library pin is separate: all workspace members build against one exact Arrow release (`arrow`, `arrow-array`, `arrow-ipc`, `arrow-schema`, `arrow-flight` at `=58.4.1`), which may move within major 58 for fixes because the IPC format and the contract schema do not change within a major. A new Arrow major needs a decision about the stamp first; `arrow_version_stamp_follows_the_pinned_arrow_major` in quad-fast-core fails until one is made.
4. **Strict Namespace**: Managed under `fast-parser-inc/` (`https://github.com/fast-parser-inc/dataplane-rs`).


### Flight authentication variables

The Flight server reads `FLIGHT_REQUIRE_AUTH`, `FLIGHT_ALLOW_LEGACY_HS256`, `FLIGHT_JWT_PUBLIC_KEY_PEM`, `FLIGHT_JWT_PUBLIC_KEY_PATH`, `FLIGHT_JWT_ISSUER`, `FLIGHT_JWT_AUDIENCE` and `JWT_SECRET`; clients read `FLIGHT_AUTHORIZATION` or `FLIGHT_BEARER_TOKEN`. These replace the earlier `ATLAS_*` names. A server that still finds one of the old server-side names set refuses to start and names its replacement, so an upgraded deployment can never come up with authentication silently off.

---

## Release Matrix & Provenance (8 Artifacts)

Every tagged release (`vYYYY.MM.DD`) builds and publishes **8 binary artifacts** after the reusable CI verification workflow passes:

| Artifact Family | Count | Targets |
| :--- | :--- | :--- |
| **Python Wheels (`cp38-abi3`)** | **4** (`quad-fast-py` × 4 targets) | `aarch64-apple-darwin` (`macosx_11_0_arm64`)<br>`x86_64-unknown-linux-gnu` (`manylinux_2_17_x86_64`)<br>`aarch64-unknown-linux-gnu` (`manylinux_2_17_aarch64`)<br>`x86_64-pc-windows-msvc` (`win_amd64`) |
| **Node-API Tarballs (`napi-2`)** | **4** (`quad-fast-node` × 4 targets) | `darwin-arm64` (`aarch64-apple-darwin`)<br>`linux-x64-gnu` (`x86_64-unknown-linux-gnu`)<br>`linux-arm64-gnu` (`aarch64-unknown-linux-gnu`)<br>`win32-x64-msvc` (`x86_64-pc-windows-msvc`) |

### Cross-Platform & Windows Compatibility

The workspace is verified for POSIX and Windows (`x86_64-pc-windows-msvc` / `x86_64-pc-windows-gnu`) compatibility:
- `.gitattributes` enforces LF line endings (`eol=lf`) across source files, scripts, `.proto` schemas, and JSON-LD/CBOR-LD fixtures so `core.autocrlf=true` on Windows never mutates test bytes or shell scripts.
- `jelly-fast-core/build.rs` resolves `protoc` through `protoc-bin-vendored` when `PROTOC` is unset, so Windows, Linux (`x86_64` and `aarch64`), and macOS builds compile protobuf and gRPC stubs out-of-the-box without requiring a host `protoc` installation.
- `scripts/build-node.sh` builds and stages `quad_fast_node.node` across macOS (`lib*.dylib`), Linux (`lib*.so`), and Windows (`*.dll` under `MINGW*`/`MSYS*`/`CYGWIN*`/`Windows_NT`) using `node` directly rather than assuming a POSIX `python3` alias.
- All Python release and verification tools (`scripts/release_manifest.py`, `scripts/inject_sbom.py`, `scripts/verify_consumer_pin.py`, `cborld-fast-core/vendor/cborld-registry/generate_tables.py`) use explicit UTF-8 encoding and deterministic LF line endings.

---

## Verification

```bash
# 1. Format and lint workspace
cargo fmt --all --check
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --locked

# 2. Run full Rust test suite
cargo test --workspace --locked

# 3. Build and test Node bindings
./scripts/build-node.sh
node scripts/smoke-node.mjs
node quad-fast-node/smoke.test.mjs

# 4. Test Python bindings and release tooling
(cd quad-fast-py && uv run pytest tests/)
uv run --with pytest pytest tests -q
```
