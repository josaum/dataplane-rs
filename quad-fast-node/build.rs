// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21

//! Build script wiring the N-API link arguments.
//!
//! `napi_build::setup()` emits the platform link flags a Node addon needs;
//! on macOS this includes `-undefined dynamic_lookup` for the cdylib so the
//! N-API symbols resolve at load time inside the Node process. This is the
//! same setup `office-parsers-rs/json-fast-node` uses to keep its workspace
//! `cargo test` / `cargo clippy` gates green without a Node runtime.

fn main() {
    napi_build::setup();
}
