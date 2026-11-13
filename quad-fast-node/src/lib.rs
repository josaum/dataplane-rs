// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21

//! quad-fast-node: N-API bindings for `quad-fast-core` and `jelly-fast-core`.
//!
//! Mirrors the `office-parsers-rs/json-fast-node` house pattern (napi 2 +
//! napi-derive 2, cdylib, `napi_build::setup()`): JavaScript passes plain
//! objects and `Buffer`s across the boundary, and every `#[napi]` function is
//! a one-line delegation into the napi-free [`convert`] layer so the whole
//! surface is unit-testable from `cargo test` without a Node runtime or a
//! built `.node` artifact.
//!
//! Four functions cover the N9 contract surface:
//!
//! - [`quads_to_ipc`] — build one `UnsignedQuadStream` batch from a JS array
//!   of quad objects and return Arrow IPC stream bytes.
//! - [`ipc_to_quads`] — decode Arrow IPC stream bytes back to quad objects.
//! - [`quads_to_jelly_frames`] — build a batch and encode it as
//!   length-delimited Jelly stream frames.
//! - [`jelly_frames_to_quads`] — decode length-delimited Jelly stream frames
//!   back to quad objects.
//!
//! All output is unsigned by construction: the Arrow schema carries
//! `dataplane.assurance = "unsigned"` and nothing in this binding attaches,
//! claims, or upgrades assurance. Every function takes an
//! optional fail-closed options object (unknown keys are typed errors); see
//! [`convert`] for the quad object shape and `index.d.ts` for the TypeScript
//! surface. Errors surface in JS as exceptions whose message starts with a
//! stable machine-readable code (`input:`, `resource_limit:`, ...).
//!
//! The JS quad shape has `iri`, `bnode`, and `literal` object kinds only, so
//! RDF 1.2 triple terms (RDF-star) are refused in both directions —
//! `kind: "triple"` on input is an `input:` error, and a decoded batch
//! carrying one raises `unsupported: rdf12_triple_term` — never flattened
//! into a node reference.

mod convert;
#[cfg(test)]
mod tests;

use napi::bindgen_prelude::{Buffer, Error, Result, Status};
use napi_derive::napi;
use serde_json::Value;

/// Maps a typed conversion error to a JS exception.
///
/// Malformed JS-shaped input surfaces as `InvalidArg`; everything else
/// (budgets, codec refusals, malformed payload bytes) is a generic failure.
/// The rendered message keeps the stable machine-readable code as its first
/// token so JS callers can dispatch on it.
fn err(error: convert::BindingError) -> Error {
    let status = match error.code() {
        "input" => Status::InvalidArg,
        _ => Status::GenericFailure,
    };
    Error::new(status, error.to_string())
}

/// Crate / binding version string.
#[napi]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Builds one `UnsignedQuadStream` batch from quad objects and returns it as
/// Arrow IPC stream bytes.
///
/// `options` (all optional, unknown keys rejected): `maxQuads`,
/// `maxRetainedTermBytes`, `maxIpcBytes`.
#[napi]
pub fn quads_to_ipc(quads: Value, options: Option<Value>) -> Result<Buffer> {
    convert::quads_to_ipc(&quads, options.as_ref())
        .map(Buffer::from)
        .map_err(err)
}

/// Decodes Arrow IPC stream bytes of contract batches into quad objects.
///
/// `options` (all optional, unknown keys rejected): `maxQuads` (cumulative
/// decoded-quad budget), `maxRetainedTermBytes`, `maxIpcBytes` (input byte
/// budget).
#[napi]
pub fn ipc_to_quads(ipc: Buffer, options: Option<Value>) -> Result<Value> {
    convert::ipc_to_quads(&ipc, options.as_ref()).map_err(err)
}

/// Builds one contract batch from quad objects and encodes it as
/// length-delimited Jelly stream frames.
///
/// `options` (all optional, unknown keys rejected): `maxQuads`,
/// `maxRetainedTermBytes`, `streamName`, `maxPrefixTableSize`,
/// `maxNameTableSize`, `maxDatatypeTableSize`, `quadsPerFrame`,
/// `allowProvenanceLoss` (Jelly has no provenance fields; without this flag,
/// quads carrying provenance are refused rather than silently stripped).
#[napi]
pub fn quads_to_jelly_frames(quads: Value, options: Option<Value>) -> Result<Buffer> {
    convert::quads_to_jelly_frames(&quads, options.as_ref())
        .map(Buffer::from)
        .map_err(err)
}

/// Decodes length-delimited Jelly stream frames into quad objects.
///
/// `options` (all optional, unknown keys rejected): `maxQuads` (per-frame and
/// cumulative decoded-quad budget), `maxRetainedTermBytes`,
/// `maxPrefixTableSize`, `maxNameTableSize`, `maxDatatypeTableSize`,
/// `maxInputBytes`, `maxFrames`.
#[napi]
pub fn jelly_frames_to_quads(frames: Buffer, options: Option<Value>) -> Result<Value> {
    convert::jelly_frames_to_quads(&frames, options.as_ref()).map_err(err)
}
