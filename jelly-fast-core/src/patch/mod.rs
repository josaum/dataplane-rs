// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Jelly-Patch frame codec over the `UnsignedQuadStream` v1 contract.
//!
//! This module encodes and decodes RDF-Patch streams in the Jelly-Patch
//! wire format defined by the vendored `proto/patch.proto` (Jelly-RDF @
//! `d1d3088274be36d761617a1228a83d5b697831d6`, see `proto/PROVENANCE.md`).
//! Patch operations reference quads through the single quad representation
//! of the semantic dataplane — [`PatchOp::Add`] and [`PatchOp::Delete`]
//! carry `UnsignedQuadStream` v1 batches, so the full provenance column
//! set survives the in-memory representation (invariant 3). Like the RDF
//! stream codec, the wire format itself has no provenance fields:
//! encoding a batch with non-null provenance is refused unless
//! [`JellyPatchEncoderOptions::allow_provenance_loss`] is set, and decoded
//! batches always carry null provenance.
//!
//! Codec output is **unsigned by construction** (Atlas product
//! invariant 7): frames carry patch operations, RDF data, and lookup
//! state — encoding or decoding never certifies, approves, or promotes
//! anything.
//!
//! # Scope
//!
//! The codec implements the `QUADS` statement type and the `FLAT` stream
//! type (the entire stream is a single patch; transactions and lookup
//! state may span frames). All other declared protocol surface is refused
//! with typed errors, never skipped silently:
//!
//! - `TRIPLES` statement type (same refusal as the RDF stream codec: no
//!   implicit default-graph mapping),
//! - `FRAME` and `PUNCTUATED` stream types (the vendored schema comments
//!   underdetermine whether lookup tables reset at patch boundaries; the
//!   Jelly-Patch prose spec is not vendored, so the codec fails closed),
//! - punctuation rows (only meaningful in `PUNCTUATED` streams),
//! - namespace add/delete rows (`PA`/`PD`; prefix declarations have no
//!   representation in the quad contract),
//! - generalized statements,
//! - triple terms in a subject or predicate position, and any triple term
//!   on a stream whose options row did not set `rdf_star`,
//! - protocol versions other than 1 (Jelly-Patch 1.0.x per the vendored
//!   schema; 10000+ marks custom extensions and is refused too).
//!
//! # RDF 1.2 triple terms
//!
//! Patch RDF-star **is** implemented, in statement rows and in header
//! values, because the vendored `patch.proto` determines it: statement rows
//! carry the same `RdfQuad` message as the RDF stream (including
//! `o_triple_term`), header values model `h_triple_term` explicitly, and
//! both are gated by the same `RdfPatchOptions.rdf_star` flag as the RDF
//! stream's options row. Nothing here depends on the un-vendored
//! Jelly-Patch prose, so the fail-closed refusal that applied to `FRAME` and
//! `PUNCTUATED` stream types has no counterpart here. Encoding is opt-in
//! ([`JellyPatchEncoderOptions::rdf_star`]) so emitted patches stay
//! byte-identical by default, and nesting is bounded by the decoder's
//! `quad_limits.max_quoted_depth`.
//!
//! # Transaction and header semantics
//!
//! Semantics are enforced exactly as far as the vendored schema defines
//! them: transactions cannot nest, `TC`/`TA` require an open transaction,
//! and a stream that ends with an open transaction is a typed error
//! (callers signal end-of-stream via the codecs' `finish` methods).
//! Header rows must occur at the start of a patch frame, before any
//! statement or transaction row of that frame. Header values always use
//! explicit lookup identifiers on encode: the vendored schema disables
//! repeated-term compression for header values and the non-vendored prose
//! spec is not available to pin the id-0 delta behavior across header
//! rows, so the encoder never relies on it (decode accepts both, sharing
//! the stream's delta state).

mod decoder;
mod encoder;

use arrow_array::RecordBatch;
use oxrdf::Term;

pub use decoder::{JellyPatchDecoder, JellyPatchDecoderOptions};
pub use encoder::{
    DEFAULT_PATCH_ROWS_PER_FRAME, JellyPatchEncoder, JellyPatchEncoderOptions,
    PATCH_PROTOCOL_VERSION,
};

/// One RDF-Patch operation, quads carried as `UnsignedQuadStream` batches.
///
/// The operation set mirrors the vendored `patch.proto` row types this
/// codec supports. Statement operations group one or more quads into a
/// contract-valid batch; on decode, maximal runs of consecutive add (or
/// delete) rows collapse into one batch each, so a round trip preserves
/// the operation *sequence* semantics, not the batch boundaries.
#[derive(Clone, Debug, PartialEq)]
pub enum PatchOp {
    /// Start a transaction (`TX`).
    TransactionStart,
    /// Commit the open transaction (`TC`).
    TransactionCommit,
    /// Abort the open transaction (`TA`).
    TransactionAbort,
    /// A patch metadata header (`H`).
    Header {
        /// Header key (required, non-empty).
        key: String,
        /// Header value: an IRI, blank node, or literal.
        value: Term,
    },
    /// Add the quads of an `UnsignedQuadStream` batch (`A`).
    Add(RecordBatch),
    /// Delete the quads of an `UnsignedQuadStream` batch (`D`).
    Delete(RecordBatch),
}
