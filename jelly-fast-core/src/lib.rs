// Rust guideline compliant 2026-02-21
//! Jelly RDF 1.1.1 frame codec over the `UnsignedQuadStream` v1 contract.
//!
//! This crate encodes and decodes the [Jelly] RDF streaming format
//! (serialization spec 1.1.1, physical stream type QUADS) against the
//! single quad representation of the semantic dataplane: the
//! `UnsignedQuadStream` v1 Arrow contract from [`quad_fast_core`]. The
//! protobuf schemas are vendored under `proto/` (see `proto/PROVENANCE.md`)
//! and compiled at build time; the generated messages and the tonic
//! `RdfStreamService` client/server stubs are exposed as [`proto`].
//!
//! Codec output is **unsigned by construction**: frames and batches carry
//! RDF data, lookup state, and nothing else — encoding or decoding never
//! certifies a source, approves a rule, or promotes a fact.
//!
//! RDF 1.2 triple terms (RDF-star) are carried end to end in the **object**
//! position, matching the vendored schema's `o_triple_term` field and the
//! [`quad_fast_core`] contract's `object_kind = "triple"` rows. Both codecs
//! gate them on the wire `rdf_star` stream option: encoders announce and
//! emit them only when [`JellyEncoderOptions::rdf_star`] (respectively
//! [`JellyPatchEncoderOptions::rdf_star`]) is set, so a stream never
//! contradicts its own options row, and decoders refuse a triple term that
//! arrives on a stream that did not announce one. Triple terms in the
//! subject or predicate position stay refused: RDF 1.2 admits them only as
//! objects and the [`oxrdf`] term model has no variant for them elsewhere.
//! Nesting is bounded by the decoder's `quad_limits.max_quoted_depth`.
//!
//! The codec never drops data silently. Unsupported protocol features —
//! triple terms outside the object position, generalized statements, the
//! TRIPLES and GRAPHS physical stream types, namespace declaration rows,
//! and unknown protocol versions — surface as
//! [`JellyError::Unsupported`]. Per-quad
//! source provenance has no Jelly representation, so the encoder rejects
//! batches that carry it unless
//! [`JellyEncoderOptions::allow_provenance_loss`] is set explicitly.
//! Frame `metadata` entries are ignored on decode; the schema documents
//! them as comment-like and carrying no RDF data.
//!
//! The crate also implements the Jelly-Patch protocol from the vendored
//! `proto/patch.proto`: [`JellyPatchEncoder`] and [`JellyPatchDecoder`]
//! move [`PatchOp`] sequences (add/delete quad batches, transactions,
//! headers) over the same lookup table machinery; see [`patch`] — the
//! codec module behind those re-exports — for the supported subset and
//! the refused surface. Patch RDF-star is implemented rather than refused
//! because the vendored `patch.proto` determines it: statement rows are the
//! very same `RdfQuad` message, header values model `h_triple_term`
//! explicitly, and both are gated by the same `rdf_star` option.
//!
//! [Jelly]: https://w3id.org/jelly/1.1.1/specification/serialization
//!
//! # Examples
//!
//! ```
//! use jelly_fast_core::{
//!     JellyDecoder, JellyDecoderOptions, JellyEncoder, JellyEncoderOptions,
//! };
//! use oxrdf::{NamedNode, Quad};
//! use quad_fast_core::{QuadBatchBuilder, QuadLimits};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let quad = Quad::new(
//!     NamedNode::new("http://example.com/s")?,
//!     NamedNode::new("http://example.com/p")?,
//!     NamedNode::new("http://example.com/o")?,
//!     oxrdf::GraphName::DefaultGraph,
//! );
//! let mut builder = QuadBatchBuilder::new(QuadLimits::default());
//! builder.push(quad.as_ref(), None)?;
//! let batch = builder.finish()?;
//!
//! let mut encoder = JellyEncoder::new(JellyEncoderOptions::default())?;
//! let frames = encoder.encode_batch(&batch)?;
//!
//! let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
//! let decoded = decoder.decode_frame(&frames[0])?;
//! assert_eq!(decoded.num_rows(), 1);
//! # Ok(())
//! # }
//! ```

/// Generated Jelly protobuf messages and gRPC service stubs.
///
/// Compiled from the vendored `proto/rdf.proto` (serialization 1.1.1) and
/// `proto/grpc.proto` (streaming 1.0.0) by `tonic-prost-build`. The tonic
/// `RdfStreamService` client and server live in the
/// [`proto::rdf_stream_service_client`] and
/// [`proto::rdf_stream_service_server`] submodules so dependent crates
/// never regenerate the shared messages. The Jelly-Patch messages from the
/// vendored `proto/patch.proto` live in [`proto::patch`].
#[allow(missing_docs, reason = "generated code")]
#[allow(missing_debug_implementations, reason = "generated code")]
#[allow(clippy::all, reason = "generated code")]
#[allow(clippy::allow_attributes_without_reason, reason = "generated code")]
pub mod proto {
    include!(concat!(
        env!("OUT_DIR"),
        "/eu.ostrzyciel.jelly.core.proto.v1.rs"
    ));

    /// Generated Jelly-Patch messages (vendored `proto/patch.proto`).
    pub mod patch {
        include!(concat!(
            env!("OUT_DIR"),
            "/eu.ostrzyciel.jelly.core.proto.v1.patch.rs"
        ));

        /// Generated dataplane patch pub/sub service surface.
        ///
        /// Compiled from `proto/dataplane_patch_grpc.proto`, which is written
        /// in this repository (NOT vendored from Jelly upstream): the
        /// vendored `patch.proto` defines no gRPC service and its options
        /// carry no topic name, so the dataplane declares its own
        /// `PatchStreamService` modeled on the vendored
        /// `RdfStreamService` shape.
        pub mod grpc {
            include!(concat!(
                env!("OUT_DIR"),
                "/dataplane/dataplane.jelly.patch.v1.rs"
            ));
        }
    }
}

mod decoder;
mod encoder;
mod error;
pub mod patch;
mod tables;
mod terms;

pub use decoder::{JellyDecoder, JellyDecoderOptions};
pub use encoder::{
    DEFAULT_MAX_DATATYPE_TABLE_SIZE, DEFAULT_MAX_NAME_TABLE_SIZE, DEFAULT_MAX_PREFIX_TABLE_SIZE,
    DEFAULT_QUADS_PER_FRAME, JellyEncoder, JellyEncoderOptions, PROTOCOL_VERSION,
    SPEC_MIN_NAME_TABLE_SIZE,
};
pub use error::{JellyError, JellyResource};
pub use patch::{
    DEFAULT_MAX_PATCH_OPS_PER_FRAME, DEFAULT_PATCH_ROWS_PER_FRAME, JellyPatchDecoder,
    JellyPatchDecoderOptions, JellyPatchEncoder, JellyPatchEncoderOptions, PATCH_PROTOCOL_VERSION,
    PatchOp,
};
