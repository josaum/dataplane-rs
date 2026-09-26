// Rust guideline compliant 2026-02-21
//! `UnsignedQuadStream` v1: Arrow-native RDF quad batches with provenance.
//!
//! This crate is the convergence point of the semantic dataplane. Every codec
//! (JSON-LD, CBOR-LD, Jelly, Arrow Flight) produces and consumes the single
//! Arrow contract defined here. The in-memory term model is [`oxrdf`], the
//! same model used by `office-parsers-rs/owl-fast-core`.
//!
//! Batches produced by this crate are **unsigned by construction**: encoding
//! preserves term identity, named-graph identity, and source provenance, but
//! never certifies a source, approves a rule, or promotes a fact (Atlas
//! product invariant 7). The schema carries `atlas.assurance = "unsigned"`
//! metadata so downstream planes cannot mistake codec output for governed
//! facts. [`UnsignedQuadBatch`] is the sealed share unit: [`Clone`] aliases
//! Arrow buffers and is not a signature.
//!
//! # RDF 1.2 triple terms
//!
//! The contract carries RDF 1.2 triple terms (RDF-star) in the **object**
//! position under `object_kind = "triple"`, serialized into `object_value`
//! by [`quoted`]. Subject, predicate, and graph positions never hold one:
//! [`oxrdf`]'s RDF 1.2 term model does not admit them there. The Arrow schema
//! and `atlas.contract_version = "1"` are unchanged, so batches written
//! before this extension decode unchanged. Triple-term rows are only
//! reachable through [`QuadStreamReader::quad_owned`]; the zero-copy
//! [`QuadStreamReader::quad`] refuses them with a typed
//! [`QuadError::Unsupported`] rather than borrowing a triple that has no home
//! in the Arrow buffers.
//!
//! # Examples
//!
//! ```
//! use oxrdf::{NamedNode, Quad};
//! use quad_fast_core::{QuadBatchBuilder, QuadLimits, QuadStreamReader};
//!
//! # fn main() -> Result<(), quad_fast_core::QuadError> {
//! let quad = Quad::new(
//!     NamedNode::new("http://example.com/s").unwrap(),
//!     NamedNode::new("http://example.com/p").unwrap(),
//!     NamedNode::new("http://example.com/o").unwrap(),
//!     oxrdf::GraphName::DefaultGraph,
//! );
//!
//! let mut builder = QuadBatchBuilder::new(QuadLimits::default());
//! builder.push(quad.as_ref(), None)?;
//! let batch = builder.finish()?;
//!
//! let reader = QuadStreamReader::new(&batch)?;
//! let decoded = reader.quad(0)?;
//! assert_eq!(decoded, quad.as_ref());
//! # Ok(())
//! # }
//! ```

mod batch;
mod builder;
mod error;
mod ipc;
pub mod quoted;
mod reader;
mod schema;

pub use batch::UnsignedQuadBatch;
pub use builder::{
    DEFAULT_MAX_QUADS, DEFAULT_MAX_QUOTED_DEPTH, DEFAULT_MAX_RETAINED_TERM_BYTES, QuadBatchBuilder,
    QuadLimits, SourceProvenance,
};
pub use error::{FEATURE_BASE_DIRECTION, FEATURE_TRIPLE_TERM, QuadError, QuadResource};
pub use ipc::{DEFAULT_MAX_IPC_BYTES, read_ipc_stream, write_ipc_stream};
pub use quoted::{TERM_KIND_TRIPLE, encode_triple_term, parse_triple_term, term_depth};
pub use reader::{ProvenanceRef, QuadStreamReader};
pub use schema::{
    CONTRACT_NAME, CONTRACT_VERSION, GRAPH_KIND_BNODE, GRAPH_KIND_DEFAULT, GRAPH_KIND_IRI,
    TERM_KIND_BNODE, TERM_KIND_IRI, TERM_KIND_LITERAL, quad_stream_schema, validate_contract,
};
