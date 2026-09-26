// Rust guideline compliant 2026-02-21
//! Closed error surface for the Jelly frame codec.

use quad_fast_core::QuadError;
use thiserror::Error;

/// Lookup table governed by a fail-closed Jelly size limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JellyResource {
    /// Prefix lookup table entries.
    PrefixTable,
    /// Name lookup table entries.
    NameTable,
    /// Datatype lookup table entries.
    DatatypeTable,
    /// RDF 1.2 triple-term nesting depth.
    QuotedDepth,
}

impl JellyResource {
    /// Stable machine-readable resource name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrefixTable => "prefix_table",
            Self::NameTable => "name_table",
            Self::DatatypeTable => "datatype_table",
            Self::QuotedDepth => "quoted_depth",
        }
    }
}

impl std::fmt::Display for JellyResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Closed error surface for encoding and decoding Jelly stream frames.
///
/// Every variant carries a stable machine-readable code as the first token
/// of its rendered message; [`JellyError::code`] returns the same token.
#[derive(Debug, Error)]
pub enum JellyError {
    /// A protocol feature this codec explicitly refuses (never skips).
    #[error("unsupported: {feature}: {detail}")]
    Unsupported {
        /// Stable feature name (e.g., `rdf_star_non_object`,
        /// `physical_type_graphs`).
        feature: &'static str,
        /// Human-readable explanation of the refusal.
        detail: String,
    },
    /// Stream options are missing, duplicated, or invalid.
    #[error("options: {0}")]
    Options(String),
    /// A declared lookup table size, or an observed triple-term nesting
    /// depth, exceeds the configured maximum.
    #[error("resource_limit: {resource}: declared {observed} exceeds limit {limit}")]
    ResourceLimit {
        /// Governed lookup table.
        resource: JellyResource,
        /// Configured inclusive limit.
        limit: u32,
        /// Declared value beyond the limit.
        observed: u32,
    },
    /// A lookup table identifier is out of range, unset, or misused.
    #[error("lookup: {0}")]
    Lookup(String),
    /// A stream row violates frame structure or row-ordering rules.
    #[error("frame: {0}")]
    Frame(String),
    /// A decoded value is not a valid RDF term of its declared kind.
    #[error("term: {0}")]
    Term(String),
    /// The underlying `UnsignedQuadStream` contract rejected an operation.
    #[error("quad: {0}")]
    Quad(#[from] QuadError),
}

impl JellyError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "unsupported",
            Self::Options(_) => "options",
            Self::ResourceLimit { .. } => "resource_limit",
            Self::Lookup(_) => "lookup",
            Self::Frame(_) => "frame",
            Self::Term(_) => "term",
            Self::Quad(_) => "quad",
        }
    }
}
