// Rust guideline compliant 2026-02-21
//! Closed error surface for the quad contract.

use thiserror::Error;

/// Resource governed by a fail-closed quad limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuadResource {
    /// Quads accepted into one batch.
    Quads,
    /// Aggregate bytes retained by term lexical forms in one batch.
    RetainedTermBytes,
    /// Encoded Arrow IPC bytes.
    IpcBytes,
    /// Nesting depth of an RDF 1.2 triple term.
    QuotedDepth,
}

impl QuadResource {
    /// Stable machine-readable resource name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quads => "quads",
            Self::RetainedTermBytes => "retained_term_bytes",
            Self::IpcBytes => "ipc_bytes",
            Self::QuotedDepth => "quoted_depth",
        }
    }
}

impl std::fmt::Display for QuadResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Closed error surface for building, reading, and transporting quad batches.
#[derive(Debug, Error)]
pub enum QuadError {
    /// A quad, retained-term, or IPC budget was exceeded.
    #[error("resource_limit: {resource}: observed {observed} exceeds limit {limit}")]
    ResourceLimit {
        /// Governed resource.
        resource: QuadResource,
        /// Configured inclusive limit.
        limit: usize,
        /// First observed value beyond the limit.
        observed: usize,
    },
    /// The batch does not satisfy the `UnsignedQuadStream` contract.
    #[error("contract: {0}")]
    Contract(String),
    /// A contract feature this API surface cannot represent.
    ///
    /// Raised instead of dropping or mangling data: the zero-copy read path
    /// cannot hand out a borrowed RDF 1.2 triple term (the nested triple has
    /// no home in the Arrow buffers), and downstream models that have no
    /// triple-term concept refuse rows carrying one.
    #[error("unsupported: {feature}: {detail}")]
    Unsupported {
        /// Stable feature name (e.g., `rdf12_triple_term`).
        feature: &'static str,
        /// Human-readable explanation of the refusal.
        detail: String,
    },
    /// A stored term is not a valid RDF term of its declared kind.
    #[error("term: {0}")]
    Term(String),
    /// Arrow IPC encoding or decoding failed.
    #[error("ipc: {0}")]
    Ipc(String),
    /// The underlying Arrow kernel rejected an operation.
    #[error("arrow: {0}")]
    Arrow(String),
}

/// Stable feature name used by every RDF 1.2 triple-term refusal.
///
/// Consumers whose target model has no triple-term concept refuse rows with
/// this name so operators can grep one token across planes.
pub const FEATURE_TRIPLE_TERM: &str = "rdf12_triple_term";

/// Stable feature name used by every RDF 1.2 base-direction refusal.
///
/// The `UnsignedQuadStream` v1 object columns carry a lexical form, a
/// datatype IRI, and a language tag. An RDF 1.2 *directional* language-tagged
/// string ([`oxrdf::Literal::direction`]) additionally carries `ltr`/`rtl`,
/// which has no column, and the schema is frozen at
/// [`crate::CONTRACT_VERSION`]. Storing one through the flat columns would
/// drop the direction *silently*, so it is refused instead — the same
/// fail-closed posture as [`FEATURE_TRIPLE_TERM`]. Directional literals
/// nested inside a triple term are unaffected: that encoding is a full
/// N-Triples serialization and carries `--ltr`/`--rtl` losslessly (see
/// [`crate::quoted`]).
pub const FEATURE_BASE_DIRECTION: &str = "rdf12_base_direction";

impl QuadError {
    /// Builds the shared refusal for an RDF 1.2 triple term.
    ///
    /// `detail` should name the surface that cannot represent it.
    #[must_use]
    pub fn triple_term_unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            feature: FEATURE_TRIPLE_TERM,
            detail: detail.into(),
        }
    }

    /// Builds the shared refusal for an RDF 1.2 base direction.
    ///
    /// `detail` should name the surface that cannot represent it.
    #[must_use]
    pub fn base_direction_unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            feature: FEATURE_BASE_DIRECTION,
            detail: detail.into(),
        }
    }

    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ResourceLimit { .. } => "resource_limit",
            Self::Contract(_) => "contract",
            Self::Unsupported { .. } => "unsupported",
            Self::Term(_) => "term",
            Self::Ipc(_) => "ipc",
            Self::Arrow(_) => "arrow",
        }
    }
}
