// Rust guideline compliant 2026-02-21
//! Closed error surface for the JSON-LD codec.

use quad_fast_core::QuadError;
use thiserror::Error;

/// Resource governed by a fail-closed JSON-LD processing limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonLdResource {
    /// Raw UTF-8 input bytes accepted by [`crate::parse_document`].
    InputBytes,
    /// JSON values visited during expansion.
    Nodes,
    /// Nesting depth reached during expansion.
    Depth,
    /// Native recursion depth reached while processing a `@context`.
    ///
    /// Governed by [`crate::MAX_CONTEXT_RECURSION`], not by
    /// [`crate::JsonLdLimits`]: the recursion follows the *contents* of a
    /// context (a scoped context, or a prefix chain in flat JSON), which
    /// the document-nesting budget cannot observe.
    ContextRecursion,
    /// Nesting of embedded nodes reached while framing.
    ///
    /// Governed by [`crate::MAX_FRAME_EMBED_DEPTH`]: embedding follows
    /// references in the node map, so a flat document of chained nodes
    /// embeds as deep as the chain is long.
    EmbedDepth,
    /// Bytes of strings produced by expansion (keys, IRIs, values).
    ///
    /// Governed by [`crate::JsonLdLimits::max_output_bytes`]: a term that
    /// expands to a long IRI multiplies the input by every use.
    OutputBytes,
}

impl JsonLdResource {
    /// Stable machine-readable resource name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputBytes => "input_bytes",
            Self::Nodes => "nodes",
            Self::Depth => "depth",
            Self::ContextRecursion => "context_recursion",
            Self::EmbedDepth => "embed_depth",
            Self::OutputBytes => "output_bytes",
        }
    }
}

impl std::fmt::Display for JsonLdResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// JSON-LD 1.1 / JSON-LD-star feature this processor refuses to process.
///
/// Refusal is explicit and fail-closed: encountering one of these features
/// aborts processing with [`JsonLdError::UnsupportedFeature`], never a
/// silent skip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonLdFeature {
    /// A quoted triple in subject, predicate, or graph position.
    ///
    /// Object-position triple terms round-trip through JSON-LD-star
    /// embedded nodes (`{"@id": {embedded node}}`). The `UnsignedQuadStream`
    /// subject model has no triple variant, so a quoted triple used as a
    /// subject (classic annotation, or `@annotation` with forward
    /// properties) is refused by name instead of being reified.
    RdfStarTripleTerm,
}

impl JsonLdFeature {
    /// Stable machine-readable feature name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RdfStarTripleTerm => "rdf12_triple_term",
        }
    }
}

impl std::fmt::Display for JsonLdFeature {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Closed error surface for JSON-LD parsing, expansion, and RDF conversion.
#[derive(Debug, Error)]
pub enum JsonLdError {
    /// A fail-closed processing budget was exceeded.
    #[error("resource_limit: {resource}: observed {observed} exceeds limit {limit}")]
    ResourceLimit {
        /// Governed resource.
        resource: JsonLdResource,
        /// Configured inclusive limit.
        limit: usize,
        /// First observed value beyond the limit.
        observed: usize,
    },
    /// A remote context reference was refused (sovereign boundary).
    ///
    /// Parsers in this dataplane perform no network I/O. A context given as
    /// a string, or an `@import` entry, names a document that would have to
    /// be fetched; it is refused with the offending IRI, never fetched and
    /// never skipped.
    #[error("remote_context_refused: refusing to fetch remote context `{iri}`")]
    RemoteContextRefused {
        /// The context IRI that would have required a network fetch.
        iri: String,
    },
    /// A JSON-LD 1.1 feature outside the supported set was found.
    #[error("unsupported_feature: `{feature}` is outside the supported subset")]
    UnsupportedFeature {
        /// Refused feature.
        feature: JsonLdFeature,
    },
    /// A `@protected` term definition would be overridden or nullified.
    #[error("protected_term: term `{term}` is protected and cannot be redefined")]
    ProtectedTermRedefinition {
        /// The protected term.
        term: String,
    },
    /// A `@context` value or term definition is malformed.
    #[error("invalid_context: {0}")]
    InvalidContext(String),
    /// The document body is malformed JSON-LD.
    #[error("invalid_document: {0}")]
    InvalidDocument(String),
    /// An IRI stayed relative after expansion and cannot become an RDF term.
    ///
    /// The JSON-LD 1.1 API drops such nodes silently; this codec fails
    /// closed instead so no data disappears without a diagnostic.
    #[error("relative_iri: `{iri}` is still relative after expansion")]
    RelativeIri {
        /// The relative IRI reference.
        iri: String,
    },
    /// A value cannot become a valid RDF term (IRI, blank node, or literal).
    #[error("invalid_term: {0}")]
    InvalidTerm(String),
    /// A frame is malformed (the Framing spec's `invalid frame` error).
    ///
    /// Mirrors the `invalid frame` error code of JSON-LD 1.1 Framing
    /// section 6 (`JsonLdFramingErrorCode`): the frame is not a map, or a
    /// frame entry does not follow the frame grammar.
    #[error("invalid_frame: {0}")]
    InvalidFrame(String),
    /// An `@embed` entry holds an unsupported value.
    ///
    /// Mirrors the `invalid @embed value` error code of JSON-LD 1.1 Framing
    /// section 6. Accepted values: `@once`, `@always`, `@never`, `true`
    /// (`@once`), and `false` (`@never`).
    #[error("invalid_embed_value: `{value}` is not a valid @embed value")]
    InvalidEmbedValue {
        /// The rejected `@embed` value, rendered as JSON.
        value: String,
    },
    /// The input text is not valid JSON.
    #[error("invalid_json: {0}")]
    InvalidJson(String),
    /// A JSON-LD Streaming Note document has keys out of required order.
    ///
    /// Mirrors the `invalid streaming key order` error of
    /// <https://w3c.github.io/json-ld-streaming/>: `@context` (if present)
    /// must be first, `@type` (if present) must precede every other
    /// property. Nested maps under `@context` are exempt — the Note's own
    /// valid examples put `@id` before `@context` inside term definitions.
    #[error("invalid_streaming_key_order: {0}")]
    InvalidStreamingKeyOrder(String),
    /// A YAML-LD stream is not UTF-8 (`invalid-encoding`).
    #[error("invalid_encoding: YAML-LD streams must be UTF-8")]
    YamlInvalidEncoding,
    /// A YAML mapping key is not a string (`mapping-key-error`).
    #[error("mapping_key_error: {0}")]
    YamlMappingKey(String),
    /// A YAML-LD profile constraint was violated (`profile-error`).
    ///
    /// Basic forbids alias nodes. Extended allows aliases (copy on compose,
    /// no cycles) and IRI tags as RDF literal datatypes; local `!foo` tags
    /// that are not IRIs still fail closed here rather than inventing a
    /// datatype IRI.
    #[error("profile_error: {0}")]
    YamlProfile(String),
    /// YAML composition or JSON conversion failed (`loading-document-failed`).
    #[error("loading_document_failed: {0}")]
    YamlLoadFailed(String),
    /// A worker thread for deep input could not be started.
    ///
    /// Inputs nested (or framed) deeper than the inline threshold are
    /// processed on a short-lived thread whose stack is sized for their
    /// depth. Where threads are unavailable (for example `wasm32`) or the
    /// address space is capped, the spawn fails and the input is refused
    /// rather than recursed on a stack that was never sized for it.
    #[error(
        "worker_unavailable: could not start a worker thread with a {stack_bytes}-byte stack \
         for depth {depth}"
    )]
    WorkerUnavailable {
        /// Stack size requested for the worker, in bytes.
        stack_bytes: usize,
        /// Nesting (or embed) depth that needed the worker.
        depth: usize,
    },
    /// The underlying quad contract rejected an operation.
    #[error("quad: {0}")]
    Quad(#[from] QuadError),
}

impl JsonLdError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ResourceLimit { .. } => "resource_limit",
            Self::RemoteContextRefused { .. } => "remote_context_refused",
            Self::UnsupportedFeature { .. } => "unsupported_feature",
            Self::ProtectedTermRedefinition { .. } => "protected_term",
            Self::InvalidContext(_) => "invalid_context",
            Self::InvalidDocument(_) => "invalid_document",
            Self::RelativeIri { .. } => "relative_iri",
            Self::InvalidTerm(_) => "invalid_term",
            Self::InvalidFrame(_) => "invalid_frame",
            Self::InvalidEmbedValue { .. } => "invalid_embed_value",
            Self::InvalidJson(_) => "invalid_json",
            Self::InvalidStreamingKeyOrder(_) => "invalid_streaming_key_order",
            Self::YamlInvalidEncoding => "invalid_encoding",
            Self::YamlMappingKey(_) => "mapping_key_error",
            Self::YamlProfile(_) => "profile_error",
            Self::YamlLoadFailed(_) => "loading_document_failed",
            Self::WorkerUnavailable { .. } => "worker_unavailable",
            Self::Quad(_) => "quad",
        }
    }
}
