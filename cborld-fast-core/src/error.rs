// Rust guideline compliant 2026-02-21
//! Closed error surface for the CBOR-LD codec.

use thiserror::Error;

/// Resource governed by a fail-closed CBOR-LD limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CborldResource {
    /// Encoded input bytes accepted by the decoder.
    InputBytes,
    /// Nesting depth of CBOR items or JSON values.
    Depth,
    /// Total CBOR data items decoded from one payload.
    Items,
    /// Byte length of one compressed value codec payload (base58/base64).
    ValueBytes,
    /// Bytes materialized or copied while decompressing one payload.
    OutputBytes,
    /// Base58 reconstruction work (squared value lengths) in one payload.
    Base58Work,
}

impl CborldResource {
    /// Stable machine-readable resource name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputBytes => "input_bytes",
            Self::Depth => "depth",
            Self::Items => "items",
            Self::ValueBytes => "value_bytes",
            Self::OutputBytes => "output_bytes",
            Self::Base58Work => "base58_work",
        }
    }
}

impl std::fmt::Display for CborldResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Closed error surface for CBOR encoding, decoding, and CBOR-LD conversion.
#[derive(Debug, Error)]
pub enum CborldError {
    /// An input-byte, depth, or item budget was exceeded.
    #[error("resource_limit: {resource}: observed {observed} exceeds limit {limit}")]
    ResourceLimit {
        /// Governed resource.
        resource: CborldResource,
        /// Configured inclusive limit.
        limit: usize,
        /// First observed value beyond the limit.
        observed: usize,
    },
    /// The input bytes are not well-formed CBOR under this crate's subset.
    #[error("cbor_decode: at byte {offset}: {detail}")]
    Decode {
        /// Byte offset where the malformed construct starts.
        offset: usize,
        /// Human-readable description of the malformed construct.
        detail: String,
    },
    /// A value cannot be encoded as canonical CBOR.
    #[error("cbor_encode: {0}")]
    Encode(String),
    /// The payload is not a CBOR-LD envelope of the vendored shape.
    #[error("envelope: {0}")]
    Envelope(String),
    /// The envelope names a CBOR-LD registry entry this crate does not vendor.
    #[error("unknown_registry_entry: registry entry id {id} is not supported")]
    UnknownRegistryEntry {
        /// Registry entry identifier found in the envelope.
        id: u64,
    },
    /// A vendored registry entry is provisional and was not opted in to.
    #[error(
        "provisional_registry_entry: registry entry id {id} ({domain}) is \
         marked provisional upstream and must be accepted explicitly"
    )]
    ProvisionalRegistryEntry {
        /// Registry entry identifier found in the envelope or the options.
        id: u64,
        /// Use case recorded for the entry in the vendored registry.
        domain: &'static str,
    },
    /// A compressed context identifier has no entry in the `context` table.
    #[error(
        "unknown_compressed_context: context id {id} has no entry in the \
         context table of registry entry {registry_entry_id}"
    )]
    UnknownCompressedContext {
        /// Compressed context identifier found on the wire.
        id: u64,
        /// Registry entry whose tables were consulted.
        registry_entry_id: u64,
    },
    /// A compressed value identifier has no entry in its typed sub-table.
    #[error(
        "unknown_compressed_value: identifier {id} has no entry in the \
         {table_type} table of registry entry {registry_entry_id}"
    )]
    UnknownCompressedValue {
        /// Compressed value identifier found on the wire.
        id: u64,
        /// Sub-table type consulted (`url` or a JSON-LD type IRI).
        table_type: String,
        /// Registry entry whose tables were consulted.
        registry_entry_id: u64,
    },
    /// An `@context` value is a remote context reference, which is refused.
    #[error("unregistered_context: remote context {iri} is refused (no network I/O)")]
    UnregisteredContext {
        /// IRI of the remote context that would require fetching.
        iri: String,
    },
    /// A compressed term identifier has no entry in the derived term map.
    #[error("unknown_term_id: term id {id} has no entry in the term map")]
    UnknownTermId {
        /// Undefined compressed term identifier.
        id: u64,
    },
    /// A spec feature outside this crate's vendored subset was encountered.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The JSON-LD document violates the subset accepted by this codec.
    #[error("document: {0}")]
    Document(String),
    /// A decoded number cannot be represented as a JSON number.
    #[error("number_range: {0}")]
    NumberRange(String),
}

impl CborldError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ResourceLimit { .. } => "resource_limit",
            Self::Decode { .. } => "cbor_decode",
            Self::Encode(_) => "cbor_encode",
            Self::Envelope(_) => "envelope",
            Self::UnknownRegistryEntry { .. } => "unknown_registry_entry",
            Self::ProvisionalRegistryEntry { .. } => "provisional_registry_entry",
            Self::UnknownCompressedContext { .. } => "unknown_compressed_context",
            Self::UnknownCompressedValue { .. } => "unknown_compressed_value",
            Self::UnregisteredContext { .. } => "unregistered_context",
            Self::UnknownTermId { .. } => "unknown_term_id",
            Self::Unsupported(_) => "unsupported",
            Self::Document(_) => "document",
            Self::NumberRange(_) => "number_range",
        }
    }
}
