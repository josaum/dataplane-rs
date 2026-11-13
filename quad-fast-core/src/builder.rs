// Rust guideline compliant 2026-02-21
//! Fail-closed construction of `UnsignedQuadStream` batches.

use std::{borrow::Cow, sync::Arc};

use arrow_array::{
    ArrayRef, RecordBatch,
    builder::{
        FixedSizeBinaryBuilder, StringBuilder, StringDictionaryBuilder,
        TimestampMicrosecondBuilder, UInt64Builder,
    },
    types::UInt32Type,
};
use oxrdf::{GraphNameRef, NamedOrBlankNodeRef, QuadRef, TermRef};

use crate::{
    error::{QuadError, QuadResource},
    quoted::{TERM_KIND_TRIPLE, check_depth, encode_triple_term},
    schema::{
        GRAPH_KIND_BNODE, GRAPH_KIND_DEFAULT, GRAPH_KIND_IRI, TERM_KIND_BNODE, TERM_KIND_IRI,
        TERM_KIND_LITERAL, quad_stream_schema,
    },
};

/// Default maximum quads per batch.
///
/// Sized so one batch stays comfortably within a single Flight/gRPC message
/// while amortizing per-batch overhead; matches the order of magnitude of
/// `owl-fast-core` statement budgets.
pub const DEFAULT_MAX_QUADS: usize = 1_048_576;

/// Default aggregate retained term budget per batch: 64 MiB.
///
/// Same default as `owl-fast-core::DEFAULT_MAX_RETAINED_TERM_BYTES` so both
/// parser planes fail closed at the same scale.
pub const DEFAULT_MAX_RETAINED_TERM_BYTES: usize = 64 * 1024 * 1024;

pub use crate::quoted::DEFAULT_MAX_QUOTED_DEPTH;

/// Fail-closed limits for one quad batch.
#[derive(Clone, Copy, Debug)]
pub struct QuadLimits {
    /// Maximum quads accepted into the batch.
    pub max_quads: usize,
    /// Maximum aggregate bytes retained by term lexical forms.
    pub max_retained_term_bytes: usize,
    /// Maximum RDF 1.2 triple-term nesting depth in an object position.
    ///
    /// Depth 0 forbids triple terms outright; the default
    /// ([`DEFAULT_MAX_QUOTED_DEPTH`]) admits them. Enforced on both the
    /// write path ([`QuadBatchBuilder::push`]) and the read path
    /// ([`crate::QuadStreamReader::quad_owned`]).
    pub max_quoted_depth: usize,
}

impl Default for QuadLimits {
    fn default() -> Self {
        Self {
            max_quads: DEFAULT_MAX_QUADS,
            max_retained_term_bytes: DEFAULT_MAX_RETAINED_TERM_BYTES,
            max_quoted_depth: DEFAULT_MAX_QUOTED_DEPTH,
        }
    }
}

/// Immutable source provenance attached to a quad.
///
/// Provenance is carried, never certified: attaching it does not sign the
/// quad.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceProvenance {
    /// IRI of the source artifact the quad was decoded from.
    pub source_artifact_iri: Option<String>,
    /// SHA-256 of the exact source bytes.
    pub source_content_sha256: Option<[u8; 32]>,
    /// Byte offset where the quad's encoding starts in the source.
    pub source_offset_start: Option<u64>,
    /// Byte offset where the quad's encoding ends in the source.
    pub source_offset_end: Option<u64>,
    /// Microseconds since the Unix epoch (UTC) when the quad was observed.
    pub observed_at_micros: Option<i64>,
}

/// Builds one `UnsignedQuadStream` batch with fail-closed limits.
pub struct QuadBatchBuilder {
    limits: QuadLimits,
    quads: usize,
    retained_term_bytes: usize,
    subject_kind: StringDictionaryBuilder<UInt32Type>,
    subject_value: StringDictionaryBuilder<UInt32Type>,
    predicate_iri: StringDictionaryBuilder<UInt32Type>,
    object_kind: StringDictionaryBuilder<UInt32Type>,
    object_value: StringBuilder,
    object_datatype: StringDictionaryBuilder<UInt32Type>,
    object_language: StringDictionaryBuilder<UInt32Type>,
    graph_kind: StringDictionaryBuilder<UInt32Type>,
    graph_value: StringDictionaryBuilder<UInt32Type>,
    source_artifact: StringDictionaryBuilder<UInt32Type>,
    source_sha256: FixedSizeBinaryBuilder,
    source_offset_start: UInt64Builder,
    source_offset_end: UInt64Builder,
    observed_at: TimestampMicrosecondBuilder,
}

impl std::fmt::Debug for QuadBatchBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuadBatchBuilder")
            .field("limits", &self.limits)
            .field("quads", &self.quads)
            .field("retained_term_bytes", &self.retained_term_bytes)
            .finish_non_exhaustive()
    }
}

fn arrow_err(error: arrow_schema::ArrowError) -> QuadError {
    QuadError::Arrow(error.to_string())
}

fn append_dict(
    builder: &mut StringDictionaryBuilder<UInt32Type>,
    value: &str,
) -> Result<(), QuadError> {
    builder.append(value).map(|_| ()).map_err(arrow_err)
}

fn append_dict_opt(
    builder: &mut StringDictionaryBuilder<UInt32Type>,
    value: Option<&str>,
) -> Result<(), QuadError> {
    match value {
        Some(value) => append_dict(builder, value),
        None => {
            builder.append_null();
            Ok(())
        }
    }
}

impl QuadBatchBuilder {
    /// Creates an empty builder governed by `limits`.
    ///
    /// Reserves Arrow's default column capacity (1,024 rows per column,
    /// about 130 KiB); use [`QuadBatchBuilder::with_capacity`] when many
    /// small batches are built.
    #[must_use]
    pub fn new(limits: QuadLimits) -> Self {
        Self {
            limits,
            quads: 0,
            retained_term_bytes: 0,
            subject_kind: StringDictionaryBuilder::new(),
            subject_value: StringDictionaryBuilder::new(),
            predicate_iri: StringDictionaryBuilder::new(),
            object_kind: StringDictionaryBuilder::new(),
            object_value: StringBuilder::new(),
            object_datatype: StringDictionaryBuilder::new(),
            object_language: StringDictionaryBuilder::new(),
            graph_kind: StringDictionaryBuilder::new(),
            graph_value: StringDictionaryBuilder::new(),
            source_artifact: StringDictionaryBuilder::new(),
            source_sha256: FixedSizeBinaryBuilder::new(32),
            source_offset_start: UInt64Builder::new(),
            source_offset_end: UInt64Builder::new(),
            observed_at: TimestampMicrosecondBuilder::new().with_timezone("UTC"),
        }
    }

    /// Creates an empty builder that reserves room for `capacity` quads.
    ///
    /// Columns grow on demand past `capacity`, so a small value only costs
    /// reallocations when the batch turns out large; it never limits the
    /// batch (that is `limits`' job).
    #[must_use]
    pub fn with_capacity(limits: QuadLimits, capacity: usize) -> Self {
        Self {
            limits,
            quads: 0,
            retained_term_bytes: 0,
            subject_kind: StringDictionaryBuilder::with_capacity(capacity, 2, 8),
            subject_value: StringDictionaryBuilder::with_capacity(capacity, capacity, 0),
            predicate_iri: StringDictionaryBuilder::with_capacity(capacity, capacity, 0),
            object_kind: StringDictionaryBuilder::with_capacity(capacity, 4, 16),
            object_value: StringBuilder::with_capacity(capacity, 0),
            object_datatype: StringDictionaryBuilder::with_capacity(capacity, capacity, 0),
            object_language: StringDictionaryBuilder::with_capacity(capacity, capacity, 0),
            graph_kind: StringDictionaryBuilder::with_capacity(capacity, 3, 16),
            graph_value: StringDictionaryBuilder::with_capacity(capacity, capacity, 0),
            source_artifact: StringDictionaryBuilder::with_capacity(capacity, 1, 0),
            source_sha256: FixedSizeBinaryBuilder::with_capacity(capacity, 32),
            source_offset_start: UInt64Builder::with_capacity(capacity),
            source_offset_end: UInt64Builder::with_capacity(capacity),
            observed_at: TimestampMicrosecondBuilder::with_capacity(capacity).with_timezone("UTC"),
        }
    }

    /// Number of quads accepted so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.quads
    }

    /// Returns `true` when no quad has been accepted yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.quads == 0
    }

    /// Appends one quad with optional source provenance.
    ///
    /// Language-tagged literals store the language and a null datatype (the
    /// datatype is implied to be `rdf:langString`); all other literals store
    /// their datatype IRI exactly as reported by [`oxrdf`], including
    /// `xsd:string` for simple literals. An RDF 1.2 *directional*
    /// language-tagged string in the object position is refused with
    /// [`crate::FEATURE_BASE_DIRECTION`]: the v1 columns have no slot for
    /// `ltr`/`rtl`, so accepting one would drop the direction silently. The
    /// same literal nested inside a triple term is accepted, because that
    /// encoding is a full N-Triples serialization (see [`crate::quoted`]).
    ///
    /// An RDF 1.2 triple term in the object position is serialized into
    /// `object_value` under `object_kind = "triple"` (see [`crate::quoted`]);
    /// its nesting depth is bounded by
    /// [`QuadLimits::max_quoted_depth`]. Triple terms cannot occur in the
    /// subject, predicate, or graph position — the [`oxrdf`] term model does
    /// not admit them there, matching RDF 1.2 Concepts.
    ///
    /// # Errors
    ///
    /// Returns [`QuadError::ResourceLimit`] when the quad, retained-term, or
    /// triple-term depth budget would be exceeded,
    /// [`QuadError::Unsupported`] (feature
    /// [`crate::FEATURE_BASE_DIRECTION`]) for a directional language-tagged
    /// object, and [`QuadError::Arrow`] when the underlying Arrow builders
    /// reject a value.
    pub fn push(
        &mut self,
        quad: QuadRef<'_>,
        provenance: Option<&SourceProvenance>,
    ) -> Result<(), QuadError> {
        if self.quads + 1 > self.limits.max_quads {
            return Err(QuadError::ResourceLimit {
                resource: QuadResource::Quads,
                limit: self.limits.max_quads,
                observed: self.quads + 1,
            });
        }

        let (subject_kind, subject_value) = match quad.subject {
            NamedOrBlankNodeRef::NamedNode(node) => (TERM_KIND_IRI, node.as_str()),
            NamedOrBlankNodeRef::BlankNode(node) => (TERM_KIND_BNODE, node.as_str()),
        };
        let predicate = quad.predicate.as_str();
        let (object_kind, object_value, object_datatype, object_language): (
            &str,
            Cow<'_, str>,
            Option<&str>,
            Option<&str>,
        ) = match quad.object {
            TermRef::NamedNode(node) => (TERM_KIND_IRI, Cow::Borrowed(node.as_str()), None, None),
            TermRef::BlankNode(node) => (TERM_KIND_BNODE, Cow::Borrowed(node.as_str()), None, None),
            TermRef::Literal(literal) => {
                // RDF 1.2 directional language-tagged string: the contract's
                // object columns have no slot for `ltr`/`rtl`, and the schema
                // is frozen at v1. Refuse rather than store the literal
                // shorn of its direction.
                if literal.direction().is_some() {
                    return Err(QuadError::base_direction_unsupported(
                        "UnsignedQuadStream v1 object columns carry a lexical form, a datatype, \
                         and a language tag, with no slot for an RDF 1.2 base direction; storing \
                         one here would drop it silently",
                    ));
                }
                match literal.language() {
                    Some(language) => (
                        TERM_KIND_LITERAL,
                        Cow::Borrowed(literal.value()),
                        None,
                        Some(language),
                    ),
                    None => (
                        TERM_KIND_LITERAL,
                        Cow::Borrowed(literal.value()),
                        Some(literal.datatype().as_str()),
                        None,
                    ),
                }
            }
            // RDF 1.2 triple term: serialized into `object_value` with a
            // null datatype and language. Depth is bounded before the
            // recursive serializer runs.
            TermRef::Triple(triple) => {
                check_depth(quad.object, self.limits.max_quoted_depth)?;
                (
                    TERM_KIND_TRIPLE,
                    Cow::Owned(encode_triple_term(triple.as_ref())),
                    None,
                    None,
                )
            }
        };
        let (graph_kind, graph_value) = match quad.graph_name {
            GraphNameRef::DefaultGraph => (GRAPH_KIND_DEFAULT, None),
            GraphNameRef::NamedNode(node) => (GRAPH_KIND_IRI, Some(node.as_str())),
            GraphNameRef::BlankNode(node) => (GRAPH_KIND_BNODE, Some(node.as_str())),
        };

        let retained = subject_value.len()
            + predicate.len()
            + object_value.len()
            + object_datatype.map_or(0, str::len)
            + object_language.map_or(0, str::len)
            + graph_value.map_or(0, str::len);
        let observed = self.retained_term_bytes + retained;
        if observed > self.limits.max_retained_term_bytes {
            return Err(QuadError::ResourceLimit {
                resource: QuadResource::RetainedTermBytes,
                limit: self.limits.max_retained_term_bytes,
                observed,
            });
        }

        append_dict(&mut self.subject_kind, subject_kind)?;
        append_dict(&mut self.subject_value, subject_value)?;
        append_dict(&mut self.predicate_iri, predicate)?;
        append_dict(&mut self.object_kind, object_kind)?;
        self.object_value.append_value(object_value.as_ref());
        append_dict_opt(&mut self.object_datatype, object_datatype)?;
        append_dict_opt(&mut self.object_language, object_language)?;
        append_dict(&mut self.graph_kind, graph_kind)?;
        append_dict_opt(&mut self.graph_value, graph_value)?;

        let provenance_default = SourceProvenance::default();
        let provenance = provenance.unwrap_or(&provenance_default);
        append_dict_opt(
            &mut self.source_artifact,
            provenance.source_artifact_iri.as_deref(),
        )?;
        match provenance.source_content_sha256 {
            Some(digest) => self.source_sha256.append_value(digest).map_err(arrow_err)?,
            None => self.source_sha256.append_null(),
        }
        self.source_offset_start
            .append_option(provenance.source_offset_start);
        self.source_offset_end
            .append_option(provenance.source_offset_end);
        self.observed_at
            .append_option(provenance.observed_at_micros);

        self.quads += 1;
        self.retained_term_bytes = observed;
        Ok(())
    }

    /// Finishes the batch under the `UnsignedQuadStream` v1 schema.
    ///
    /// # Errors
    ///
    /// Returns [`QuadError::Arrow`] when batch assembly fails; this signals
    /// an internal builder inconsistency and should not occur for inputs
    /// accepted by [`QuadBatchBuilder::push`].
    pub fn finish(mut self) -> Result<RecordBatch, QuadError> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.subject_kind.finish()),
            Arc::new(self.subject_value.finish()),
            Arc::new(self.predicate_iri.finish()),
            Arc::new(self.object_kind.finish()),
            Arc::new(self.object_value.finish()),
            Arc::new(self.object_datatype.finish()),
            Arc::new(self.object_language.finish()),
            Arc::new(self.graph_kind.finish()),
            Arc::new(self.graph_value.finish()),
            Arc::new(self.source_artifact.finish()),
            Arc::new(self.source_sha256.finish()),
            Arc::new(self.source_offset_start.finish()),
            Arc::new(self.source_offset_end.finish()),
            Arc::new(self.observed_at.finish()),
        ];
        RecordBatch::try_new(quad_stream_schema(), columns).map_err(arrow_err)
    }
}
