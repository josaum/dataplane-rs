// Rust guideline compliant 2026-02-21
//! Zero-copy decoding of `UnsignedQuadStream` batches.

use arrow_array::{
    Array, ArrayAccessor, DictionaryArray, FixedSizeBinaryArray, RecordBatch, StringArray,
    TimestampMicrosecondArray, TypedDictionaryArray, UInt64Array, types::UInt32Type,
};
use oxrdf::{
    BlankNodeRef, GraphNameRef, LiteralRef, NamedNodeRef, NamedOrBlankNodeRef, Quad, QuadRef, Term,
    TermRef,
};

use crate::{
    builder::QuadLimits,
    error::QuadError,
    quoted::{TERM_KIND_TRIPLE, parse_triple_term},
    schema::{
        COL_GRAPH_KIND, COL_GRAPH_VALUE, COL_OBJECT_DATATYPE, COL_OBJECT_KIND, COL_OBJECT_LANGUAGE,
        COL_OBJECT_VALUE, COL_OBSERVED_AT, COL_PREDICATE_IRI, COL_SOURCE_ARTIFACT,
        COL_SOURCE_OFFSET_END, COL_SOURCE_OFFSET_START, COL_SOURCE_SHA256, COL_SUBJECT_KIND,
        COL_SUBJECT_VALUE, GRAPH_KIND_BNODE, GRAPH_KIND_DEFAULT, GRAPH_KIND_IRI, TERM_KIND_BNODE,
        TERM_KIND_IRI, TERM_KIND_LITERAL, validate_contract,
    },
};

type DictStr<'a> = TypedDictionaryArray<'a, UInt32Type, StringArray>;

/// Borrowed source provenance of one decoded quad.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvenanceRef<'a> {
    /// IRI of the source artifact the quad was decoded from.
    pub source_artifact_iri: Option<&'a str>,
    /// SHA-256 of the exact source bytes.
    pub source_content_sha256: Option<&'a [u8]>,
    /// Byte offset where the quad's encoding starts in the source.
    pub source_offset_start: Option<u64>,
    /// Byte offset where the quad's encoding ends in the source.
    pub source_offset_end: Option<u64>,
    /// Microseconds since the Unix epoch (UTC) when the quad was observed.
    pub observed_at_micros: Option<i64>,
}

/// Zero-copy reader over one validated `UnsignedQuadStream` batch.
///
/// Decoded terms borrow directly from the batch's Arrow buffers; no per-quad
/// allocation happens on the read path.
#[derive(Clone, Copy, Debug)]
pub struct QuadStreamReader<'a> {
    rows: usize,
    subject_kind: DictStr<'a>,
    subject_value: DictStr<'a>,
    predicate_iri: DictStr<'a>,
    object_kind: DictStr<'a>,
    object_value: &'a StringArray,
    object_datatype: DictStr<'a>,
    object_language: DictStr<'a>,
    graph_kind: DictStr<'a>,
    graph_value: DictStr<'a>,
    source_artifact: DictStr<'a>,
    source_sha256: &'a FixedSizeBinaryArray,
    source_offset_start: &'a UInt64Array,
    source_offset_end: &'a UInt64Array,
    observed_at: &'a TimestampMicrosecondArray,
}

fn dict_column(batch: &RecordBatch, index: usize) -> Result<DictStr<'_>, QuadError> {
    batch
        .column(index)
        .as_any()
        .downcast_ref::<DictionaryArray<UInt32Type>>()
        .and_then(|dictionary| dictionary.downcast_dict::<StringArray>())
        .ok_or_else(|| {
            QuadError::Contract(format!("column {index} is not Dictionary<UInt32, Utf8>"))
        })
}

fn plain_column<'a, T: 'static>(
    batch: &'a RecordBatch,
    index: usize,
    type_name: &str,
) -> Result<&'a T, QuadError> {
    batch
        .column(index)
        .as_any()
        .downcast_ref::<T>()
        .ok_or_else(|| QuadError::Contract(format!("column {index} is not {type_name}")))
}

fn opt_str<'a>(column: DictStr<'a>, row: usize) -> Option<&'a str> {
    if column.is_null(row) {
        None
    } else {
        Some(column.value(row))
    }
}

/// Checks the shape of a BCP 47 language tag without allocating.
///
/// This intentionally validates only the character repertoire and hyphen
/// placement; full BCP 47 well-formedness is the writer's responsibility
/// (writers accept only [`oxrdf`] terms, which are valid by construction).
///
/// An embedded `--` is refused. A BCP 47 tag never contains an empty subtag,
/// and `tag--dir` is exactly the N-Triples 1.2 `LANG_DIR` spelling of a
/// directional language-tagged string — which the flat contract columns
/// cannot represent (see [`crate::FEATURE_BASE_DIRECTION`]). Without this
/// check a foreign batch could smuggle a direction past the unchecked
/// borrowing constructor and have it read back as part of the language tag.
fn language_shape_is_valid(language: &str) -> bool {
    !language.is_empty()
        && !language.starts_with('-')
        && !language.ends_with('-')
        && !language.contains("--")
        && language
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

impl<'a> QuadStreamReader<'a> {
    /// Validates `batch` against the contract and prepares typed accessors.
    ///
    /// # Errors
    ///
    /// Returns [`QuadError::Contract`] when the batch schema or column
    /// encodings do not match `UnsignedQuadStream` v1.
    pub fn new(batch: &'a RecordBatch) -> Result<Self, QuadError> {
        validate_contract(batch.schema().as_ref())?;
        Ok(Self {
            rows: batch.num_rows(),
            subject_kind: dict_column(batch, COL_SUBJECT_KIND)?,
            subject_value: dict_column(batch, COL_SUBJECT_VALUE)?,
            predicate_iri: dict_column(batch, COL_PREDICATE_IRI)?,
            object_kind: dict_column(batch, COL_OBJECT_KIND)?,
            object_value: plain_column(batch, COL_OBJECT_VALUE, "Utf8")?,
            object_datatype: dict_column(batch, COL_OBJECT_DATATYPE)?,
            object_language: dict_column(batch, COL_OBJECT_LANGUAGE)?,
            graph_kind: dict_column(batch, COL_GRAPH_KIND)?,
            graph_value: dict_column(batch, COL_GRAPH_VALUE)?,
            source_artifact: dict_column(batch, COL_SOURCE_ARTIFACT)?,
            source_sha256: plain_column(batch, COL_SOURCE_SHA256, "FixedSizeBinary(32)")?,
            source_offset_start: plain_column(batch, COL_SOURCE_OFFSET_START, "UInt64")?,
            source_offset_end: plain_column(batch, COL_SOURCE_OFFSET_END, "UInt64")?,
            observed_at: plain_column(batch, COL_OBSERVED_AT, "Timestamp(us, UTC)")?,
        })
    }

    /// Number of quads in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows
    }

    /// Returns `true` when the batch holds no quads.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows == 0
    }

    /// Returns `true` when any row in the batch stores a triple term.
    ///
    /// Cheap: the `object_kind` dictionary holds at most one entry per
    /// distinct kind, so this scans the dictionary values, not the rows.
    /// Consumers that cannot represent triple terms use this to refuse a
    /// batch once instead of per row.
    #[must_use]
    pub fn contains_triple_terms(&self) -> bool {
        let values = self.object_kind.values();
        (0..values.len())
            .any(|index| !values.is_null(index) && values.value(index) == TERM_KIND_TRIPLE)
    }

    /// Decodes the quad at `row`, borrowing terms from the Arrow buffers.
    ///
    /// # Errors
    ///
    /// Returns [`QuadError::Term`] when a stored value is not a valid RDF
    /// term of its declared kind (fail-closed reading of foreign batches),
    /// and [`QuadError::Unsupported`] (feature `rdf12_triple_term`) when the
    /// row stores an RDF 1.2 triple term: the nested triple lives nowhere in
    /// the Arrow buffers, so it cannot be handed out as a borrowed
    /// [`TermRef`]. Use [`QuadStreamReader::quad_owned`] for those rows.
    ///
    /// # Panics
    ///
    /// Panics when `row >= self.len()`; indexing past the end is a
    /// programming error.
    pub fn quad(&self, row: usize) -> Result<QuadRef<'a>, QuadError> {
        assert!(
            row < self.rows,
            "row {row} out of bounds ({} rows)",
            self.rows
        );

        let (subject, predicate, graph_name) = self.quad_shape(row)?;
        let object = self.object(row)?;
        Ok(QuadRef::new(subject, predicate, object, graph_name))
    }

    /// Decodes the quad at `row` into owned terms, admitting triple terms.
    ///
    /// This is the read path for RDF 1.2 batches: it allocates, because a
    /// triple term's nested triple is materialized from the serialized
    /// `object_value` and cannot borrow from the Arrow buffers. Rows without
    /// a triple term decode to exactly the same quad as
    /// [`QuadStreamReader::quad`].
    ///
    /// # Errors
    ///
    /// Returns [`QuadError::Term`] when a stored value is not a valid RDF
    /// term of its declared kind, and [`QuadError::ResourceLimit`] with
    /// [`crate::QuadResource::QuotedDepth`] when the stored triple term nests
    /// deeper than `limits.max_quoted_depth`.
    ///
    /// # Panics
    ///
    /// Panics when `row >= self.len()`.
    pub fn quad_owned(&self, row: usize, limits: QuadLimits) -> Result<Quad, QuadError> {
        assert!(
            row < self.rows,
            "row {row} out of bounds ({} rows)",
            self.rows
        );
        if self.object_kind.value(row) != TERM_KIND_TRIPLE {
            return Ok(self.quad(row)?.into_owned());
        }
        let quad = self.quad_shape(row)?;
        if !self.object_datatype.is_null(row) || !self.object_language.is_null(row) {
            return Err(QuadError::Term(
                "object_kind `triple` must have a null datatype and language".into(),
            ));
        }
        let triple = parse_triple_term(self.object_value.value(row), limits.max_quoted_depth)?;
        Ok(Quad::new(
            quad.0.into_owned(),
            quad.1.into_owned(),
            Term::Triple(Box::new(triple)),
            quad.2.into_owned(),
        ))
    }

    /// Decodes the subject, predicate, and graph name of `row`.
    ///
    /// Shared by the borrowed and owned read paths so their term validation
    /// cannot drift.
    fn quad_shape(
        &self,
        row: usize,
    ) -> Result<(NamedOrBlankNodeRef<'a>, NamedNodeRef<'a>, GraphNameRef<'a>), QuadError> {
        let subject = match self.subject_kind.value(row) {
            TERM_KIND_IRI => NamedOrBlankNodeRef::NamedNode(named_node(
                self.subject_value.value(row),
                "subject",
            )?),
            TERM_KIND_BNODE => NamedOrBlankNodeRef::BlankNode(blank_node(
                self.subject_value.value(row),
                "subject",
            )?),
            TERM_KIND_TRIPLE => {
                return Err(QuadError::triple_term_unsupported(
                    "RDF 1.2 admits triple terms only in the object position, and the oxrdf \
                     subject model has no triple variant",
                ));
            }
            other => {
                return Err(QuadError::Term(format!("invalid subject_kind `{other}`")));
            }
        };
        let predicate = named_node(self.predicate_iri.value(row), "predicate")?;
        let graph_name = match self.graph_kind.value(row) {
            GRAPH_KIND_DEFAULT => GraphNameRef::DefaultGraph,
            GRAPH_KIND_IRI => GraphNameRef::NamedNode(named_node(
                self.graph_value(row, GRAPH_KIND_IRI)?,
                "graph",
            )?),
            GRAPH_KIND_BNODE => GraphNameRef::BlankNode(blank_node(
                self.graph_value(row, GRAPH_KIND_BNODE)?,
                "graph",
            )?),
            other => return Err(QuadError::Term(format!("invalid graph_kind `{other}`"))),
        };
        Ok((subject, predicate, graph_name))
    }

    /// Iterates over `(quad, provenance)` pairs in row order, admitting
    /// triple terms by decoding into owned quads.
    ///
    /// The owned counterpart of [`QuadStreamReader::iter`].
    pub fn iter_owned(
        &self,
        limits: QuadLimits,
    ) -> impl Iterator<Item = Result<(Quad, ProvenanceRef<'a>), QuadError>> + '_ {
        (0..self.rows).map(move |row| Ok((self.quad_owned(row, limits)?, self.provenance(row))))
    }

    /// Returns the provenance stored with the quad at `row`.
    ///
    /// # Panics
    ///
    /// Panics when `row >= self.len()`.
    #[must_use]
    pub fn provenance(&self, row: usize) -> ProvenanceRef<'a> {
        assert!(
            row < self.rows,
            "row {row} out of bounds ({} rows)",
            self.rows
        );
        ProvenanceRef {
            source_artifact_iri: opt_str(self.source_artifact, row),
            source_content_sha256: if self.source_sha256.is_null(row) {
                None
            } else {
                Some(self.source_sha256.value(row))
            },
            source_offset_start: if self.source_offset_start.is_null(row) {
                None
            } else {
                Some(self.source_offset_start.value(row))
            },
            source_offset_end: if self.source_offset_end.is_null(row) {
                None
            } else {
                Some(self.source_offset_end.value(row))
            },
            observed_at_micros: if self.observed_at.is_null(row) {
                None
            } else {
                Some(self.observed_at.value(row))
            },
        }
    }

    /// Iterates over `(quad, provenance)` pairs in row order.
    ///
    /// Yields the same typed refusal as [`QuadStreamReader::quad`] for a row
    /// that stores an RDF 1.2 triple term; use
    /// [`QuadStreamReader::iter_owned`] to admit those rows.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = Result<(QuadRef<'a>, ProvenanceRef<'a>), QuadError>> + '_ {
        (0..self.rows).map(|row| Ok((self.quad(row)?, self.provenance(row))))
    }

    fn graph_value(&self, row: usize, kind: &str) -> Result<&'a str, QuadError> {
        if self.graph_value.is_null(row) {
            return Err(QuadError::Term(format!(
                "graph_kind `{kind}` requires a graph_value"
            )));
        }
        Ok(self.graph_value.value(row))
    }

    fn object(&self, row: usize) -> Result<TermRef<'a>, QuadError> {
        let value = self.object_value.value(row);
        match self.object_kind.value(row) {
            TERM_KIND_IRI => Ok(TermRef::NamedNode(named_node(value, "object")?)),
            TERM_KIND_BNODE => Ok(TermRef::BlankNode(blank_node(value, "object")?)),
            TERM_KIND_LITERAL => {
                let datatype = opt_str(self.object_datatype, row);
                let language = opt_str(self.object_language, row);
                match (datatype, language) {
                    (Some(_), Some(_)) => Err(QuadError::Term(
                        "literal carries both a datatype and a language".into(),
                    )),
                    (None, Some(language)) => {
                        if !language_shape_is_valid(language) {
                            return Err(QuadError::Term(format!(
                                "invalid language tag `{language}`"
                            )));
                        }
                        Ok(TermRef::Literal(
                            LiteralRef::new_language_tagged_literal_unchecked(value, language),
                        ))
                    }
                    (Some(datatype), None) => Ok(TermRef::Literal(LiteralRef::new_typed_literal(
                        value,
                        named_node(datatype, "datatype")?,
                    ))),
                    (None, None) => Ok(TermRef::Literal(LiteralRef::new_simple_literal(value))),
                }
            }
            TERM_KIND_TRIPLE => Err(QuadError::triple_term_unsupported(
                "the zero-copy read path cannot borrow a triple term; use \
                 QuadStreamReader::quad_owned",
            )),
            other => Err(QuadError::Term(format!("invalid object_kind `{other}`"))),
        }
    }
}

fn named_node<'a>(value: &'a str, position: &str) -> Result<NamedNodeRef<'a>, QuadError> {
    NamedNodeRef::new(value)
        .map_err(|error| QuadError::Term(format!("invalid {position} IRI `{value}`: {error}")))
}

fn blank_node<'a>(value: &'a str, position: &str) -> Result<BlankNodeRef<'a>, QuadError> {
    BlankNodeRef::new(value).map_err(|error| {
        QuadError::Term(format!("invalid {position} blank node `{value}`: {error}"))
    })
}
