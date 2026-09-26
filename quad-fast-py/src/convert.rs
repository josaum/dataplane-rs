// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21

//! Interpreter-free conversion between plain quad data and codec bytes.
//!
//! This module is the entire logic of the Python binding, expressed over
//! plain Rust data ([`QuadSpec`], [`TermSpec`], [`ProvenanceSpec`]) so it
//! compiles and tests without a Python interpreter. The `lib.rs` layer only
//! translates Python objects to and from these types.
//!
//! All conversions are fail-closed: malformed terms, malformed payload
//! bytes, and exceeded [`QuadLimits`] budgets surface as [`BindingError`]
//! values, never as silent drops. Output stays unsigned by construction —
//! this module only moves data through `quad-fast-core` and
//! `jelly-fast-core`, which pin `atlas.assurance = "unsigned"` metadata and
//! never promote assurance.
//!
//! Jelly frames are exchanged as *non-delimited* protobuf-encoded
//! `RdfStreamFrame` messages (one byte string per frame). The
//! varint-delimited `.jelly` file framing is out of scope here.

use jelly_fast_core::{
    JellyDecoder, JellyDecoderOptions, JellyEncoder, JellyEncoderOptions, JellyError,
    proto::RdfStreamFrame,
};
use jsonld_fast_core::{JsonLdError, JsonLdLimits, JsonLdOptions};
use oxrdf::{GraphName, Literal, NamedNode, NamedOrBlankNode, Quad, QuadRef, Term};
use prost::Message;
use quad_fast_core::{
    GRAPH_KIND_BNODE, GRAPH_KIND_IRI, ProvenanceRef, QuadBatchBuilder, QuadError, QuadLimits,
    QuadStreamReader, SourceProvenance, TERM_KIND_BNODE, TERM_KIND_IRI, TERM_KIND_LITERAL,
    read_ipc_stream, write_ipc_stream,
};

/// One RDF term as plain data: kind, lexical value, and literal metadata.
///
/// `kind` is one of the contract kind strings (`iri`, `bnode`, `literal`).
/// `datatype` and `language` are only meaningful for literals and follow the
/// contract's storage rule: language-tagged literals carry a language and a
/// `None` datatype (`rdf:langString` is implied), all other literals carry
/// their datatype IRI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TermSpec {
    /// Contract term kind: `iri`, `bnode`, or `literal`.
    pub(crate) kind: String,
    /// IRI, blank node identifier, or literal lexical form.
    pub(crate) value: String,
    /// Literal datatype IRI; `None` for simple and language-tagged literals.
    pub(crate) datatype: Option<String>,
    /// BCP 47 language tag for language-tagged literals.
    pub(crate) language: Option<String>,
}

/// Per-quad source provenance as plain data.
///
/// Mirrors [`SourceProvenance`] with an unvalidated digest so the length
/// check is a typed error of this layer rather than a Python-side panic.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProvenanceSpec {
    /// IRI of the source artifact the quad was decoded from.
    pub(crate) source_artifact_iri: Option<String>,
    /// SHA-256 of the exact source bytes (must be exactly 32 bytes).
    pub(crate) source_content_sha256: Option<Vec<u8>>,
    /// Byte offset where the quad's encoding starts in the source.
    pub(crate) source_offset_start: Option<u64>,
    /// Byte offset where the quad's encoding ends in the source.
    pub(crate) source_offset_end: Option<u64>,
    /// Microseconds since the Unix epoch (UTC) when the quad was observed.
    pub(crate) observed_at_micros: Option<i64>,
}

impl ProvenanceSpec {
    /// Returns `true` when every provenance field is absent.
    pub(crate) fn is_empty(&self) -> bool {
        self.source_artifact_iri.is_none()
            && self.source_content_sha256.is_none()
            && self.source_offset_start.is_none()
            && self.source_offset_end.is_none()
            && self.observed_at_micros.is_none()
    }
}

/// One quad as plain data, with optional named graph and provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QuadSpec {
    /// Subject term (`iri` or `bnode`; literal metadata must be absent).
    pub(crate) subject: TermSpec,
    /// Predicate IRI.
    pub(crate) predicate: String,
    /// Object term (`iri`, `bnode`, or `literal`).
    pub(crate) object: TermSpec,
    /// Named graph (`iri` or `bnode`); `None` selects the default graph.
    pub(crate) graph: Option<TermSpec>,
    /// Optional source provenance carried into the batch.
    pub(crate) provenance: Option<ProvenanceSpec>,
}

/// Closed error surface of the binding conversion layer.
///
/// Every rendered message starts with a stable machine-readable code token,
/// matching the convention of [`QuadError`] and [`JellyError`].
#[derive(Debug)]
pub(crate) enum BindingError {
    /// The `UnsignedQuadStream` contract rejected an operation.
    Quad(QuadError),
    /// The Jelly codec rejected an operation.
    Jelly(JellyError),
    /// The JSON-LD codec rejected an operation.
    JsonLd(JsonLdError),
    /// The submitted plain data is malformed.
    Input {
        /// Stable machine-readable code (e.g., `term_kind`, `frame_bytes`).
        code: &'static str,
        /// Human-readable explanation.
        detail: String,
    },
}

impl BindingError {
    /// Returns `true` when the error is an exceeded fail-closed limit.
    pub(crate) fn is_resource_limit(&self) -> bool {
        matches!(
            self,
            Self::Quad(QuadError::ResourceLimit { .. })
                | Self::Jelly(JellyError::ResourceLimit { .. })
                | Self::Jelly(JellyError::Quad(QuadError::ResourceLimit { .. }))
                | Self::JsonLd(JsonLdError::ResourceLimit { .. })
        )
    }
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quad(error) => error.fmt(formatter),
            Self::Jelly(error) => error.fmt(formatter),
            Self::JsonLd(error) => error.fmt(formatter),
            Self::Input { code, detail } => write!(formatter, "{code}: {detail}"),
        }
    }
}

impl std::error::Error for BindingError {}

impl From<QuadError> for BindingError {
    fn from(error: QuadError) -> Self {
        Self::Quad(error)
    }
}

impl From<JellyError> for BindingError {
    fn from(error: JellyError) -> Self {
        Self::Jelly(error)
    }
}

fn input_err(code: &'static str, detail: String) -> BindingError {
    BindingError::Input { code, detail }
}

fn parse_iri(value: &str, role: &str) -> Result<NamedNode, BindingError> {
    NamedNode::new(value)
        .map_err(|error| input_err("term", format!("{role}: invalid IRI {value:?}: {error}")))
}

fn parse_bnode(value: &str, role: &str) -> Result<oxrdf::BlankNode, BindingError> {
    oxrdf::BlankNode::new(value).map_err(|error| {
        input_err(
            "term",
            format!("{role}: invalid blank node id {value:?}: {error}"),
        )
    })
}

/// Requires the literal metadata slots of a non-literal term to be empty.
fn require_no_literal_parts(spec: &TermSpec, role: &str) -> Result<(), BindingError> {
    if spec.datatype.is_some() || spec.language.is_some() {
        return Err(input_err(
            "term_shape",
            format!(
                "{role}: kind {:?} does not take datatype or language",
                spec.kind
            ),
        ));
    }
    Ok(())
}

fn subject_term(spec: &TermSpec) -> Result<NamedOrBlankNode, BindingError> {
    match spec.kind.as_str() {
        TERM_KIND_IRI => {
            require_no_literal_parts(spec, "subject")?;
            Ok(parse_iri(&spec.value, "subject")?.into())
        }
        TERM_KIND_BNODE => {
            require_no_literal_parts(spec, "subject")?;
            Ok(parse_bnode(&spec.value, "subject")?.into())
        }
        other => Err(input_err(
            "term_kind",
            format!("subject: kind must be \"iri\" or \"bnode\", got {other:?}"),
        )),
    }
}

fn object_term(spec: &TermSpec) -> Result<Term, BindingError> {
    match spec.kind.as_str() {
        TERM_KIND_IRI => {
            require_no_literal_parts(spec, "object")?;
            Ok(parse_iri(&spec.value, "object")?.into())
        }
        TERM_KIND_BNODE => {
            require_no_literal_parts(spec, "object")?;
            Ok(parse_bnode(&spec.value, "object")?.into())
        }
        TERM_KIND_LITERAL => match (&spec.datatype, &spec.language) {
            (Some(_), Some(_)) => Err(input_err(
                "term_shape",
                "object: a literal cannot carry both a datatype and a language".to_string(),
            )),
            (None, Some(language)) => Literal::new_language_tagged_literal(&spec.value, language)
                .map(Term::from)
                .map_err(|error| {
                    input_err(
                        "language",
                        format!("object: invalid language tag {language:?}: {error}"),
                    )
                }),
            (Some(datatype), None) => Ok(Literal::new_typed_literal(
                &spec.value,
                parse_iri(datatype, "object datatype")?,
            )
            .into()),
            (None, None) => Ok(Literal::new_simple_literal(&spec.value).into()),
        },
        other => Err(input_err(
            "term_kind",
            format!("object: kind must be \"iri\", \"bnode\", or \"literal\", got {other:?}"),
        )),
    }
}

fn graph_term(spec: Option<&TermSpec>) -> Result<GraphName, BindingError> {
    let Some(spec) = spec else {
        return Ok(GraphName::DefaultGraph);
    };
    match spec.kind.as_str() {
        GRAPH_KIND_IRI => {
            require_no_literal_parts(spec, "graph")?;
            Ok(parse_iri(&spec.value, "graph")?.into())
        }
        GRAPH_KIND_BNODE => {
            require_no_literal_parts(spec, "graph")?;
            Ok(parse_bnode(&spec.value, "graph")?.into())
        }
        other => Err(input_err(
            "term_kind",
            format!(
                "graph: kind must be \"iri\" or \"bnode\" (pass no graph for the default graph), \
                 got {other:?}"
            ),
        )),
    }
}

fn source_provenance(spec: &ProvenanceSpec) -> Result<SourceProvenance, BindingError> {
    let source_content_sha256 = match &spec.source_content_sha256 {
        None => None,
        Some(bytes) => Some(
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_length_only| {
                input_err(
                    "provenance_sha256_length",
                    format!(
                        "source_content_sha256 must contain exactly 32 bytes, got {}",
                        bytes.len()
                    ),
                )
            })?,
        ),
    };
    Ok(SourceProvenance {
        source_artifact_iri: spec.source_artifact_iri.clone(),
        source_content_sha256,
        source_offset_start: spec.source_offset_start,
        source_offset_end: spec.source_offset_end,
        observed_at_micros: spec.observed_at_micros,
    })
}

fn term_spec_of_subject(subject: oxrdf::NamedOrBlankNodeRef<'_>) -> TermSpec {
    let (kind, value) = match subject {
        oxrdf::NamedOrBlankNodeRef::NamedNode(node) => (TERM_KIND_IRI, node.as_str()),
        oxrdf::NamedOrBlankNodeRef::BlankNode(node) => (TERM_KIND_BNODE, node.as_str()),
    };
    TermSpec {
        kind: kind.to_string(),
        value: value.to_string(),
        datatype: None,
        language: None,
    }
}

/// Maps one object term onto the Python-facing [`TermSpec`] shape.
///
/// The Python shape has `iri`, `bnode`, and `literal` kinds only, so an RDF
/// 1.2 triple term is refused by name rather than flattened into a node
/// reference that would invent a reification the source never asserted.
fn term_spec_of_object(object: oxrdf::TermRef<'_>) -> Result<TermSpec, BindingError> {
    Ok(match object {
        oxrdf::TermRef::Triple(_) => {
            return Err(BindingError::Quad(QuadError::triple_term_unsupported(
                "the quad-fast-py term shape has no triple-term object kind",
            )));
        }
        oxrdf::TermRef::NamedNode(node) => TermSpec {
            kind: TERM_KIND_IRI.to_string(),
            value: node.as_str().to_string(),
            datatype: None,
            language: None,
        },
        oxrdf::TermRef::BlankNode(node) => TermSpec {
            kind: TERM_KIND_BNODE.to_string(),
            value: node.as_str().to_string(),
            datatype: None,
            language: None,
        },
        oxrdf::TermRef::Literal(literal) => match literal.language() {
            Some(language) => TermSpec {
                kind: TERM_KIND_LITERAL.to_string(),
                value: literal.value().to_string(),
                datatype: None,
                language: Some(language.to_string()),
            },
            None => TermSpec {
                kind: TERM_KIND_LITERAL.to_string(),
                value: literal.value().to_string(),
                datatype: Some(literal.datatype().as_str().to_string()),
                language: None,
            },
        },
    })
}

fn graph_spec(graph: oxrdf::GraphNameRef<'_>) -> Option<TermSpec> {
    let (kind, value) = match graph {
        oxrdf::GraphNameRef::DefaultGraph => return None,
        oxrdf::GraphNameRef::NamedNode(node) => (GRAPH_KIND_IRI, node.as_str()),
        oxrdf::GraphNameRef::BlankNode(node) => (GRAPH_KIND_BNODE, node.as_str()),
    };
    Some(TermSpec {
        kind: kind.to_string(),
        value: value.to_string(),
        datatype: None,
        language: None,
    })
}

fn provenance_spec(provenance: ProvenanceRef<'_>) -> Option<ProvenanceSpec> {
    let spec = ProvenanceSpec {
        source_artifact_iri: provenance.source_artifact_iri.map(str::to_string),
        source_content_sha256: provenance.source_content_sha256.map(<[u8]>::to_vec),
        source_offset_start: provenance.source_offset_start,
        source_offset_end: provenance.source_offset_end,
        observed_at_micros: provenance.observed_at_micros,
    };
    if spec.is_empty() { None } else { Some(spec) }
}

fn quad_spec(quad: QuadRef<'_>, provenance: ProvenanceRef<'_>) -> Result<QuadSpec, BindingError> {
    Ok(QuadSpec {
        subject: term_spec_of_subject(quad.subject),
        predicate: quad.predicate.as_str().to_string(),
        object: term_spec_of_object(quad.object)?,
        graph: graph_spec(quad.graph_name),
        provenance: provenance_spec(provenance),
    })
}

/// Builds one `UnsignedQuadStream` batch and encodes it as Arrow IPC bytes.
///
/// # Errors
///
/// Returns [`BindingError::Input`] for malformed terms or provenance,
/// and [`BindingError::Quad`] when a fail-closed budget in `limits` or
/// `max_ipc_bytes` is exceeded or Arrow encoding fails.
pub(crate) fn quads_to_ipc(
    quads: &[QuadSpec],
    limits: QuadLimits,
    max_ipc_bytes: usize,
) -> Result<Vec<u8>, BindingError> {
    let mut builder = QuadBatchBuilder::new(limits);
    for spec in quads {
        let quad = Quad::new(
            subject_term(&spec.subject)?,
            parse_iri(&spec.predicate, "predicate")?,
            object_term(&spec.object)?,
            graph_term(spec.graph.as_ref())?,
        );
        let provenance = spec
            .provenance
            .as_ref()
            .map(source_provenance)
            .transpose()?;
        builder.push(quad.as_ref(), provenance.as_ref())?;
    }
    let batch = builder.finish()?;
    Ok(write_ipc_stream(&[batch], max_ipc_bytes)?)
}

/// Decodes Arrow IPC bytes into plain quads with provenance.
///
/// Simple literals come back normalized with an explicit `xsd:string`
/// datatype (the contract's storage form); language-tagged literals come
/// back with a `None` datatype and a lowercase language tag ([`oxrdf`]
/// normalizes tags per RDF 1.1's case-insensitive semantics).
///
/// # Errors
///
/// Returns [`BindingError::Quad`] when the payload is not a readable IPC
/// stream of contract-valid `UnsignedQuadStream` batches.
pub(crate) fn ipc_to_quads(bytes: &[u8]) -> Result<Vec<QuadSpec>, BindingError> {
    let batches = read_ipc_stream(bytes)?;
    let mut quads = Vec::new();
    for batch in &batches {
        let reader = QuadStreamReader::new(batch)?;
        for row in 0..reader.len() {
            quads.push(quad_spec(reader.quad(row)?, reader.provenance(row))?);
        }
    }
    Ok(quads)
}

/// Decodes one JSON-LD document (inline context) into Arrow IPC bytes.
///
/// The document is parsed, expanded, and deserialized to quads by
/// `jsonld-fast-core` under its fail-closed budgets, then serialized as one
/// `UnsignedQuadStream` IPC stream. Provenance given by the caller rides
/// every row of the batch. Blank nodes keep document scope: each call is
/// one document with freshly issued labels, so callers projecting a JSONL
/// log must keep one batch per line rather than merging lines.
///
/// # Errors
///
/// Returns [`BindingError::JsonLd`] for parse, expansion, and quad-budget
/// failures — including the sovereign remote-context refusal — and
/// [`BindingError::Quad`] when the IPC budget is exceeded.
pub(crate) fn jsonld_to_ipc(
    text: &str,
    provenance: Option<&ProvenanceSpec>,
    limits: &JsonLdLimits,
    quad_limits: QuadLimits,
    max_ipc_bytes: usize,
) -> Result<Vec<u8>, BindingError> {
    let document = jsonld_fast_core::parse_document(text, limits).map_err(BindingError::JsonLd)?;
    let options = JsonLdOptions {
        limits: *limits,
        quad_limits,
        ..JsonLdOptions::default()
    };
    let provenance = provenance.map(source_provenance).transpose()?;
    let batches = jsonld_fast_core::to_quads(&document, &options, provenance.as_ref())
        .map_err(BindingError::JsonLd)?;
    Ok(write_ipc_stream(&batches, max_ipc_bytes)?)
}

/// Encodes an Arrow IPC quad stream as protobuf-encoded Jelly frames.
///
/// All batches in the IPC payload are encoded as one logical Jelly stream
/// (one options row, shared lookup tables). Each returned element is one
/// non-delimited protobuf `RdfStreamFrame` message.
///
/// # Errors
///
/// Returns [`BindingError::Quad`] for unreadable IPC bytes and
/// [`BindingError::Jelly`] when the encoder refuses the stream — notably
/// batches carrying provenance while
/// [`JellyEncoderOptions::allow_provenance_loss`] is unset.
pub(crate) fn ipc_to_jelly_frames(
    ipc: &[u8],
    options: JellyEncoderOptions,
) -> Result<Vec<Vec<u8>>, BindingError> {
    let batches = read_ipc_stream(ipc)?;
    let mut encoder = JellyEncoder::new(options)?;
    let mut frames = Vec::new();
    for batch in &batches {
        for frame in encoder.encode_batch(batch)? {
            frames.push(frame.encode_to_vec());
        }
    }
    Ok(frames)
}

/// Decodes protobuf-encoded Jelly frames back into Arrow IPC bytes.
///
/// The frames must form exactly one logical Jelly stream in list order
/// (options row first); frames from a second stream surface as a typed
/// duplicate-options error. `options.quad_limits` governs every frame
/// individually, and `max_ipc_bytes` governs the re-encoded payload.
/// Decoded batches always carry null provenance (Jelly has no provenance
/// fields on the wire).
///
/// # Errors
///
/// Returns [`BindingError::Input`] (code `frame_bytes`) for bytes that are
/// not a valid `RdfStreamFrame` message, [`BindingError::Jelly`] for
/// protocol violations, and [`BindingError::Quad`] when re-encoding the
/// decoded batches fails or exceeds `max_ipc_bytes`.
pub(crate) fn jelly_frames_to_ipc(
    frames: &[Vec<u8>],
    options: JellyDecoderOptions,
    max_ipc_bytes: usize,
) -> Result<Vec<u8>, BindingError> {
    let mut decoder = JellyDecoder::new(options);
    let mut batches = Vec::new();
    for bytes in frames {
        let frame = RdfStreamFrame::decode(bytes.as_slice()).map_err(|error| {
            input_err(
                "frame_bytes",
                format!("not a valid RdfStreamFrame protobuf message: {error}"),
            )
        })?;
        batches.push(decoder.decode_frame(&frame)?);
    }
    Ok(write_ipc_stream(&batches, max_ipc_bytes)?)
}
