// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21

//! Pure-Rust conversion between JS-shaped JSON values and the quad contract.
//!
//! Everything in this module is independent of the N-API runtime so the whole
//! binding surface stays unit-testable from `cargo test` without a built
//! `.node` artifact; the `#[napi]` wrappers in the crate root are one-line
//! delegations into these functions.
//!
//! # Quad object shape
//!
//! One quad is a JSON object with camelCase keys (unknown keys are typed
//! errors, never ignored):
//!
//! ```json
//! {
//!   "subject":   { "kind": "iri" | "bnode", "value": "..." },
//!   "predicate": "http://example.com/p",
//!   "object":    { "kind": "iri" | "bnode" | "literal", "value": "...",
//!                  "datatype": "...", "language": "..." },
//!   "graph":     { "kind": "default" | "iri" | "bnode", "value": "..." },
//!   "provenance": {
//!     "sourceArtifactIri": "...",
//!     "sourceContentSha256": "<64 hex chars>",
//!     "sourceOffsetStart": 0,
//!     "sourceOffsetEnd": 0,
//!     "observedAtMicros": 0
//!   }
//! }
//! ```
//!
//! `graph` and `provenance` are optional (`graph` omitted means the default
//! graph); `datatype`/`language` are only legal on literals and mutually
//! exclusive. Simple literals are stored with an explicit `xsd:string`
//! datatype by the contract, so a round trip reports that datatype.
//!
//! JS numbers are IEEE-754 doubles, so every integer field is confined to
//! `Number.MAX_SAFE_INTEGER`; decoded values beyond it are a typed
//! [`BindingError::Precision`] error, never a silent rounding.

use jelly_fast_core::{
    JellyDecoder, JellyDecoderOptions, JellyEncoder, JellyEncoderOptions, JellyError,
    proto::RdfStreamFrame,
};
use oxrdf::{BlankNode, GraphName, Literal, NamedNode, NamedOrBlankNode, Quad, QuadRef, Term};
use prost::Message;
use quad_fast_core::{
    DEFAULT_MAX_IPC_BYTES, ProvenanceRef, QuadBatchBuilder, QuadError, QuadLimits,
    QuadStreamReader, SourceProvenance, read_ipc_stream, write_ipc_stream,
};
use serde_json::{Map, Value, json};
use thiserror::Error;

/// Largest integer a JS `number` (IEEE-754 double) represents exactly.
///
/// Mirrors `Number.MAX_SAFE_INTEGER` (2^53 - 1). Values above it cannot
/// cross the N-API boundary without silent precision loss, so the binding
/// fails closed on them instead.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Default maximum length-delimited Jelly frames accepted per payload.
///
/// 65,536 frames at the default 8,192 quads per frame is far beyond one
/// batch-oriented call; the cap exists so a hostile payload of tiny frames
/// cannot force unbounded looping before the byte budget triggers.
const DEFAULT_MAX_JELLY_FRAMES: usize = 65_536;

/// Closed error surface for the Node binding conversion layer.
///
/// Every variant renders with a stable machine-readable code as the first
/// token of its message; [`BindingError::code`] returns the same token.
#[derive(Debug, Error)]
pub enum BindingError {
    /// A JS-shaped input value does not match the documented quad or
    /// options shape.
    #[error("input: {0}")]
    Input(String),
    /// A decoded integer exceeds `Number.MAX_SAFE_INTEGER` and cannot cross
    /// the N-API boundary exactly.
    #[error("precision: {field}: value {value} exceeds Number.MAX_SAFE_INTEGER")]
    Precision {
        /// Field whose value cannot be represented as a JS number.
        field: &'static str,
        /// The unrepresentable value.
        value: u64,
    },
    /// A binding-level fail-closed budget was exceeded.
    #[error("resource_limit: {resource}: observed {observed} exceeds limit {limit}")]
    ResourceLimit {
        /// Governed resource name.
        resource: &'static str,
        /// Configured inclusive limit.
        limit: usize,
        /// First observed value beyond the limit.
        observed: usize,
    },
    /// A length-delimited Jelly frame payload is not valid protobuf.
    #[error("frame_decode: {0}")]
    FrameDecode(String),
    /// The `UnsignedQuadStream` contract rejected an operation.
    #[error(transparent)]
    Quad(#[from] QuadError),
    /// The Jelly codec rejected an operation.
    #[error(transparent)]
    Jelly(#[from] JellyError),
}

impl BindingError {
    /// Stable machine-readable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Input(_) => "input",
            Self::Precision { .. } => "precision",
            Self::ResourceLimit { .. } => "resource_limit",
            Self::FrameDecode(_) => "frame_decode",
            Self::Quad(error) => error.code(),
            Self::Jelly(error) => error.code(),
        }
    }
}

// ---------------------------------------------------------------------------
// JSON accessor helpers (fail-closed: wrong types and unknown keys error).
// ---------------------------------------------------------------------------

/// Requires `value` to be a JSON object.
fn as_object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, BindingError> {
    value
        .as_object()
        .ok_or_else(|| BindingError::Input(format!("{what} must be an object")))
}

/// Rejects keys outside `allowed` (fail-closed: typos never pass silently).
fn check_keys(map: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), BindingError> {
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(BindingError::Input(format!(
                "{what} has unknown key `{key}` (allowed: {})",
                allowed.join(", ")
            )));
        }
    }
    Ok(())
}

/// Returns the string at `key`, treating `null` as absent.
fn opt_str_field<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<Option<&'a str>, BindingError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(BindingError::Input(format!(
            "{what}.{key} must be a string"
        ))),
    }
}

/// Returns the required string at `key`.
fn require_str_field<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<&'a str, BindingError> {
    opt_str_field(map, key, what)?
        .ok_or_else(|| BindingError::Input(format!("{what}.{key} is required")))
}

/// Converts a JSON number to an exact `u64` within the JS-safe range.
fn number_to_u64(value: &Value, what: &str) -> Result<u64, BindingError> {
    let number = value
        .as_number()
        .ok_or_else(|| BindingError::Input(format!("{what} must be a number")))?;
    let exact = if let Some(unsigned) = number.as_u64() {
        Some(unsigned)
    } else {
        // JS integers may arrive as integral doubles; accept them exactly.
        number.as_f64().and_then(|float| {
            (float >= 0.0 && float.fract() == 0.0 && float <= MAX_SAFE_INTEGER as f64)
                .then_some(float as u64)
        })
    };
    match exact {
        Some(unsigned) if unsigned <= MAX_SAFE_INTEGER => Ok(unsigned),
        _ => Err(BindingError::Input(format!(
            "{what} must be a non-negative integer at most Number.MAX_SAFE_INTEGER"
        ))),
    }
}

/// Converts a JSON number to an exact `i64` within the JS-safe range.
fn number_to_i64(value: &Value, what: &str) -> Result<i64, BindingError> {
    let number = value
        .as_number()
        .ok_or_else(|| BindingError::Input(format!("{what} must be a number")))?;
    let exact = if let Some(signed) = number.as_i64() {
        Some(signed)
    } else {
        number.as_f64().and_then(|float| {
            (float.fract() == 0.0 && float.abs() <= MAX_SAFE_INTEGER as f64).then_some(float as i64)
        })
    };
    match exact {
        Some(signed) if signed.unsigned_abs() <= MAX_SAFE_INTEGER => Ok(signed),
        _ => Err(BindingError::Input(format!(
            "{what} must be an integer within Number.MAX_SAFE_INTEGER"
        ))),
    }
}

/// Returns the optional `u64` at `key`, treating `null` as absent.
fn opt_u64_field(
    map: &Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<Option<u64>, BindingError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(number_to_u64(value, &format!("{what}.{key}"))?)),
    }
}

/// Returns the optional `usize` at `key`, treating `null` as absent.
fn opt_usize_field(
    map: &Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<Option<usize>, BindingError> {
    opt_u64_field(map, key, what)?
        .map(|unsigned| {
            usize::try_from(unsigned).map_err(|error| {
                BindingError::Input(format!(
                    "{what}.{key} does not fit this platform's usize: {error}"
                ))
            })
        })
        .transpose()
}

/// Returns the optional `u32` at `key`, treating `null` as absent.
fn opt_u32_field(
    map: &Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<Option<u32>, BindingError> {
    opt_u64_field(map, key, what)?
        .map(|unsigned| {
            u32::try_from(unsigned).map_err(|error| {
                BindingError::Input(format!("{what}.{key} must fit in u32: {error}"))
            })
        })
        .transpose()
}

/// Returns the optional `bool` at `key`, treating `null` as absent.
fn opt_bool_field(
    map: &Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<Option<bool>, BindingError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(flag)) => Ok(Some(*flag)),
        Some(_) => Err(BindingError::Input(format!(
            "{what}.{key} must be a boolean"
        ))),
    }
}

/// Normalizes an omitted or `null` options value to an empty object view.
fn options_map(options: Option<&Value>) -> Result<Map<String, Value>, BindingError> {
    match options {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(value) => Ok(as_object(value, "options")?.clone()),
    }
}

// ---------------------------------------------------------------------------
// Option parsing.
// ---------------------------------------------------------------------------

/// Applies `maxQuads` / `maxRetainedTermBytes` overrides onto the defaults.
fn quad_limits_from(map: &Map<String, Value>) -> Result<QuadLimits, BindingError> {
    let mut limits = QuadLimits::default();
    if let Some(value) = opt_usize_field(map, "maxQuads", "options")? {
        limits.max_quads = value;
    }
    if let Some(value) = opt_usize_field(map, "maxRetainedTermBytes", "options")? {
        limits.max_retained_term_bytes = value;
    }
    Ok(limits)
}

/// Fail-closed options accepted by [`quads_to_ipc`] and [`ipc_to_quads`].
struct IpcOptions {
    limits: QuadLimits,
    max_ipc_bytes: usize,
}

impl IpcOptions {
    fn parse(options: Option<&Value>) -> Result<Self, BindingError> {
        let map = options_map(options)?;
        check_keys(
            &map,
            &["maxQuads", "maxRetainedTermBytes", "maxIpcBytes"],
            "options",
        )?;
        Ok(Self {
            limits: quad_limits_from(&map)?,
            max_ipc_bytes: opt_usize_field(&map, "maxIpcBytes", "options")?
                .unwrap_or(DEFAULT_MAX_IPC_BYTES),
        })
    }
}

/// Fail-closed options accepted by [`quads_to_jelly_frames`].
struct JellyEncodeCallOptions {
    limits: QuadLimits,
    encoder: JellyEncoderOptions,
}

impl JellyEncodeCallOptions {
    fn parse(options: Option<&Value>) -> Result<Self, BindingError> {
        let map = options_map(options)?;
        check_keys(
            &map,
            &[
                "maxQuads",
                "maxRetainedTermBytes",
                "streamName",
                "maxPrefixTableSize",
                "maxNameTableSize",
                "maxDatatypeTableSize",
                "quadsPerFrame",
                "allowProvenanceLoss",
            ],
            "options",
        )?;
        let defaults = JellyEncoderOptions::default();
        let encoder = JellyEncoderOptions {
            stream_name: opt_str_field(&map, "streamName", "options")?.map(str::to_owned),
            max_prefix_table_size: opt_u32_field(&map, "maxPrefixTableSize", "options")?
                .unwrap_or(defaults.max_prefix_table_size),
            max_name_table_size: opt_u32_field(&map, "maxNameTableSize", "options")?
                .unwrap_or(defaults.max_name_table_size),
            max_datatype_table_size: opt_u32_field(&map, "maxDatatypeTableSize", "options")?
                .unwrap_or(defaults.max_datatype_table_size),
            quads_per_frame: opt_usize_field(&map, "quadsPerFrame", "options")?
                .unwrap_or(defaults.quads_per_frame),
            allow_provenance_loss: opt_bool_field(&map, "allowProvenanceLoss", "options")?
                .unwrap_or(defaults.allow_provenance_loss),
            // The JS quad shape has no triple-term form (see
            // `quad_to_value`), so this binding never produces a batch that
            // carries one and never announces RDF-star on the wire.
            rdf_star: false,
            max_quoted_depth: defaults.max_quoted_depth,
        };
        Ok(Self {
            limits: quad_limits_from(&map)?,
            encoder,
        })
    }
}

/// Fail-closed options accepted by [`jelly_frames_to_quads`].
struct JellyDecodeCallOptions {
    decoder: JellyDecoderOptions,
    max_input_bytes: usize,
    max_frames: usize,
}

impl JellyDecodeCallOptions {
    fn parse(options: Option<&Value>) -> Result<Self, BindingError> {
        let map = options_map(options)?;
        check_keys(
            &map,
            &[
                "maxQuads",
                "maxRetainedTermBytes",
                "maxPrefixTableSize",
                "maxNameTableSize",
                "maxDatatypeTableSize",
                "maxInputBytes",
                "maxFrames",
            ],
            "options",
        )?;
        let defaults = JellyDecoderOptions::default();
        let decoder = JellyDecoderOptions {
            quad_limits: quad_limits_from(&map)?,
            max_prefix_table_size: opt_u32_field(&map, "maxPrefixTableSize", "options")?
                .unwrap_or(defaults.max_prefix_table_size),
            max_name_table_size: opt_u32_field(&map, "maxNameTableSize", "options")?
                .unwrap_or(defaults.max_name_table_size),
            max_datatype_table_size: opt_u32_field(&map, "maxDatatypeTableSize", "options")?
                .unwrap_or(defaults.max_datatype_table_size),
        };
        Ok(Self {
            decoder,
            max_input_bytes: opt_usize_field(&map, "maxInputBytes", "options")?
                .unwrap_or(DEFAULT_MAX_IPC_BYTES),
            max_frames: opt_usize_field(&map, "maxFrames", "options")?
                .unwrap_or(DEFAULT_MAX_JELLY_FRAMES),
        })
    }
}

// ---------------------------------------------------------------------------
// Quad object -> oxrdf.
// ---------------------------------------------------------------------------

fn named_node(iri: &str, what: &str) -> Result<NamedNode, BindingError> {
    NamedNode::new(iri)
        .map_err(|error| BindingError::Input(format!("{what}: invalid IRI `{iri}`: {error}")))
}

fn blank_node(id: &str, what: &str) -> Result<BlankNode, BindingError> {
    BlankNode::new(id)
        .map_err(|error| BindingError::Input(format!("{what}: invalid blank node `{id}`: {error}")))
}

/// Parses a `{kind, value}` subject term.
fn parse_subject(value: &Value, what: &str) -> Result<NamedOrBlankNode, BindingError> {
    let map = as_object(value, what)?;
    check_keys(map, &["kind", "value"], what)?;
    let kind = require_str_field(map, "kind", what)?;
    let lexical = require_str_field(map, "value", what)?;
    match kind {
        "iri" => Ok(NamedOrBlankNode::NamedNode(named_node(lexical, what)?)),
        "bnode" => Ok(NamedOrBlankNode::BlankNode(blank_node(lexical, what)?)),
        other => Err(BindingError::Input(format!(
            "{what}.kind must be `iri` or `bnode`, got `{other}`"
        ))),
    }
}

/// Parses a `{kind, value, datatype?, language?}` object term.
fn parse_object_term(value: &Value, what: &str) -> Result<Term, BindingError> {
    let map = as_object(value, what)?;
    check_keys(map, &["kind", "value", "datatype", "language"], what)?;
    let kind = require_str_field(map, "kind", what)?;
    let lexical = require_str_field(map, "value", what)?;
    let datatype = opt_str_field(map, "datatype", what)?;
    let language = opt_str_field(map, "language", what)?;
    if kind != "literal" && (datatype.is_some() || language.is_some()) {
        return Err(BindingError::Input(format!(
            "{what}: `datatype`/`language` are only legal when kind is `literal`"
        )));
    }
    match kind {
        "iri" => Ok(Term::NamedNode(named_node(lexical, what)?)),
        "bnode" => Ok(Term::BlankNode(blank_node(lexical, what)?)),
        "literal" => match (datatype, language) {
            (Some(_), Some(_)) => Err(BindingError::Input(format!(
                "{what}: `datatype` and `language` are mutually exclusive"
            ))),
            (None, Some(language)) => Literal::new_language_tagged_literal(lexical, language)
                .map(Term::Literal)
                .map_err(|error| {
                    BindingError::Input(format!(
                        "{what}: invalid language tag `{language}`: {error}"
                    ))
                }),
            (Some(datatype), None) => Ok(Term::Literal(Literal::new_typed_literal(
                lexical,
                named_node(datatype, what)?,
            ))),
            (None, None) => Ok(Term::Literal(Literal::new_simple_literal(lexical))),
        },
        other => Err(BindingError::Input(format!(
            "{what}.kind must be `iri`, `bnode`, or `literal`, got `{other}`"
        ))),
    }
}

/// Parses an optional `{kind, value?}` graph name (absent = default graph).
fn parse_graph(value: Option<&Value>, what: &str) -> Result<GraphName, BindingError> {
    let Some(value) = value else {
        return Ok(GraphName::DefaultGraph);
    };
    if value.is_null() {
        return Ok(GraphName::DefaultGraph);
    }
    let map = as_object(value, what)?;
    check_keys(map, &["kind", "value"], what)?;
    let kind = require_str_field(map, "kind", what)?;
    match kind {
        "default" => {
            if opt_str_field(map, "value", what)?.is_some() {
                return Err(BindingError::Input(format!(
                    "{what}: the default graph carries no `value`"
                )));
            }
            Ok(GraphName::DefaultGraph)
        }
        "iri" => Ok(GraphName::NamedNode(named_node(
            require_str_field(map, "value", what)?,
            what,
        )?)),
        "bnode" => Ok(GraphName::BlankNode(blank_node(
            require_str_field(map, "value", what)?,
            what,
        )?)),
        other => Err(BindingError::Input(format!(
            "{what}.kind must be `default`, `iri`, or `bnode`, got `{other}`"
        ))),
    }
}

/// Decodes 64 lowercase-or-uppercase hex characters into 32 bytes.
fn parse_sha256_hex(hex: &str, what: &str) -> Result<[u8; 32], BindingError> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(BindingError::Input(format!(
            "{what} must be exactly 64 hex characters, got {}",
            bytes.len()
        )));
    }
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let mut digest = [0u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        let (Some(high), Some(low)) = (nibble(chunk[0]), nibble(chunk[1])) else {
            return Err(BindingError::Input(format!(
                "{what} contains a non-hex character"
            )));
        };
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

/// Parses an optional provenance object.
fn parse_provenance(
    value: Option<&Value>,
    what: &str,
) -> Result<Option<SourceProvenance>, BindingError> {
    let Some(value) = value else { return Ok(None) };
    if value.is_null() {
        return Ok(None);
    }
    let map = as_object(value, what)?;
    check_keys(
        map,
        &[
            "sourceArtifactIri",
            "sourceContentSha256",
            "sourceOffsetStart",
            "sourceOffsetEnd",
            "observedAtMicros",
        ],
        what,
    )?;
    let observed_at_micros = match map.get("observedAtMicros") {
        None | Some(Value::Null) => None,
        Some(value) => Some(number_to_i64(value, &format!("{what}.observedAtMicros"))?),
    };
    Ok(Some(SourceProvenance {
        source_artifact_iri: opt_str_field(map, "sourceArtifactIri", what)?.map(str::to_owned),
        source_content_sha256: opt_str_field(map, "sourceContentSha256", what)?
            .map(|hex| parse_sha256_hex(hex, &format!("{what}.sourceContentSha256")))
            .transpose()?,
        source_offset_start: opt_u64_field(map, "sourceOffsetStart", what)?,
        source_offset_end: opt_u64_field(map, "sourceOffsetEnd", what)?,
        observed_at_micros,
    }))
}

/// Parses one quad object into an owned quad plus optional provenance.
fn parse_quad(
    value: &Value,
    index: usize,
) -> Result<(Quad, Option<SourceProvenance>), BindingError> {
    let what = format!("quads[{index}]");
    let map = as_object(value, &what)?;
    check_keys(
        map,
        &["subject", "predicate", "object", "graph", "provenance"],
        &what,
    )?;
    let subject = parse_subject(
        map.get("subject")
            .ok_or_else(|| BindingError::Input(format!("{what}.subject is required")))?,
        &format!("{what}.subject"),
    )?;
    let predicate = named_node(
        require_str_field(map, "predicate", &what)?,
        &format!("{what}.predicate"),
    )?;
    let object = parse_object_term(
        map.get("object")
            .ok_or_else(|| BindingError::Input(format!("{what}.object is required")))?,
        &format!("{what}.object"),
    )?;
    let graph = parse_graph(map.get("graph"), &format!("{what}.graph"))?;
    let provenance = parse_provenance(map.get("provenance"), &format!("{what}.provenance"))?;
    Ok((Quad::new(subject, predicate, object, graph), provenance))
}

/// Builds one contract batch from a JS array of quad objects.
fn build_batch(
    quads: &Value,
    limits: QuadLimits,
) -> Result<arrow_array::RecordBatch, BindingError> {
    let items = quads
        .as_array()
        .ok_or_else(|| BindingError::Input("quads must be an array".into()))?;
    let mut builder = QuadBatchBuilder::new(limits);
    for (index, item) in items.iter().enumerate() {
        let (quad, provenance) = parse_quad(item, index)?;
        builder.push(quad.as_ref(), provenance.as_ref())?;
    }
    Ok(builder.finish()?)
}

// ---------------------------------------------------------------------------
// oxrdf -> quad object.
// ---------------------------------------------------------------------------

/// Guards a `u64` against the JS-safe integer boundary.
fn safe_u64(value: u64, field: &'static str) -> Result<u64, BindingError> {
    if value > MAX_SAFE_INTEGER {
        return Err(BindingError::Precision { field, value });
    }
    Ok(value)
}

/// Encodes 32 bytes as 64 lowercase hex characters.
fn sha256_to_hex(digest: &[u8]) -> String {
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    hex
}

/// Serializes one decoded quad (plus provenance) back to the JS shape.
fn quad_to_value(quad: QuadRef<'_>, provenance: ProvenanceRef<'_>) -> Result<Value, BindingError> {
    let subject = match quad.subject {
        oxrdf::NamedOrBlankNodeRef::NamedNode(node) => {
            json!({ "kind": "iri", "value": node.as_str() })
        }
        oxrdf::NamedOrBlankNodeRef::BlankNode(node) => {
            json!({ "kind": "bnode", "value": node.as_str() })
        }
    };
    let object = match quad.object {
        oxrdf::TermRef::NamedNode(node) => json!({ "kind": "iri", "value": node.as_str() }),
        oxrdf::TermRef::BlankNode(node) => json!({ "kind": "bnode", "value": node.as_str() }),
        // The documented JS quad shape has `iri`, `bnode`, and `literal`
        // object kinds only. An RDF 1.2 triple term is refused by name
        // rather than flattened into a node reference.
        oxrdf::TermRef::Triple(_) => {
            return Err(QuadError::triple_term_unsupported(
                "the quad-fast-node JS quad shape has no triple-term object kind",
            )
            .into());
        }
        oxrdf::TermRef::Literal(literal) => match literal.language() {
            Some(language) => json!({
                "kind": "literal",
                "value": literal.value(),
                "language": language,
            }),
            None => json!({
                "kind": "literal",
                "value": literal.value(),
                "datatype": literal.datatype().as_str(),
            }),
        },
    };
    let graph = match quad.graph_name {
        oxrdf::GraphNameRef::DefaultGraph => json!({ "kind": "default" }),
        oxrdf::GraphNameRef::NamedNode(node) => json!({ "kind": "iri", "value": node.as_str() }),
        oxrdf::GraphNameRef::BlankNode(node) => json!({ "kind": "bnode", "value": node.as_str() }),
    };
    let mut quad_value = json!({
        "subject": subject,
        "predicate": quad.predicate.as_str(),
        "object": object,
        "graph": graph,
    });

    let mut provenance_map = Map::new();
    if let Some(iri) = provenance.source_artifact_iri {
        provenance_map.insert("sourceArtifactIri".into(), Value::String(iri.to_owned()));
    }
    if let Some(digest) = provenance.source_content_sha256 {
        provenance_map.insert(
            "sourceContentSha256".into(),
            Value::String(sha256_to_hex(digest)),
        );
    }
    if let Some(offset) = provenance.source_offset_start {
        provenance_map.insert(
            "sourceOffsetStart".into(),
            safe_u64(offset, "sourceOffsetStart")?.into(),
        );
    }
    if let Some(offset) = provenance.source_offset_end {
        provenance_map.insert(
            "sourceOffsetEnd".into(),
            safe_u64(offset, "sourceOffsetEnd")?.into(),
        );
    }
    if let Some(micros) = provenance.observed_at_micros {
        safe_u64(micros.unsigned_abs(), "observedAtMicros")?;
        provenance_map.insert("observedAtMicros".into(), micros.into());
    }
    if !provenance_map.is_empty()
        && let Some(quad_map) = quad_value.as_object_mut()
    {
        quad_map.insert("provenance".into(), Value::Object(provenance_map));
    }
    Ok(quad_value)
}

/// Appends every quad of one contract batch to `out`, enforcing `max_quads`
/// as the cumulative output budget.
fn append_batch_quads(
    batch: &arrow_array::RecordBatch,
    max_quads: usize,
    out: &mut Vec<Value>,
) -> Result<(), BindingError> {
    let reader = QuadStreamReader::new(batch)?;
    for row in reader.iter() {
        let (quad, provenance) = row?;
        if out.len() + 1 > max_quads {
            return Err(BindingError::ResourceLimit {
                resource: "decoded_quads",
                limit: max_quads,
                observed: out.len() + 1,
            });
        }
        out.push(quad_to_value(quad, provenance)?);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public conversion entry points (delegated to by the `#[napi]` wrappers).
// ---------------------------------------------------------------------------

/// Builds one `UnsignedQuadStream` batch from quad objects and encodes it as
/// one Arrow IPC stream.
///
/// # Errors
///
/// Returns [`BindingError::Input`] for malformed quad objects or options,
/// [`BindingError::Quad`] when a quad or IPC budget is exceeded or batch
/// assembly fails.
pub fn quads_to_ipc(quads: &Value, options: Option<&Value>) -> Result<Vec<u8>, BindingError> {
    let options = IpcOptions::parse(options)?;
    let batch = build_batch(quads, options.limits)?;
    Ok(write_ipc_stream(&[batch], options.max_ipc_bytes)?)
}

/// Decodes an Arrow IPC stream of contract batches into quad objects.
///
/// # Errors
///
/// Returns [`BindingError::ResourceLimit`] when the payload or decoded quad
/// count exceeds its budget, [`BindingError::Quad`] for non-contract
/// payloads, and [`BindingError::Precision`] when a stored offset cannot be
/// represented as a JS number.
pub fn ipc_to_quads(bytes: &[u8], options: Option<&Value>) -> Result<Value, BindingError> {
    let options = IpcOptions::parse(options)?;
    if bytes.len() > options.max_ipc_bytes {
        return Err(BindingError::ResourceLimit {
            resource: "ipc_input_bytes",
            limit: options.max_ipc_bytes,
            observed: bytes.len(),
        });
    }
    let batches = read_ipc_stream(bytes)?;
    let mut out = Vec::new();
    for batch in &batches {
        append_batch_quads(batch, options.limits.max_quads, &mut out)?;
    }
    Ok(Value::Array(out))
}

/// Builds one contract batch from quad objects and encodes it as
/// length-delimited Jelly stream frames.
///
/// Jelly 1.1.1 carries no per-quad provenance; quads that carry provenance
/// are refused unless `allowProvenanceLoss` is set (mirrors
/// `jelly-fast-core`'s fail-closed resolution of invariant 3).
///
/// # Errors
///
/// Returns [`BindingError::Input`] for malformed quad objects or options,
/// [`BindingError::Quad`] for quad-budget violations, and
/// [`BindingError::Jelly`] for encoder-option or provenance refusals.
pub fn quads_to_jelly_frames(
    quads: &Value,
    options: Option<&Value>,
) -> Result<Vec<u8>, BindingError> {
    let options = JellyEncodeCallOptions::parse(options)?;
    let batch = build_batch(quads, options.limits)?;
    let mut encoder = JellyEncoder::new(options.encoder)?;
    let frames = encoder.encode_batch(&batch)?;
    let mut bytes = Vec::new();
    for frame in &frames {
        frame
            .encode_length_delimited(&mut bytes)
            .map_err(|error| BindingError::FrameDecode(error.to_string()))?;
    }
    Ok(bytes)
}

/// Decodes length-delimited Jelly stream frames into quad objects.
///
/// The whole payload is one logical Jelly stream: the first frame must open
/// with the options row, and lookup-table plus repeated-term state spans
/// frames. Decoded quads never carry provenance (the wire format has none)
/// and are unsigned by construction.
///
/// # Errors
///
/// Returns [`BindingError::ResourceLimit`] when the payload, frame count, or
/// decoded quad count exceeds its budget, [`BindingError::FrameDecode`] for
/// bytes that are not length-delimited frames (including malformed trailing
/// bytes), and [`BindingError::Jelly`] for protocol violations or refused
/// features.
pub fn jelly_frames_to_quads(bytes: &[u8], options: Option<&Value>) -> Result<Value, BindingError> {
    let options = JellyDecodeCallOptions::parse(options)?;
    if bytes.len() > options.max_input_bytes {
        return Err(BindingError::ResourceLimit {
            resource: "jelly_input_bytes",
            limit: options.max_input_bytes,
            observed: bytes.len(),
        });
    }
    let max_quads = options.decoder.quad_limits.max_quads;
    let mut decoder = JellyDecoder::new(options.decoder);
    let mut buf = bytes;
    let mut frames_seen = 0usize;
    let mut out = Vec::new();
    while !buf.is_empty() {
        frames_seen += 1;
        if frames_seen > options.max_frames {
            return Err(BindingError::ResourceLimit {
                resource: "jelly_frames",
                limit: options.max_frames,
                observed: frames_seen,
            });
        }
        let frame = RdfStreamFrame::decode_length_delimited(&mut buf)
            .map_err(|error| BindingError::FrameDecode(error.to_string()))?;
        let batch = decoder.decode_frame(&frame)?;
        append_batch_quads(&batch, max_quads, &mut out)?;
    }
    Ok(Value::Array(out))
}
