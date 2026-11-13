// Rust guideline compliant 2026-02-21
//! JSON-LD 1.1 codec for the semantic dataplane (inline contexts only).
//!
//! Converts JSON-LD documents to and from `UnsignedQuadStream` v1 batches
//! ([`quad_fast_core`]). Processing is deterministic: the same input always
//! yields the same expanded document and the same quad rows, including
//! blank node labels.
//!
//! Output is **unsigned by construction**:
//! decoding preserves term identity, named-graph identity, and source
//! provenance, but never certifies a source or promotes a fact. This crate
//! is also a **sovereign boundary**: it performs no network I/O. A context
//! given as a string, or an `@import` entry, would require fetching a remote
//! document and is refused with [`JsonLdError::RemoteContextRefused`] naming
//! the IRI — never fetched, never silently skipped.
//!
//! > Gate: JSON-LD flattening is currently gated out; the canonical
//! > `flatten` implementation was not part of the restoration, and it is
//! > not invented here.
//!
//! # Supported (JSON-LD 1.1, inline contexts)
//!
//! - Inline `@context` values: term definitions (string shorthand and object
//!   form), `@id`, `@type` (including `@id`/`@vocab` coercion and
//!   `@type: @json` literals), `@language` and `@direction` (default and
//!   per-term, including `null` overrides), `@vocab`, `@base` (RFC 3986
//!   reference resolution), `@prefix`, compact IRIs, keyword aliasing,
//!   `@protected` (identical redefinition allowed, conflicting redefinition
//!   and nullification are errors), `@version: 1.1`, `@reverse` term
//!   definitions, `@nest` values, scoped (embedded) contexts on term
//!   definitions with `@propagate` semantics (type-scoped contexts revert
//!   on new node objects; property-scoped contexts may override protected
//!   terms), and the full 1.1 `@container` grammar: `@list`, `@set`,
//!   `@index`, `@id`, `@type`, `@graph`, `@language` (language maps),
//!   combinations with `@set`, `@graph` with `@id` or `@index`, and
//!   property-based `@index` (section 4.6.1.1).
//! - Expansion per the JSON-LD 1.1 Expansion Algorithm (API section 5.1.2),
//!   including `@graph`, `@reverse` (term and keyword form), `@index` keys,
//!   index/id/type/language container maps (`@none` keys included), graph
//!   containers, `@nest` unfolding, `@included`, JSON-LD-star embedded `@id`
//!   nodes, `@annotation`, value objects with `@direction`, JSON literals,
//!   and free-floating-node dropping.
//! - RDF deserialization (API section 8.1): deterministic `_:b0`-style
//!   blank node issuer, `@list` chains, named graphs, reverse-property
//!   triples, `@included` nodes, the number/boolean/string round-tripping
//!   rules, `rdf:JSON` literals in the canonical form of JSON-LD 1.1
//!   section 10.2, and `@direction` via `rdfDirection: i18n-datatype`
//!   (documented fixed choice; compound literals are not emitted).
//! - Compaction per the JSON-LD 1.1 API section 5.2 (inverse context
//!   construction, IRI compaction with term selection over container
//!   preferences and `@reverse`, compact IRIs, `@vocab`, value compaction,
//!   `compactArrays`, keyword aliasing on output) with deterministic
//!   ordered output.
//! - Framing per the JSON-LD 1.1 Framing REC (sections 4.1–4.3): node
//!   pattern, wildcard and match-none patterns, duplicate suppression,
//!   `@embed` (`@once`/`@always`/`@never`), `@explicit`, `@requireAll`,
//!   `@omitDefault`, `@default`, value pattern matching, blank node
//!   pruning, `@reverse` incoming-edge matching (Framing section 2.3),
//!   and deterministic blank node ordering. Framing runs over the
//!   default graph; named graphs are reached through `@graph` entries to
//!   the extent expansion supports them.
//! - RDF serialization (API section 8.4): quad batches back to expanded
//!   JSON-LD, decoding `rdf:JSON` and i18n datatypes. Well-formed
//!   `rdf:first`/`rdf:rest` chains reassemble into `@list` arrays;
//!   malformed chains stay as triples.
//! - Streaming document form (JSON-LD Streaming Note): required key order
//!   `@context`, then `@type`, then other properties is validated on the
//!   source JSON text; a violation is
//!   [`JsonLdError::InvalidStreamingKeyOrder`]. Maps nested under
//!   `@context` are exempt. [`write_streaming_document`] / [`from_quads_streaming`]
//!   emit that order as JSON text (`serde_json::Value` cannot carry it).
//!   [`expand_streaming_graph`] / [`parse_streaming_graph`] yield each
//!   top-level `@graph` (or top-level array) element without retaining the
//!   full graph array.
//! - YAML-LD Basic profile (default): UTF-8 YAML 1.2 Core Schema streams
//!   convert to the JSON-LD internal representation (string keys, no alias
//!   nodes, no inf/nan). [`YamlLdOptions::extract_all_scripts`] selects
//!   first-document vs the whole stream as an array.
//! - YAML-LD Extended profile ([`YamlLdProfile::Extended`]): aliases
//!   compose as copies (cycles fail closed), and non-Core IRI tags become
//!   JSON-LD value objects with `@type` set to that IRI. Local `!foo` tags
//!   that are not IRIs are a `profile_error`.
//! - JSON-LD-star embedded nodes in object position: a property value
//!   `{"@id": {embedded node}}` round-trips through `toRdf`/`fromRdf` as
//!   an RDF 1.2 triple term. Quoted triples in subject/predicate/graph
//!   position stay [`JsonLdFeature::RdfStarTripleTerm`].
//!
//! # Refused features (typed errors, never silent)
//!
//! - Remote contexts and `@import`
//!   ([`JsonLdError::RemoteContextRefused`]): the sovereign no-network
//!   boundary.
//! - Quoted triples in subject, predicate, or graph position
//!   ([`JsonLdFeature::RdfStarTripleTerm`]): the quad contract has no
//!   triple-term subject. Object-position triple terms use JSON-LD-star
//!   embedded nodes instead of this refusal.
//! - `@type: @none` in term definitions stays an `invalid_context` error.
//! - Remote frames (a frame given as a string) and remote frame contexts
//!   ([`JsonLdError::RemoteContextRefused`]).
//! - Malformed frames fail closed with [`JsonLdError::InvalidFrame`] and
//!   [`JsonLdError::InvalidEmbedValue`] (the Framing REC `invalid frame`
//!   and `invalid @embed value` error codes).
//!
//! # Spec-mandated drops (not deviations)
//!
//! Keys that expand to neither a keyword nor an IRI, values with keyword
//! form, free-floating scalars or value objects, `@index` when converting
//! to RDF, and the `@index` entry of an unwrapped `@set` object are dropped,
//! exactly as the JSON-LD 1.1 algorithms require.
//!
//! # Fail-closed budgets
//!
//! [`JsonLdLimits`] governs input bytes, JSON values visited, and document
//! nesting depth. Two further budgets exist because they guard the native
//! stack against inputs those three cannot see:
//!
//! - the payload of a `@type: @json` entry is charged to
//!   [`JsonLdLimits::max_nodes`] and [`JsonLdLimits::max_depth`] *before*
//!   it is copied, even though expansion never descends into it (spec step
//!   13.7 copies it verbatim);
//! - context processing recurses on a scoped context and on a prefix
//!   chain, neither of which is document nesting — a prefix chain is flat
//!   JSON — so both are bounded by [`MAX_CONTEXT_RECURSION`] and refused
//!   with [`JsonLdResource::ContextRecursion`];
//! - framing embeds referenced nodes inside their referrers, so a flat
//!   chain of N nodes frames N levels deep: embedding is bounded by
//!   [`MAX_FRAME_EMBED_DEPTH`] ([`JsonLdResource::EmbedDepth`]) and every
//!   embedded copy is charged to [`JsonLdLimits::max_nodes`], which stops
//!   `@embed: @always` from multiplying a shared node exponentially.
//!
//! Every caller-built [`serde_json::Value`] (document, frame, compaction
//! context) is measured against [`JsonLdLimits::max_depth`] with an
//! explicit heap stack before any recursive code — including `clone` —
//! touches it, so a value nested 100,000 levels deep is refused instead of
//! overflowing the native stack. Native stack use per level is large in
//! unoptimized builds (about 17 KiB per object level in expansion), so a
//! document *within* the limit but deeper than a few levels is processed
//! on a short-lived worker thread whose stack is sized from its measured
//! depth; shallow documents run inline. The caller's stack size therefore
//! never decides whether a legal document can be processed.
//!
//! # Deliberate deviations (all fail closed)
//!
//! - IRIs that stay relative after expansion fail closed with
//!   [`JsonLdError::RelativeIri`]; the spec drops the node silently.
//! - Malformed `@language` tags are errors, not spec warnings (a fail-closed
//!   dataplane has no warning channel).
//! - Raw nested arrays inside a `@container: @list` value are flattened, not
//!   turned into nested lists; explicit `{"@list": [...]}` objects nest
//!   correctly.
//! - Blank node predicates (forward or reverse) raise
//!   [`JsonLdError::InvalidTerm`]: generalized RDF is not representable in
//!   the quad contract.
//! - `@json` as a node object `@type`, value objects inside `@id`/`@type`
//!   container maps, entries other than `@container`/`@protected` in a
//!   `@reverse` term definition, and `@included` entries whose content
//!   expands to nothing are errors; the spec would silently produce or drop
//!   malformed data in these positions.
//! - JSON literal integers outside the exact IEEE 754 double range are
//!   errors (RFC 8785 treats all numbers as doubles; changing the value
//!   silently is not acceptable here).
//!
//! # Examples
//!
//! ```
//! use jsonld_fast_core::{JsonLdOptions, expand, from_quads, to_quads};
//! use serde_json::json;
//!
//! # fn main() -> Result<(), jsonld_fast_core::JsonLdError> {
//! let document = json!({
//!     "@context": {"name": "http://schema.org/name"},
//!     "@id": "http://example.com/alice",
//!     "name": "Alice"
//! });
//! let options = JsonLdOptions::default();
//! let expanded = expand(&document, &options)?;
//! assert_eq!(expanded[0]["@id"], "http://example.com/alice");
//!
//! let batches = to_quads(&document, &options, None)?;
//! assert_eq!(batches[0].num_rows(), 1);
//!
//! let round_tripped = from_quads(&batches)?;
//! assert_eq!(round_tripped[0]["http://schema.org/name"][0]["@value"], "Alice");
//! # Ok(())
//! # }
//! ```

mod compact;
mod context;
mod error;
mod expand;
mod frame;
mod from_rdf;
mod guard;
mod iri;
mod json_canon;
mod node_map;
mod options;
mod streaming;
mod to_rdf;
mod yaml;

use arrow_array::RecordBatch;
use quad_fast_core::{QuadBatchBuilder, SourceProvenance};
use serde_json::Value;

pub use error::{JsonLdError, JsonLdFeature, JsonLdResource};
pub use options::{
    DEFAULT_MAX_DEPTH, DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_NODES, JsonLdLimits, JsonLdOptions,
    MAX_CONTEXT_RECURSION, MAX_FRAME_EMBED_DEPTH,
};
pub use streaming::{
    ExpandStreamingGraph, STREAMING_PROFILE, StreamingGraphNodes, compact_streaming,
    expand_streaming, expand_streaming_graph, from_quads_streaming, parse_streaming_document,
    parse_streaming_graph, to_quads_streaming, validate_streaming_form, write_streaming_document,
};
pub use yaml::{
    YamlLdOptions, YamlLdProfile, compact_yaml_ld, expand_yaml_ld, parse_yaml_ld,
    parse_yaml_ld_bytes, to_quads_yaml_ld, to_yaml_ld,
};

/// Parses raw JSON text under the fail-closed input budget.
///
/// # Errors
///
/// Returns [`JsonLdError::ResourceLimit`] when `text` exceeds
/// [`JsonLdLimits::max_input_bytes`] and [`JsonLdError::InvalidJson`] when
/// the text is not valid JSON.
pub fn parse_document(text: &str, limits: &JsonLdLimits) -> Result<Value, JsonLdError> {
    if text.len() > limits.max_input_bytes {
        return Err(JsonLdError::ResourceLimit {
            resource: JsonLdResource::InputBytes,
            limit: limits.max_input_bytes,
            observed: text.len(),
        });
    }
    serde_json::from_str(text).map_err(|error| JsonLdError::InvalidJson(error.to_string()))
}

/// Expands a JSON-LD document to expanded form (a top-level array).
///
/// # Errors
///
/// Returns the typed [`JsonLdError`] raised by context processing, refused
/// features, malformed documents, or an exceeded resource limit.
pub fn expand(document: &Value, options: &JsonLdOptions) -> Result<Value, JsonLdError> {
    let depth = guard::check_nesting(document, options.limits.max_depth)?;
    guard::run_sized(depth, || expand::expand_document(document, options))
}

/// Compacts a JSON-LD document against an inline context
/// (JSON-LD 1.1 API section 6, `JsonLdProcessor.compact`).
///
/// The document is expanded first, so compacted, expanded, and framed
/// inputs are all accepted. `context` is either a context value (a map, or
/// an array of maps) or a map carrying an `@context` entry; a string
/// context names a remote document and is refused. The result is
/// deterministic: entries are ordered, term selection and compact-IRI
/// choice resolve by total orders, and single-element arrays collapse
/// exactly when [`JsonLdOptions::compact_arrays`] permits. The context is
/// attached to the output under `@context` unless it is empty.
///
/// # Errors
///
/// Returns expansion errors for `document`, context-processing errors for
/// `context` (including [`JsonLdError::RemoteContextRefused`]), and
/// [`JsonLdError::InvalidTerm`] for the API's `IRI confused with prefix`
/// condition.
pub fn compact(
    document: &Value,
    context: &Value,
    options: &JsonLdOptions,
) -> Result<Value, JsonLdError> {
    // The context is caller-built and is cloned below; `Clone` recurses, so
    // its nesting is bounded before anything touches it.
    let context_depth = guard::check_nesting(context, options.limits.max_depth)?;
    let document_depth = guard::check_nesting(document, options.limits.max_depth)?;
    guard::run_sized(context_depth.max(document_depth), || {
        let expanded = expand::expand_document(document, options)?;
        let context_value = match context {
            Value::Object(map) => map
                .get("@context")
                .cloned()
                .unwrap_or_else(|| Value::Object(map.clone())),
            other => other.clone(),
        };
        let compacted = compact::compact_expanded(&expanded, &context_value, options)?;
        Ok(compact::attach_context(compacted, &context_value))
    })
}

/// Frames `document` with `frame` (JSON-LD 1.1 Framing REC section 4.1).
///
/// The document is expanded and turned into a node map (API section 7.2.2)
/// with deterministic `_:b0`-style blank node relabeling; the frame is
/// expanded in frame-expansion mode and matched per Frame Matching
/// (Framing section 4.2), honouring `@embed` (`@once`/`@always`/`@never`),
/// `@explicit`, `@requireAll`, `@omitDefault`, and `@default`. The framed
/// output is compacted with the frame's own inline `@context`. Framing runs
/// over the default graph; a string frame or a remote frame context is
/// refused.
///
/// Embedding is bounded by [`MAX_FRAME_EMBED_DEPTH`]. A framing that embeds
/// more than a few levels deep is re-run on a short-lived worker thread
/// whose stack is sized for that bound, so the caller's stack size does not
/// limit it; the returned value can still nest that deep.
///
/// # Errors
///
/// Returns [`JsonLdError::InvalidFrame`] and
/// [`JsonLdError::InvalidEmbedValue`] for frame grammar violations,
/// [`JsonLdError::RemoteContextRefused`] for
/// remote frame contexts, [`JsonLdError::ResourceLimit`] with
/// [`JsonLdResource::EmbedDepth`] or [`JsonLdResource::Nodes`] when
/// embedding exceeds its bounds, and every expansion and compaction error
/// of the document and the frame.
pub fn frame(
    document: &Value,
    frame: &Value,
    options: &JsonLdOptions,
) -> Result<Value, JsonLdError> {
    let frame_depth = guard::check_nesting(frame, options.limits.max_depth)?;
    let document_depth = guard::check_nesting(document, options.limits.max_depth)?;
    guard::run_sized(frame_depth.max(document_depth), || {
        frame::frame_document(document, frame, options)
    })
}

/// Deserializes a JSON-LD document to `UnsignedQuadStream` batches.
///
/// The document is expanded first, so both compacted and expanded inputs are
/// accepted. All rows carry `provenance` when given. The current
/// implementation emits exactly one batch governed by
/// [`JsonLdOptions::quad_limits`]; the limit fails closed over the whole
/// document.
///
/// # Errors
///
/// Returns expansion errors, [`JsonLdError::RelativeIri`] for IRIs that
/// stayed relative, [`JsonLdError::InvalidTerm`] for unrepresentable terms,
/// and [`JsonLdError::Quad`] when a quad-batch budget is exceeded.
pub fn to_quads(
    document: &Value,
    options: &JsonLdOptions,
    provenance: Option<&SourceProvenance>,
) -> Result<Vec<RecordBatch>, JsonLdError> {
    let depth = guard::check_nesting(document, options.limits.max_depth)?;
    let quads = guard::run_sized(depth, || {
        let expanded = expand::expand_document(document, options)?;
        to_rdf::expanded_to_quads(&expanded)
    })?;
    let mut builder = QuadBatchBuilder::new(options.quad_limits);
    for quad in &quads {
        builder.push(quad.as_ref(), provenance)?;
    }
    Ok(vec![builder.finish()?])
}

/// Serializes `UnsignedQuadStream` batches to an expanded JSON-LD document.
///
/// Named graphs group under `@graph` on the node whose `@id` is the graph
/// name; well-formed `rdf:first`/`rdf:rest` chains reassemble into `@list`
/// arrays. The output is deterministic: nodes and predicates are
/// sorted.
///
/// # Errors
///
/// Returns [`JsonLdError::Quad`] when a batch fails contract validation or
/// a row does not decode to a valid quad, and [`JsonLdError::ResourceLimit`]
/// when lists nest deeper than [`DEFAULT_MAX_DEPTH`] or repeated copies of
/// shared lists exceed [`DEFAULT_MAX_NODES`] values; use
/// [`from_quads_with_limits`] to raise them.
pub fn from_quads(batches: &[RecordBatch]) -> Result<Value, JsonLdError> {
    from_rdf::quads_to_expanded(batches, &JsonLdLimits::default())
}

/// [`from_quads`] with caller-chosen list budgets.
///
/// Well-formed `rdf:first`/`rdf:rest` chains become `@list` arrays. Lists
/// may nest at most [`JsonLdLimits::max_depth`] deep, and copies made
/// because one list is referenced from several places may total at most
/// [`JsonLdLimits::max_nodes`] values (the first use of each list is not
/// charged). [`from_quads`] uses [`JsonLdLimits::default`].
///
/// # Errors
///
/// The errors of [`from_quads`], with the limits taken from `limits`.
pub fn from_quads_with_limits(
    batches: &[RecordBatch],
    limits: &JsonLdLimits,
) -> Result<Value, JsonLdError> {
    from_rdf::quads_to_expanded(batches, limits)
}
