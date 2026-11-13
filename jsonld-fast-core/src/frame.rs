// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Framing of JSON-LD documents (JSON-LD 1.1 Framing REC).
//!
//! Implements the Framing Algorithm (Framing section 4.1) and Frame
//! Matching (section 4.2) over a node map built with Node Map Generation
//! (JSON-LD 1.1 API section 7.2.2). The frame expands in frame-expansion
//! mode ([`crate::expand`]); the framed output compacts through
//! [`crate::compact`] with the frame's own `@context`.
//!
//! Determinism: blank nodes are relabeled `_:b0, _:b1, ...` in encounter
//! order during node map generation (the shared issuer in
//! [`crate::node_map`]), subjects are always visited in sorted order, and
//! the output maps are `BTreeMap`-backed.
//!
//! Documented fixed choices (fail-closed, mirroring the crate's
//! `rdfDirection` precedent):
//!
//! - Framing runs over the **default graph** (the `frameDefault` behavior).
//!   Merging node maps would erase named-graph identity, which this
//!   dataplane guarantees survives every transformation; named graphs are
//!   framed explicitly through `@graph` entries in the frame.
//! - The API options keep their spec defaults: object embed flag `@once`,
//!   `explicit` and `requireAll` and `omitDefault` false, blank node
//!   pruning on, `omitGraph` on (JSON-LD 1.1 processing mode). Frames
//!   override them per node with `@embed`, `@explicit`, `@requireAll`, and
//!   `@omitDefault`.
//! - `@reverse` inside a frame matches incoming edges (Framing section 2.3)
//!   and embeds the referring nodes under `@reverse` (or a reverse term).

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use crate::{
    error::{JsonLdError, JsonLdResource},
    expand,
    node_map::{DEFAULT_GRAPH, Graph, GraphMap, build_node_map},
    options::{
        FRAME_STACK_PER_EMBED_LEVEL, FRAME_WORKER_BASE_STACK, JsonLdOptions, MAX_FRAME_EMBED_DEPTH,
    },
};

/// Embed depth framed on the caller's own thread before escalating.
///
/// Framing and the compaction of its output recurse once per embed level.
/// A shallow framing (the common case) runs inline at no extra cost; one
/// that embeds deeper is re-run on a worker thread whose stack is sized
/// for [`MAX_FRAME_EMBED_DEPTH`]. The threshold keeps the inline run within
/// a 256 KiB caller stack: unoptimized builds use about 25 KiB of native
/// stack per embed level (measured), optimized builds a small fraction of
/// that.
const INLINE_EMBED_DEPTH: usize = if cfg!(debug_assertions) { 4 } else { 24 };

/// Frames `document` with `frame` (JSON-LD 1.1 Framing section 4.1).
///
/// # Errors
///
/// Returns [`JsonLdError::InvalidFrame`] and
/// [`JsonLdError::InvalidEmbedValue`] for frame grammar violations
/// and every expansion, context-processing, or compaction error of the
/// document and the frame's context.
pub(crate) fn frame_document(
    document: &Value,
    frame: &Value,
    options: &JsonLdOptions,
    (document_budget, frame_budget): (usize, usize),
) -> Result<Value, JsonLdError> {
    let Value::Object(frame_map) = frame else {
        return Err(JsonLdError::InvalidFrame(
            "a frame must be a map".to_owned(),
        ));
    };
    let expanded_frame = expand::expand_frame_document(frame, options, frame_budget)?;
    let frame_object = match &expanded_frame {
        Value::Array(items) if items.is_empty() => Map::new(),
        Value::Array(items) if items.len() == 1 => match &items[0] {
            Value::Object(map) => map.clone(),
            _ => {
                return Err(JsonLdError::InvalidFrame(
                    "a frame must expand to a node pattern".to_owned(),
                ));
            }
        },
        _ => {
            return Err(JsonLdError::InvalidFrame(
                "a frame must expand to a single node pattern".to_owned(),
            ));
        }
    };
    validate_frame(&frame_object)?;

    let expanded_input = expand::expand_document(document, options, document_budget)?;
    let graphs = build_node_map(&expanded_input)?;
    let subjects: Vec<String> = graphs
        .get(DEFAULT_GRAPH)
        .map(|graph| graph.keys().cloned().collect())
        .unwrap_or_default();
    let context_value = frame_map.get("@context").cloned().unwrap_or(Value::Null);
    let run = FramingRun {
        graphs: &graphs,
        subjects: &subjects,
        frame: &frame_object,
        context_value: &context_value,
        options,
        output_budget: document_budget,
    };

    // Embedding follows references in the node map, not document nesting:
    // a flat `@graph` of N chained nodes embeds N levels deep. Try the
    // shallow case inline, and re-run a deeper one on a sized worker stack.
    match run.execute(INLINE_EMBED_DEPTH) {
        Err(FrameAbort::TooDeepForInline) => run_on_worker(&run),
        Err(FrameAbort::Failed(error)) => Err(error),
        Ok(framed) => Ok(framed),
    }
}

/// Inputs of one framing run (everything after expansion and the node map).
#[derive(Debug)]
struct FramingRun<'run> {
    graphs: &'run GraphMap,
    subjects: &'run [String],
    frame: &'run Map<String, Value>,
    context_value: &'run Value,
    options: &'run JsonLdOptions,
    /// Output budget of the framed document's compaction.
    output_budget: usize,
}

/// Why a framing run stopped.
#[derive(Debug)]
enum FrameAbort {
    /// The inline embed-depth threshold was reached; re-run on a worker.
    TooDeepForInline,
    /// A real framing, budget, or compaction error.
    Failed(JsonLdError),
}

impl FramingRun<'_> {
    /// Frames, prunes, and compacts with embedding capped at `embed_cap`.
    fn execute(&self, embed_cap: usize) -> Result<Value, FrameAbort> {
        let max_embed_depth = embed_cap.min(MAX_FRAME_EMBED_DEPTH);
        let mut state = FramingState {
            graphs: self.graphs,
            current_graph: DEFAULT_GRAPH.to_owned(),
            unique_embeds: HashMap::new(),
            subject_stack: Vec::new(),
            embed: Embed::Once,
            explicit: false,
            require_all: false,
            omit_default: false,
            max_embed_depth,
            embedded_values: 0,
            max_embedded_values: self.options.limits.max_nodes,
        };
        let mut results = Vec::new();
        if let Err(error) = frame_subjects(&mut state, self.subjects, self.frame, &mut results) {
            let inline_cap_hit = max_embed_depth < MAX_FRAME_EMBED_DEPTH
                && matches!(
                    error,
                    JsonLdError::ResourceLimit {
                        resource: JsonLdResource::EmbedDepth,
                        ..
                    }
                );
            return Err(if inline_cap_hit {
                FrameAbort::TooDeepForInline
            } else {
                FrameAbort::Failed(error)
            });
        }
        prune_blank_node_identifiers(&mut results);

        // Compact the framed output with the frame's own context, wrap per
        // omitGraph, clean up @preserve/@null, then attach the context.
        let compacted = crate::compact::compact_expanded(
            &Value::Array(results),
            self.context_value,
            self.options,
            self.output_budget,
        )
        .map_err(FrameAbort::Failed)?;
        let cleaned = cleanup_preserved(compacted);
        Ok(crate::compact::attach_context(cleaned, self.context_value))
    }
}

/// Re-runs `run` on a worker thread whose stack fits
/// [`MAX_FRAME_EMBED_DEPTH`] embed levels.
///
/// Partial results are built and dropped on the worker, so the caller's
/// stack never holds more than the inline threshold of embed recursion.
fn run_on_worker(run: &FramingRun<'_>) -> Result<Value, JsonLdError> {
    let stack_bytes = MAX_FRAME_EMBED_DEPTH
        .saturating_mul(FRAME_STACK_PER_EMBED_LEVEL)
        .saturating_add(FRAME_WORKER_BASE_STACK);
    std::thread::scope(|scope| {
        let spawned = std::thread::Builder::new()
            .name("jsonld-frame".to_owned())
            .stack_size(stack_bytes)
            .spawn_scoped(scope, || run.execute(MAX_FRAME_EMBED_DEPTH));
        let Ok(handle) = spawned else {
            // No worker stack: refuse rather than recurse on a caller
            // stack that was never sized for this embed depth.
            return Err(JsonLdError::WorkerUnavailable {
                stack_bytes,
                depth: INLINE_EMBED_DEPTH.saturating_add(1),
            });
        };
        match handle.join() {
            Ok(Ok(framed)) => Ok(framed),
            Ok(Err(FrameAbort::Failed(error))) => Err(error),
            // Unreachable: the worker runs at the full cap, so a depth
            // refusal there is `Failed`. Fail closed regardless.
            Ok(Err(FrameAbort::TooDeepForInline)) => Err(JsonLdError::ResourceLimit {
                resource: JsonLdResource::EmbedDepth,
                limit: MAX_FRAME_EMBED_DEPTH,
                observed: MAX_FRAME_EMBED_DEPTH.saturating_add(1),
            }),
            // A panic on the worker is a bug; propagate it unchanged.
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

/// Validates the expanded frame (the Framing spec's `invalid frame` error).
fn validate_frame(frame: &Map<String, Value>) -> Result<(), JsonLdError> {
    for (key, value) in frame {
        match key.as_str() {
            "@reverse" => {
                let Some(reverse_map) = value.as_object() else {
                    return Err(JsonLdError::InvalidFrame(
                        "@reverse must be a map".to_owned(),
                    ));
                };
                for (property, subframe) in reverse_map {
                    if property.starts_with('@') {
                        return Err(JsonLdError::InvalidFrame(format!(
                            "keyword `{property}` is not valid inside @reverse"
                        )));
                    }
                    validate_frame_value(subframe)?;
                }
            }
            "@id" => {
                let valid = match value {
                    Value::String(_) => true,
                    Value::Array(items) => items
                        .iter()
                        .all(|item| item.is_string() || is_empty_map(item)),
                    _ => false,
                };
                if !valid {
                    return Err(JsonLdError::InvalidFrame(
                        "@id must hold IRI strings or the {} wildcard".to_owned(),
                    ));
                }
            }
            "@type" => {
                let valid = match value {
                    Value::Array(items) => items.iter().all(|item| {
                        item.is_string()
                            || is_empty_map(item)
                            || item
                                .as_object()
                                .is_some_and(|map| map.len() == 1 && map.contains_key("@default"))
                    }),
                    _ => false,
                };
                if !valid {
                    return Err(JsonLdError::InvalidFrame(
                        "@type must hold IRI strings, {}, or {\"@default\": ...}".to_owned(),
                    ));
                }
            }
            keyword if keyword.starts_with('@') => {}
            _ => validate_frame_value(value)?,
        }
    }
    Ok(())
}

/// Recurses into a property or reverse-property subframe.
fn validate_frame_value(value: &Value) -> Result<(), JsonLdError> {
    match value {
        Value::Object(map) => validate_frame(map),
        Value::Array(items) => {
            for item in items {
                if let Some(map) = item.as_object() {
                    validate_frame(map)?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn is_empty_map(value: &Value) -> bool {
    value.as_object().is_some_and(Map::is_empty)
}

// ===========================================================================
// Framing (JSON-LD 1.1 Framing sections 4.1 and 4.2)
// ===========================================================================

/// The object embed flag (Framing section 4.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Embed {
    /// Embed at the first reference only (the 1.1 default).
    Once,
    /// Embed at every reference (cycles still fall back to references).
    Always,
    /// Never embed; always emit node references.
    Never,
}

/// Mutable framing state (Framing section 4.1).
#[derive(Debug)]
struct FramingState<'graphs> {
    /// The node map.
    graphs: &'graphs GraphMap,
    /// The graph currently being framed.
    current_graph: String,
    /// Per-graph registry of `@once`-embedded subjects.
    unique_embeds: HashMap<String, HashSet<String>>,
    /// Subjects on the recursion stack (cycle protection).
    subject_stack: Vec<(String, String)>,
    /// The inherited object embed flag (Framing section 4.1 state).
    embed: Embed,
    /// The inherited `@explicit` flag.
    explicit: bool,
    /// The inherited `@requireAll` flag.
    require_all: bool,
    /// The inherited `@omitDefault` flag.
    omit_default: bool,
    /// Embed nesting allowed in this run (see [`MAX_FRAME_EMBED_DEPTH`]).
    max_embed_depth: usize,
    /// Node values copied into the output so far.
    embedded_values: usize,
    /// Budget for `embedded_values` ([`crate::JsonLdLimits::max_nodes`]).
    max_embedded_values: usize,
}

/// Reads a boolean framing flag from `frame`, with the spec default.
fn frame_flag(frame: &Map<String, Value>, keyword: &str, default: bool) -> bool {
    match frame.get(keyword) {
        Some(Value::Bool(flag)) => *flag,
        _ => default,
    }
}

/// Reads the object embed flag from `frame` (Framing section 4.1).
fn frame_embed(frame: &Map<String, Value>, default: Embed) -> Result<Embed, JsonLdError> {
    match frame.get("@embed") {
        None => Ok(default),
        Some(Value::Bool(true)) => Ok(Embed::Once),
        Some(Value::Bool(false)) => Ok(Embed::Never),
        Some(Value::String(text)) => match text.as_str() {
            "@once" => Ok(Embed::Once),
            "@always" => Ok(Embed::Always),
            "@never" => Ok(Embed::Never),
            other => Err(JsonLdError::InvalidEmbedValue {
                value: other.to_owned(),
            }),
        },
        Some(other) => Err(JsonLdError::InvalidEmbedValue {
            value: other.to_string(),
        }),
    }
}

/// Frames `subjects` against `frame`, appending matches to `output`
/// (Framing section 4.1).
fn frame_subjects(
    state: &mut FramingState<'_>,
    subjects: &[String],
    frame: &Map<String, Value>,
    output: &mut Vec<Value>,
) -> Result<(), JsonLdError> {
    validate_frame(frame)?;
    // Framing section 4.1: the flags live in the framing state; a frame
    // object overrides them for itself and everything it frames below.
    let outer = (
        state.embed,
        state.explicit,
        state.require_all,
        state.omit_default,
    );
    let embed = frame_embed(frame, state.embed)?;
    let explicit = frame_flag(frame, "@explicit", state.explicit);
    let require_all = frame_flag(frame, "@requireAll", state.require_all);
    let omit_default = frame_flag(frame, "@omitDefault", state.omit_default);
    state.embed = embed;
    state.explicit = explicit;
    state.require_all = require_all;
    state.omit_default = omit_default;
    let result = frame_subjects_inner(
        state,
        subjects,
        frame,
        output,
        embed,
        explicit,
        require_all,
        omit_default,
    );
    state.embed = outer.0;
    state.explicit = outer.1;
    state.require_all = outer.2;
    state.omit_default = outer.3;
    result
}

/// The body of [`frame_subjects`], with the framing flags already resolved.
#[expect(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "mirrors the sequential steps of Framing section 4.1"
)]
fn frame_subjects_inner(
    state: &mut FramingState<'_>,
    subjects: &[String],
    frame: &Map<String, Value>,
    output: &mut Vec<Value>,
    embed: Embed,
    explicit: bool,
    require_all: bool,
    omit_default: bool,
) -> Result<(), JsonLdError> {
    let graph = state.current_graph.clone();
    let empty_graph = Graph::new();
    let graph_nodes = state.graphs.get(&graph).unwrap_or(&empty_graph);

    for id in subjects {
        let Some(node) = graph_nodes.get(id) else {
            continue;
        };
        if !matches_frame(node, frame, require_all, graph_nodes)? {
            continue;
        }
        let node = node.clone();
        let circular = state
            .subject_stack
            .iter()
            .any(|(stack_graph, stack_id)| stack_graph == &graph && stack_id == id);
        if embed == Embed::Never || circular {
            output.push(node_reference(id));
            continue;
        }
        if embed == Embed::Once
            && !state
                .unique_embeds
                .entry(graph.clone())
                .or_default()
                .insert(id.clone())
        {
            output.push(node_reference(id));
            continue;
        }
        charge_embed(state, &node)?;
        state.subject_stack.push((graph.clone(), id.clone()));
        let mut out: Map<String, Value> = Map::new();
        out.insert("@id".to_owned(), Value::String(id.clone()));

        // Named graph recursion: a node that names a graph frames its
        // content when the frame carries an @graph entry.
        if state.graphs.contains_key(id)
            && let Some(graph_frame) = frame.get("@graph")
        {
            let subframe = first_frame_object(graph_frame);
            let inner_subjects: Vec<String> = state
                .graphs
                .get(id)
                .map(|inner| inner.keys().cloned().collect())
                .unwrap_or_default();
            let previous_graph = std::mem::replace(&mut state.current_graph, id.clone());
            let mut inner_output = Vec::new();
            frame_subjects(state, &inner_subjects, &subframe, &mut inner_output)?;
            state.current_graph = previous_graph;
            out.insert("@graph".to_owned(), Value::Array(inner_output));
        }

        for (property, values) in &node {
            match property.as_str() {
                "@id" => {}
                "@type" | "@index" => {
                    out.insert(property.clone(), values.clone());
                }
                keyword if keyword.starts_with('@') => {
                    out.insert(keyword.to_owned(), values.clone());
                }
                property => {
                    // Framing section 4.1: @explicit skips properties the
                    // frame does not mention.
                    if explicit && !frame.contains_key(property) {
                        continue;
                    }
                    let Value::Array(values) = values else {
                        continue;
                    };
                    let subframe = frame
                        .get(property)
                        .map_or_else(Map::new, first_frame_object);
                    let mut out_values = Vec::with_capacity(values.len());
                    for value in values {
                        if let Some(list_items) = value
                            .as_object()
                            .and_then(|map| map.get("@list"))
                            .and_then(Value::as_array)
                        {
                            let list_frame = subframe
                                .get("@list")
                                .map_or_else(Map::new, first_frame_object);
                            let mut list_out = Vec::with_capacity(list_items.len());
                            for item in list_items {
                                match node_reference_id(item) {
                                    Some(reference) => frame_subjects(
                                        state,
                                        &[reference.to_owned()],
                                        &list_frame,
                                        &mut list_out,
                                    )?,
                                    None => list_out.push(item.clone()),
                                }
                            }
                            out_values.push(Value::Object(Map::from_iter([(
                                "@list".to_owned(),
                                Value::Array(list_out),
                            )])));
                            continue;
                        }
                        match node_reference_id(value) {
                            Some(reference) => frame_subjects(
                                state,
                                &[reference.to_owned()],
                                &subframe,
                                &mut out_values,
                            )?,
                            None => out_values.push(value.clone()),
                        }
                    }
                    out.insert(property.to_owned(), Value::Array(out_values));
                }
            }
        }

        // Framing section 2.3 / 4.1: reverse properties embed the nodes
        // that point at this subject.
        if let Some(reverse_frame) = frame.get("@reverse") {
            let Some(reverse_map) = reverse_frame.as_object() else {
                return Err(JsonLdError::InvalidFrame(
                    "@reverse must be a map".to_owned(),
                ));
            };
            let mut out_reverse = Map::new();
            for (property, subframe_value) in reverse_map {
                let subframe = first_frame_object(subframe_value);
                let incoming = reverse_subjects(graph_nodes, id, property);
                let mut out_values = Vec::with_capacity(incoming.len());
                frame_subjects(state, &incoming, &subframe, &mut out_values)?;
                if out_values.is_empty() {
                    if frame_flag(&subframe, "@omitDefault", omit_default) {
                        continue;
                    }
                    let default_value = match subframe.get("@default") {
                        Some(Value::Array(items)) => items.clone(),
                        Some(other) => vec![other.clone()],
                        None => vec![Value::String("@null".to_owned())],
                    };
                    out_values.push(Value::Object(Map::from_iter([(
                        "@preserve".to_owned(),
                        Value::Array(default_value),
                    )])));
                }
                out_reverse.insert(property.clone(), Value::Array(out_values));
            }
            if !out_reverse.is_empty() {
                out.insert("@reverse".to_owned(), Value::Object(out_reverse));
            }
        }

        // Framing section 4.1: defaults for frame properties the node
        // lacks, unless omitted.
        for (property, property_frame) in frame {
            if property.starts_with('@') || out.contains_key(property) {
                continue;
            }
            let property_frame = first_frame_object(property_frame);
            if frame_flag(&property_frame, "@omitDefault", omit_default) {
                continue;
            }
            let default_value = match property_frame.get("@default") {
                Some(Value::Array(items)) => items.clone(),
                Some(other) => vec![other.clone()],
                None => vec![Value::String("@null".to_owned())],
            };
            out.insert(
                property.clone(),
                Value::Array(vec![Value::Object(Map::from_iter([(
                    "@preserve".to_owned(),
                    Value::Array(default_value),
                )]))]),
            );
        }

        state.subject_stack.pop();
        output.push(Value::Object(out));
    }
    Ok(())
}

/// Charges one embedding of `node` to the framing budgets.
///
/// `@embed: @always` copies a node every time it is referenced, so a DAG
/// whose nodes each reference the next one twice frames to an output
/// exponential in its size. Every embedded node is charged its value count
/// against [`crate::JsonLdLimits::max_nodes`], and embed nesting against
/// the run's cap, before the copy is made. This is an intended limit:
/// legitimate `@always` fan-out that copies more than `max_nodes` values in
/// total is refused too; raise `max_nodes` to frame it.
fn charge_embed(
    state: &mut FramingState<'_>,
    node: &Map<String, Value>,
) -> Result<(), JsonLdError> {
    let depth = state.subject_stack.len().saturating_add(1);
    if depth > state.max_embed_depth {
        return Err(JsonLdError::ResourceLimit {
            resource: JsonLdResource::EmbedDepth,
            limit: state.max_embed_depth,
            observed: depth,
        });
    }
    let values = node
        .values()
        .map(|values| values.as_array().map_or(1, Vec::len))
        .fold(1_usize, usize::saturating_add);
    state.embedded_values = state.embedded_values.saturating_add(values);
    if state.embedded_values > state.max_embedded_values {
        return Err(JsonLdError::ResourceLimit {
            resource: JsonLdResource::Nodes,
            limit: state.max_embedded_values,
            observed: state.embedded_values,
        });
    }
    Ok(())
}

/// Returns the first object of a frame entry (`[]`/non-object entries frame
/// as the empty wildcard).
fn first_frame_object(entry: &Value) -> Map<String, Value> {
    match entry {
        Value::Array(items) => items
            .iter()
            .find_map(Value::as_object)
            .cloned()
            .unwrap_or_default(),
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    }
}

fn node_reference(id: &str) -> Value {
    Value::Object(Map::from_iter([(
        "@id".to_owned(),
        Value::String(id.to_owned()),
    )]))
}

/// Subjects in `graph` whose `property` values reference `target`.
fn reverse_subjects(graph: &Graph, target: &str, property: &str) -> Vec<String> {
    let mut subjects = Vec::new();
    for (id, node) in graph {
        let Some(Value::Array(values)) = node.get(property) else {
            continue;
        };
        let points_here = values.iter().any(|value| {
            value
                .as_object()
                .and_then(|map| map.get("@id"))
                .and_then(Value::as_str)
                == Some(target)
        });
        if points_here {
            subjects.push(id.clone());
        }
    }
    subjects
}

/// Returns the id when `value` is a node reference (a map holding only
/// `@id`).
fn node_reference_id(value: &Value) -> Option<&str> {
    let map = value.as_object()?;
    if map.len() == 1 {
        map.get("@id").and_then(Value::as_str)
    } else {
        None
    }
}

/// Frame Matching (Framing section 4.2).
fn matches_frame(
    node: &Map<String, Value>,
    frame: &Map<String, Value>,
    require_all: bool,
    graph: &Graph,
) -> Result<bool, JsonLdError> {
    let mut constrained = false;
    let mut matched_some = false;
    for (key, frame_value) in frame {
        match key.as_str() {
            "@id" => {
                constrained = true;
                let node_id = node.get("@id").and_then(Value::as_str).unwrap_or_default();
                let ids: Vec<&Value> = match frame_value {
                    Value::Array(items) => items.iter().collect(),
                    other => vec![other],
                };
                let wildcard = ids.is_empty() || ids.iter().any(|item| is_empty_map(item));
                let hit = wildcard || ids.iter().any(|item| item.as_str() == Some(node_id));
                if !hit {
                    return Ok(false);
                }
                matched_some = true;
            }
            "@type" => {
                constrained = true;
                let node_types: Vec<&str> = node
                    .get("@type")
                    .and_then(Value::as_array)
                    .map(|types| types.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let Value::Array(patterns) = frame_value else {
                    return Err(JsonLdError::InvalidFrame(
                        "@type must hold an array in an expanded frame".to_owned(),
                    ));
                };
                let hit = if patterns.is_empty() {
                    // Match none: the node must be untyped.
                    node_types.is_empty()
                } else if patterns.iter().any(is_empty_map) {
                    // Wildcard: the node must have some type.
                    !node_types.is_empty()
                } else if patterns.iter().any(|pattern| {
                    pattern
                        .as_object()
                        .is_some_and(|map| map.contains_key("@default"))
                }) {
                    true // A default type matches every node.
                } else {
                    patterns
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|pattern| node_types.contains(&pattern))
                };
                if !hit {
                    return Ok(false);
                }
                matched_some = true;
            }
            "@reverse" => {
                constrained = true;
                let Some(reverse_map) = frame_value.as_object() else {
                    return Err(JsonLdError::InvalidFrame(
                        "@reverse must be a map".to_owned(),
                    ));
                };
                let node_id = node.get("@id").and_then(Value::as_str).unwrap_or_default();
                for (property, subframe_value) in reverse_map {
                    let patterns: &[Value] = match subframe_value {
                        Value::Array(items) => items,
                        _ => &[],
                    };
                    let incoming = reverse_subjects(graph, node_id, property);
                    let has_default = patterns.iter().any(|pattern| {
                        pattern
                            .as_object()
                            .is_some_and(|map| map.contains_key("@default"))
                    });
                    let hit = if patterns.is_empty() {
                        incoming.is_empty()
                    } else if incoming.is_empty() {
                        if has_default {
                            continue;
                        }
                        false
                    } else {
                        let mut any = false;
                        for pattern in patterns {
                            let subframe = first_frame_object(pattern);
                            for subject in &incoming {
                                let Some(incoming_node) = graph.get(subject) else {
                                    continue;
                                };
                                if matches_frame(incoming_node, &subframe, require_all, graph)? {
                                    any = true;
                                    break;
                                }
                            }
                            if any {
                                break;
                            }
                        }
                        any
                    };
                    if hit {
                        matched_some = true;
                    } else if require_all {
                        return Ok(false);
                    }
                }
            }
            keyword if keyword.starts_with('@') => {}
            property => {
                constrained = true;
                let patterns: &[Value] = match frame_value {
                    Value::Array(items) => items,
                    _ => &[],
                };
                let node_values = node
                    .get(property)
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let has_default = patterns.iter().any(|pattern| {
                    pattern
                        .as_object()
                        .is_some_and(|map| map.contains_key("@default"))
                });
                let hit = if patterns.is_empty() {
                    // Match none: the property must be absent or empty.
                    node_values.is_empty()
                } else if node_values.is_empty() {
                    // Absent property: a @default keeps the node eligible
                    // without counting as a match.
                    if has_default {
                        continue;
                    }
                    false
                } else {
                    patterns.iter().any(|pattern| {
                        node_values
                            .iter()
                            .any(|value| frame_value_matches(pattern, value))
                    })
                };
                if hit {
                    matched_some = true;
                } else if require_all {
                    return Ok(false);
                }
            }
        }
    }
    // A frame without constraints is a wildcard (Framing section 4.2).
    Ok(
        !constrained
            || matched_some
            || (require_all && !matched_some && frame_only_defaults(frame)),
    )
}

/// Returns `true` when every non-keyword frame property carries `@default`.
fn frame_only_defaults(frame: &Map<String, Value>) -> bool {
    let mut saw_property = false;
    for (key, value) in frame {
        if key.starts_with('@') {
            continue;
        }
        saw_property = true;
        let has_default = match value {
            Value::Array(items) => items.iter().any(|item| {
                item.as_object()
                    .is_some_and(|map| map.contains_key("@default"))
            }),
            _ => false,
        };
        if !has_default {
            return false;
        }
    }
    saw_property
}

/// Value Pattern Matching (Framing section 4.3), plus node-reference
/// patterns and list recursion.
fn frame_value_matches(pattern: &Value, value: &Value) -> bool {
    let Some(pattern_map) = pattern.as_object() else {
        return false; // Expanded frame patterns are maps.
    };
    if pattern_map.is_empty() {
        return true; // Wildcard.
    }
    let Some(value_map) = value.as_object() else {
        return false;
    };
    if value_map.contains_key("@value") {
        if !pattern_map.contains_key("@value")
            && !pattern_map.contains_key("@type")
            && !pattern_map.contains_key("@language")
        {
            return pattern_map.contains_key("@default");
        }
        return value_pattern_matches(pattern_map, value_map);
    }
    if let Some(list) = value_map.get("@list").and_then(Value::as_array) {
        let list_patterns = match pattern_map.get("@list") {
            Some(Value::Array(items)) => items.as_slice(),
            _ => return pattern_map.contains_key("@default"),
        };
        return list.iter().any(|item| {
            list_patterns
                .iter()
                .any(|list_pattern| frame_value_matches(list_pattern, item))
        });
    }
    // Node reference or node object: match on @id constraints when given.
    match pattern_map.get("@id") {
        None => true, // A node pattern matches by presence.
        Some(Value::Array(ids)) => {
            let value_id = value_map.get("@id").and_then(Value::as_str);
            ids.is_empty()
                || ids.iter().any(is_empty_map)
                || ids
                    .iter()
                    .any(|id| id.as_str().is_some() && id.as_str() == value_id)
        }
        Some(Value::String(id)) => value_map.get("@id").and_then(Value::as_str) == Some(id),
        Some(_) => false,
    }
}

/// Matches one value object against a value pattern (Framing section 4.3).
fn value_pattern_matches(pattern: &Map<String, Value>, value: &Map<String, Value>) -> bool {
    for key in ["@value", "@type", "@language"] {
        let entry = value.get(key);
        match pattern.get(key) {
            None => {}
            Some(Value::Array(items)) if items.is_empty() => {
                // Match none: the entry must be absent.
                if entry.is_some() {
                    return false;
                }
            }
            Some(pattern_entry) => {
                let candidates: Vec<&Value> = match pattern_entry {
                    Value::Array(items) => items.iter().collect(),
                    other => vec![other],
                };
                let wildcard = candidates.iter().any(|item| is_empty_map(item));
                let Some(entry) = entry else {
                    return false;
                };
                let hit = wildcard
                    || candidates.iter().any(|candidate| {
                        if key == "@language" {
                            match (candidate.as_str(), entry.as_str()) {
                                (Some(left), Some(right)) => {
                                    left.to_lowercase() == right.to_lowercase()
                                }
                                _ => false,
                            }
                        } else {
                            *candidate == entry
                        }
                    });
                if !hit {
                    return false;
                }
            }
        }
    }
    true
}

// ===========================================================================
// Post-processing
// ===========================================================================

/// Removes `@id` entries whose blank node identifier occurs exactly once in
/// the framed output (the `pruneBlankNodeIdentifiers` option, on by default
/// in JSON-LD 1.1 framing).
fn prune_blank_node_identifiers(results: &mut [Value]) {
    let mut usage: HashMap<String, usize> = HashMap::new();
    for result in results.iter() {
        count_blank_ids(result, &mut usage);
    }
    for result in results.iter_mut() {
        prune_single_use(result, &usage);
    }
}

fn count_blank_ids(value: &Value, usage: &mut HashMap<String, usize>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(id)) = map.get("@id")
                && id.starts_with("_:")
            {
                *usage.entry(id.clone()).or_default() += 1;
            }
            for entry in map.values() {
                count_blank_ids(entry, usage);
            }
        }
        Value::Array(items) => {
            for item in items {
                count_blank_ids(item, usage);
            }
        }
        _ => {}
    }
}

fn prune_single_use(value: &mut Value, usage: &HashMap<String, usize>) {
    match value {
        Value::Object(map) => {
            let remove = matches!(
                map.get("@id"),
                Some(Value::String(id))
                    if id.starts_with("_:") && usage.get(id).copied() == Some(1)
            );
            if remove {
                map.remove("@id");
            }
            for entry in map.values_mut() {
                prune_single_use(entry, usage);
            }
        }
        Value::Array(items) => {
            for item in items {
                prune_single_use(item, usage);
            }
        }
        _ => {}
    }
}

/// Unwraps `@preserve` wrappers and replaces `"@null"` markers with JSON
/// `null` after compaction (Framing section 4.1, final cleanup).
fn cleanup_preserved(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            if map.len() == 1
                && let Some(preserved) = map.get("@preserve")
            {
                return cleanup_preserved(preserved.clone());
            }
            Value::Object(
                map.into_iter()
                    .map(|(key, entry)| (key, cleanup_preserved(entry)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(cleanup_preserved).collect()),
        Value::String(text) if text == "@null" => Value::Null,
        other => other,
    }
}
