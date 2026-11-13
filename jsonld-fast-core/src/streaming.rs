// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! JSON-LD 1.1 Streaming Note: document form and RDF form.
//!
//! The Note (<https://w3c.github.io/json-ld-streaming/>) is not a REC. This
//! module is an additive, fail-closed subset:
//!
//! - **Document form (deserialize):** required key order is validated on
//!   the source JSON text (`@context`, then `@type`, then other
//!   properties). A violation is [`JsonLdError::InvalidStreamingKeyOrder`]
//!   (`invalid streaming key order`). Maps nested under `@context` are
//!   exempt so term definitions in the Note's own valid examples stay
//!   valid. [`parse_streaming_graph`] / [`expand_streaming_graph`] yield
//!   each top-level `@graph` (or top-level array) element without
//!   retaining the full graph array. Other streaming entry points still
//!   load the document after the form check.
//! - **RDF form (serialize):** [`write_streaming_document`] emits JSON
//!   text with that key order (`@type` before `@id`). `serde_json::Value`
//!   cannot carry key order (`Map` is ordered by key), so streaming form
//!   is a *serialization* property.

use serde_json::{Map, Number, Value};

use crate::{
    compact,
    error::JsonLdError,
    expand, from_quads,
    options::{JsonLdLimits, JsonLdOptions},
    parse_document, to_quads,
};

use arrow_array::RecordBatch;
use quad_fast_core::SourceProvenance;

/// Profile URI identifying JSON-LD in streaming document form.
pub const STREAMING_PROFILE: &str = "http://www.w3.org/ns/json-ld#streaming";

/// Validates that `text` is JSON whose node objects follow streaming
/// document form (required key order).
///
/// # Errors
///
/// [`JsonLdError::ResourceLimit`] when `text` exceeds
/// [`JsonLdLimits::max_input_bytes`], [`JsonLdError::InvalidJson`] when
/// the text is not JSON, and
/// [`JsonLdError::InvalidStreamingKeyOrder`] when `@context` or `@type`
/// appear after other properties in a node object.
pub fn validate_streaming_form(text: &str, limits: &JsonLdLimits) -> Result<(), JsonLdError> {
    if text.len() > limits.max_input_bytes {
        return Err(JsonLdError::ResourceLimit {
            resource: crate::JsonLdResource::InputBytes,
            limit: limits.max_input_bytes,
            observed: text.len(),
        });
    }
    let mut cursor = Cursor {
        bytes: text.as_bytes(),
        pos: 0,
        depth: 0,
        max_depth: limits.max_depth,
    };
    cursor.skip_ws();
    if cursor.eof() {
        return Err(JsonLdError::InvalidJson("empty document".to_owned()));
    }
    cursor.parse_value(false)?;
    cursor.skip_ws();
    if !cursor.eof() {
        return Err(JsonLdError::InvalidJson(
            "trailing content after the top-level JSON value".to_owned(),
        ));
    }
    Ok(())
}

/// Parses `text` after validating streaming document form.
///
/// # Errors
///
/// Streaming-form errors, then the same errors as [`parse_document`].
pub fn parse_streaming_document(text: &str, limits: &JsonLdLimits) -> Result<Value, JsonLdError> {
    validate_streaming_form(text, limits)?;
    parse_document(text, limits)
}

/// Expands a streaming-form JSON-LD document.
///
/// # Errors
///
/// Streaming-form errors, then the same errors as [`crate::expand`].
pub fn expand_streaming(text: &str, options: &JsonLdOptions) -> Result<Value, JsonLdError> {
    let document = parse_streaming_document(text, &options.limits)?;
    expand(&document, options)
}

/// Compacts a streaming-form JSON-LD document.
///
/// # Errors
///
/// Streaming-form errors, then the same errors as [`crate::compact`].
pub fn compact_streaming(
    text: &str,
    context: &Value,
    options: &JsonLdOptions,
) -> Result<Value, JsonLdError> {
    let document = parse_streaming_document(text, &options.limits)?;
    compact(&document, context, options)
}

/// Deserializes a streaming-form JSON-LD document to quad batches.
///
/// # Errors
///
/// Streaming-form errors, then the same errors as [`crate::to_quads`].
pub fn to_quads_streaming(
    text: &str,
    options: &JsonLdOptions,
    provenance: Option<&SourceProvenance>,
) -> Result<Vec<RecordBatch>, JsonLdError> {
    let document = parse_streaming_document(text, &options.limits)?;
    to_quads(&document, options, provenance)
}

/// Serializes quad batches as JSON text in streaming document form.
///
/// Semantic content matches [`from_quads`]; keys are emitted `@context`
/// (if present), `@type`, `@id`, then remaining properties in sorted
/// order so a streaming deserializer can emit triples without buffering
/// the subject.
///
/// # Errors
///
/// The same errors as [`from_quads`].
pub fn from_quads_streaming(batches: &[RecordBatch]) -> Result<String, JsonLdError> {
    let expanded = from_quads(batches)?;
    Ok(write_streaming_document(&expanded))
}

/// Serializes `document` as JSON text with streaming document form key
/// order on every node object that is not nested under `@context`.
#[must_use]
pub fn write_streaming_document(document: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, document, false);
    out
}

/// Yields each node object from a streaming-form document's `@graph`
/// array, or each element of a top-level array, without retaining the
/// full graph.
///
/// Top-level keys other than `@graph` are available from [`Self::header`].
/// Streaming form requires `@context` first, so the context is in the
/// header before the first graph node is yielded.
pub struct StreamingGraphNodes<'a> {
    cursor: Cursor<'a>,
    header: Map<String, Value>,
    in_graph_array: bool,
    graph_need_comma: bool,
    /// Remaining `}` of the top-level object after `@graph` is consumed.
    finish_object: bool,
    done: bool,
    fallback: std::vec::IntoIter<Value>,
}

impl std::fmt::Debug for StreamingGraphNodes<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamingGraphNodes")
            .field("header", &self.header)
            .field("in_graph_array", &self.in_graph_array)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl StreamingGraphNodes<'_> {
    /// Top-level keys other than yielded `@graph` / array elements.
    #[must_use]
    pub fn header(&self) -> &Map<String, Value> {
        &self.header
    }
}

impl Iterator for StreamingGraphNodes<'_> {
    type Item = Result<Value, JsonLdError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(value) = self.fallback.next() {
            return Some(Ok(value));
        }
        if self.done {
            return None;
        }
        if self.in_graph_array {
            return self.next_graph_element();
        }
        self.done = true;
        None
    }
}

impl StreamingGraphNodes<'_> {
    fn next_graph_element(&mut self) -> Option<Result<Value, JsonLdError>> {
        match self.read_graph_element() {
            Ok(None) => None,
            Ok(Some(value)) => Some(Ok(value)),
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }

    fn read_graph_element(&mut self) -> Result<Option<Value>, JsonLdError> {
        self.cursor.skip_ws();
        if self.graph_need_comma {
            match self.cursor.bump() {
                Some(b']') => {
                    self.close_graph_array()?;
                    return Ok(None);
                }
                Some(b',') => {}
                _ => {
                    return Err(JsonLdError::InvalidJson(format!(
                        "expected ',' or ']' at offset {}",
                        self.cursor.pos
                    )));
                }
            }
            self.cursor.skip_ws();
        } else if self.cursor.peek() == Some(b']') {
            self.cursor.bump();
            self.close_graph_array()?;
            return Ok(None);
        }
        let value = self.cursor.parse_value_to(false)?;
        self.graph_need_comma = true;
        Ok(Some(value))
    }

    fn close_graph_array(&mut self) -> Result<(), JsonLdError> {
        self.cursor.exit();
        self.in_graph_array = false;
        if self.finish_object {
            self.finish_top_level_object()?;
        }
        self.cursor.skip_ws();
        if !self.cursor.eof() {
            return Err(JsonLdError::InvalidJson(
                "trailing content after the top-level JSON value".to_owned(),
            ));
        }
        self.done = true;
        Ok(())
    }

    fn finish_top_level_object(&mut self) -> Result<(), JsonLdError> {
        loop {
            self.cursor.skip_ws();
            match self.cursor.bump() {
                Some(b'}') => {
                    self.cursor.exit();
                    return Ok(());
                }
                Some(b',') => {
                    self.cursor.skip_ws();
                    if self.cursor.peek() != Some(b'"') {
                        return Err(JsonLdError::InvalidJson(format!(
                            "object key must be a string at offset {}",
                            self.cursor.pos
                        )));
                    }
                    let key = self.cursor.parse_string()?;
                    self.cursor.skip_ws();
                    if self.cursor.bump() != Some(b':') {
                        return Err(JsonLdError::InvalidJson(format!(
                            "expected ':' after object key at offset {}",
                            self.cursor.pos
                        )));
                    }
                    let child_in_context = key == "@context";
                    let value = self.cursor.parse_value_to(child_in_context)?;
                    self.header.insert(key, value);
                }
                _ => {
                    return Err(JsonLdError::InvalidJson(format!(
                        "expected ',' or '}}' at offset {}",
                        self.cursor.pos
                    )));
                }
            }
        }
    }
}

/// Parses `text` into a streaming graph-node iterator after validating
/// streaming document form on every node object visited.
///
/// # Errors
///
/// The same errors as [`validate_streaming_form`], plus JSON syntax errors
/// raised while building each yielded node.
pub fn parse_streaming_graph<'a>(
    text: &'a str,
    limits: &JsonLdLimits,
) -> Result<StreamingGraphNodes<'a>, JsonLdError> {
    if text.len() > limits.max_input_bytes {
        return Err(JsonLdError::ResourceLimit {
            resource: crate::JsonLdResource::InputBytes,
            limit: limits.max_input_bytes,
            observed: text.len(),
        });
    }
    let mut cursor = Cursor {
        bytes: text.as_bytes(),
        pos: 0,
        depth: 0,
        max_depth: limits.max_depth,
    };
    cursor.skip_ws();
    if cursor.eof() {
        return Err(JsonLdError::InvalidJson("empty document".to_owned()));
    }
    match cursor.peek() {
        Some(b'{') => open_top_level_object(cursor),
        Some(b'[') => open_top_level_array(cursor),
        _ => {
            let value = cursor.parse_value_to(false)?;
            cursor.skip_ws();
            if !cursor.eof() {
                return Err(JsonLdError::InvalidJson(
                    "trailing content after the top-level JSON value".to_owned(),
                ));
            }
            Ok(StreamingGraphNodes {
                cursor,
                header: Map::new(),
                in_graph_array: false,
                graph_need_comma: false,
                finish_object: false,
                done: false,
                fallback: vec![value].into_iter(),
            })
        }
    }
}

fn open_top_level_array(mut cursor: Cursor<'_>) -> Result<StreamingGraphNodes<'_>, JsonLdError> {
    cursor.enter()?;
    cursor.bump();
    Ok(StreamingGraphNodes {
        cursor,
        header: Map::new(),
        in_graph_array: true,
        graph_need_comma: false,
        finish_object: false,
        done: false,
        fallback: Vec::new().into_iter(),
    })
}

fn open_top_level_object(mut cursor: Cursor<'_>) -> Result<StreamingGraphNodes<'_>, JsonLdError> {
    cursor.enter()?;
    cursor.bump();
    cursor.skip_ws();
    let mut header = Map::new();
    let mut keys = Vec::new();
    if cursor.peek() == Some(b'}') {
        cursor.bump();
        cursor.exit();
        cursor.skip_ws();
        if !cursor.eof() {
            return Err(JsonLdError::InvalidJson(
                "trailing content after the top-level JSON value".to_owned(),
            ));
        }
        return Ok(StreamingGraphNodes {
            cursor,
            header,
            in_graph_array: false,
            graph_need_comma: false,
            finish_object: false,
            done: false,
            fallback: vec![Value::Object(Map::new())].into_iter(),
        });
    }
    loop {
        cursor.skip_ws();
        if cursor.peek() != Some(b'"') {
            return Err(JsonLdError::InvalidJson(format!(
                "object key must be a string at offset {}",
                cursor.pos
            )));
        }
        let key = cursor.parse_string()?;
        cursor.skip_ws();
        if cursor.bump() != Some(b':') {
            return Err(JsonLdError::InvalidJson(format!(
                "expected ':' after object key at offset {}",
                cursor.pos
            )));
        }
        keys.push(key.clone());
        if key == "@graph" {
            cursor.skip_ws();
            if cursor.peek() == Some(b'[') {
                check_streaming_keys(&keys)?;
                cursor.enter()?;
                cursor.bump();
                return Ok(StreamingGraphNodes {
                    cursor,
                    header,
                    in_graph_array: true,
                    graph_need_comma: false,
                    finish_object: true,
                    done: false,
                    fallback: Vec::new().into_iter(),
                });
            }
            let value = cursor.parse_value_to(false)?;
            header.insert(key, value);
        } else {
            let child_in_context = key == "@context";
            let value = cursor.parse_value_to(child_in_context)?;
            header.insert(key, value);
        }
        cursor.skip_ws();
        match cursor.bump() {
            Some(b',') => continue,
            Some(b'}') => {
                cursor.exit();
                check_streaming_keys(&keys)?;
                cursor.skip_ws();
                if !cursor.eof() {
                    return Err(JsonLdError::InvalidJson(
                        "trailing content after the top-level JSON value".to_owned(),
                    ));
                }
                let document = Value::Object(header.clone());
                return Ok(StreamingGraphNodes {
                    cursor,
                    header,
                    in_graph_array: false,
                    graph_need_comma: false,
                    finish_object: false,
                    done: false,
                    fallback: vec![document].into_iter(),
                });
            }
            _ => {
                return Err(JsonLdError::InvalidJson(format!(
                    "expected ',' or '}}' at offset {}",
                    cursor.pos
                )));
            }
        }
    }
}

/// Expanded nodes yielded from [`expand_streaming_graph`].
pub struct ExpandStreamingGraph<'a> {
    inner: StreamingGraphNodes<'a>,
    context: Option<Value>,
    options: &'a JsonLdOptions,
}

impl std::fmt::Debug for ExpandStreamingGraph<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExpandStreamingGraph")
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

/// Expands each `@graph` (or top-level array) node as it is parsed.
///
/// The document `@context` is applied to every yielded node. Each item is
/// one expanded node object (not a wrapping array).
///
/// # Errors
///
/// Constructor errors match [`parse_streaming_graph`]. Iterator items are
/// expansion errors for that node.
pub fn expand_streaming_graph<'a>(
    text: &'a str,
    options: &'a JsonLdOptions,
) -> Result<ExpandStreamingGraph<'a>, JsonLdError> {
    let inner = parse_streaming_graph(text, &options.limits)?;
    let context = inner.header().get("@context").cloned();
    Ok(ExpandStreamingGraph {
        inner,
        context,
        options,
    })
}

impl Iterator for ExpandStreamingGraph<'_> {
    type Item = Result<Value, JsonLdError>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = match self.inner.next()? {
            Ok(node) => node,
            Err(error) => return Some(Err(error)),
        };
        Some(expand_graph_node(node, self.context.as_ref(), self.options))
    }
}

fn expand_graph_node(
    node: Value,
    context: Option<&Value>,
    options: &JsonLdOptions,
) -> Result<Value, JsonLdError> {
    let document = match (node, context) {
        (Value::Object(mut map), Some(context)) if !map.contains_key("@context") => {
            map.insert("@context".to_owned(), context.clone());
            Value::Object(map)
        }
        (node, _) => node,
    };
    let expanded = expand(&document, options)?;
    match expanded {
        Value::Array(mut items) if items.len() == 1 => Ok(items.remove(0)),
        other => Ok(other),
    }
}

/// One pending step of the iterative writer.
enum WriteStep<'value> {
    /// Serialize a value; `bool` is "nested under `@context`".
    Value(&'value Value, bool),
    /// Emit `"key":` (preceded by `,` unless it is the first entry).
    Key(&'value str, bool),
    /// Emit a punctuation character.
    Punct(char),
}

/// Writes `value` as JSON text with an explicit heap stack.
///
/// [`write_streaming_document`] returns a `String` and cannot fail, so it
/// must not recurse on caller-built nesting: a 100,000-level value would
/// otherwise overflow the native stack.
fn write_value(out: &mut String, value: &Value, in_context: bool) {
    let mut steps = vec![WriteStep::Value(value, in_context)];
    while let Some(step) = steps.pop() {
        match step {
            WriteStep::Punct(ch) => out.push(ch),
            WriteStep::Key(key, first) => {
                if !first {
                    out.push(',');
                }
                push_json_string(out, key);
                out.push(':');
            }
            WriteStep::Value(current, in_context) => match current {
                Value::Null => out.push_str("null"),
                Value::Bool(true) => out.push_str("true"),
                Value::Bool(false) => out.push_str("false"),
                Value::Number(number) => out.push_str(&number.to_string()),
                Value::String(text) => push_json_string(out, text),
                Value::Array(items) => {
                    out.push('[');
                    steps.push(WriteStep::Punct(']'));
                    for (index, item) in items.iter().enumerate().rev() {
                        steps.push(WriteStep::Value(item, in_context));
                        if index > 0 {
                            steps.push(WriteStep::Punct(','));
                        }
                    }
                }
                Value::Object(map) => {
                    out.push('{');
                    steps.push(WriteStep::Punct('}'));
                    let keys = if in_context {
                        map.keys().cloned().collect::<Vec<_>>()
                    } else {
                        streaming_key_order(map)
                    };
                    for (index, key) in keys.iter().enumerate().rev() {
                        let Some((key, child)) = map.get_key_value(key) else {
                            continue;
                        };
                        let child_in_context = in_context || key == "@context";
                        steps.push(WriteStep::Value(child, child_in_context));
                        steps.push(WriteStep::Key(key, index == 0));
                    }
                }
            },
        }
    }
}

fn streaming_key_order(map: &Map<String, Value>) -> Vec<String> {
    let mut keys = Vec::with_capacity(map.len());
    if map.contains_key("@context") {
        keys.push("@context".to_owned());
    }
    if map.contains_key("@type") {
        keys.push("@type".to_owned());
    }
    if map.contains_key("@id") {
        keys.push("@id".to_owned());
    }
    let mut rest: Vec<String> = map
        .keys()
        .filter(|key| {
            key.as_str() != "@context" && key.as_str() != "@type" && key.as_str() != "@id"
        })
        .cloned()
        .collect();
    rest.sort();
    keys.extend(rest);
    keys
}

fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                let code = c as u32;
                for shift in [12, 8, 4, 0] {
                    let nibble = ((code >> shift) & 0xF) as u8;
                    out.push(char::from(if nibble < 10 {
                        b'0' + nibble
                    } else {
                        b'a' + nibble - 10
                    }));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
    max_depth: usize,
}

impl Cursor<'_> {
    fn eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn enter(&mut self) -> Result<(), JsonLdError> {
        self.depth += 1;
        if self.depth > self.max_depth {
            return Err(JsonLdError::ResourceLimit {
                resource: crate::JsonLdResource::Depth,
                limit: self.max_depth,
                observed: self.depth,
            });
        }
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self, in_context: bool) -> Result<(), JsonLdError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(in_context),
            Some(b'[') => self.parse_array(in_context),
            Some(b'"') => {
                self.parse_string()?;
                Ok(())
            }
            Some(b't') => self.eat_literal(b"true"),
            Some(b'f') => self.eat_literal(b"false"),
            Some(b'n') => self.eat_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(other) => Err(JsonLdError::InvalidJson(format!(
                "unexpected byte {other} at offset {}",
                self.pos
            ))),
            None => Err(JsonLdError::InvalidJson(
                "unexpected end of JSON input".to_owned(),
            )),
        }
    }

    fn parse_value_to(&mut self, in_context: bool) -> Result<Value, JsonLdError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object_to(in_context),
            Some(b'[') => self.parse_array_to(in_context),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b't') => {
                self.eat_literal(b"true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.eat_literal(b"false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.eat_literal(b"null")?;
                Ok(Value::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.parse_number_to(),
            Some(other) => Err(JsonLdError::InvalidJson(format!(
                "unexpected byte {other} at offset {}",
                self.pos
            ))),
            None => Err(JsonLdError::InvalidJson(
                "unexpected end of JSON input".to_owned(),
            )),
        }
    }

    fn parse_object_to(&mut self, in_context: bool) -> Result<Value, JsonLdError> {
        self.enter()?;
        self.bump();
        self.skip_ws();
        let mut map = Map::new();
        let mut keys = Vec::new();
        if self.peek() == Some(b'}') {
            self.bump();
            self.exit();
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(JsonLdError::InvalidJson(format!(
                    "object key must be a string at offset {}",
                    self.pos
                )));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(JsonLdError::InvalidJson(format!(
                    "expected ':' after object key at offset {}",
                    self.pos
                )));
            }
            let child_in_context = in_context || key == "@context";
            let value = self.parse_value_to(child_in_context)?;
            keys.push(key.clone());
            map.insert(key, value);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => {
                    return Err(JsonLdError::InvalidJson(format!(
                        "expected ',' or '}}' at offset {}",
                        self.pos
                    )));
                }
            }
        }
        self.exit();
        if !in_context {
            check_streaming_keys(&keys)?;
        }
        Ok(Value::Object(map))
    }

    fn parse_array_to(&mut self, in_context: bool) -> Result<Value, JsonLdError> {
        self.enter()?;
        self.bump();
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.bump();
            self.exit();
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.parse_value_to(in_context)?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => break,
                _ => {
                    return Err(JsonLdError::InvalidJson(format!(
                        "expected ',' or ']' at offset {}",
                        self.pos
                    )));
                }
            }
        }
        self.exit();
        Ok(Value::Array(items))
    }

    fn parse_number_to(&mut self) -> Result<Value, JsonLdError> {
        let start = self.pos;
        self.parse_number()?;
        let slice = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_utf8| JsonLdError::InvalidJson("invalid UTF-8 in number".to_owned()))?;
        let number: Number = slice.parse().map_err(|error| {
            JsonLdError::InvalidJson(format!("invalid number `{slice}`: {error}"))
        })?;
        Ok(Value::Number(number))
    }

    fn parse_object(&mut self, in_context: bool) -> Result<(), JsonLdError> {
        self.enter()?;
        self.bump();
        self.skip_ws();
        let mut keys = Vec::new();
        if self.peek() == Some(b'}') {
            self.bump();
            self.exit();
            return Ok(());
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(JsonLdError::InvalidJson(format!(
                    "object key must be a string at offset {}",
                    self.pos
                )));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(JsonLdError::InvalidJson(format!(
                    "expected ':' after object key at offset {}",
                    self.pos
                )));
            }
            let child_in_context = in_context || key == "@context";
            self.parse_value(child_in_context)?;
            keys.push(key);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => {
                    return Err(JsonLdError::InvalidJson(format!(
                        "expected ',' or '}}' at offset {}",
                        self.pos
                    )));
                }
            }
        }
        self.exit();
        if !in_context {
            check_streaming_keys(&keys)?;
        }
        Ok(())
    }

    fn parse_array(&mut self, in_context: bool) -> Result<(), JsonLdError> {
        self.enter()?;
        self.bump();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.bump();
            self.exit();
            return Ok(());
        }
        loop {
            self.parse_value(in_context)?;
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => break,
                _ => {
                    return Err(JsonLdError::InvalidJson(format!(
                        "expected ',' or ']' at offset {}",
                        self.pos
                    )));
                }
            }
        }
        self.exit();
        Ok(())
    }

    fn parse_string(&mut self) -> Result<String, JsonLdError> {
        if self.bump() != Some(b'"') {
            return Err(JsonLdError::InvalidJson(format!(
                "expected string at offset {}",
                self.pos
            )));
        }
        let mut out = String::new();
        loop {
            match self.bump() {
                Some(b'"') => return Ok(out),
                Some(b'\\') => match self.bump() {
                    Some(b'"') => out.push('"'),
                    Some(b'\\') => out.push('\\'),
                    Some(b'/') => out.push('/'),
                    Some(b'b') => out.push('\u{0008}'),
                    Some(b'f') => out.push('\u{000c}'),
                    Some(b'n') => out.push('\n'),
                    Some(b'r') => out.push('\r'),
                    Some(b't') => out.push('\t'),
                    Some(b'u') => out.push(self.parse_hex_escape()?),
                    Some(other) => {
                        return Err(JsonLdError::InvalidJson(format!(
                            "invalid escape \\{} at offset {}",
                            other as char, self.pos
                        )));
                    }
                    None => {
                        return Err(JsonLdError::InvalidJson(
                            "unterminated string escape".to_owned(),
                        ));
                    }
                },
                Some(byte) if byte < 0x20 => {
                    return Err(JsonLdError::InvalidJson(format!(
                        "unescaped control byte {byte} in string at offset {}",
                        self.pos
                    )));
                }
                Some(byte) => {
                    // UTF-8: consume continuation bytes so we don't split a
                    // scalar. Keys we care about (`@context`, `@type`) are
                    // ASCII; remaining bytes are copied through as chars.
                    if byte < 0x80 {
                        out.push(byte as char);
                    } else {
                        self.pos -= 1;
                        let rest =
                            std::str::from_utf8(&self.bytes[self.pos..]).map_err(|_utf8| {
                                JsonLdError::InvalidJson("invalid UTF-8 in string".to_owned())
                            })?;
                        let ch = rest.chars().next().ok_or_else(|| {
                            JsonLdError::InvalidJson("invalid UTF-8 in string".to_owned())
                        })?;
                        out.push(ch);
                        self.pos += ch.len_utf8();
                    }
                }
                None => {
                    return Err(JsonLdError::InvalidJson("unterminated string".to_owned()));
                }
            }
        }
    }

    fn parse_hex_escape(&mut self) -> Result<char, JsonLdError> {
        let mut code = 0_u32;
        for _ in 0..4 {
            let byte = self
                .bump()
                .ok_or_else(|| JsonLdError::InvalidJson("unterminated \\u escape".to_owned()))?;
            let nibble = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => {
                    return Err(JsonLdError::InvalidJson(format!(
                        "invalid \\u hex digit at offset {}",
                        self.pos
                    )));
                }
            };
            code = (code << 4) | u32::from(nibble);
        }
        char::from_u32(code)
            .ok_or_else(|| JsonLdError::InvalidJson(format!("invalid unicode scalar {code:#x}")))
    }

    fn parse_number(&mut self) -> Result<(), JsonLdError> {
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => {
                self.bump();
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.bump();
                }
            }
            _ => {
                return Err(JsonLdError::InvalidJson(format!(
                    "invalid number at offset {}",
                    self.pos
                )));
            }
        }
        if self.peek() == Some(b'.') {
            self.bump();
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonLdError::InvalidJson(
                    "invalid number after decimal point".to_owned(),
                ));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.bump();
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(JsonLdError::InvalidJson(
                    "invalid number exponent".to_owned(),
                ));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.bump();
            }
        }
        Ok(())
    }

    fn eat_literal(&mut self, literal: &[u8]) -> Result<(), JsonLdError> {
        for expected in literal {
            if self.bump() != Some(*expected) {
                return Err(JsonLdError::InvalidJson(format!(
                    "invalid literal at offset {}",
                    self.pos
                )));
            }
        }
        Ok(())
    }
}

fn check_streaming_keys(keys: &[String]) -> Result<(), JsonLdError> {
    let mut seen_type = false;
    let mut seen_other = false;
    for key in keys {
        match key.as_str() {
            "@context" => {
                if seen_type || seen_other {
                    return Err(JsonLdError::InvalidStreamingKeyOrder(
                        "@context must be the first key in a node object".to_owned(),
                    ));
                }
            }
            "@type" => {
                if seen_other {
                    return Err(JsonLdError::InvalidStreamingKeyOrder(
                        "@type must appear before other properties".to_owned(),
                    ));
                }
                seen_type = true;
            }
            _ => seen_other = true,
        }
    }
    Ok(())
}
