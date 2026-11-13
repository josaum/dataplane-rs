// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! YAML-LD Basic and Extended profiles (YAML 1.2 Core Schema → JSON-LD).
//!
//! YAML-LD is a WG Note, not a REC. Both profiles share:
//!
//! - UTF-8 streams ([`JsonLdError::YamlInvalidEncoding`])
//! - YAML 1.2 Core Schema via [`saphyr`] (so `no` is a string, not a
//!   boolean — the YAML 1.1 "Norway problem")
//! - string mapping keys only ([`JsonLdError::YamlMappingKey`])
//! - no `.inf` / `.nan`
//! - timestamps stay strings (Core Schema has no timestamp type)
//! - [`YamlLdOptions::extract_all_scripts`]: `false` keeps the first
//!   document; `true` returns an array of every document in the stream
//!
//! **Basic** (default) additionally forbids alias nodes
//! ([`JsonLdError::YamlProfile`]; detected on the YAML event stream
//! because composition copies aliases away) and unwraps user tags.
//!
//! **Extended** composes aliases as copies (a leftover `Yaml::Alias` is a
//! cycle and fails as `loading-document-failed`). Non-Core tags whose
//! suffix is an absolute IRI become JSON-LD value objects with `@type`
//! set to that IRI. Local `!foo` tags that are not IRIs stay a
//! `profile_error` rather than inventing a datatype.
//!
//! The resulting [`serde_json::Value`] is ordinary JSON-LD and is processed
//! by the existing expand / compact / flatten / toRdf algorithms. Remote
//! contexts stay refused.

use std::collections::HashMap;

use saphyr::{LoadableYamlNode, Scalar, Yaml};
use saphyr_parser::{Event, Parser, Tag};
use serde_json::{Map, Number, Value};

use crate::{
    compact,
    error::{JsonLdError, JsonLdResource},
    expand,
    iri::is_absolute_iri,
    options::{JsonLdLimits, JsonLdOptions},
    to_quads,
};

use arrow_array::RecordBatch;
use quad_fast_core::SourceProvenance;

/// YAML-LD processing profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum YamlLdProfile {
    /// Basic profile: no aliases, user tags unwrapped.
    #[default]
    Basic,
    /// Extended profile: aliases compose as copies; IRI tags become
    /// JSON-LD value-object datatypes.
    Extended,
}

impl YamlLdProfile {
    /// Stable machine-readable profile name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Extended => "extended",
        }
    }
}

/// YAML-LD processing options.
#[derive(Clone, Debug, Default)]
pub struct YamlLdOptions {
    /// JSON-LD processor options applied after YAML→JSON conversion.
    pub jsonld: JsonLdOptions,
    /// JSON-LD `extractAllScripts`: when `true`, every document in the
    /// YAML stream becomes one element of a top-level array, even if the
    /// stream contains a single document. When `false` (the default), only
    /// the first document is constructed.
    pub extract_all_scripts: bool,
    /// Basic (default) or Extended YAML-LD profile.
    pub profile: YamlLdProfile,
}

/// Parses a UTF-8 YAML-LD stream into the JSON-LD internal representation.
///
/// # Errors
///
/// Byte-budget errors, YAML composition errors, mapping-key / profile /
/// load failures, and inf/nan refusals. [`JsonLdError::ResourceLimit`]
/// with [`JsonLdResource::Depth`] when collections nest deeper than
/// [`JsonLdLimits::max_depth`], and with [`JsonLdResource::Nodes`] when the
/// composed stream — every alias counted as a full copy of its anchor —
/// would exceed [`JsonLdLimits::max_nodes`]; both are checked on the event
/// stream before anything is composed.
pub fn parse_yaml_ld(text: &str, options: &YamlLdOptions) -> Result<Value, JsonLdError> {
    parse_yaml_ld_bytes(text.as_bytes(), options)
}

/// Parses a YAML-LD stream from raw bytes (UTF-8 only).
///
/// A UTF-16 BOM is [`JsonLdError::YamlInvalidEncoding`]. A UTF-8 BOM is
/// stripped.
///
/// # Errors
///
/// [`JsonLdError::YamlInvalidEncoding`] when the bytes are not UTF-8, then
/// the same errors as [`parse_yaml_ld`].
pub fn parse_yaml_ld_bytes(bytes: &[u8], options: &YamlLdOptions) -> Result<Value, JsonLdError> {
    if bytes.starts_with(&[0xFF, 0xFE])
        || bytes.starts_with(&[0xFE, 0xFF])
        || bytes.starts_with(&[0xFF, 0xFE, 0x00, 0x00])
        || bytes.starts_with(&[0x00, 0x00, 0xFE, 0xFF])
    {
        return Err(JsonLdError::YamlInvalidEncoding);
    }
    let rest = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let text = std::str::from_utf8(rest).map_err(|_utf8| JsonLdError::YamlInvalidEncoding)?;
    if text.len() > options.jsonld.limits.max_input_bytes {
        return Err(JsonLdError::ResourceLimit {
            resource: crate::JsonLdResource::InputBytes,
            limit: options.jsonld.limits.max_input_bytes,
            observed: text.len(),
        });
    }
    prescan_events(text, options.profile, &options.jsonld.limits)?;
    let docs = Yaml::load_from_str(text)
        .map_err(|error| JsonLdError::YamlLoadFailed(format!("YAML parse failed: {error}")))?;
    if docs.is_empty() {
        return Err(JsonLdError::YamlLoadFailed(
            "YAML-LD stream contains no documents".to_owned(),
        ));
    }
    let mut converted = Vec::with_capacity(docs.len());
    for document in &docs {
        converted.push(yaml_to_json(
            document,
            &mut 0,
            options.jsonld.limits.max_depth,
            options.profile,
        )?);
    }
    if options.extract_all_scripts {
        Ok(Value::Array(converted))
    } else {
        Ok(converted.into_iter().next().unwrap_or(Value::Null))
    }
}

/// Serializes a JSON-LD internal representation as YAML-LD Basic (no tags,
/// no aliases). Keys that would be ambiguous in YAML 1.2 are quoted.
///
/// # Errors
///
/// [`JsonLdError::YamlLoadFailed`] when a number cannot be written as YAML,
/// and [`JsonLdError::ResourceLimit`] with [`crate::JsonLdResource::Depth`]
/// when `document` nests deeper than [`crate::DEFAULT_MAX_DEPTH`] (the
/// writer recurses once per level, so the bound is checked first).
pub fn to_yaml_ld(document: &Value) -> Result<String, JsonLdError> {
    crate::guard::check_nesting(document, crate::DEFAULT_MAX_DEPTH)?;
    let mut out = String::new();
    write_yaml(&mut out, document, 0)?;
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// Expands a YAML-LD stream.
///
/// # Errors
///
/// YAML conversion errors, then the same errors as [`crate::expand`].
pub fn expand_yaml_ld(text: &str, options: &YamlLdOptions) -> Result<Value, JsonLdError> {
    let document = parse_yaml_ld(text, options)?;
    expand(&document, &options.jsonld)
}

/// Compacts a YAML-LD stream against an inline JSON-LD context.
///
/// # Errors
///
/// YAML conversion errors, then the same errors as [`crate::compact`].
pub fn compact_yaml_ld(
    text: &str,
    context: &Value,
    options: &YamlLdOptions,
) -> Result<Value, JsonLdError> {
    let document = parse_yaml_ld(text, options)?;
    compact(&document, context, &options.jsonld)
}

/// Deserializes a YAML-LD stream to quad batches.
///
/// # Errors
///
/// YAML conversion errors, then the same errors as [`crate::to_quads`].
pub fn to_quads_yaml_ld(
    text: &str,
    options: &YamlLdOptions,
    provenance: Option<&SourceProvenance>,
) -> Result<Vec<RecordBatch>, JsonLdError> {
    let document = parse_yaml_ld(text, options)?;
    to_quads(&document, &options.jsonld, provenance)
}

/// Scans the YAML event stream before saphyr composes it.
///
/// Composition is where YAML input amplifies, and the composed tree is
/// where it recurses, so both are bounded here on the flat event stream:
///
/// - YAML-LD Basic forbids alias nodes (`*name`). saphyr composes aliases
///   into copies, so the composed graph no longer contains `Yaml::Alias`;
///   the event stream is the only place the profile can fail closed.
/// - saphyr composes every alias by deep-copying the anchored node, so ten
///   anchors that each alias the previous one ten times compose to 10^10
///   nodes from a few hundred bytes ("billion laughs"). Each alias is
///   charged the composed size of its anchor, and the total is held to
///   [`JsonLdLimits::max_nodes`].
/// - Block collections nest without a parser limit (flow collections stop
///   at 255 in saphyr), and the composed tree is converted and dropped
///   recursively, so collection nesting is held to
///   [`JsonLdLimits::max_depth`] before any tree exists.
fn prescan_events(
    text: &str,
    profile: YamlLdProfile,
    limits: &JsonLdLimits,
) -> Result<(), JsonLdError> {
    // Open collections: (anchor id, composed count including the opener).
    let mut open: Vec<(usize, usize)> = Vec::new();
    // Composed node count of each anchored node, by anchor id.
    let mut anchored: HashMap<usize, usize> = HashMap::new();
    let mut composed: usize = 0;
    for event in Parser::new_from_str(text) {
        let (event, _) = event
            .map_err(|error| JsonLdError::YamlLoadFailed(format!("YAML parse failed: {error}")))?;
        match event {
            Event::Alias(id) => {
                if profile == YamlLdProfile::Basic {
                    return Err(JsonLdError::YamlProfile(
                        "YAML-LD Basic profile forbids alias nodes".to_owned(),
                    ));
                }
                let size = anchored.get(&id).copied().unwrap_or(1);
                composed = composed.saturating_add(size);
            }
            Event::Scalar(_, _, anchor, _) => {
                composed = composed.saturating_add(1);
                if anchor != 0 {
                    anchored.insert(anchor, 1);
                }
            }
            Event::SequenceStart(anchor, _) | Event::MappingStart(anchor, _) => {
                composed = composed.saturating_add(1);
                open.push((anchor, composed));
                if open.len() > limits.max_depth {
                    return Err(JsonLdError::ResourceLimit {
                        resource: JsonLdResource::Depth,
                        limit: limits.max_depth,
                        observed: open.len(),
                    });
                }
            }
            Event::SequenceEnd | Event::MappingEnd => {
                if let Some((anchor, opened)) = open.pop()
                    && anchor != 0
                {
                    anchored.insert(anchor, composed.saturating_sub(opened).saturating_add(1));
                }
            }
            Event::Nothing
            | Event::StreamStart
            | Event::StreamEnd
            | Event::DocumentStart(_)
            | Event::DocumentEnd => {}
        }
        if composed > limits.max_nodes {
            return Err(JsonLdError::ResourceLimit {
                resource: JsonLdResource::Nodes,
                limit: limits.max_nodes,
                observed: composed,
            });
        }
    }
    Ok(())
}

fn yaml_to_json(
    node: &Yaml<'_>,
    depth: &mut usize,
    max_depth: usize,
    profile: YamlLdProfile,
) -> Result<Value, JsonLdError> {
    *depth += 1;
    if *depth > max_depth {
        return Err(JsonLdError::ResourceLimit {
            resource: crate::JsonLdResource::Depth,
            limit: max_depth,
            observed: *depth,
        });
    }
    let result = yaml_to_json_inner(node, depth, max_depth, profile);
    *depth = depth.saturating_sub(1);
    result
}

fn yaml_to_json_inner(
    node: &Yaml<'_>,
    depth: &mut usize,
    max_depth: usize,
    profile: YamlLdProfile,
) -> Result<Value, JsonLdError> {
    match node {
        Yaml::Value(scalar) => scalar_to_json(scalar),
        Yaml::Sequence(items) => {
            let mut array = Vec::with_capacity(items.len());
            for item in items {
                array.push(yaml_to_json(item, depth, max_depth, profile)?);
            }
            Ok(Value::Array(array))
        }
        Yaml::Mapping(mapping) => {
            let mut map = Map::new();
            for (key, value) in mapping {
                let key = mapping_key_to_string(key)?;
                map.insert(key, yaml_to_json(value, depth, max_depth, profile)?);
            }
            Ok(Value::Object(map))
        }
        Yaml::Tagged(tag, inner) => {
            let converted = yaml_to_json(inner, depth, max_depth, profile)?;
            match profile {
                YamlLdProfile::Basic => Ok(converted),
                YamlLdProfile::Extended => apply_extended_tag(tag.as_ref(), converted),
            }
        }
        Yaml::Alias(_) => Err(JsonLdError::YamlLoadFailed(
            "YAML alias survived composition (cyclic alias)".to_owned(),
        )),
        Yaml::BadValue => Err(JsonLdError::YamlLoadFailed(
            "YAML scalar failed Core Schema resolution".to_owned(),
        )),
        Yaml::Representation(text, _, _) => Ok(Value::String(text.as_ref().to_owned())),
    }
}

/// Extended profile: Core Schema tags stay JSON scalars; an IRI suffix
/// becomes a typed JSON-LD value object; anything else fails closed.
fn apply_extended_tag(tag: &Tag, value: Value) -> Result<Value, JsonLdError> {
    if tag.is_yaml_core_schema() {
        return Ok(value);
    }
    let iri = tag_to_datatype_iri(tag)?;
    match value {
        Value::Object(_) | Value::Array(_) => Err(JsonLdError::YamlProfile(format!(
            "YAML-LD Extended IRI tag `{tag}` is only valid on scalars"
        ))),
        scalar => Ok(Value::Object(Map::from_iter([
            ("@value".to_owned(), scalar),
            ("@type".to_owned(), Value::String(iri)),
        ]))),
    }
}

fn tag_to_datatype_iri(tag: &Tag) -> Result<String, JsonLdError> {
    let suffix = tag.suffix.trim_start_matches('<').trim_end_matches('>');
    if is_absolute_iri(suffix) {
        return Ok(suffix.to_owned());
    }
    let combined = format!("{}{suffix}", tag.handle);
    if is_absolute_iri(&combined) {
        return Ok(combined);
    }
    Err(JsonLdError::YamlProfile(format!(
        "YAML-LD Extended forbids local tag `{tag}` that is not an IRI"
    )))
}

fn mapping_key_to_string(key: &Yaml<'_>) -> Result<String, JsonLdError> {
    match key {
        Yaml::Value(Scalar::String(text)) => Ok(text.as_ref().to_owned()),
        Yaml::Value(Scalar::Null) => Err(JsonLdError::YamlMappingKey(
            "mapping key is null, not a string".to_owned(),
        )),
        Yaml::Value(Scalar::Boolean(_)) => Err(JsonLdError::YamlMappingKey(
            "mapping key is a boolean, not a string".to_owned(),
        )),
        Yaml::Value(Scalar::Integer(int)) => Err(JsonLdError::YamlMappingKey(format!(
            "mapping key `{int}` is an integer, not a string"
        ))),
        Yaml::Value(Scalar::FloatingPoint(_)) => Err(JsonLdError::YamlMappingKey(
            "mapping key is a float, not a string".to_owned(),
        )),
        Yaml::Tagged(_, inner) => mapping_key_to_string(inner),
        other => Err(JsonLdError::YamlMappingKey(format!(
            "mapping key `{other:?}` is not a string"
        ))),
    }
}

fn scalar_to_json(scalar: &Scalar<'_>) -> Result<Value, JsonLdError> {
    match scalar {
        Scalar::Null => Ok(Value::Null),
        Scalar::Boolean(flag) => Ok(Value::Bool(*flag)),
        Scalar::Integer(int) => Ok(Value::Number(Number::from(*int))),
        Scalar::FloatingPoint(float) => {
            let value = f64::from(*float);
            if !value.is_finite() {
                return Err(JsonLdError::YamlLoadFailed(
                    "YAML float infinity/NaN cannot become JSON".to_owned(),
                ));
            }
            Number::from_f64(value).map(Value::Number).ok_or_else(|| {
                JsonLdError::YamlLoadFailed("YAML float is not a finite JSON number".to_owned())
            })
        }
        Scalar::String(text) => Ok(Value::String(text.as_ref().to_owned())),
    }
}

fn write_yaml(out: &mut String, value: &Value, indent: usize) -> Result<(), JsonLdError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => push_yaml_scalar(out, text),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return Ok(());
            }
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push('\n');
                    for _ in 0..indent {
                        out.push_str("  ");
                    }
                }
                out.push_str("- ");
                write_yaml_block(out, item, indent + 1)?;
            }
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return Ok(());
            }
            for (index, (key, child)) in map.iter().enumerate() {
                if index > 0 {
                    out.push('\n');
                    for _ in 0..indent {
                        out.push_str("  ");
                    }
                }
                push_yaml_key(out, key);
                if is_collection(child) && !is_empty_collection(child) {
                    out.push(':');
                    out.push('\n');
                    for _ in 0..(indent + 1) {
                        out.push_str("  ");
                    }
                    write_yaml(out, child, indent + 1)?;
                } else {
                    out.push(':');
                    out.push(' ');
                    write_yaml(out, child, indent + 1)?;
                }
            }
        }
    }
    Ok(())
}

fn write_yaml_block(out: &mut String, value: &Value, indent: usize) -> Result<(), JsonLdError> {
    match value {
        Value::Array(_) | Value::Object(_) if !is_empty_collection(value) => {
            write_yaml(out, value, indent)
        }
        _ => write_yaml(out, value, indent),
    }
}

fn is_collection(value: &Value) -> bool {
    matches!(value, Value::Array(_) | Value::Object(_))
}

fn is_empty_collection(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

fn push_yaml_key(out: &mut String, key: &str) {
    if yaml_plain_ok(key) && !key.contains(':') {
        out.push_str(key);
    } else {
        push_yaml_quoted(out, key);
    }
}

fn push_yaml_scalar(out: &mut String, text: &str) {
    if yaml_plain_ok(text) && !yaml_looks_like_non_string(text) {
        out.push_str(text);
    } else {
        push_yaml_quoted(out, text);
    }
}

fn yaml_looks_like_non_string(text: &str) -> bool {
    matches!(
        text,
        "true"
            | "false"
            | "null"
            | "True"
            | "False"
            | "Null"
            | "TRUE"
            | "FALSE"
            | "NULL"
            | "~"
            | "yes"
            | "no"
            | "on"
            | "off"
            | ".inf"
            | ".nan"
            | "-.inf"
            | "+.inf"
    ) || text.parse::<f64>().is_ok()
}

fn yaml_plain_ok(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() && first != '_' && first != '/' {
        return false;
    }
    text.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | '#' | '?')
    })
}

fn push_yaml_quoted(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
}
