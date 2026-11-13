// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Compaction of expanded JSON-LD documents (JSON-LD 1.1 API section 6).
//!
//! Implements the Compaction Algorithm (API section 6.1.2) over inline
//! contexts, together with its four supporting algorithms: Inverse Context
//! Creation (section 6.2.2), Term Selection (section 6.3.2), IRI Compaction
//! (section 6.4.2), and Value Compaction (section 6.5.2). Output is
//! deterministic: result maps are `BTreeMap`-backed, so entries are always
//! ordered, and every choice point (term selection, compact-IRI candidates)
//! resolves by a total order.
//!
//! Two safety properties tighten the spec without deviating from it
//! observably on valid input:
//!
//! - **Verified relativization.** IRIs compact to base-relative references
//!   only when resolving the candidate against the base reproduces the
//!   original IRI byte-for-byte ([`crate::iri::relativize`]).
//! - **Verified container reshaping.** A value is re-expressed through a
//!   term's container mapping (`@list`, map containers, graph containers)
//!   only when expansion of that shape reproduces the original expanded
//!   value; otherwise the property compacts to a term-free key (compact IRI
//!   or absolute IRI) with a generic wrapping, which always round-trips.

use std::{cell::Cell, collections::HashMap};

use serde_json::{Map, Value};

use crate::{
    context::{
        ContainerSet, Context, DirectionMapping, LanguageMapping, TermDefinition, is_keyword,
        process_context,
    },
    error::JsonLdError,
    iri::relativize,
    options::JsonLdOptions,
};

/// Compacts an expanded document against an inline context value.
///
/// Applies the `JsonLdProcessor.compact` wrapping rules (API section 5.1 of
/// the JSON-LD 1.1 API's `compact()` entry point): an empty top-level array
/// becomes an empty map and a non-empty array is wrapped under the `@graph`
/// alias. The `@context` entry is *not* attached; use [`attach_context`].
///
/// # Errors
///
/// Returns context-processing errors for the given context (including
/// [`JsonLdError::RemoteContextRefused`] for remote references) and
/// [`JsonLdError::InvalidDocument`] when `expanded` is not valid expanded
/// form.
pub(crate) fn compact_expanded(
    expanded: &Value,
    context_value: &Value,
    options: &JsonLdOptions,
    output_budget: usize,
) -> Result<Value, JsonLdError> {
    let initial = Context {
        base: options.base.clone(),
        ..Context::default()
    };
    let active = process_context(
        &initial,
        context_value,
        options.base.as_deref(),
        false,
        true,
    )?;
    let compactor = Compactor {
        options_base: options.base.clone(),
        compact_arrays: options.compact_arrays,
        output_bytes: Cell::new(0),
        max_output_bytes: output_budget,
    };
    let compacted = compactor.compact_element(&active, None, expanded)?;
    match compacted {
        Value::Array(items) if items.is_empty() => Ok(Value::Object(Map::new())),
        Value::Array(items) => {
            let inverse = create_inverse_context(&active);
            let graph_alias =
                compactor.compact_iri(&active, &inverse, "@graph", None, true, false)?;
            Ok(Value::Object(Map::from_iter([(
                graph_alias,
                Value::Array(items),
            )])))
        }
        other => Ok(other),
    }
}

/// Attaches the original inline context to a compacted result.
///
/// Mirrors the final step of `JsonLdProcessor.compact`: the context is added
/// verbatim under `@context` unless it is `null` or empty.
pub(crate) fn attach_context(result: Value, context_value: &Value) -> Value {
    let empty = match context_value {
        Value::Null => true,
        Value::Object(map) => map.is_empty(),
        Value::Array(items) => items.is_empty(),
        _ => false,
    };
    match result {
        Value::Object(map) if !empty => {
            let mut ordered = serde_json::Map::new();
            ordered.insert("@context".to_owned(), sort_object_keys(context_value));
            for (key, value) in map {
                ordered.insert(key, sort_object_keys(&value));
            }
            Value::Object(ordered)
        }
        other => other,
    }
}

/// Recursively emits object keys in byte order — the BTreeMap-backed shape
/// the compacted-output contract requires. Array order is semantically
/// meaningful (lists, sets, index entries) and is preserved.
fn sort_object_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map
                .iter()
                .map(|(key, value)| (key.clone(), sort_object_keys(value)))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_object_keys).collect()),
        other => other.clone(),
    }
}

/// The type/language axis of one inverse-context lookup.
#[derive(Clone, Copy, Debug)]
enum TypeLanguage {
    /// Look in the language map.
    Language,
    /// Look in the type map.
    Type,
    /// Look in the any map (empty `@list` values).
    Any,
}

/// One `(container, term)` bucket of the inverse context.
#[derive(Debug, Default)]
struct TypeLanguageMaps {
    /// Terms keyed by language (or language-direction) key.
    language: HashMap<String, String>,
    /// Terms keyed by type mapping (or `@reverse`).
    type_: HashMap<String, String>,
    /// The fallback term of this container (keyed `@none`).
    any: HashMap<String, String>,
}

/// Inverse context (JSON-LD 1.1 API section 6.2): IRI to container to
/// type/language maps.
#[derive(Debug, Default)]
struct InverseContext {
    /// `iri -> canonical container key -> maps`.
    map: HashMap<String, HashMap<String, TypeLanguageMaps>>,
}

/// Canonical container key of one term (members concatenated in
/// lexicographic order, `@none` when empty). The single source of truth for
/// both inverse-context construction and IRI-compaction preferences.
fn container_key(set: ContainerSet) -> String {
    let mut members = String::new();
    // Lexicographic member order:
    // @graph < @id < @index < @language < @list < @set < @type.
    if set.graph {
        members.push_str("@graph");
    }
    if set.id {
        members.push_str("@id");
    }
    if set.index {
        members.push_str("@index");
    }
    if set.language {
        members.push_str("@language");
    }
    if set.list {
        members.push_str("@list");
    }
    if set.set {
        members.push_str("@set");
    }
    if set.type_ {
        members.push_str("@type");
    }
    if members.is_empty() {
        "@none".to_owned()
    } else {
        members
    }
}

fn insert_if_absent(map: &mut HashMap<String, String>, key: &str, term: &str) {
    if !map.contains_key(key) {
        map.insert(key.to_owned(), term.to_owned());
    }
}

/// Builds the inverse context (JSON-LD 1.1 API section 6.2.2).
///
/// Terms are visited shortest-first, then lexicographically least, so the
/// first (preferred) term wins every bucket deterministically.
fn create_inverse_context(ctx: &Context) -> InverseContext {
    let default_language = ctx
        .default_language
        .as_deref()
        .map_or_else(|| "@none".to_owned(), str::to_lowercase);
    let mut terms: Vec<(&String, &TermDefinition)> = ctx.terms.iter().collect();
    terms.sort_by(|(left, _), (right, _)| {
        left.len().cmp(&right.len()).then_with(|| left.cmp(right))
    });
    let mut inverse = InverseContext::default();
    for (term, definition) in terms {
        let Some(iri) = &definition.iri else {
            continue;
        };
        let container = container_key(definition.container);
        let entry = inverse
            .map
            .entry(iri.clone())
            .or_default()
            .entry(container)
            .or_default();
        insert_if_absent(&mut entry.any, "@none", term);
        if definition.reverse {
            // Section 6.2.2: reverse properties key the type map @reverse.
            insert_if_absent(&mut entry.type_, "@reverse", term);
        } else if let Some(type_mapping) = &definition.type_mapping {
            insert_if_absent(&mut entry.type_, type_mapping, term);
        } else {
            let language = &definition.language;
            let direction = definition.direction;
            let unset = matches!(language, LanguageMapping::Unset)
                && matches!(direction, DirectionMapping::Unset);
            if unset {
                // No per-term mapping: the context defaults apply.
                let language_key = match ctx.default_direction {
                    Some(default_direction) => {
                        format!("{default_language}_{}", default_direction.as_str())
                    }
                    None => default_language.clone(),
                };
                insert_if_absent(&mut entry.language, &language_key, term);
                insert_if_absent(&mut entry.language, "@none", term);
                insert_if_absent(&mut entry.type_, "@none", term);
            } else {
                let key = language_direction_key(language, direction);
                insert_if_absent(&mut entry.language, &key, term);
            }
        }
    }
    inverse
}

/// Language-map key of a term with an explicit language or direction
/// mapping (JSON-LD 1.1 API section 6.2.2, direction-aware keys).
fn language_direction_key(language: &LanguageMapping, direction: DirectionMapping) -> String {
    let language_tag = match language {
        LanguageMapping::Tag(tag) => Some(tag.to_lowercase()),
        LanguageMapping::Null => None,
        LanguageMapping::Unset => None,
    };
    match (language, direction) {
        (LanguageMapping::Unset, DirectionMapping::Fixed(fixed)) => {
            format!("_{}", fixed.as_str())
        }
        (LanguageMapping::Unset, _) => "@none".to_owned(),
        (_, DirectionMapping::Fixed(fixed)) => match language_tag {
            Some(tag) => format!("{tag}_{}", fixed.as_str()),
            None => format!("_{}", fixed.as_str()),
        },
        (_, DirectionMapping::Null | DirectionMapping::Unset) => {
            language_tag.unwrap_or_else(|| "@null".to_owned())
        }
    }
}

/// Term Selection (JSON-LD 1.1 API section 6.3.2).
fn select_term<'inverse>(
    inverse: &'inverse InverseContext,
    iri: &str,
    containers: &[String],
    type_language: TypeLanguage,
    preferred: &[String],
) -> Option<&'inverse str> {
    let container_map = inverse.map.get(iri)?;
    for container in containers {
        let Some(entry) = container_map.get(container) else {
            continue;
        };
        let value_map = match type_language {
            TypeLanguage::Language => &entry.language,
            TypeLanguage::Type => &entry.type_,
            TypeLanguage::Any => &entry.any,
        };
        for item in preferred {
            // Section 6.3.2 step 3.4: every preferred value, `@any`
            // included, is looked up in the *selected* type or language
            // map. `@any` keys only the type/language maps of a term whose
            // type mapping is `@none` (section 6.2.2), a feature this
            // processor refuses, so the lookup is inert rather than a
            // universal fallback. Treating it as one — returning the
            // container's `any` map, whose `@none` entry every term
            // populates for the empty-`@list` lookup — would select a term
            // whose coercion the value does not have, and
            // `expand(compact(doc))` would stop equalling `expand(doc)`.
            if let Some(term) = value_map.get(item) {
                return Some(term);
            }
        }
    }
    None
}

/// Returns `true` when `map` is an expanded graph object.
fn is_graph_object(map: &Map<String, Value>) -> bool {
    map.contains_key("@graph")
        && map
            .keys()
            .all(|key| matches!(key.as_str(), "@graph" | "@id" | "@index"))
}

/// Merges `value` into `map[key]` (the API's Add Value helper).
///
/// Arrays merge element-wise; `as_array` forces the slot into array form.
fn add_value(map: &mut Map<String, Value>, key: &str, value: Value, as_array: bool) {
    if let Value::Array(items) = value {
        if items.is_empty() && !map.contains_key(key) {
            map.insert(key.to_owned(), Value::Array(Vec::new()));
            return;
        }
        for item in items {
            add_value(map, key, item, true);
        }
        return;
    }
    match map.get_mut(key) {
        Some(Value::Array(existing)) => existing.push(value),
        Some(existing) => {
            let previous = existing.take();
            *existing = Value::Array(vec![previous, value]);
        }
        None => {
            let slot = if as_array {
                Value::Array(vec![value])
            } else {
                value
            };
            map.insert(key.to_owned(), slot);
        }
    }
}

fn ensure_array(value: Value) -> Value {
    if value.is_array() {
        value
    } else {
        Value::Array(vec![value])
    }
}

/// Shared state of one compaction run.
pub(crate) struct Compactor {
    /// The API base IRI, restored when a scoped context nullifies `@base`.
    options_base: Option<String>,
    /// The `compactArrays` option.
    compact_arrays: bool,
    /// String bytes produced so far (see [`Compactor::charge_output`]).
    output_bytes: Cell<usize>,
    /// Budget for `output_bytes`
    /// ([`crate::JsonLdLimits::max_output_bytes`]).
    max_output_bytes: usize,
}

impl std::fmt::Debug for Compactor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Compactor")
            .field("compact_arrays", &self.compact_arrays)
            .finish_non_exhaustive()
    }
}

impl Compactor {
    /// Charges the strings a compacted element holds directly.
    ///
    /// Compaction can amplify as expansion does: a context term with a
    /// long name chosen for a short IRI is copied at every use. Each object
    /// compaction builds is charged its keys and direct strings once, when
    /// it is built; a scalar (a compacted value) is charged its string.
    fn charge_output(&self, value: &Value) -> Result<(), JsonLdError> {
        let mut bytes = 0_usize;
        match value {
            Value::String(text) => bytes = text.len(),
            Value::Object(map) => {
                for (key, item) in map {
                    bytes = bytes.saturating_add(key.len());
                    match item {
                        Value::String(text) => bytes = bytes.saturating_add(text.len()),
                        Value::Array(items) => {
                            for entry in items {
                                if let Value::String(text) = entry {
                                    bytes = bytes.saturating_add(text.len());
                                }
                            }
                        }
                        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => {}
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) => {}
        }
        let total = self.output_bytes.get().saturating_add(bytes);
        self.output_bytes.set(total);
        if total > self.max_output_bytes {
            return Err(JsonLdError::ResourceLimit {
                resource: crate::error::JsonLdResource::OutputBytes,
                limit: self.max_output_bytes,
                observed: total,
            });
        }
        Ok(())
    }

    /// Compacts one expanded element (API section 6.1.2).
    fn compact_element(
        &self,
        ctx: &Context,
        active_property: Option<&str>,
        element: &Value,
    ) -> Result<Value, JsonLdError> {
        match element {
            Value::Array(items) => {
                let mut result = Vec::with_capacity(items.len());
                for item in items {
                    result.push(self.compact_element(ctx, active_property, item)?);
                }
                let container = active_property
                    .and_then(|property| ctx.terms.get(property))
                    .map(|definition| definition.container)
                    .unwrap_or_default();
                let keep_array = !self.compact_arrays
                    || container.set
                    || container.list
                    || matches!(active_property, Some("@graph" | "@set"));
                if result.len() == 1 && !keep_array {
                    Ok(result.remove(0))
                } else {
                    Ok(Value::Array(result))
                }
            }
            Value::Object(map) => {
                let compacted = self.compact_object(ctx, active_property, map)?;
                self.charge_output(&compacted)?;
                Ok(compacted)
            }
            scalar => Ok(scalar.clone()),
        }
    }

    /// Compacts one expanded map (API section 6.1.2 steps 4-13).
    #[expect(
        clippy::too_many_lines,
        reason = "mirrors the sequential keyword steps of API section 6.1.2"
    )]
    fn compact_object(
        &self,
        parent_ctx: &Context,
        active_property: Option<&str>,
        element: &Map<String, Value>,
    ) -> Result<Value, JsonLdError> {
        // Section 6.1.2: the property-scoped context of the active property
        // applies before compacting its values.
        let mut owned: Option<Context> = None;
        if let Some(local) = active_property
            .and_then(|property| parent_ctx.terms.get(property))
            .and_then(|definition| definition.local_context.clone())
        {
            owned = Some(process_context(
                parent_ctx,
                &local,
                self.options_base.as_deref(),
                true,
                true,
            )?);
        }
        // Section 6.1.2: type-scoped contexts of the (compacted, sorted)
        // types apply next; the inverse context is rebuilt afterwards.
        if let Some(Value::Array(types)) = element.get("@type") {
            let snapshot = owned.as_ref().unwrap_or(parent_ctx);
            let inverse = create_inverse_context(snapshot);
            let mut compacted_types = Vec::with_capacity(types.len());
            for entry in types {
                if let Value::String(type_iri) = entry {
                    compacted_types
                        .push(self.compact_iri(snapshot, &inverse, type_iri, None, true, false)?);
                }
            }
            compacted_types.sort();
            for term in &compacted_types {
                let local = {
                    let current = owned.as_ref().unwrap_or(parent_ctx);
                    current
                        .terms
                        .get(term)
                        .and_then(|definition| definition.local_context.clone())
                };
                if let Some(local) = local {
                    let current = owned.as_ref().unwrap_or(parent_ctx);
                    owned = Some(process_context(
                        current,
                        &local,
                        self.options_base.as_deref(),
                        false,
                        false,
                    )?);
                }
            }
        }
        let ctx = owned.as_ref().unwrap_or(parent_ctx);
        let inverse = create_inverse_context(ctx);

        // Value objects and lone node references go through value compaction.
        if element.contains_key("@value") || (element.len() == 1 && element.contains_key("@id")) {
            return self.compact_value(ctx, &inverse, active_property, element);
        }

        let inside_reverse = active_property == Some("@reverse");
        let mut result: Map<String, Value> = Map::new();
        for (expanded_property, expanded_value) in element {
            match expanded_property.as_str() {
                "@id" => {
                    let key = self.compact_iri(ctx, &inverse, "@id", None, true, false)?;
                    match expanded_value {
                        Value::String(id) => {
                            let compacted =
                                self.compact_iri(ctx, &inverse, id, None, false, false)?;
                            result.insert(key, Value::String(compacted));
                        }
                        Value::Object(_) => {
                            let compacted = self.compact_element(ctx, None, expanded_value)?;
                            result.insert(key, compacted);
                        }
                        _ => {
                            return Err(JsonLdError::InvalidDocument(
                                "an expanded @id must be a string or an embedded node".to_owned(),
                            ));
                        }
                    }
                }
                "@type" => {
                    let Value::Array(types) = expanded_value else {
                        return Err(JsonLdError::InvalidDocument(
                            "an expanded @type must be an array".to_owned(),
                        ));
                    };
                    let mut compacted = Vec::with_capacity(types.len());
                    for entry in types {
                        let Value::String(type_iri) = entry else {
                            return Err(JsonLdError::InvalidDocument(
                                "expanded @type entries must be strings".to_owned(),
                            ));
                        };
                        compacted.push(Value::String(
                            self.compact_iri(ctx, &inverse, type_iri, None, true, false)?,
                        ));
                    }
                    let key = self.compact_iri(ctx, &inverse, "@type", None, true, false)?;
                    let value = if compacted.len() == 1 && self.compact_arrays {
                        compacted.remove(0)
                    } else {
                        Value::Array(compacted)
                    };
                    result.insert(key, value);
                }
                "@reverse" => {
                    // Section 6.1.2: reverse entries whose compacted key is a
                    // reverse term hoist into the node; the rest stay under
                    // the @reverse alias.
                    let compacted = self.compact_element(ctx, Some("@reverse"), expanded_value)?;
                    let Value::Object(reverse_map) = compacted else {
                        return Err(JsonLdError::InvalidDocument(
                            "an expanded @reverse must be a map".to_owned(),
                        ));
                    };
                    let mut remaining = Map::new();
                    for (key, value) in reverse_map {
                        let definition = ctx.terms.get(&key);
                        if definition.is_some_and(|definition| definition.reverse) {
                            let container = definition
                                .map(|definition| definition.container)
                                .unwrap_or_default();
                            let as_array = !self.compact_arrays || container.set;
                            add_value(&mut result, &key, value, as_array);
                        } else {
                            remaining.insert(key, value);
                        }
                    }
                    if !remaining.is_empty() {
                        let alias =
                            self.compact_iri(ctx, &inverse, "@reverse", None, true, false)?;
                        result.insert(alias, Value::Object(remaining));
                    }
                }
                "@preserve" => {
                    // Framing passthrough (API section 6.1.2): the value
                    // compacts with the same active property; the wrapper is
                    // unwrapped by the framing post-pass.
                    let compacted = self.compact_element(ctx, active_property, expanded_value)?;
                    let empty = matches!(&compacted, Value::Array(items) if items.is_empty());
                    if !empty {
                        result.insert("@preserve".to_owned(), compacted);
                    }
                }
                "@index" => {
                    let container = active_property
                        .and_then(|property| ctx.terms.get(property))
                        .map(|definition| definition.container)
                        .unwrap_or_default();
                    if container.index {
                        continue; // Re-expressed as the container map key.
                    }
                    let key = self.compact_iri(ctx, &inverse, "@index", None, true, false)?;
                    result.insert(key, expanded_value.clone());
                }
                "@list" => {
                    // A list object outside a property position (e.g. inside
                    // @preserve): compact under the @list alias.
                    let compacted = self.compact_element(ctx, active_property, expanded_value)?;
                    let key = self.compact_iri(ctx, &inverse, "@list", None, true, false)?;
                    result.insert(key, ensure_array(compacted));
                }
                "@graph" => {
                    let compacted = self.compact_element(ctx, Some("@graph"), expanded_value)?;
                    let key = self.compact_iri(ctx, &inverse, "@graph", None, true, false)?;
                    result.insert(key, ensure_array(compacted));
                }
                "@included" => {
                    let compacted = self.compact_element(ctx, Some("@included"), expanded_value)?;
                    let key = self.compact_iri(ctx, &inverse, "@included", None, true, false)?;
                    result.insert(key, compacted);
                }
                "@annotation" => {
                    let compacted =
                        self.compact_element(ctx, Some("@annotation"), expanded_value)?;
                    let key = self.compact_iri(ctx, &inverse, "@annotation", None, true, false)?;
                    result.insert(key, compacted);
                }
                other if other.starts_with('@') => {
                    return Err(JsonLdError::InvalidDocument(format!(
                        "keyword `{other}` is not valid in an expanded node object"
                    )));
                }
                property => {
                    self.compact_property(
                        ctx,
                        &inverse,
                        &mut result,
                        property,
                        expanded_value,
                        inside_reverse,
                    )?;
                }
            }
        }
        Ok(Value::Object(result))
    }

    /// Compacts the values of one expanded property into `result`
    /// (API section 6.1.2 step 12, including container reshaping).
    #[expect(
        clippy::too_many_lines,
        reason = "one branch per @container family, mirroring API section 6.1.2 step 12"
    )]
    fn compact_property(
        &self,
        ctx: &Context,
        inverse: &InverseContext,
        result: &mut Map<String, Value>,
        property: &str,
        values: &Value,
        inside_reverse: bool,
    ) -> Result<(), JsonLdError> {
        let Value::Array(items) = values else {
            return Err(JsonLdError::InvalidDocument(format!(
                "expanded property `{property}` must hold an array"
            )));
        };
        if items.is_empty() {
            // Step 12.1: an empty array compacts to an empty array under the
            // term selected with a null value.
            let item_key = self.compact_iri(ctx, inverse, property, None, true, inside_reverse)?;
            let definition = ctx.terms.get(&item_key).cloned().unwrap_or_default();
            let target = nest_target(ctx, result, &definition)?;
            add_value(target, &item_key, Value::Array(Vec::new()), true);
            return Ok(());
        }
        for item in items {
            let item_key =
                self.compact_iri(ctx, inverse, property, Some(item), true, inside_reverse)?;
            let definition = ctx.terms.get(&item_key).cloned().unwrap_or_default();
            let container = definition.container;
            let Some(item_map) = item.as_object() else {
                return Err(JsonLdError::InvalidDocument(format!(
                    "expanded values of `{property}` must be objects"
                )));
            };

            if let Some(list_value) = item_map.get("@list") {
                self.compact_list_item(
                    ctx,
                    inverse,
                    result,
                    &item_key,
                    &definition,
                    item_map,
                    list_value,
                )?;
                continue;
            }
            if is_graph_object(item_map) {
                self.compact_graph_item(
                    ctx,
                    inverse,
                    result,
                    property,
                    &item_key,
                    &definition,
                    item_map,
                )?;
                continue;
            }
            if container.language && item_map.contains_key("@value") {
                // Language maps (step 12.8.7): the @language entry becomes
                // the key; the value object compact to a string when the
                // remaining entries are just @value.
                let (map_key, trimmed) = match item_map.get("@language") {
                    Some(Value::String(language)) => {
                        let mut trimmed = item_map.clone();
                        trimmed.remove("@language");
                        (language.to_lowercase(), trimmed)
                    }
                    _ => (
                        self.compact_iri(ctx, inverse, "@none", None, true, false)?,
                        item_map.clone(),
                    ),
                };
                let compacted =
                    self.compact_element(ctx, Some(&item_key), &Value::Object(trimmed))?;
                let as_array = !self.compact_arrays || container.set;
                insert_into_map_entry(
                    result,
                    ctx,
                    &definition,
                    &item_key,
                    &map_key,
                    compacted,
                    as_array,
                )?;
                continue;
            }
            if container.index && !container.graph {
                // Index maps (step 12.8.8): the @index entry becomes the key,
                // or the index-mapping property for property-based indexing
                // (section 4.6.1.1).
                let (map_key, trimmed) = if let Some(index_iri) = &definition.index {
                    match property_index_entry(item_map, index_iri)? {
                        Some(entry) => (entry.key, entry.trimmed),
                        None => (
                            self.compact_iri(ctx, inverse, "@none", None, true, false)?,
                            item_map.clone(),
                        ),
                    }
                } else {
                    match item_map.get("@index") {
                        Some(Value::String(index)) => {
                            let mut trimmed = item_map.clone();
                            trimmed.remove("@index");
                            (index.clone(), trimmed)
                        }
                        _ => (
                            self.compact_iri(ctx, inverse, "@none", None, true, false)?,
                            item_map.clone(),
                        ),
                    }
                };
                let compacted =
                    self.compact_element(ctx, Some(&item_key), &Value::Object(trimmed))?;
                let as_array = !self.compact_arrays || container.set;
                insert_into_map_entry(
                    result,
                    ctx,
                    &definition,
                    &item_key,
                    &map_key,
                    compacted,
                    as_array,
                )?;
                continue;
            }
            if container.id {
                // Id maps (step 12.8.9): the @id entry becomes the key.
                let (map_key, trimmed) = match item_map.get("@id") {
                    Some(Value::String(id)) => {
                        let mut trimmed = item_map.clone();
                        trimmed.remove("@id");
                        (
                            self.compact_iri(ctx, inverse, id, None, false, false)?,
                            trimmed,
                        )
                    }
                    _ => (
                        self.compact_iri(ctx, inverse, "@none", None, true, false)?,
                        item_map.clone(),
                    ),
                };
                let compacted =
                    self.compact_element(ctx, Some(&item_key), &Value::Object(trimmed))?;
                let as_array = !self.compact_arrays || container.set;
                insert_into_map_entry(
                    result,
                    ctx,
                    &definition,
                    &item_key,
                    &map_key,
                    compacted,
                    as_array,
                )?;
                continue;
            }
            if container.type_ {
                // Type maps (step 12.8.10): the first @type entry becomes the
                // key; the remainder stays on the item.
                let mut trimmed = item_map.clone();
                let map_key = match trimmed.get_mut("@type") {
                    Some(Value::Array(types)) if !types.is_empty() => {
                        let first = types.remove(0);
                        let Value::String(type_iri) = first else {
                            return Err(JsonLdError::InvalidDocument(
                                "expanded @type entries must be strings".to_owned(),
                            ));
                        };
                        if types.is_empty() {
                            trimmed.remove("@type");
                        }
                        self.compact_iri(ctx, inverse, &type_iri, None, true, false)?
                    }
                    _ => {
                        trimmed.remove("@type");
                        self.compact_iri(ctx, inverse, "@none", None, true, false)?
                    }
                };
                let compacted =
                    self.compact_element(ctx, Some(&item_key), &Value::Object(trimmed))?;
                let as_array = !self.compact_arrays || container.set;
                insert_into_map_entry(
                    result,
                    ctx,
                    &definition,
                    &item_key,
                    &map_key,
                    compacted,
                    as_array,
                )?;
                continue;
            }
            // Plain values (step 12.8.11).
            let compacted = self.compact_element(ctx, Some(&item_key), item)?;
            let as_array = !self.compact_arrays || container.set || container.list;
            let target = nest_target(ctx, result, &definition)?;
            add_value(target, &item_key, compacted, as_array);
        }
        Ok(())
    }

    /// Compacts one expanded list object under `item_key`
    /// (API section 6.1.2 step 12.8.4).
    #[expect(
        clippy::too_many_arguments,
        reason = "list reshaping shares the full per-item state of the property loop"
    )]
    fn compact_list_item(
        &self,
        ctx: &Context,
        inverse: &InverseContext,
        result: &mut Map<String, Value>,
        item_key: &str,
        definition: &TermDefinition,
        item_map: &Map<String, Value>,
        list_value: &Value,
    ) -> Result<(), JsonLdError> {
        let compacted_inner = self.compact_element(ctx, Some(item_key), list_value)?;
        let compacted_list = ensure_array(compacted_inner);
        if definition.container.list && !item_map.contains_key("@index") {
            // Step 12.8.4.2: the term reassembles the list. Two lists on one
            // term cannot compact (`compaction to list of lists`).
            let target = nest_target(ctx, result, definition)?;
            if target.contains_key(item_key) {
                return Err(JsonLdError::InvalidDocument(format!(
                    "compaction to list of lists on term `{item_key}`"
                )));
            }
            target.insert(item_key.to_owned(), compacted_list);
            return Ok(());
        }
        // Generic wrapping under the @list alias, keeping @index.
        let mut wrapped = Map::new();
        wrapped.insert(
            self.compact_iri(ctx, inverse, "@list", None, true, false)?,
            compacted_list,
        );
        if let Some(index) = item_map.get("@index") {
            wrapped.insert(
                self.compact_iri(ctx, inverse, "@index", None, true, false)?,
                index.clone(),
            );
        }
        let as_array = !self.compact_arrays || definition.container.set;
        let target = nest_target(ctx, result, definition)?;
        add_value(target, item_key, Value::Object(wrapped), as_array);
        Ok(())
    }

    /// Compacts one expanded graph object under `item_key`
    /// (API section 6.1.2 steps 12.8.5-12.8.7).
    ///
    /// Container reshaping only happens when re-expansion provably
    /// reproduces the item (single inner node, expressible extra entries);
    /// otherwise the item compacts under a term-free key with a generic
    /// `@graph` wrapping, which always round-trips.
    #[expect(
        clippy::too_many_arguments,
        reason = "graph reshaping shares the full per-item state of the property loop"
    )]
    fn compact_graph_item(
        &self,
        ctx: &Context,
        inverse: &InverseContext,
        result: &mut Map<String, Value>,
        property: &str,
        item_key: &str,
        definition: &TermDefinition,
        item_map: &Map<String, Value>,
    ) -> Result<(), JsonLdError> {
        let container = definition.container;
        let inner = item_map.get("@graph").cloned().unwrap_or_default();
        let single_node = matches!(&inner, Value::Array(nodes) if nodes.len() == 1);
        let has_id = item_map.contains_key("@id");
        let has_index = item_map.contains_key("@index");
        let compacted_inner = self.compact_element(ctx, Some(item_key), &inner)?;
        let as_array = !self.compact_arrays || container.set;

        if container.graph && container.id && !has_index && single_node {
            let map_key = match item_map.get("@id") {
                Some(Value::String(id)) => {
                    self.compact_iri(ctx, inverse, id, None, false, false)?
                }
                _ => self.compact_iri(ctx, inverse, "@none", None, true, false)?,
            };
            let unwrapped = unwrap_single(compacted_inner, self.compact_arrays);
            insert_into_map_entry(
                result, ctx, definition, item_key, &map_key, unwrapped, as_array,
            )?;
            return Ok(());
        }
        if container.graph && container.index && !has_id && single_node {
            let map_key = match item_map.get("@index") {
                Some(Value::String(index)) => index.clone(),
                _ => self.compact_iri(ctx, inverse, "@none", None, true, false)?,
            };
            let unwrapped = unwrap_single(compacted_inner, self.compact_arrays);
            insert_into_map_entry(
                result, ctx, definition, item_key, &map_key, unwrapped, as_array,
            )?;
            return Ok(());
        }
        if container.graph
            && !container.id
            && !container.index
            && !has_id
            && !has_index
            && single_node
        {
            // Simple graph container: the wrapping is implied by the term.
            let unwrapped = unwrap_single(compacted_inner, self.compact_arrays);
            let target = nest_target(ctx, result, definition)?;
            add_value(target, item_key, unwrapped, as_array);
            return Ok(());
        }
        // Generic wrapping. Under a map-container term the object form would
        // be re-read as a container map, so fall back to a term-free key.
        let (key, key_definition) = if container.is_map_container() || container.graph {
            let fallback = self.compact_iri_without_term(ctx, property)?;
            (fallback, TermDefinition::default())
        } else {
            (item_key.to_owned(), definition.clone())
        };
        let mut wrapped = Map::new();
        wrapped.insert(
            self.compact_iri(ctx, inverse, "@graph", None, true, false)?,
            ensure_array(compacted_inner),
        );
        if let Some(Value::String(id)) = item_map.get("@id") {
            wrapped.insert(
                self.compact_iri(ctx, inverse, "@id", None, true, false)?,
                Value::String(self.compact_iri(ctx, inverse, id, None, false, false)?),
            );
        }
        if let Some(index) = item_map.get("@index") {
            wrapped.insert(
                self.compact_iri(ctx, inverse, "@index", None, true, false)?,
                index.clone(),
            );
        }
        let wrap_as_array = !self.compact_arrays || key_definition.container.set;
        let target = nest_target(ctx, result, &key_definition)?;
        add_value(target, &key, Value::Object(wrapped), wrap_as_array);
        Ok(())
    }

    /// Value Compaction (API section 6.5.2), also covering lone node
    /// references.
    ///
    /// A value object compacts to its bare `@value` only when re-expansion
    /// under the active term provably reproduces it: matching `@type`
    /// against the term's type mapping, or matching language/direction
    /// against the term's effective language and direction (a string with no
    /// language never compacts bare while a default language is in scope).
    #[expect(
        clippy::too_many_lines,
        reason = "mirrors the case analysis of API section 6.5.2"
    )]
    fn compact_value(
        &self,
        ctx: &Context,
        inverse: &InverseContext,
        active_property: Option<&str>,
        element: &Map<String, Value>,
    ) -> Result<Value, JsonLdError> {
        let definition = active_property
            .and_then(|property| ctx.terms.get(property))
            .cloned()
            .unwrap_or_default();

        if !element.contains_key("@value") {
            // Lone node reference, including a JSON-LD-star quoted triple.
            match element.get("@id") {
                Some(Value::Object(_)) => {
                    let compacted = self.compact_element(ctx, None, &element["@id"])?;
                    let key = self.compact_iri(ctx, inverse, "@id", None, true, false)?;
                    return Ok(Value::Object(Map::from_iter([(key, compacted)])));
                }
                Some(Value::String(id)) => {
                    match definition.type_mapping.as_deref() {
                        Some("@id") => {
                            return Ok(Value::String(
                                self.compact_iri(ctx, inverse, id, None, false, false)?,
                            ));
                        }
                        Some("@vocab") => {
                            return Ok(Value::String(
                                self.compact_iri(ctx, inverse, id, None, true, false)?,
                            ));
                        }
                        _ => {}
                    }
                    let key = self.compact_iri(ctx, inverse, "@id", None, true, false)?;
                    let compacted = self.compact_iri(ctx, inverse, id, None, false, false)?;
                    return Ok(Value::Object(Map::from_iter([(
                        key,
                        Value::String(compacted),
                    )])));
                }
                _ => {
                    return Err(JsonLdError::InvalidDocument(
                        "an expanded @id must be a string or an embedded node".to_owned(),
                    ));
                }
            }
        }

        for key in element.keys() {
            if !matches!(
                key.as_str(),
                "@value" | "@type" | "@language" | "@direction" | "@index" | "@annotation"
            ) {
                return Err(JsonLdError::InvalidDocument(format!(
                    "`{key}` is not valid inside a value object"
                )));
            }
        }
        let raw_value = &element["@value"];
        let has_index = element.contains_key("@index");
        let index_expressible = definition.container.index;
        // Bare compaction is only possible when a present @index is carried
        // by the term's index container instead.
        let index_ok = !has_index || index_expressible;
        let significant_entries = element.len() - usize::from(has_index && index_expressible);

        let effective_language = match &definition.language {
            LanguageMapping::Tag(tag) => Some(tag.to_lowercase()),
            LanguageMapping::Null => None,
            LanguageMapping::Unset => ctx.default_language.as_deref().map(str::to_lowercase),
        };
        let effective_direction = match definition.direction {
            DirectionMapping::Fixed(direction) => Some(direction.as_str()),
            DirectionMapping::Null => None,
            DirectionMapping::Unset => ctx.default_direction.map(|direction| direction.as_str()),
        };

        match element.get("@type") {
            Some(Value::String(type_iri)) => {
                if index_ok
                    && significant_entries == 2
                    && definition.type_mapping.as_deref() == Some(type_iri)
                {
                    return Ok(raw_value.clone());
                }
            }
            Some(_) => {
                return Err(JsonLdError::InvalidDocument(
                    "a value object @type must be a string".to_owned(),
                ));
            }
            None => {
                let value_language = element
                    .get("@language")
                    .and_then(Value::as_str)
                    .map(str::to_lowercase);
                let value_direction = element.get("@direction").and_then(Value::as_str);
                if index_ok && raw_value.is_string() {
                    let language_matches = value_language == effective_language;
                    let direction_matches = value_direction == effective_direction;
                    if language_matches && direction_matches && definition.type_mapping.is_none() {
                        return Ok(raw_value.clone());
                    }
                } else if index_ok
                    && value_language.is_none()
                    && value_direction.is_none()
                    && matches!(
                        definition.type_mapping.as_deref(),
                        None | Some("@id" | "@vocab")
                    )
                {
                    return Ok(raw_value.clone());
                }
            }
        }

        // Fallback: a value object with aliased keys and a compacted @type.
        let mut result = Map::new();
        for (key, value) in element {
            match key.as_str() {
                "@value" | "@language" | "@direction" | "@index" => {
                    let alias = self.compact_iri(ctx, inverse, key, None, true, false)?;
                    result.insert(alias, value.clone());
                }
                "@type" => {
                    let Value::String(type_iri) = value else {
                        return Err(JsonLdError::InvalidDocument(
                            "a value object @type must be a string".to_owned(),
                        ));
                    };
                    let alias = self.compact_iri(ctx, inverse, "@type", None, true, false)?;
                    let compacted = self.compact_iri(ctx, inverse, type_iri, None, true, false)?;
                    result.insert(alias, Value::String(compacted));
                }
                "@annotation" => {
                    let alias = self.compact_iri(ctx, inverse, "@annotation", None, true, false)?;
                    let compacted = self.compact_element(ctx, Some("@annotation"), value)?;
                    result.insert(alias, compacted);
                }
                _ => unreachable!("validated above"),
            }
        }
        Ok(Value::Object(result))
    }

    /// IRI Compaction (API section 6.4.2).
    ///
    /// With `vocab`, the inverse context selects the best term for `value`
    /// (Term Selection, section 6.3.2); otherwise, and as fallback, the IRI
    /// compacts to a `@vocab` suffix, a compact IRI, a verified
    /// base-relative reference (`vocab == false`), or itself.
    fn compact_iri(
        &self,
        ctx: &Context,
        inverse: &InverseContext,
        var: &str,
        value: Option<&Value>,
        vocab: bool,
        reverse: bool,
    ) -> Result<String, JsonLdError> {
        if vocab
            && inverse.map.contains_key(var)
            && let Some(term) = self.select_by_value(ctx, inverse, var, value, reverse)?
        {
            return Ok(term);
        }
        if vocab
            && let Some(vocab_iri) = &ctx.vocab
            && var.len() > vocab_iri.len()
            && var.starts_with(vocab_iri.as_str())
        {
            // Section 6.4.2: a vocab-relative suffix, unless it collides
            // with a term or could not expand back (colon, keyword form).
            let suffix = &var[vocab_iri.len()..];
            if !ctx.terms.contains_key(suffix) && !suffix.contains(':') && !suffix.starts_with('@')
            {
                return Ok(suffix.to_owned());
            }
        }
        if let Some(candidate) = compact_iri_candidate(ctx, var, value.is_none()) {
            return Ok(candidate);
        }
        confused_with_prefix_guard(ctx, var)?;
        if vocab {
            return Ok(var.to_owned());
        }
        if let Some(base) = &ctx.base
            && let Some(relative) = relativize(base, var)
        {
            // A relative reference equal to a keyword-aliasing term would be
            // captured by that term during expansion; keep the absolute form.
            let shadowed = ctx
                .terms
                .get(&relative)
                .is_some_and(|definition| definition.iri.as_deref().is_some_and(is_keyword));
            if !shadowed {
                return Ok(relative);
            }
        }
        Ok(var.to_owned())
    }

    /// IRI compaction that never selects a term with special behavior:
    /// `@vocab` suffix, compact IRI, or the absolute IRI. Used when a value
    /// cannot be expressed through the selected term's container.
    fn compact_iri_without_term(&self, ctx: &Context, var: &str) -> Result<String, JsonLdError> {
        if let Some(vocab_iri) = &ctx.vocab
            && var.len() > vocab_iri.len()
            && var.starts_with(vocab_iri.as_str())
        {
            let suffix = &var[vocab_iri.len()..];
            if !ctx.terms.contains_key(suffix) && !suffix.contains(':') && !suffix.starts_with('@')
            {
                return Ok(suffix.to_owned());
            }
        }
        if let Some(candidate) = compact_iri_candidate(ctx, var, true) {
            return Ok(candidate);
        }
        confused_with_prefix_guard(ctx, var)?;
        Ok(var.to_owned())
    }

    /// Builds container preferences and preferred type/language values from
    /// `value`, then runs Term Selection (API section 6.4.2 steps 2.1-2.19).
    #[expect(
        clippy::too_many_lines,
        reason = "mirrors the container/preference case analysis of API section 6.4.2"
    )]
    fn select_by_value(
        &self,
        ctx: &Context,
        inverse: &InverseContext,
        var: &str,
        value: Option<&Value>,
        reverse: bool,
    ) -> Result<Option<String>, JsonLdError> {
        // Step 2.3: a framing @preserve wrapper is transparent.
        let preserved;
        let value = match value {
            Some(Value::Object(map)) if map.contains_key("@preserve") => {
                preserved = match &map["@preserve"] {
                    Value::Array(items) if !items.is_empty() => items[0].clone(),
                    other => other.clone(),
                };
                Some(&preserved)
            }
            other => other,
        };
        let value_map = value.and_then(Value::as_object);
        let is_graph = value_map.is_some_and(is_graph_object);
        let has_index = value_map.is_some_and(|map| map.contains_key("@index"));
        let is_list = !is_graph && value_map.is_some_and(|map| map.contains_key("@list"));
        let is_value = value_map.is_some_and(|map| map.contains_key("@value"));

        let mut containers: Vec<String> = Vec::new();
        let mut type_language = TypeLanguage::Language;
        let mut type_language_value = "@null".to_owned();

        if has_index && !is_graph {
            containers.extend(["@index".to_owned(), "@index@set".to_owned()]);
        }
        if reverse {
            type_language = TypeLanguage::Type;
            type_language_value = "@reverse".to_owned();
            containers.push("@set".to_owned());
        } else if is_list {
            // Step 2.8: common type or language of the list items.
            let map = value_map.expect("is_list implies a map");
            if !has_index {
                containers.push("@list".to_owned());
            }
            let items = match map.get("@list") {
                Some(Value::Array(items)) => items.as_slice(),
                _ => &[],
            };
            if items.is_empty() {
                type_language = TypeLanguage::Any;
                type_language_value = "@none".to_owned();
            } else {
                let mut common_language: Option<String> = None;
                let mut common_type: Option<String> = None;
                for item in items {
                    let mut item_language = "@none".to_owned();
                    let mut item_type = "@none".to_owned();
                    if let Some(item_map) = item.as_object()
                        && item_map.contains_key("@value")
                    {
                        if let Some(direction) = item_map.get("@direction").and_then(Value::as_str)
                        {
                            let language = item_map
                                .get("@language")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_lowercase();
                            item_language = format!("{language}_{direction}");
                        } else if let Some(language) =
                            item_map.get("@language").and_then(Value::as_str)
                        {
                            item_language = language.to_lowercase();
                        } else if let Some(item_type_iri) =
                            item_map.get("@type").and_then(Value::as_str)
                        {
                            item_type = item_type_iri.to_owned();
                        } else {
                            item_language = "@null".to_owned();
                        }
                    } else {
                        item_type = "@id".to_owned();
                    }
                    match &common_language {
                        None => common_language = Some(item_language),
                        Some(current) if *current != item_language => {
                            common_language = Some("@none".to_owned());
                        }
                        Some(_) => {}
                    }
                    match &common_type {
                        None => common_type = Some(item_type),
                        Some(current) if *current != item_type => {
                            common_type = Some("@none".to_owned());
                        }
                        Some(_) => {}
                    }
                }
                let common_type = common_type.unwrap_or_else(|| "@none".to_owned());
                if common_type != "@none" {
                    type_language = TypeLanguage::Type;
                    type_language_value = common_type;
                } else {
                    type_language_value = common_language.unwrap_or_else(|| "@none".to_owned());
                }
            }
        } else if is_graph {
            // Step 2.9: graph objects prefer the container expressing their
            // extra entries.
            let map = value_map.expect("is_graph implies a map");
            let has_id = map.contains_key("@id");
            if has_index {
                containers.extend(["@graph@index".to_owned(), "@graph@index@set".to_owned()]);
            }
            if has_id {
                containers.extend(["@graph@id".to_owned(), "@graph@id@set".to_owned()]);
            }
            containers.extend([
                "@graph".to_owned(),
                "@graph@set".to_owned(),
                "@set".to_owned(),
            ]);
            if !has_index {
                containers.extend(["@graph@index".to_owned(), "@graph@index@set".to_owned()]);
            }
            if !has_id {
                containers.extend(["@graph@id".to_owned(), "@graph@id@set".to_owned()]);
            }
            containers.extend(["@index".to_owned(), "@index@set".to_owned()]);
            type_language = TypeLanguage::Type;
            type_language_value = "@id".to_owned();
        } else {
            if is_value {
                let map = value_map.expect("is_value implies a map");
                if let Some(language) = map.get("@language").and_then(Value::as_str)
                    && !has_index
                {
                    let mut key = language.to_lowercase();
                    if let Some(direction) = map.get("@direction").and_then(Value::as_str) {
                        key = format!("{key}_{direction}");
                    }
                    type_language_value = key;
                    containers.extend(["@language".to_owned(), "@language@set".to_owned()]);
                } else if let Some(direction) = map.get("@direction").and_then(Value::as_str)
                    && !has_index
                {
                    type_language_value = format!("_{direction}");
                } else if let Some(type_iri) = map.get("@type").and_then(Value::as_str) {
                    type_language = TypeLanguage::Type;
                    type_language_value = type_iri.to_owned();
                }
            } else {
                // Node objects and references prefer @id and @type maps.
                type_language = TypeLanguage::Type;
                type_language_value = "@id".to_owned();
                containers.extend([
                    "@id".to_owned(),
                    "@id@set".to_owned(),
                    "@type".to_owned(),
                    "@set@type".to_owned(),
                ]);
            }
            containers.push("@set".to_owned());
        }
        containers.push("@none".to_owned());
        // 1.1 extensions (steps 2.12-2.13): index-less values may live in
        // index containers; plain value objects in language containers.
        if !has_index {
            containers.extend(["@index".to_owned(), "@index@set".to_owned()]);
        }
        if is_value && value_map.is_some_and(|map| map.len() == 1) {
            containers.extend(["@language".to_owned(), "@language@set".to_owned()]);
        }

        // Steps 2.14-2.19: preferred values.
        let mut preferred: Vec<String> = Vec::new();
        if type_language_value == "@reverse" {
            preferred.push("@reverse".to_owned());
        }
        let id_entry = if is_graph {
            None
        } else {
            value_map
                .and_then(|map| map.get("@id"))
                .and_then(Value::as_str)
        };
        if (type_language_value == "@id" || type_language_value == "@reverse")
            && let Some(id) = id_entry
        {
            // Step 2.16: prefer @vocab when the @id itself compacts to a
            // term mapping exactly to it.
            let candidate = self.compact_iri(ctx, inverse, id, None, true, false)?;
            let term_matches = ctx
                .terms
                .get(&candidate)
                .is_some_and(|definition| definition.iri.as_deref() == Some(id));
            if term_matches {
                preferred.extend(["@vocab".to_owned(), "@id".to_owned()]);
            } else {
                preferred.extend(["@id".to_owned(), "@vocab".to_owned()]);
            }
        } else {
            preferred.push(type_language_value.clone());
            if let Some(position) = type_language_value.find('_') {
                // Direction-only fallback for language_direction keys.
                preferred.push(type_language_value[position..].to_owned());
            }
        }
        preferred.push("@none".to_owned());
        preferred.push("@any".to_owned());
        Ok(select_term(inverse, var, &containers, type_language, &preferred).map(str::to_owned))
    }
}

/// Unwraps a single-element array when `compact_arrays` is set.
fn unwrap_single(value: Value, compact_arrays: bool) -> Value {
    match value {
        Value::Array(mut items) if items.len() == 1 && compact_arrays => items.remove(0),
        other => other,
    }
}

/// Chooses the best compact-IRI candidate for `var` (API section 6.4.2
/// step 5): shortest, then lexicographically least, over prefix-enabled
/// terms whose IRI mapping is a proper prefix of `var`.
fn compact_iri_candidate(ctx: &Context, var: &str, value_is_null: bool) -> Option<String> {
    let mut best: Option<String> = None;
    for (term, definition) in ctx.terms.iter() {
        if !definition.prefix || term == "_" {
            continue;
        }
        let Some(iri) = &definition.iri else {
            continue;
        };
        if var.len() <= iri.len() || !var.starts_with(iri.as_str()) {
            continue;
        }
        let suffix = &var[iri.len()..];
        if suffix.starts_with("//") {
            continue; // Would re-expand as an authority, not a suffix.
        }
        let candidate = format!("{term}:{suffix}");
        let usable = match ctx.terms.get(&candidate) {
            None => true,
            Some(existing) => existing.iri.as_deref() == Some(var) && value_is_null,
        };
        if !usable {
            continue;
        }
        let better = best.as_ref().is_none_or(|current| {
            candidate.len() < current.len()
                || (candidate.len() == current.len() && candidate < *current)
        });
        if better {
            best = Some(candidate);
        }
    }
    best
}

/// The API's `IRI confused with prefix` check (section 6.4.2): an emitted
/// absolute IRI whose scheme collides with a prefix-enabled term would
/// re-expand through that term instead.
fn confused_with_prefix_guard(ctx: &Context, var: &str) -> Result<(), JsonLdError> {
    if let Some(colon) = var.find(':')
        && colon > 0
    {
        let scheme = &var[..colon];
        let suffix = &var[colon + 1..];
        if !suffix.starts_with("//")
            && ctx.terms.get(scheme).is_some_and(|definition| {
                definition.prefix
                    && definition
                        .iri
                        .as_deref()
                        .is_some_and(|iri| format!("{iri}{suffix}") != var)
            })
        {
            return Err(JsonLdError::InvalidTerm(format!(
                "IRI confused with prefix: `{var}` collides with term `{scheme}`"
            )));
        }
    }
    Ok(())
}

/// Resolves the output map a term writes into, honoring `@nest`
/// (API section 6.1.2 steps 12.2-12.3).
fn nest_target<'result>(
    ctx: &Context,
    result: &'result mut Map<String, Value>,
    definition: &TermDefinition,
) -> Result<&'result mut Map<String, Value>, JsonLdError> {
    let Some(nest) = &definition.nest else {
        return Ok(result);
    };
    let valid = nest == "@nest"
        || ctx
            .terms
            .get(nest)
            .is_some_and(|definition| definition.iri.as_deref() == Some("@nest"));
    if !valid {
        return Err(JsonLdError::InvalidContext(format!(
            "@nest value `{nest}` does not expand to @nest"
        )));
    }
    let slot = result
        .entry(nest.clone())
        .or_insert_with(|| Value::Object(Map::new()));
    slot.as_object_mut()
        .ok_or_else(|| JsonLdError::InvalidDocument(format!("nest entry `{nest}` is not a map")))
}

/// The map key and remaining item after peeling a property-based index.
struct PropertyIndexEntry {
    key: String,
    trimmed: Map<String, Value>,
}

/// Pulls the property-based index key out of an expanded item (section
/// 4.6.1.1). The index property must hold a single plain-string value
/// object; anything else fails closed rather than inventing a map key.
fn property_index_entry(
    item_map: &Map<String, Value>,
    index_iri: &str,
) -> Result<Option<PropertyIndexEntry>, JsonLdError> {
    let mut trimmed = item_map.clone();
    match trimmed.remove(index_iri) {
        None => Ok(None),
        Some(Value::Array(values)) if values.len() == 1 => {
            let Some(object) = values[0].as_object() else {
                return Err(JsonLdError::InvalidDocument(format!(
                    "property-based index `{index_iri}` must hold a value object"
                )));
            };
            let extra = object.keys().any(|key| key != "@value");
            let Some(Value::String(key)) = object.get("@value") else {
                return Err(JsonLdError::InvalidDocument(format!(
                    "property-based index `{index_iri}` must hold a string @value"
                )));
            };
            if extra {
                return Err(JsonLdError::InvalidDocument(format!(
                    "property-based index `{index_iri}` must be a plain string"
                )));
            }
            Ok(Some(PropertyIndexEntry {
                key: key.clone(),
                trimmed,
            }))
        }
        Some(_) => Err(JsonLdError::InvalidDocument(format!(
            "property-based index `{index_iri}` must hold exactly one value"
        ))),
    }
}

/// Adds one compacted item into the container map stored under `item_key`.
fn insert_into_map_entry(
    result: &mut Map<String, Value>,
    ctx: &Context,
    definition: &TermDefinition,
    item_key: &str,
    map_key: &str,
    value: Value,
    as_array: bool,
) -> Result<(), JsonLdError> {
    let target = nest_target(ctx, result, definition)?;
    let slot = target
        .entry(item_key.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    let map_object = slot.as_object_mut().ok_or_else(|| {
        JsonLdError::InvalidDocument(format!(
            "container map entry `{item_key}` collides with a non-map value"
        ))
    })?;
    add_value(map_object, map_key, value, as_array);
    Ok(())
}
