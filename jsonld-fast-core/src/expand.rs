// Rust guideline compliant 2026-02-21
//! Expansion of JSON-LD documents to expanded form.
//!
//! Implements the JSON-LD 1.1 Expansion Algorithm (API section 5.1.2) over
//! inline contexts: `@id`, `@type` (including `@id`/`@vocab` coercion and
//! `@json` literals), `@language`, `@direction`, `@vocab`, `@base`,
//! `@list`, `@set`, `@graph`, `@reverse`, `@nest`, `@included`, `@index`,
//! index/id/type/language container maps, graph containers, scoped contexts with
//! `@propagate` semantics, compact IRIs, keyword aliasing, and JSON-LD-star
//! embedded `@id` nodes (object-position quoted triples). Keys that do
//! not expand to a keyword, an absolute IRI, or a blank node identifier are
//! dropped, as the spec requires. Refused features abort with typed errors.

use std::{
    collections::{BTreeMap, HashMap},
    rc::Rc,
};

use serde_json::{Map, Value};

use crate::{
    context::{
        Context, DirectionMapping, LanguageMapping, TermDefinition, expand_iri, is_keyword,
        language_shape_is_valid, process_context,
    },
    error::JsonLdError,
    iri::{is_absolute_iri, is_blank_node_id},
    options::JsonLdOptions,
};

/// Expands `document` to expanded form (always a top-level array).
///
/// # Errors
///
/// Returns the typed [`JsonLdError`] raised by context processing, refused
/// features, malformed nodes, or an exceeded resource limit.
pub(crate) fn expand_document(
    document: &Value,
    options: &JsonLdOptions,
    output_budget: usize,
) -> Result<Value, JsonLdError> {
    expand_with_mode(document, options, false, output_budget)
}

/// Expands a frame document (JSON-LD 1.1 Framing section 4.1: expansion
/// with the `frameExpansion` flag set).
///
/// Frame expansion additionally accepts the frame grammar: `@id` and
/// `@type` value patterns (arrays, the `{}` wildcard, the `[]` match-none,
/// and `@type: {"@default": ...}`), value patterns under `@value`,
/// `@language`, and the framing keywords `@default`, `@embed`, `@explicit`,
/// `@omitDefault`, and `@requireAll`. `@reverse` inside a frame expands to
/// the reverse-property map Framing section 2.3 matches against.
///
/// # Errors
///
/// Returns [`JsonLdError::InvalidFrame`] and
/// [`JsonLdError::InvalidEmbedValue`] for frame grammar violations, plus
/// every error regular expansion can raise.
pub(crate) fn expand_frame_document(
    document: &Value,
    options: &JsonLdOptions,
    output_budget: usize,
) -> Result<Value, JsonLdError> {
    expand_with_mode(document, options, true, output_budget)
}

fn expand_with_mode(
    document: &Value,
    options: &JsonLdOptions,
    frame_expansion: bool,
    output_budget: usize,
) -> Result<Value, JsonLdError> {
    // Nesting is bounded by the caller: every public entry point that
    // reaches here (`expand`, `compact`, `to_quads`, `frame`) has already
    // run `guard::check_nesting` on this value and sized its stack.
    let mut ctx = Context {
        base: options.base.clone(),
        ..Context::default()
    };
    let mut expander = Expander {
        options_base: options.base.clone(),
        max_nodes: options.limits.max_nodes,
        max_depth: options.limits.max_depth,
        nodes: 0,
        output_bytes: 0,
        max_output_bytes: output_budget,
        scoped_cache: HashMap::new(),
        frame_expansion,
    };
    let expanded = expander.expand_element(&mut ctx, None, document, 0, false)?;
    let items = match expanded {
        None => Vec::new(),
        Some(Value::Array(items)) => items,
        Some(Value::Object(map)) => {
            // Spec section 5.1.2 step 19: a result holding only @graph
            // unwraps to it.
            if map.len() == 1
                && let Some(Value::Array(graph)) = map.get("@graph")
            {
                graph.clone()
            } else {
                vec![Value::Object(map)]
            }
        }
        Some(other) => vec![other],
    };
    Ok(Value::Array(items))
}

/// Expands `key` in `ctx` with `vocab = true` (no local-context recursion).
fn expand_key(ctx: &mut Context, key: &str) -> Result<Option<String>, JsonLdError> {
    let mut defined = HashMap::new();
    expand_iri(ctx, key, true, false, None, &mut defined)
}

/// Returns `true` when any key of `map` IRI-expands to `keyword`.
fn has_entry_expanding_to(
    ctx: &mut Context,
    map: &Map<String, Value>,
    keyword: &str,
) -> Result<bool, JsonLdError> {
    for key in map.keys() {
        if expand_key(ctx, key)?.as_deref() == Some(keyword) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Returns the working context: the owned override when present, else the
/// parent context.
fn current<'a>(owned: &'a mut Option<Context>, parent: &'a mut Context) -> &'a mut Context {
    match owned {
        Some(ctx) => ctx,
        None => parent,
    }
}

/// Returns `true` when `map` is an expanded graph object (only `@graph`,
/// `@id`, and `@index` entries, with `@graph` present).
fn is_graph_object(map: &Map<String, Value>) -> bool {
    map.contains_key("@graph")
        && map
            .keys()
            .all(|key| matches!(key.as_str(), "@graph" | "@id" | "@index"))
}

/// Returns `true` when `value` is a value object or list object.
fn is_value_or_list_object(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.contains_key("@value") || map.contains_key("@list"))
}

/// Per-object expansion state shared with `@nest` recursion.
#[derive(Debug, Default)]
struct ObjectState {
    /// Expanded entries collected so far.
    result: BTreeMap<String, Value>,
    /// Replacement value produced by a top-level `@set` entry.
    set_value: Option<Value>,
    /// Input type of the object (spec section 5.1.2 step 12): the expansion
    /// of the last value of the first entry expanding to `@type`.
    input_type: Option<String>,
}

struct Expander {
    options_base: Option<String>,
    max_nodes: usize,
    max_depth: usize,
    nodes: usize,
    /// String bytes produced so far (see [`Expander::charge_output`]).
    output_bytes: usize,
    /// Budget for `output_bytes`
    /// ([`crate::JsonLdLimits::max_output_bytes`]).
    max_output_bytes: usize,
    /// Processed scoped contexts of this run (see [`Expander::apply_scoped`]).
    scoped_cache: HashMap<ScopedKey, ScopedEntry>,
    /// Frame-expansion mode (JSON-LD 1.1 Framing): frame value patterns and
    /// framing keywords are accepted and preserved.
    frame_expansion: bool,
}

/// Identity of one scoped-context application: the parent scope's term
/// map, the scoped context, and the two processing flags.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ScopedKey {
    parent_terms: usize,
    local: usize,
    override_protected: bool,
    propagate: bool,
}

/// A cached scoped-context application.
///
/// `parent` and `local` keep the keyed allocations alive, so their
/// addresses cannot be reused by another map or value while the entry
/// exists; `parent` also carries the non-term fields compared on a hit.
#[derive(Debug)]
struct ScopedEntry {
    parent: Context,
    local: Rc<Value>,
    result: Context,
}

/// Most scoped-context applications cached per expansion run: 4,096.
///
/// A document normally applies a handful of distinct scoped contexts to
/// many nodes; the bound only stops a document with ever-new parent scopes
/// from retaining every processed context. When full, the cache is cleared
/// (correctness never depends on a hit).
const SCOPED_CACHE_ENTRIES: usize = 4_096;

/// `true` when two contexts agree on everything but the term map, which
/// the cache key compares by identity.
fn same_scope_fields(left: &Context, right: &Context) -> bool {
    left.vocab == right.vocab
        && left.base == right.base
        && left.default_language == right.default_language
        && left.default_direction == right.default_direction
        && match (&left.previous, &right.previous) {
            (None, None) => true,
            (Some(left), Some(right)) => Rc::ptr_eq(left, right),
            _ => false,
        }
}

/// The framing keywords accepted (only) in frame expansion.
const FRAME_KEYWORDS: &[&str] = &[
    "@default",
    "@embed",
    "@explicit",
    "@omitDefault",
    "@requireAll",
];

impl Expander {
    fn visit(&mut self, depth: usize) -> Result<(), JsonLdError> {
        self.nodes += 1;
        if self.nodes > self.max_nodes {
            return Err(JsonLdError::ResourceLimit {
                resource: crate::error::JsonLdResource::Nodes,
                limit: self.max_nodes,
                observed: self.nodes,
            });
        }
        if depth > self.max_depth {
            return Err(JsonLdError::ResourceLimit {
                resource: crate::error::JsonLdResource::Depth,
                limit: self.max_depth,
                observed: depth,
            });
        }
        Ok(())
    }

    /// Applies the term-scoped context `local` on top of `base`, reusing an
    /// earlier identical application.
    ///
    /// A type- or property-scoped context is applied at every node or
    /// property that uses its term. Reprocessing it each time made `n`
    /// uses of an `n`-term scoped context cost `O(n^2)`; processing is a
    /// pure function of the parent scope, the context, and the flags, so
    /// the result is cached by their identities and shared (`Rc` term
    /// maps make the copy O(1)).
    fn apply_scoped(
        &mut self,
        base: &Context,
        local: &Rc<Value>,
        override_protected: bool,
        propagate: bool,
    ) -> Result<Context, JsonLdError> {
        let key = ScopedKey {
            parent_terms: Rc::as_ptr(&base.terms) as usize,
            local: Rc::as_ptr(local) as usize,
            override_protected,
            propagate,
        };
        if let Some(entry) = self.scoped_cache.get(&key)
            && Rc::ptr_eq(&entry.parent.terms, &base.terms)
            && Rc::ptr_eq(&entry.local, local)
            && same_scope_fields(&entry.parent, base)
        {
            return Ok(entry.result.clone());
        }
        let result = process_context(
            base,
            local,
            self.options_base.as_deref(),
            override_protected,
            propagate,
        )?;
        if self.scoped_cache.len() >= SCOPED_CACHE_ENTRIES {
            self.scoped_cache.clear();
        }
        self.scoped_cache.insert(
            key,
            ScopedEntry {
                parent: base.clone(),
                local: Rc::clone(local),
                result: result.clone(),
            },
        );
        Ok(result)
    }

    /// Charges `bytes` of produced strings to the output budget.
    fn charge_output(&mut self, bytes: usize) -> Result<(), JsonLdError> {
        self.output_bytes = self.output_bytes.saturating_add(bytes);
        if self.output_bytes > self.max_output_bytes {
            return Err(JsonLdError::ResourceLimit {
                resource: crate::error::JsonLdResource::OutputBytes,
                limit: self.max_output_bytes,
                observed: self.output_bytes,
            });
        }
        Ok(())
    }

    /// Charges the strings an expanded object holds directly: its keys,
    /// string values, and strings directly inside its arrays.
    ///
    /// Each object expansion builds is charged once, when it is built;
    /// nested objects were charged when they were built, so they are not
    /// descended into. This covers expanded property IRIs, `@id` and
    /// `@type` IRIs (including `@vocab`/`@base` resolution), and value
    /// objects with their coerced `@type`.
    fn charge_object(&mut self, map: &Map<String, Value>) -> Result<(), JsonLdError> {
        let mut bytes = 0_usize;
        for (key, value) in map {
            bytes = bytes.saturating_add(key.len());
            match value {
                Value::String(text) => bytes = bytes.saturating_add(text.len()),
                Value::Array(items) => {
                    for item in items {
                        if let Value::String(text) = item {
                            bytes = bytes.saturating_add(text.len());
                        }
                    }
                }
                // A `@reverse` map is built here, not by a nested object
                // expansion: its keys (reverse property IRIs) are new
                // strings, while its values were charged when built.
                Value::Object(reverse) if key == "@reverse" => {
                    for property in reverse.keys() {
                        bytes = bytes.saturating_add(property.len());
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => {}
            }
        }
        self.charge_output(bytes)
    }

    /// Charges a value object produced from a scalar.
    fn charge_value(&mut self, value: &Value) -> Result<(), JsonLdError> {
        match value {
            Value::Object(map) => self.charge_object(map),
            Value::String(text) => self.charge_output(text.len()),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) => Ok(()),
        }
    }

    /// Charges a `@json` literal payload to the node and depth budgets.
    ///
    /// Spec step 13.7 copies the value of a `@json`-typed entry verbatim,
    /// without expanding it, so its interior never reaches
    /// [`Self::expand_element`] and never meets [`Self::visit`]. Left
    /// unguarded that is a fail-open hole: the recursive `Clone` performed
    /// here, and the recursive canonicalization performed later by
    /// `json_canon`, would both blow the stack on a deeply nested payload
    /// that the budget was supposed to refuse.
    ///
    /// The walk is iterative (an explicit worklist, never recursion), so
    /// the check itself is safe on exactly the inputs it exists to refuse,
    /// and it runs *before* the clone so an over-budget payload is never
    /// copied.
    fn charge_json_literal(&mut self, value: &Value, depth: usize) -> Result<(), JsonLdError> {
        let mut pending: Vec<(&Value, usize)> = vec![(value, depth)];
        while let Some((node, level)) = pending.pop() {
            self.visit(level)?;
            let child = level.saturating_add(1);
            match node {
                Value::Array(items) => pending.extend(items.iter().map(|item| (item, child))),
                Value::Object(map) => {
                    let keys: usize = map.keys().map(String::len).sum();
                    self.charge_output(keys)?;
                    pending.extend(map.values().map(|item| (item, child)));
                }
                // The payload is copied verbatim: charge its strings too.
                Value::String(text) => self.charge_output(text.len())?,
                Value::Null | Value::Bool(_) | Value::Number(_) => {}
            }
        }
        Ok(())
    }

    fn expand_element(
        &mut self,
        ctx: &mut Context,
        active_property: Option<&str>,
        element: &Value,
        depth: usize,
        from_map: bool,
    ) -> Result<Option<Value>, JsonLdError> {
        self.visit(depth)?;
        let free_floating = matches!(active_property, None | Some("@graph"));
        match element {
            Value::Null => Ok(None),
            Value::Array(items) => {
                let mut expanded = Vec::with_capacity(items.len());
                for item in items {
                    match self.expand_element(ctx, active_property, item, depth + 1, from_map)? {
                        None => {}
                        Some(Value::Array(nested)) => expanded.extend(nested),
                        Some(value) => expanded.push(value),
                    }
                }
                Ok(Some(Value::Array(expanded)))
            }
            Value::Object(map) => {
                let expanded = self.expand_object(ctx, active_property, map, depth, from_map)?;
                if let Some(Value::Object(object)) = &expanded {
                    self.charge_object(object)?;
                }
                Ok(expanded)
            }
            scalar => {
                if free_floating {
                    // Spec section 5.1.2 step 4.1: free-floating scalars drop.
                    return Ok(None);
                }
                let property = active_property.unwrap_or_default();
                // Spec section 5.1.2 step 4.2: apply a property-scoped
                // context before value expansion.
                let scoped = ctx
                    .terms
                    .get(property)
                    .and_then(|definition| definition.local_context.clone());
                if let Some(local) = scoped {
                    let mut scoped_ctx = self.apply_scoped(ctx, &local, true, true)?;
                    let value = expand_value(&mut scoped_ctx, property, scalar)?;
                    self.charge_value(&value)?;
                    return Ok(Some(value));
                }
                let value = expand_value(ctx, property, scalar)?;
                self.charge_value(&value)?;
                Ok(Some(value))
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "mirrors the sequential steps of JSON-LD 1.1 API section 5.1.2"
    )]
    fn expand_object(
        &mut self,
        parent: &mut Context,
        active_property: Option<&str>,
        map: &Map<String, Value>,
        depth: usize,
        from_map: bool,
    ) -> Result<Option<Value>, JsonLdError> {
        // Spec step 3: the property-scoped context comes from the term
        // definition of the active property in the incoming active context.
        let property_scoped = active_property
            .and_then(|property| parent.terms.get(property))
            .and_then(|definition| definition.local_context.clone());

        // Spec step 8: revert a non-propagated context when entering a new
        // node object (not a value object, not a single-@id map, and not an
        // item of a container map expansion).
        let needs_revert = if parent.previous.is_some() && !from_map {
            let has_value = has_entry_expanding_to(parent, map, "@value")?;
            let single_id = map.len() == 1 && has_entry_expanding_to(parent, map, "@id")?;
            !has_value && !single_id
        } else {
            false
        };

        // The working context; cloned into `owned` when any scoped
        // transformation applies, otherwise `parent` is used directly.
        let mut owned: Option<Context> = None;
        if needs_revert {
            let previous = parent.previous.clone().expect("checked above");
            owned = Some((*previous).clone());
        }
        // Spec step 9: property-scoped context, with override protected.
        if let Some(local) = &property_scoped {
            let next = {
                let base = current(&mut owned, parent);
                self.apply_scoped(base, local, true, true)?
            };
            owned = Some(next);
        }
        // Spec step 10: the element's own local context.
        if let Some(local) = map.get("@context") {
            let next = {
                let base = current(&mut owned, parent);
                process_context(base, local, self.options_base.as_deref(), false, true)?
            };
            owned = Some(next);
        }

        // Spec step 12: type-scoped contexts. Collect the string values of
        // every entry expanding to @type, ordered lexicographically.
        let mut type_terms: Vec<String> = Vec::new();
        {
            let ctx = current(&mut owned, parent);
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                if expand_key(ctx, key)?.as_deref() == Some("@type") {
                    let raw = &map[key.as_str()];
                    let values: Vec<&Value> = match raw {
                        Value::Array(items) => items.iter().collect(),
                        other => vec![other],
                    };
                    let mut terms: Vec<&str> =
                        values.iter().filter_map(|value| value.as_str()).collect();
                    terms.sort_unstable();
                    type_terms.extend(terms.iter().map(|term| (*term).to_owned()));
                }
            }
        }
        // Apply the local context of each type term with propagate = false,
        // looking definitions up in the type-scoped snapshot.
        let needs_type_scoped = {
            let ctx = current(&mut owned, parent);
            type_terms.iter().any(|term| {
                ctx.terms
                    .get(term)
                    .is_some_and(|definition| definition.local_context.is_some())
            })
        };
        let mut type_scoped: Option<Context> = None;
        if needs_type_scoped {
            let snapshot = current(&mut owned, parent).clone();
            for term in &type_terms {
                if let Some(local) = snapshot
                    .terms
                    .get(term)
                    .and_then(|definition| definition.local_context.clone())
                {
                    let next = {
                        let base = current(&mut owned, parent);
                        self.apply_scoped(base, &local, false, false)?
                    };
                    owned = Some(next);
                }
            }
            type_scoped = Some(snapshot);
        }

        // Spec step 12 (input type): expansion of the last value of the
        // first entry expanding to @type.
        let mut state = ObjectState::default();
        {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                let expands_to_type = {
                    let ctx = current(&mut owned, parent);
                    expand_key(ctx, key)?.as_deref() == Some("@type")
                };
                if !expands_to_type {
                    continue;
                }
                let raw = &map[key.as_str()];
                let last = match raw {
                    Value::Array(items) => items.last(),
                    other => Some(other),
                };
                if let Some(Value::String(name)) = last {
                    let lookup = match type_scoped.as_mut() {
                        Some(snapshot) => snapshot,
                        None => current(&mut owned, parent),
                    };
                    state.input_type = expand_key(lookup, name)?;
                }
                break;
            }
        }

        {
            let ctx = current(&mut owned, parent);
            self.expand_entries(
                ctx,
                &mut type_scoped,
                active_property,
                map,
                &mut state,
                depth,
            )?;
        }

        let ObjectState {
            result,
            set_value,
            input_type,
        } = state;

        // Spec step 17: a @set (or @list) object may carry at most one other
        // entry, which must be @index; unwrapping @set drops that @index
        // (spec-mandated drop, step 17.2).
        if let Some(set) = set_value {
            if result.keys().any(|key| key != "@index") {
                return Err(JsonLdError::InvalidDocument(
                    "@set cannot be combined with entries other than @index".to_owned(),
                ));
            }
            return Ok(Some(set));
        }

        let free_floating = matches!(active_property, None | Some("@graph"));
        if result.contains_key("@value") {
            if self.frame_expansion {
                // Frame expansion keeps value patterns verbatim; the frame
                // matcher interprets them.
                if free_floating {
                    return Ok(None);
                }
                return Ok(Some(Value::Object(Map::from_iter(result))));
            }
            let value_object = finish_value_object(result, input_type.as_deref())?;
            if free_floating {
                return Ok(None); // Free-floating value objects are dropped.
            }
            return Ok(value_object.map(Value::Object));
        }
        if result.contains_key("@list") {
            if result
                .keys()
                .any(|key| !matches!(key.as_str(), "@list" | "@index"))
            {
                return Err(JsonLdError::InvalidDocument(
                    "@list cannot be combined with entries other than @index".to_owned(),
                ));
            }
            if free_floating {
                return Ok(None); // Free-floating lists are dropped.
            }
        }
        // Fail-closed extension of spec step 13.4.4: `@json` is only
        // meaningful as the @type of a value object; as a node type it can
        // never become an RDF term.
        if let Some(Value::Array(types)) = result.get("@type")
            && types.iter().any(|entry| entry == "@json")
        {
            return Err(JsonLdError::InvalidDocument(
                "@json is not a valid node object @type".to_owned(),
            ));
        }
        // Spec step 18: a map containing only @language is dropped.
        if result.len() == 1 && result.contains_key("@language") {
            return Ok(None);
        }
        if free_floating
            && !self.frame_expansion
            && (result.is_empty() || (result.len() == 1 && result.contains_key("@id")))
        {
            // Spec step 19: free-floating nodes with only @id are dropped
            // — but only when frame expansion is false, since `{"@id": ...}`
            // is a legitimate top-level frame (Framing section 4.2).
            return Ok(None);
        }
        Ok(Some(Value::Object(Map::from_iter(result))))
    }

    /// Runs spec steps 13 and 14 (entry expansion plus `@nest` unfolding)
    /// over `element`, merging into `state`. Recursion happens for nested
    /// maps referenced by keys expanding to `@nest`.
    fn expand_entries(
        &mut self,
        ctx: &mut Context,
        type_scoped: &mut Option<Context>,
        active_property: Option<&str>,
        element: &Map<String, Value>,
        state: &mut ObjectState,
        depth: usize,
    ) -> Result<(), JsonLdError> {
        let mut keys: Vec<&String> = element.keys().filter(|key| *key != "@context").collect();
        keys.sort();
        let mut nests: Vec<&String> = Vec::new();

        for key in keys {
            let value = &element[key.as_str()];
            if self.frame_expansion && FRAME_KEYWORDS.contains(&key.as_str()) {
                self.expand_frame_keyword_entry(ctx, active_property, key, value, state, depth)?;
                continue;
            }
            let Some(expanded_property) = expand_key(ctx, key)? else {
                continue; // Keyword-form non-keywords are dropped per spec.
            };
            if is_keyword(&expanded_property) {
                if expanded_property == "@nest" {
                    // Spec step 13.4.14: collect nesting keys for step 14.
                    nests.push(key);
                    continue;
                }
                self.expand_keyword_entry(
                    ctx,
                    type_scoped,
                    active_property,
                    &expanded_property,
                    value,
                    state,
                    depth,
                )?;
                continue;
            }
            if !expanded_property.contains(':') {
                continue; // Spec step 13.3: unmapped keys are dropped.
            }

            let definition = ctx.terms.get(key.as_str()).cloned().unwrap_or_default();
            let container = definition.container;

            let mut items: Vec<Value>;
            if definition.type_mapping.as_deref() == Some("@json") {
                // Spec step 13.7: values of @json-typed terms become JSON
                // literals verbatim, without recursion. The payload is
                // still charged to the budgets first: the verbatim copy
                // below is a recursive `Clone`, so an unbudgeted payload
                // would overflow the stack here rather than fail closed.
                self.charge_json_literal(value, depth.saturating_add(1))?;
                items = vec![Value::Object(Map::from_iter([
                    ("@value".to_owned(), value.clone()),
                    ("@type".to_owned(), Value::String("@json".to_owned())),
                ]))];
            } else if container.language && value.is_object() {
                let value_map = value.as_object().expect("checked is_object");
                items = expand_language_map(key, value_map)?;
            } else if container.is_map_container() && value.is_object() {
                let value_map = value.as_object().expect("checked is_object");
                items = self.expand_map_container(ctx, key, &definition, value_map, depth)?;
            } else {
                let expanded_value =
                    self.expand_element(ctx, Some(key), value, depth + 1, false)?;
                items = match expanded_value {
                    None => continue,
                    Some(Value::Array(items)) => items,
                    Some(single) => vec![single],
                };
                // Spec step 13.10: wrap in a list object.
                if container.list && !(items.len() == 1 && items[0].get("@list").is_some()) {
                    items = vec![Value::Object(Map::from_iter([(
                        "@list".to_owned(),
                        Value::Array(items),
                    )]))];
                }
                // Spec step 13.11: a @graph container (without @id/@index)
                // wraps every value in a graph object, unconditionally.
                if container.graph && !container.id && !container.index {
                    items = items
                        .into_iter()
                        .map(|item| {
                            Value::Object(Map::from_iter([(
                                "@graph".to_owned(),
                                Value::Array(vec![item]),
                            )]))
                        })
                        .collect();
                }
            }

            if definition.reverse {
                // Spec step 13.13: reverse property values must be node
                // objects.
                for item in &items {
                    if is_value_or_list_object(item) {
                        return Err(JsonLdError::InvalidDocument(format!(
                            "invalid reverse property value on `{key}`"
                        )));
                    }
                }
                add_reverse_items(&mut state.result, &expanded_property, items);
            } else {
                let slot = state
                    .result
                    .entry(expanded_property)
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(existing) = slot {
                    existing.extend(items);
                }
            }
        }

        // Spec step 14: unfold nested values.
        for nest_key in nests {
            let nested_values: Vec<&Value> = match &element[nest_key.as_str()] {
                Value::Array(items) => items.iter().collect(),
                other => vec![other],
            };
            for nested_value in nested_values {
                let Value::Object(nested_map) = nested_value else {
                    return Err(JsonLdError::InvalidDocument(
                        "@nest values must be node objects".to_owned(),
                    ));
                };
                if has_entry_expanding_to(ctx, nested_map, "@value")? {
                    return Err(JsonLdError::InvalidDocument(
                        "@nest values must not contain @value entries".to_owned(),
                    ));
                }
                self.visit(depth + 1)?;
                self.expand_entries(
                    ctx,
                    type_scoped,
                    active_property,
                    nested_map,
                    state,
                    depth + 1,
                )?;
            }
        }
        Ok(())
    }

    /// Expands one framing keyword entry (frame expansion only).
    ///
    /// `@default` values expand with the current active property (`null`
    /// survives as `"@null"` per the Framing spec); `@embed` accepts
    /// `@once`/`@always`/`@never` and booleans; the flag keywords require
    /// booleans.
    fn expand_frame_keyword_entry(
        &mut self,
        ctx: &mut Context,
        active_property: Option<&str>,
        keyword: &str,
        value: &Value,
        state: &mut ObjectState,
        depth: usize,
    ) -> Result<(), JsonLdError> {
        if state.result.contains_key(keyword) {
            return Err(JsonLdError::InvalidDocument(format!(
                "colliding keyword `{keyword}`"
            )));
        }
        match keyword {
            "@default" => {
                let items = match value {
                    Value::Null => vec![Value::String("@null".to_owned())],
                    other => {
                        match self.expand_element(ctx, active_property, other, depth + 1, false)? {
                            None => vec![Value::String("@null".to_owned())],
                            Some(Value::Array(items)) => items,
                            Some(single) => vec![single],
                        }
                    }
                };
                state
                    .result
                    .insert("@default".to_owned(), Value::Array(items));
            }
            "@embed" => {
                let valid = matches!(value, Value::Bool(_))
                    || matches!(
                        value,
                        Value::String(text)
                            if matches!(text.as_str(), "@once" | "@always" | "@never")
                    );
                if !valid {
                    return Err(JsonLdError::InvalidEmbedValue {
                        value: value.to_string(),
                    });
                }
                state.result.insert("@embed".to_owned(), value.clone());
            }
            "@explicit" | "@omitDefault" | "@requireAll" => {
                if !value.is_boolean() {
                    return Err(JsonLdError::InvalidFrame(format!(
                        "`{keyword}` must be a boolean"
                    )));
                }
                state.result.insert(keyword.to_owned(), value.clone());
            }
            other => {
                return Err(JsonLdError::InvalidFrame(format!(
                    "`{other}` is not a framing keyword"
                )));
            }
        }
        Ok(())
    }

    /// Expands one index/id/type container map (spec step 13.8).
    fn expand_map_container(
        &mut self,
        ctx: &mut Context,
        key: &str,
        definition: &TermDefinition,
        value: &Map<String, Value>,
        depth: usize,
    ) -> Result<Vec<Value>, JsonLdError> {
        let container = definition.container;
        let mut expanded_value: Vec<Value> = Vec::new();
        let mut index_keys: Vec<&String> = value.keys().collect();
        index_keys.sort();
        for index in index_keys {
            // Spec step 13.8.3.1-2: @id and @type maps start from the
            // previous context when one exists; @type maps additionally
            // apply the index term's local context.
            let mut owned_map_ctx: Option<Context> = None;
            if (container.id || container.type_)
                && let Some(previous) = &ctx.previous
            {
                owned_map_ctx = Some((**previous).clone());
            }
            if container.type_ {
                let local = {
                    let lookup = current(&mut owned_map_ctx, ctx);
                    lookup
                        .terms
                        .get(index.as_str())
                        .and_then(|definition| definition.local_context.clone())
                };
                if let Some(local) = local {
                    let next = {
                        let base = current(&mut owned_map_ctx, ctx);
                        self.apply_scoped(base, &local, false, true)?
                    };
                    owned_map_ctx = Some(next);
                }
            }
            let map_ctx = current(&mut owned_map_ctx, ctx);
            let expanded_index = expand_key(map_ctx, index)?;
            let is_none_index = expanded_index.as_deref() == Some("@none");
            // Document-relative form, used when an @id map supplies the @id.
            let document_relative_index = {
                let mut defined = HashMap::new();
                expand_iri(map_ctx, index, false, true, None, &mut defined)?
            };
            let index_items = match self.expand_element(
                map_ctx,
                Some(key),
                &value[index.as_str()],
                depth + 1,
                true,
            )? {
                None => continue,
                Some(Value::Array(items)) => items,
                Some(single) => vec![single],
            };
            for mut item in index_items {
                // Spec step 13.8.3.7.1: inside @id/@index maps combined with
                // @graph, items become graph objects unless they already are.
                if container.graph && !item.as_object().is_some_and(is_graph_object) {
                    self.charge_output("@graph".len())?;
                    item = Value::Object(Map::from_iter([(
                        "@graph".to_owned(),
                        Value::Array(vec![item]),
                    )]));
                }
                let Value::Object(object) = &mut item else {
                    return Err(JsonLdError::InvalidDocument(format!(
                        "container map entries of `{key}` must expand to objects"
                    )));
                };
                if container.index {
                    // Spec step 13.8.3.7.4: annotate with the map key, or
                    // with the index-mapping property (section 4.6.1.1).
                    if !is_none_index && !object.contains_key("@index") {
                        if let Some(index_iri) = &definition.index {
                            // The item was charged when it was expanded: the
                            // index property IRI (a key) and the copied map
                            // key (its value) are new strings.
                            self.charge_output(
                                index_iri
                                    .len()
                                    .saturating_add("@value".len())
                                    .saturating_add(index.len()),
                            )?;
                            let index_value = Value::Object(Map::from_iter([(
                                "@value".to_owned(),
                                Value::String(index.clone()),
                            )]));
                            let slot = object
                                .entry(index_iri.clone())
                                .or_insert_with(|| Value::Array(Vec::new()));
                            if let Value::Array(existing) = slot {
                                existing.push(index_value);
                            }
                        } else {
                            self.charge_output("@index".len().saturating_add(index.len()))?;
                            object.insert("@index".to_owned(), Value::String(index.clone()));
                        }
                    }
                } else if container.id {
                    // Fail-closed extension: the spec would attach @id to a
                    // value object here, producing output that is invalid
                    // downstream; reject it with a diagnostic instead.
                    if object.contains_key("@value") || object.contains_key("@list") {
                        return Err(JsonLdError::InvalidDocument(format!(
                            "@id map entries of `{key}` must be node objects"
                        )));
                    }
                    // Spec step 13.8.3.7.5: supply the @id from the map key.
                    if !is_none_index && !object.contains_key("@id") {
                        let id = document_relative_index
                            .clone()
                            .unwrap_or_else(|| index.clone());
                        // The map key expands (through a prefix, say) to an
                        // `@id` the already-charged item did not hold.
                        self.charge_output("@id".len().saturating_add(id.len()))?;
                        object.insert("@id".to_owned(), Value::String(id));
                    }
                } else if container.type_ && !is_none_index {
                    if object.contains_key("@value") || object.contains_key("@list") {
                        return Err(JsonLdError::InvalidDocument(format!(
                            "@type map entries of `{key}` must be node objects"
                        )));
                    }
                    // Spec step 13.8.3.7.6: prepend the map key to @type.
                    let expanded = expanded_index.clone().unwrap_or_else(|| index.clone());
                    // The item was charged when it was expanded; the type
                    // prepended from the map key is a new string.
                    self.charge_output(expanded.len())?;
                    let mut types = vec![Value::String(expanded)];
                    match object.remove("@type") {
                        Some(Value::Array(existing)) => types.extend(existing),
                        Some(single) => types.push(single),
                        None => {}
                    }
                    object.insert("@type".to_owned(), Value::Array(types));
                }
                expanded_value.push(item);
            }
        }
        Ok(expanded_value)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "keyword dispatch shares the expansion state of one object"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "one match arm per JSON-LD keyword, mirroring spec step 13.4"
    )]
    fn expand_keyword_entry(
        &mut self,
        ctx: &mut Context,
        type_scoped: &mut Option<Context>,
        active_property: Option<&str>,
        keyword: &str,
        value: &Value,
        state: &mut ObjectState,
        depth: usize,
    ) -> Result<(), JsonLdError> {
        // Spec step 13.4.1: keywords are invalid inside a reverse map.
        if active_property == Some("@reverse") {
            return Err(JsonLdError::InvalidDocument(format!(
                "invalid reverse property map: keyword `{keyword}` inside @reverse"
            )));
        }
        // Spec step 13.4.2: colliding keywords (except @included and @type,
        // which merge).
        let collides = match keyword {
            "@included" | "@type" | "@annotation" => false,
            "@set" => state.set_value.is_some(),
            other => state.result.contains_key(other),
        };
        if collides {
            return Err(JsonLdError::InvalidDocument(format!(
                "colliding keyword `{keyword}`"
            )));
        }
        match keyword {
            "@id" => {
                if let Value::Object(map) = value
                    && !(self.frame_expansion && map.is_empty())
                {
                    // JSON-LD-star: `@id` may be an embedded node describing
                    // exactly one relationship. Frame expansion still uses
                    // `{}` as the wildcard (empty object).
                    let expanded = self.expand_element(ctx, None, value, depth + 1, false)?;
                    let Some(Value::Object(embedded)) = expanded else {
                        return Err(JsonLdError::InvalidDocument(
                            "an embedded @id must expand to a node object".to_owned(),
                        ));
                    };
                    validate_embedded_node(&embedded)?;
                    state
                        .result
                        .insert("@id".to_owned(), Value::Object(embedded));
                    return Ok(());
                }
                if self.frame_expansion && !value.is_string() {
                    // Framing section 4.1: @id patterns are arrays of IRIs
                    // or the {} wildcard.
                    let expanded = match value {
                        Value::Object(map) if map.is_empty() => {
                            vec![Value::Object(Map::new())]
                        }
                        Value::Array(items) => {
                            let mut expanded = Vec::with_capacity(items.len());
                            for item in items {
                                let Value::String(id) = item else {
                                    return Err(JsonLdError::InvalidFrame(
                                        "@id patterns must be IRI strings".to_owned(),
                                    ));
                                };
                                let mut defined = HashMap::new();
                                let iri = expand_iri(ctx, id, false, true, None, &mut defined)?
                                    .ok_or_else(|| {
                                        JsonLdError::InvalidFrame(format!("invalid @id `{id}`"))
                                    })?;
                                expanded.push(Value::String(iri));
                            }
                            expanded
                        }
                        _ => {
                            return Err(JsonLdError::InvalidFrame(
                                "@id in a frame must be a string, an array of strings, or {}"
                                    .to_owned(),
                            ));
                        }
                    };
                    state
                        .result
                        .insert("@id".to_owned(), Value::Array(expanded));
                    return Ok(());
                }
                let Value::String(id) = value else {
                    return Err(JsonLdError::InvalidDocument(
                        "@id must be a string or an embedded node".to_owned(),
                    ));
                };
                let mut defined = HashMap::new();
                let expanded = expand_iri(ctx, id, false, true, None, &mut defined)?
                    .ok_or_else(|| JsonLdError::InvalidDocument(format!("invalid @id `{id}`")))?;
                state
                    .result
                    .insert("@id".to_owned(), Value::String(expanded));
            }
            "@type" => {
                if self.frame_expansion
                    && let Value::Object(map) = value
                {
                    // Framing section 4.1: @type patterns may be the {}
                    // wildcard or a {"@default": ...} pattern.
                    let is_default = map.len() == 1 && map.contains_key("@default");
                    if !map.is_empty() && !is_default {
                        return Err(JsonLdError::InvalidFrame(
                            "a @type frame pattern must be {} or {\"@default\": ...}".to_owned(),
                        ));
                    }
                    state.result.insert(
                        "@type".to_owned(),
                        Value::Array(vec![Value::Object(map.clone())]),
                    );
                    return Ok(());
                }
                let raw: Vec<&Value> = match value {
                    Value::Array(items) => items.iter().collect(),
                    other => vec![other],
                };
                let mut types = match state.result.remove("@type") {
                    Some(Value::Array(existing)) => existing,
                    _ => Vec::new(),
                };
                for entry in raw {
                    let Value::String(name) = entry else {
                        return Err(JsonLdError::InvalidDocument(
                            "@type values must be strings".to_owned(),
                        ));
                    };
                    // Spec step 13.4.4: @type values expand against the
                    // type-scoped context, document-relative.
                    let lookup = match type_scoped.as_mut() {
                        Some(snapshot) => snapshot,
                        None => &mut *ctx,
                    };
                    let mut defined = HashMap::new();
                    let expanded = expand_iri(lookup, name, true, true, None, &mut defined)?
                        .ok_or_else(|| {
                            JsonLdError::InvalidDocument(format!("invalid @type `{name}`"))
                        })?;
                    types.push(Value::String(expanded));
                }
                state.result.insert("@type".to_owned(), Value::Array(types));
            }
            "@graph" => {
                let expanded = self.expand_element(ctx, Some("@graph"), value, depth + 1, false)?;
                let items = match expanded {
                    None => Vec::new(),
                    Some(Value::Array(items)) => items,
                    Some(single) => vec![single],
                };
                state
                    .result
                    .insert("@graph".to_owned(), Value::Array(items));
            }
            "@included" => {
                // Spec step 13.4.7: expanded with a null active property;
                // every element must be a node object.
                let expanded = self.expand_element(ctx, None, value, depth + 1, false)?;
                let items = match expanded {
                    None => Vec::new(),
                    Some(Value::Array(items)) => items,
                    Some(single) => vec![single],
                };
                // Fail-closed extension: the spec silently drops free-floating
                // scalars inside @included; an @included entry whose content
                // vanished entirely is rejected instead.
                let input_empty = match value {
                    Value::Null => true,
                    Value::Array(entries) => entries.is_empty(),
                    _ => false,
                };
                let dropped_everything = items.is_empty() && !input_empty;
                let is_node_object = |item: &Value| {
                    item.as_object().is_some_and(|map| {
                        !map.contains_key("@value") && !map.contains_key("@list")
                    })
                };
                if dropped_everything || !items.iter().all(is_node_object) {
                    return Err(JsonLdError::InvalidDocument(
                        "@included values must be node objects".to_owned(),
                    ));
                }
                let slot = state
                    .result
                    .entry("@included".to_owned())
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(existing) = slot {
                    existing.extend(items);
                }
            }
            "@annotation" => {
                // JSON-LD-star: annotations expand like `@included` (an
                // array of node objects). Forward annotations need a
                // quoted-triple subject and are refused at toRdf; reverse
                // annotations are object-position and emit.
                let expanded = self.expand_element(ctx, None, value, depth + 1, false)?;
                let items = match expanded {
                    None => Vec::new(),
                    Some(Value::Array(items)) => items,
                    Some(single) => vec![single],
                };
                let is_node_object = |item: &Value| {
                    item.as_object().is_some_and(|map| {
                        !map.contains_key("@value") && !map.contains_key("@list")
                    })
                };
                if !items.iter().all(is_node_object) {
                    return Err(JsonLdError::InvalidDocument(
                        "@annotation values must be node objects".to_owned(),
                    ));
                }
                let slot = state
                    .result
                    .entry("@annotation".to_owned())
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(existing) = slot {
                    existing.extend(items);
                }
            }
            "@value" => {
                // Spec step 13.4.8: when the input type is @json, @value
                // accepts any JSON value; otherwise only scalars and null.
                // Frame expansion additionally accepts value patterns:
                // arrays of scalars, the {} wildcard, and the [] match-none.
                if state.input_type.as_deref() == Some("@json") {
                    // An already-expanded document reaches the JSON literal
                    // through this branch instead of step 13.7, so the same
                    // budget charge applies before the verbatim clone.
                    self.charge_json_literal(value, depth.saturating_add(1))?;
                } else {
                    let is_scalar = |entry: &Value| {
                        matches!(
                            entry,
                            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
                        )
                    };
                    let valid = match value {
                        entry if is_scalar(entry) => true,
                        Value::Array(items) if self.frame_expansion => items.iter().all(is_scalar),
                        Value::Object(map) if self.frame_expansion => map.is_empty(),
                        _ => false,
                    };
                    if !valid {
                        return Err(JsonLdError::InvalidDocument(
                            "@value must be a scalar or null".to_owned(),
                        ));
                    }
                }
                state.result.insert("@value".to_owned(), value.clone());
            }
            "@language" => {
                if self.frame_expansion && !value.is_string() {
                    // Framing: @language patterns are arrays of tags, the
                    // {} wildcard, or the [] match-none.
                    let valid = match value {
                        Value::Array(items) => items
                            .iter()
                            .all(|item| item.as_str().is_some_and(language_shape_is_valid)),
                        Value::Object(map) => map.is_empty(),
                        _ => false,
                    };
                    if !valid {
                        return Err(JsonLdError::InvalidFrame(
                            "a @language pattern must hold well-formed tags".to_owned(),
                        ));
                    }
                    state.result.insert("@language".to_owned(), value.clone());
                    return Ok(());
                }
                let Value::String(tag) = value else {
                    return Err(JsonLdError::InvalidDocument(
                        "@language must be a string".to_owned(),
                    ));
                };
                if !language_shape_is_valid(tag) {
                    return Err(JsonLdError::InvalidDocument(format!(
                        "malformed language tag `{tag}`"
                    )));
                }
                state
                    .result
                    .insert("@language".to_owned(), Value::String(tag.clone()));
            }
            "@direction" => {
                // Spec step 13.4.10: only "ltr" and "rtl" are valid.
                let valid = matches!(value, Value::String(text) if text == "ltr" || text == "rtl");
                if !valid {
                    return Err(JsonLdError::InvalidDocument(
                        "@direction must be \"ltr\" or \"rtl\"".to_owned(),
                    ));
                }
                state.result.insert("@direction".to_owned(), value.clone());
            }
            "@index" => {
                // Spec step 13.4.11: @index values must be strings.
                let Value::String(index) = value else {
                    return Err(JsonLdError::InvalidDocument(
                        "@index must be a string".to_owned(),
                    ));
                };
                state
                    .result
                    .insert("@index".to_owned(), Value::String(index.clone()));
            }
            "@list" => {
                let expanded =
                    self.expand_element(ctx, active_property, value, depth + 1, false)?;
                let items = match expanded {
                    None => Vec::new(),
                    Some(Value::Array(items)) => items,
                    Some(single) => vec![single],
                };
                state.result.insert("@list".to_owned(), Value::Array(items));
            }
            "@set" => {
                let expanded =
                    self.expand_element(ctx, active_property, value, depth + 1, false)?;
                state.set_value = Some(match expanded {
                    None => Value::Array(Vec::new()),
                    Some(Value::Array(items)) => Value::Array(items),
                    Some(single) => Value::Array(vec![single]),
                });
            }
            "@reverse" => {
                // Spec step 13.4.13: the value is expanded with @reverse as
                // the active property; double-reversed entries become
                // forward properties. Frame expansion uses the same path so
                // Framing section 2.3 can match the reverse-property map.
                let Value::Object(_) = value else {
                    return Err(JsonLdError::InvalidDocument(
                        "@reverse must be a map".to_owned(),
                    ));
                };
                let expanded =
                    self.expand_element(ctx, Some("@reverse"), value, depth + 1, false)?;
                let Some(Value::Object(expanded_map)) = expanded else {
                    return Ok(());
                };
                for (property, items) in &expanded_map {
                    let items: Vec<Value> = match items {
                        Value::Array(items) => items.clone(),
                        other => vec![other.clone()],
                    };
                    if property == "@reverse" {
                        // Double reverse: forward properties.
                        for (inner_property, inner_items) in
                            items.iter().filter_map(Value::as_object).flatten()
                        {
                            let inner: Vec<Value> = match inner_items {
                                Value::Array(values) => values.clone(),
                                other => vec![other.clone()],
                            };
                            let slot = state
                                .result
                                .entry(inner_property.clone())
                                .or_insert_with(|| Value::Array(Vec::new()));
                            if let Value::Array(existing) = slot {
                                existing.extend(inner);
                            }
                        }
                        continue;
                    }
                    for item in &items {
                        if is_value_or_list_object(item) {
                            return Err(JsonLdError::InvalidDocument(format!(
                                "invalid reverse property value on `{property}`"
                            )));
                        }
                    }
                    add_reverse_items(&mut state.result, property, items);
                }
            }
            other => {
                return Err(JsonLdError::InvalidDocument(format!(
                    "keyword `{other}` is not valid in this position"
                )));
            }
        }
        Ok(())
    }
}

/// Expands one language-map value (spec step 13.8, `@container: @language`).
fn expand_language_map(key: &str, value: &Map<String, Value>) -> Result<Vec<Value>, JsonLdError> {
    let mut expanded_value: Vec<Value> = Vec::new();
    let mut languages: Vec<&String> = value.keys().collect();
    languages.sort();
    for language in languages {
        let is_none = language.as_str() == "@none";
        if !is_none && !language_shape_is_valid(language) {
            return Err(JsonLdError::InvalidDocument(format!(
                "malformed language tag `{language}`"
            )));
        }
        let items: Vec<&Value> = match &value[language.as_str()] {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        for item in items {
            match item {
                Value::String(text) => {
                    let mut object = Map::new();
                    object.insert("@value".to_owned(), Value::String(text.clone()));
                    if !is_none {
                        object.insert(
                            "@language".to_owned(),
                            Value::String(language.to_lowercase()),
                        );
                    }
                    expanded_value.push(Value::Object(object));
                }
                Value::Object(map) if map.contains_key("@value") => {
                    let mut object = map.clone();
                    if !is_none && !object.contains_key("@language") {
                        object.insert(
                            "@language".to_owned(),
                            Value::String(language.to_lowercase()),
                        );
                    }
                    expanded_value.push(Value::Object(object));
                }
                _ => {
                    return Err(JsonLdError::InvalidDocument(format!(
                        "language map values of `{key}` must be strings or value objects"
                    )));
                }
            }
        }
    }
    Ok(expanded_value)
}

/// Adds `items` under `property` inside the `@reverse` map of `result`.
fn add_reverse_items(result: &mut BTreeMap<String, Value>, property: &str, items: Vec<Value>) {
    let reverse = result
        .entry("@reverse".to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(reverse_map) = reverse {
        let slot = reverse_map
            .entry(property.to_owned())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(existing) = slot {
            existing.extend(items);
        }
    }
}

/// Applies the value expansion algorithm (spec section 5.3.2) to one scalar.
fn expand_value(
    ctx: &mut Context,
    active_property: &str,
    scalar: &Value,
) -> Result<Value, JsonLdError> {
    let definition: TermDefinition = ctx.terms.get(active_property).cloned().unwrap_or_default();
    if let Value::String(text) = scalar {
        let mut defined = HashMap::new();
        match definition.type_mapping.as_deref() {
            Some("@id") => {
                let expanded = expand_iri(ctx, text, false, true, None, &mut defined)?
                    .unwrap_or_else(|| text.clone());
                return Ok(Value::Object(Map::from_iter([(
                    "@id".to_owned(),
                    Value::String(expanded),
                )])));
            }
            Some("@vocab") => {
                let expanded = expand_iri(ctx, text, true, true, None, &mut defined)?
                    .unwrap_or_else(|| text.clone());
                return Ok(Value::Object(Map::from_iter([(
                    "@id".to_owned(),
                    Value::String(expanded),
                )])));
            }
            _ => {}
        }
    }
    let mut object = Map::new();
    object.insert("@value".to_owned(), scalar.clone());
    match definition.type_mapping.as_deref() {
        Some("@id" | "@vocab") | None => {
            if scalar.is_string() {
                let language = match &definition.language {
                    LanguageMapping::Tag(tag) => Some(tag.clone()),
                    LanguageMapping::Null => None,
                    LanguageMapping::Unset => ctx.default_language.clone(),
                };
                if let Some(tag) = language {
                    object.insert("@language".to_owned(), Value::String(tag));
                }
                // Spec section 5.3.2 step 5: the direction mapping falls
                // back to the default base direction.
                let direction = match definition.direction {
                    DirectionMapping::Fixed(direction) => Some(direction),
                    DirectionMapping::Null => None,
                    DirectionMapping::Unset => ctx.default_direction,
                };
                if let Some(direction) = direction {
                    object.insert(
                        "@direction".to_owned(),
                        Value::String(direction.as_str().to_owned()),
                    );
                }
            }
        }
        Some(datatype) => {
            object.insert("@type".to_owned(), Value::String(datatype.to_owned()));
        }
    }
    Ok(Value::Object(object))
}

/// Validates and normalizes an expanded value object (spec step 15).
fn finish_value_object(
    mut result: BTreeMap<String, Value>,
    input_type: Option<&str>,
) -> Result<Option<Map<String, Value>>, JsonLdError> {
    for key in result.keys() {
        if !matches!(
            key.as_str(),
            "@value" | "@type" | "@language" | "@direction" | "@index" | "@annotation"
        ) {
            return Err(JsonLdError::InvalidDocument(format!(
                "`{key}` is not valid inside a value object"
            )));
        }
    }
    if result.contains_key("@type")
        && (result.contains_key("@language") || result.contains_key("@direction"))
    {
        return Err(JsonLdError::InvalidDocument(
            "a value object cannot carry both @type and @language/@direction".to_owned(),
        ));
    }
    let mut is_json_literal = input_type == Some("@json");
    if let Some(types) = result.remove("@type") {
        let single = match &types {
            Value::Array(items) if items.len() == 1 => items[0].as_str(),
            _ => None,
        };
        let Some(datatype) = single else {
            return Err(JsonLdError::InvalidDocument(
                "the @type of a value object must be a single string".to_owned(),
            ));
        };
        if datatype == "@json" {
            is_json_literal = true;
        } else if !(is_absolute_iri(datatype) || is_blank_node_id(datatype)) {
            return Err(JsonLdError::InvalidDocument(format!(
                "value object @type `{datatype}` is not an absolute IRI"
            )));
        }
        result.insert("@type".to_owned(), Value::String(datatype.to_owned()));
    }
    if is_json_literal {
        // Spec step 15.2: with @type @json the @value may be any JSON value
        // and is treated as a JSON literal.
        return Ok(Some(Map::from_iter(result)));
    }
    match result.get("@value") {
        Some(Value::Null) => return Ok(None),
        Some(Value::String(_)) => {}
        Some(_) if result.contains_key("@language") || result.contains_key("@direction") => {
            return Err(JsonLdError::InvalidDocument(
                "@language and @direction require a string @value".to_owned(),
            ));
        }
        Some(_) => {}
        None => unreachable!("finish_value_object is only called with @value present"),
    }
    Ok(Some(Map::from_iter(result)))
}

/// JSON-LD-star: an embedded node (the object value of `@id`) describes
/// exactly one relationship — `@type` xor one IRI property — and must not
/// carry `@graph` or `@included`.
fn validate_embedded_node(map: &Map<String, Value>) -> Result<(), JsonLdError> {
    if map.contains_key("@graph") || map.contains_key("@included") {
        return Err(JsonLdError::InvalidDocument(
            "an embedded node cannot contain @graph or @included".to_owned(),
        ));
    }
    if !map.contains_key("@id") {
        return Err(JsonLdError::InvalidDocument(
            "an embedded node must have an @id".to_owned(),
        ));
    }
    let mut relationships = 0usize;
    if map.contains_key("@type") {
        let Some(Value::Array(types)) = map.get("@type") else {
            return Err(JsonLdError::InvalidDocument(
                "an embedded node @type must be an array".to_owned(),
            ));
        };
        if types.len() != 1 {
            return Err(JsonLdError::InvalidDocument(
                "an embedded node must describe exactly one relationship".to_owned(),
            ));
        }
        relationships += 1;
    }
    for (key, value) in map {
        if key.starts_with('@') {
            continue;
        }
        let Value::Array(items) = value else {
            return Err(JsonLdError::InvalidDocument(format!(
                "expanded property `{key}` must hold an array"
            )));
        };
        if items.len() != 1 {
            return Err(JsonLdError::InvalidDocument(
                "an embedded node must describe exactly one relationship".to_owned(),
            ));
        }
        relationships += 1;
    }
    if relationships != 1 {
        return Err(JsonLdError::InvalidDocument(
            "an embedded node must describe exactly one relationship".to_owned(),
        ));
    }
    Ok(())
}
