// Rust guideline compliant 2026-02-21
//! Serialization of `UnsignedQuadStream` batches to expanded JSON-LD.
//!
//! Produces a deterministic expanded-form document: nodes sorted by `@id`,
//! predicates sorted, named graphs grouped under `@graph` on the node whose
//! `@id` is the graph name. Well-formed `rdf:first`/`rdf:rest` chains are
//! reassembled into `@list` arrays (JSON-LD 1.1 API section 8.4); malformed
//! chains stay as regular triples so nothing is dropped. Object-position
//! RDF 1.2 triple terms become JSON-LD-star embedded `@id` nodes.
//!
//! Two literal datatypes decode specially, mirroring the encode side
//! (JSON-LD 1.1 API section 8.5.2): `rdf:JSON` literals parse back into
//! `@type: @json` value objects (a malformed lexical form is the spec's
//! *invalid JSON literal* error, surfaced as
//! [`JsonLdError::InvalidTerm`]), and `https://www.w3.org/ns/i18n#`
//! datatypes decode into `@language`/`@direction` entries
//! (`rdfDirection: i18n-datatype`); an i18n datatype without a valid
//! `<language>_<direction>` fragment fails closed.

use std::collections::{BTreeMap, HashMap, HashSet};

use arrow_array::RecordBatch;
use oxrdf::{GraphNameRef, NamedOrBlankNodeRef, TermRef, Triple};
use quad_fast_core::{QuadLimits, QuadStreamReader};
use serde_json::{Map, Value};

use crate::{
    error::{JsonLdError, JsonLdResource},
    options::JsonLdLimits,
    to_rdf::{I18N_NAMESPACE, RDF_FIRST, RDF_JSON, RDF_NIL, RDF_REST, RDF_TYPE, XSD_STRING},
};

/// `rdf:List` class IRI. A list node may carry this type and still convert.
const RDF_LIST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#List";

/// Accumulated state of one output node.
#[derive(Debug, Default)]
struct NodeAcc {
    types: Vec<String>,
    properties: BTreeMap<String, Vec<Value>>,
}

/// Converts validated quad batches to one expanded JSON-LD document.
///
/// # Errors
///
/// Returns [`JsonLdError::Quad`] when a batch fails `UnsignedQuadStream`
/// contract validation or a row does not decode to a valid quad, and the
/// list budgets of `limits` described on [`reassemble_lists`].
pub(crate) fn quads_to_expanded(
    batches: &[RecordBatch],
    limits: &JsonLdLimits,
) -> Result<Value, JsonLdError> {
    // Graph key `None` is the default graph.
    let mut graphs: BTreeMap<Option<String>, BTreeMap<String, NodeAcc>> = BTreeMap::new();
    for batch in batches {
        let reader = QuadStreamReader::new(batch)?;
        // Triple terms cannot borrow from Arrow buffers; use the owned
        // path for those batches and keep the zero-copy path otherwise.
        let owned_triples = reader.contains_triple_terms();
        for row in 0..reader.len() {
            let owned = if owned_triples {
                reader.quad_owned(row, QuadLimits::default())?
            } else {
                reader.quad(row)?.into_owned()
            };
            let quad = owned.as_ref();
            let graph_key = match quad.graph_name {
                GraphNameRef::DefaultGraph => None,
                GraphNameRef::NamedNode(named) => Some(named.as_str().to_owned()),
                GraphNameRef::BlankNode(blank) => Some(format!("_:{}", blank.as_str())),
            };
            let subject_id = subject_to_id(quad.subject);
            let node = graphs
                .entry(graph_key)
                .or_default()
                .entry(subject_id)
                .or_default();
            let predicate = quad.predicate.as_str();
            if predicate == RDF_TYPE
                && let TermRef::NamedNode(type_iri) = quad.object
            {
                let type_id = type_iri.as_str().to_owned();
                if !node.types.contains(&type_id) {
                    node.types.push(type_id);
                }
                continue;
            }
            let object = object_to_json(quad.object)?;
            let values = node.properties.entry(predicate.to_owned()).or_default();
            if !values.contains(&object) {
                values.push(object);
            }
        }
    }

    let mut default_nodes = graphs.remove(&None).unwrap_or_default();
    let mut budget = ListBudget::new(limits);
    reassemble_lists(&mut default_nodes, &mut budget)?;
    // Every named graph needs a carrier node in the default graph.
    let named_graph_names: Vec<String> = graphs.keys().flatten().cloned().collect();
    for name in &named_graph_names {
        default_nodes.entry(name.clone()).or_default();
    }
    for graph_nodes in graphs.values_mut() {
        reassemble_lists(graph_nodes, &mut budget)?;
    }

    let mut output = Vec::with_capacity(default_nodes.len());
    for (id, node) in &default_nodes {
        let mut rendered = render_node(id, node);
        if let Some(graph_nodes) = graphs.get(&Some(id.clone())) {
            let rendered_graph: Vec<Value> = graph_nodes
                .iter()
                .map(|(inner_id, inner)| render_node(inner_id, inner))
                .collect();
            if let Value::Object(map) = &mut rendered {
                map.insert("@graph".to_owned(), Value::Array(rendered_graph));
            }
        }
        output.push(rendered);
    }
    Ok(Value::Array(output))
}

fn subject_to_id(subject: NamedOrBlankNodeRef<'_>) -> String {
    match subject {
        NamedOrBlankNodeRef::NamedNode(named) => named.as_str().to_owned(),
        NamedOrBlankNodeRef::BlankNode(blank) => format!("_:{}", blank.as_str()),
    }
}

fn triple_to_embedded_node(triple: &Triple) -> Result<Value, JsonLdError> {
    let mut inner = Map::new();
    inner.insert(
        "@id".to_owned(),
        Value::String(subject_to_id(triple.subject.as_ref())),
    );
    let predicate = triple.predicate.as_str();
    if predicate == RDF_TYPE {
        match triple.object.as_ref() {
            TermRef::NamedNode(named) => {
                inner.insert(
                    "@type".to_owned(),
                    Value::Array(vec![Value::String(named.as_str().to_owned())]),
                );
            }
            TermRef::BlankNode(blank) => {
                inner.insert(
                    "@type".to_owned(),
                    Value::Array(vec![Value::String(format!("_:{}", blank.as_str()))]),
                );
            }
            other => {
                inner.insert(
                    predicate.to_owned(),
                    Value::Array(vec![object_to_json(other)?]),
                );
            }
        }
    } else {
        inner.insert(
            predicate.to_owned(),
            Value::Array(vec![object_to_json(triple.object.as_ref())?]),
        );
    }
    Ok(Value::Object(inner))
}

fn object_to_json(object: TermRef<'_>) -> Result<Value, JsonLdError> {
    let mut map = Map::new();
    match object {
        TermRef::NamedNode(named) => {
            map.insert("@id".to_owned(), Value::String(named.as_str().to_owned()));
        }
        TermRef::BlankNode(blank) => {
            map.insert(
                "@id".to_owned(),
                Value::String(format!("_:{}", blank.as_str())),
            );
        }
        TermRef::Triple(triple) => {
            map.insert("@id".to_owned(), triple_to_embedded_node(triple)?);
        }
        TermRef::Literal(literal) => {
            let datatype = literal.datatype().as_str();
            // Spec section 8.5.2 step 2.4.3: rdf:JSON literals parse back
            // into the internal representation with @type @json; a
            // malformed lexical form is an *invalid JSON literal* error.
            if datatype == RDF_JSON {
                let parsed: Value = serde_json::from_str(literal.value()).map_err(|error| {
                    JsonLdError::InvalidTerm(format!("invalid JSON literal: {error}"))
                })?;
                map.insert("@value".to_owned(), parsed);
                map.insert("@type".to_owned(), Value::String("@json".to_owned()));
                return Ok(Value::Object(map));
            }
            // Spec section 8.5.2 step 2.4.4 (rdfDirection: i18n-datatype):
            // decode language and direction from the datatype fragment.
            if let Some(fragment) = datatype.strip_prefix(I18N_NAMESPACE) {
                let (language, direction) = fragment.split_once('_').ok_or_else(|| {
                    JsonLdError::InvalidTerm(format!(
                        "i18n datatype `{datatype}` lacks a `<language>_<direction>` fragment"
                    ))
                })?;
                if direction != "ltr" && direction != "rtl" {
                    return Err(JsonLdError::InvalidTerm(format!(
                        "i18n datatype `{datatype}` carries an invalid direction"
                    )));
                }
                map.insert(
                    "@value".to_owned(),
                    Value::String(literal.value().to_owned()),
                );
                if !language.is_empty() {
                    map.insert("@language".to_owned(), Value::String(language.to_owned()));
                }
                map.insert("@direction".to_owned(), Value::String(direction.to_owned()));
                return Ok(Value::Object(map));
            }
            map.insert(
                "@value".to_owned(),
                Value::String(literal.value().to_owned()),
            );
            if let Some(language) = literal.language() {
                map.insert("@language".to_owned(), Value::String(language.to_owned()));
            } else if datatype != XSD_STRING {
                map.insert("@type".to_owned(), Value::String(datatype.to_owned()));
            }
        }
    }
    Ok(Value::Object(map))
}

fn render_node(id: &str, node: &NodeAcc) -> Value {
    let mut map = Map::new();
    map.insert("@id".to_owned(), Value::String(id.to_owned()));
    if !node.types.is_empty() {
        let mut types = node.types.clone();
        types.sort();
        map.insert(
            "@type".to_owned(),
            Value::Array(types.into_iter().map(Value::String).collect()),
        );
    }
    for (predicate, values) in &node.properties {
        map.insert(predicate.clone(), Value::Array(values.clone()));
    }
    Value::Object(map)
}

/// Converts well-formed `rdf:first`/`rdf:rest` chains into `@list` arrays
/// (JSON-LD 1.1 API section 8.4). Malformed chains are left as triples.
///
/// A list item may itself be the head of a list, so lists nest. Nesting is
/// resolved innermost-first; heads on a cycle stay as triples (their chain
/// nodes are kept, so nothing is lost).
///
/// # Errors
///
/// [`JsonLdError::ResourceLimit`] with [`JsonLdResource::Depth`] when lists
/// nest deeper than [`JsonLdLimits::max_depth`] (flat quads would otherwise
/// build an arbitrarily deep value), and with [`JsonLdResource::Nodes`]
/// when repeated copies of shared lists exceed [`JsonLdLimits::max_nodes`]
/// (a list head referenced twice from each level doubles per level). The
/// first use of each list is free: its values come from the input's own
/// quads, so only duplication is charged.
fn reassemble_lists(
    nodes: &mut BTreeMap<String, NodeAcc>,
    budget: &mut ListBudget,
) -> Result<(), JsonLdError> {
    let list_nodes: HashSet<String> = nodes
        .iter()
        .filter(|(_, node)| is_list_node(node))
        .map(|(id, _)| id.clone())
        .collect();

    let mut rest_in: HashSet<String> = HashSet::new();
    let mut branched: HashSet<String> = HashSet::new();
    for id in &list_nodes {
        let Some(node) = nodes.get(id) else {
            continue;
        };
        let Some(rest) = rest_id(node) else {
            continue;
        };
        if rest == RDF_NIL {
            continue;
        }
        if !rest_in.insert(rest.to_owned()) {
            branched.insert(rest.to_owned());
        }
    }

    let mut replacements: BTreeMap<String, Value> = BTreeMap::new();
    let mut consumed: HashSet<String> = HashSet::new();
    let mut heads: Vec<String> = list_nodes
        .iter()
        .filter(|id| !rest_in.contains(*id))
        .cloned()
        .collect();
    heads.sort();
    for head in heads {
        if let Some((items, chain)) = walk_list(&head, nodes, &list_nodes, &branched) {
            replacements.insert(
                head,
                Value::Object(Map::from_iter([("@list".to_owned(), Value::Array(items))])),
            );
            consumed.extend(chain);
        }
    }

    let mut replacements = resolve_nested_lists(replacements, &mut consumed, nodes, budget)?;
    keep_unreferenced_lists(&mut replacements, &mut consumed, nodes);

    for (id, node) in nodes.iter_mut() {
        // Consumed chain nodes are removed below; substituting into them
        // would only spend budget.
        if consumed.contains(id) {
            continue;
        }
        for (predicate, values) in &mut node.properties {
            // `rdf:first` of a node kept as triples may reference a
            // converted list head; substituting it there keeps the head's
            // items, which are otherwise removed with the consumed chain.
            // `rdf:rest` of a node that is not a well-formed list node
            // (extra properties, several `rdf:first`) may point at a
            // well-formed tail: JSON-LD 1.1 API section 8.4.2 step 6.4
            // replaces that reference with the tail's `@list`. A converted
            // head is never the `rdf:rest` target of a list node, so this
            // touches only such malformed nodes.
            let is_first = predicate == RDF_FIRST;
            let is_rest = predicate == RDF_REST;
            for value in values {
                let Some(id) = value_id(value) else {
                    continue;
                };
                if let Some((list, size)) = replacements.get(id) {
                    budget.use_list(id, *size)?;
                    *value = list.clone();
                } else if id == RDF_NIL && !is_first && !is_rest {
                    *value = empty_list();
                }
            }
        }
    }

    for id in &consumed {
        nodes.remove(id);
    }
    Ok(())
}

/// Keeps lists that nothing references as `rdf:first`/`rdf:rest` triples.
///
/// A converted list only survives where it is substituted: in a property
/// of a node outside the list chains, or as an item of another list (the
/// `rdf:first` of a chain node). A head with neither has no place to go;
/// removing its chain would drop its triples silently, so its chain nodes
/// are kept and it is not converted.
fn keep_unreferenced_lists(
    replacements: &mut ResolvedLists,
    consumed: &mut HashSet<String>,
    nodes: &BTreeMap<String, NodeAcc>,
) {
    let mut referenced: HashSet<&str> = HashSet::new();
    for (id, node) in nodes {
        let in_chain = consumed.contains(id);
        for (predicate, values) in &node.properties {
            // Outside a chain any property can hold a list (including the
            // `rdf:rest` of a malformed list node, which points at a
            // well-formed tail); inside one only `rdf:first` (a nested list
            // item) can.
            let holds_items = !in_chain || predicate == RDF_FIRST;
            if !holds_items {
                continue;
            }
            for value in values {
                if let Some(target) = value_id(value)
                    && replacements.contains_key(target)
                {
                    referenced.insert(target);
                }
            }
        }
    }
    let unreferenced: Vec<String> = replacements
        .keys()
        .filter(|head| !referenced.contains(head.as_str()))
        .cloned()
        .collect();
    for head in unreferenced {
        replacements.remove(&head);
        let mut current = head;
        let mut seen: HashSet<String> = HashSet::new();
        while consumed.remove(&current) && seen.insert(current.clone()) {
            let Some(next) = nodes.get(&current).and_then(rest_id) else {
                break;
            };
            current = next.to_owned();
        }
    }
}

/// Charges list copies in `fromRdf` against [`JsonLdLimits`].
#[derive(Debug)]
struct ListBudget {
    /// Lists already placed once (their first use is not charged).
    used: HashSet<String>,
    /// Values produced by second and later uses.
    copied: usize,
    max_nodes: usize,
    max_depth: usize,
}

impl ListBudget {
    fn new(limits: &JsonLdLimits) -> Self {
        Self {
            used: HashSet::new(),
            copied: 0,
            max_nodes: limits.max_nodes,
            max_depth: limits.max_depth,
        }
    }

    /// Charges placing the list headed by `head` (holding `size` values).
    ///
    /// The first placement is free; every later one copies `size` values
    /// and is charged before the copy is made.
    fn use_list(&mut self, head: &str, size: usize) -> Result<(), JsonLdError> {
        if self.used.insert(head.to_owned()) {
            return Ok(());
        }
        self.copied = self.copied.saturating_add(size);
        if self.copied > self.max_nodes {
            return Err(JsonLdError::ResourceLimit {
                resource: JsonLdResource::Nodes,
                limit: self.max_nodes,
                observed: self.copied,
            });
        }
        Ok(())
    }
}

/// Per-head facts gathered by [`resolve_nested_lists`].
#[derive(Debug, Default)]
struct HeadFacts {
    /// Nesting depth of the head's list (1 for a list of plain items).
    depth: usize,
    /// Values its fully resolved list holds, nested lists included.
    size: usize,
}

/// Resolved list objects by head id, with the values each one holds.
type ResolvedLists = BTreeMap<String, (Value, usize)>;

/// Substitutes nested list heads inside `replacements`, innermost first.
///
/// Iterative post-order over the "item is a list head" graph: no native
/// recursion, every head resolved once. Heads on a cycle are dropped from
/// `replacements` and their chains un-consumed, so they stay as triples.
fn resolve_nested_lists(
    replacements: BTreeMap<String, Value>,
    consumed: &mut HashSet<String>,
    nodes: &BTreeMap<String, NodeAcc>,
    budget: &mut ListBudget,
) -> Result<ResolvedLists, JsonLdError> {
    let children = |head: &str| -> Vec<String> {
        replacements
            .get(head)
            .and_then(|list| list.get("@list"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(value_id)
                    .filter(|id| replacements.contains_key(*id))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };

    // Post-order with cycle detection (white / on-stack / done).
    let mut facts: HashMap<String, HeadFacts> = HashMap::new();
    let mut on_stack: HashSet<String> = HashSet::new();
    let mut cyclic: HashSet<String> = HashSet::new();
    let mut order: Vec<String> = Vec::new();
    for root in replacements.keys() {
        if facts.contains_key(root) {
            continue;
        }
        let mut stack: Vec<(String, bool)> = vec![(root.clone(), false)];
        while let Some((head, expanded)) = stack.pop() {
            if expanded {
                on_stack.remove(&head);
                let mut depth = 1_usize;
                let mut size = 1_usize;
                let mut items = 0_usize;
                for child in children(&head) {
                    items = items.saturating_add(1);
                    match facts.get(&child) {
                        Some(child_facts) if !cyclic.contains(&child) => {
                            depth = depth.max(child_facts.depth.saturating_add(1));
                            size = size.saturating_add(child_facts.size);
                        }
                        _ => {}
                    }
                }
                let plain = replacements
                    .get(&head)
                    .and_then(|list| list.get("@list"))
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len)
                    .saturating_sub(items);
                size = size.saturating_add(plain);
                if depth > budget.max_depth {
                    return Err(JsonLdError::ResourceLimit {
                        resource: JsonLdResource::Depth,
                        limit: budget.max_depth,
                        observed: depth,
                    });
                }
                facts.insert(head.clone(), HeadFacts { depth, size });
                order.push(head);
                continue;
            }
            if facts.contains_key(&head) {
                continue;
            }
            if on_stack.contains(&head) {
                cyclic.insert(head);
                continue;
            }
            on_stack.insert(head.clone());
            stack.push((head.clone(), true));
            for child in children(&head) {
                if on_stack.contains(&child) {
                    cyclic.insert(child);
                } else if !facts.contains_key(&child) {
                    stack.push((child, false));
                }
            }
        }
    }

    let mut remaining = replacements;
    let mut resolved: ResolvedLists = BTreeMap::new();
    for head in order {
        let Some(mut list_object) = remaining.remove(&head) else {
            continue;
        };
        if cyclic.contains(&head) {
            continue;
        }
        if let Some(Value::Array(items)) = list_object.get_mut("@list") {
            for item in items {
                let Some(id) = value_id(item) else {
                    continue;
                };
                if let Some((nested, size)) = resolved.get(id) {
                    budget.use_list(id, *size)?;
                    *item = nested.clone();
                }
            }
        }
        let size = facts.get(&head).map_or(0, |fact| fact.size);
        resolved.insert(head, (list_object, size));
    }

    // Cyclic heads stay as triples: give their chain nodes back.
    for head in &cyclic {
        let mut current = head.clone();
        let mut seen: HashSet<String> = HashSet::new();
        while consumed.remove(&current) && seen.insert(current.clone()) {
            let Some(next) = nodes.get(&current).and_then(rest_id) else {
                break;
            };
            current = next.to_owned();
        }
    }
    Ok(resolved)
}

fn empty_list() -> Value {
    Value::Object(Map::from_iter([(
        "@list".to_owned(),
        Value::Array(Vec::new()),
    )]))
}

fn is_list_node(node: &NodeAcc) -> bool {
    let Some(first) = node.properties.get(RDF_FIRST) else {
        return false;
    };
    let Some(rest) = node.properties.get(RDF_REST) else {
        return false;
    };
    first.len() == 1
        && rest.len() == 1
        && node.properties.len() == 2
        && node.types.iter().all(|type_iri| type_iri == RDF_LIST)
}

fn rest_id(node: &NodeAcc) -> Option<&str> {
    value_id(node.properties.get(RDF_REST)?.first()?)
}

fn value_id(value: &Value) -> Option<&str> {
    value.as_object()?.get("@id").and_then(Value::as_str)
}

fn walk_list(
    head: &str,
    nodes: &BTreeMap<String, NodeAcc>,
    list_nodes: &HashSet<String>,
    branched: &HashSet<String>,
) -> Option<(Vec<Value>, Vec<String>)> {
    let mut items = Vec::new();
    let mut chain = Vec::new();
    let mut current = head.to_owned();
    let mut seen: HashSet<String> = HashSet::new();
    loop {
        if branched.contains(&current) || !seen.insert(current.clone()) {
            return None;
        }
        if !list_nodes.contains(&current) {
            return None;
        }
        let node = nodes.get(&current)?;
        items.push(node.properties.get(RDF_FIRST)?.first()?.clone());
        chain.push(current.clone());
        let rest = rest_id(node)?;
        if rest == RDF_NIL {
            return Some((items, chain));
        }
        current = rest.to_owned();
    }
}
