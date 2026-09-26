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

use std::collections::{BTreeMap, HashSet};

use arrow_array::RecordBatch;
use oxrdf::{GraphNameRef, NamedOrBlankNodeRef, TermRef, Triple};
use quad_fast_core::{QuadLimits, QuadStreamReader};
use serde_json::{Map, Value};

use crate::{
    error::JsonLdError,
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
/// contract validation or a row does not decode to a valid quad.
pub(crate) fn quads_to_expanded(batches: &[RecordBatch]) -> Result<Value, JsonLdError> {
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
    reassemble_lists(&mut default_nodes);
    // Every named graph needs a carrier node in the default graph.
    let named_graph_names: Vec<String> = graphs.keys().flatten().cloned().collect();
    for name in &named_graph_names {
        default_nodes.entry(name.clone()).or_default();
    }
    for graph_nodes in graphs.values_mut() {
        reassemble_lists(graph_nodes);
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
fn reassemble_lists(nodes: &mut BTreeMap<String, NodeAcc>) {
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

    // Nested lists: substitute list-head references inside collected
    // `@list` arrays. A bounded number of passes handles nesting without
    // looping forever on a cyclic first/rest graph we failed to classify.
    for _ in 0..replacements.len().saturating_add(1) {
        let lookup = replacements.clone();
        let mut changed = false;
        for list_object in replacements.values_mut() {
            let Some(Value::Array(items)) = list_object.get_mut("@list") else {
                continue;
            };
            for item in items {
                let Some(id) = value_id(item) else {
                    continue;
                };
                let Some(nested) = lookup.get(id) else {
                    continue;
                };
                *item = nested.clone();
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    for node in nodes.values_mut() {
        for (predicate, values) in &mut node.properties {
            if predicate == RDF_REST || predicate == RDF_FIRST {
                continue;
            }
            for value in values {
                let Some(id) = value_id(value) else {
                    continue;
                };
                if let Some(list) = replacements.get(id) {
                    *value = list.clone();
                } else if id == RDF_NIL {
                    *value = empty_list();
                }
            }
        }
    }

    for id in &consumed {
        nodes.remove(id);
    }
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
