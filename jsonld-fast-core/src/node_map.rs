// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Node Map Generation (JSON-LD 1.1 API section 7.2.2).
//!
//! Shared by flattening and framing so both algorithms assign the same
//! deterministic `_:b0`-style blank node identities. There is one issuer
//! implementation; do not add a second.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value};

use crate::error::{JsonLdError, JsonLdFeature};

/// One graph of the node map: subject id to node object.
pub(crate) type Graph = BTreeMap<String, Map<String, Value>>;

/// The node map: graph name (`@default` or a graph id) to graph.
pub(crate) type GraphMap = BTreeMap<String, Graph>;

/// The key of the default graph in the node map.
pub(crate) const DEFAULT_GRAPH: &str = "@default";

/// Deterministic relabeling issuer for blank node identifiers.
#[derive(Debug, Default)]
struct BlankNodeIssuer {
    mapping: HashMap<String, String>,
    counter: usize,
}

impl BlankNodeIssuer {
    fn issue(&mut self, existing: Option<&str>) -> String {
        if let Some(existing) = existing
            && let Some(issued) = self.mapping.get(existing)
        {
            return issued.clone();
        }
        let issued = format!("_:b{}", self.counter);
        self.counter += 1;
        if let Some(existing) = existing {
            self.mapping.insert(existing.to_owned(), issued.clone());
        }
        issued
    }
}

#[derive(Debug, Default)]
struct NodeMapBuilder {
    graphs: GraphMap,
    issuer: BlankNodeIssuer,
}

/// Builds the node map of an expanded document (API section 7.2.2).
pub(crate) fn build_node_map(expanded: &Value) -> Result<GraphMap, JsonLdError> {
    let Value::Array(items) = expanded else {
        return Err(JsonLdError::InvalidDocument(
            "expanded form must be a top-level array".to_owned(),
        ));
    };
    let mut builder = NodeMapBuilder::default();
    builder
        .graphs
        .insert(DEFAULT_GRAPH.to_owned(), Graph::new());
    for item in items {
        let Value::Object(node) = item else {
            return Err(JsonLdError::InvalidDocument(
                "expanded top-level entries must be node objects".to_owned(),
            ));
        };
        builder.process_node(node, DEFAULT_GRAPH)?;
    }
    Ok(builder.graphs)
}

impl NodeMapBuilder {
    /// Registers one node object in `graph`, returning its id.
    #[expect(
        clippy::too_many_lines,
        reason = "mirrors the sequential entry handling of API section 7.2.2"
    )]
    fn process_node(
        &mut self,
        node: &Map<String, Value>,
        graph: &str,
    ) -> Result<String, JsonLdError> {
        let id = match node.get("@id") {
            Some(Value::String(id)) if id.starts_with("_:") => self.issuer.issue(Some(id)),
            Some(Value::String(id)) => id.clone(),
            Some(Value::Object(_)) => {
                return Err(JsonLdError::UnsupportedFeature {
                    feature: JsonLdFeature::RdfStarTripleTerm,
                });
            }
            Some(_) => {
                return Err(JsonLdError::InvalidDocument(
                    "an expanded @id must be a string or an embedded node".to_owned(),
                ));
            }
            None => self.issuer.issue(None),
        };
        self.ensure_node(graph, &id);

        if let Some(types) = node.get("@type") {
            let Value::Array(types) = types else {
                return Err(JsonLdError::InvalidDocument(
                    "an expanded @type must be an array".to_owned(),
                ));
            };
            for entry in types {
                let Value::String(type_iri) = entry else {
                    return Err(JsonLdError::InvalidDocument(
                        "expanded @type entries must be strings".to_owned(),
                    ));
                };
                let relabeled = if type_iri.starts_with("_:") {
                    self.issuer.issue(Some(type_iri))
                } else {
                    type_iri.clone()
                };
                let target = self.node_mut(graph, &id);
                let slot = target
                    .entry("@type".to_owned())
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Value::Array(existing) = slot {
                    let value = Value::String(relabeled);
                    if !existing.contains(&value) {
                        existing.push(value);
                    }
                }
            }
        }

        if let Some(index) = node.get("@index") {
            let target = self.node_mut(graph, &id);
            if let Some(existing) = target.get("@index")
                && existing != index
            {
                // API section 7.2.2 step 4.3.1: `conflicting indexes`.
                return Err(JsonLdError::InvalidDocument(format!(
                    "conflicting indexes on node `{id}`"
                )));
            }
            target.insert("@index".to_owned(), index.clone());
        }

        for (property, values) in node {
            match property.as_str() {
                "@id" | "@type" | "@index" | "@annotation" => {}
                "@reverse" => {
                    // Reverse entries invert: each value node gains a
                    // forward property pointing at this node.
                    let Value::Object(reverse_map) = values else {
                        return Err(JsonLdError::InvalidDocument(
                            "an expanded @reverse must be a map".to_owned(),
                        ));
                    };
                    for (reverse_property, reverse_values) in reverse_map {
                        let Value::Array(reverse_values) = reverse_values else {
                            return Err(JsonLdError::InvalidDocument(
                                "expanded reverse properties must hold arrays".to_owned(),
                            ));
                        };
                        for value in reverse_values {
                            let Value::Object(value_node) = value else {
                                return Err(JsonLdError::InvalidDocument(
                                    "reverse property values must be node objects".to_owned(),
                                ));
                            };
                            let value_id = self.process_node(value_node, graph)?;
                            let reference = Value::Object(Map::from_iter([(
                                "@id".to_owned(),
                                Value::String(id.clone()),
                            )]));
                            add_unique(
                                self.node_mut(graph, &value_id),
                                reverse_property,
                                reference,
                            );
                        }
                    }
                }
                "@graph" => {
                    let Value::Array(graph_nodes) = values else {
                        return Err(JsonLdError::InvalidDocument(
                            "an expanded @graph must be an array".to_owned(),
                        ));
                    };
                    self.graphs.entry(id.clone()).or_default();
                    for graph_node in graph_nodes {
                        let Value::Object(inner) = graph_node else {
                            return Err(JsonLdError::InvalidDocument(
                                "@graph entries must be node objects".to_owned(),
                            ));
                        };
                        self.process_node(inner, &id.clone())?;
                    }
                }
                "@included" => {
                    let Value::Array(included) = values else {
                        return Err(JsonLdError::InvalidDocument(
                            "an expanded @included must be an array".to_owned(),
                        ));
                    };
                    for included_node in included {
                        let Value::Object(inner) = included_node else {
                            return Err(JsonLdError::InvalidDocument(
                                "@included entries must be node objects".to_owned(),
                            ));
                        };
                        self.process_node(inner, graph)?;
                    }
                }
                keyword if keyword.starts_with('@') => {
                    return Err(JsonLdError::InvalidDocument(format!(
                        "keyword `{keyword}` is not valid in an expanded node object"
                    )));
                }
                property => {
                    let Value::Array(values) = values else {
                        return Err(JsonLdError::InvalidDocument(format!(
                            "expanded property `{property}` must hold an array"
                        )));
                    };
                    // Ensure the slot exists even for empty value arrays.
                    self.node_mut(graph, &id)
                        .entry(property.to_owned())
                        .or_insert_with(|| Value::Array(Vec::new()));
                    for value in values {
                        let converted = self.convert_value(value, graph)?;
                        add_unique(self.node_mut(graph, &id), property, converted);
                    }
                }
            }
        }
        Ok(id)
    }

    /// Converts one expanded value into its node-map form (value objects
    /// verbatim, node objects to references, lists recursively).
    fn convert_value(&mut self, value: &Value, graph: &str) -> Result<Value, JsonLdError> {
        let Value::Object(map) = value else {
            return Err(JsonLdError::InvalidDocument(
                "expanded values must be node, value, or list objects".to_owned(),
            ));
        };
        if map.contains_key("@value") {
            return Ok(value.clone());
        }
        if let Some(Value::Object(_)) = map.get("@id") {
            // JSON-LD-star quoted triple used as an object: keep the
            // embedded node verbatim rather than interning a subject id.
            return Ok(value.clone());
        }
        if let Some(list) = map.get("@list") {
            let Value::Array(items) = list else {
                return Err(JsonLdError::InvalidDocument(
                    "an expanded @list must be an array".to_owned(),
                ));
            };
            let mut converted = Vec::with_capacity(items.len());
            for item in items {
                converted.push(self.convert_value(item, graph)?);
            }
            return Ok(Value::Object(Map::from_iter([(
                "@list".to_owned(),
                Value::Array(converted),
            )])));
        }
        let id = self.process_node(map, graph)?;
        Ok(Value::Object(Map::from_iter([(
            "@id".to_owned(),
            Value::String(id),
        )])))
    }

    fn ensure_node(&mut self, graph: &str, id: &str) {
        let graph_entry = self.graphs.entry(graph.to_owned()).or_default();
        graph_entry
            .entry(id.to_owned())
            .or_insert_with(|| Map::from_iter([("@id".to_owned(), Value::String(id.to_owned()))]));
    }

    fn node_mut(&mut self, graph: &str, id: &str) -> &mut Map<String, Value> {
        self.graphs
            .entry(graph.to_owned())
            .or_default()
            .entry(id.to_owned())
            .or_insert_with(|| Map::from_iter([("@id".to_owned(), Value::String(id.to_owned()))]))
    }
}

/// Appends `value` to the array at `map[property]` unless already present.
fn add_unique(map: &mut Map<String, Value>, property: &str, value: Value) {
    let slot = map
        .entry(property.to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(existing) = slot
        && !existing.contains(&value)
    {
        existing.push(value);
    }
}
