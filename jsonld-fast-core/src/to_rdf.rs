// Rust guideline compliant 2026-02-21
//! Deserialization of expanded JSON-LD to RDF quads.
//!
//! Follows the "Deserialize JSON-LD to RDF" algorithm (JSON-LD 1.1 API
//! section 8.1): blank node identifiers are reissued from a deterministic
//! counter (`_:b0`, `_:b1`, ... in encounter order), `@list` arrays become
//! `rdf:first`/`rdf:rest`/`rdf:nil` chains, `@graph` entries emit into
//! named graphs, `@reverse` maps emit inverted triples, `@included` nodes
//! emit into the same graph, `@type: @json` values become `rdf:JSON`
//! literals in the canonical form of JSON-LD 1.1 section 10.2, and
//! `@direction` uses the `rdfDirection: i18n-datatype` serialization
//! (datatype `https://www.w3.org/ns/i18n#<language>_<direction>` with the
//! language lowercased or empty). `@index` entries are dropped, exactly as
//! section 8.1.2 requires (RDF has no representation for them). IRIs that
//! stayed relative after expansion fail closed with
//! [`JsonLdError::RelativeIri`]; the spec's silent node drop is deliberately
//! not implemented.

use std::collections::HashMap;

use oxrdf::{BlankNode, GraphName, Literal, NamedNode, NamedOrBlankNode, Quad, Term, Triple};
use serde_json::{Map, Number, Value};

use crate::{
    error::{JsonLdError, JsonLdFeature},
    iri::{is_absolute_iri, is_blank_node_id},
    json_canon::canonical_json,
};

/// `rdf:type` predicate IRI.
pub(crate) const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
/// `rdf:JSON` datatype IRI (JSON-LD 1.1 section 10.2).
pub(crate) const RDF_JSON: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON";
/// The i18n datatype namespace (JSON-LD 1.1 section 10.3).
pub(crate) const I18N_NAMESPACE: &str = "https://www.w3.org/ns/i18n#";
/// `rdf:first` predicate IRI.
pub(crate) const RDF_FIRST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
/// `rdf:rest` predicate IRI.
pub(crate) const RDF_REST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
/// `rdf:nil` list terminator IRI.
pub(crate) const RDF_NIL: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";
/// `xsd:string` datatype IRI.
pub(crate) const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
/// `xsd:integer` datatype IRI.
pub(crate) const XSD_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
/// `xsd:double` datatype IRI.
pub(crate) const XSD_DOUBLE: &str = "http://www.w3.org/2001/XMLSchema#double";
/// `xsd:boolean` datatype IRI.
pub(crate) const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";

/// Converts an expanded document (top-level array) to a quad list.
///
/// # Errors
///
/// Returns [`JsonLdError::RelativeIri`] for IRIs that stayed relative,
/// [`JsonLdError::InvalidTerm`] for values [`oxrdf`] rejects (including
/// blank node predicates, which generalized RDF would allow but the quad
/// contract does not), and [`JsonLdError::InvalidDocument`] for malformed
/// expanded input.
pub(crate) fn expanded_to_quads(expanded: &Value) -> Result<Vec<Quad>, JsonLdError> {
    let Value::Array(items) = expanded else {
        return Err(JsonLdError::InvalidDocument(
            "expanded form must be a top-level array".to_owned(),
        ));
    };
    let mut emitter = Emitter {
        issuer: BlankNodeIssuer::default(),
        quads: Vec::new(),
    };
    for item in items {
        let Value::Object(node) = item else {
            return Err(JsonLdError::InvalidDocument(
                "expanded top-level entries must be node objects".to_owned(),
            ));
        };
        emitter.emit_node(node, &GraphName::DefaultGraph)?;
    }
    Ok(emitter.quads)
}

/// Deterministic blank node identifier issuer (`b0`, `b1`, ...).
#[derive(Debug, Default)]
struct BlankNodeIssuer {
    mapping: HashMap<String, String>,
    counter: usize,
}

impl BlankNodeIssuer {
    /// Issues a label, reusing the mapping for previously seen identifiers.
    fn issue(&mut self, existing: Option<&str>) -> String {
        if let Some(existing) = existing
            && let Some(issued) = self.mapping.get(existing)
        {
            return issued.clone();
        }
        let issued = format!("b{}", self.counter);
        self.counter += 1;
        if let Some(existing) = existing {
            self.mapping.insert(existing.to_owned(), issued.clone());
        }
        issued
    }
}

#[derive(Debug)]
struct Emitter {
    issuer: BlankNodeIssuer,
    quads: Vec<Quad>,
}

impl Emitter {
    /// Emits all quads of one node object, returning its subject term.
    fn emit_node(
        &mut self,
        node: &Map<String, Value>,
        graph: &GraphName,
    ) -> Result<NamedOrBlankNode, JsonLdError> {
        let subject = match node.get("@id") {
            Some(Value::String(id)) => self.named_or_blank(id)?,
            Some(Value::Object(_)) => {
                // Quoted triple as subject: the quad contract has no
                // triple-term subject variant.
                return Err(JsonLdError::UnsupportedFeature {
                    feature: JsonLdFeature::RdfStarTripleTerm,
                });
            }
            Some(_) => {
                return Err(JsonLdError::InvalidDocument(
                    "an expanded @id must be a string or an embedded node".to_owned(),
                ));
            }
            None => NamedOrBlankNode::BlankNode(self.fresh_blank(None)),
        };

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
                let object: Term = match self.named_or_blank(type_iri)? {
                    NamedOrBlankNode::NamedNode(named) => named.into(),
                    NamedOrBlankNode::BlankNode(blank) => blank.into(),
                };
                self.quads.push(Quad::new(
                    subject.clone(),
                    named_node(RDF_TYPE)?,
                    object,
                    graph.clone(),
                ));
            }
        }

        // `@index` carries no RDF representation and is dropped here, as
        // spec section 8.1.2 step 3.2 requires (keywords other than @type
        // are skipped when emitting triples).
        let mut keys: Vec<&String> = node
            .keys()
            .filter(|key| {
                !matches!(
                    key.as_str(),
                    "@id"
                        | "@type"
                        | "@graph"
                        | "@index"
                        | "@reverse"
                        | "@included"
                        | "@annotation"
                )
            })
            .collect();
        keys.sort();
        for key in keys {
            if key.starts_with('@') {
                return Err(JsonLdError::InvalidDocument(format!(
                    "keyword `{key}` is not valid in an expanded node object"
                )));
            }
            if is_blank_node_id(key) {
                return Err(JsonLdError::InvalidTerm(format!(
                    "blank node predicate `{key}` is not representable as a quad"
                )));
            }
            if !is_absolute_iri(key) {
                return Err(JsonLdError::RelativeIri { iri: key.clone() });
            }
            let predicate = named_node(key)?;
            let Value::Array(values) = &node[key.as_str()] else {
                return Err(JsonLdError::InvalidDocument(format!(
                    "expanded property `{key}` must hold an array"
                )));
            };
            for value in values {
                let object = self.object_term(value, graph)?;
                self.quads.push(Quad::new(
                    subject.clone(),
                    predicate.clone(),
                    object.clone(),
                    graph.clone(),
                ));
                if let Value::Object(value_map) = value
                    && let Some(annotation) = value_map.get("@annotation")
                {
                    self.emit_annotations(&subject, &predicate, &object, annotation, graph)?;
                }
            }
        }

        // `@reverse` maps invert subject and object: the expanded item is
        // the subject of the emitted quad and this node is its object
        // (node map generation, JSON-LD 1.1 API section 7.2, normalizes
        // reverse properties exactly this way before section 8.1 runs).
        if let Some(reverse_value) = node.get("@reverse") {
            let Value::Object(reverse_map) = reverse_value else {
                return Err(JsonLdError::InvalidDocument(
                    "an expanded @reverse must be a map".to_owned(),
                ));
            };
            let mut reverse_keys: Vec<&String> = reverse_map.keys().collect();
            reverse_keys.sort();
            for key in reverse_keys {
                if is_blank_node_id(key) {
                    return Err(JsonLdError::InvalidTerm(format!(
                        "blank node reverse predicate `{key}` is not representable as a quad"
                    )));
                }
                if !is_absolute_iri(key) {
                    return Err(JsonLdError::RelativeIri { iri: key.clone() });
                }
                let predicate = named_node(key)?;
                let Value::Array(values) = &reverse_map[key.as_str()] else {
                    return Err(JsonLdError::InvalidDocument(format!(
                        "expanded reverse property `{key}` must hold an array"
                    )));
                };
                let object: Term = match &subject {
                    NamedOrBlankNode::NamedNode(named) => named.clone().into(),
                    NamedOrBlankNode::BlankNode(blank) => blank.clone().into(),
                };
                for value in values {
                    let Value::Object(target) = value else {
                        return Err(JsonLdError::InvalidDocument(
                            "reverse property values must be node objects".to_owned(),
                        ));
                    };
                    if target.contains_key("@value") || target.contains_key("@list") {
                        return Err(JsonLdError::InvalidDocument(
                            "reverse property values must be node objects".to_owned(),
                        ));
                    }
                    let reversed_subject = self.emit_node(target, graph)?;
                    self.quads.push(Quad::new(
                        reversed_subject,
                        predicate.clone(),
                        object.clone(),
                        graph.clone(),
                    ));
                }
            }
        }

        // `@included` nodes emit into the same graph as the including node
        // (JSON-LD 1.1 section 4.7 / API section 7.2 step 13.8.7).
        if let Some(included_value) = node.get("@included") {
            let Value::Array(included_nodes) = included_value else {
                return Err(JsonLdError::InvalidDocument(
                    "an expanded @included must be an array".to_owned(),
                ));
            };
            for included_node in included_nodes {
                let Value::Object(inner) = included_node else {
                    return Err(JsonLdError::InvalidDocument(
                        "@included entries must be node objects".to_owned(),
                    ));
                };
                self.emit_node(inner, graph)?;
            }
        }

        if let Some(graph_value) = node.get("@graph") {
            let Value::Array(graph_nodes) = graph_value else {
                return Err(JsonLdError::InvalidDocument(
                    "an expanded @graph must be an array".to_owned(),
                ));
            };
            let named_graph: GraphName = match &subject {
                NamedOrBlankNode::NamedNode(named) => named.clone().into(),
                NamedOrBlankNode::BlankNode(blank) => blank.clone().into(),
            };
            for graph_node in graph_nodes {
                let Value::Object(inner) = graph_node else {
                    return Err(JsonLdError::InvalidDocument(
                        "@graph entries must be node objects".to_owned(),
                    ));
                };
                self.emit_node(inner, &named_graph)?;
            }
        }

        Ok(subject)
    }

    /// Converts one expanded value to an RDF object term.
    fn object_term(&mut self, value: &Value, graph: &GraphName) -> Result<Term, JsonLdError> {
        let Value::Object(map) = value else {
            return Err(JsonLdError::InvalidDocument(
                "expanded values must be node, value, or list objects".to_owned(),
            ));
        };
        if let Some(list) = map.get("@list") {
            let Value::Array(items) = list else {
                return Err(JsonLdError::InvalidDocument(
                    "an expanded @list must be an array".to_owned(),
                ));
            };
            return self.list_chain(items, graph);
        }
        if map.contains_key("@value") {
            return Ok(literal_from_value_object(map)?.into());
        }
        // JSON-LD-star object-position quoted triple: a node whose `@id`
        // is an embedded node and which carries no other asserted
        // properties (annotations are peeled by the caller).
        if let Some(Value::Object(embedded)) = map.get("@id") {
            let extra = map
                .keys()
                .any(|key| !matches!(key.as_str(), "@id" | "@index" | "@annotation"));
            if extra {
                return Err(JsonLdError::UnsupportedFeature {
                    feature: JsonLdFeature::RdfStarTripleTerm,
                });
            }
            return Ok(Term::Triple(Box::new(
                self.embedded_to_triple(embedded, graph)?,
            )));
        }
        Ok(match self.emit_node(map, graph)? {
            NamedOrBlankNode::NamedNode(named) => named.into(),
            NamedOrBlankNode::BlankNode(blank) => blank.into(),
        })
    }

    /// Converts an expanded embedded node to an RDF triple term.
    ///
    /// The inner `@id` must be a named or blank node (quoted-triple
    /// subjects are not representable). The single relationship is either
    /// `@type` or one IRI property; its object may itself be a nested
    /// quoted triple.
    fn embedded_to_triple(
        &mut self,
        node: &Map<String, Value>,
        graph: &GraphName,
    ) -> Result<Triple, JsonLdError> {
        let subject = match node.get("@id") {
            Some(Value::String(id)) => self.named_or_blank(id)?,
            Some(Value::Object(_)) => {
                return Err(JsonLdError::UnsupportedFeature {
                    feature: JsonLdFeature::RdfStarTripleTerm,
                });
            }
            Some(_) => {
                return Err(JsonLdError::InvalidDocument(
                    "an embedded node @id must be a string".to_owned(),
                ));
            }
            None => {
                return Err(JsonLdError::InvalidDocument(
                    "an embedded node must have an @id".to_owned(),
                ));
            }
        };
        if let Some(types) = node.get("@type") {
            let Value::Array(types) = types else {
                return Err(JsonLdError::InvalidDocument(
                    "an expanded @type must be an array".to_owned(),
                ));
            };
            if types.len() != 1 {
                return Err(JsonLdError::InvalidDocument(
                    "an embedded node must describe exactly one relationship".to_owned(),
                ));
            }
            let Value::String(type_iri) = &types[0] else {
                return Err(JsonLdError::InvalidDocument(
                    "expanded @type entries must be strings".to_owned(),
                ));
            };
            let object: Term = match self.named_or_blank(type_iri)? {
                NamedOrBlankNode::NamedNode(named) => named.into(),
                NamedOrBlankNode::BlankNode(blank) => blank.into(),
            };
            return Ok(Triple::new(subject, named_node(RDF_TYPE)?, object));
        }
        let property = node
            .keys()
            .find(|key| !key.starts_with('@'))
            .ok_or_else(|| {
                JsonLdError::InvalidDocument(
                    "an embedded node must describe exactly one relationship".to_owned(),
                )
            })?;
        let Value::Array(values) = &node[property.as_str()] else {
            return Err(JsonLdError::InvalidDocument(format!(
                "expanded property `{property}` must hold an array"
            )));
        };
        if values.len() != 1 {
            return Err(JsonLdError::InvalidDocument(
                "an embedded node must describe exactly one relationship".to_owned(),
            ));
        }
        let object = self.object_term(&values[0], graph)?;
        Ok(Triple::new(subject, named_node(property)?, object))
    }

    /// Emits reverse `@annotation` quads (`annotator pred <<s p o>>`).
    /// Forward annotations need a quoted-triple subject and are refused.
    fn emit_annotations(
        &mut self,
        subject: &NamedOrBlankNode,
        predicate: &NamedNode,
        object: &Term,
        annotation: &Value,
        graph: &GraphName,
    ) -> Result<(), JsonLdError> {
        let nodes: Vec<&Value> = match annotation {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        let quoted = Term::Triple(Box::new(Triple::new(
            subject.clone(),
            predicate.clone(),
            object.clone(),
        )));
        for node in nodes {
            let Value::Object(map) = node else {
                return Err(JsonLdError::InvalidDocument(
                    "@annotation values must be node objects".to_owned(),
                ));
            };
            let has_forward =
                map.contains_key("@type") || map.keys().any(|key| !key.starts_with('@'));
            if has_forward {
                return Err(JsonLdError::UnsupportedFeature {
                    feature: JsonLdFeature::RdfStarTripleTerm,
                });
            }
            let Some(reverse_value) = map.get("@reverse") else {
                continue;
            };
            let Value::Object(reverse_map) = reverse_value else {
                return Err(JsonLdError::InvalidDocument(
                    "an expanded @reverse must be a map".to_owned(),
                ));
            };
            let mut reverse_keys: Vec<&String> = reverse_map.keys().collect();
            reverse_keys.sort();
            for key in reverse_keys {
                if is_blank_node_id(key) {
                    return Err(JsonLdError::InvalidTerm(format!(
                        "blank node reverse predicate `{key}` is not representable as a quad"
                    )));
                }
                if !is_absolute_iri(key) {
                    return Err(JsonLdError::RelativeIri { iri: key.clone() });
                }
                let annotation_predicate = named_node(key)?;
                let Value::Array(values) = &reverse_map[key.as_str()] else {
                    return Err(JsonLdError::InvalidDocument(format!(
                        "expanded reverse property `{key}` must hold an array"
                    )));
                };
                for value in values {
                    let Value::Object(target) = value else {
                        return Err(JsonLdError::InvalidDocument(
                            "reverse property values must be node objects".to_owned(),
                        ));
                    };
                    let annotator = self.emit_node(target, graph)?;
                    self.quads.push(Quad::new(
                        annotator,
                        annotation_predicate.clone(),
                        quoted.clone(),
                        graph.clone(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Emits an `rdf:first`/`rdf:rest` chain and returns its head term.
    fn list_chain(&mut self, items: &[Value], graph: &GraphName) -> Result<Term, JsonLdError> {
        if items.is_empty() {
            return Ok(named_node(RDF_NIL)?.into());
        }
        let mut links = Vec::with_capacity(items.len());
        for item in items {
            let term = self.object_term(item, graph)?;
            links.push((self.fresh_blank(None), term));
        }
        let first = named_node(RDF_FIRST)?;
        let rest = named_node(RDF_REST)?;
        let nil: Term = named_node(RDF_NIL)?.into();
        for index in 0..links.len() {
            let (link, term) = links[index].clone();
            self.quads
                .push(Quad::new(link.clone(), first.clone(), term, graph.clone()));
            let tail: Term = match links.get(index + 1) {
                Some((next, _)) => next.clone().into(),
                None => nil.clone(),
            };
            self.quads
                .push(Quad::new(link, rest.clone(), tail, graph.clone()));
        }
        Ok(links[0].0.clone().into())
    }

    fn named_or_blank(&mut self, id: &str) -> Result<NamedOrBlankNode, JsonLdError> {
        if let Some(label) = id.strip_prefix("_:") {
            return Ok(NamedOrBlankNode::BlankNode(self.fresh_blank(Some(label))));
        }
        if !is_absolute_iri(id) {
            return Err(JsonLdError::RelativeIri { iri: id.to_owned() });
        }
        Ok(NamedOrBlankNode::NamedNode(named_node(id)?))
    }

    fn fresh_blank(&mut self, existing: Option<&str>) -> BlankNode {
        let label = self.issuer.issue(existing);
        // Issued labels are `b{counter}`, always valid blank node labels.
        BlankNode::new(label).unwrap_or_else(|_| BlankNode::default())
    }
}

fn named_node(iri: &str) -> Result<NamedNode, JsonLdError> {
    NamedNode::new(iri)
        .map_err(|error| JsonLdError::InvalidTerm(format!("invalid IRI `{iri}`: {error}")))
}

/// Converts an expanded value object to an RDF literal.
fn literal_from_value_object(map: &Map<String, Value>) -> Result<Literal, JsonLdError> {
    let value = map
        .get("@value")
        .ok_or_else(|| JsonLdError::InvalidDocument("a value object needs @value".to_owned()))?;
    let datatype_override = match map.get("@type") {
        None => None,
        Some(Value::String(datatype)) => Some(datatype.as_str()),
        Some(_) => {
            return Err(JsonLdError::InvalidDocument(
                "a value object @type must be a string".to_owned(),
            ));
        }
    };
    // Spec section 8.2.2 step 8: `@type: @json` values serialize to the
    // canonical form of JSON-LD 1.1 section 10.2 with datatype `rdf:JSON`.
    if datatype_override == Some("@json") {
        let lexical = canonical_json(value)?;
        return Ok(Literal::new_typed_literal(lexical, named_node(RDF_JSON)?));
    }
    // Spec section 8.2.2 step 13: `@direction` uses the fixed
    // `rdfDirection: i18n-datatype` serialization in this codec (documented
    // subset choice; the compound-literal form is not implemented).
    if let Some(direction) = map.get("@direction") {
        let Value::String(direction) = direction else {
            return Err(JsonLdError::InvalidDocument(
                "@direction must be a string".to_owned(),
            ));
        };
        if direction != "ltr" && direction != "rtl" {
            return Err(JsonLdError::InvalidDocument(format!(
                "invalid base direction `{direction}`"
            )));
        }
        let Value::String(text) = value else {
            return Err(JsonLdError::InvalidDocument(
                "@direction requires a string @value".to_owned(),
            ));
        };
        // The language is lowercased, or empty when absent (an IRI such as
        // `i18n#_rtl` is legitimate per spec section 8.2.2 step 13.1).
        let language = match map.get("@language") {
            None => String::new(),
            Some(Value::String(tag)) => tag.to_lowercase(),
            Some(_) => {
                return Err(JsonLdError::InvalidDocument(
                    "@language must be a string".to_owned(),
                ));
            }
        };
        let datatype = named_node(&format!("{I18N_NAMESPACE}{language}_{direction}"))?;
        return Ok(Literal::new_typed_literal(text.clone(), datatype));
    }
    if let Some(language) = map.get("@language") {
        let (Value::String(text), Value::String(tag)) = (value, language) else {
            return Err(JsonLdError::InvalidDocument(
                "@language requires string @value and tag".to_owned(),
            ));
        };
        // The "Deserialize JSON-LD to RDF" algorithm lowercases the tag.
        return Literal::new_language_tagged_literal(text, tag.to_lowercase())
            .map_err(|error| JsonLdError::InvalidTerm(format!("language tag `{tag}`: {error}")));
    }
    let (lexical, default_datatype) = match value {
        Value::Bool(flag) => (flag.to_string(), XSD_BOOLEAN),
        Value::Number(number) => number_lexical(number, datatype_override == Some(XSD_DOUBLE)),
        Value::String(text) => (text.clone(), XSD_STRING),
        _ => {
            return Err(JsonLdError::InvalidDocument(
                "@value must be a scalar".to_owned(),
            ));
        }
    };
    let datatype = datatype_override.unwrap_or(default_datatype);
    if datatype == XSD_STRING {
        return Ok(Literal::new_simple_literal(lexical));
    }
    Ok(Literal::new_typed_literal(lexical, named_node(datatype)?))
}

/// Converts a JSON number per the spec's data round-tripping rules.
///
/// Integral values with an absolute value below 10^21 become `xsd:integer`;
/// everything else becomes `xsd:double` in canonical exponent form.
fn number_lexical(number: &Number, force_double: bool) -> (String, &'static str) {
    if !force_double {
        if let Some(integer) = number.as_i64() {
            return (integer.to_string(), XSD_INTEGER);
        }
        if let Some(integer) = number.as_u64() {
            return (integer.to_string(), XSD_INTEGER);
        }
        if let Some(float) = number.as_f64()
            && float == float.trunc()
            // Spec threshold: integral doubles below 10^21 stay integers.
            && float.abs() < 1.0e21
        {
            if float == 0.0 {
                return ("0".to_owned(), XSD_INTEGER);
            }
            return (format!("{float:.0}"), XSD_INTEGER);
        }
    }
    let float = number.as_f64().unwrap_or_default();
    (canonical_double(float), XSD_DOUBLE)
}

/// Formats `value` in the canonical `xsd:double` form (`1.0E0` style).
fn canonical_double(value: f64) -> String {
    let formatted = format!("{value:E}");
    match formatted.find('E') {
        Some(position) if !formatted[..position].contains('.') => {
            format!("{}.0{}", &formatted[..position], &formatted[position..])
        }
        _ => formatted,
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_double, number_lexical};

    #[test]
    fn canonical_double_forms() {
        assert_eq!(canonical_double(5.5), "5.5E0");
        assert_eq!(canonical_double(1.0), "1.0E0");
        assert_eq!(canonical_double(0.0), "0.0E0");
        assert_eq!(canonical_double(-2.5e-3), "-2.5E-3");
        assert_eq!(canonical_double(1.0e21), "1.0E21");
    }

    #[test]
    fn number_conversion_rules() {
        let integral = serde_json::Number::from_f64(5.0).expect("finite");
        assert_eq!(
            number_lexical(&integral, false),
            ("5".to_owned(), super::XSD_INTEGER)
        );
        let fractional = serde_json::Number::from_f64(5.5).expect("finite");
        assert_eq!(
            number_lexical(&fractional, false),
            ("5.5E0".to_owned(), super::XSD_DOUBLE)
        );
        let big = serde_json::Number::from_f64(1.0e21).expect("finite");
        assert_eq!(
            number_lexical(&big, false),
            ("1.0E21".to_owned(), super::XSD_DOUBLE)
        );
        let forced = serde_json::Number::from(7);
        assert_eq!(
            number_lexical(&forced, true),
            ("7.0E0".to_owned(), super::XSD_DOUBLE)
        );
    }
}
