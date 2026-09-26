// Rust guideline compliant 2026-02-21
//! Fail-closed refusals: remote contexts, unsupported features, malformed
//! feature use, and resource limits.

use jsonld_fast_core::{
    JsonLdError, JsonLdLimits, JsonLdOptions, JsonLdResource, expand, from_quads, parse_document,
    to_quads,
};
use oxrdf::{GraphName, Literal, NamedNode, Quad};
use quad_fast_core::{QuadBatchBuilder, QuadLimits};
use serde_json::{Value, json};

fn expand_err(document: Value) -> JsonLdError {
    expand(&document, &JsonLdOptions::default()).expect_err("expansion must fail")
}

fn to_quads_err(document: Value) -> JsonLdError {
    to_quads(&document, &JsonLdOptions::default(), None).expect_err("conversion must fail")
}

// ---------------------------------------------------------------------------
// Sovereign boundary: remote contexts stay refused.
// ---------------------------------------------------------------------------

#[test]
fn remote_context_string_is_refused_with_iri() {
    let error = expand_err(json!({
        "@context": "https://schema.org",
        "@id": "http://example.com/it"
    }));
    match error {
        JsonLdError::RemoteContextRefused { iri } => assert_eq!(iri, "https://schema.org"),
        other => panic!("expected RemoteContextRefused, got {other}"),
    }
}

#[test]
fn remote_context_inside_array_is_refused() {
    let error = expand_err(json!({
        "@context": [{"name": "http://example.com/name"}, "https://example.com/ctx"],
        "@id": "http://example.com/it"
    }));
    assert_eq!(error.code(), "remote_context_refused");
}

#[test]
fn context_import_is_refused_with_iri() {
    let error = expand_err(json!({
        "@context": {"@import": "https://example.com/base-context"},
        "@id": "http://example.com/it"
    }));
    match error {
        JsonLdError::RemoteContextRefused { iri } => {
            assert_eq!(iri, "https://example.com/base-context");
        }
        other => panic!("expected RemoteContextRefused, got {other}"),
    }
}

/// A scoped context is validated at definition time (JSON-LD 1.1 API section
/// 4.2.2 step 21.2); a remote scoped context keeps the sovereign refusal
/// identity, including the offending IRI.
#[test]
fn remote_scoped_context_is_refused_with_iri() {
    let error = expand_err(json!({
        "@context": {
            "thing": {
                "@id": "http://example.com/thing",
                "@context": "https://example.com/scoped"
            }
        },
        "@id": "http://example.com/it"
    }));
    match error {
        JsonLdError::RemoteContextRefused { iri } => {
            assert_eq!(iri, "https://example.com/scoped");
        }
        other => panic!("expected RemoteContextRefused, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Malformed containers (spec-invalid combinations are invalid_context).
// ---------------------------------------------------------------------------

/// JSON-LD 1.1 API section 4.2.2 step 19: only specific combinations are
/// valid; everything else is an invalid container mapping.
#[test]
fn invalid_container_combinations_fail_closed() {
    let invalid = [
        json!(["@id", "@type"]),
        json!(["@graph", "@type"]),
        json!(["@list", "@set"]),
        json!(["@language", "@index"]),
        json!([]),
        json!(true),
        json!(["@id", 1]),
        json!("@banana"),
    ];
    for container in invalid {
        let error = expand_err(json!({
            "@context": {
                "p": {"@id": "http://example.com/p", "@container": container}
            },
            "@id": "http://example.com/it"
        }));
        assert_eq!(error.code(), "invalid_context", "container {container}");
    }
}

/// JSON-LD 1.1 API section 4.2.2 step 20: `@index` inside a term
/// definition requires an `@index` container.
#[test]
fn index_mapping_without_index_container_fails_closed() {
    let error = expand_err(json!({
        "@context": {
            "p": {"@id": "http://example.com/p", "@index": "http://example.com/k"}
        },
        "@id": "http://example.com/it"
    }));
    assert_eq!(error.code(), "invalid_context");
}

// ---------------------------------------------------------------------------
// @reverse fail-closed paths.
// ---------------------------------------------------------------------------

/// JSON-LD 1.1 API section 5.1.2 step 13.4.13.1: @reverse must be a map.
#[test]
fn reverse_keyword_requires_a_map() {
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "@reverse": "http://example.com/parent"
    }));
    assert_eq!(error.code(), "invalid_document");
}

/// JSON-LD 1.1 API section 5.1.2 step 13.4.1: keywords are invalid inside a
/// reverse property map.
#[test]
fn keyword_inside_reverse_map_fails_closed() {
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "@reverse": {"@id": "http://example.com/x"}
    }));
    assert_eq!(error.code(), "invalid_document");
}

/// JSON-LD 1.1 API section 5.1.2 step 13.13.4.1: literals cannot be reverse
/// property values (term form and keyword form).
#[test]
fn literal_reverse_values_fail_closed() {
    let error = expand_err(json!({
        "@context": {"children": {"@reverse": "http://example.com/parent"}},
        "@id": "http://example.com/it",
        "children": "just a string"
    }));
    assert_eq!(error.code(), "invalid_document");
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "@reverse": {"http://example.com/parent": {"@value": "v"}}
    }));
    assert_eq!(error.code(), "invalid_document");
}

/// JSON-LD 1.1 API section 4.2.2 step 13.1: @id alongside @reverse is an
/// invalid reverse property. This codec extends the check to every entry
/// the spec would silently ignore (fail-closed deviation).
#[test]
fn reverse_term_definitions_reject_extra_entries() {
    for extra in [
        json!({"@id": "http://example.com/x"}),
        json!({"@type": "@id"}),
    ] {
        let mut definition = extra.as_object().expect("object").clone();
        definition.insert("@reverse".to_owned(), json!("http://example.com/parent"));
        let error = expand_err(json!({
            "@context": {"children": definition},
            "@id": "http://example.com/it"
        }));
        assert_eq!(error.code(), "invalid_context");
    }
}

/// JSON-LD 1.1 API section 4.2.2 step 13.4: reverse properties only support
/// @set and @index containers.
#[test]
fn reverse_term_rejects_list_container() {
    let error = expand_err(json!({
        "@context": {
            "children": {"@reverse": "http://example.com/parent", "@container": "@list"}
        },
        "@id": "http://example.com/it"
    }));
    assert_eq!(error.code(), "invalid_context");
}

/// Blank node reverse predicates are unrepresentable in the quad contract.
#[test]
fn blank_node_reverse_predicates_fail_closed() {
    let error = to_quads_err(json!({
        "@id": "http://example.com/it",
        "@reverse": {"_:p": [{"@id": "http://example.com/kid"}]}
    }));
    assert_eq!(error.code(), "invalid_term");
}

// ---------------------------------------------------------------------------
// @index fail-closed paths.
// ---------------------------------------------------------------------------

/// JSON-LD 1.1 API section 5.1.2 step 13.4.11: @index must be a string.
#[test]
fn non_string_index_fails_closed() {
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "@index": 5
    }));
    assert_eq!(error.code(), "invalid_document");
}

// ---------------------------------------------------------------------------
// Scoped context and @propagate fail-closed paths.
// ---------------------------------------------------------------------------

/// JSON-LD 1.1 API section 4.1.2 step 5.11: @propagate must be a boolean.
#[test]
fn non_boolean_propagate_fails_closed() {
    let error = expand_err(json!({
        "@context": {"@propagate": "yes"},
        "@id": "http://example.com/it"
    }));
    assert_eq!(error.code(), "invalid_context");
}

/// JSON-LD 1.1 API section 4.2.2 step 21.2: scoped contexts are validated at
/// definition time; a malformed one is an invalid scoped context error.
#[test]
fn invalid_scoped_context_fails_at_definition_time() {
    let error = expand_err(json!({
        "@context": {
            "thing": {
                "@id": "http://example.com/thing",
                "@context": {"@version": 2}
            }
        },
        "@id": "http://example.com/it"
    }));
    assert_eq!(error.code(), "invalid_context");
}

// ---------------------------------------------------------------------------
// @direction fail-closed paths.
// ---------------------------------------------------------------------------

/// JSON-LD 1.1 API section 4.1.2 step 5.10: only "ltr", "rtl", null.
#[test]
fn invalid_context_direction_fails_closed() {
    for direction in [json!("up"), json!(5)] {
        let error = expand_err(json!({
            "@context": {"@direction": direction},
            "@id": "http://example.com/it"
        }));
        assert_eq!(error.code(), "invalid_context");
    }
}

/// JSON-LD 1.1 API section 5.1.2 step 13.4.10: invalid base direction.
#[test]
fn invalid_value_object_direction_fails_closed() {
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "http://example.com/p": {"@value": "x", "@direction": "up"}
    }));
    assert_eq!(error.code(), "invalid_document");
}

/// JSON-LD 1.1 API section 5.1.2 step 15.1: @type excludes @direction.
#[test]
fn value_object_with_type_and_direction_is_invalid() {
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "http://example.com/p": {
            "@value": "x",
            "@type": "http://example.com/T",
            "@direction": "rtl"
        }
    }));
    assert_eq!(error.code(), "invalid_document");
}

/// JSON-LD 1.1 API section 4.2.2 step 22: @direction with @type in a term
/// definition is rejected.
#[test]
fn term_with_type_and_direction_fails_closed() {
    let error = expand_err(json!({
        "@context": {
            "p": {"@id": "http://example.com/p", "@type": "@id", "@direction": "rtl"}
        },
        "@id": "http://example.com/it"
    }));
    assert_eq!(error.code(), "invalid_context");
}

// ---------------------------------------------------------------------------
// @nest and @included fail-closed paths.
// ---------------------------------------------------------------------------

/// JSON-LD 1.1 API section 5.1.2 step 14.2: nested values must be maps that
/// do not contain @value.
#[test]
fn nest_values_must_be_value_free_maps() {
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "@nest": "scalar"
    }));
    assert_eq!(error.code(), "invalid_document");
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "@nest": {"@value": "v"}
    }));
    assert_eq!(error.code(), "invalid_document");
}

/// JSON-LD 1.1 API section 4.2.2 step 23.2: a term's @nest entry must be
/// @nest or a non-keyword.
#[test]
fn nest_term_entry_rejects_other_keywords() {
    let error = expand_err(json!({
        "@context": {
            "p": {"@id": "http://example.com/p", "@nest": "@id"}
        },
        "@id": "http://example.com/it"
    }));
    assert_eq!(error.code(), "invalid_context");
}

/// JSON-LD 1.1 API section 5.1.2 step 13.4.7.2: @included values must be
/// node objects; content that expands to nothing is also rejected here
/// (fail-closed deviation from the spec's silent drop).
#[test]
fn included_values_must_be_node_objects() {
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "@included": "scalar"
    }));
    assert_eq!(error.code(), "invalid_document");
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "@included": {"@value": "v"}
    }));
    assert_eq!(error.code(), "invalid_document");
}

// ---------------------------------------------------------------------------
// @json fail-closed paths.
// ---------------------------------------------------------------------------

/// Fail-closed extension: @json is only valid as a value object @type.
#[test]
fn json_as_node_type_fails_closed() {
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "@type": "@json",
        "http://example.com/p": "v"
    }));
    assert_eq!(error.code(), "invalid_document");
}

/// RFC 8785 treats all numbers as IEEE 754 doubles; integers outside exact
/// double range fail closed instead of silently changing value.
#[test]
fn json_literal_lossy_integer_fails_closed() {
    let error = to_quads_err(json!({
        "@context": {"blob": {"@id": "http://example.com/blob", "@type": "@json"}},
        "@id": "http://example.com/it",
        "blob": {"n": 9_007_199_254_740_993_i64}
    }));
    assert_eq!(error.code(), "invalid_term");
}

/// Builds one quad batch with a single literal object of `datatype`.
fn literal_batch(lexical: &str, datatype: &str) -> Vec<arrow_array::RecordBatch> {
    let quad = Quad::new(
        NamedNode::new("http://example.com/s").expect("valid IRI"),
        NamedNode::new("http://example.com/p").expect("valid IRI"),
        Literal::new_typed_literal(
            lexical,
            NamedNode::new(datatype).expect("valid datatype IRI"),
        ),
        GraphName::DefaultGraph,
    );
    let mut builder = QuadBatchBuilder::new(quad_fast_core::QuadLimits::default());
    builder.push(quad.as_ref(), None).expect("push succeeds");
    vec![builder.finish().expect("finish succeeds")]
}

/// JSON-LD 1.1 API section 8.5.2 step 2.4.3: a lexical form that is not
/// valid JSON is an *invalid JSON literal* error, never a silent pass-through.
#[test]
fn invalid_json_literal_lexical_form_fails_closed() {
    let batches = literal_batch(
        "{not json",
        "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON",
    );
    let error = from_quads(&batches).expect_err("invalid JSON literal must fail");
    assert_eq!(error.code(), "invalid_term");
}

/// Fail-closed extension of API section 8.5.2 step 2.4.4: an i18n datatype
/// whose fragment does not decode to `<language>_<direction>` is an error,
/// not an opaque pass-through.
#[test]
fn malformed_i18n_datatype_fails_closed() {
    for datatype in [
        "https://www.w3.org/ns/i18n#nodirection",
        "https://www.w3.org/ns/i18n#en_up",
    ] {
        let batches = literal_batch("x", datatype);
        let error = from_quads(&batches).expect_err("malformed i18n datatype must fail");
        assert_eq!(error.code(), "invalid_term", "datatype {datatype}");
    }
}

// ---------------------------------------------------------------------------
// Container map fail-closed paths.
// ---------------------------------------------------------------------------

/// Fail-closed extension: the spec would attach @id / @type to value
/// objects inside id/type maps, producing output that is invalid downstream.
#[test]
fn value_objects_inside_id_and_type_maps_fail_closed() {
    let error = expand_err(json!({
        "@context": {
            "byId": {"@id": "http://example.com/byId", "@container": "@id"}
        },
        "@id": "http://example.com/it",
        "byId": {"http://example.com/k": "plain string"}
    }));
    assert_eq!(error.code(), "invalid_document");
    // Note: a bare string in a @type map coerces to a node reference (the
    // @type container forces an @id type mapping, API section 4.2.2 step
    // 19.4), so an explicit value object is needed to hit this path.
    let error = expand_err(json!({
        "@context": {
            "byType": {"@id": "http://example.com/byType", "@container": "@type"}
        },
        "@id": "http://example.com/it",
        "byType": {"http://example.com/T": {"@value": "plain string"}}
    }));
    assert_eq!(error.code(), "invalid_document");
}

// ---------------------------------------------------------------------------
// Structural validation.
// ---------------------------------------------------------------------------

/// JSON-LD 1.1 API section 5.1.2 step 13.4.2: colliding keywords.
#[test]
fn colliding_keywords_fail_closed() {
    let error = expand_err(json!({
        "@context": {"id": "@id"},
        "id": "http://example.com/a",
        "@id": "http://example.com/b"
    }));
    assert_eq!(error.code(), "invalid_document");
}

/// JSON-LD 1.1 API section 5.1.2 step 17.1: a @set or @list object allows at
/// most one other entry, which must be @index.
#[test]
fn set_and_list_reject_entries_other_than_index() {
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "http://example.com/p": {"@set": ["a"], "@id": "http://example.com/x"}
    }));
    assert_eq!(error.code(), "invalid_document");
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "http://example.com/p": {"@list": ["a"], "@id": "http://example.com/x"}
    }));
    assert_eq!(error.code(), "invalid_document");
}

#[test]
fn protected_term_conflicts_are_refused() {
    let error = expand_err(json!({
        "@context": [
            {"@protected": true, "name": "http://example.com/name"},
            {"name": "http://example.com/other"}
        ],
        "@id": "http://example.com/it"
    }));
    match error {
        JsonLdError::ProtectedTermRedefinition { term } => assert_eq!(term, "name"),
        other => panic!("expected ProtectedTermRedefinition, got {other}"),
    }
}

#[test]
fn protected_context_cannot_be_nullified() {
    let error = expand_err(json!({
        "@context": [
            {"@protected": true, "name": "http://example.com/name"},
            null
        ],
        "@id": "http://example.com/it"
    }));
    assert_eq!(error.code(), "invalid_context");
}

#[test]
fn input_byte_budget_fails_closed() {
    let limits = JsonLdLimits {
        max_input_bytes: 8,
        ..JsonLdLimits::default()
    };
    let error = parse_document("{\"@id\": \"http://example.com/it\"}", &limits)
        .expect_err("oversized input must fail");
    match error {
        JsonLdError::ResourceLimit {
            resource, limit, ..
        } => {
            assert_eq!(resource, JsonLdResource::InputBytes);
            assert_eq!(limit, 8);
        }
        other => panic!("expected ResourceLimit, got {other}"),
    }
}

#[test]
fn node_budget_fails_closed() {
    let options = JsonLdOptions {
        limits: JsonLdLimits {
            max_nodes: 4,
            ..JsonLdLimits::default()
        },
        ..JsonLdOptions::default()
    };
    let document = json!({
        "@id": "http://example.com/it",
        "http://example.com/p": ["a", "b", "c", "d", "e"]
    });
    let error = expand(&document, &options).expect_err("node budget must fail");
    assert!(matches!(
        error,
        JsonLdError::ResourceLimit {
            resource: JsonLdResource::Nodes,
            ..
        }
    ));
}

#[test]
fn depth_budget_fails_closed() {
    let options = JsonLdOptions {
        limits: JsonLdLimits {
            max_depth: 2,
            ..JsonLdLimits::default()
        },
        ..JsonLdOptions::default()
    };
    let document = json!({
        "@id": "http://example.com/a",
        "http://example.com/p": {
            "@id": "http://example.com/b",
            "http://example.com/p": {
                "@id": "http://example.com/c",
                "http://example.com/p": {"@id": "http://example.com/d"}
            }
        }
    });
    let error = expand(&document, &options).expect_err("depth budget must fail");
    assert!(matches!(
        error,
        JsonLdError::ResourceLimit {
            resource: JsonLdResource::Depth,
            ..
        }
    ));
}

#[test]
fn quad_budget_fails_closed() {
    let options = JsonLdOptions {
        quad_limits: QuadLimits {
            max_quads: 1,
            ..QuadLimits::default()
        },
        ..JsonLdOptions::default()
    };
    let document = json!({
        "@id": "http://example.com/it",
        "http://example.com/p": ["a", "b"]
    });
    let error = to_quads(&document, &options, None).expect_err("quad budget must fail");
    assert_eq!(error.code(), "quad");
}

#[test]
fn keywords_cannot_be_redefined() {
    let error = expand_err(json!({
        "@context": {"@id": "http://example.com/id"},
        "@id": "http://example.com/it"
    }));
    assert_eq!(error.code(), "invalid_context");
}

#[test]
fn invalid_version_is_refused() {
    let error = expand_err(json!({
        "@context": {"@version": 1.0},
        "@id": "http://example.com/it"
    }));
    assert_eq!(error.code(), "invalid_context");
}

#[test]
fn value_object_with_type_and_language_is_invalid() {
    let error = expand_err(json!({
        "@id": "http://example.com/it",
        "http://example.com/p": {
            "@value": "x",
            "@type": "http://example.com/T",
            "@language": "en"
        }
    }));
    assert_eq!(error.code(), "invalid_document");
}

#[test]
fn malformed_json_is_refused() {
    let error = parse_document("{not json", &JsonLdLimits::default())
        .expect_err("malformed JSON must fail");
    assert_eq!(error.code(), "invalid_json");
}
