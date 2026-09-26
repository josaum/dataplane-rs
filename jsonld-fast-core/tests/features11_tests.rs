// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! JSON-LD 1.1 feature coverage: `@reverse`, `@index` containers, language
//! maps, property-based `@index`, scoped contexts with `@propagate`,
//! `@id`/`@type`/`@graph` container maps, `@type: @json`, `@direction`,
//! `@nest`, and `@included`.
//!
//! Tests are anchored to the JSON-LD 1.1 syntax specification (section
//! numbers in comments) and the JSON-LD 1.1 Processing Algorithms and API
//! (expansion section 5.1.2, RDF conversion sections 8.1-8.6).

use arrow_array::RecordBatch;
use jsonld_fast_core::{JsonLdOptions, expand, from_quads, to_quads};
use quad_fast_core::QuadStreamReader;
use serde_json::{Value, json};

fn expand_ok(document: Value) -> Value {
    expand(&document, &JsonLdOptions::default()).expect("expansion succeeds")
}

fn quads(document: &Value) -> Vec<RecordBatch> {
    to_quads(document, &JsonLdOptions::default(), None).expect("deserialization succeeds")
}

/// Renders every quad of `batches` as an N-Quads-style line, sorted.
fn quad_lines(batches: &[RecordBatch]) -> Vec<String> {
    let mut lines = Vec::new();
    for batch in batches {
        let reader = QuadStreamReader::new(batch).expect("valid batch");
        for row in 0..reader.len() {
            lines.push(reader.quad(row).expect("valid quad").to_string());
        }
    }
    lines.sort();
    lines
}

fn assert_expected_lines(batches: &[RecordBatch], expected: &[&str]) {
    let mut expected: Vec<String> = expected.iter().map(ToString::to_string).collect();
    expected.sort();
    assert_eq!(quad_lines(batches), expected);
}

// ===========================================================================
// 1. @reverse (JSON-LD 1.1 section 4.8; API section 5.1.2 steps 13.4.13 and
//    13.13)
// ===========================================================================

#[test]
fn reverse_term_definition_expands_to_reverse_map() {
    let expanded = expand_ok(json!({
        "@context": {"children": {"@reverse": "http://example.com/parent"}},
        "@id": "http://example.com/it",
        "children": [{"@id": "http://example.com/kid"}]
    }));
    assert_eq!(
        expanded,
        json!([{
            "@id": "http://example.com/it",
            "@reverse": {
                "http://example.com/parent": [{"@id": "http://example.com/kid"}]
            }
        }])
    );
}

#[test]
fn reverse_keyword_expands_to_reverse_map() {
    let expanded = expand_ok(json!({
        "@id": "http://example.com/it",
        "@reverse": {
            "http://example.com/parent": {"@id": "http://example.com/kid"}
        }
    }));
    assert_eq!(
        expanded[0]["@reverse"]["http://example.com/parent"],
        json!([{"@id": "http://example.com/kid"}])
    );
}

/// API section 5.1.2 step 13.4.13.3: a reverse term inside @reverse flips
/// back to a forward property.
#[test]
fn double_reverse_becomes_forward_property() {
    let expanded = expand_ok(json!({
        "@context": {"kids": {"@reverse": "http://example.com/parent"}},
        "@id": "http://example.com/it",
        "@reverse": {"kids": {"@id": "http://example.com/x"}}
    }));
    assert_eq!(
        expanded,
        json!([{
            "@id": "http://example.com/it",
            "http://example.com/parent": [{"@id": "http://example.com/x"}]
        }])
    );
}

/// API section 8.1: reverse properties emit inverted triples.
#[test]
fn reverse_properties_emit_inverted_quads() {
    let batches = quads(&json!({
        "@context": {"children": {"@reverse": "http://example.com/parent", "@container": "@set"}},
        "@id": "http://example.com/it",
        "children": [{"@id": "http://example.com/kid"}, {"@id": "http://example.com/kid2"}]
    }));
    assert_expected_lines(
        &batches,
        &[
            "<http://example.com/kid> <http://example.com/parent> <http://example.com/it>",
            "<http://example.com/kid2> <http://example.com/parent> <http://example.com/it>",
        ],
    );
}

#[test]
fn reverse_round_trip_preserves_quads() {
    let document = json!({
        "@id": "http://example.com/it",
        "http://example.com/name": "root",
        "@reverse": {
            "http://example.com/parent": {
                "@id": "http://example.com/kid",
                "http://example.com/name": "leaf"
            }
        }
    });
    let first = quads(&document);
    let serialized = from_quads(&first).expect("serialization succeeds");
    let second = quads(&serialized);
    assert_eq!(quad_lines(&first), quad_lines(&second));
}

// ===========================================================================
// 2. @index containers (JSON-LD 1.1 section 4.6.1; API section 5.1.2 step
//    13.8.3.7.4)
// ===========================================================================

#[test]
fn index_maps_preserve_indexes_through_expansion() {
    let expanded = expand_ok(json!({
        "@context": {
            "post": {"@id": "http://schema.org/blogPost", "@container": "@index"}
        },
        "@id": "http://example.com/blog",
        "post": {
            "en": {"@id": "http://example.com/1", "http://schema.org/name": "post 1"},
            "@none": {"@id": "http://example.com/2"}
        }
    }));
    // Map keys process in lexicographical order: "@none" sorts before "en".
    assert_eq!(
        expanded[0]["http://schema.org/blogPost"],
        json!([
            {"@id": "http://example.com/2"},
            {
                "@id": "http://example.com/1",
                "@index": "en",
                "http://schema.org/name": [{"@value": "post 1"}]
            }
        ])
    );
}

/// API section 5.1.2 step 13.8.3.7.4: an existing @index wins over the key.
#[test]
fn existing_index_entry_is_not_overwritten() {
    let expanded = expand_ok(json!({
        "@context": {
            "post": {"@id": "http://schema.org/blogPost", "@container": ["@index", "@set"]}
        },
        "@id": "http://example.com/blog",
        "post": {"en": {"@id": "http://example.com/1", "@index": "own"}}
    }));
    assert_eq!(
        expanded[0]["http://schema.org/blogPost"][0]["@index"],
        "own"
    );
}

/// API section 5.1.2 step 13.4.11: explicit @index entries survive
/// expansion on node objects and value objects.
#[test]
fn explicit_index_entries_survive_expansion() {
    let expanded = expand_ok(json!({
        "@id": "http://example.com/it",
        "@index": "node-level",
        "http://example.com/p": {"@value": "x", "@index": "value-level"}
    }));
    assert_eq!(expanded[0]["@index"], "node-level");
    assert_eq!(
        expanded[0]["http://example.com/p"][0],
        json!({"@index": "value-level", "@value": "x"})
    );
}

/// API section 8.1.2: @index has no RDF representation and is dropped
/// (spec-mandated drop, not a silent failure).
#[test]
fn index_is_dropped_when_converting_to_rdf() {
    let batches = quads(&json!({
        "@context": {
            "post": {"@id": "http://schema.org/blogPost", "@container": "@index"}
        },
        "@id": "http://example.com/blog",
        "post": {"en": {"@id": "http://example.com/1"}}
    }));
    assert_expected_lines(
        &batches,
        &["<http://example.com/blog> <http://schema.org/blogPost> <http://example.com/1>"],
    );
}

/// A list object may carry @index (API section 5.1.2 step 17.1).
#[test]
fn list_objects_may_carry_an_index() {
    let expanded = expand_ok(json!({
        "@id": "http://example.com/it",
        "http://example.com/p": {"@list": ["a"], "@index": "i"}
    }));
    assert_eq!(
        expanded[0]["http://example.com/p"][0],
        json!({"@index": "i", "@list": [{"@value": "a"}]})
    );
}

// ===========================================================================
// 2b. Language maps (JSON-LD 1.1 section 4.6.2; API section 5.1.2 step 13.8)
// ===========================================================================

#[test]
fn language_maps_expand_keys_to_language_tags() {
    let expanded = expand_ok(json!({
        "@context": {
            "label": {"@id": "http://example.com/label", "@container": "@language"}
        },
        "@id": "http://example.com/it",
        "label": {
            "en": "The Queen",
            "de": "Die Königin",
            "@none": "untitled"
        }
    }));
    assert_eq!(
        expanded[0]["http://example.com/label"],
        json!([
            {"@value": "untitled"},
            {"@language": "de", "@value": "Die Königin"},
            {"@language": "en", "@value": "The Queen"}
        ])
    );
}

#[test]
fn language_map_with_set_keeps_arrays() {
    let expanded = expand_ok(json!({
        "@context": {
            "label": {
                "@id": "http://example.com/label",
                "@container": ["@language", "@set"]
            }
        },
        "label": {"en": ["a", "b"]}
    }));
    assert_eq!(
        expanded[0]["http://example.com/label"],
        json!([
            {"@language": "en", "@value": "a"},
            {"@language": "en", "@value": "b"}
        ])
    );
}

#[test]
fn language_map_rejects_non_string_values() {
    let error = expand(
        &json!({
            "@context": {
                "label": {"@id": "http://example.com/label", "@container": "@language"}
            },
            "label": {"en": {"@id": "http://example.com/not-a-string"}}
        }),
        &JsonLdOptions::default(),
    )
    .expect_err("node objects are not language-map values");
    assert_eq!(error.code(), "invalid_document");
}

// ===========================================================================
// 2c. Property-based indexing (JSON-LD 1.1 section 4.6.1.1)
// ===========================================================================

#[test]
fn property_based_index_becomes_a_property() {
    let expanded = expand_ok(json!({
        "@context": {
            "post": {
                "@id": "http://schema.org/blogPost",
                "@container": "@index",
                "@index": "http://schema.org/datePublished"
            }
        },
        "@id": "http://example.com/blog",
        "post": {
            "2026": {"@id": "http://example.com/1"}
        }
    }));
    assert_eq!(
        expanded[0]["http://schema.org/blogPost"],
        json!([{
            "@id": "http://example.com/1",
            "http://schema.org/datePublished": [{"@value": "2026"}]
        }])
    );
}

#[test]
fn property_based_index_term_expands_against_the_context() {
    let expanded = expand_ok(json!({
        "@context": {
            "datePublished": "http://schema.org/datePublished",
            "post": {
                "@id": "http://schema.org/blogPost",
                "@container": "@index",
                "@index": "datePublished"
            }
        },
        "post": {"2026": {"@id": "http://example.com/1"}}
    }));
    assert_eq!(
        expanded[0]["http://schema.org/blogPost"][0]["http://schema.org/datePublished"],
        json!([{"@value": "2026"}])
    );
}

// ===========================================================================
// 3. Scoped contexts and @propagate (JSON-LD 1.1 sections 4.1.8 and 4.1.9)
// ===========================================================================

/// Section 4.1.8: a property-scoped context applies to the values of the
/// term and, by default, propagates into deeper nodes.
#[test]
fn property_scoped_context_applies_to_values() {
    let expanded = expand_ok(json!({
        "@context": {
            "@vocab": "http://example.com/v/",
            "detail": {
                "@id": "http://example.com/detail",
                "@context": {"@vocab": "http://example.com/detail/"}
            }
        },
        "@id": "http://example.com/it",
        "detail": {
            "@id": "http://example.com/d",
            "name": "n",
            "deeper": {"@id": "http://example.com/dd", "name": "m"}
        }
    }));
    let detail = &expanded[0]["http://example.com/detail"][0];
    assert_eq!(detail["http://example.com/detail/name"][0]["@value"], "n");
    let deeper = &detail["http://example.com/detail/deeper"][0];
    assert_eq!(
        deeper["http://example.com/detail/name"][0]["@value"], "m",
        "property-scoped contexts propagate by default"
    );
}

/// Section 4.1.8: a property-scoped context is applied to scalar values of
/// the term as well (API section 5.1.2 step 4.2).
#[test]
fn property_scoped_context_applies_to_scalar_values() {
    let expanded = expand_ok(json!({
        "@context": {
            "label": {
                "@id": "http://example.com/label",
                "@context": {"@language": "de"}
            }
        },
        "@id": "http://example.com/it",
        "label": "hallo"
    }));
    assert_eq!(
        expanded[0]["http://example.com/label"][0],
        json!({"@language": "de", "@value": "hallo"})
    );
}

/// Section 4.1.9: type-scoped contexts do not propagate by default; the
/// previous context is restored when a new node object is entered.
#[test]
fn type_scoped_context_reverts_on_new_node_objects() {
    let expanded = expand_ok(json!({
        "@context": {
            "@vocab": "http://example.com/v/",
            "Person": {
                "@id": "http://example.com/Person",
                "@context": {"knows": {"@id": "http://example.com/knows"}}
            }
        },
        "@id": "http://example.com/a",
        "@type": "Person",
        "knows": {"@id": "http://example.com/b", "knows": "x"}
    }));
    let outer = &expanded[0];
    assert_eq!(outer["@type"], json!(["http://example.com/Person"]));
    let inner = &outer["http://example.com/knows"][0];
    assert_eq!(inner["@id"], "http://example.com/b");
    assert_eq!(
        inner["http://example.com/v/knows"][0]["@value"], "x",
        "the type-scoped term definition must not leak into the inner node"
    );
}

/// Section 4.1.9: `"@propagate": true` keeps a type-scoped context alive in
/// nested node objects.
#[test]
fn type_scoped_context_with_propagate_true_survives() {
    let expanded = expand_ok(json!({
        "@context": {
            "@vocab": "http://example.com/v/",
            "Person": {
                "@id": "http://example.com/Person",
                "@context": {
                    "@propagate": true,
                    "knows": {"@id": "http://example.com/knows"}
                }
            }
        },
        "@id": "http://example.com/a",
        "@type": "Person",
        "knows": {"@id": "http://example.com/b", "knows": {"@id": "http://example.com/c"}}
    }));
    let inner = &expanded[0]["http://example.com/knows"][0];
    assert!(
        inner.get("http://example.com/knows").is_some(),
        "propagate: true keeps the scoped term alive: {inner}"
    );
}

/// Section 4.1.9: `"@propagate": false` on a plain embedded context makes
/// it revert when the next node object is entered.
#[test]
fn embedded_context_with_propagate_false_reverts() {
    let expanded = expand_ok(json!({
        "@context": {"@vocab": "http://example.com/v/"},
        "@id": "http://example.com/a",
        "http://example.com/child": {
            "@context": {"@propagate": false, "name": "http://example.com/name"},
            "@id": "http://example.com/b",
            "name": "direct",
            "http://example.com/grand": {
                "@id": "http://example.com/c",
                "name": "reverted"
            }
        }
    }));
    let child = &expanded[0]["http://example.com/child"][0];
    assert_eq!(child["http://example.com/name"][0]["@value"], "direct");
    let grand = &child["http://example.com/grand"][0];
    assert_eq!(
        grand["http://example.com/v/name"][0]["@value"], "reverted",
        "the non-propagated definition must not survive into the grandchild"
    );
}

/// Section 4.1.11 with 4.1.8: property-scoped contexts may override
/// protected terms (override protected is true, API section 5.1.2 step 9).
#[test]
fn property_scoped_context_overrides_protected_terms() {
    let expanded = expand_ok(json!({
        "@context": {
            "@protected": true,
            "name": "http://example.com/name",
            "detail": {
                "@id": "http://example.com/detail",
                "@context": {"name": "http://example.com/other"}
            }
        },
        "@id": "http://example.com/it",
        "name": "outer",
        "detail": {"@id": "http://example.com/d", "name": "inner"}
    }));
    let node = &expanded[0];
    assert_eq!(node["http://example.com/name"][0]["@value"], "outer");
    let detail = &node["http://example.com/detail"][0];
    assert_eq!(detail["http://example.com/other"][0]["@value"], "inner");
}

// ===========================================================================
// 4. Container maps: @id, @type, @graph (JSON-LD 1.1 sections 4.6.3, 4.6.4,
//    4.9.1-4.9.3; API section 5.1.2 steps 13.8 and 13.11)
// ===========================================================================

/// Section 4.6.3 (node identifier indexing): map keys become @id values.
#[test]
fn id_maps_supply_node_identifiers() {
    let expanded = expand_ok(json!({
        "@context": {
            "post": {"@id": "http://schema.org/blogPost", "@container": "@id"}
        },
        "@id": "http://example.com/blog",
        "post": {
            "http://example.com/1": {"http://schema.org/name": "p1"},
            "@none": {"http://schema.org/name": "p3"}
        }
    }));
    assert_eq!(
        expanded[0]["http://schema.org/blogPost"],
        json!([
            {"http://schema.org/name": [{"@value": "p3"}]},
            {
                "@id": "http://example.com/1",
                "http://schema.org/name": [{"@value": "p1"}]
            }
        ])
    );
}

/// Section 4.6.3: an existing @id wins over the map key.
#[test]
fn id_maps_do_not_overwrite_existing_ids() {
    let expanded = expand_ok(json!({
        "@context": {
            "post": {"@id": "http://schema.org/blogPost", "@container": ["@id", "@set"]}
        },
        "@id": "http://example.com/blog",
        "post": {
            "http://example.com/key": {"@id": "http://example.com/own"}
        }
    }));
    assert_eq!(
        expanded[0]["http://schema.org/blogPost"][0]["@id"],
        "http://example.com/own"
    );
}

/// Section 4.6.4 (node type indexing): map keys prepend to @type,
/// vocabulary-expanded.
#[test]
fn type_maps_prepend_expanded_types() {
    let expanded = expand_ok(json!({
        "@context": {
            "@vocab": "http://example.com/v/",
            "stuff": {"@id": "http://example.com/stuff", "@container": ["@type", "@set"]}
        },
        "@id": "http://example.com/it",
        "stuff": {
            "Widget": {"@id": "http://example.com/w", "@type": "Existing"}
        }
    }));
    assert_eq!(
        expanded[0]["http://example.com/stuff"][0]["@type"],
        json!([
            "http://example.com/v/Widget",
            "http://example.com/v/Existing"
        ])
    );
}

/// Section 4.9.1 (graph containers): each value wraps in a graph object;
/// section 8.1: the anonymous graph gets a blank node name shared by the
/// referencing triple.
#[test]
fn graph_containers_wrap_values_and_emit_named_graphs() {
    let document = json!({
        "@context": {
            "claims": {"@id": "http://example.com/claims", "@container": "@graph"}
        },
        "@id": "http://example.com/it",
        "claims": {"@id": "http://example.com/s", "http://example.com/p": "v"}
    });
    let expanded = expand_ok(document.clone());
    assert_eq!(
        expanded[0]["http://example.com/claims"][0]["@graph"][0]["@id"],
        "http://example.com/s"
    );
    let batches = quads(&document);
    assert_expected_lines(
        &batches,
        &[
            "<http://example.com/it> <http://example.com/claims> _:b0",
            "<http://example.com/s> <http://example.com/p> \"v\" _:b0",
        ],
    );
}

/// Section 4.9.3 (named graph indexing by identifier): @graph + @id maps
/// name the graph from the map key.
#[test]
fn graph_id_maps_name_graphs_from_keys() {
    let document = json!({
        "@context": {
            "claims": {"@id": "http://example.com/claims", "@container": ["@graph", "@id"]}
        },
        "@id": "http://example.com/it",
        "claims": {
            "http://example.com/g1": {"@id": "http://example.com/s", "http://example.com/p": "v"}
        }
    });
    let batches = quads(&document);
    assert_expected_lines(
        &batches,
        &[
            "<http://example.com/it> <http://example.com/claims> <http://example.com/g1>",
            "<http://example.com/s> <http://example.com/p> \"v\" <http://example.com/g1>",
        ],
    );
}

/// Section 4.9.2 (named graph data indexing): @graph + @index maps keep the
/// index through expansion and drop it in RDF.
#[test]
fn graph_index_maps_keep_index_in_expansion() {
    let document = json!({
        "@context": {
            "claims": {"@id": "http://example.com/claims", "@container": ["@graph", "@index"]}
        },
        "@id": "http://example.com/it",
        "claims": {
            "batch-1": {"@id": "http://example.com/s", "http://example.com/p": "v"}
        }
    });
    let expanded = expand_ok(document.clone());
    let claim = &expanded[0]["http://example.com/claims"][0];
    assert_eq!(claim["@index"], "batch-1");
    assert_eq!(claim["@graph"][0]["@id"], "http://example.com/s");
    let batches = quads(&document);
    assert_expected_lines(
        &batches,
        &[
            "<http://example.com/it> <http://example.com/claims> _:b0",
            "<http://example.com/s> <http://example.com/p> \"v\" _:b0",
        ],
    );
}

// ===========================================================================
// 5. @type: @json (JSON-LD 1.1 sections 4.2.2 and 10.2; API sections 8.2.2
//    step 8 and 8.5.2 step 2.4.3)
// ===========================================================================

#[test]
fn json_typed_terms_expand_to_json_value_objects() {
    let expanded = expand_ok(json!({
        "@context": {"blob": {"@id": "http://example.com/blob", "@type": "@json"}},
        "@id": "http://example.com/it",
        "blob": {"b": 2, "a": [1.5, true, null, "x"]}
    }));
    assert_eq!(
        expanded[0]["http://example.com/blob"][0],
        json!({
            "@type": "@json",
            "@value": {"b": 2, "a": [1.5, true, null, "x"]}
        })
    );
}

/// Section 10.2: the rdf:JSON lexical form has sorted keys, no whitespace,
/// and ECMAScript number serialization.
#[test]
fn json_literals_serialize_canonically_to_rdf() {
    let batches = quads(&json!({
        "@context": {"blob": {"@id": "http://example.com/blob", "@type": "@json"}},
        "@id": "http://example.com/it",
        "blob": {"b": 2, "a": [1.5, true, null, "x"]}
    }));
    let lines = quad_lines(&batches);
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].contains(
            "\"{\\\"a\\\":[1.5,true,null,\\\"x\\\"],\\\"b\\\":2}\"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON>"
        ),
        "unexpected literal: {}",
        lines[0]
    );
}

/// API section 8.5.2 step 2.4.3: rdf:JSON literals decode back into
/// @type: @json value objects, enabling round trips.
#[test]
fn json_literal_round_trip_preserves_quads() {
    let document = json!({
        "@id": "http://example.com/it",
        "http://example.com/blob": {"@value": {"z": [1, 2], "a": "x"}, "@type": "@json"}
    });
    let first = quads(&document);
    let serialized = from_quads(&first).expect("serialization succeeds");
    assert_eq!(
        serialized[0]["http://example.com/blob"][0]["@type"],
        "@json"
    );
    let second = quads(&serialized);
    assert_eq!(quad_lines(&first), quad_lines(&second));
}

#[test]
fn json_literal_expansion_is_idempotent() {
    let document = json!({
        "@context": {"blob": {"@id": "http://example.com/blob", "@type": "@json"}},
        "@id": "http://example.com/it",
        "blob": [true, {"k": "v"}]
    });
    let options = JsonLdOptions::default();
    let once = expand(&document, &options).expect("first expansion");
    let twice = expand(&once, &options).expect("second expansion");
    assert_eq!(once, twice);
}

// ===========================================================================
// 6. @direction (JSON-LD 1.1 section 4.2.4.1 and 10.3; API section 8.2.2
//    step 13, rdfDirection: i18n-datatype)
// ===========================================================================

#[test]
fn default_and_per_term_direction() {
    let expanded = expand_ok(json!({
        "@context": {
            "@language": "ar",
            "@direction": "rtl",
            "title": "http://example.com/title",
            "ltrTerm": {"@id": "http://example.com/ltr", "@direction": "ltr"},
            "noDir": {"@id": "http://example.com/nodir", "@direction": null}
        },
        "@id": "http://example.com/it",
        "title": "عنوان",
        "ltrTerm": "left",
        "noDir": "plain"
    }));
    let node = &expanded[0];
    assert_eq!(
        node["http://example.com/title"][0],
        json!({"@direction": "rtl", "@language": "ar", "@value": "عنوان"})
    );
    assert_eq!(node["http://example.com/ltr"][0]["@direction"], "ltr");
    assert!(
        node["http://example.com/nodir"][0]
            .get("@direction")
            .is_none()
    );
}

/// Section 10.3: the i18n datatype encodes lowercased language and
/// direction; without a language the tag part is empty (`i18n#_rtl`).
#[test]
fn direction_serializes_as_i18n_datatype() {
    let batches = quads(&json!({
        "@id": "http://example.com/it",
        "http://example.com/a": {"@value": "x", "@language": "en-US", "@direction": "ltr"},
        "http://example.com/b": {"@value": "y", "@direction": "rtl"}
    }));
    let lines = quad_lines(&batches);
    assert!(
        lines
            .iter()
            .any(|line| line.contains("\"x\"^^<https://www.w3.org/ns/i18n#en-us_ltr>")),
        "missing i18n datatype with language: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("\"y\"^^<https://www.w3.org/ns/i18n#_rtl>")),
        "missing i18n datatype without language: {lines:?}"
    );
}

/// API section 8.5.2 step 2.4.4: i18n datatypes decode back into
/// @language/@direction entries, enabling round trips.
#[test]
fn direction_round_trip_preserves_quads() {
    let document = json!({
        "@id": "http://example.com/it",
        "http://example.com/a": {"@value": "x", "@language": "en", "@direction": "ltr"},
        "http://example.com/b": {"@value": "y", "@direction": "rtl"}
    });
    let first = quads(&document);
    let serialized = from_quads(&first).expect("serialization succeeds");
    assert_eq!(
        serialized[0]["http://example.com/a"][0],
        json!({"@direction": "ltr", "@language": "en", "@value": "x"})
    );
    assert_eq!(
        serialized[0]["http://example.com/b"][0],
        json!({"@direction": "rtl", "@value": "y"})
    );
    let second = quads(&serialized);
    assert_eq!(quad_lines(&first), quad_lines(&second));
}

// ===========================================================================
// 7. @nest and @included (JSON-LD 1.1 sections 4.4 and 4.7; API section
//    5.1.2 steps 13.4.7, 13.4.14, and 14)
// ===========================================================================

/// Section 4.4: nested properties unfold into the enclosing node.
#[test]
fn nest_unfolds_into_the_node() {
    let expanded = expand_ok(json!({
        "@context": {"@vocab": "http://example.com/v/"},
        "@id": "http://example.com/it",
        "name": "outer",
        "@nest": {
            "inner": "value",
            "@nest": {"deeper": "deep value"}
        }
    }));
    let node = &expanded[0];
    assert_eq!(node["http://example.com/v/name"][0]["@value"], "outer");
    assert_eq!(node["http://example.com/v/inner"][0]["@value"], "value");
    assert_eq!(
        node["http://example.com/v/deeper"][0]["@value"],
        "deep value"
    );
}

/// Section 4.4: terms may alias @nest ("@nest": "@nest" term definitions
/// and plain aliases both work).
#[test]
fn aliased_nest_terms_unfold() {
    let expanded = expand_ok(json!({
        "@context": {
            "@vocab": "http://example.com/v/",
            "meta": "@nest",
            "labeled": {"@id": "http://example.com/labeled", "@nest": "@nest"}
        },
        "@id": "http://example.com/it",
        "meta": {"inner": "value"}
    }));
    assert_eq!(
        expanded[0]["http://example.com/v/inner"][0]["@value"],
        "value"
    );
}

/// Section 4.7: included blocks hold secondary node objects.
#[test]
fn included_nodes_survive_expansion() {
    let expanded = expand_ok(json!({
        "@id": "http://example.com/it",
        "http://example.com/p": "v",
        "@included": [
            {"@id": "http://example.com/other", "http://example.com/p": "w"}
        ]
    }));
    assert_eq!(
        expanded[0]["@included"],
        json!([{
            "@id": "http://example.com/other",
            "http://example.com/p": [{"@value": "w"}]
        }])
    );
}

/// Included node objects emit into the same graph as the including node.
#[test]
fn included_nodes_emit_into_the_same_graph() {
    let batches = quads(&json!({
        "@id": "http://example.com/g",
        "@graph": [{
            "@id": "http://example.com/a",
            "http://example.com/p": "v",
            "@included": [
                {"@id": "http://example.com/b", "http://example.com/p": "w"}
            ]
        }]
    }));
    assert_expected_lines(
        &batches,
        &[
            "<http://example.com/a> <http://example.com/p> \"v\" <http://example.com/g>",
            "<http://example.com/b> <http://example.com/p> \"w\" <http://example.com/g>",
        ],
    );
}

// ===========================================================================
// Cross-feature determinism and idempotency.
// ===========================================================================

#[test]
fn feature_rich_expansion_is_idempotent() {
    let document = json!({
        "@context": {
            "@vocab": "http://example.com/v/",
            "@direction": "ltr",
            "children": {"@reverse": "http://example.com/parent"},
            "post": {"@id": "http://example.com/post", "@container": "@index"},
            "blob": {"@id": "http://example.com/blob", "@type": "@json"}
        },
        "@id": "http://example.com/it",
        "@index": "top",
        "children": {"@id": "http://example.com/kid"},
        "post": {"en": {"@id": "http://example.com/1"}},
        "blob": {"n": 1},
        "name": "x",
        "@included": [{"@id": "http://example.com/inc", "name": "y"}]
    });
    let options = JsonLdOptions::default();
    let once = expand(&document, &options).expect("first expansion");
    let twice = expand(&once, &options).expect("second expansion");
    assert_eq!(once, twice);
}

#[test]
fn feature_rich_round_trip_reaches_a_fixed_point() {
    let document = json!({
        "@context": {
            "@vocab": "http://example.com/v/",
            "children": {"@reverse": "http://example.com/parent"},
            "blob": {"@id": "http://example.com/blob", "@type": "@json"}
        },
        "@id": "http://example.com/it",
        "children": {"@id": "http://example.com/kid"},
        "blob": {"n": [1.5, "x"]},
        "name": {"@value": "שלום", "@language": "he", "@direction": "rtl"}
    });
    let first = quads(&document);
    let second = quads(&from_quads(&first).expect("first serialization"));
    let third = quads(&from_quads(&second).expect("second serialization"));
    assert_eq!(quad_lines(&second), quad_lines(&third));
    assert_eq!(quad_lines(&first).len(), quad_lines(&second).len());
}
