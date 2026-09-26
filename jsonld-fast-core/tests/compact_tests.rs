// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Compaction coverage (JSON-LD 1.1 API section 6): the Compaction
//! Algorithm (6.1.2), Inverse Context Creation (6.2.2), Term Selection
//! (6.3.2), IRI Compaction (6.4.2), and Value Compaction (6.5.2).
//!
//! Every fixture is checked with the round-trip property
//! `expand(compact(doc, ctx)) == expand(doc)`; exact-output tests anchor
//! individual algorithm steps.

use jsonld_fast_core::{JsonLdError, JsonLdOptions, compact, expand};
use serde_json::{Value, json};

fn compact_ok(document: &Value, context: &Value) -> Value {
    compact(document, context, &JsonLdOptions::default()).expect("compaction succeeds")
}

/// Round-trip driver: compaction never changes the expanded meaning.
fn assert_round_trip(document: &Value, context: &Value) {
    let options = JsonLdOptions::default();
    let expanded = expand(document, &options).expect("document expands");
    let compacted = compact(document, context, &options).expect("document compacts");
    let re_expanded = expand(&compacted, &options).expect("compacted document expands");
    assert_eq!(re_expanded, expanded, "compacted form: {compacted}");
}

// ===========================================================================
// 1. Term selection and IRI compaction (API sections 6.3.2 and 6.4.2)
// ===========================================================================

/// API section 6.1.2: plain term compaction with value compaction to a bare
/// string (section 6.5.2).
#[test]
fn simple_term_and_bare_value() {
    let context = json!({"name": "http://schema.org/name"});
    let document = json!({
        "@context": {"name": "http://schema.org/name"},
        "@id": "http://example.com/a",
        "name": "Alice"
    });
    let compacted = compact_ok(&document, &context);
    assert_eq!(
        compacted,
        json!({
            "@context": {"name": "http://schema.org/name"},
            "@id": "http://example.com/a",
            "name": "Alice"
        })
    );
    assert_round_trip(&document, &context);
}

/// API section 6.4.2 step 4: a `@vocab`-relative suffix wins when no term
/// matches.
#[test]
fn vocab_suffix_compaction() {
    let context = json!({"@vocab": "http://vocab.example/"});
    let document = json!([{
        "@id": "http://example.com/a",
        "@type": ["http://vocab.example/Thing"],
        "http://vocab.example/name": [{"@value": "x"}]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["@type"], json!("Thing"));
    assert_eq!(compacted["name"], json!("x"));
    assert_round_trip(&document, &context);
}

/// API section 6.4.2 step 5: compact IRIs use the shortest, then
/// lexicographically least candidate over prefix-enabled terms.
#[test]
fn compact_iri_prefers_shortest_candidate() {
    let context = json!({
        "ex": "http://example.org/",
        "exvocab": "http://example.org/vocab/"
    });
    let document = json!([{
        "@id": "http://example.com/a",
        "http://example.org/vocab/p": [{"@value": "v"}]
    }]);
    let compacted = compact_ok(&document, &context);
    // "exvocab:p" (9 chars) beats "ex:vocab/p" (10 chars).
    assert_eq!(compacted["exvocab:p"], json!("v"));
    assert_round_trip(&document, &context);
}

/// API section 6.4.2: keyword aliases apply to `@id` and `@type` on output.
#[test]
fn keyword_aliases_on_output() {
    let context = json!({"id": "@id", "type": "@type"});
    let document = json!([{
        "@id": "http://example.com/a",
        "@type": ["http://example.com/Type"]
    , "http://example.com/p": [{"@value": 1}]}]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["id"], json!("http://example.com/a"));
    assert_eq!(compacted["type"], json!("http://example.com/Type"));
    assert_round_trip(&document, &context);
}

/// API section 6.4.2 step 8: without `vocab`, IRIs compact to verified
/// base-relative references.
#[test]
fn base_relative_id_compaction() {
    let context = json!({"@base": "http://example.com/doc/"});
    let document = json!([{
        "@id": "http://example.com/doc/items/a",
        "http://example.com/p": [{"@value": "v"}]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["@id"], json!("items/a"));
    assert_round_trip(&document, &context);
}

/// API section 6.4.2: the `IRI confused with prefix` condition is a typed
/// error, never a silently wrong output.
#[test]
fn iri_confused_with_prefix_is_refused() {
    let context = json!({"urn": {"@id": "http://example.com/urn#", "@prefix": true}});
    let document = json!([{
        "@id": "urn:isbn:0451450523",
        "http://example.com/p": [{"@value": "v"}]
    }]);
    let error = compact(&document, &context, &JsonLdOptions::default())
        .expect_err("confused IRI is refused");
    assert!(matches!(error, JsonLdError::InvalidTerm(_)));
    assert_eq!(error.code(), "invalid_term");
}

/// Sovereign boundary: a remote context handed to `compact` is refused by
/// name, never fetched.
#[test]
fn remote_compaction_context_is_refused() {
    let document = json!([{"http://example.com/p": [{"@value": "v"}]}]);
    let context = json!("http://remote.example/context.jsonld");
    let error = compact(&document, &context, &JsonLdOptions::default())
        .expect_err("remote context is refused");
    let JsonLdError::RemoteContextRefused { iri } = error else {
        panic!("expected RemoteContextRefused, got {error}");
    };
    assert_eq!(iri, "http://remote.example/context.jsonld");
}

// ===========================================================================
// 2. Value compaction (API section 6.5.2)
// ===========================================================================

/// Section 6.5.2: a typed value compacts to its bare `@value` when the term
/// carries the same type mapping.
#[test]
fn typed_value_compacts_to_bare_value() {
    let context = json!({
        "age": {"@id": "http://example.com/age",
                 "@type": "http://www.w3.org/2001/XMLSchema#integer"}
    });
    let document = json!([{
        "http://example.com/age": [{
            "@value": "30",
            "@type": "http://www.w3.org/2001/XMLSchema#integer"
        }]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["age"], json!("30"));
    assert_round_trip(&document, &context);
}

/// Section 6.5.2: with a default language in scope, a language-free string
/// must NOT compact to a bare scalar (it would gain the language back).
#[test]
fn language_free_string_stays_object_under_default_language() {
    let context = json!({"@language": "en", "label": "http://example.com/label"});
    let document = json!([{
        "http://example.com/label": [{"@value": "plain"}]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["label"], json!({"@value": "plain"}));
    assert_round_trip(&document, &context);
}

/// Section 6.5.2: a string matching the default language compacts bare; a
/// term with `@language: null` collects the language-free strings.
#[test]
fn language_selection_with_null_override() {
    let context = json!({
        "@language": "en",
        "label": "http://example.com/label",
        "comment": {"@id": "http://example.com/comment", "@language": null}
    });
    let document = json!([{
        "http://example.com/label": [{"@value": "hi", "@language": "en"}],
        "http://example.com/comment": [{"@value": "plain"}]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["label"], json!("hi"));
    assert_eq!(compacted["comment"], json!("plain"));
    assert_round_trip(&document, &context);
}

/// Sections 6.2.2/6.5.2 direction-aware keys: `@direction` values compact
/// bare only when the term (or context default) matches.
#[test]
fn direction_aware_value_compaction() {
    let context = json!({
        "@direction": "rtl",
        "title": "http://example.com/title"
    });
    let document = json!([{
        "http://example.com/title": [{"@value": "x", "@direction": "rtl"}]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["title"], json!("x"));
    assert_round_trip(&document, &context);
}

/// Section 6.5.2: `@type: @json` literals compact to the raw JSON value.
#[test]
fn json_literal_compacts_to_raw_json() {
    let context = json!({"data": {"@id": "http://example.com/data", "@type": "@json"}});
    let document = json!([{
        "http://example.com/data": [{"@value": {"a": [1, 2]}, "@type": "@json"}]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["data"], json!({"a": [1, 2]}));
    assert_round_trip(&document, &context);
}

/// Section 6.5.2: `@type: @id` node references compact to bare strings and
/// `@type: @vocab` prefers term names.
#[test]
fn node_reference_compaction_id_and_vocab() {
    let context = json!({
        "home": {"@id": "http://example.com/home", "@type": "@id"},
        "role": {"@id": "http://example.com/role", "@type": "@vocab"},
        "admin": "http://example.com/roles/admin"
    });
    let document = json!([{
        "http://example.com/home": [{"@id": "http://example.com/hq"}],
        "http://example.com/role": [{"@id": "http://example.com/roles/admin"}]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["home"], json!("http://example.com/hq"));
    assert_eq!(compacted["role"], json!("admin"));
    assert_round_trip(&document, &context);
}

// ===========================================================================
// 3. Container reshaping (API section 6.1.2 step 12.8)
// ===========================================================================

/// Step 12.8.4: `@container: @list` reassembles list objects.
#[test]
fn list_container_round_trip() {
    let context = json!({"nums": {"@id": "http://example.com/n", "@container": "@list"}});
    let document = json!({
        "@context": {"nums": {"@id": "http://example.com/n", "@container": "@list"}},
        "@id": "http://example.com/x",
        "nums": [1, 2, 3]
    });
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["nums"], json!([1, 2, 3]));
    assert_round_trip(&document, &context);
}

/// Step 12.8.4.2: two lists on one `@list`-container term cannot compact
/// (the API's `compaction to list of lists`).
#[test]
fn compaction_to_list_of_lists_is_refused() {
    let context = json!({"nums": {"@id": "http://example.com/n", "@container": "@list"}});
    let document = json!([{
        "http://example.com/n": [
            {"@list": [{"@value": 1}]},
            {"@list": [{"@value": 2}]}
        ]
    }]);
    let error = compact(&document, &context, &JsonLdOptions::default())
        .expect_err("list of lists is refused");
    assert_eq!(error.code(), "invalid_document");
}

/// Step 12.8.11 with `@set`: the array form is kept.
#[test]
fn set_container_keeps_arrays() {
    let context = json!({"tag": {"@id": "http://example.com/tag", "@container": "@set"}});
    let document = json!([{
        "http://example.com/tag": [{"@value": "a"}]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["tag"], json!(["a"]));
    assert_round_trip(&document, &context);
}

/// Step 12.8.8: index maps re-express `@index` entries as map keys.
#[test]
fn index_container_round_trip() {
    let context = json!({"post": {"@id": "http://example.com/post", "@container": "@index"}});
    let document = json!({
        "@context": {"post": {"@id": "http://example.com/post", "@container": "@index"}},
        "@id": "http://example.com/x",
        "post": {
            "en": {"@id": "http://example.com/p1"},
            "de": {"@id": "http://example.com/p2"}
        }
    });
    let compacted = compact_ok(&document, &context);
    assert_eq!(
        compacted["post"],
        json!({
            "de": {"@id": "http://example.com/p2"},
            "en": {"@id": "http://example.com/p1"}
        })
    );
    assert_round_trip(&document, &context);
}

/// Step 12.8.7: language maps re-express `@language` as map keys.
#[test]
fn language_container_round_trip() {
    let context = json!({
        "label": {"@id": "http://example.com/label", "@container": "@language"}
    });
    let document = json!({
        "@context": {
            "label": {"@id": "http://example.com/label", "@container": "@language"}
        },
        "@id": "http://example.com/x",
        "label": {"en": "The Queen", "de": "Die Königin"}
    });
    let compacted = compact_ok(&document, &context);
    assert_eq!(
        compacted["label"],
        json!({"de": "Die Königin", "en": "The Queen"})
    );
    assert_round_trip(&document, &context);
}

/// Step 12.8.8 with property-based `@index` (section 4.6.1.1).
#[test]
fn property_index_container_round_trip() {
    let context = json!({
        "post": {
            "@id": "http://example.com/post",
            "@container": "@index",
            "@index": "http://example.com/lang"
        }
    });
    let document = json!({
        "@context": {
            "post": {
                "@id": "http://example.com/post",
                "@container": "@index",
                "@index": "http://example.com/lang"
            }
        },
        "@id": "http://example.com/x",
        "post": {
            "en": {"@id": "http://example.com/p1"},
            "de": {"@id": "http://example.com/p2"}
        }
    });
    let compacted = compact_ok(&document, &context);
    assert_eq!(
        compacted["post"],
        json!({
            "de": {"@id": "http://example.com/p2"},
            "en": {"@id": "http://example.com/p1"}
        })
    );
    assert_round_trip(&document, &context);
}

/// Step 12.8.8 with `@none`: an index-less value lands under the `@none`
/// key of the index map.
#[test]
fn index_container_none_key() {
    let context = json!({"post": {"@id": "http://example.com/post", "@container": "@index"}});
    let document = json!([{
        "http://example.com/post": [{"@id": "http://example.com/p1"}]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(
        compacted["post"],
        json!({"@none": {"@id": "http://example.com/p1"}})
    );
    assert_round_trip(&document, &context);
}

/// Step 12.8.9: id maps re-express `@id` entries as map keys.
#[test]
fn id_container_round_trip() {
    let context = json!({"posts": {"@id": "http://example.com/posts", "@container": "@id"}});
    let document = json!({
        "@context": {"posts": {"@id": "http://example.com/posts", "@container": "@id"}},
        "posts": {
            "http://example.com/a": {"http://example.com/t": "x"},
            "http://example.com/b": {}
        }
    });
    let compacted = compact_ok(&document, &context);
    assert_eq!(
        compacted["posts"],
        json!({
            "http://example.com/a": {"http://example.com/t": "x"},
            "http://example.com/b": {}
        })
    );
    assert_round_trip(&document, &context);
}

/// Step 12.8.9 with `["@id", "@set"]` (canonical container `@id@set`).
#[test]
fn id_set_container_round_trip() {
    let context = json!({
        "posts": {"@id": "http://example.com/posts", "@container": ["@id", "@set"]}
    });
    let document = json!({
        "@context": {
            "posts": {"@id": "http://example.com/posts", "@container": ["@id", "@set"]}
        },
        "posts": {"http://example.com/a": {"http://example.com/t": "x"}}
    });
    let compacted = compact_ok(&document, &context);
    assert_eq!(
        compacted["posts"],
        json!({"http://example.com/a": [{"http://example.com/t": "x"}]})
    );
    assert_round_trip(&document, &context);
}

/// Step 12.8.10: type maps hoist the first `@type` into the map key.
#[test]
fn type_container_round_trip() {
    let context = json!({
        "stuff": {"@id": "http://example.com/stuff", "@container": "@type"},
        "Person": "http://example.com/Person"
    });
    let document = json!({
        "@context": {
            "stuff": {"@id": "http://example.com/stuff", "@container": "@type"},
            "Person": "http://example.com/Person"
        },
        "stuff": {"Person": {"@id": "http://example.com/alice"}}
    });
    let compacted = compact_ok(&document, &context);
    assert_eq!(
        compacted["stuff"],
        json!({"Person": "http://example.com/alice"})
    );
    assert_round_trip(&document, &context);
}

/// Step 12.8.10 with `["@type", "@set"]` (canonical container `@set@type`).
#[test]
fn type_set_container_round_trip() {
    let context = json!({
        "stuff": {"@id": "http://example.com/stuff", "@container": ["@type", "@set"]},
        "Person": "http://example.com/Person"
    });
    let document = json!({
        "@context": {
            "stuff": {"@id": "http://example.com/stuff", "@container": ["@type", "@set"]},
            "Person": "http://example.com/Person"
        },
        "stuff": {"Person": {"@id": "http://example.com/alice"}}
    });
    assert_round_trip(&document, &context);
}

/// Step 12.8.5: a simple `@graph` container implies the graph wrapping.
#[test]
fn graph_container_round_trip() {
    let context = json!({
        "claims": {"@id": "http://example.com/claims", "@container": "@graph"}
    });
    let document = json!({
        "@context": {
            "claims": {"@id": "http://example.com/claims", "@container": "@graph"}
        },
        "@id": "http://example.com/x",
        "claims": {"http://example.com/t": "v"}
    });
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["claims"], json!({"http://example.com/t": "v"}));
    assert_round_trip(&document, &context);
}

/// Step 12.8.6: `["@graph", "@id"]` maps named graphs by graph name.
#[test]
fn graph_id_container_round_trip() {
    let context = json!({
        "graphs": {"@id": "http://example.com/graphs", "@container": ["@graph", "@id"]}
    });
    let document = json!({
        "@context": {
            "graphs": {"@id": "http://example.com/graphs", "@container": ["@graph", "@id"]}
        },
        "graphs": {
            "http://example.com/g1": {"http://example.com/t": "v"}
        }
    });
    let compacted = compact_ok(&document, &context);
    assert_eq!(
        compacted["graphs"],
        json!({"http://example.com/g1": {"http://example.com/t": "v"}})
    );
    assert_round_trip(&document, &context);
}

/// Step 12.8.7: `["@graph", "@index"]` maps graphs by index key.
#[test]
fn graph_index_container_round_trip() {
    let context = json!({
        "graphs": {"@id": "http://example.com/graphs", "@container": ["@graph", "@index"]}
    });
    let document = json!({
        "@context": {
            "graphs": {"@id": "http://example.com/graphs", "@container": ["@graph", "@index"]}
        },
        "graphs": {"k": {"http://example.com/t": "v"}}
    });
    assert_round_trip(&document, &context);
}

/// A graph object that its term's container cannot express (here: two inner
/// nodes on a simple `@graph` container) falls back to a term-free key with
/// generic `@graph` wrapping instead of producing a non-round-tripping map.
#[test]
fn inexpressible_graph_object_falls_back_to_generic_wrapping() {
    let context = json!({
        "claims": {"@id": "http://example.com/claims", "@container": "@graph"}
    });
    let document = json!([{
        "http://example.com/claims": [{
            "@graph": [
                {"@id": "http://example.com/n1", "http://example.com/t": [{"@value": "a"}]},
                {"@id": "http://example.com/n2", "http://example.com/t": [{"@value": "b"}]}
            ]
        }]
    }]);
    let compacted = compact_ok(&document, &context);
    // The property key is not the term (the term's container cannot hold
    // this shape); the graph wrapping stays explicit.
    assert!(compacted.get("claims").is_none(), "got: {compacted}");
    assert!(
        compacted["http://example.com/claims"]
            .get("@graph")
            .is_some(),
        "got: {compacted}"
    );
    assert_round_trip(&document, &context);
}

// ===========================================================================
// 4. @reverse, @nest, scoped contexts, @included, named graphs
// ===========================================================================

/// Section 6.1.2 step 8: reverse terms hoist matching `@reverse` entries.
#[test]
fn reverse_term_selection() {
    let context = json!({"children": {"@reverse": "http://example.com/parent"}});
    let document = json!([{
        "@id": "http://example.com/it",
        "@reverse": {
            "http://example.com/parent": [{"@id": "http://example.com/kid"}]
        }
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(
        compacted["children"],
        json!({"@id": "http://example.com/kid"})
    );
    assert_round_trip(&document, &context);
}

/// Section 6.1.2 step 8.2: entries with no reverse term stay under the
/// `@reverse` alias.
#[test]
fn reverse_without_term_stays_under_reverse() {
    let context = json!({"ex": "http://example.com/"});
    let document = json!([{
        "@id": "http://example.com/it",
        "@reverse": {
            "http://example.com/parent": [{"@id": "http://example.com/kid"}]
        }
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(
        compacted["@reverse"],
        json!({"ex:parent": {"@id": "ex:kid"}})
    );
    assert_round_trip(&document, &context);
}

/// Section 6.1.2 steps 12.2-12.3: terms with `@nest` write into their nest
/// entry, which re-expands transparently.
#[test]
fn nest_property_reconstitution() {
    let context = json!({
        "meta": "@nest",
        "label": {"@id": "http://example.com/label", "@nest": "meta"}
    });
    let document = json!([{
        "http://example.com/label": [{"@value": "x"}]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["meta"], json!({"label": "x"}));
    assert_round_trip(&document, &context);
}

/// Section 6.1.2: type-scoped contexts apply during compaction (after the
/// types are compacted and sorted).
#[test]
fn type_scoped_context_applies_in_compaction() {
    let context = json!({
        "Person": {
            "@id": "http://example.com/Person",
            "@context": {"name": "http://example.com/name"}
        }
    });
    let document = json!([{
        "@type": ["http://example.com/Person"],
        "http://example.com/name": [{"@value": "Alice"}]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["@type"], json!("Person"));
    assert_eq!(compacted["name"], json!("Alice"));
    assert_round_trip(&document, &context);
}

/// Property-scoped contexts apply when descending into a term's values.
#[test]
fn property_scoped_context_applies_in_compaction() {
    let context = json!({
        "friend": {
            "@id": "http://example.com/friend",
            "@context": {"name": "http://example.com/name"}
        }
    });
    let document = json!([{
        "http://example.com/friend": [{
            "http://example.com/name": [{"@value": "Bob"}]
        }]
    }]);
    let compacted = compact_ok(&document, &context);
    assert_eq!(compacted["friend"], json!({"name": "Bob"}));
    assert_round_trip(&document, &context);
}

/// `@included` blocks and named graphs (`@graph` on a node) compact
/// recursively and round-trip.
#[test]
fn included_and_named_graphs_round_trip() {
    let context = json!({"ex": "http://example.com/"});
    let document = json!([{
        "@id": "http://example.com/g",
        "@graph": [
            {"@id": "http://example.com/inner", "http://example.com/t": [{"@value": "v"}]}
        ],
        "@included": [
            {"@id": "http://example.com/other", "http://example.com/t": [{"@value": "w"}]}
        ]
    }]);
    assert_round_trip(&document, &context);
}

// ===========================================================================
// 5. compactArrays, top-level wrapping, determinism
// ===========================================================================

/// API section 6.1: `compactArrays == false` keeps every array.
#[test]
fn compact_arrays_false_keeps_arrays() {
    let options = JsonLdOptions {
        compact_arrays: false,
        ..JsonLdOptions::default()
    };
    let context = json!({"name": "http://schema.org/name"});
    let document = json!([{
        "@id": "http://example.com/a",
        "@type": ["http://example.com/T"],
        "http://schema.org/name": [{"@value": "Alice"}]
    }]);
    let compacted = compact(&document, &context, &options).expect("compaction succeeds");
    // The single-node top-level array is kept and wraps under @graph.
    let node = &compacted["@graph"][0];
    assert_eq!(node["name"], json!(["Alice"]));
    assert_eq!(node["@type"], json!(["http://example.com/T"]));
    let re_expanded = expand(&compacted, &options).expect("re-expansion succeeds");
    let expanded = expand(&document, &options).expect("expansion succeeds");
    assert_eq!(re_expanded, expanded);
}

/// `JsonLdProcessor.compact`: multiple top-level nodes wrap under the
/// `@graph` alias; re-expansion unwraps them.
#[test]
fn multiple_top_level_nodes_wrap_in_graph() {
    let context = json!({"ex": "http://example.com/"});
    let document = json!([
        {"@id": "http://example.com/a", "http://example.com/t": [{"@value": 1}]},
        {"@id": "http://example.com/b", "http://example.com/t": [{"@value": 2}]}
    ]);
    let compacted = compact_ok(&document, &context);
    let graph = compacted["@graph"].as_array().expect("graph array");
    assert_eq!(graph.len(), 2);
    assert_round_trip(&document, &context);
}

/// `JsonLdProcessor.compact`: an empty expansion compacts to an empty map
/// (no `@context` attached for an empty result body with empty context).
#[test]
fn empty_document_compacts_to_empty_map() {
    let compacted = compact_ok(&json!([]), &json!({}));
    assert_eq!(compacted, json!({}));
}

/// Deterministic output: two runs serialize identically, and keys are
/// ordered.
#[test]
fn compaction_is_deterministic_and_ordered() {
    let context = json!({
        "b": "http://example.com/b",
        "a": "http://example.com/a",
        "@language": "en"
    });
    let document = json!([{
        "@id": "http://example.com/x",
        "http://example.com/b": [{"@value": "vb", "@language": "en"}],
        "http://example.com/a": [{"@value": "va", "@language": "en"}]
    }]);
    let first = serde_json::to_string(&compact_ok(&document, &context)).expect("serializes");
    let second = serde_json::to_string(&compact_ok(&document, &context)).expect("serializes");
    assert_eq!(first, second);
    // BTreeMap-backed maps: @context < @id < a < b, byte-stable.
    assert_eq!(
        first,
        "{\"@context\":{\"@language\":\"en\",\"a\":\"http://example.com/a\",\
         \"b\":\"http://example.com/b\"},\"@id\":\"http://example.com/x\",\
         \"a\":\"va\",\"b\":\"vb\"}"
    );
}

/// Round-trip matrix over every supported container and coercion in one
/// document.
#[test]
fn combined_round_trip_matrix() {
    let context = json!({
        "@vocab": "http://vocab.example/",
        "@language": "en",
        "ex": "http://example.com/",
        "id": "@id",
        "list": {"@id": "http://example.com/list", "@container": "@list"},
        "set": {"@id": "http://example.com/set", "@container": "@set"},
        "index": {"@id": "http://example.com/index", "@container": ["@index", "@set"]},
        "byId": {"@id": "http://example.com/byId", "@container": "@id"},
        "byType": {"@id": "http://example.com/byType", "@container": "@type"},
        "graph": {"@id": "http://example.com/graph", "@container": "@graph"},
        "typed": {"@id": "http://example.com/typed",
                   "@type": "http://www.w3.org/2001/XMLSchema#date"},
        "ref": {"@id": "http://example.com/ref", "@type": "@id"},
        "json": {"@id": "http://example.com/json", "@type": "@json"},
        "nolang": {"@id": "http://example.com/nolang", "@language": null},
        "children": {"@reverse": "http://example.com/parent"}
    });
    let document = json!({
        "@context": context.clone(),
        "@id": "http://example.com/it",
        "@type": "Thing",
        "list": ["a", "b"],
        "set": ["x"],
        "index": {"i1": {"@id": "http://example.com/v1"}},
        "byId": {"http://example.com/v2": {"name": "n"}},
        "byType": {"Thing": {"@id": "http://example.com/v3"}},
        "graph": {"ex:t": "inner"},
        "typed": "2026-01-01",
        "ref": "http://example.com/target",
        "json": {"k": [true, null]},
        "nolang": "plain",
        "children": {"@id": "http://example.com/kid"}
    });
    assert_round_trip(&document, &context);
}
