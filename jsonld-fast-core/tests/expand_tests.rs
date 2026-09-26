// Rust guideline compliant 2026-02-21
//! Expansion behavior over inline contexts (fixtures adapted from the
//! JSON-LD 1.1 specification examples).

use jsonld_fast_core::{JsonLdOptions, expand};
use serde_json::{Value, json};

fn expand_ok(document: Value) -> Value {
    expand(&document, &JsonLdOptions::default()).expect("expansion succeeds")
}

fn expand_with_base(document: Value, base: &str) -> Value {
    let options = JsonLdOptions {
        base: Some(base.to_owned()),
        ..JsonLdOptions::default()
    };
    expand(&document, &options).expect("expansion succeeds")
}

#[test]
fn term_shorthand_and_expanded_form() {
    let expanded = expand_ok(json!({
        "@context": {
            "name": "http://schema.org/name",
            "homepage": {"@id": "http://schema.org/url", "@type": "@id"}
        },
        "@id": "http://example.com/alice",
        "name": "Alice",
        "homepage": "http://example.com/alice/"
    }));
    assert_eq!(
        expanded,
        json!([{
            "@id": "http://example.com/alice",
            "http://schema.org/name": [{"@value": "Alice"}],
            "http://schema.org/url": [{"@id": "http://example.com/alice/"}]
        }])
    );
}

#[test]
fn type_vocab_coercion() {
    let expanded = expand_ok(json!({
        "@context": {
            "@vocab": "http://example.com/vocab/",
            "kind": {"@id": "http://example.com/vocab/kind", "@type": "@vocab"}
        },
        "@id": "http://example.com/it",
        "kind": "Widget"
    }));
    assert_eq!(
        expanded[0]["http://example.com/vocab/kind"][0]["@id"],
        "http://example.com/vocab/Widget"
    );
}

#[test]
fn vocab_expands_plain_keys() {
    let expanded = expand_ok(json!({
        "@context": {"@vocab": "http://example.com/vocab/"},
        "@id": "http://example.com/it",
        "name": "thing"
    }));
    assert_eq!(
        expanded[0]["http://example.com/vocab/name"][0]["@value"],
        "thing"
    );
}

#[test]
fn base_resolves_relative_ids() {
    let expanded = expand_ok(json!({
        "@context": {"@base": "http://example.com/dir/"},
        "@id": "doc",
        "http://example.com/p": "v"
    }));
    assert_eq!(expanded[0]["@id"], "http://example.com/dir/doc");
}

#[test]
fn context_base_resolves_against_options_base() {
    let expanded = expand_with_base(
        json!({
            "@context": {"@base": "sub/"},
            "@id": "doc",
            "http://example.com/p": "v"
        }),
        "http://example.com/root/",
    );
    assert_eq!(expanded[0]["@id"], "http://example.com/root/sub/doc");
}

#[test]
fn options_base_applies_without_context() {
    let expanded = expand_with_base(
        json!({"@id": "../other", "http://example.com/p": "v"}),
        "http://a/b/c/d;p?q",
    );
    assert_eq!(expanded[0]["@id"], "http://a/b/other");
}

#[test]
fn compact_iri_expansion() {
    let expanded = expand_ok(json!({
        "@context": {"schema": "http://schema.org/"},
        "@id": "http://example.com/bob",
        "schema:name": "Bob"
    }));
    assert_eq!(expanded[0]["http://schema.org/name"][0]["@value"], "Bob");
}

#[test]
fn explicit_prefix_flag() {
    let expanded = expand_ok(json!({
        "@context": {
            "ex": {"@id": "http://example.com/vocab#", "@prefix": true}
        },
        "@id": "http://example.com/it",
        "ex:label": "x"
    }));
    assert_eq!(
        expanded[0]["http://example.com/vocab#label"][0]["@value"],
        "x"
    );
}

#[test]
fn object_form_term_is_not_a_prefix() {
    // A term defined in object form without @prefix must not be usable as a
    // compact IRI prefix; `foo:bar` then reads as an IRI with scheme `foo`.
    let expanded = expand_ok(json!({
        "@context": {"foo": {"@id": "http://example.com/foo#"}},
        "@id": "http://example.com/it",
        "foo:bar": "x"
    }));
    assert_eq!(expanded[0]["foo:bar"][0]["@value"], "x");
}

#[test]
fn default_and_per_term_language() {
    let expanded = expand_ok(json!({
        "@context": {
            "@language": "en",
            "title": {"@id": "http://example.com/title", "@language": "de"},
            "plain": {"@id": "http://example.com/plain", "@language": null},
            "note": "http://example.com/note"
        },
        "@id": "http://example.com/it",
        "title": "Titel",
        "plain": "raw",
        "note": "hello"
    }));
    let node = &expanded[0];
    assert_eq!(node["http://example.com/title"][0]["@language"], "de");
    assert_eq!(node["http://example.com/note"][0]["@language"], "en");
    assert!(
        node["http://example.com/plain"][0]
            .get("@language")
            .is_none()
    );
}

#[test]
fn list_container_wraps_values() {
    let expanded = expand_ok(json!({
        "@context": {
            "seq": {"@id": "http://example.com/seq", "@container": "@list"}
        },
        "@id": "http://example.com/it",
        "seq": ["a", "b"]
    }));
    assert_eq!(
        expanded[0]["http://example.com/seq"],
        json!([{"@list": [{"@value": "a"}, {"@value": "b"}]}])
    );
}

#[test]
fn set_container_flattens() {
    let expanded = expand_ok(json!({
        "@context": {
            "tags": {"@id": "http://example.com/tags", "@container": "@set"}
        },
        "@id": "http://example.com/it",
        "tags": ["a", ["b"], null]
    }));
    assert_eq!(
        expanded[0]["http://example.com/tags"],
        json!([{"@value": "a"}, {"@value": "b"}])
    );
}

#[test]
fn explicit_set_object_collapses() {
    let expanded = expand_ok(json!({
        "@id": "http://example.com/it",
        "http://example.com/p": {"@set": ["a", "b"]}
    }));
    assert_eq!(
        expanded[0]["http://example.com/p"],
        json!([{"@value": "a"}, {"@value": "b"}])
    );
}

#[test]
fn keyword_aliasing() {
    let expanded = expand_ok(json!({
        "@context": {"id": "@id", "type": "@type", "@vocab": "http://example.com/v/"},
        "id": "http://example.com/it",
        "type": "Thing",
        "http://example.com/p": "v"
    }));
    assert_eq!(expanded[0]["@id"], "http://example.com/it");
    assert_eq!(expanded[0]["@type"], json!(["http://example.com/v/Thing"]));
}

#[test]
fn typed_value_object_datatype_expansion() {
    let expanded = expand_ok(json!({
        "@context": {"xsd": "http://www.w3.org/2001/XMLSchema#"},
        "@id": "http://example.com/it",
        "http://example.com/when": {"@value": "2026-01-01", "@type": "xsd:date"}
    }));
    assert_eq!(
        expanded[0]["http://example.com/when"][0]["@type"],
        "http://www.w3.org/2001/XMLSchema#date"
    );
}

#[test]
fn unmapped_keys_are_dropped_per_spec() {
    let expanded = expand_ok(json!({
        "@id": "http://example.com/it",
        "name": "dropped",
        "http://example.com/p": "kept"
    }));
    let node = expanded[0].as_object().expect("node object");
    assert!(node.get("name").is_none());
    assert!(node.get("http://example.com/p").is_some());
}

#[test]
fn free_floating_values_are_dropped() {
    let expanded = expand_ok(json!([
        "just a string",
        {"@value": 5},
        {"@id": "http://example.com/only-id"},
        {"@id": "http://example.com/kept", "http://example.com/p": "v"}
    ]));
    assert_eq!(
        expanded,
        json!([{
            "@id": "http://example.com/kept",
            "http://example.com/p": [{"@value": "v"}]
        }])
    );
}

#[test]
fn top_level_graph_unwraps() {
    let expanded = expand_ok(json!({
        "@context": {"@vocab": "http://example.com/v/"},
        "@graph": [
            {"@id": "http://example.com/a", "p": "1"},
            {"@id": "http://example.com/b", "p": "2"}
        ]
    }));
    assert_eq!(expanded.as_array().map(Vec::len), Some(2));
    assert_eq!(expanded[0]["@id"], "http://example.com/a");
}

#[test]
fn protected_terms_allow_identical_redefinition() {
    let expanded = expand(
        &json!({
            "@context": [
                {"@protected": true, "name": "http://example.com/name"},
                {"name": "http://example.com/name"}
            ],
            "@id": "http://example.com/it",
            "name": "ok"
        }),
        &JsonLdOptions::default(),
    );
    assert!(expanded.is_ok());
}

#[test]
fn expansion_is_idempotent_on_expanded_documents() {
    let document = json!({
        "@context": {
            "@language": "en",
            "seq": {"@id": "http://example.com/seq", "@container": "@list"}
        },
        "@id": "http://example.com/it",
        "@type": "http://example.com/T",
        "seq": ["a", 1, true],
        "http://example.com/p": "text"
    });
    let options = JsonLdOptions::default();
    let once = expand(&document, &options).expect("first expansion");
    let twice = expand(&once, &options).expect("second expansion");
    assert_eq!(once, twice);
}

#[test]
fn nested_context_overrides_outer_terms() {
    let expanded = expand_ok(json!({
        "@context": {"label": "http://example.com/outer"},
        "@id": "http://example.com/it",
        "label": "outer",
        "http://example.com/child": {
            "@context": {"label": "http://example.com/inner"},
            "@id": "http://example.com/child-node",
            "label": "inner"
        }
    }));
    let node = &expanded[0];
    assert_eq!(node["http://example.com/outer"][0]["@value"], "outer");
    let child = &node["http://example.com/child"][0];
    assert_eq!(child["http://example.com/inner"][0]["@value"], "inner");
}

#[test]
fn null_context_resets_terms() {
    let expanded = expand_ok(json!({
        "@context": {"name": "http://example.com/name"},
        "@id": "http://example.com/it",
        "name": "kept",
        "http://example.com/child": {
            "@context": null,
            "@id": "http://example.com/child-node",
            "name": "dropped"
        }
    }));
    let child = &expanded[0]["http://example.com/child"][0];
    let child_map = child.as_object().expect("child node");
    assert_eq!(child_map.len(), 1, "only @id survives: {child_map:?}");
}

#[test]
fn term_mapped_to_null_drops_keys() {
    let expanded = expand_ok(json!({
        "@context": {"secret": null, "name": "http://example.com/name"},
        "@id": "http://example.com/it",
        "secret": "dropped",
        "name": "kept"
    }));
    let node = expanded[0].as_object().expect("node object");
    assert_eq!(node.len(), 2);
    assert!(node.contains_key("http://example.com/name"));
}
