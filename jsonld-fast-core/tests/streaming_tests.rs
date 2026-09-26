// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! JSON-LD Streaming Note: required key order and streaming RDF form.

use jsonld_fast_core::{
    JsonLdError, JsonLdLimits, JsonLdOptions, STREAMING_PROFILE, expand, expand_streaming,
    expand_streaming_graph, from_quads, from_quads_streaming, parse_streaming_graph, to_quads,
    to_quads_streaming, validate_streaming_form, write_streaming_document,
};
use serde_json::{Value, json};

fn limits() -> JsonLdLimits {
    JsonLdLimits::default()
}

#[test]
fn streaming_profile_uri_is_the_note_identifier() {
    assert_eq!(STREAMING_PROFILE, "http://www.w3.org/ns/json-ld#streaming");
}

#[test]
fn valid_streaming_form_expands_like_the_in_memory_processor() {
    let text = r#"{
  "@context": {"name": "http://schema.org/name"},
  "@id": "http://example.com/alice",
  "name": "Alice"
}"#;
    validate_streaming_form(text, &limits()).expect("valid streaming form");
    let streamed = expand_streaming(text, &JsonLdOptions::default()).expect("expand_streaming");
    let parsed: Value = serde_json::from_str(text).expect("json");
    let in_memory = expand(&parsed, &JsonLdOptions::default()).expect("expand");
    assert_eq!(streamed, in_memory);
}

#[test]
fn context_before_id_is_required() {
    let text = r#"{
  "@id": "http://example.com/alice",
  "@context": {"name": "http://schema.org/name"},
  "name": "Alice"
}"#;
    let error = validate_streaming_form(text, &limits()).expect_err("id before context");
    assert_eq!(error.code(), "invalid_streaming_key_order");
}

#[test]
fn type_must_precede_other_properties() {
    let text = r#"{
  "http://schema.org/name": "Alice",
  "@type": "http://schema.org/Person"
}"#;
    let error = validate_streaming_form(text, &limits()).expect_err("property before type");
    match error {
        JsonLdError::InvalidStreamingKeyOrder(detail) => {
            assert!(detail.contains("@type"), "{detail}");
        }
        other => panic!("expected InvalidStreamingKeyOrder, got {other}"),
    }
}

#[test]
fn nested_node_objects_are_checked() {
    let text = r#"{
  "@id": "http://example.com/alice",
  "http://schema.org/knows": {
    "http://schema.org/name": "Bob",
    "@id": "http://example.com/bob"
  }
}"#;
    // Inner node has @id after a property — valid per the Note (id is
    // recommended first among "other", not required). @type is absent.
    validate_streaming_form(text, &limits()).expect("id after properties is allowed");
}

#[test]
fn nested_type_after_properties_fails() {
    let text = r#"{
  "@id": "http://example.com/alice",
  "http://schema.org/knows": {
    "http://schema.org/name": "Bob",
    "@type": "http://schema.org/Person"
  }
}"#;
    let error = validate_streaming_form(text, &limits()).expect_err("nested type after props");
    assert_eq!(error.code(), "invalid_streaming_key_order");
}

#[test]
fn term_definitions_inside_context_are_exempt() {
    // Copied from the Note's valid type-scoped example: @id precedes
    // @context inside the Person term definition.
    let text = r#"{
  "@context": {
    "Person": {
      "@id": "http://schema.org/Person",
      "@context": {"name": "http://schema.org/name"}
    }
  },
  "@type": "Person",
  "@id": "http://example.com/alice",
  "name": "Alice"
}"#;
    validate_streaming_form(text, &limits()).expect("context tree is exempt");
}

#[test]
fn to_quads_streaming_matches_to_quads_on_valid_form() {
    let text = r#"{"@id":"http://example.com/alice","http://schema.org/name":"Alice"}"#;
    let streamed = to_quads_streaming(text, &JsonLdOptions::default(), None).expect("stream");
    let parsed: Value = serde_json::from_str(text).expect("json");
    let in_memory = to_quads(&parsed, &JsonLdOptions::default(), None).expect("to_quads");
    assert_eq!(streamed[0].num_rows(), in_memory[0].num_rows());
}

#[test]
fn from_quads_streaming_puts_type_before_id() {
    let document = json!({
        "@id": "http://example.com/alice",
        "@type": "http://schema.org/Person",
        "http://schema.org/name": "Alice"
    });
    let batches = to_quads(&document, &JsonLdOptions::default(), None).expect("to_quads");
    let text = from_quads_streaming(&batches).expect("streaming json");
    validate_streaming_form(&text, &limits()).expect("emitted form is streaming");
    let type_at = text.find("\"@type\"").expect("@type present");
    let id_at = text.find("\"@id\"").expect("@id present");
    assert!(
        type_at < id_at,
        "@type must precede @id in streaming form: {text}"
    );
    let parsed: Value = serde_json::from_str(&text).expect("json");
    let reparsed = from_quads(&batches).expect("from_quads");
    assert_eq!(parsed, reparsed);
}

#[test]
fn write_streaming_document_reorders_existing_values() {
    let document = json!({
        "@id": "http://example.com/alice",
        "@type": "http://schema.org/Person",
        "http://schema.org/name": [{"@value": "Alice"}]
    });
    let text = write_streaming_document(&document);
    let type_at = text.find("\"@type\"").expect("@type");
    let id_at = text.find("\"@id\"").expect("@id");
    assert!(type_at < id_at, "{text}");
}

#[test]
fn streaming_expand_refuses_remote_context_after_form_check() {
    let text = r#"{
  "@context": "https://schema.org/",
  "@id": "http://example.com/alice"
}"#;
    validate_streaming_form(text, &limits()).expect("order is valid");
    let error = expand_streaming(text, &JsonLdOptions::default()).expect_err("remote");
    assert_eq!(error.code(), "remote_context_refused");
}

#[test]
fn streaming_graph_yields_each_node_without_a_wrapping_array() {
    let text = r#"{
  "@context": {"name": "http://schema.org/name"},
  "@graph": [
    {"@id": "http://example.com/a", "name": "A"},
    {"@id": "http://example.com/b", "name": "B"}
  ]
}"#;
    let options = JsonLdOptions::default();
    let nodes: Vec<Value> = expand_streaming_graph(text, &options)
        .expect("open")
        .collect::<Result<Vec<_>, _>>()
        .expect("expand nodes");
    assert_eq!(
        nodes,
        vec![
            json!({
                "@id": "http://example.com/a",
                "http://schema.org/name": [{"@value": "A"}]
            }),
            json!({
                "@id": "http://example.com/b",
                "http://schema.org/name": [{"@value": "B"}]
            }),
        ]
    );
}

#[test]
fn streaming_graph_raw_nodes_keep_the_document_context_in_the_header() {
    let text = r#"{
  "@context": {"name": "http://schema.org/name"},
  "@graph": [
    {"@id": "http://example.com/a", "name": "A"}
  ]
}"#;
    let mut stream = parse_streaming_graph(text, &limits()).expect("parse graph");
    let node = stream.next().expect("one node").expect("json");
    assert_eq!(node["@id"], json!("http://example.com/a"));
    assert_eq!(
        stream.header()["@context"],
        json!({"name": "http://schema.org/name"})
    );
    assert!(stream.next().is_none());
}

#[test]
fn streaming_top_level_array_yields_each_element() {
    let text = r#"[
  {"@id": "http://example.com/a", "http://schema.org/name": "A"},
  {"@id": "http://example.com/b", "http://schema.org/name": "B"}
]"#;
    let nodes: Vec<Value> = parse_streaming_graph(text, &limits())
        .expect("parse array")
        .collect::<Result<Vec<_>, _>>()
        .expect("nodes");
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[1]["@id"], json!("http://example.com/b"));
}
