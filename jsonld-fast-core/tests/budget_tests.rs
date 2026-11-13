// Rust guideline compliant 2026-02-21
//! Output budget: expansion must not amplify a small input into a large
//! output.

use std::time::Instant;

use jsonld_fast_core::{JsonLdOptions, compact, expand};
use serde_json::{Map, Value, json};

/// A term expanding to a 1 MiB IRI, used by `uses` nodes: about 1 MiB of
/// input that expands to `uses` MiB of output.
fn long_iri_document(uses: usize) -> Value {
    let iri = format!("http://example.com/{}", "a".repeat(1 << 20));
    let nodes: Vec<Value> = (0..uses)
        .map(|index| json!({"@id": format!("http://example.com/n{index}"), "t": "x"}))
        .collect();
    let mut context = Map::new();
    context.insert("t".to_owned(), Value::String(iri));
    json!({"@context": Value::Object(context), "@graph": nodes})
}

#[test]
fn long_iri_amplification_is_refused_by_output_budget() {
    let document = long_iri_document(128);
    let started = Instant::now();
    let error = expand(&document, &JsonLdOptions::default())
        .expect_err("128 MiB of output from 1 MiB of input is refused");
    assert_eq!(error.code(), "resource_limit", "{error}");
    assert!(error.to_string().contains("output_bytes"), "{error}");
    println!("refused in {:?}: {error}", started.elapsed());
}

/// Compaction amplifies the other way: a context term with a 1 MiB name,
/// chosen for a short IRI, is copied at each of 128 uses.
#[test]
fn long_term_name_amplification_is_refused_by_output_budget() {
    let nodes: Vec<Value> = (0..128)
        .map(|index| {
            json!({"@id": format!("http://example.com/n{index}"), "http://example.com/p": "x"})
        })
        .collect();
    let document = json!({"@graph": nodes});
    let mut context = Map::new();
    context.insert("a".repeat(1 << 20), json!("http://example.com/p"));
    let started = Instant::now();
    let error = compact(
        &document,
        &Value::Object(context),
        &JsonLdOptions::default(),
    )
    .expect_err("128 MiB of compacted keys from a 1 MiB context is refused");
    assert!(error.to_string().contains("output_bytes"), "{error}");
    println!("refused in {:?}: {error}", started.elapsed());
}

/// A term mapped to `definition` and used by 128 nodes built by `node`.
fn term_used_128_times(definition: Value, node: impl Fn(usize) -> Value) -> Value {
    let mut context = Map::new();
    context.insert("t".to_owned(), definition);
    let nodes: Vec<Value> = (0..128).map(node).collect();
    json!({"@context": Value::Object(context), "@graph": nodes})
}

/// A reverse term whose IRI is 1 MiB lands as a key of each node's
/// `@reverse` map: 128 MiB of keys from 1 MiB of input.
#[test]
fn long_reverse_iri_is_charged() {
    let iri = format!("http://example.com/{}", "a".repeat(1 << 20));
    let document = term_used_128_times(
        json!({"@reverse": iri}),
        |index| json!({"@id": format!("http://example.com/n{index}"), "t": {"@id": "http://example.com/o"}}),
    );
    let error = expand(&document, &JsonLdOptions::default()).expect_err("refused");
    assert!(error.to_string().contains("output_bytes"), "{error}");
}

/// A `@type` map key `k` that expands to a 1 MiB IRI is prepended to each
/// of 128 items' `@type`; those copies are charged where they are made.
#[test]
fn long_type_map_key_is_charged() {
    let iri = format!("http://example.com/{}", "a".repeat(1 << 20));
    let nodes: Vec<Value> = (0..128)
        .map(|index| {
            json!({
                "@id": format!("http://example.com/n{index}"),
                "t": {"k": {"@id": format!("http://example.com/o{index}")}}
            })
        })
        .collect();
    let mut context = Map::new();
    context.insert(
        "t".to_owned(),
        json!({"@id": "http://example.com/p", "@container": "@type"}),
    );
    context.insert("k".to_owned(), Value::String(iri));
    let document = json!({"@context": Value::Object(context), "@graph": nodes});
    let error = expand(&document, &JsonLdOptions::default()).expect_err("refused");
    assert!(error.to_string().contains("output_bytes"), "{error}");
}
