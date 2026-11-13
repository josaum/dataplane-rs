// Rust guideline compliant 2026-02-21
//! Output budget: expansion must not amplify a small input into a large
//! output.

use std::time::Instant;

use jsonld_fast_core::{JsonLdOptions, compact, expand, frame};
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

/// An `@id` map key expanding through a 64 KiB prefix supplies each item's
/// `@id` after the item was charged: 2,000 entries turned 88 KB of input
/// into 131 MB.
#[test]
fn id_map_keys_are_charged() {
    let prefix = format!("http://example.com/{}/", "a".repeat(64 * 1024));
    let mut entries = Map::new();
    for index in 0..2_000 {
        entries.insert(format!("p:{index}"), json!({}));
    }
    let mut context = Map::new();
    context.insert("p".to_owned(), Value::String(prefix));
    context.insert(
        "m".to_owned(),
        json!({"@id": "http://example.com/m", "@container": "@id"}),
    );
    let document = json!({
        "@context": Value::Object(context),
        "@id": "http://example.com/root",
        "m": Value::Object(entries)
    });
    let error = expand(&document, &JsonLdOptions::default()).expect_err("refused");
    assert!(error.to_string().contains("output_bytes"), "{error}");
}

/// A property-valued `@index` whose property is a 64 KiB IRI is attached
/// to each of 2,000 items after they were charged: 131 KB in, 131 MB out.
#[test]
fn property_valued_index_is_charged() {
    let iri = format!("http://example.com/{}", "a".repeat(64 * 1024));
    let mut entries = Map::new();
    for index in 0..2_000 {
        entries.insert(
            format!("k{index}"),
            json!({"@id": format!("http://example.com/n{index}")}),
        );
    }
    let mut context = Map::new();
    context.insert("idx".to_owned(), Value::String(iri));
    context.insert(
        "m".to_owned(),
        json!({"@id": "http://example.com/m", "@container": "@index", "@index": "idx"}),
    );
    let document = json!({
        "@context": Value::Object(context),
        "@id": "http://example.com/root",
        "m": Value::Object(entries)
    });
    let error = expand(&document, &JsonLdOptions::default()).expect_err("refused");
    assert!(error.to_string().contains("output_bytes"), "{error}");
}

/// Legitimate `@embed: @always` framing that main completes: 20,000 items
/// each embedding one of 10 shared 2 KB nodes (1.9 MB in, 42 MB out). Each
/// compacted string must be charged once, and the default must fit it.
#[test]
fn embed_always_over_shared_nodes_fits_the_default_budget() {
    let description = "d".repeat(2_000);
    let mut graph: Vec<Value> = (0..10)
        .map(|org| {
            json!({"@id": format!("http://example.com/org{org}"), "@type": "http://s/Org",
                "http://s/desc": description})
        })
        .collect();
    for item in 0..20_000 {
        graph.push(
            json!({"@id": format!("http://example.com/item{item}"), "@type": "http://s/Item",
            "http://s/org": {"@id": format!("http://example.com/org{}", item % 10)}}),
        );
    }
    let document = json!({"@graph": graph});
    let frame_value =
        json!({"@context": {"@vocab": "http://s/"}, "@type": "Item", "@embed": "@always"});
    let options = JsonLdOptions {
        limits: jsonld_fast_core::JsonLdLimits {
            max_nodes: usize::MAX / 2,
            ..jsonld_fast_core::JsonLdLimits::default()
        },
        ..JsonLdOptions::default()
    };
    let framed = frame(&document, &frame_value, &options).expect("legitimate framing fits");
    assert!(
        framed
            .get("@graph")
            .and_then(Value::as_array)
            .is_some_and(|items| items.len() == 20_000)
    );
}
