// Rust guideline compliant 2026-02-21
//! Scoped contexts are processed once per distinct scope, not per node.

use std::time::{Duration, Instant};

use jsonld_fast_core::{JsonLdOptions, expand};
use serde_json::{Map, Value, json};

/// A type-scoped context of `terms` terms applied to `nodes` nodes.
fn type_scoped_document(terms: usize, nodes: usize) -> Value {
    let mut scoped = Map::new();
    for index in 0..terms {
        scoped.insert(
            format!("t{index}"),
            json!(format!("http://example.com/t{index}")),
        );
    }
    let graph: Vec<Value> = (0..nodes)
        .map(
            |index| json!({"@id": format!("http://example.com/n{index}"), "@type": "T", "t0": "x"}),
        )
        .collect();
    json!({
        "@context": {"T": {"@id": "http://example.com/T", "@context": Value::Object(scoped)}},
        "@graph": graph
    })
}

/// A property-scoped context given as an array of `entries` contexts,
/// used at `uses` property occurrences.
fn property_scoped_array_document(entries: usize, uses: usize) -> Value {
    let contexts: Vec<Value> = (0..entries)
        .map(|index| json!({format!("c{index}"): format!("http://example.com/c{index}")}))
        .collect();
    let graph: Vec<Value> = (0..uses)
        .map(|index| json!({"@id": format!("http://example.com/n{index}"), "p": {"c0": "x"}}))
        .collect();
    json!({
        "@context": {"p": {"@id": "http://example.com/p", "@context": contexts}},
        "@graph": graph
    })
}

fn timed_expand(document: &Value) -> Duration {
    let started = Instant::now();
    let expanded = expand(document, &JsonLdOptions::default()).expect("expands");
    assert!(expanded.as_array().is_some_and(|nodes| !nodes.is_empty()));
    started.elapsed()
}

/// Debug-speed variant: n = 2,000 took about 3 s optimized (30 s
/// unoptimized) when each node reprocessed the scoped context.
#[test]
fn scoped_contexts_are_not_reprocessed_per_node() {
    let type_scoped = timed_expand(&type_scoped_document(2_000, 2_000));
    let property_scoped = timed_expand(&property_scoped_array_document(2_000, 2_000));
    println!("n=2000: type-scoped {type_scoped:?}, property-scoped array {property_scoped:?}");
    assert!(type_scoped < Duration::from_secs(5), "{type_scoped:?}");
    assert!(
        property_scoped < Duration::from_secs(5),
        "{property_scoped:?}"
    );
}

/// Release-only: n = 4,000 took 13.4 s and 15.6 s before the cache.
#[test]
#[ignore = "timing bound for optimized builds: run with --release -- --ignored"]
fn scoped_contexts_at_4000_finish_under_a_second_optimized() {
    let type_scoped = timed_expand(&type_scoped_document(4_000, 4_000));
    let property_scoped = timed_expand(&property_scoped_array_document(4_000, 4_000));
    println!("n=4000: type-scoped {type_scoped:?}, property-scoped array {property_scoped:?}");
    assert!(type_scoped < Duration::from_secs(1), "{type_scoped:?}");
    assert!(
        property_scoped < Duration::from_secs(1),
        "{property_scoped:?}"
    );
}
