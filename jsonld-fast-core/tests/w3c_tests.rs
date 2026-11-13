// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Curated W3C JSON-LD 1.1 API fixtures (inline contexts only).
//!
//! See [`tests/w3c/PROVENANCE.md`]. Remote-context tests must fail closed.

use std::path::Path;

use jsonld_fast_core::{JsonLdOptions, compact, expand, from_quads, to_quads};
use serde_json::Value;

fn load(path: &str) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("read {path}: {error}");
    });
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("json {path}: {error}"))
}

fn fixture(rel: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("w3c")
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn expand_prefix() {
    let got = expand(
        &load(&fixture("expand/prefix-in.json")),
        &JsonLdOptions::default(),
    )
    .expect("expand prefix");
    assert_eq!(got, load(&fixture("expand/prefix-out.json")));
}

#[test]
fn expand_vocab() {
    let got = expand(
        &load(&fixture("expand/vocab-in.json")),
        &JsonLdOptions::default(),
    )
    .expect("expand vocab");
    assert_eq!(got, load(&fixture("expand/vocab-out.json")));
}

#[test]
fn expand_type_coercion() {
    let got = expand(
        &load(&fixture("expand/type-coercion-in.json")),
        &JsonLdOptions::default(),
    )
    .expect("expand type coercion");
    assert_eq!(got, load(&fixture("expand/type-coercion-out.json")));
}

#[test]
fn expand_language() {
    let got = expand(
        &load(&fixture("expand/language-in.json")),
        &JsonLdOptions::default(),
    )
    .expect("expand language");
    assert_eq!(got, load(&fixture("expand/language-out.json")));
}

#[test]
fn expand_graph() {
    let got = expand(
        &load(&fixture("expand/graph-in.json")),
        &JsonLdOptions::default(),
    )
    .expect("expand graph");
    assert_eq!(got, load(&fixture("expand/graph-out.json")));
}

#[test]
fn expand_list() {
    let got = expand(
        &load(&fixture("expand/list-in.json")),
        &JsonLdOptions::default(),
    )
    .expect("expand list");
    assert_eq!(got, load(&fixture("expand/list-out.json")));
}

#[test]
fn expand_drops_id_only_nodes() {
    let got = expand(
        &load(&fixture("expand/drop-id-only-in.json")),
        &JsonLdOptions::default(),
    )
    .expect("expand id-only");
    assert_eq!(got, load(&fixture("expand/drop-id-only-out.json")));
}

#[test]
fn compact_prefix() {
    let got = compact(
        &load(&fixture("compact/prefix-in.json")),
        &load(&fixture("compact/prefix-context.json")),
        &JsonLdOptions::default(),
    )
    .expect("compact prefix");
    assert_eq!(got, load(&fixture("compact/prefix-out.json")));
}

#[test]
fn remote_context_is_refused_not_fetched() {
    let error = expand(
        &load(&fixture("expand/remote-context-in.json")),
        &JsonLdOptions::default(),
    )
    .expect_err("remote context");
    assert_eq!(error.code(), "remote_context_refused");
}

#[test]
fn to_rdf_and_from_rdf_round_trip_type_coercion() {
    let input = load(&fixture("expand/type-coercion-in.json"));
    let expanded = expand(&input, &JsonLdOptions::default()).expect("expand");
    let batches = to_quads(&input, &JsonLdOptions::default(), None).expect("toRdf");
    assert_eq!(batches[0].num_rows(), 1);
    let round_tripped = from_quads(&batches).expect("fromRdf");
    assert_eq!(round_tripped, expanded);
}
