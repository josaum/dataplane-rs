// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! YAML-LD Basic profile: YAML 1.2 Core Schema → JSON-LD.

use jsonld_fast_core::{
    JsonLdError, JsonLdOptions, YamlLdOptions, YamlLdProfile, expand, expand_yaml_ld,
    parse_yaml_ld, parse_yaml_ld_bytes, to_quads, to_quads_yaml_ld, to_yaml_ld,
};
use serde_json::json;

fn options() -> YamlLdOptions {
    YamlLdOptions::default()
}

#[test]
fn yaml_ld_expands_like_equivalent_json_ld() {
    let yaml = r#"
"@context":
  name: http://schema.org/name
"@id": http://example.com/alice
name: Alice
"#;
    let expanded = expand_yaml_ld(yaml, &options()).expect("expand yaml-ld");
    let json = json!({
        "@context": {"name": "http://schema.org/name"},
        "@id": "http://example.com/alice",
        "name": "Alice"
    });
    assert_eq!(
        expanded,
        expand(&json, &JsonLdOptions::default()).expect("expand json")
    );
}

#[test]
fn norway_problem_plain_no_stays_a_string() {
    // YAML 1.1 would parse `no` as boolean false. YAML-LD requires 1.2 Core
    // Schema, so the country code remains the string "no".
    let yaml = r#"
"@id": http://example.com/place
"http://example.com/country": no
"#;
    let document = parse_yaml_ld(yaml, &options()).expect("parse");
    assert_eq!(
        document["http://example.com/country"],
        json!("no"),
        "YAML 1.2 Core Schema must not booleanize `no`"
    );
}

#[test]
fn comments_are_whitespace() {
    let yaml = r#"
# leading comment
"@id": http://example.com/alice # inline
"http://schema.org/name": Alice
"#;
    let document = parse_yaml_ld(yaml, &options()).expect("parse");
    assert_eq!(document["@id"], json!("http://example.com/alice"));
    assert_eq!(document["http://schema.org/name"], json!("Alice"));
}

#[test]
fn integer_mapping_key_is_refused() {
    let yaml = "1: value\n";
    let error = parse_yaml_ld(yaml, &options()).expect_err("integer key");
    assert_eq!(error.code(), "mapping_key_error");
}

#[test]
fn alias_nodes_are_a_profile_error() {
    let yaml = r#"
anchor: &shared { "@id": "http://example.com/us" }
copy: *shared
"#;
    let error = parse_yaml_ld(yaml, &options()).expect_err("alias");
    match error {
        JsonLdError::YamlProfile(detail) => {
            assert!(detail.contains("alias"), "{detail}");
        }
        other => panic!("expected YamlProfile, got {other}"),
    }
}

#[test]
fn inf_float_fails_closed() {
    let yaml = r#"
"@id": http://example.com/n
"http://example.com/value": .inf
"#;
    let error = parse_yaml_ld(yaml, &options()).expect_err("inf");
    assert_eq!(error.code(), "loading_document_failed");
}

#[test]
fn utf16_bom_is_invalid_encoding() {
    let error = parse_yaml_ld_bytes(
        &[0xFF, 0xFE, b'a', 0, b':', 0, b' ', 0, b'1', 0],
        &options(),
    )
    .expect_err("utf16");
    assert_eq!(error.code(), "invalid_encoding");
}

#[test]
fn extract_all_scripts_returns_every_document() {
    let yaml = r#"
"@id": http://example.com/one
---
"@id": http://example.com/two
"#;
    let first_only = parse_yaml_ld(yaml, &options()).expect("first");
    assert_eq!(first_only["@id"], json!("http://example.com/one"));

    let mut all = options();
    all.extract_all_scripts = true;
    let stream = parse_yaml_ld(yaml, &all).expect("all");
    assert_eq!(
        stream,
        json!([
            {"@id": "http://example.com/one"},
            {"@id": "http://example.com/two"}
        ])
    );
}

#[test]
fn json_yaml_json_round_trip_preserves_the_data_model() {
    let original = json!({
        "@context": {"name": "http://schema.org/name"},
        "@id": "http://example.com/alice",
        "name": "Alice",
        "age": 30,
        "ok": true,
        "tags": ["a", "b"]
    });
    let yaml = to_yaml_ld(&original).expect("to yaml");
    let back = parse_yaml_ld(&yaml, &options()).expect("from yaml");
    assert_eq!(back, original);
}

#[test]
fn to_quads_yaml_ld_matches_json() {
    let yaml = r#"
"@id": http://example.com/alice
"http://schema.org/name": Alice
"#;
    let yaml_batches = to_quads_yaml_ld(yaml, &options(), None).expect("yaml quads");
    let json = json!({
        "@id": "http://example.com/alice",
        "http://schema.org/name": "Alice"
    });
    let json_batches = to_quads(&json, &JsonLdOptions::default(), None).expect("json quads");
    assert_eq!(yaml_batches[0].num_rows(), json_batches[0].num_rows());
}

#[test]
fn remote_context_in_yaml_ld_is_still_refused() {
    let yaml = r#"
"@context": https://schema.org/
"@id": http://example.com/alice
"#;
    let error = expand_yaml_ld(yaml, &options()).expect_err("remote");
    assert_eq!(error.code(), "remote_context_refused");
}

fn extended() -> YamlLdOptions {
    YamlLdOptions {
        profile: YamlLdProfile::Extended,
        ..YamlLdOptions::default()
    }
}

#[test]
fn extended_aliases_compose_as_copies() {
    let yaml = r#"
"@context":
  homepage: &idterm
    "@id": http://schema.org/url
    "@type": "@id"
  page: *idterm
  name: http://schema.org/name
"@id": http://example.com/alice
homepage: http://example.com/alice/
name: Alice
"#;
    let document = parse_yaml_ld(yaml, &extended()).expect("extended aliases");
    assert_eq!(
        document["@context"]["page"],
        json!({ "@id": "http://schema.org/url", "@type": "@id" })
    );
    let expanded = expand_yaml_ld(yaml, &extended()).expect("expand");
    assert_eq!(
        expanded[0]["http://schema.org/url"],
        json!([{ "@id": "http://example.com/alice/" }])
    );
}

#[test]
fn extended_iri_tags_become_typed_value_objects() {
    let yaml = r#"
"@id": http://example.com/n
"http://example.com/when": !<http://www.w3.org/2001/XMLSchema#date> "2026-01-25"
"#;
    let document = parse_yaml_ld(yaml, &extended()).expect("tagged scalar");
    assert_eq!(
        document["http://example.com/when"],
        json!({
            "@value": "2026-01-25",
            "@type": "http://www.w3.org/2001/XMLSchema#date"
        })
    );
}

#[test]
fn extended_local_tags_that_are_not_iris_fail_closed() {
    let yaml = r#"
"@id": http://example.com/n
"http://example.com/value": !local 1
"#;
    let error = parse_yaml_ld(yaml, &extended()).expect_err("local tag");
    assert_eq!(error.code(), "profile_error");
}

/// A "billion laughs" alias bomb: nine anchors, each aliasing the previous
/// one ten times, composes to 10^9 scalars from about 400 bytes. The
/// Extended profile (which permits aliases) must refuse it by budget before
/// composition instead of deep-copying every alias.
#[test]
fn extended_profile_alias_bomb_is_refused_by_node_budget() {
    let mut text = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
    for level in 1..10 {
        let previous = format!("*a{}", level - 1);
        let items = [previous.as_str(); 10].join(", ");
        text.push_str(&format!("a{level}: &a{level} [{items}]\n"));
    }
    let options = YamlLdOptions {
        profile: YamlLdProfile::Extended,
        ..YamlLdOptions::default()
    };
    let started = std::time::Instant::now();
    let error = parse_yaml_ld(&text, &options).expect_err("alias bomb is refused");
    assert_eq!(error.code(), "resource_limit", "{error}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "refusal must not compose the bomb first"
    );
}
