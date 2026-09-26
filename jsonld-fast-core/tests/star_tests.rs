// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! JSON-LD-star embedded nodes (object-position quoted triples).

use jsonld_fast_core::{
    JsonLdError, JsonLdFeature, JsonLdOptions, compact, expand, from_quads, to_quads,
};
use oxrdf::TermRef;
use quad_fast_core::QuadStreamReader;
use serde_json::json;

fn options() -> JsonLdOptions {
    JsonLdOptions::default()
}

#[test]
fn embedded_id_expands_to_a_node_object() {
    let expanded = expand(
        &json!({
            "@id": "http://example.com/alice",
            "http://example.com/says": {
                "@id": {
                    "@id": "http://example.com/s",
                    "http://example.com/p": { "@id": "http://example.com/o" }
                }
            }
        }),
        &options(),
    )
    .expect("expand embedded @id");
    assert_eq!(
        expanded,
        json!([{
            "@id": "http://example.com/alice",
            "http://example.com/says": [{
                "@id": {
                    "@id": "http://example.com/s",
                    "http://example.com/p": [{ "@id": "http://example.com/o" }]
                }
            }]
        }])
    );
}

#[test]
fn object_position_quoted_triple_round_trips_through_rdf() {
    let document = json!({
        "@id": "http://example.com/alice",
        "http://example.com/says": {
            "@id": {
                "@id": "http://example.com/s",
                "http://example.com/p": { "@id": "http://example.com/o" }
            }
        }
    });
    let batches = to_quads(&document, &options(), None).expect("toRdf");
    let reader = QuadStreamReader::new(&batches[0]).expect("reader");
    assert_eq!(reader.len(), 1);
    assert!(reader.contains_triple_terms());
    let quad = reader
        .quad_owned(0, quad_fast_core::QuadLimits::default())
        .expect("quad");
    let TermRef::Triple(triple) = quad.object.as_ref() else {
        panic!("object must be a triple term: {quad}");
    };
    assert_eq!(triple.subject.to_string(), "<http://example.com/s>");
    assert_eq!(triple.predicate.as_str(), "http://example.com/p");
    assert_eq!(triple.object.to_string(), "<http://example.com/o>");

    let round_tripped = from_quads(&batches).expect("fromRdf");
    assert_eq!(
        round_tripped,
        expand(&document, &options()).expect("expand")
    );
}

#[test]
fn nested_object_position_quoted_triples_round_trip() {
    let document = json!({
        "@id": "http://example.com/alice",
        "http://example.com/says": {
            "@id": {
                "@id": "http://example.com/s",
                "http://example.com/p": {
                    "@id": {
                        "@id": "http://example.com/s2",
                        "http://example.com/p2": { "@id": "http://example.com/o2" }
                    }
                }
            }
        }
    });
    let batches = to_quads(&document, &options(), None).expect("toRdf nested");
    let round_tripped = from_quads(&batches).expect("fromRdf nested");
    assert_eq!(
        round_tripped,
        expand(&document, &options()).expect("expand")
    );
}

#[test]
fn quoted_triple_as_subject_is_refused_by_name() {
    let error = to_quads(
        &json!({
            "@id": {
                "@id": "http://example.com/bob",
                "http://example.com/age": 23
            },
            "http://example.com/certainty": 0.8
        }),
        &options(),
        None,
    )
    .expect_err("subject-position quoted triple");
    match error {
        JsonLdError::UnsupportedFeature {
            feature: JsonLdFeature::RdfStarTripleTerm,
        } => {}
        other => panic!("expected RdfStarTripleTerm, got {other}"),
    }
}

#[test]
fn reverse_annotation_emits_object_position_quoted_triple() {
    let document = json!({
        "@id": "http://example.com/bob",
        "http://example.com/age": {
            "@value": 23,
            "@annotation": {
                "@reverse": {
                    "http://example.com/certainty": { "@id": "http://example.com/alice" }
                }
            }
        }
    });
    let batches = to_quads(&document, &options(), None).expect("reverse annotation");
    let reader = QuadStreamReader::new(&batches[0]).expect("reader");
    assert_eq!(reader.len(), 2);
    assert!(reader.contains_triple_terms());
}

#[test]
fn forward_annotation_is_refused_by_name() {
    let error = to_quads(
        &json!({
            "@id": "http://example.com/bob",
            "http://example.com/age": {
                "@value": 23,
                "@annotation": {
                    "http://example.com/certainty": 0.8
                }
            }
        }),
        &options(),
        None,
    )
    .expect_err("forward annotation");
    assert_eq!(error.code(), "unsupported_feature");
}

#[test]
fn embedded_node_compacts_back() {
    let document = json!({
        "@id": "http://example.com/alice",
        "http://example.com/says": {
            "@id": {
                "@id": "http://example.com/s",
                "http://example.com/p": { "@id": "http://example.com/o" }
            }
        }
    });
    let compacted = compact(&document, &json!({}), &options()).expect("compact");
    let expanded = expand(&compacted, &options()).expect("re-expand");
    assert_eq!(expanded, expand(&document, &options()).expect("expand"));
}

#[test]
fn malformed_embedded_node_fails_closed() {
    let error = expand(
        &json!({
            "@id": "http://example.com/alice",
            "http://example.com/says": {
                "@id": {
                    "@id": "http://example.com/s",
                    "http://example.com/p": { "@id": "http://example.com/o" },
                    "http://example.com/q": { "@id": "http://example.com/r" }
                }
            }
        }),
        &options(),
    )
    .expect_err("two relationships");
    assert_eq!(error.code(), "invalid_document");
}
