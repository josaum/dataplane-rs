// Rust guideline compliant 2026-02-21
//! RDF deserialization and serialization behavior, including round-trips.

use arrow_array::RecordBatch;
use jsonld_fast_core::{JsonLdError, JsonLdOptions, from_quads, to_quads};
use quad_fast_core::{QuadStreamReader, SourceProvenance};
use serde_json::{Value, json};

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

fn quads(document: &Value) -> Vec<RecordBatch> {
    to_quads(document, &JsonLdOptions::default(), None).expect("deserialization succeeds")
}

#[test]
fn literals_follow_data_round_tripping_rules() {
    let batches = quads(&json!({
        "@id": "http://example.com/it",
        "http://example.com/int": 5,
        "http://example.com/integral": 5.0,
        "http://example.com/frac": 5.5,
        "http://example.com/flag": true,
        "http://example.com/text": "plain",
        "http://example.com/greeting": {"@value": "hallo", "@language": "de"}
    }));
    let lines = quad_lines(&batches);
    let expected = [
        "<http://example.com/it> <http://example.com/flag> \"true\"^^<http://www.w3.org/2001/XMLSchema#boolean>",
        "<http://example.com/it> <http://example.com/frac> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double>",
        "<http://example.com/it> <http://example.com/greeting> \"hallo\"@de",
        "<http://example.com/it> <http://example.com/int> \"5\"^^<http://www.w3.org/2001/XMLSchema#integer>",
        "<http://example.com/it> <http://example.com/integral> \"5\"^^<http://www.w3.org/2001/XMLSchema#integer>",
        "<http://example.com/it> <http://example.com/text> \"plain\"",
    ];
    let mut expected: Vec<String> = expected.iter().map(ToString::to_string).collect();
    expected.sort();
    assert_eq!(lines, expected);
}

#[test]
fn language_tags_are_lowercased() {
    let batches = quads(&json!({
        "@id": "http://example.com/it",
        "http://example.com/p": {"@value": "hi", "@language": "en-US"}
    }));
    assert!(quad_lines(&batches)[0].contains("\"hi\"@en-us"));
}

#[test]
fn typed_literal_with_explicit_datatype() {
    let batches = quads(&json!({
        "@id": "http://example.com/it",
        "http://example.com/when": {
            "@value": "2026-01-01",
            "@type": "http://www.w3.org/2001/XMLSchema#date"
        }
    }));
    assert!(quad_lines(&batches)[0].contains("XMLSchema#date"));
}

#[test]
fn lists_become_first_rest_chains() {
    let batches = quads(&json!({
        "@context": {"seq": {"@id": "http://example.com/seq", "@container": "@list"}},
        "@id": "http://example.com/it",
        "seq": ["a", "b"]
    }));
    let lines = quad_lines(&batches);
    let expected = [
        "<http://example.com/it> <http://example.com/seq> _:b0",
        "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> \"a\"",
        "_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> _:b1",
        "_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#first> \"b\"",
        "_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#rest> <http://www.w3.org/1999/02/22-rdf-syntax-ns#nil>",
    ];
    let mut expected: Vec<String> = expected.iter().map(ToString::to_string).collect();
    expected.sort();
    assert_eq!(lines, expected);
}

#[test]
fn empty_list_is_rdf_nil() {
    let batches = quads(&json!({
        "@id": "http://example.com/it",
        "http://example.com/seq": {"@list": []}
    }));
    let lines = quad_lines(&batches);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].ends_with("<http://www.w3.org/1999/02/22-rdf-syntax-ns#nil>"));
}

#[test]
fn from_quads_reassembles_lists() {
    let batches = quads(&json!({
        "@context": {"seq": {"@id": "http://example.com/seq", "@container": "@list"}},
        "@id": "http://example.com/it",
        "seq": ["a", "b"]
    }));
    let document = from_quads(&batches).expect("serialization succeeds");
    assert_eq!(
        document[0]["http://example.com/seq"],
        json!([{"@list": [{"@value": "a"}, {"@value": "b"}]}])
    );
}

#[test]
fn from_quads_reassembles_empty_list() {
    let batches = quads(&json!({
        "@id": "http://example.com/it",
        "http://example.com/seq": {"@list": []}
    }));
    let document = from_quads(&batches).expect("serialization succeeds");
    assert_eq!(
        document[0]["http://example.com/seq"],
        json!([{"@list": []}])
    );
}

#[test]
fn from_quads_leaves_malformed_lists_as_triples() {
    let batches = quads(&json!({
        "@id": "_:b0",
        "http://www.w3.org/1999/02/22-rdf-syntax-ns#first": "a",
        "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest": {
            "@id": "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil"
        },
        "http://example.com/extra": "nope"
    }));
    let document = from_quads(&batches).expect("serialization succeeds");
    let node = &document[0];
    assert!(node["http://www.w3.org/1999/02/22-rdf-syntax-ns#first"].is_array());
    assert!(node.get("http://example.com/seq").is_none());
    assert!(node.get("@list").is_none());
}

#[test]
fn named_graphs_and_default_graph_coexist() {
    let batches = quads(&json!({
        "@id": "http://example.com/g",
        "http://example.com/meta": "m",
        "@graph": [
            {"@id": "http://example.com/a", "http://example.com/p": "x"}
        ]
    }));
    let lines = quad_lines(&batches);
    let expected = [
        "<http://example.com/a> <http://example.com/p> \"x\" <http://example.com/g>",
        "<http://example.com/g> <http://example.com/meta> \"m\"",
    ];
    let mut expected: Vec<String> = expected.iter().map(ToString::to_string).collect();
    expected.sort();
    assert_eq!(lines, expected);
}

#[test]
fn anonymous_graph_gets_blank_node_name() {
    let batches = quads(&json!([{
        "@graph": [
            {"@id": "http://example.com/a", "http://example.com/p": "x"}
        ],
        "http://example.com/meta": "m"
    }]));
    let lines = quad_lines(&batches);
    assert!(lines.iter().any(|line| line.contains("\"x\" _:b0")));
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("_:b0 <http://example.com/meta>"))
    );
}

#[test]
fn blank_node_labels_are_deterministic() {
    let document = json!({
        "@id": "http://example.com/it",
        "http://example.com/knows": [
            {"http://example.com/name": "anon one"},
            {"@id": "_:known", "http://example.com/name": "anon two"}
        ]
    });
    let first = quad_lines(&quads(&document));
    let second = quad_lines(&quads(&document));
    assert_eq!(first, second);
    assert!(first.iter().any(|line| line.contains("_:b0")));
    assert!(first.iter().any(|line| line.contains("_:b1")));
}

#[test]
fn relative_iri_fails_closed() {
    let error = to_quads(
        &json!({"@id": "relative-doc", "http://example.com/p": "v"}),
        &JsonLdOptions::default(),
        None,
    )
    .expect_err("relative IRI must fail");
    match error {
        JsonLdError::RelativeIri { iri } => assert_eq!(iri, "relative-doc"),
        other => panic!("expected RelativeIri, got {other}"),
    }
    assert_eq!(
        JsonLdError::RelativeIri { iri: String::new() }.code(),
        "relative_iri"
    );
}

#[test]
fn blank_node_predicates_fail_closed() {
    let error = to_quads(
        &json!({"@id": "http://example.com/it", "_:p": [{"@value": "v"}]}),
        &JsonLdOptions::default(),
        None,
    )
    .expect_err("blank node predicates are unrepresentable");
    assert_eq!(error.code(), "invalid_term");
}

#[test]
fn provenance_is_stamped_on_every_row() {
    let provenance = SourceProvenance {
        source_artifact_iri: Some("http://example.com/doc.jsonld".to_owned()),
        source_content_sha256: Some([7; 32]),
        source_offset_start: Some(0),
        source_offset_end: Some(42),
        observed_at_micros: Some(1_700_000_000_000_000),
    };
    let batches = to_quads(
        &json!({
            "@id": "http://example.com/it",
            "http://example.com/p": ["a", "b"]
        }),
        &JsonLdOptions::default(),
        Some(&provenance),
    )
    .expect("deserialization succeeds");
    let reader = QuadStreamReader::new(&batches[0]).expect("valid batch");
    assert_eq!(reader.len(), 2);
    for row in 0..reader.len() {
        let stamped = reader.provenance(row);
        assert_eq!(
            stamped.source_artifact_iri,
            Some("http://example.com/doc.jsonld")
        );
        assert_eq!(stamped.source_offset_end, Some(42));
    }
}

#[test]
fn from_quads_groups_named_graphs() {
    let batches = quads(&json!({
        "@id": "http://example.com/g",
        "http://example.com/meta": "m",
        "@graph": [
            {"@id": "http://example.com/a", "http://example.com/p": "x"}
        ]
    }));
    let document = from_quads(&batches).expect("serialization succeeds");
    assert_eq!(
        document,
        json!([{
            "@id": "http://example.com/g",
            "http://example.com/meta": [{"@value": "m"}],
            "@graph": [{
                "@id": "http://example.com/a",
                "http://example.com/p": [{"@value": "x"}]
            }]
        }])
    );
}

#[test]
fn from_quads_renders_types_and_literals() {
    let batches = quads(&json!({
        "@id": "http://example.com/it",
        "@type": "http://example.com/T",
        "http://example.com/n": 5,
        "http://example.com/s": "text",
        "http://example.com/l": {"@value": "hallo", "@language": "de"}
    }));
    let document = from_quads(&batches).expect("serialization succeeds");
    let node = &document[0];
    assert_eq!(node["@type"], json!(["http://example.com/T"]));
    assert_eq!(
        node["http://example.com/n"][0],
        json!({"@value": "5", "@type": "http://www.w3.org/2001/XMLSchema#integer"})
    );
    assert_eq!(node["http://example.com/s"][0], json!({"@value": "text"}));
    assert_eq!(
        node["http://example.com/l"][0],
        json!({"@value": "hallo", "@language": "de"})
    );
}

/// JSON-LD -> quads -> JSON-LD -> quads: the second pass must reproduce the
/// first pass's quad set exactly (small, ordered blank node population).
#[test]
fn round_trip_preserves_quad_set() {
    let document = json!({
        "@context": {
            "name": "http://schema.org/name",
            "knows": {"@id": "http://schema.org/knows", "@type": "@id"}
        },
        "@id": "http://example.com/alice",
        "@type": "http://schema.org/Person",
        "name": "Alice",
        "knows": "http://example.com/bob",
        "http://schema.org/age": 31
    });
    let first = quads(&document);
    let serialized = from_quads(&first).expect("serialization succeeds");
    let second = quads(&serialized);
    assert_eq!(quad_lines(&first), quad_lines(&second));
}

#[test]
fn round_trip_named_graphs_and_language() {
    let document = json!({
        "@id": "http://example.com/g",
        "http://example.com/meta": {"@value": "hallo", "@language": "de"},
        "@graph": [
            {"@id": "http://example.com/a", "http://example.com/p": 2.5}
        ]
    });
    let first = quads(&document);
    let serialized = from_quads(&first).expect("serialization succeeds");
    let second = quads(&serialized);
    assert_eq!(quad_lines(&first), quad_lines(&second));
}

/// With many interlinked blank nodes the relabeling may permute on the first
/// re-pass; the second re-pass must be a fixed point.
#[test]
fn round_trip_blank_nodes_reach_a_fixed_point() {
    let document = json!({
        "@context": {"seq": {"@id": "http://example.com/seq", "@container": "@list"}},
        "@id": "http://example.com/it",
        "seq": ["a", "b", "c", "d"],
        "http://example.com/knows": [
            {"http://example.com/name": "one"},
            {"http://example.com/name": "two"}
        ]
    });
    let first = quads(&document);
    let second = quads(&from_quads(&first).expect("first serialization"));
    let third = quads(&from_quads(&second).expect("second serialization"));
    assert_eq!(quad_lines(&second), quad_lines(&third));
    assert_eq!(quad_lines(&first).len(), quad_lines(&second).len());
}

/// One batch carrying an RDF 1.2 triple term in the object position.
fn triple_term_batch() -> RecordBatch {
    use oxrdf::{GraphName, NamedNode, Quad, Term, Triple};
    use quad_fast_core::{QuadBatchBuilder, QuadLimits};

    let node = |value: &str| NamedNode::new(value).expect("valid IRI");
    let quad = Quad::new(
        node("http://example.com/alice"),
        node("http://example.com/says"),
        Term::Triple(Box::new(Triple::new(
            node("http://example.com/s"),
            node("http://example.com/p"),
            node("http://example.com/o"),
        ))),
        GraphName::DefaultGraph,
    );
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    builder.push(quad.as_ref(), None).expect("quad accepted");
    builder.finish().expect("batch built")
}

#[test]
fn from_rdf_emits_jsonld_star_embedded_nodes_for_object_position_triples() {
    let expanded = from_quads(&[triple_term_batch()]).expect("object-position triple term");
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
fn from_rdf_still_accepts_batches_without_triple_terms() {
    // The refusal is targeted: ordinary batches are unaffected.
    let batches = quads(&json!({
        "@id": "http://example.com/it",
        "http://example.com/p": { "@id": "http://example.com/o" },
    }));
    from_quads(&batches).expect("plain batches still convert");
}

/// Lists nested three deep (a list whose item is a list whose item is a
/// list) must round-trip through `fromRdf` without losing the innermost
/// items: every quad of the original survives a second `toRdf`.
#[test]
fn nested_lists_three_deep_round_trip_without_loss() {
    let document = json!({
        "@id": "http://example.com/s",
        "http://example.com/p": {"@list": [
            {"@list": [
                {"@list": ["innermost", "items"]},
                "middle"
            ]},
            "outer"
        ]}
    });
    let original = quads(&document);
    let expanded = from_quads(&original).expect("fromRdf succeeds");
    let round_tripped = quads(&expanded);
    assert_eq!(quad_lines(&round_tripped), quad_lines(&original));
}

/// A well-formed list that nothing references has no place to be
/// substituted; it must stay as `rdf:first`/`rdf:rest` triples, not vanish.
#[test]
fn unreferenced_list_survives_from_rdf() {
    let rdf = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
    let document = json!({"@graph": [{
        "@id": "_:l0",
        format!("{rdf}first"): "a",
        format!("{rdf}rest"): {"@id": format!("{rdf}nil")}
    }]});
    let original = quads(&document);
    let expanded = from_quads(&original).expect("fromRdf succeeds");
    assert_eq!(quad_lines(&quads(&expanded)), quad_lines(&original));
}
