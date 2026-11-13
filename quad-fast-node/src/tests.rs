// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21

//! Unit tests for the napi-free conversion layer.
//!
//! These tests exercise [`crate::convert`] directly with `serde_json`
//! values, so the cargo gate never needs a Node runtime or a built `.node`
//! artifact. Coverage is a named deliverable: spec-anchored positive tests,
//! one fail-closed test per typed error path, and round-trip tests.

use serde_json::{Value, json};

use crate::convert::{
    BindingError, ipc_to_quads, jelly_frames_to_quads, quads_to_ipc, quads_to_jelly_frames,
};

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// One quad of every term shape, written in already-canonical output form
/// (explicit datatypes, explicit graph) so round trips compare equal.
fn canonical_quads() -> Value {
    json!([
        {
            "subject": { "kind": "iri", "value": "http://example.com/s" },
            "predicate": "http://example.com/p",
            "object": { "kind": "iri", "value": "http://example.com/o" },
            "graph": { "kind": "default" },
        },
        {
            "subject": { "kind": "bnode", "value": "b0" },
            "predicate": "http://example.com/p",
            "object": {
                "kind": "literal",
                "value": "42",
                "datatype": "http://www.w3.org/2001/XMLSchema#integer",
            },
            "graph": { "kind": "iri", "value": "http://example.com/g" },
        },
        {
            "subject": { "kind": "iri", "value": "http://example.com/s" },
            "predicate": "http://example.com/p",
            "object": { "kind": "literal", "value": "ola", "language": "pt" },
            "graph": { "kind": "bnode", "value": "g0" },
        },
        {
            "subject": { "kind": "iri", "value": "http://example.com/s" },
            "predicate": "http://example.com/p",
            "object": { "kind": "bnode", "value": "b1" },
            "graph": { "kind": "default" },
        },
    ])
}

/// A quad carrying every provenance field, in canonical output form.
fn provenance_quad() -> Value {
    json!([{
        "subject": { "kind": "iri", "value": "http://example.com/s" },
        "predicate": "http://example.com/p",
        "object": {
            "kind": "literal",
            "value": "v",
            "datatype": "http://www.w3.org/2001/XMLSchema#string",
        },
        "graph": { "kind": "default" },
        "provenance": {
            "sourceArtifactIri": "http://example.com/doc.jsonld",
            "sourceContentSha256":
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "sourceOffsetStart": 10,
            "sourceOffsetEnd": 99,
            "observedAtMicros": 1_756_684_800_000_000i64,
        },
    }])
}

fn code_of(error: &BindingError) -> &'static str {
    error.code()
}

// ---------------------------------------------------------------------------
// Round trips.
// ---------------------------------------------------------------------------

#[test]
fn ipc_round_trip_preserves_all_term_shapes() {
    let quads = canonical_quads();
    let ipc = quads_to_ipc(&quads, None).expect("encode");
    let decoded = ipc_to_quads(&ipc, None).expect("decode");
    assert_eq!(decoded, quads);
}

#[test]
fn ipc_round_trip_preserves_provenance() {
    let quads = provenance_quad();
    let ipc = quads_to_ipc(&quads, None).expect("encode");
    let decoded = ipc_to_quads(&ipc, None).expect("decode");
    assert_eq!(decoded, quads);
}

#[test]
fn jelly_round_trip_preserves_all_term_shapes() {
    let quads = canonical_quads();
    let frames = quads_to_jelly_frames(&quads, None).expect("encode");
    let decoded = jelly_frames_to_quads(&frames, None).expect("decode");
    assert_eq!(decoded, quads);
}

#[test]
fn jelly_round_trip_chunks_across_frames() {
    let quads = canonical_quads();
    let frames =
        quads_to_jelly_frames(&quads, Some(&json!({ "quadsPerFrame": 1 }))).expect("encode");
    let decoded = jelly_frames_to_quads(&frames, None).expect("decode");
    assert_eq!(decoded, quads);
}

#[test]
fn simple_literal_round_trips_with_explicit_xsd_string() {
    // Spec anchor: the contract stores simple literals with an explicit
    // `xsd:string` datatype (see `QuadBatchBuilder::push` docs), so the
    // canonical output form always names the datatype.
    let quads = json!([{
        "subject": { "kind": "iri", "value": "http://example.com/s" },
        "predicate": "http://example.com/p",
        "object": { "kind": "literal", "value": "plain" },
    }]);
    let ipc = quads_to_ipc(&quads, None).expect("encode");
    let decoded = ipc_to_quads(&ipc, None).expect("decode");
    assert_eq!(
        decoded[0]["object"]["datatype"],
        json!("http://www.w3.org/2001/XMLSchema#string")
    );
    // The omitted graph is reported explicitly as the default graph.
    assert_eq!(decoded[0]["graph"], json!({ "kind": "default" }));
}

#[test]
fn empty_input_round_trips_through_both_codecs() {
    let quads = json!([]);
    let ipc = quads_to_ipc(&quads, None).expect("encode ipc");
    assert_eq!(ipc_to_quads(&ipc, None).expect("decode ipc"), json!([]));
    // An empty Jelly stream still carries the mandatory options row.
    let frames = quads_to_jelly_frames(&quads, None).expect("encode jelly");
    assert!(!frames.is_empty());
    assert_eq!(
        jelly_frames_to_quads(&frames, None).expect("decode jelly"),
        json!([])
    );
}

#[test]
fn ipc_bytes_carry_the_unsigned_assurance_metadata() {
    // Spec anchor: `UnsignedQuadStream` v1 schema metadata (TASK-GRAPH N1).
    let ipc = quads_to_ipc(&canonical_quads(), None).expect("encode");
    let batches = quad_fast_core::read_ipc_stream(&ipc).expect("contract batches");
    let schema = batches[0].schema();
    let metadata = schema.metadata();
    assert_eq!(
        metadata.get("dataplane.assurance").map(String::as_str),
        Some("unsigned")
    );
    assert_eq!(
        metadata.get("dataplane.contract").map(String::as_str),
        Some("UnsignedQuadStream")
    );
}

#[test]
fn jelly_provenance_loss_requires_explicit_consent() {
    let quads = provenance_quad();
    // Refused by default: Jelly has no provenance fields.
    let error = quads_to_jelly_frames(&quads, None).expect_err("must refuse");
    assert_eq!(code_of(&error), "unsupported");
    // With explicit consent the encode succeeds and provenance is gone.
    let frames = quads_to_jelly_frames(&quads, Some(&json!({ "allowProvenanceLoss": true })))
        .expect("encode with consent");
    let decoded = jelly_frames_to_quads(&frames, None).expect("decode");
    assert_eq!(decoded[0].get("provenance"), None);
}

// ---------------------------------------------------------------------------
// Fail-closed error paths: BindingError::Input.
// ---------------------------------------------------------------------------

#[test]
fn input_error_when_quads_is_not_an_array() {
    let error = quads_to_ipc(&json!({}), None).expect_err("must fail");
    assert_eq!(code_of(&error), "input");
}

#[test]
fn input_error_on_missing_predicate() {
    let quads = json!([{
        "subject": { "kind": "iri", "value": "http://example.com/s" },
        "object": { "kind": "iri", "value": "http://example.com/o" },
    }]);
    let error = quads_to_ipc(&quads, None).expect_err("must fail");
    assert_eq!(code_of(&error), "input");
    assert!(error.to_string().contains("predicate"));
}

#[test]
fn input_error_on_unknown_quad_key() {
    let quads = json!([{
        "subject": { "kind": "iri", "value": "http://example.com/s" },
        "predicate": "http://example.com/p",
        "object": { "kind": "iri", "value": "http://example.com/o" },
        "sneaky": true,
    }]);
    let error = quads_to_ipc(&quads, None).expect_err("must fail");
    assert_eq!(code_of(&error), "input");
    assert!(error.to_string().contains("sneaky"));
}

#[test]
fn input_error_on_unknown_option_key() {
    let error = quads_to_ipc(&json!([]), Some(&json!({ "maxQauds": 1 }))).expect_err("must fail");
    assert_eq!(code_of(&error), "input");
    assert!(error.to_string().contains("maxQauds"));
}

#[test]
fn input_error_on_bad_subject_kind() {
    let quads = json!([{
        "subject": { "kind": "literal", "value": "nope" },
        "predicate": "http://example.com/p",
        "object": { "kind": "iri", "value": "http://example.com/o" },
    }]);
    let error = quads_to_ipc(&quads, None).expect_err("must fail");
    assert_eq!(code_of(&error), "input");
}

#[test]
fn input_error_on_invalid_predicate_iri() {
    let quads = json!([{
        "subject": { "kind": "iri", "value": "http://example.com/s" },
        "predicate": "not an iri",
        "object": { "kind": "iri", "value": "http://example.com/o" },
    }]);
    let error = quads_to_ipc(&quads, None).expect_err("must fail");
    assert_eq!(code_of(&error), "input");
}

#[test]
fn input_error_when_literal_has_datatype_and_language() {
    let quads = json!([{
        "subject": { "kind": "iri", "value": "http://example.com/s" },
        "predicate": "http://example.com/p",
        "object": {
            "kind": "literal",
            "value": "x",
            "datatype": "http://www.w3.org/2001/XMLSchema#string",
            "language": "en",
        },
    }]);
    let error = quads_to_ipc(&quads, None).expect_err("must fail");
    assert_eq!(code_of(&error), "input");
    assert!(error.to_string().contains("mutually exclusive"));
}

#[test]
fn input_error_when_non_literal_carries_language() {
    let quads = json!([{
        "subject": { "kind": "iri", "value": "http://example.com/s" },
        "predicate": "http://example.com/p",
        "object": { "kind": "iri", "value": "http://example.com/o", "language": "en" },
    }]);
    let error = quads_to_ipc(&quads, None).expect_err("must fail");
    assert_eq!(code_of(&error), "input");
}

#[test]
fn input_error_on_malformed_language_tag() {
    let quads = json!([{
        "subject": { "kind": "iri", "value": "http://example.com/s" },
        "predicate": "http://example.com/p",
        "object": { "kind": "literal", "value": "x", "language": "-bad-" },
    }]);
    let error = quads_to_ipc(&quads, None).expect_err("must fail");
    assert_eq!(code_of(&error), "input");
}

#[test]
fn input_error_when_named_graph_lacks_value() {
    let quads = json!([{
        "subject": { "kind": "iri", "value": "http://example.com/s" },
        "predicate": "http://example.com/p",
        "object": { "kind": "iri", "value": "http://example.com/o" },
        "graph": { "kind": "iri" },
    }]);
    let error = quads_to_ipc(&quads, None).expect_err("must fail");
    assert_eq!(code_of(&error), "input");
}

#[test]
fn input_error_when_default_graph_carries_value() {
    let quads = json!([{
        "subject": { "kind": "iri", "value": "http://example.com/s" },
        "predicate": "http://example.com/p",
        "object": { "kind": "iri", "value": "http://example.com/o" },
        "graph": { "kind": "default", "value": "http://example.com/g" },
    }]);
    let error = quads_to_ipc(&quads, None).expect_err("must fail");
    assert_eq!(code_of(&error), "input");
}

#[test]
fn input_error_on_bad_sha256_hex() {
    for bad in ["deadbeef", &"zz".repeat(32)] {
        let quads = json!([{
            "subject": { "kind": "iri", "value": "http://example.com/s" },
            "predicate": "http://example.com/p",
            "object": { "kind": "iri", "value": "http://example.com/o" },
            "provenance": { "sourceContentSha256": bad },
        }]);
        let error = quads_to_ipc(&quads, None).expect_err("must fail");
        assert_eq!(code_of(&error), "input");
    }
}

#[test]
fn input_error_on_negative_or_fractional_offset() {
    for bad in [json!(-1), json!(1.5)] {
        let quads = json!([{
            "subject": { "kind": "iri", "value": "http://example.com/s" },
            "predicate": "http://example.com/p",
            "object": { "kind": "iri", "value": "http://example.com/o" },
            "provenance": { "sourceOffsetStart": bad },
        }]);
        let error = quads_to_ipc(&quads, None).expect_err("must fail");
        assert_eq!(code_of(&error), "input");
    }
}

// ---------------------------------------------------------------------------
// Fail-closed error paths: resource limits (binding and core).
// ---------------------------------------------------------------------------

#[test]
fn quad_budget_is_enforced_while_building() {
    let error =
        quads_to_ipc(&canonical_quads(), Some(&json!({ "maxQuads": 2 }))).expect_err("must fail");
    assert_eq!(code_of(&error), "resource_limit");
}

#[test]
fn ipc_input_byte_budget_is_enforced_before_decoding() {
    let ipc = quads_to_ipc(&canonical_quads(), None).expect("encode");
    let error = ipc_to_quads(&ipc, Some(&json!({ "maxIpcBytes": 8 }))).expect_err("must fail");
    assert!(matches!(
        error,
        BindingError::ResourceLimit {
            resource: "ipc_input_bytes",
            ..
        }
    ));
}

#[test]
fn decoded_quad_budget_is_enforced_on_ipc_read() {
    let ipc = quads_to_ipc(&canonical_quads(), None).expect("encode");
    let error = ipc_to_quads(&ipc, Some(&json!({ "maxQuads": 1 }))).expect_err("must fail");
    assert!(matches!(
        error,
        BindingError::ResourceLimit {
            resource: "decoded_quads",
            limit: 1,
            ..
        }
    ));
}

#[test]
fn jelly_input_byte_budget_is_enforced_before_decoding() {
    let frames = quads_to_jelly_frames(&canonical_quads(), None).expect("encode");
    let error = jelly_frames_to_quads(&frames, Some(&json!({ "maxInputBytes": 4 })))
        .expect_err("must fail");
    assert!(matches!(
        error,
        BindingError::ResourceLimit {
            resource: "jelly_input_bytes",
            ..
        }
    ));
}

#[test]
fn jelly_frame_budget_is_enforced_while_decoding() {
    let frames = quads_to_jelly_frames(&canonical_quads(), Some(&json!({ "quadsPerFrame": 1 })))
        .expect("encode");
    let error =
        jelly_frames_to_quads(&frames, Some(&json!({ "maxFrames": 1 }))).expect_err("must fail");
    assert!(matches!(
        error,
        BindingError::ResourceLimit {
            resource: "jelly_frames",
            limit: 1,
            ..
        }
    ));
}

#[test]
fn jelly_decoder_rejects_tables_beyond_its_maxima() {
    // The encoder declares the default 4000-entry name table; a decoder
    // configured to accept at most the spec minimum must refuse it.
    let frames = quads_to_jelly_frames(&canonical_quads(), None).expect("encode");
    let error = jelly_frames_to_quads(&frames, Some(&json!({ "maxNameTableSize": 8 })))
        .expect_err("must fail");
    assert_eq!(code_of(&error), "resource_limit");
}

// ---------------------------------------------------------------------------
// Fail-closed error paths: frame decoding, jelly options, precision.
// ---------------------------------------------------------------------------

#[test]
fn frame_decode_error_on_garbage_bytes() {
    let error = jelly_frames_to_quads(&[0xff, 0xff, 0xff, 0xff], None).expect_err("must fail");
    assert_eq!(code_of(&error), "frame_decode");
}

#[test]
fn frame_decode_error_on_malformed_trailing_bytes() {
    let mut frames = quads_to_jelly_frames(&canonical_quads(), None).expect("encode");
    frames.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    let error = jelly_frames_to_quads(&frames, None).expect_err("must fail");
    assert_eq!(code_of(&error), "frame_decode");
}

#[test]
fn jelly_encoder_options_are_validated() {
    // Below the Jelly spec minimum name-table size of 8.
    let error = quads_to_jelly_frames(&json!([]), Some(&json!({ "maxNameTableSize": 4 })))
        .expect_err("must fail");
    assert_eq!(code_of(&error), "options");
}

#[test]
fn ipc_decode_rejects_non_contract_payloads() {
    let error = ipc_to_quads(&[0u8; 16], None).expect_err("must fail");
    assert_eq!(code_of(&error), "ipc");
}

#[test]
fn precision_error_on_offsets_beyond_max_safe_integer() {
    // Build a contract batch directly with an offset JS cannot represent;
    // the binding must refuse to decode it rather than round silently.
    use oxrdf::{NamedNode, Quad};
    use quad_fast_core::{QuadBatchBuilder, QuadLimits, SourceProvenance, write_ipc_stream};

    let quad = Quad::new(
        NamedNode::new("http://example.com/s").expect("iri"),
        NamedNode::new("http://example.com/p").expect("iri"),
        NamedNode::new("http://example.com/o").expect("iri"),
        oxrdf::GraphName::DefaultGraph,
    );
    let provenance = SourceProvenance {
        source_offset_start: Some((1 << 53) + 1),
        ..SourceProvenance::default()
    };
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    builder
        .push(quad.as_ref(), Some(&provenance))
        .expect("push");
    let batch = builder.finish().expect("finish");
    let ipc = write_ipc_stream(&[batch], usize::MAX).expect("ipc");

    let error = ipc_to_quads(&ipc, None).expect_err("must fail");
    assert!(matches!(
        error,
        BindingError::Precision {
            field: "sourceOffsetStart",
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// RDF 1.2 triple terms (RDF-star).
// ---------------------------------------------------------------------------

/// Arrow IPC bytes for one quad carrying an RDF 1.2 triple term.
///
/// Written through `quad-fast-core` directly: the documented JS quad shape
/// deliberately has no triple-term object kind, so no JSON input can
/// produce this batch.
fn triple_term_ipc() -> Vec<u8> {
    use oxrdf::{GraphName, NamedNode, Quad, Term, Triple};
    use quad_fast_core::{QuadBatchBuilder, QuadLimits, write_ipc_stream};

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
    write_ipc_stream(&[builder.finish().expect("batch")], usize::MAX).expect("ipc")
}

#[test]
fn triple_term_batches_are_refused_by_name() {
    let error = ipc_to_quads(&triple_term_ipc(), None).expect_err("must fail closed");
    assert_eq!(code_of(&error), "unsupported");
    assert!(
        error.to_string().contains("rdf12_triple_term"),
        "error must name the feature: {error}"
    );
}

#[test]
fn a_triple_object_kind_is_refused_on_input() {
    // The forward direction is closed too: the JS quad shape has no
    // triple-term kind, so `kind: "triple"` is an input error rather than a
    // silently accepted term.
    let quads = json!([
        {
            "subject": { "kind": "iri", "value": "http://example.com/s" },
            "predicate": "http://example.com/p",
            "object": { "kind": "triple", "value": "<<( <http://a> <http://b> <http://c> )>>" },
            "graph": { "kind": "default" },
        }
    ]);
    let error = quads_to_ipc(&quads, None).expect_err("must fail closed");
    assert_eq!(code_of(&error), "input");
}
