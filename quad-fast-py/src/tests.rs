// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21

//! Interpreter-free unit tests for the [`crate::convert`] layer.
//!
//! These tests exercise the whole binding logic (quad tuples to Arrow IPC,
//! IPC back to tuples, and the Jelly frame round trip) without a Python
//! interpreter: the `lib.rs` layer above [`crate::convert`] is a pure
//! object-shape adapter. The Python smoke test in `tests/test_quad_fast.py`
//! covers that adapter once the module is built with maturin.

use jelly_fast_core::{JellyDecoderOptions, JellyEncoderOptions};
use jsonld_fast_core::JsonLdLimits;
use quad_fast_core::QuadLimits;

use crate::convert::{
    BindingError, ProvenanceSpec, QuadSpec, TermSpec, ipc_to_jelly_frames, ipc_to_quads,
    jelly_frames_to_ipc, jsonld_to_ipc, quads_to_ipc,
};

/// The `xsd:string` datatype IRI simple literals normalize to on read.
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

fn iri(value: &str) -> TermSpec {
    TermSpec {
        kind: "iri".to_string(),
        value: value.to_string(),
        datatype: None,
        language: None,
    }
}

fn bnode(value: &str) -> TermSpec {
    TermSpec {
        kind: "bnode".to_string(),
        value: value.to_string(),
        datatype: None,
        language: None,
    }
}

fn literal(value: &str, datatype: Option<&str>, language: Option<&str>) -> TermSpec {
    TermSpec {
        kind: "literal".to_string(),
        value: value.to_string(),
        datatype: datatype.map(str::to_string),
        language: language.map(str::to_string),
    }
}

fn quad(subject: TermSpec, predicate: &str, object: TermSpec, graph: Option<TermSpec>) -> QuadSpec {
    QuadSpec {
        subject,
        predicate: predicate.to_string(),
        object,
        graph,
        provenance: None,
    }
}

/// The sample quads as they read back: language tags normalize to
/// lowercase (`oxrdf` applies RDF 1.1's case-insensitive tag semantics).
fn normalized_sample_quads() -> Vec<QuadSpec> {
    let mut quads = sample_quads();
    quads[1].object.language = Some("de-de".to_string());
    quads
}

fn sample_quads() -> Vec<QuadSpec> {
    vec![
        quad(
            iri("http://example.com/s"),
            "http://example.com/p",
            iri("http://example.com/o"),
            None,
        ),
        quad(
            bnode("b0"),
            "http://example.com/p",
            literal("hallo", None, Some("de-DE")),
            Some(iri("http://example.com/g")),
        ),
        quad(
            iri("http://example.com/s"),
            "http://example.com/count",
            literal("42", Some("http://www.w3.org/2001/XMLSchema#integer"), None),
            Some(bnode("g0")),
        ),
    ]
}

fn full_provenance() -> ProvenanceSpec {
    ProvenanceSpec {
        source_artifact_iri: Some("http://example.com/artifact".to_string()),
        source_content_sha256: Some(vec![7u8; 32]),
        source_offset_start: Some(10),
        source_offset_end: Some(99),
        observed_at_micros: Some(1_756_684_800_000_000),
    }
}

fn assert_input_code(result: Result<Vec<u8>, BindingError>, expected: &str) {
    match result {
        Err(BindingError::Input { code, .. }) => assert_eq!(code, expected),
        other => panic!("expected Input error with code {expected}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Positive paths: IPC round trips.
// ---------------------------------------------------------------------------

#[test]
fn ipc_round_trip_preserves_terms_and_graphs() {
    let quads = sample_quads();
    let ipc = quads_to_ipc(&quads, QuadLimits::default(), usize::MAX).expect("encode");
    let decoded = ipc_to_quads(&ipc).expect("decode");
    assert_eq!(decoded, normalized_sample_quads());
}

#[test]
fn simple_literal_normalizes_to_explicit_xsd_string() {
    // RDF 1.1 Concepts §3.3: simple literals are syntactic sugar for
    // xsd:string-typed literals, and the contract stores the datatype
    // explicitly. The round trip therefore normalizes, not echoes.
    let quads = vec![quad(
        iri("http://example.com/s"),
        "http://example.com/p",
        literal("plain", None, None),
        None,
    )];
    let ipc = quads_to_ipc(&quads, QuadLimits::default(), usize::MAX).expect("encode");
    let decoded = ipc_to_quads(&ipc).expect("decode");
    assert_eq!(decoded[0].object, literal("plain", Some(XSD_STRING), None));
}

#[test]
fn provenance_round_trips_through_ipc() {
    let mut quads = sample_quads();
    quads[0].provenance = Some(full_provenance());
    let ipc = quads_to_ipc(&quads, QuadLimits::default(), usize::MAX).expect("encode");
    let decoded = ipc_to_quads(&ipc).expect("decode");
    assert_eq!(decoded[0].provenance, Some(full_provenance()));
    assert_eq!(decoded[1].provenance, None);
}

#[test]
fn empty_quad_list_round_trips() {
    let ipc = quads_to_ipc(&[], QuadLimits::default(), usize::MAX).expect("encode");
    assert!(ipc_to_quads(&ipc).expect("decode").is_empty());
}

// ---------------------------------------------------------------------------
// Positive paths: Jelly frame round trips.
// ---------------------------------------------------------------------------

#[test]
fn jelly_round_trip_preserves_quads() {
    let quads = sample_quads();
    let ipc = quads_to_ipc(&quads, QuadLimits::default(), usize::MAX).expect("encode ipc");
    let frames = ipc_to_jelly_frames(&ipc, JellyEncoderOptions::default()).expect("encode jelly");
    assert!(!frames.is_empty());
    let decoded_ipc = jelly_frames_to_ipc(&frames, JellyDecoderOptions::default(), usize::MAX)
        .expect("decode jelly");
    assert_eq!(
        ipc_to_quads(&decoded_ipc).expect("decode ipc"),
        normalized_sample_quads()
    );
}

#[test]
fn jelly_decode_of_no_frames_yields_empty_stream() {
    let ipc = jelly_frames_to_ipc(&[], JellyDecoderOptions::default(), usize::MAX).expect("empty");
    assert!(ipc_to_quads(&ipc).expect("decode").is_empty());
}

#[test]
fn jelly_encoder_refuses_provenance_by_default_and_drops_it_when_allowed() {
    let mut quads = sample_quads();
    quads[0].provenance = Some(full_provenance());
    let ipc = quads_to_ipc(&quads, QuadLimits::default(), usize::MAX).expect("encode ipc");

    // Fail-closed default: provenance cannot ride Jelly 1.1.1.
    let refused = ipc_to_jelly_frames(&ipc, JellyEncoderOptions::default());
    assert!(matches!(refused, Err(BindingError::Jelly(_))));

    // Explicit opt-in: encoding succeeds, decoded provenance is null.
    let options = JellyEncoderOptions {
        allow_provenance_loss: true,
        ..JellyEncoderOptions::default()
    };
    let frames = ipc_to_jelly_frames(&ipc, options).expect("encode jelly");
    let decoded_ipc = jelly_frames_to_ipc(&frames, JellyDecoderOptions::default(), usize::MAX)
        .expect("decode jelly");
    let decoded = ipc_to_quads(&decoded_ipc).expect("decode ipc");
    assert!(decoded.iter().all(|quad| quad.provenance.is_none()));
}

// ---------------------------------------------------------------------------
// Fail-closed error paths: malformed terms.
// ---------------------------------------------------------------------------

#[test]
fn unknown_subject_kind_is_a_typed_error() {
    let quads = vec![quad(
        literal("s", None, None),
        "http://example.com/p",
        iri("http://example.com/o"),
        None,
    )];
    assert_input_code(
        quads_to_ipc(&quads, QuadLimits::default(), usize::MAX),
        "term_kind",
    );
}

#[test]
fn unknown_object_kind_is_a_typed_error() {
    let quads = vec![quad(
        iri("http://example.com/s"),
        "http://example.com/p",
        TermSpec {
            kind: "triple".to_string(),
            value: "x".to_string(),
            datatype: None,
            language: None,
        },
        None,
    )];
    assert_input_code(
        quads_to_ipc(&quads, QuadLimits::default(), usize::MAX),
        "term_kind",
    );
}

#[test]
fn invalid_iri_is_a_typed_error() {
    let quads = vec![quad(
        iri("not an iri"),
        "http://example.com/p",
        iri("http://example.com/o"),
        None,
    )];
    assert_input_code(
        quads_to_ipc(&quads, QuadLimits::default(), usize::MAX),
        "term",
    );
}

#[test]
fn invalid_predicate_iri_is_a_typed_error() {
    let quads = vec![quad(
        iri("http://example.com/s"),
        "no scheme",
        iri("http://example.com/o"),
        None,
    )];
    assert_input_code(
        quads_to_ipc(&quads, QuadLimits::default(), usize::MAX),
        "term",
    );
}

#[test]
fn invalid_blank_node_id_is_a_typed_error() {
    let quads = vec![quad(
        bnode("not a bnode id"),
        "http://example.com/p",
        iri("http://example.com/o"),
        None,
    )];
    assert_input_code(
        quads_to_ipc(&quads, QuadLimits::default(), usize::MAX),
        "term",
    );
}

#[test]
fn invalid_language_tag_is_a_typed_error() {
    let quads = vec![quad(
        iri("http://example.com/s"),
        "http://example.com/p",
        literal("x", None, Some("-not-a-tag-")),
        None,
    )];
    assert_input_code(
        quads_to_ipc(&quads, QuadLimits::default(), usize::MAX),
        "language",
    );
}

#[test]
fn literal_with_datatype_and_language_is_a_typed_error() {
    let quads = vec![quad(
        iri("http://example.com/s"),
        "http://example.com/p",
        literal("x", Some(XSD_STRING), Some("en")),
        None,
    )];
    assert_input_code(
        quads_to_ipc(&quads, QuadLimits::default(), usize::MAX),
        "term_shape",
    );
}

#[test]
fn non_literal_term_with_literal_parts_is_a_typed_error() {
    let mut subject = iri("http://example.com/s");
    subject.language = Some("en".to_string());
    let quads = vec![quad(
        subject,
        "http://example.com/p",
        iri("http://example.com/o"),
        None,
    )];
    assert_input_code(
        quads_to_ipc(&quads, QuadLimits::default(), usize::MAX),
        "term_shape",
    );
}

#[test]
fn graph_kind_default_inside_some_is_a_typed_error() {
    let quads = vec![quad(
        iri("http://example.com/s"),
        "http://example.com/p",
        iri("http://example.com/o"),
        Some(TermSpec {
            kind: "default".to_string(),
            value: String::new(),
            datatype: None,
            language: None,
        }),
    )];
    assert_input_code(
        quads_to_ipc(&quads, QuadLimits::default(), usize::MAX),
        "term_kind",
    );
}

// ---------------------------------------------------------------------------
// Fail-closed error paths: provenance, limits, malformed payloads.
// ---------------------------------------------------------------------------

#[test]
fn short_sha256_is_a_typed_error() {
    let mut quads = sample_quads();
    quads[0].provenance = Some(ProvenanceSpec {
        source_content_sha256: Some(vec![7u8; 31]),
        ..ProvenanceSpec::default()
    });
    assert_input_code(
        quads_to_ipc(&quads, QuadLimits::default(), usize::MAX),
        "provenance_sha256_length",
    );
}

#[test]
fn exceeding_max_quads_is_a_resource_limit() {
    let limits = QuadLimits {
        max_quads: 2,
        ..QuadLimits::default()
    };
    let error = quads_to_ipc(&sample_quads(), limits, usize::MAX).expect_err("must fail");
    assert!(error.is_resource_limit(), "got {error:?}");
}

#[test]
fn exceeding_max_ipc_bytes_is_a_resource_limit() {
    let error = quads_to_ipc(&sample_quads(), QuadLimits::default(), 16).expect_err("must fail");
    assert!(error.is_resource_limit(), "got {error:?}");
}

#[test]
fn jelly_decode_respects_per_frame_quad_limits() {
    let ipc = quads_to_ipc(&sample_quads(), QuadLimits::default(), usize::MAX).expect("ipc");
    let frames = ipc_to_jelly_frames(&ipc, JellyEncoderOptions::default()).expect("frames");
    let options = JellyDecoderOptions {
        quad_limits: QuadLimits {
            max_quads: 1,
            ..QuadLimits::default()
        },
        ..JellyDecoderOptions::default()
    };
    let error = jelly_frames_to_ipc(&frames, options, usize::MAX).expect_err("must fail");
    assert!(error.is_resource_limit(), "got {error:?}");
}

#[test]
fn malformed_ipc_bytes_are_a_typed_error() {
    let error = ipc_to_quads(b"definitely not arrow ipc").expect_err("must fail");
    assert!(matches!(error, BindingError::Quad(_)), "got {error:?}");
}

#[test]
fn malformed_frame_bytes_are_a_typed_error() {
    let frames = vec![b"\xff\xff\xff\xff not protobuf".to_vec()];
    assert_input_code(
        jelly_frames_to_ipc(&frames, JellyDecoderOptions::default(), usize::MAX),
        "frame_bytes",
    );
}

#[test]
fn frames_from_two_streams_are_a_typed_error() {
    let ipc = quads_to_ipc(&sample_quads(), QuadLimits::default(), usize::MAX).expect("ipc");
    let stream_a = ipc_to_jelly_frames(&ipc, JellyEncoderOptions::default()).expect("a");
    let stream_b = ipc_to_jelly_frames(&ipc, JellyEncoderOptions::default()).expect("b");
    let mut frames = stream_a;
    frames.extend(stream_b);
    let error = jelly_frames_to_ipc(&frames, JellyDecoderOptions::default(), usize::MAX)
        .expect_err("must fail");
    assert!(matches!(error, BindingError::Jelly(_)), "got {error:?}");
}

/// Builds Arrow IPC bytes for one quad carrying an RDF 1.2 triple term.
///
/// Written through `quad-fast-core` directly, because the Python-facing
/// [`QuadSpec`] shape deliberately has no triple-term object kind.
fn triple_term_ipc() -> Vec<u8> {
    use oxrdf::{GraphName, NamedNode, Quad, Term, Triple};
    use quad_fast_core::{QuadBatchBuilder, write_ipc_stream};

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
    // The Python term shape has iri/bnode/literal kinds only; an RDF 1.2
    // triple term is refused, never flattened into a node reference.
    let error = ipc_to_quads(&triple_term_ipc()).expect_err("must fail closed");
    let rendered = error.to_string();
    assert!(
        rendered.contains("rdf12_triple_term"),
        "error must name the feature: {rendered}"
    );
    assert!(matches!(error, BindingError::Quad(_)), "got {error:?}");
    assert!(!error.is_resource_limit());
}

#[test]
fn triple_term_batches_are_refused_before_jelly_encoding() {
    // The same refusal guards the Jelly path: this binding never announces
    // RDF-star on the wire.
    let error = ipc_to_jelly_frames(&triple_term_ipc(), JellyEncoderOptions::default())
        .expect_err("must fail closed");
    assert!(
        error.to_string().contains("rdf_star"),
        "error must name the option: {error}"
    );
}

// ---------------------------------------------------------------------------
// JSON-LD decode: telemetry audit lines and sovereign refusals.
// ---------------------------------------------------------------------------

/// One emitted line of the telemetry event log (`jsonld-fast-core/tests/cartridge_audit_tests.rs`).
const TELEMETRY_EVENT_LINE: &str = r#"{"@context":{"@version":1.1,"@vocab":"urn:dataplane:","dp":"urn:dataplane:","xsd":"http://www.w3.org/2001/XMLSchema#","id":"@id","type":"@type","named_graph":{"@id":"dp:namedGraph","@type":"@id"},"occurred_at":{"@id":"dp:occurredAt","@type":"xsd:dateTime"},"metric_id":"dp:metricId","target_metric_id":"dp:metricId","entity_id":"dp:entityId","source":"dp:source","detail":"dp:detail","question":"dp:question","persona":"dp:persona","status":"dp:status","grain":"dp:grain","event_id":{"@id":"dp:eventId","@type":"@id"},"trace_id":{"@id":"dp:traceId","@type":"@id"},"hypotheses":{"@id":"dp:hypotheses","@container":"@set"},"paths":{"@id":"dp:paths","@container":"@set"},"signed_by":"dp:signedBy","corrected_label":"dp:correctedLabel"},"id":"urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e","type":"ObservationRecorded","named_graph":"urn:dataplane:graph:events:v1","occurred_at":"2026-09-01T19:34:35.499204Z","metric_id":"latency_ms","source":"telemetry","entity_id":"sensor:S100","detail":{"value":3.6,"grain":"sensor","asOf":"2026-09-01T19:34:35.499035+00:00"}}"#;

#[test]
fn jsonld_line_decodes_with_provenance_on_every_row() {
    let ipc = jsonld_to_ipc(
        TELEMETRY_EVENT_LINE,
        Some(&full_provenance()),
        &JsonLdLimits::default(),
        QuadLimits::default(),
        usize::MAX,
    )
    .expect("decode");
    let quads = ipc_to_quads(&ipc).expect("read back");
    assert!(!quads.is_empty());
    assert!(
        quads
            .iter()
            .all(|quad| quad.provenance == Some(full_provenance()))
    );
    let named = quads.iter().any(|quad| {
        quad.subject == iri("urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e")
            && quad.predicate == "urn:dataplane:namedGraph"
            && quad.object == iri("urn:dataplane:graph:events:v1")
            && quad.graph.is_none()
    });
    assert!(named, "named-graph link must survive: {quads:?}");
}

#[test]
fn jsonld_remote_context_is_refused_by_name() {
    let error = jsonld_to_ipc(
        r#"{"@context": "https://schema.org/", "@id": "http://example.com/it"}"#,
        None,
        &JsonLdLimits::default(),
        QuadLimits::default(),
        usize::MAX,
    )
    .expect_err("must fail closed");
    let rendered = error.to_string();
    assert!(
        rendered.contains("remote_context_refused"),
        "error must name the refusal: {rendered}"
    );
    assert!(matches!(error, BindingError::JsonLd(_)), "got {error:?}");
    assert!(!error.is_resource_limit());
}

#[test]
fn jsonld_relative_iri_is_refused_rather_than_dropped() {
    // Pre-migration audit shape: a bare UUID under @id stays relative after
    // expansion, and the codec refuses instead of silently dropping the node.
    let relative = TELEMETRY_EVENT_LINE.replace(
        "urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e",
        "7bb73a56-9116-44e7-a5d3-0c5061ed805e",
    );
    let error = jsonld_to_ipc(
        &relative,
        None,
        &JsonLdLimits::default(),
        QuadLimits::default(),
        usize::MAX,
    )
    .expect_err("must fail closed");
    assert!(
        error.to_string().contains("relative_iri"),
        "error must name the refusal: {}",
        error
    );
}

#[test]
fn jsonld_exceeded_budget_is_a_resource_limit() {
    let limits = JsonLdLimits {
        max_input_bytes: 8,
        ..JsonLdLimits::default()
    };
    let error = jsonld_to_ipc(
        TELEMETRY_EVENT_LINE,
        None,
        &limits,
        QuadLimits::default(),
        usize::MAX,
    )
    .expect_err("must fail closed");
    assert!(error.is_resource_limit());
}
