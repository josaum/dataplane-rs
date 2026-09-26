// Rust guideline compliant 2026-02-21
//! Behavioral tests: build → read → IPC round-trips and fail-closed limits.

use oxrdf::{BlankNode, GraphName, Literal, NamedNode, Quad, Term};
use quad_fast_core::{
    QuadBatchBuilder, QuadError, QuadLimits, QuadResource, QuadStreamReader, SourceProvenance,
    read_ipc_stream, validate_contract, write_ipc_stream,
};

fn iri(value: &str) -> NamedNode {
    NamedNode::new(value).expect("test IRI must be valid")
}

fn sample_quads() -> Vec<Quad> {
    vec![
        Quad::new(
            iri("http://example.com/s"),
            iri("http://example.com/p"),
            iri("http://example.com/o"),
            GraphName::DefaultGraph,
        ),
        Quad::new(
            BlankNode::new("b0").expect("valid bnode"),
            iri("http://example.com/p"),
            Term::Literal(Literal::new_simple_literal("plain")),
            GraphName::NamedNode(iri("http://example.com/g")),
        ),
        Quad::new(
            iri("http://example.com/s"),
            iri("http://example.com/p2"),
            Term::Literal(
                Literal::new_language_tagged_literal("hallo", "de-DE").expect("valid tag"),
            ),
            GraphName::BlankNode(BlankNode::new("g1").expect("valid bnode")),
        ),
        Quad::new(
            iri("http://example.com/s"),
            iri("http://example.com/p3"),
            Term::Literal(Literal::new_typed_literal(
                "42",
                iri("http://www.w3.org/2001/XMLSchema#integer"),
            )),
            GraphName::DefaultGraph,
        ),
    ]
}

#[test]
fn quads_round_trip_through_batch() {
    let quads = sample_quads();
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    for quad in &quads {
        builder
            .push(quad.as_ref(), None)
            .expect("push must succeed");
    }
    let batch = builder.finish().expect("finish must succeed");
    assert_eq!(batch.num_rows(), quads.len());
    validate_contract(batch.schema().as_ref()).expect("contract must hold");

    let reader = QuadStreamReader::new(&batch).expect("reader must open");
    for (row, quad) in quads.iter().enumerate() {
        assert_eq!(reader.quad(row).expect("row must decode"), quad.as_ref());
    }
}

#[test]
fn provenance_round_trips() {
    let quads = sample_quads();
    let provenance = SourceProvenance {
        source_artifact_iri: Some("http://example.com/artifact".into()),
        source_content_sha256: Some([7_u8; 32]),
        source_offset_start: Some(10),
        source_offset_end: Some(99),
        observed_at_micros: Some(1_756_600_000_000_000),
    };
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    builder
        .push(quads[0].as_ref(), Some(&provenance))
        .expect("push with provenance");
    builder
        .push(quads[1].as_ref(), None)
        .expect("push without provenance");
    let batch = builder.finish().expect("finish");

    let reader = QuadStreamReader::new(&batch).expect("reader");
    let stored = reader.provenance(0);
    assert_eq!(
        stored.source_artifact_iri,
        Some("http://example.com/artifact")
    );
    assert_eq!(stored.source_content_sha256, Some(&[7_u8; 32][..]));
    assert_eq!(stored.source_offset_start, Some(10));
    assert_eq!(stored.source_offset_end, Some(99));
    assert_eq!(stored.observed_at_micros, Some(1_756_600_000_000_000));

    let empty = reader.provenance(1);
    assert_eq!(empty.source_artifact_iri, None);
    assert_eq!(empty.source_content_sha256, None);
    assert_eq!(empty.observed_at_micros, None);
}

#[test]
fn quad_limit_fails_closed() {
    let quads = sample_quads();
    let mut builder = QuadBatchBuilder::new(QuadLimits {
        max_quads: 1,
        ..QuadLimits::default()
    });
    builder
        .push(quads[0].as_ref(), None)
        .expect("first push fits");
    let error = builder
        .push(quads[1].as_ref(), None)
        .expect_err("second push must fail");
    match error {
        QuadError::ResourceLimit {
            resource,
            limit,
            observed,
        } => {
            assert_eq!(resource, QuadResource::Quads);
            assert_eq!(limit, 1);
            assert_eq!(observed, 2);
        }
        other => panic!("expected resource_limit, got {other}"),
    }
}

#[test]
fn term_byte_limit_fails_closed() {
    let quads = sample_quads();
    let mut builder = QuadBatchBuilder::new(QuadLimits {
        max_retained_term_bytes: 8,
        ..QuadLimits::default()
    });
    let error = builder
        .push(quads[0].as_ref(), None)
        .expect_err("push must fail");
    assert_eq!(error.code(), "resource_limit");
}

#[test]
fn ipc_round_trips_and_enforces_budget() {
    let quads = sample_quads();
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    for quad in &quads {
        builder.push(quad.as_ref(), None).expect("push");
    }
    let batch = builder.finish().expect("finish");

    let bytes = write_ipc_stream(std::slice::from_ref(&batch), 1024 * 1024).expect("encode");
    let decoded = read_ipc_stream(&bytes).expect("decode");
    assert_eq!(decoded.len(), 1);
    let reader = QuadStreamReader::new(&decoded[0]).expect("reader");
    let collected: Vec<_> = reader
        .iter()
        .map(|entry| entry.expect("row decodes").0.into_owned())
        .collect();
    assert_eq!(collected, quads);

    let error = write_ipc_stream(std::slice::from_ref(&batch), 8).expect_err("budget must bind");
    assert_eq!(error.code(), "resource_limit");
}

#[test]
fn foreign_schema_is_rejected() {
    let batch = arrow_array::RecordBatch::try_from_iter([(
        "not_a_quad",
        std::sync::Arc::new(arrow_array::Int64Array::from(vec![1_i64])) as arrow_array::ArrayRef,
    )])
    .expect("foreign batch");
    let error = QuadStreamReader::new(&batch).expect_err("must reject foreign schema");
    assert_eq!(error.code(), "contract");
}

#[test]
fn empty_batch_is_valid() {
    let batch = QuadBatchBuilder::new(QuadLimits::default())
        .finish()
        .expect("empty finish");
    assert_eq!(batch.num_rows(), 0);
    let reader = QuadStreamReader::new(&batch).expect("reader");
    assert!(reader.is_empty());
}
