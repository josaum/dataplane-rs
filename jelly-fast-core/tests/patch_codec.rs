// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Round-trip, fail-closed, and proto-conformance tests for the patch codec.

use arrow_array::RecordBatch;
use jelly_fast_core::{
    JellyError, JellyPatchDecoder, JellyPatchDecoderOptions, JellyPatchEncoder,
    JellyPatchEncoderOptions, PATCH_PROTOCOL_VERSION, PatchOp,
    proto::patch::{
        PatchStatementType, PatchStreamType, RdfPatchFrame, RdfPatchHeader, RdfPatchNamespace,
        RdfPatchOptions, RdfPatchPunctuation, RdfPatchRow, RdfPatchTransactionCommit,
        RdfPatchTransactionStart, rdf_patch_header, rdf_patch_row,
    },
    proto::{RdfIri, RdfQuad, RdfTriple, rdf_quad},
};
use oxrdf::{BlankNode, GraphName, Literal, NamedNode, Quad, Term, vocab::xsd};
use prost::Message;
use quad_fast_core::{QuadBatchBuilder, QuadLimits, QuadStreamReader, SourceProvenance};

fn iri(value: &str) -> NamedNode {
    NamedNode::new(value).expect("valid test IRI")
}

fn batch_of(quads: &[Quad]) -> RecordBatch {
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    for quad in quads {
        builder.push(quad.as_ref(), None).expect("quad accepted");
    }
    builder.finish().expect("batch built")
}

fn quads_of(batch: &RecordBatch) -> Vec<Quad> {
    let reader = QuadStreamReader::new(batch).expect("contract-valid batch");
    (0..reader.len())
        .map(|row| reader.quad(row).expect("valid quad").into_owned())
        .collect()
}

fn assert_provenance_null(batch: &RecordBatch) {
    let reader = QuadStreamReader::new(batch).expect("contract-valid batch");
    for row in 0..reader.len() {
        let provenance = reader.provenance(row);
        assert_eq!(provenance.source_artifact_iri, None);
        assert_eq!(provenance.source_content_sha256, None);
        assert_eq!(provenance.source_offset_start, None);
        assert_eq!(provenance.source_offset_end, None);
        assert_eq!(provenance.observed_at_micros, None);
    }
}

/// One patch operation flattened to per-quad granularity.
///
/// Round trips preserve the operation sequence, not batch boundaries
/// (consecutive same-kind statement rows regroup on decode), so tests
/// compare flattened sequences.
#[derive(Clone, Debug, PartialEq)]
enum FlatOp {
    Add(Quad),
    Delete(Quad),
    TransactionStart,
    TransactionCommit,
    TransactionAbort,
    Header(String, Term),
}

fn flatten(ops: &[PatchOp]) -> Vec<FlatOp> {
    let mut flat = Vec::new();
    for op in ops {
        match op {
            PatchOp::Add(batch) => flat.extend(quads_of(batch).into_iter().map(FlatOp::Add)),
            PatchOp::Delete(batch) => {
                flat.extend(quads_of(batch).into_iter().map(FlatOp::Delete));
            }
            PatchOp::TransactionStart => flat.push(FlatOp::TransactionStart),
            PatchOp::TransactionCommit => flat.push(FlatOp::TransactionCommit),
            PatchOp::TransactionAbort => flat.push(FlatOp::TransactionAbort),
            PatchOp::Header { key, value } => {
                flat.push(FlatOp::Header(key.clone(), value.clone()));
            }
        }
    }
    flat
}

/// Mixed corpus: shared prefixes, bnodes, literal kinds, graphs, repeats.
fn corpus() -> Vec<Quad> {
    let alice = iri("http://example.com/people#alice");
    let knows = iri("http://xmlns.com/foaf/0.1/knows");
    let graph = GraphName::NamedNode(iri("http://example.com/graphs/g1"));
    vec![
        Quad::new(
            alice.clone(),
            knows.clone(),
            iri("http://example.com/people#bob"),
            GraphName::DefaultGraph,
        ),
        Quad::new(
            alice.clone(),
            iri("http://xmlns.com/foaf/0.1/name"),
            Literal::new_language_tagged_literal("Alicia", "es").expect("valid tag"),
            GraphName::DefaultGraph,
        ),
        Quad::new(
            alice.clone(),
            iri("http://xmlns.com/foaf/0.1/age"),
            Literal::new_typed_literal("33", xsd::INTEGER),
            graph.clone(),
        ),
        Quad::new(
            BlankNode::new("b0").expect("valid bnode"),
            knows,
            alice,
            graph,
        ),
    ]
}

fn round_trip(
    ops: &[PatchOp],
    encoder_options: JellyPatchEncoderOptions,
    decoder_options: JellyPatchDecoderOptions,
) -> (Vec<RdfPatchFrame>, Vec<PatchOp>) {
    let mut encoder = JellyPatchEncoder::new(encoder_options).expect("valid encoder options");
    let frames = encoder.encode_ops(ops).expect("encoded");
    encoder.finish().expect("no open transaction");
    let mut decoder = JellyPatchDecoder::new(decoder_options);
    let mut decoded = Vec::new();
    for frame in &frames {
        decoded.extend(decoder.decode_frame(frame).expect("decoded"));
    }
    decoder.finish().expect("no open transaction");
    for op in &decoded {
        if let PatchOp::Add(batch) | PatchOp::Delete(batch) = op {
            assert_provenance_null(batch);
        }
    }
    (frames, decoded)
}

#[test]
fn add_only_patch_round_trips() {
    let ops = vec![PatchOp::Add(batch_of(&corpus()))];
    let (frames, decoded) = round_trip(
        &ops,
        JellyPatchEncoderOptions::default(),
        JellyPatchDecoderOptions::default(),
    );
    assert_eq!(frames.len(), 1);
    assert_eq!(flatten(&decoded), flatten(&ops));
}

#[test]
fn delete_only_patch_round_trips() {
    let ops = vec![PatchOp::Delete(batch_of(&corpus()))];
    let (_, decoded) = round_trip(
        &ops,
        JellyPatchEncoderOptions::default(),
        JellyPatchDecoderOptions::default(),
    );
    assert_eq!(flatten(&decoded), flatten(&ops));
}

#[test]
fn mixed_patch_with_transactions_and_headers_round_trips() {
    let quads = corpus();
    let ops = vec![
        PatchOp::Header {
            key: "id".into(),
            value: Term::NamedNode(iri("http://example.com/patch/1")),
        },
        PatchOp::Header {
            key: "prev".into(),
            value: Term::BlankNode(BlankNode::new("prev0").expect("valid bnode")),
        },
        PatchOp::Header {
            key: "note".into(),
            value: Term::Literal(Literal::new_typed_literal("7", xsd::INTEGER)),
        },
        PatchOp::TransactionStart,
        PatchOp::Add(batch_of(&quads[..2])),
        PatchOp::Delete(batch_of(&quads[2..3])),
        PatchOp::TransactionCommit,
        PatchOp::TransactionStart,
        PatchOp::Add(batch_of(&quads[3..])),
        PatchOp::TransactionAbort,
        PatchOp::Delete(batch_of(&quads[..1])),
    ];
    // Tiny frames so the round trip crosses frame boundaries with live
    // lookup-table, repeated-term, and transaction state.
    let (frames, decoded) = round_trip(
        &ops,
        JellyPatchEncoderOptions {
            rows_per_frame: 2,
            ..JellyPatchEncoderOptions::default()
        },
        JellyPatchDecoderOptions::default(),
    );
    assert!(frames.len() > 2, "expected chunking into multiple frames");
    assert_eq!(flatten(&decoded), flatten(&ops));
}

#[test]
fn consecutive_same_kind_batches_regroup_on_decode() {
    let quads = corpus();
    let ops = vec![
        PatchOp::Add(batch_of(&quads[..2])),
        PatchOp::Add(batch_of(&quads[2..])),
    ];
    let (_, decoded) = round_trip(
        &ops,
        JellyPatchEncoderOptions::default(),
        JellyPatchDecoderOptions::default(),
    );
    // Batch boundaries are not wire-visible: one maximal run comes back.
    assert_eq!(decoded.len(), 1);
    assert!(matches!(&decoded[0], PatchOp::Add(batch) if batch.num_rows() == quads.len()));
    assert_eq!(flatten(&decoded), flatten(&ops));
}

#[test]
fn empty_patch_round_trips_as_options_only_frame() {
    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let frames = encoder.encode_ops(&[]).expect("encoded");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].rows.len(), 1);
    assert!(matches!(
        frames[0].rows[0].row,
        Some(rdf_patch_row::Row::Options(_))
    ));

    let mut decoder = JellyPatchDecoder::new(JellyPatchDecoderOptions::default());
    let ops = decoder.decode_frame(&frames[0]).expect("decoded");
    decoder.finish().expect("no open transaction");
    assert!(ops.is_empty());

    // A second empty call has no options row left to emit: no frames.
    let more = encoder.encode_ops(&[]).expect("encoded");
    assert!(more.is_empty());
}

#[test]
fn options_row_announces_flat_quads_version_1() {
    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let frames = encoder.encode_ops(&[]).expect("encoded");
    let Some(rdf_patch_row::Row::Options(options)) = &frames[0].rows[0].row else {
        panic!("first row must be the options row");
    };
    assert_eq!(options.version, PATCH_PROTOCOL_VERSION);
    assert_eq!(options.statement_type, PatchStatementType::Quads as i32);
    assert_eq!(options.stream_type, PatchStreamType::Flat as i32);
    assert!(!options.rdf_star);
    assert!(!options.generalized_statements);
}

#[test]
fn repeated_terms_are_elided_across_add_and_delete_rows() {
    let quad = corpus().remove(0);
    let ops = vec![
        PatchOp::Add(batch_of(std::slice::from_ref(&quad))),
        PatchOp::Delete(batch_of(std::slice::from_ref(&quad))),
    ];
    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let frames = encoder.encode_ops(&ops).expect("encoded");
    let delete_rows: Vec<&RdfQuad> = frames[0]
        .rows
        .iter()
        .filter_map(|row| match &row.row {
            Some(rdf_patch_row::Row::StatementDelete(quad)) => Some(quad),
            _ => None,
        })
        .collect();
    assert_eq!(delete_rows.len(), 1);
    // The vendored patch.proto shares repeated-term compression across
    // statement rows: the delete of the same quad elides every position.
    let delete = delete_rows[0];
    assert!(delete.subject.is_none());
    assert!(delete.predicate.is_none());
    assert!(delete.object.is_none());
    assert!(delete.graph.is_none());
}

// --- encoder fail-closed paths -------------------------------------------

#[test]
fn encoder_rejects_undersized_tables_and_zero_frame_rows() {
    let error = JellyPatchEncoder::new(JellyPatchEncoderOptions {
        max_name_table_size: 7,
        ..JellyPatchEncoderOptions::default()
    })
    .expect_err("name table below the schema minimum");
    assert_eq!(error.code(), "options");

    let error = JellyPatchEncoder::new(JellyPatchEncoderOptions {
        rows_per_frame: 0,
        ..JellyPatchEncoderOptions::default()
    })
    .expect_err("zero rows per frame");
    assert_eq!(error.code(), "options");
}

#[test]
fn encoder_rejects_provenance_by_default() {
    let quad = corpus().remove(0);
    let provenance = SourceProvenance {
        source_artifact_iri: Some("http://example.com/artifact".into()),
        ..SourceProvenance::default()
    };
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    builder
        .push(quad.as_ref(), Some(&provenance))
        .expect("quad accepted");
    let batch = builder.finish().expect("batch built");

    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let error = encoder
        .encode_ops(&[PatchOp::Add(batch.clone())])
        .expect_err("provenance refused");
    assert_eq!(error.code(), "unsupported");

    let mut permissive = JellyPatchEncoder::new(JellyPatchEncoderOptions {
        allow_provenance_loss: true,
        ..JellyPatchEncoderOptions::default()
    })
    .expect("valid options");
    let frames = permissive
        .encode_ops(&[PatchOp::Add(batch)])
        .expect("encoded with explicit opt-in");
    let mut decoder = JellyPatchDecoder::new(JellyPatchDecoderOptions::default());
    for op in decoder.decode_frame(&frames[0]).expect("decoded") {
        if let PatchOp::Add(batch) | PatchOp::Delete(batch) = op {
            assert_provenance_null(&batch);
        }
    }
}

#[test]
fn encoder_rejects_transaction_misuse() {
    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let error = encoder
        .encode_ops(&[PatchOp::TransactionStart, PatchOp::TransactionStart])
        .expect_err("nested transaction refused");
    assert_eq!(error.code(), "frame");

    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let error = encoder
        .encode_ops(&[PatchOp::TransactionCommit])
        .expect_err("commit without open transaction refused");
    assert_eq!(error.code(), "frame");

    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let error = encoder
        .encode_ops(&[PatchOp::TransactionAbort])
        .expect_err("abort without open transaction refused");
    assert_eq!(error.code(), "frame");
}

#[test]
fn encoder_finish_rejects_open_transaction() {
    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    encoder
        .encode_ops(&[PatchOp::TransactionStart])
        .expect("encoded");
    let error = encoder.finish().expect_err("open transaction refused");
    assert_eq!(error.code(), "frame");
}

#[test]
fn encoder_rejects_header_after_statements_and_empty_key() {
    let batch = batch_of(&corpus());
    let header = PatchOp::Header {
        key: "id".into(),
        value: Term::NamedNode(iri("http://example.com/patch/1")),
    };
    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let error = encoder
        .encode_ops(&[PatchOp::Add(batch), header])
        .expect_err("late header refused");
    assert_eq!(error.code(), "frame");

    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let error = encoder
        .encode_ops(&[PatchOp::Header {
            key: String::new(),
            value: Term::NamedNode(iri("http://example.com/patch/1")),
        }])
        .expect_err("empty header key refused");
    assert_eq!(error.code(), "frame");
}

// --- decoder fail-closed paths -------------------------------------------

fn valid_options() -> RdfPatchOptions {
    RdfPatchOptions {
        statement_type: PatchStatementType::Quads.into(),
        stream_type: PatchStreamType::Flat.into(),
        generalized_statements: false,
        rdf_star: false,
        max_name_table_size: 16,
        max_prefix_table_size: 16,
        max_datatype_table_size: 16,
        version: PATCH_PROTOCOL_VERSION,
    }
}

fn options_row_with(mutate: impl FnOnce(&mut RdfPatchOptions)) -> RdfPatchRow {
    let mut options = valid_options();
    mutate(&mut options);
    RdfPatchRow {
        row: Some(rdf_patch_row::Row::Options(options)),
    }
}

fn frame_of(rows: Vec<RdfPatchRow>) -> RdfPatchFrame {
    RdfPatchFrame { rows }
}

fn decode_one(frame: &RdfPatchFrame) -> Result<Vec<PatchOp>, JellyError> {
    JellyPatchDecoder::new(JellyPatchDecoderOptions::default()).decode_frame(frame)
}

fn row(row: rdf_patch_row::Row) -> RdfPatchRow {
    RdfPatchRow { row: Some(row) }
}

#[test]
fn decoder_rejects_rows_before_options() {
    let frame = frame_of(vec![row(rdf_patch_row::Row::TransactionStart(
        RdfPatchTransactionStart {},
    ))]);
    let error = decode_one(&frame).expect_err("row before options refused");
    assert_eq!(error.code(), "options");
}

#[test]
fn decoder_rejects_duplicate_options() {
    let frame = frame_of(vec![options_row_with(|_| {}), options_row_with(|_| {})]);
    let error = decode_one(&frame).expect_err("duplicate options refused");
    assert_eq!(error.code(), "options");
}

#[test]
fn decoder_rejects_bad_versions() {
    let frame = frame_of(vec![options_row_with(|options| options.version = 0)]);
    assert_eq!(
        decode_one(&frame).expect_err("version 0 refused").code(),
        "options"
    );

    for version in [2, 10_000] {
        let frame = frame_of(vec![options_row_with(|options| options.version = version)]);
        let error = decode_one(&frame).expect_err("unknown version refused");
        match error {
            JellyError::Unsupported { feature, .. } => assert_eq!(feature, "patch_version"),
            other => panic!("expected an unsupported error, got {other:?}"),
        }
    }
}

#[test]
fn decoder_rejects_triples_statement_type() {
    let frame = frame_of(vec![options_row_with(|options| {
        options.statement_type = PatchStatementType::Triples.into();
    })]);
    let error = decode_one(&frame).expect_err("TRIPLES refused");
    match error {
        JellyError::Unsupported { feature, .. } => {
            assert_eq!(feature, "patch_statement_type_triples");
        }
        other => panic!("expected an unsupported error, got {other:?}"),
    }

    let frame = frame_of(vec![options_row_with(|options| {
        options.statement_type = 0;
    })]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("unspecified statement type refused")
            .code(),
        "options"
    );
}

#[test]
fn decoder_rejects_frame_and_punctuated_stream_types() {
    for (stream_type, feature) in [
        (PatchStreamType::Frame, "patch_stream_type_frame"),
        (PatchStreamType::Punctuated, "patch_stream_type_punctuated"),
    ] {
        let frame = frame_of(vec![options_row_with(|options| {
            options.stream_type = stream_type.into();
        })]);
        let error = decode_one(&frame).expect_err("non-FLAT stream type refused");
        match error {
            JellyError::Unsupported {
                feature: actual, ..
            } => assert_eq!(actual, feature),
            other => panic!("expected an unsupported error, got {other:?}"),
        }
    }

    let frame = frame_of(vec![options_row_with(|options| options.stream_type = 0)]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("unspecified stream type refused")
            .code(),
        "options"
    );
}

#[test]
fn decoder_accepts_the_rdf_star_flag_and_rejects_generalized() {
    // The vendored patch schema carries statement rows as the same `RdfQuad`
    // message as the RDF stream and gates them with the same `rdf_star`
    // option, so the flag is honoured rather than refused (N8).
    let frame = frame_of(vec![options_row_with(|options| options.rdf_star = true)]);
    let ops = decode_one(&frame).expect("an rdf-star patch stream must be accepted");
    assert!(ops.is_empty());

    let frame = frame_of(vec![options_row_with(|options| {
        options.generalized_statements = true;
    })]);
    assert_eq!(
        decode_one(&frame).expect_err("generalized refused").code(),
        "unsupported"
    );
}

#[test]
fn decoder_rejects_oversized_declared_tables() {
    let frame = frame_of(vec![options_row_with(|options| {
        options.max_name_table_size = 4001;
    })]);
    let error = decode_one(&frame).expect_err("oversized table refused");
    match error {
        JellyError::ResourceLimit {
            limit, observed, ..
        } => {
            assert_eq!(limit, 4000);
            assert_eq!(observed, 4001);
        }
        other => panic!("expected a resource limit error, got {other:?}"),
    }
}

#[test]
fn decoder_rejects_namespace_and_punctuation_rows() {
    let namespace = RdfPatchNamespace {
        name: "ex".into(),
        value: Some(RdfIri {
            prefix_id: 0,
            name_id: 1,
        }),
        graph: None,
    };
    for make_row in [
        rdf_patch_row::Row::NamespaceAdd,
        rdf_patch_row::Row::NamespaceDelete,
    ] {
        let frame = frame_of(vec![
            options_row_with(|_| {}),
            row(make_row(namespace.clone())),
        ]);
        let error = decode_one(&frame).expect_err("namespace row refused");
        match error {
            JellyError::Unsupported { feature, .. } => {
                assert_eq!(feature, "namespace_declaration");
            }
            other => panic!("expected an unsupported error, got {other:?}"),
        }
    }

    let frame = frame_of(vec![
        options_row_with(|_| {}),
        row(rdf_patch_row::Row::Punctuation(RdfPatchPunctuation {})),
    ]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("punctuation row refused")
            .code(),
        "frame"
    );
}

#[test]
fn decoder_rejects_transaction_misuse() {
    let frame = frame_of(vec![
        options_row_with(|_| {}),
        row(rdf_patch_row::Row::TransactionStart(
            RdfPatchTransactionStart {},
        )),
        row(rdf_patch_row::Row::TransactionStart(
            RdfPatchTransactionStart {},
        )),
    ]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("nested transaction refused")
            .code(),
        "frame"
    );

    let frame = frame_of(vec![
        options_row_with(|_| {}),
        row(rdf_patch_row::Row::TransactionCommit(
            RdfPatchTransactionCommit {},
        )),
    ]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("orphan commit refused")
            .code(),
        "frame"
    );
}

#[test]
fn decoder_finish_rejects_open_transaction() {
    let mut decoder = JellyPatchDecoder::new(JellyPatchDecoderOptions::default());
    let frame = frame_of(vec![
        options_row_with(|_| {}),
        row(rdf_patch_row::Row::TransactionStart(
            RdfPatchTransactionStart {},
        )),
    ]);
    let ops = decoder.decode_frame(&frame).expect("decoded");
    assert_eq!(ops, vec![PatchOp::TransactionStart]);
    let error = decoder.finish().expect_err("open transaction refused");
    assert_eq!(error.code(), "frame");
}

#[test]
fn decoder_rejects_misplaced_and_malformed_headers() {
    let header = RdfPatchHeader {
        key: "id".into(),
        value: Some(rdf_patch_header::Value::HBnode("b0".into())),
    };
    // Header after a transaction row in the same frame.
    let frame = frame_of(vec![
        options_row_with(|_| {}),
        row(rdf_patch_row::Row::TransactionStart(
            RdfPatchTransactionStart {},
        )),
        row(rdf_patch_row::Row::Header(header.clone())),
    ]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("misplaced header refused")
            .code(),
        "frame"
    );

    // Missing value.
    let frame = frame_of(vec![
        options_row_with(|_| {}),
        row(rdf_patch_row::Row::Header(RdfPatchHeader {
            key: "id".into(),
            value: None,
        })),
    ]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("valueless header refused")
            .code(),
        "frame"
    );

    // Empty key.
    let frame = frame_of(vec![
        options_row_with(|_| {}),
        row(rdf_patch_row::Row::Header(RdfPatchHeader {
            key: String::new(),
            value: header.value,
        })),
    ]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("empty header key refused")
            .code(),
        "frame"
    );

    // A triple-term header value on a stream that did not announce RDF-star
    // contradicts its own options row.
    let frame = frame_of(vec![
        options_row_with(|_| {}),
        row(rdf_patch_row::Row::Header(RdfPatchHeader {
            key: "id".into(),
            value: Some(rdf_patch_header::Value::HTripleTerm(RdfTriple {
                subject: None,
                predicate: None,
                object: None,
            })),
        })),
    ]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("triple term header without the rdf_star flag refused")
            .code(),
        "frame"
    );

    // With the flag set, the schema's "all terms must be set" rule applies.
    let frame = frame_of(vec![
        options_row_with(|options| options.rdf_star = true),
        row(rdf_patch_row::Row::Header(RdfPatchHeader {
            key: "id".into(),
            value: Some(rdf_patch_header::Value::HTripleTerm(RdfTriple {
                subject: None,
                predicate: None,
                object: None,
            })),
        })),
    ]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("unset terms inside a triple term refused")
            .code(),
        "frame"
    );
}

#[test]
fn decoder_rejects_generalized_and_rdf_star_statement_terms() {
    // A literal subject requires a generalized RDF stream.
    let quad = RdfQuad {
        subject: Some(rdf_quad::Subject::SLiteral(
            jelly_fast_core::proto::RdfLiteral {
                lex: "x".into(),
                literal_kind: None,
            },
        )),
        predicate: None,
        object: None,
        graph: None,
    };
    let frame = frame_of(vec![
        options_row_with(|_| {}),
        row(rdf_patch_row::Row::StatementAdd(quad)),
    ]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("generalized subject refused")
            .code(),
        "unsupported"
    );
}

#[test]
fn decoder_rejects_payloadless_row_and_quad_limit_overflow() {
    let frame = frame_of(vec![options_row_with(|_| {}), RdfPatchRow { row: None }]);
    assert_eq!(
        decode_one(&frame)
            .expect_err("payloadless row refused")
            .code(),
        "frame"
    );

    // Quad limits govern the batches built from statement runs.
    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let frames = encoder
        .encode_ops(&[PatchOp::Add(batch_of(&corpus()))])
        .expect("encoded");
    let mut decoder = JellyPatchDecoder::new(JellyPatchDecoderOptions {
        quad_limits: QuadLimits {
            max_quads: 2,
            ..QuadLimits::default()
        },
        ..JellyPatchDecoderOptions::default()
    });
    let error = decoder
        .decode_frame(&frames[0])
        .expect_err("quad limit enforced");
    assert_eq!(error.code(), "quad");
}

// --- proto conformance against the vendored schema ------------------------

/// Computes the protobuf key byte for a length-delimited field.
///
/// Wire format: `(field_number << 3) | wire_type`, with wire type 2 for
/// length-delimited (all `RdfPatchRow` oneof members are messages).
fn key_byte(field_number: u8) -> u8 {
    (field_number << 3) | 2
}

#[test]
fn patch_row_field_numbers_match_the_vendored_schema() {
    // Field numbers from the vendored proto/patch.proto `RdfPatchRow`.
    let cases: Vec<(rdf_patch_row::Row, u8)> = vec![
        (rdf_patch_row::Row::Options(valid_options()), 1),
        (rdf_patch_row::Row::StatementAdd(RdfQuad::default()), 2),
        (rdf_patch_row::Row::StatementDelete(RdfQuad::default()), 3),
        (
            rdf_patch_row::Row::NamespaceAdd(RdfPatchNamespace::default()),
            4,
        ),
        (
            rdf_patch_row::Row::NamespaceDelete(RdfPatchNamespace::default()),
            5,
        ),
        (
            rdf_patch_row::Row::TransactionStart(RdfPatchTransactionStart {}),
            6,
        ),
        (
            rdf_patch_row::Row::TransactionCommit(RdfPatchTransactionCommit {}),
            7,
        ),
        (
            rdf_patch_row::Row::TransactionAbort(
                jelly_fast_core::proto::patch::RdfPatchTransactionAbort {},
            ),
            8,
        ),
        (
            rdf_patch_row::Row::Name(jelly_fast_core::proto::RdfNameEntry::default()),
            11,
        ),
        (
            rdf_patch_row::Row::Prefix(jelly_fast_core::proto::RdfPrefixEntry::default()),
            12,
        ),
        (
            rdf_patch_row::Row::Datatype(jelly_fast_core::proto::RdfDatatypeEntry::default()),
            13,
        ),
        (rdf_patch_row::Row::Header(RdfPatchHeader::default()), 14),
        (rdf_patch_row::Row::Punctuation(RdfPatchPunctuation {}), 15),
    ];
    for (payload, field_number) in cases {
        let bytes = RdfPatchRow { row: Some(payload) }.encode_to_vec();
        assert!(
            !bytes.is_empty(),
            "row with field {field_number} must encode a key byte"
        );
        assert_eq!(
            bytes[0],
            key_byte(field_number),
            "oneof member must map to field {field_number}"
        );
    }
}

#[test]
fn patch_enum_values_match_the_vendored_schema() {
    // Values from the vendored proto/patch.proto enums.
    assert_eq!(PatchStatementType::Unspecified as i32, 0);
    assert_eq!(PatchStatementType::Triples as i32, 1);
    assert_eq!(PatchStatementType::Quads as i32, 2);
    assert_eq!(PatchStreamType::Unspecified as i32, 0);
    assert_eq!(PatchStreamType::Frame as i32, 1);
    assert_eq!(PatchStreamType::Flat as i32, 2);
    assert_eq!(PatchStreamType::Punctuated as i32, 3);
}

#[test]
fn patch_options_field_numbers_match_the_vendored_schema() {
    // RdfPatchOptions field numbers: statement_type=1, stream_type=2,
    // generalized_statements=3, rdf_star=4, max_name_table_size=9,
    // max_prefix_table_size=10, max_datatype_table_size=11, version=15
    // (varint wire type 0 for all of them).
    let options = RdfPatchOptions {
        statement_type: 2,
        stream_type: 2,
        generalized_statements: true,
        rdf_star: true,
        max_name_table_size: 1,
        max_prefix_table_size: 1,
        max_datatype_table_size: 1,
        version: 1,
    };
    let bytes = options.encode_to_vec();
    let keys: Vec<u8> = bytes.iter().copied().step_by(2).collect();
    let expected: Vec<u8> = [1u8, 2, 3, 4, 9, 10, 11, 15]
        .into_iter()
        .map(|field| field << 3)
        .collect();
    assert_eq!(keys, expected);
}

#[test]
fn patch_frame_rows_field_number_matches_the_vendored_schema() {
    // RdfPatchFrame.rows is field 1, length-delimited.
    let frame = frame_of(vec![row(rdf_patch_row::Row::Punctuation(
        RdfPatchPunctuation {},
    ))]);
    let bytes = frame.encode_to_vec();
    assert_eq!(bytes[0], key_byte(1));
}
