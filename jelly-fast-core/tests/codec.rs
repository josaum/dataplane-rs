// Rust guideline compliant 2026-02-21
//! Frame-level round-trip and fail-closed rejection tests for the codec.

use arrow_array::RecordBatch;
use jelly_fast_core::{
    JellyDecoder, JellyDecoderOptions, JellyEncoder, JellyEncoderOptions, PROTOCOL_VERSION,
    proto::{
        PhysicalStreamType, RdfIri, RdfQuad, RdfStreamFrame, RdfStreamOptions, RdfStreamRow,
        RdfTriple, rdf_quad, rdf_stream_row,
    },
};
use oxrdf::{BlankNode, GraphName, Literal, NamedNode, Quad, Term, vocab::xsd};
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

/// Mixed corpus: shared prefixes, bnodes, literal kinds, graphs, repeats.
fn mixed_corpus() -> Vec<Quad> {
    let alice = iri("http://example.com/people#alice");
    let bob = iri("http://example.com/people#bob");
    let knows = iri("http://xmlns.com/foaf/0.1/knows");
    let name = iri("http://xmlns.com/foaf/0.1/name");
    let graph1 = GraphName::NamedNode(iri("http://example.com/graphs/g1"));
    let bnode = BlankNode::new("b0").expect("valid bnode");
    let graph_bnode = GraphName::BlankNode(BlankNode::new("g0").expect("valid bnode"));
    vec![
        Quad::new(
            alice.clone(),
            knows.clone(),
            bob.clone(),
            GraphName::DefaultGraph,
        ),
        Quad::new(
            alice.clone(),
            name.clone(),
            Literal::new_simple_literal("Alice"),
            GraphName::DefaultGraph,
        ),
        Quad::new(
            alice.clone(),
            name.clone(),
            Literal::new_language_tagged_literal("Alicia", "es").expect("valid tag"),
            GraphName::DefaultGraph,
        ),
        Quad::new(
            alice.clone(),
            iri("http://xmlns.com/foaf/0.1/age"),
            Literal::new_typed_literal("33", xsd::INTEGER),
            GraphName::DefaultGraph,
        ),
        Quad::new(bnode.clone(), knows.clone(), alice.clone(), graph1.clone()),
        // Repeated subject, predicate, and graph across consecutive quads.
        Quad::new(bnode.clone(), knows.clone(), bob.clone(), graph1.clone()),
        Quad::new(
            bnode,
            knows.clone(),
            Term::BlankNode(BlankNode::new("b1").expect("valid bnode")),
            graph1,
        ),
        Quad::new(bob, knows, alice, graph_bnode),
    ]
}

fn round_trip(
    quads: &[Quad],
    encoder_options: JellyEncoderOptions,
    decoder_options: JellyDecoderOptions,
) -> (Vec<RdfStreamFrame>, Vec<Quad>) {
    let batch = batch_of(quads);
    let mut encoder = JellyEncoder::new(encoder_options).expect("valid encoder options");
    let frames = encoder.encode_batch(&batch).expect("encoded");
    let mut decoder = JellyDecoder::new(decoder_options);
    let mut decoded = Vec::new();
    for frame in &frames {
        let out = decoder.decode_frame(frame).expect("decoded");
        assert_provenance_null(&out);
        decoded.extend(quads_of(&out));
    }
    (frames, decoded)
}

#[test]
fn mixed_corpus_round_trips() {
    let quads = mixed_corpus();
    let expected = quads_of(&batch_of(&quads));
    let (frames, decoded) = round_trip(
        &quads,
        JellyEncoderOptions::default(),
        JellyDecoderOptions::default(),
    );
    assert_eq!(frames.len(), 1);
    assert_eq!(decoded, expected);
}

#[test]
fn options_row_is_first_and_announces_version() {
    let quads = mixed_corpus();
    let batch = batch_of(&quads);
    let mut encoder = JellyEncoder::new(JellyEncoderOptions::default()).expect("valid options");
    let frames = encoder.encode_batch(&batch).expect("encoded");
    let first_row = frames[0].rows[0].row.as_ref().expect("payload");
    match first_row {
        rdf_stream_row::Row::Options(options) => {
            assert_eq!(options.version, PROTOCOL_VERSION);
            assert_eq!(options.physical_type, i32::from(PhysicalStreamType::Quads));
            assert!(!options.rdf_star);
            assert!(!options.generalized_statements);
        }
        other => panic!("first row is not options: {other:?}"),
    }
}

#[test]
fn repeated_terms_are_elided_on_the_wire() {
    // Two quads sharing subject, predicate, and graph: the second quad row
    // must leave those oneofs unset.
    let subject = iri("http://example.com/s");
    let predicate = iri("http://example.com/p");
    let quads = vec![
        Quad::new(
            subject.clone(),
            predicate.clone(),
            iri("http://example.com/o1"),
            GraphName::DefaultGraph,
        ),
        Quad::new(
            subject,
            predicate,
            iri("http://example.com/o2"),
            GraphName::DefaultGraph,
        ),
    ];
    let mut encoder = JellyEncoder::new(JellyEncoderOptions::default()).expect("valid options");
    let frames = encoder.encode_batch(&batch_of(&quads)).expect("encoded");
    let quad_rows: Vec<&RdfQuad> = frames[0]
        .rows
        .iter()
        .filter_map(|row| match row.row.as_ref() {
            Some(rdf_stream_row::Row::Quad(quad)) => Some(quad),
            _ => None,
        })
        .collect();
    assert_eq!(quad_rows.len(), 2);
    assert!(quad_rows[1].subject.is_none());
    assert!(quad_rows[1].predicate.is_none());
    assert!(quad_rows[1].graph.is_none());
    assert!(quad_rows[1].object.is_some());
}

#[test]
fn tiny_tables_force_eviction_and_still_round_trip() {
    // Three rotating prefixes against a 2-entry prefix table, more than 8
    // distinct names, and alternating datatypes against a 1-entry datatype
    // table force identifier reassignment in every table.
    let mut quads = Vec::new();
    for index in 0..12u32 {
        let prefix = match index % 3 {
            0 => "http://example.com/a#",
            1 => "http://example.com/b#",
            _ => "http://example.com/c#",
        };
        let datatype = if index % 2 == 0 {
            xsd::INTEGER
        } else {
            xsd::DATE
        };
        quads.push(Quad::new(
            iri(&format!("{prefix}s{index}")),
            iri(&format!("{prefix}p{index}")),
            Literal::new_typed_literal(format!("{index}"), datatype),
            GraphName::DefaultGraph,
        ));
    }
    let expected = quads_of(&batch_of(&quads));
    let encoder_options = JellyEncoderOptions {
        max_prefix_table_size: 2,
        max_name_table_size: 8,
        max_datatype_table_size: 1,
        ..JellyEncoderOptions::default()
    };
    let (_, decoded) = round_trip(&quads, encoder_options, JellyDecoderOptions::default());
    assert_eq!(decoded, expected);
}

#[test]
fn chunking_splits_quads_across_frames() {
    let quads = mixed_corpus();
    let expected = quads_of(&batch_of(&quads));
    let encoder_options = JellyEncoderOptions {
        quads_per_frame: 3,
        ..JellyEncoderOptions::default()
    };
    let (frames, decoded) = round_trip(&quads, encoder_options, JellyDecoderOptions::default());
    assert_eq!(frames.len(), quads.len().div_ceil(3));
    for frame in &frames {
        let quad_rows = frame
            .rows
            .iter()
            .filter(|row| matches!(row.row, Some(rdf_stream_row::Row::Quad(_))))
            .count();
        assert!(quad_rows <= 3, "frame holds more quads than requested");
    }
    assert_eq!(decoded, expected);
}

#[test]
fn lookup_state_spans_batches_in_one_stream() {
    let quads = mixed_corpus();
    let (first, second) = quads.split_at(4);
    let mut encoder = JellyEncoder::new(JellyEncoderOptions::default()).expect("valid options");
    let mut frames = encoder.encode_batch(&batch_of(first)).expect("encoded");
    frames.extend(encoder.encode_batch(&batch_of(second)).expect("encoded"));
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let mut decoded = Vec::new();
    for frame in &frames {
        decoded.extend(quads_of(&decoder.decode_frame(frame).expect("decoded")));
    }
    assert_eq!(decoded, quads_of(&batch_of(&quads)));
}

#[test]
fn empty_stream_round_trips_as_options_only_frame() {
    let (frames, decoded) = round_trip(
        &[],
        JellyEncoderOptions::default(),
        JellyDecoderOptions::default(),
    );
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].rows.len(), 1);
    assert!(matches!(
        frames[0].rows[0].row,
        Some(rdf_stream_row::Row::Options(_))
    ));
    assert!(decoded.is_empty());
}

#[test]
fn second_empty_batch_yields_no_frames() {
    let mut encoder = JellyEncoder::new(JellyEncoderOptions::default()).expect("valid options");
    let first = encoder.encode_batch(&batch_of(&[])).expect("encoded");
    assert_eq!(first.len(), 1);
    let second = encoder.encode_batch(&batch_of(&[])).expect("encoded");
    assert!(second.is_empty());
}

#[test]
fn encoder_rejects_undersized_tables() {
    let error = JellyEncoder::new(JellyEncoderOptions {
        max_name_table_size: 7,
        ..JellyEncoderOptions::default()
    })
    .expect_err("name table below the spec minimum");
    assert_eq!(error.code(), "options");
}

#[test]
fn encoder_rejects_provenance_by_default() {
    let quad = Quad::new(
        iri("http://example.com/s"),
        iri("http://example.com/p"),
        iri("http://example.com/o"),
        GraphName::DefaultGraph,
    );
    let provenance = SourceProvenance {
        source_artifact_iri: Some("http://example.com/artifact".into()),
        ..SourceProvenance::default()
    };
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    builder
        .push(quad.as_ref(), Some(&provenance))
        .expect("quad accepted");
    let batch = builder.finish().expect("batch built");

    let mut encoder = JellyEncoder::new(JellyEncoderOptions::default()).expect("valid options");
    let error = encoder
        .encode_batch(&batch)
        .expect_err("provenance refused");
    assert_eq!(error.code(), "unsupported");

    let mut permissive = JellyEncoder::new(JellyEncoderOptions {
        allow_provenance_loss: true,
        ..JellyEncoderOptions::default()
    })
    .expect("valid options");
    let frames = permissive
        .encode_batch(&batch)
        .expect("encoded with explicit opt-in");
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let decoded = decoder.decode_frame(&frames[0]).expect("decoded");
    assert_provenance_null(&decoded);
}

fn valid_options_row() -> RdfStreamRow {
    RdfStreamRow {
        row: Some(rdf_stream_row::Row::Options(RdfStreamOptions {
            stream_name: String::new(),
            physical_type: PhysicalStreamType::Quads.into(),
            generalized_statements: false,
            rdf_star: false,
            max_name_table_size: 16,
            max_prefix_table_size: 16,
            max_datatype_table_size: 8,
            logical_type: 0,
            version: PROTOCOL_VERSION,
        })),
    }
}

fn options_row_with(mutate: impl FnOnce(&mut RdfStreamOptions)) -> RdfStreamRow {
    let mut row = valid_options_row();
    if let Some(rdf_stream_row::Row::Options(options)) = row.row.as_mut() {
        mutate(options);
    }
    row
}

fn frame_of(rows: Vec<RdfStreamRow>) -> RdfStreamFrame {
    RdfStreamFrame {
        rows,
        metadata: std::collections::HashMap::new(),
    }
}

fn subject_only_quad_row(prefix_id: u32, name_id: u32) -> RdfStreamRow {
    RdfStreamRow {
        row: Some(rdf_stream_row::Row::Quad(RdfQuad {
            subject: Some(rdf_quad::Subject::SIri(RdfIri { prefix_id, name_id })),
            predicate: None,
            object: None,
            graph: None,
        })),
    }
}

#[test]
fn decoder_rejects_rows_before_options() {
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let error = decoder
        .decode_frame(&frame_of(vec![subject_only_quad_row(1, 1)]))
        .expect_err("quad before options");
    assert_eq!(error.code(), "options");
}

#[test]
fn decoder_rejects_duplicate_options() {
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let error = decoder
        .decode_frame(&frame_of(vec![valid_options_row(), valid_options_row()]))
        .expect_err("duplicate options");
    assert_eq!(error.code(), "options");
}

#[test]
fn decoder_rejects_unknown_version() {
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let row = options_row_with(|options| options.version = 3);
    let error = decoder
        .decode_frame(&frame_of(vec![row]))
        .expect_err("unknown version");
    assert_eq!(error.code(), "unsupported");

    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let row = options_row_with(|options| options.version = 0);
    let error = decoder
        .decode_frame(&frame_of(vec![row]))
        .expect_err("missing version");
    assert_eq!(error.code(), "options");
}

#[test]
fn decoder_accepts_the_rdf_star_flag_and_rejects_generalized() {
    // The `rdf_star` options flag is now announced content, not a refusal:
    // RDF 1.2 triple terms in the object position are supported (N8).
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let row = options_row_with(|options| options.rdf_star = true);
    let batch = decoder
        .decode_frame(&frame_of(vec![row]))
        .expect("an rdf-star stream must be accepted");
    assert_eq!(batch.num_rows(), 0);

    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let row = options_row_with(|options| options.generalized_statements = true);
    let error = decoder
        .decode_frame(&frame_of(vec![row]))
        .expect_err("generalized flag");
    assert_eq!(error.code(), "unsupported");
}

#[test]
fn decoder_rejects_triples_and_graphs_physical_types() {
    for physical_type in [PhysicalStreamType::Triples, PhysicalStreamType::Graphs] {
        let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
        let row = options_row_with(|options| options.physical_type = physical_type.into());
        let error = decoder
            .decode_frame(&frame_of(vec![row]))
            .expect_err("unsupported physical type");
        assert_eq!(error.code(), "unsupported");
    }
}

#[test]
fn decoder_rejects_triple_row_in_quads_stream() {
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let triple_row = RdfStreamRow {
        row: Some(rdf_stream_row::Row::Triple(RdfTriple {
            subject: None,
            predicate: None,
            object: None,
        })),
    };
    let error = decoder
        .decode_frame(&frame_of(vec![valid_options_row(), triple_row]))
        .expect_err("triple row in quads stream");
    assert_eq!(error.code(), "frame");
}

#[test]
fn decoder_rejects_lookup_miss() {
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let error = decoder
        .decode_frame(&frame_of(vec![
            valid_options_row(),
            subject_only_quad_row(5, 5),
        ]))
        .expect_err("unassigned lookup ids");
    assert_eq!(error.code(), "lookup");
}

#[test]
fn decoder_rejects_repeated_term_in_first_quad() {
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let quad_row = RdfStreamRow {
        row: Some(rdf_stream_row::Row::Quad(RdfQuad {
            subject: None,
            predicate: None,
            object: None,
            graph: None,
        })),
    };
    let error = decoder
        .decode_frame(&frame_of(vec![valid_options_row(), quad_row]))
        .expect_err("all-repeated first quad");
    assert_eq!(error.code(), "frame");
}

#[test]
fn decoder_rejects_datatype_id_zero() {
    use jelly_fast_core::proto::{RdfLiteral, rdf_literal};
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let quad_row = RdfStreamRow {
        row: Some(rdf_stream_row::Row::Quad(RdfQuad {
            subject: Some(rdf_quad::Subject::SBnode("b0".into())),
            predicate: Some(rdf_quad::Predicate::PIri(RdfIri {
                prefix_id: 0,
                name_id: 0,
            })),
            object: Some(rdf_quad::Object::OLiteral(RdfLiteral {
                lex: "1".into(),
                literal_kind: Some(rdf_literal::LiteralKind::Datatype(0)),
            })),
            graph: None,
        })),
    };
    let name_row = RdfStreamRow {
        row: Some(rdf_stream_row::Row::Name(
            jelly_fast_core::proto::RdfNameEntry {
                id: 0,
                value: "http://example.com/p".into(),
            },
        )),
    };
    let error = decoder
        .decode_frame(&frame_of(vec![valid_options_row(), name_row, quad_row]))
        .expect_err("datatype id 0 is invalid");
    assert_eq!(error.code(), "lookup");
}

#[test]
fn decoder_rejects_oversized_declared_tables() {
    let options = JellyDecoderOptions {
        max_name_table_size: 64,
        ..JellyDecoderOptions::default()
    };
    let mut decoder = JellyDecoder::new(options);
    let row = options_row_with(|options| options.max_name_table_size = 65);
    let error = decoder
        .decode_frame(&frame_of(vec![row]))
        .expect_err("declared table above configured maximum");
    assert_eq!(error.code(), "resource_limit");
}
