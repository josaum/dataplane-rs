// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! RDF 1.2 triple terms over the Jelly wire, in both vendored codecs.
//!
//! Schema anchors (vendored `proto/rdf.proto`, Jelly serialization 1.1.1):
//! * `RdfQuad.o_triple_term` field 12, `RdfTriple.o_triple_term` field 12 —
//!   "RDF-star quoted triple".
//! * `RdfStreamOptions.rdf_star` field 4 — "Whether the stream may contain
//!   RDF-star statements".
//! * `RdfTriple` doc comment — "All terms must also be set in quoted triples
//!   (RDF-star)."
//!
//! And the vendored `proto/patch.proto`: `RdfPatchOptions.rdf_star` field 4,
//! `RdfPatchHeader.h_triple_term` field 5.

use arrow_array::RecordBatch;
use jelly_fast_core::{
    JellyDecoder, JellyDecoderOptions, JellyEncoder, JellyEncoderOptions, JellyError,
    JellyPatchDecoder, JellyPatchDecoderOptions, JellyPatchEncoder, JellyPatchEncoderOptions,
    JellyResource, PatchOp,
    proto::{
        RdfQuad, RdfStreamFrame, RdfStreamRow, RdfTriple,
        patch::{RdfPatchFrame, RdfPatchHeader, RdfPatchRow, rdf_patch_header, rdf_patch_row},
        rdf_quad, rdf_stream_row, rdf_triple,
    },
};
use oxrdf::{BlankNode, GraphName, Literal, NamedNode, Quad, Term, Triple, vocab::xsd};
use quad_fast_core::{QuadBatchBuilder, QuadLimits, QuadStreamReader};

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
        .map(|row| {
            reader
                .quad_owned(row, QuadLimits::default())
                .expect("valid quad")
        })
        .collect()
}

/// A corpus mixing plain quads with triple terms of several shapes.
fn star_corpus() -> Vec<Quad> {
    let alice = iri("http://example.com/people#alice");
    let says = iri("http://example.com/says");
    let knows = iri("http://xmlns.com/foaf/0.1/knows");
    let bob = iri("http://example.com/people#bob");
    vec![
        // Plain quad first, so lookup tables and delta state warm up.
        Quad::new(
            alice.clone(),
            knows.clone(),
            bob.clone(),
            GraphName::DefaultGraph,
        ),
        // Triple term with an IRI object.
        Quad::new(
            alice.clone(),
            says.clone(),
            Term::Triple(Box::new(Triple::new(
                alice.clone(),
                knows.clone(),
                bob.clone(),
            ))),
            GraphName::NamedNode(iri("http://example.com/graphs/g1")),
        ),
        // Triple term with a blank-node subject and a typed literal object.
        Quad::new(
            BlankNode::new("b0").expect("valid bnode"),
            says.clone(),
            Term::Triple(Box::new(Triple::new(
                BlankNode::new("b1").expect("valid bnode"),
                iri("http://example.com/age"),
                Term::Literal(Literal::new_typed_literal("42", xsd::INTEGER)),
            ))),
            GraphName::DefaultGraph,
        ),
        // Triple term with a language-tagged literal object.
        Quad::new(
            alice.clone(),
            says.clone(),
            Term::Triple(Box::new(Triple::new(
                bob.clone(),
                iri("http://xmlns.com/foaf/0.1/name"),
                Term::Literal(
                    Literal::new_language_tagged_literal("Bob", "en").expect("valid tag"),
                ),
            ))),
            GraphName::BlankNode(BlankNode::new("g0").expect("valid bnode")),
        ),
        // Nested triple term (an annotation of an annotation).
        Quad::new(
            alice.clone(),
            says.clone(),
            Term::Triple(Box::new(Triple::new(
                alice.clone(),
                says.clone(),
                Term::Triple(Box::new(Triple::new(alice, knows, bob))),
            ))),
            GraphName::DefaultGraph,
        ),
    ]
}

fn star_encoder() -> JellyEncoder {
    JellyEncoder::new(JellyEncoderOptions {
        rdf_star: true,
        ..JellyEncoderOptions::default()
    })
    .expect("valid options")
}

fn decode_frames(frames: &[RdfStreamFrame]) -> Vec<Quad> {
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let mut quads = Vec::new();
    for frame in frames {
        let batch = decoder.decode_frame(frame).expect("frame must decode");
        quads.extend(quads_of(&batch));
    }
    quads
}

// --- RDF stream codec -----------------------------------------------------

#[test]
fn triple_terms_round_trip_over_the_jelly_wire() {
    let quads = star_corpus();
    let frames = star_encoder()
        .encode_batch(&batch_of(&quads))
        .expect("encode must succeed");
    assert_eq!(decode_frames(&frames), quads);
}

#[test]
fn options_row_announces_rdf_star_only_when_enabled() {
    // Vendored `rdf.proto` field 4: the options row declares whether the
    // stream may carry RDF-star statements.
    let plain = JellyEncoder::new(JellyEncoderOptions::default())
        .expect("valid options")
        .encode_batch(&batch_of(&[Quad::new(
            iri("http://example.com/s"),
            iri("http://example.com/p"),
            iri("http://example.com/o"),
            GraphName::DefaultGraph,
        )]))
        .expect("encode");
    assert!(!options_of(&plain[0]).rdf_star);

    let starred = star_encoder()
        .encode_batch(&batch_of(&star_corpus()))
        .expect("encode");
    assert!(options_of(&starred[0]).rdf_star);
}

#[test]
fn triple_terms_set_every_nested_term_on_the_wire() {
    // Vendored `rdf.proto`: "All terms must also be set in quoted triples."
    let frames = star_encoder()
        .encode_batch(&batch_of(&star_corpus()))
        .expect("encode");
    let mut checked = 0usize;
    for row in &frames[0].rows {
        if let Some(rdf_stream_row::Row::Quad(quad)) = &row.row
            && let Some(rdf_quad::Object::OTripleTerm(triple)) = &quad.object
        {
            checked += assert_all_terms_set(triple);
        }
    }
    assert!(checked >= 4, "expected several triple terms, saw {checked}");
}

fn assert_all_terms_set(triple: &RdfTriple) -> usize {
    assert!(triple.subject.is_some(), "quoted subject must be set");
    assert!(triple.predicate.is_some(), "quoted predicate must be set");
    let object = triple.object.as_ref().expect("quoted object must be set");
    let mut seen = 1;
    if let rdf_triple::Object::OTripleTerm(nested) = object {
        seen += assert_all_terms_set(nested);
    }
    seen
}

fn options_of(frame: &RdfStreamFrame) -> &jelly_fast_core::proto::RdfStreamOptions {
    match frame.rows.first().and_then(|row| row.row.as_ref()) {
        Some(rdf_stream_row::Row::Options(options)) => options,
        _ => panic!("first row must be the options row"),
    }
}

#[test]
fn encoder_refuses_triple_terms_without_the_opt_in() {
    let error = JellyEncoder::new(JellyEncoderOptions::default())
        .expect("valid options")
        .encode_batch(&batch_of(&star_corpus()))
        .expect_err("must fail closed");
    assert_eq!(error.code(), "unsupported");
    assert!(
        error.to_string().contains("rdf_star"),
        "error must name the option: {error}"
    );
}

#[test]
fn decoder_refuses_a_triple_term_the_options_row_denied() {
    // A stream whose options row says `rdf_star = false` but whose rows
    // carry a triple term contradicts itself; refuse rather than accept.
    let mut plain = JellyEncoder::new(JellyEncoderOptions::default()).expect("valid options");
    let frames = plain
        .encode_batch(&batch_of(&[Quad::new(
            iri("http://example.com/s"),
            iri("http://example.com/p"),
            iri("http://example.com/o"),
            GraphName::DefaultGraph,
        )]))
        .expect("encode");
    let mut rows = frames[0].rows.clone();
    rows.push(RdfStreamRow {
        row: Some(rdf_stream_row::Row::Quad(RdfQuad {
            subject: None,
            predicate: None,
            object: Some(rdf_quad::Object::OTripleTerm(wire_triple())),
            graph: None,
        })),
    });
    let frame = RdfStreamFrame {
        rows,
        metadata: std::collections::HashMap::new(),
    };
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let error = decoder.decode_frame(&frame).expect_err("must fail closed");
    assert_eq!(error.code(), "frame");
    assert!(error.to_string().contains("rdf_star"));
}

/// A fully-populated wire triple term: `<s> <p> <o>` via explicit ids.
fn wire_triple() -> RdfTriple {
    RdfTriple {
        subject: Some(rdf_triple::Subject::SBnode("q0".into())),
        predicate: Some(rdf_triple::Predicate::PIri(
            jelly_fast_core::proto::RdfIri {
                prefix_id: 1,
                name_id: 1,
            },
        )),
        object: Some(rdf_triple::Object::OBnode("q1".into())),
    }
}

#[test]
fn decoder_refuses_triple_terms_outside_the_object_position() {
    // RDF 1.2 admits triple terms only as objects.
    for (label, quad) in [
        (
            "subject",
            RdfQuad {
                subject: Some(rdf_quad::Subject::STripleTerm(wire_triple())),
                predicate: None,
                object: None,
                graph: None,
            },
        ),
        (
            "predicate",
            RdfQuad {
                subject: Some(rdf_quad::Subject::SBnode("b0".into())),
                predicate: Some(rdf_quad::Predicate::PTripleTerm(wire_triple())),
                object: None,
                graph: None,
            },
        ),
    ] {
        let error = decode_starred_quad(quad).expect_err("must fail closed");
        assert_eq!(error.code(), "unsupported", "{label}");
        assert!(
            error.to_string().contains("rdf_star_non_object"),
            "{label}: {error}"
        );
    }
}

#[test]
fn decoder_refuses_unset_terms_inside_a_triple_term() {
    let error = decode_starred_quad(RdfQuad {
        subject: Some(rdf_quad::Subject::SBnode("b0".into())),
        predicate: Some(rdf_quad::Predicate::PIri(jelly_fast_core::proto::RdfIri {
            prefix_id: 1,
            name_id: 1,
        })),
        object: Some(rdf_quad::Object::OTripleTerm(RdfTriple {
            subject: None,
            predicate: None,
            object: None,
        })),
        graph: Some(rdf_quad::Graph::GDefaultGraph(
            jelly_fast_core::proto::RdfDefaultGraph {},
        )),
    })
    .expect_err("must fail closed");
    assert_eq!(error.code(), "frame");
    assert!(error.to_string().contains("all terms"));
}

#[test]
fn decoder_bounds_triple_term_nesting_depth() {
    let quads = vec![Quad::new(
        iri("http://example.com/a"),
        iri("http://example.com/says"),
        Term::Triple(Box::new(Triple::new(
            iri("http://example.com/a"),
            iri("http://example.com/says"),
            Term::Triple(Box::new(Triple::new(
                iri("http://example.com/a"),
                iri("http://example.com/knows"),
                iri("http://example.com/b"),
            ))),
        ))),
        GraphName::DefaultGraph,
    )];
    let frames = star_encoder()
        .encode_batch(&batch_of(&quads))
        .expect("encode");
    let mut decoder = JellyDecoder::new(JellyDecoderOptions {
        quad_limits: QuadLimits {
            max_quoted_depth: 1,
            ..QuadLimits::default()
        },
        ..JellyDecoderOptions::default()
    });
    let error = decoder
        .decode_frame(&frames[0])
        .expect_err("must fail closed");
    match error {
        JellyError::ResourceLimit {
            resource,
            limit,
            observed,
        } => {
            assert_eq!(resource, JellyResource::QuotedDepth);
            assert_eq!(resource.as_str(), "quoted_depth");
            assert_eq!(limit, 1);
            assert_eq!(observed, 2);
        }
        other => panic!("expected a quoted_depth resource limit, got {other}"),
    }
}

/// Decodes one quad row on a stream that announced `rdf_star`.
fn decode_starred_quad(quad: RdfQuad) -> Result<RecordBatch, JellyError> {
    let mut encoder = star_encoder();
    let frames = encoder
        .encode_batch(&batch_of(&[Quad::new(
            iri("http://example.com/s"),
            iri("http://example.com/p"),
            iri("http://example.com/o"),
            GraphName::DefaultGraph,
        )]))
        .expect("encode");
    let mut rows = frames[0].rows.clone();
    rows.push(RdfStreamRow {
        row: Some(rdf_stream_row::Row::Quad(quad)),
    });
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    decoder.decode_frame(&RdfStreamFrame {
        rows,
        metadata: std::collections::HashMap::new(),
    })
}

// --- patch codec ----------------------------------------------------------

fn patch_encoder() -> JellyPatchEncoder {
    JellyPatchEncoder::new(JellyPatchEncoderOptions {
        rdf_star: true,
        ..JellyPatchEncoderOptions::default()
    })
    .expect("valid options")
}

fn decode_patch(frames: &[RdfPatchFrame]) -> Vec<PatchOp> {
    let mut decoder = JellyPatchDecoder::new(JellyPatchDecoderOptions::default());
    let mut ops = Vec::new();
    for frame in frames {
        ops.extend(decoder.decode_frame(frame).expect("frame must decode"));
    }
    decoder.finish().expect("patch must end cleanly");
    ops
}

#[test]
fn patch_statements_round_trip_triple_terms() {
    let quads = star_corpus();
    let mut encoder = patch_encoder();
    let frames = encoder
        .encode_ops(&[PatchOp::Add(batch_of(&quads))])
        .expect("encode");
    encoder.finish().expect("patch ends cleanly");
    let ops = decode_patch(&frames);
    assert_eq!(ops.len(), 1);
    match &ops[0] {
        PatchOp::Add(batch) => assert_eq!(quads_of(batch), quads),
        other => panic!("expected an add operation, got {other:?}"),
    }
}

#[test]
fn patch_headers_round_trip_triple_terms() {
    // The vendored patch.proto models `h_triple_term` explicitly, so header
    // triple terms are implemented rather than refused.
    let value = Term::Triple(Box::new(Triple::new(
        iri("http://example.com/s"),
        iri("http://example.com/p"),
        Term::Literal(Literal::new_typed_literal("42", xsd::INTEGER)),
    )));
    let mut encoder = patch_encoder();
    let frames = encoder
        .encode_ops(&[PatchOp::Header {
            key: "provenance".into(),
            value: value.clone(),
        }])
        .expect("encode");
    encoder.finish().expect("patch ends cleanly");
    let ops = decode_patch(&frames);
    assert_eq!(
        ops,
        vec![PatchOp::Header {
            key: "provenance".into(),
            value,
        }]
    );
}

#[test]
fn patch_encoder_refuses_triple_terms_without_the_opt_in() {
    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let error = encoder
        .encode_ops(&[PatchOp::Add(batch_of(&star_corpus()))])
        .expect_err("must fail closed");
    assert_eq!(error.code(), "unsupported");
    assert!(error.to_string().contains("rdf_star"));

    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let error = encoder
        .encode_ops(&[PatchOp::Header {
            key: "provenance".into(),
            value: Term::Triple(Box::new(Triple::new(
                iri("http://example.com/s"),
                iri("http://example.com/p"),
                iri("http://example.com/o"),
            ))),
        }])
        .expect_err("must fail closed");
    assert_eq!(error.code(), "unsupported");
}

#[test]
fn patch_decoder_refuses_a_header_triple_term_the_options_row_denied() {
    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid options");
    let frames = encoder
        .encode_ops(&[PatchOp::Header {
            key: "k".into(),
            value: Term::NamedNode(iri("http://example.com/v")),
        }])
        .expect("encode");
    let mut rows = frames[0].rows.clone();
    rows.push(RdfPatchRow {
        row: Some(rdf_patch_row::Row::Header(RdfPatchHeader {
            key: "starred".into(),
            value: Some(rdf_patch_header::Value::HTripleTerm(wire_triple())),
        })),
    });
    let mut decoder = JellyPatchDecoder::new(JellyPatchDecoderOptions::default());
    let error = decoder
        .decode_frame(&RdfPatchFrame { rows })
        .expect_err("must fail closed");
    assert_eq!(error.code(), "frame");
    assert!(error.to_string().contains("rdf_star"));
}
