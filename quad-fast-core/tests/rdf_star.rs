// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! RDF 1.2 triple terms in the `UnsignedQuadStream` contract.
//!
//! Spec anchors:
//! * RDF 1.2 Concepts §3.1 "Triple Terms" — a triple term may appear only in
//!   the object position of a triple.
//! * RDF 1.2 N-Triples §2.5, production `tripleTerm` — `<<( s p o )>>`.

use std::sync::Arc;

use arrow_array::{
    RecordBatch,
    builder::{
        FixedSizeBinaryBuilder, StringBuilder, StringDictionaryBuilder,
        TimestampMicrosecondBuilder, UInt64Builder,
    },
    types::UInt32Type,
};
use oxrdf::{BlankNode, GraphName, Literal, NamedNode, Quad, Term, Triple};
use quad_fast_core::{
    QuadBatchBuilder, QuadError, QuadLimits, QuadResource, QuadStreamReader, encode_triple_term,
    parse_triple_term, quad_stream_schema, read_ipc_stream, term_depth, validate_contract,
    write_ipc_stream,
};

fn iri(value: &str) -> NamedNode {
    NamedNode::new(value).expect("test IRI must be valid")
}

/// `<< <s> <p> "o" >>` as the object of `<s2> <says> _`.
fn quoting_quad() -> Quad {
    Quad::new(
        iri("http://example.com/alice"),
        iri("http://example.com/says"),
        Term::Triple(Box::new(Triple::new(
            iri("http://example.com/s"),
            iri("http://example.com/p"),
            Term::Literal(Literal::new_simple_literal("o")),
        ))),
        GraphName::NamedNode(iri("http://example.com/g")),
    )
}

fn nested_quad(depth: usize) -> Quad {
    let mut object = Term::Literal(Literal::new_simple_literal("leaf"));
    for _ in 0..depth {
        object = Term::Triple(Box::new(Triple::new(
            iri("http://example.com/s"),
            iri("http://example.com/p"),
            object,
        )));
    }
    Quad::new(
        iri("http://example.com/a"),
        iri("http://example.com/says"),
        object,
        GraphName::DefaultGraph,
    )
}

fn build(quads: &[Quad], limits: QuadLimits) -> Result<RecordBatch, QuadError> {
    let mut builder = QuadBatchBuilder::new(limits);
    for quad in quads {
        builder.push(quad.as_ref(), None)?;
    }
    builder.finish()
}

// --- positive: contract round-trips --------------------------------------

#[test]
fn triple_term_round_trips_through_batch() {
    let quads = vec![
        quoting_quad(),
        // A plain quad interleaved so the shared columns keep working.
        Quad::new(
            iri("http://example.com/s"),
            iri("http://example.com/p"),
            Term::Literal(Literal::new_typed_literal(
                "42",
                iri("http://www.w3.org/2001/XMLSchema#integer"),
            )),
            GraphName::DefaultGraph,
        ),
    ];
    let batch = build(&quads, QuadLimits::default()).expect("build must succeed");
    validate_contract(batch.schema().as_ref()).expect("contract must hold");

    let reader = QuadStreamReader::new(&batch).expect("reader must accept the batch");
    assert!(reader.contains_triple_terms());
    let decoded: Vec<Quad> = reader
        .iter_owned(QuadLimits::default())
        .map(|item| item.expect("row must decode").0)
        .collect();
    assert_eq!(decoded, quads);
}

#[test]
fn triple_term_survives_ipc_round_trip() {
    let quads = vec![quoting_quad()];
    let batch = build(&quads, QuadLimits::default()).expect("build must succeed");
    let bytes = write_ipc_stream(&[batch], usize::MAX).expect("ipc write must succeed");
    let batches = read_ipc_stream(&bytes).expect("ipc read must succeed");
    assert_eq!(batches.len(), 1);

    let reader = QuadStreamReader::new(&batches[0]).expect("reader must accept the batch");
    let decoded = reader
        .quad_owned(0, QuadLimits::default())
        .expect("row must decode");
    assert_eq!(decoded, quads[0]);
}

#[test]
fn nested_triple_terms_round_trip() {
    for depth in 1..=4 {
        let quad = nested_quad(depth);
        assert_eq!(term_depth(quad.object.as_ref()), depth);
        let batch =
            build(std::slice::from_ref(&quad), QuadLimits::default()).expect("build must succeed");
        let reader = QuadStreamReader::new(&batch).expect("reader must accept the batch");
        let decoded = reader
            .quad_owned(0, QuadLimits::default())
            .expect("row must decode");
        assert_eq!(decoded, quad);
    }
}

#[test]
fn every_inner_term_kind_round_trips() {
    let objects = vec![
        Term::NamedNode(iri("http://example.com/o")),
        Term::BlankNode(BlankNode::new("b0").expect("valid bnode")),
        Term::Literal(Literal::new_simple_literal("plain")),
        Term::Literal(Literal::new_typed_literal(
            "42",
            iri("http://www.w3.org/2001/XMLSchema#integer"),
        )),
        Term::Literal(Literal::new_language_tagged_literal("hallo", "de-DE").expect("valid tag")),
        // Escaping-sensitive lexical forms.
        Term::Literal(Literal::new_simple_literal(
            "quote \" backslash \\ newline \n tab \t",
        )),
        Term::Literal(Literal::new_simple_literal("unit\u{1}separator")),
    ];
    for object in objects {
        for subject in [
            oxrdf::NamedOrBlankNode::NamedNode(iri("http://example.com/s")),
            oxrdf::NamedOrBlankNode::BlankNode(BlankNode::new("inner").expect("valid bnode")),
        ] {
            let triple = Triple::new(subject, iri("http://example.com/p"), object.clone());
            let encoded = encode_triple_term(triple.as_ref());
            let parsed = parse_triple_term(&encoded, 8).expect("encoded term must parse");
            assert_eq!(parsed, triple, "round trip failed for `{encoded}`");
        }
    }
}

#[test]
fn encoding_matches_the_n_triples_triple_term_syntax() {
    // RDF 1.2 N-Triples §2.5: `<<( subject predicate object )>>`.
    let triple = Triple::new(
        iri("http://example.com/s"),
        iri("http://example.com/p"),
        Term::Literal(Literal::new_simple_literal("o")),
    );
    assert_eq!(
        encode_triple_term(triple.as_ref()),
        "<<( <http://example.com/s> <http://example.com/p> \
         \"o\"^^<http://www.w3.org/2001/XMLSchema#string> )>>"
    );
}

#[test]
fn encoding_is_deterministic() {
    let quad = quoting_quad();
    let first = build(std::slice::from_ref(&quad), QuadLimits::default()).expect("build");
    let second = build(std::slice::from_ref(&quad), QuadLimits::default()).expect("build");
    assert_eq!(
        write_ipc_stream(&[first], usize::MAX).expect("ipc"),
        write_ipc_stream(&[second], usize::MAX).expect("ipc")
    );
}

// --- fail-closed: one test per typed error path ---------------------------

#[test]
fn depth_limit_fails_closed_on_write() {
    let quad = nested_quad(3);
    let limits = QuadLimits {
        max_quoted_depth: 2,
        ..QuadLimits::default()
    };
    let error = build(std::slice::from_ref(&quad), limits).expect_err("must fail closed");
    match error {
        QuadError::ResourceLimit {
            resource,
            limit,
            observed,
        } => {
            assert_eq!(resource, QuadResource::QuotedDepth);
            assert_eq!(resource.as_str(), "quoted_depth");
            assert_eq!(limit, 2);
            assert_eq!(observed, 3);
        }
        other => panic!("expected a quoted_depth resource limit, got {other}"),
    }
    assert_eq!(
        build(std::slice::from_ref(&quad), limits)
            .expect_err("must fail closed")
            .code(),
        "resource_limit"
    );
}

#[test]
fn depth_limit_fails_closed_on_read() {
    let quad = nested_quad(4);
    let batch = build(std::slice::from_ref(&quad), QuadLimits::default()).expect("build");
    let reader = QuadStreamReader::new(&batch).expect("reader");
    let limits = QuadLimits {
        max_quoted_depth: 2,
        ..QuadLimits::default()
    };
    let error = reader.quad_owned(0, limits).expect_err("must fail closed");
    match error {
        QuadError::ResourceLimit {
            resource, limit, ..
        } => {
            assert_eq!(resource, QuadResource::QuotedDepth);
            assert_eq!(limit, 2);
        }
        other => panic!("expected a quoted_depth resource limit, got {other}"),
    }
}

#[test]
fn zero_copy_read_path_refuses_triple_terms() {
    let batch = build(&[quoting_quad()], QuadLimits::default()).expect("build");
    let reader = QuadStreamReader::new(&batch).expect("reader");
    let error = reader.quad(0).expect_err("borrowed path must refuse");
    assert_eq!(error.code(), "unsupported");
    assert!(
        error.to_string().contains("rdf12_triple_term"),
        "error must name the feature: {error}"
    );
    // The owned path decodes the very same row.
    reader
        .quad_owned(0, QuadLimits::default())
        .expect("owned path must decode");
}

#[test]
fn depth_zero_forbids_triple_terms_entirely() {
    let limits = QuadLimits {
        max_quoted_depth: 0,
        ..QuadLimits::default()
    };
    let error = build(&[quoting_quad()], limits).expect_err("must fail closed");
    assert_eq!(error.code(), "resource_limit");
}

#[test]
fn malformed_triple_term_encodings_are_typed_errors() {
    let cases = [
        "<<( <http://example.com/s> <http://example.com/p> )>>",
        "<<( <http://example.com/s> <http://example.com/p> \"o\" )>>",
        "<<( \"lit\" <http://example.com/p> <http://example.com/o> )>>",
        "<<( <http://example.com/s> _:b <http://example.com/o> )>>",
        "<<( <http://example.com/s> <http://example.com/p> <http://example.com/o> )>> trailing",
        "not a triple term",
        "<<( <unterminated",
    ];
    for case in cases {
        let error = parse_triple_term(case, 8).expect_err("must be refused");
        assert_eq!(error.code(), "term", "case `{case}` gave {error}");
    }
}

#[test]
fn triple_term_row_with_datatype_is_refused() {
    // A hand-built (foreign) batch that violates the encoding rule
    // "object_kind = triple implies null datatype and language".
    let batch = foreign_batch(
        "triple",
        "<<( <http://a> <http://b> <http://c> )>>",
        Some("http://www.w3.org/2001/XMLSchema#string"),
    );
    let reader = QuadStreamReader::new(&batch).expect("reader");
    let error = reader
        .quad_owned(0, QuadLimits::default())
        .expect_err("must be refused");
    assert_eq!(error.code(), "term");
}

#[test]
fn subject_position_triple_kind_is_refused() {
    // RDF 1.2 admits triple terms only as objects; a foreign batch that
    // claims one as a subject is refused, never guessed at.
    let batch = foreign_subject_kind_batch("triple");
    let reader = QuadStreamReader::new(&batch).expect("reader");
    let error = reader.quad(0).expect_err("must be refused");
    assert_eq!(error.code(), "unsupported");
    assert!(error.to_string().contains("object position"));
    let error = reader
        .quad_owned(0, QuadLimits::default())
        .expect_err("must be refused");
    assert_eq!(error.code(), "unsupported");
}

#[test]
fn unknown_object_kind_is_still_refused() {
    let batch = foreign_batch("quoted-triple", "whatever", None);
    let reader = QuadStreamReader::new(&batch).expect("reader");
    assert_eq!(
        reader.quad(0).expect_err("must be refused").code(),
        "term",
        "kinds outside the contract vocabulary stay fail-closed"
    );
}

// --- backward compatibility ----------------------------------------------

#[test]
fn pre_rdf12_batches_decode_unchanged() {
    // Built column-by-column, bypassing `QuadBatchBuilder` entirely, so this
    // is exactly what a writer from before the triple-term extension emits:
    // the same schema, the same metadata, only `iri`/`bnode`/`literal` kinds.
    let batch = legacy_batch();
    validate_contract(batch.schema().as_ref()).expect("v1 contract must still hold");
    let bytes = write_ipc_stream(&[batch], usize::MAX).expect("ipc write");
    let batches = read_ipc_stream(&bytes).expect("ipc read");
    let reader = QuadStreamReader::new(&batches[0]).expect("reader");

    assert!(!reader.contains_triple_terms());
    let expected = vec![
        Quad::new(
            iri("http://example.com/s"),
            iri("http://example.com/p"),
            iri("http://example.com/o"),
            GraphName::DefaultGraph,
        ),
        Quad::new(
            BlankNode::new("b0").expect("valid bnode"),
            iri("http://example.com/p"),
            Term::Literal(Literal::new_language_tagged_literal("hallo", "de").expect("tag")),
            GraphName::NamedNode(iri("http://example.com/g")),
        ),
    ];
    // The zero-copy path is untouched for legacy rows.
    let borrowed: Vec<Quad> = (0..reader.len())
        .map(|row| {
            reader
                .quad(row)
                .expect("legacy row must decode")
                .into_owned()
        })
        .collect();
    assert_eq!(borrowed, expected);
    // And the owned path agrees with it.
    let owned: Vec<Quad> = (0..reader.len())
        .map(|row| {
            reader
                .quad_owned(row, QuadLimits::default())
                .expect("legacy row must decode")
        })
        .collect();
    assert_eq!(owned, expected);
}

#[test]
fn builder_output_matches_a_legacy_writer_byte_for_byte() {
    // Freezes the on-wire encoding of non-triple-term rows: the extension
    // must not have perturbed any existing column value.
    let quads = vec![
        Quad::new(
            iri("http://example.com/s"),
            iri("http://example.com/p"),
            iri("http://example.com/o"),
            GraphName::DefaultGraph,
        ),
        Quad::new(
            BlankNode::new("b0").expect("valid bnode"),
            iri("http://example.com/p"),
            Term::Literal(Literal::new_language_tagged_literal("hallo", "de").expect("tag")),
            GraphName::NamedNode(iri("http://example.com/g")),
        ),
    ];
    let built = build(&quads, QuadLimits::default()).expect("build");
    assert_eq!(
        write_ipc_stream(&[built], usize::MAX).expect("ipc"),
        write_ipc_stream(&[legacy_batch()], usize::MAX).expect("ipc")
    );
}

// --- foreign-batch helpers ------------------------------------------------

struct Columns {
    subject_kind: StringDictionaryBuilder<UInt32Type>,
    subject_value: StringDictionaryBuilder<UInt32Type>,
    predicate_iri: StringDictionaryBuilder<UInt32Type>,
    object_kind: StringDictionaryBuilder<UInt32Type>,
    object_value: StringBuilder,
    object_datatype: StringDictionaryBuilder<UInt32Type>,
    object_language: StringDictionaryBuilder<UInt32Type>,
    graph_kind: StringDictionaryBuilder<UInt32Type>,
    graph_value: StringDictionaryBuilder<UInt32Type>,
}

impl Columns {
    fn new() -> Self {
        Self {
            subject_kind: StringDictionaryBuilder::new(),
            subject_value: StringDictionaryBuilder::new(),
            predicate_iri: StringDictionaryBuilder::new(),
            object_kind: StringDictionaryBuilder::new(),
            object_value: StringBuilder::new(),
            object_datatype: StringDictionaryBuilder::new(),
            object_language: StringDictionaryBuilder::new(),
            graph_kind: StringDictionaryBuilder::new(),
            graph_value: StringDictionaryBuilder::new(),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one argument per contract column"
    )]
    fn push(
        &mut self,
        subject: (&str, &str),
        predicate: &str,
        object: (&str, &str, Option<&str>, Option<&str>),
        graph: (&str, Option<&str>),
    ) {
        self.subject_kind.append_value(subject.0);
        self.subject_value.append_value(subject.1);
        self.predicate_iri.append_value(predicate);
        self.object_kind.append_value(object.0);
        self.object_value.append_value(object.1);
        append_opt(&mut self.object_datatype, object.2);
        append_opt(&mut self.object_language, object.3);
        self.graph_kind.append_value(graph.0);
        append_opt(&mut self.graph_value, graph.1);
    }

    fn finish(mut self, rows: usize) -> RecordBatch {
        let mut sha = FixedSizeBinaryBuilder::new(32);
        let mut start = UInt64Builder::new();
        let mut end = UInt64Builder::new();
        let mut observed = TimestampMicrosecondBuilder::new().with_timezone("UTC");
        let mut artifact: StringDictionaryBuilder<UInt32Type> = StringDictionaryBuilder::new();
        for _ in 0..rows {
            artifact.append_null();
            sha.append_null();
            start.append_null();
            end.append_null();
            observed.append_null();
        }
        RecordBatch::try_new(
            quad_stream_schema(),
            vec![
                Arc::new(self.subject_kind.finish()),
                Arc::new(self.subject_value.finish()),
                Arc::new(self.predicate_iri.finish()),
                Arc::new(self.object_kind.finish()),
                Arc::new(self.object_value.finish()),
                Arc::new(self.object_datatype.finish()),
                Arc::new(self.object_language.finish()),
                Arc::new(self.graph_kind.finish()),
                Arc::new(self.graph_value.finish()),
                Arc::new(artifact.finish()),
                Arc::new(sha.finish()),
                Arc::new(start.finish()),
                Arc::new(end.finish()),
                Arc::new(observed.finish()),
            ],
        )
        .expect("hand-built batch must match the schema")
    }
}

fn append_opt(builder: &mut StringDictionaryBuilder<UInt32Type>, value: Option<&str>) {
    match value {
        Some(value) => builder.append_value(value),
        None => builder.append_null(),
    }
}

fn legacy_batch() -> RecordBatch {
    let mut columns = Columns::new();
    columns.push(
        ("iri", "http://example.com/s"),
        "http://example.com/p",
        ("iri", "http://example.com/o", None, None),
        ("default", None),
    );
    columns.push(
        ("bnode", "b0"),
        "http://example.com/p",
        ("literal", "hallo", None, Some("de")),
        ("iri", Some("http://example.com/g")),
    );
    columns.finish(2)
}

fn foreign_batch(object_kind: &str, object_value: &str, datatype: Option<&str>) -> RecordBatch {
    let mut columns = Columns::new();
    columns.push(
        ("iri", "http://example.com/s"),
        "http://example.com/p",
        (object_kind, object_value, datatype, None),
        ("default", None),
    );
    columns.finish(1)
}

fn foreign_subject_kind_batch(subject_kind: &str) -> RecordBatch {
    let mut columns = Columns::new();
    columns.push(
        (subject_kind, "<<( <http://a> <http://b> <http://c> )>>"),
        "http://example.com/p",
        ("iri", "http://example.com/o", None, None),
        ("default", None),
    );
    columns.finish(1)
}
