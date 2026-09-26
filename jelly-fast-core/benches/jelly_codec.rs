// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Criterion benchmarks for the Jelly RDF and Jelly-Patch codec hot paths.
//!
//! Every corpus here is deterministic (no PRNG, no clock) so numbers are
//! comparable between runs, and every quad is one a real corpus would
//! produce: shared IRI prefixes, a small predicate vocabulary, a mix of
//! plain/typed/language-tagged literals, blank nodes, and several named
//! graphs. Degenerate one-element inputs are deliberately absent.
//!
//! Four groups, chosen so a regression shows up as a *slope* change rather
//! than a single number:
//!
//! * `encode/quads` and `decode/*` sweep the batch size across four orders
//!   of magnitude, with `Throughput::Elements` so criterion reports
//!   quads/second and a per-quad cost regression is visible even if the
//!   absolute time moves for unrelated reasons.
//! * `encode/table_churn` holds the corpus fixed at a term cardinality well
//!   above every table size it sweeps, so the swept axis is exactly how
//!   often the encoder's LRU reassigns a lookup identifier — the expensive
//!   and interesting behavior of `tables.rs`, and the one a naive change to
//!   eviction would silently pessimize.
//! * `terms` holds the row count fixed and varies only the *shape* of the
//!   terms, isolating the shared `terms.rs` compression path (IRI splitting
//!   and interning, repeated-term elision, the datatype table, RDF-star
//!   nesting) from framing and Arrow costs. `terms.rs` is `pub(crate)`, so
//!   this is the closest a bench target can get to it, and it is a fair
//!   proxy: the fixed row count makes everything but the term path a
//!   constant across the group.
//! * `patch` covers the Jelly-Patch encoder and decoder over the same
//!   corpus, sweeping the operation count.
//!
//! Decode groups build one decoder per stream and feed it every frame, the
//! way a transport consumer does; `decode/frame_bytes` additionally pays the
//! `prost` deserialization the gRPC path pays.

use std::hint::black_box;

use arrow_array::RecordBatch;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use jelly_fast_core::{
    JellyDecoder, JellyDecoderOptions, JellyEncoder, JellyEncoderOptions, JellyPatchDecoder,
    JellyPatchDecoderOptions, JellyPatchEncoder, JellyPatchEncoderOptions, PatchOp,
    proto::{RdfStreamFrame, patch::RdfPatchFrame},
};
use oxrdf::{BlankNode, GraphName, Literal, NamedNode, Quad, Term, Triple};
use prost::Message;
use quad_fast_core::{QuadBatchBuilder, QuadLimits};

/// Batch sizes swept by the encode and decode groups.
const SIZES: &[usize] = &[256, 1_024, 4_096, 16_384];

/// Rows used by the fixed-size `terms` and `table_churn` groups.
const FIXED_ROWS: usize = 4_096;

/// IRI prefixes of the realistic corpus (host + path, as Jelly splits them).
const PREFIXES: &[&str] = &[
    "http://example.org/resource/",
    "http://example.org/vocab#",
    "http://xmlns.com/foaf/0.1/",
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "https://schema.org/",
    "http://purl.org/dc/terms/",
];

/// Predicate IRIs: a small, heavily repeated vocabulary, as in real data.
const PREDICATES: &[&str] = &[
    "http://xmlns.com/foaf/0.1/name",
    "http://xmlns.com/foaf/0.1/knows",
    "http://purl.org/dc/terms/created",
    "https://schema.org/identifier",
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
];

/// Datatype IRIs used by the typed-literal objects.
const DATATYPES: &[&str] = &[
    "http://www.w3.org/2001/XMLSchema#integer",
    "http://www.w3.org/2001/XMLSchema#dateTime",
    "http://www.w3.org/2001/XMLSchema#double",
    "http://www.w3.org/2001/XMLSchema#boolean",
];

/// Builds an IRI, panicking only on a programming error in this file.
fn iri(value: &str) -> NamedNode {
    NamedNode::new(value).expect("benchmark IRI is valid")
}

/// Shape of the object term a corpus emits.
#[derive(Clone, Copy)]
enum ObjectShape {
    /// Cycle through IRIs, literals, language tags, and blank nodes.
    Mixed,
    /// Only IRIs, maximizing prefix/name lookup table traffic.
    IriOnly,
    /// Only typed literals, maximizing datatype lookup table traffic.
    TypedLiteral,
    /// Only language-tagged literals (no table traffic, string-heavy).
    LangLiteral,
    /// RDF 1.2 triple terms nested two deep.
    TripleTerm,
}

/// Builds one object term for row `index` under `shape`.
fn object_for(index: usize, shape: ObjectShape, cardinality: usize) -> Term {
    match shape {
        ObjectShape::Mixed => match index % 4 {
            0 => Term::NamedNode(iri(&format!(
                "{}o{}",
                PREFIXES[index % PREFIXES.len()],
                index % cardinality
            ))),
            1 => Term::Literal(Literal::new_typed_literal(
                (index % 100_000).to_string(),
                iri(DATATYPES[index % DATATYPES.len()]),
            )),
            2 => Term::Literal(
                Literal::new_language_tagged_literal(
                    format!("label {}", index % cardinality),
                    if index.is_multiple_of(2) {
                        "en"
                    } else {
                        "pt-BR"
                    },
                )
                .expect("benchmark language tag is valid"),
            ),
            _ => Term::BlankNode(
                BlankNode::new(format!("b{}", index % 64)).expect("benchmark bnode is valid"),
            ),
        },
        ObjectShape::IriOnly => Term::NamedNode(iri(&format!(
            "{}o{}",
            PREFIXES[index % PREFIXES.len()],
            index % cardinality
        ))),
        ObjectShape::TypedLiteral => Term::Literal(Literal::new_typed_literal(
            (index % 100_000).to_string(),
            iri(DATATYPES[index % DATATYPES.len()]),
        )),
        ObjectShape::LangLiteral => Term::Literal(
            Literal::new_language_tagged_literal(
                format!("a moderately long label for row {index}"),
                if index.is_multiple_of(3) { "en" } else { "de" },
            )
            .expect("benchmark language tag is valid"),
        ),
        ObjectShape::TripleTerm => Term::Triple(Box::new(Triple::new(
            iri(&format!("{}s{}", PREFIXES[0], index % cardinality)),
            iri(PREDICATES[index % PREDICATES.len()]),
            Term::Triple(Box::new(Triple::new(
                iri(&format!("{}n{}", PREFIXES[1], index % cardinality)),
                iri(PREDICATES[(index + 1) % PREDICATES.len()]),
                Term::Literal(Literal::new_simple_literal(format!("inner {index}"))),
            ))),
        ))),
    }
}

/// Builds `count` quads over `cardinality` distinct local names.
///
/// Consecutive quads share a subject in runs of three and a graph in runs of
/// sixteen, which is what real serializations look like and what makes
/// repeated-term elision worth measuring.
fn corpus(count: usize, cardinality: usize, shape: ObjectShape) -> Vec<Quad> {
    (0..count)
        .map(|index| {
            let subject = iri(&format!(
                "{}s{}",
                PREFIXES[(index / 3) % PREFIXES.len()],
                (index / 3) % cardinality
            ));
            let predicate = iri(PREDICATES[index % PREDICATES.len()]);
            let graph = match (index / 16) % 4 {
                0 => GraphName::DefaultGraph,
                other => GraphName::NamedNode(iri(&format!("{}g{other}", PREFIXES[2]))),
            };
            Quad::new(
                subject,
                predicate,
                object_for(index, shape, cardinality),
                graph,
            )
        })
        .collect()
}

/// Packs quads into one `UnsignedQuadStream` batch.
fn batch_of(quads: &[Quad]) -> RecordBatch {
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    for quad in quads {
        builder.push(quad.as_ref(), None).expect("quad accepted");
    }
    builder.finish().expect("batch built")
}

/// Encoder options for a given table sizing and RDF-star setting.
fn encoder_options(prefix: u32, name: u32, datatype: u32, rdf_star: bool) -> JellyEncoderOptions {
    JellyEncoderOptions {
        max_prefix_table_size: prefix,
        max_name_table_size: name,
        max_datatype_table_size: datatype,
        rdf_star,
        ..JellyEncoderOptions::default()
    }
}

/// Decoder options mirroring `encoder_options`.
fn decoder_options(prefix: u32, name: u32, datatype: u32) -> JellyDecoderOptions {
    JellyDecoderOptions {
        max_prefix_table_size: prefix,
        max_name_table_size: name,
        max_datatype_table_size: datatype,
        quad_limits: QuadLimits::default(),
    }
}

/// Encodes one batch through a fresh encoder, as one whole stream.
fn encode_stream(batch: &RecordBatch, options: JellyEncoderOptions) -> Vec<RdfStreamFrame> {
    let mut encoder = JellyEncoder::new(options).expect("valid encoder options");
    encoder.encode_batch(batch).expect("batch encodes")
}

/// `JellyEncoder` over realistic quad batches, swept by batch size.
fn bench_encode(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("encode/quads");
    for &size in SIZES {
        let batch = batch_of(&corpus(size, 512, ObjectShape::Mixed));
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &batch,
            |bencher, batch| {
                bencher.iter(|| {
                    black_box(encode_stream(
                        black_box(batch),
                        encoder_options(128, 4_000, 32, false),
                    ))
                });
            },
        );
    }
    group.finish();
}

/// `JellyEncoder` under lookup-table churn.
///
/// The corpus holds 4,096 quads over 2,048 distinct local names; sweeping
/// the table size from far below that to comfortably above it moves the
/// encoder from reassigning an identifier on nearly every term to never
/// reassigning one. The interesting cost — LRU victim selection, which is a
/// linear scan of the occupied slots, plus the extra entry rows a
/// reassignment forces onto the wire — is exactly the difference across this
/// axis. The curve is not monotonic and is not meant to be: cost peaks where
/// the table is large enough for an expensive scan yet still too small for
/// the working set, and drops again once every name fits. A change that
/// makes eviction cheaper or the table smarter moves that peak, which is the
/// regression signal.
fn bench_encode_table_churn(criterion: &mut Criterion) {
    let batch = batch_of(&corpus(FIXED_ROWS, 2_048, ObjectShape::IriOnly));
    let mut group = criterion.benchmark_group("encode/table_churn");
    group.throughput(Throughput::Elements(FIXED_ROWS as u64));
    for &name_table in &[8_u32, 64, 512, 4_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(name_table),
            &name_table,
            |bencher, &name_table| {
                bencher.iter(|| {
                    black_box(encode_stream(
                        black_box(&batch),
                        encoder_options(8, name_table, 32, false),
                    ))
                });
            },
        );
    }
    group.finish();
}

/// `JellyDecoder` over frames the encoder produced, swept by batch size.
fn bench_decode(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("decode/frames");
    for &size in SIZES {
        let batch = batch_of(&corpus(size, 512, ObjectShape::Mixed));
        let frames = encode_stream(&batch, encoder_options(128, 4_000, 32, false));
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &frames,
            |bencher, frames| {
                bencher.iter(|| {
                    let mut decoder = JellyDecoder::new(decoder_options(128, 4_000, 32));
                    for frame in frames {
                        black_box(decoder.decode_frame(frame).expect("frame decodes"));
                    }
                });
            },
        );
    }
    group.finish();
}

/// The transport-shaped decode path: `prost` deserialization plus the codec.
fn bench_decode_frame_bytes(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("decode/frame_bytes");
    for &size in SIZES {
        let batch = batch_of(&corpus(size, 512, ObjectShape::Mixed));
        let encoded: Vec<Vec<u8>> = encode_stream(&batch, encoder_options(128, 4_000, 32, false))
            .iter()
            .map(RdfStreamFrame::encode_to_vec)
            .collect();
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &encoded,
            |bencher, encoded| {
                bencher.iter(|| {
                    let mut decoder = JellyDecoder::new(decoder_options(128, 4_000, 32));
                    for bytes in encoded {
                        let frame =
                            RdfStreamFrame::decode(bytes.as_slice()).expect("frame deserializes");
                        black_box(decoder.decode_frame(&frame).expect("frame decodes"));
                    }
                });
            },
        );
    }
    group.finish();
}

/// The shared `terms.rs` compression path, isolated by holding rows fixed.
///
/// Every case encodes and decodes the same 4,096 rows, so framing, Arrow
/// reads, and per-frame overhead are constant and the only thing that moves
/// is which arm of the term codec the rows exercise.
fn bench_terms(criterion: &mut Criterion) {
    let cases: &[(&str, ObjectShape, bool)] = &[
        // High-cardinality IRIs: IRI splitting and prefix/name interning.
        ("iri_high_cardinality", ObjectShape::IriOnly, false),
        // Typed literals: datatype table traffic instead of name traffic.
        ("typed_literal", ObjectShape::TypedLiteral, false),
        // Language tags: no table traffic, pure string handling.
        ("lang_literal", ObjectShape::LangLiteral, false),
        // RDF-star: the recursive term encoder, two levels deep.
        ("triple_term", ObjectShape::TripleTerm, true),
    ];
    let mut encode_group = criterion.benchmark_group("terms/encode");
    encode_group.throughput(Throughput::Elements(FIXED_ROWS as u64));
    for &(label, shape, rdf_star) in cases {
        // Low cardinality on the repeated case is the point of contrast:
        // 64 distinct names means elision and table hits dominate.
        let cardinality = if matches!(shape, ObjectShape::IriOnly) {
            2_048
        } else {
            64
        };
        let batch = batch_of(&corpus(FIXED_ROWS, cardinality, shape));
        encode_group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &batch,
            |bencher, batch| {
                bencher.iter(|| {
                    black_box(encode_stream(
                        black_box(batch),
                        encoder_options(128, 4_000, 32, rdf_star),
                    ))
                });
            },
        );
    }
    encode_group.finish();

    let mut decode_group = criterion.benchmark_group("terms/decode");
    decode_group.throughput(Throughput::Elements(FIXED_ROWS as u64));
    for &(label, shape, rdf_star) in cases {
        let cardinality = if matches!(shape, ObjectShape::IriOnly) {
            2_048
        } else {
            64
        };
        let batch = batch_of(&corpus(FIXED_ROWS, cardinality, shape));
        let frames = encode_stream(&batch, encoder_options(128, 4_000, 32, rdf_star));
        decode_group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &frames,
            |bencher, frames| {
                bencher.iter(|| {
                    let mut decoder = JellyDecoder::new(decoder_options(128, 4_000, 32));
                    for frame in frames {
                        black_box(decoder.decode_frame(frame).expect("frame decodes"));
                    }
                });
            },
        );
    }
    decode_group.finish();
}

/// Builds a patch operation sequence: headers, then transactional add/delete
/// runs over `count` quads split into four batches.
fn patch_ops(count: usize) -> Vec<PatchOp> {
    let quads = corpus(count, 512, ObjectShape::Mixed);
    let chunk = count.div_ceil(4).max(1);
    let mut ops = vec![
        PatchOp::Header {
            key: "source".to_owned(),
            value: Term::NamedNode(iri("http://example.org/resource/feed")),
        },
        PatchOp::Header {
            key: "seq".to_owned(),
            value: Term::Literal(Literal::new_simple_literal("1")),
        },
        PatchOp::TransactionStart,
    ];
    for (index, window) in quads.chunks(chunk).enumerate() {
        let batch = batch_of(window);
        ops.push(if index.is_multiple_of(2) {
            PatchOp::Add(batch)
        } else {
            PatchOp::Delete(batch)
        });
    }
    ops.push(PatchOp::TransactionCommit);
    ops
}

/// Encodes a patch operation sequence through a fresh encoder.
fn encode_patch(ops: &[PatchOp]) -> Vec<RdfPatchFrame> {
    let mut encoder =
        JellyPatchEncoder::new(JellyPatchEncoderOptions::default()).expect("valid encoder options");
    let frames = encoder.encode_ops(ops).expect("ops encode");
    encoder.finish().expect("balanced patch");
    frames
}

/// The Jelly-Patch codec, swept by operation size.
fn bench_patch(criterion: &mut Criterion) {
    let mut encode_group = criterion.benchmark_group("patch/encode");
    for &size in SIZES {
        let ops = patch_ops(size);
        encode_group.throughput(Throughput::Elements(size as u64));
        encode_group.bench_with_input(BenchmarkId::from_parameter(size), &ops, |bencher, ops| {
            bencher.iter(|| black_box(encode_patch(black_box(ops))));
        });
    }
    encode_group.finish();

    let mut decode_group = criterion.benchmark_group("patch/decode");
    for &size in SIZES {
        let frames = encode_patch(&patch_ops(size));
        decode_group.throughput(Throughput::Elements(size as u64));
        decode_group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &frames,
            |bencher, frames| {
                bencher.iter(|| {
                    let mut decoder = JellyPatchDecoder::new(JellyPatchDecoderOptions::default());
                    for frame in frames {
                        black_box(decoder.decode_frame(frame).expect("frame decodes"));
                    }
                    decoder.finish().expect("balanced patch");
                });
            },
        );
    }
    decode_group.finish();
}

criterion_group!(
    benches,
    bench_encode,
    bench_encode_table_churn,
    bench_decode,
    bench_decode_frame_bytes,
    bench_terms,
    bench_patch
);
criterion_main!(benches);
