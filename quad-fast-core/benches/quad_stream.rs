// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Criterion benchmarks over the `UnsignedQuadStream` v1 hot paths.
//!
//! # What is measured, and why
//!
//! * `builder/push` — the write path, swept over 100 / 1 000 / 10 000 quads
//!   with `Throughput::Elements` so a regression shows up as a slope change
//!   rather than one number moving. The dictionary columns only pay off when
//!   values repeat, so the generator repeats subjects, predicates, graphs, and
//!   datatypes the way a real RDF corpus does; a generator of all-distinct
//!   terms would benchmark a workload nobody runs.
//! * `builder/finish` — the Arrow assembly step, timed separately because it
//!   is `O(distinct values)` while `push` is `O(quads)`.
//! * `read/zero_copy` vs `read/owned` — **the load-bearing comparison**. The
//!   contract's zero-copy claim ("decoding borrows from Arrow buffers, no
//!   per-quad allocation") is a design commitment, and a benchmark is how it
//!   stays true: if `iter` ever starts allocating, its curve converges on
//!   `iter_owned`'s and this pair says so. Both run over the *same*
//!   triple-term-free batch, because `iter` refuses triple-term rows by
//!   design — comparing them on a batch containing one would be comparing a
//!   decode against a refusal.
//! * `ipc/*` — Arrow IPC write, read, and the full round-trip, the shape a
//!   Flight `DoPut` actually takes.
//! * `read/contains_triple_terms` — swept over the same sizes to show the
//!   scan is flat in row count: it walks the `object_kind` *dictionary*, not
//!   the rows, so consumers can refuse a batch once instead of per row.
//!
//! Run with `cargo bench -p quad-fast-core`; `--no-run` compiles only.

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use oxrdf::{BlankNode, GraphName, Literal, NamedNode, Quad, Term, Triple};
use quad_fast_core::{
    DEFAULT_MAX_IPC_BYTES, QuadBatchBuilder, QuadLimits, QuadStreamReader, SourceProvenance,
    read_ipc_stream, write_ipc_stream,
};

/// Row counts swept by every size-sensitive benchmark.
const SIZES: [usize; 3] = [100, 1_000, 10_000];

fn iri(value: &str) -> NamedNode {
    NamedNode::new(value).expect("benchmark IRI must be valid")
}

/// Builds `count` quads with realistic term repetition.
///
/// When `triple_term_every` is non-zero, every n-th object is a depth-2 RDF
/// 1.2 triple term, so the RDF-star path is measured over a batch that also
/// contains ordinary rows — the mix a real annotated dataset produces.
fn sample_quads(count: usize, triple_term_every: usize) -> Vec<Quad> {
    let predicates: Vec<NamedNode> = (0..8)
        .map(|index| iri(&format!("http://example.com/ns/p{index}")))
        .collect();
    let graphs: Vec<GraphName> = vec![
        GraphName::DefaultGraph,
        GraphName::NamedNode(iri("http://example.com/graph/a")),
        GraphName::NamedNode(iri("http://example.com/graph/b")),
        GraphName::BlankNode(BlankNode::new("g0").expect("valid blank node")),
    ];
    let datatypes: Vec<NamedNode> = ["string", "integer", "dateTime", "double"]
        .iter()
        .map(|name| iri(&format!("http://www.w3.org/2001/XMLSchema#{name}")))
        .collect();

    (0..count)
        .map(|index| {
            let subject: oxrdf::NamedOrBlankNode = if index % 11 == 0 {
                BlankNode::new(format!("b{}", index % 97))
                    .expect("valid blank node")
                    .into()
            } else {
                iri(&format!("http://example.com/resource/{}", index % 512)).into()
            };
            let object = if triple_term_every != 0 && index % triple_term_every == 0 {
                Term::Triple(Box::new(Triple::new(
                    iri(&format!("http://example.com/resource/{}", index % 128)),
                    predicates[index % predicates.len()].clone(),
                    Term::Triple(Box::new(Triple::new(
                        iri("http://example.com/inner/s"),
                        iri("http://example.com/inner/p"),
                        Term::Literal(
                            Literal::new_language_tagged_literal(
                                format!("annotated {index}"),
                                "en",
                            )
                            .expect("valid language tag"),
                        ),
                    ))),
                )))
            } else {
                match index % 4 {
                    0 => {
                        Term::NamedNode(iri(&format!("http://example.com/object/{}", index % 256)))
                    }
                    1 => Term::BlankNode(
                        BlankNode::new(format!("o{}", index % 64)).expect("valid blank node"),
                    ),
                    2 => Term::Literal(
                        Literal::new_language_tagged_literal(
                            format!("label number {index}"),
                            "en-GB",
                        )
                        .expect("valid language tag"),
                    ),
                    _ => Term::Literal(Literal::new_typed_literal(
                        format!("{index}"),
                        datatypes[index % datatypes.len()].clone(),
                    )),
                }
            };
            Quad::new(
                subject,
                predicates[index % predicates.len()].clone(),
                object,
                graphs[index % graphs.len()].clone(),
            )
        })
        .collect()
}

/// Provenance with a realistic mix of present and absent columns.
fn sample_provenance(index: usize) -> SourceProvenance {
    let mut digest = [0u8; 32];
    for (slot, byte) in digest.iter_mut().enumerate() {
        *byte = u8::try_from(slot.wrapping_mul(31).wrapping_add(index) % 256).unwrap_or(0);
    }
    SourceProvenance {
        source_artifact_iri: Some(format!("http://example.com/artifact/{}", index % 16)),
        source_content_sha256: Some(digest),
        source_offset_start: Some(u64::try_from(index).unwrap_or(0) * 64),
        source_offset_end: Some(u64::try_from(index).unwrap_or(0) * 64 + 63),
        observed_at_micros: Some(1_700_000_000_000_000 + i64::try_from(index).unwrap_or(0)),
    }
}

/// Builds a finished contract batch from `quads`.
fn build_batch(quads: &[Quad], with_provenance: bool) -> arrow_array::RecordBatch {
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    for (index, quad) in quads.iter().enumerate() {
        let provenance = with_provenance.then(|| sample_provenance(index));
        builder
            .push(quad.as_ref(), provenance.as_ref())
            .expect("benchmark quad must be accepted");
    }
    builder.finish().expect("benchmark batch must finish")
}

fn bench_push(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("builder/push");
    for size in SIZES {
        let quads = sample_quads(size, 0);
        group.throughput(Throughput::Elements(u64::try_from(size).unwrap_or(0)));
        group.bench_with_input(BenchmarkId::new("bare", size), &quads, |bencher, quads| {
            bencher.iter(|| {
                let mut builder = QuadBatchBuilder::new(QuadLimits::default());
                for quad in quads {
                    builder
                        .push(black_box(quad.as_ref()), None)
                        .expect("push must succeed");
                }
                black_box(builder.len())
            });
        });
        group.bench_with_input(
            BenchmarkId::new("with_provenance", size),
            &quads,
            |bencher, quads| {
                bencher.iter(|| {
                    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
                    for (index, quad) in quads.iter().enumerate() {
                        let provenance = sample_provenance(index);
                        builder
                            .push(black_box(quad.as_ref()), Some(&provenance))
                            .expect("push must succeed");
                    }
                    black_box(builder.len())
                });
            },
        );
    }
    // Triple terms cost a recursive serialization per row; the contrast at one
    // size is enough to catch that path regressing.
    let quads = sample_quads(1_000, 4);
    group.throughput(Throughput::Elements(1_000));
    group.bench_with_input(
        BenchmarkId::new("with_triple_terms", 1_000),
        &quads,
        |bencher, quads| {
            bencher.iter(|| {
                let mut builder = QuadBatchBuilder::new(QuadLimits::default());
                for quad in quads {
                    builder
                        .push(black_box(quad.as_ref()), None)
                        .expect("push must succeed");
                }
                black_box(builder.len())
            });
        },
    );
    group.finish();
}

fn bench_finish(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("builder/finish");
    for size in SIZES {
        let quads = sample_quads(size, 0);
        group.throughput(Throughput::Elements(u64::try_from(size).unwrap_or(0)));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &quads,
            |bencher, quads| {
                bencher.iter_batched(
                    || {
                        let mut builder = QuadBatchBuilder::new(QuadLimits::default());
                        for quad in quads {
                            builder
                                .push(quad.as_ref(), None)
                                .expect("push must succeed");
                        }
                        builder
                    },
                    |builder| black_box(builder.finish().expect("finish must succeed")),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_read_paths(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("read/zero_copy_vs_owned");
    for size in SIZES {
        // No triple terms: `iter` refuses those rows by design, so including
        // them would compare a decode against a refusal.
        let batch = build_batch(&sample_quads(size, 0), true);
        group.throughput(Throughput::Elements(u64::try_from(size).unwrap_or(0)));
        group.bench_with_input(
            BenchmarkId::new("iter_zero_copy", size),
            &batch,
            |bencher, batch| {
                let reader = QuadStreamReader::new(batch).expect("contract must hold");
                bencher.iter(|| {
                    let mut count = 0usize;
                    for item in reader.iter() {
                        let (quad, provenance) = item.expect("row must decode");
                        black_box(&quad);
                        black_box(&provenance);
                        count += 1;
                    }
                    black_box(count)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("iter_owned", size),
            &batch,
            |bencher, batch| {
                let reader = QuadStreamReader::new(batch).expect("contract must hold");
                let limits = QuadLimits::default();
                bencher.iter(|| {
                    let mut count = 0usize;
                    for item in reader.iter_owned(limits) {
                        let (quad, provenance) = item.expect("row must decode");
                        black_box(&quad);
                        black_box(&provenance);
                        count += 1;
                    }
                    black_box(count)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("quad_zero_copy", size),
            &batch,
            |bencher, batch| {
                let reader = QuadStreamReader::new(batch).expect("contract must hold");
                bencher.iter(|| {
                    let mut count = 0usize;
                    for row in 0..reader.len() {
                        black_box(reader.quad(row).expect("row must decode"));
                        count += 1;
                    }
                    black_box(count)
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("quad_owned", size),
            &batch,
            |bencher, batch| {
                let reader = QuadStreamReader::new(batch).expect("contract must hold");
                let limits = QuadLimits::default();
                bencher.iter(|| {
                    let mut count = 0usize;
                    for row in 0..reader.len() {
                        black_box(reader.quad_owned(row, limits).expect("row must decode"));
                        count += 1;
                    }
                    black_box(count)
                });
            },
        );
    }
    group.finish();

    // The owned path is the only one that admits triple terms; measure it on
    // a batch that has them so the recursive parser is covered too.
    let mut group = criterion.benchmark_group("read/owned_with_triple_terms");
    for size in SIZES {
        let batch = build_batch(&sample_quads(size, 4), false);
        group.throughput(Throughput::Elements(u64::try_from(size).unwrap_or(0)));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &batch,
            |bencher, batch| {
                let reader = QuadStreamReader::new(batch).expect("contract must hold");
                let limits = QuadLimits::default();
                bencher.iter(|| {
                    let mut count = 0usize;
                    for item in reader.iter_owned(limits) {
                        black_box(item.expect("row must decode"));
                        count += 1;
                    }
                    black_box(count)
                });
            },
        );
    }
    group.finish();
}

fn bench_contains_triple_terms(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("read/contains_triple_terms");
    for size in SIZES {
        let clean = build_batch(&sample_quads(size, 0), false);
        let annotated = build_batch(&sample_quads(size, 4), false);
        group.throughput(Throughput::Elements(u64::try_from(size).unwrap_or(0)));
        group.bench_with_input(
            BenchmarkId::new("absent", size),
            &clean,
            |bencher, batch| {
                let reader = QuadStreamReader::new(batch).expect("contract must hold");
                bencher.iter(|| black_box(reader.contains_triple_terms()));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("present", size),
            &annotated,
            |bencher, batch| {
                let reader = QuadStreamReader::new(batch).expect("contract must hold");
                bencher.iter(|| black_box(reader.contains_triple_terms()));
            },
        );
    }
    group.finish();
}

fn bench_ipc(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("ipc");
    for size in SIZES {
        let batch = build_batch(&sample_quads(size, 0), true);
        let encoded = write_ipc_stream(std::slice::from_ref(&batch), DEFAULT_MAX_IPC_BYTES)
            .expect("write must succeed");
        group.throughput(Throughput::Elements(u64::try_from(size).unwrap_or(0)));
        group.bench_with_input(BenchmarkId::new("write", size), &batch, |bencher, batch| {
            bencher.iter(|| {
                black_box(
                    write_ipc_stream(std::slice::from_ref(batch), DEFAULT_MAX_IPC_BYTES)
                        .expect("write must succeed"),
                )
            });
        });
        group.bench_with_input(
            BenchmarkId::new("read", size),
            &encoded,
            |bencher, bytes| {
                bencher.iter(|| black_box(read_ipc_stream(bytes).expect("read must succeed")));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("round_trip", size),
            &batch,
            |bencher, batch| {
                bencher.iter(|| {
                    let bytes =
                        write_ipc_stream(std::slice::from_ref(batch), DEFAULT_MAX_IPC_BYTES)
                            .expect("write must succeed");
                    black_box(read_ipc_stream(&bytes).expect("read must succeed"))
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_push,
    bench_finish,
    bench_read_paths,
    bench_contains_triple_terms,
    bench_ipc
);
criterion_main!(benches);
