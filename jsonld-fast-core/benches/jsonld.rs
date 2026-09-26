// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Criterion benchmarks for the JSON-LD hot paths (task-graph N12).
//!
//! Five paths are measured over inputs that look like real documents, not
//! degenerate one-entry cases: expansion, `toRdf` into an
//! `UnsignedQuadStream` batch, `fromRdf` back out, compaction against a
//! non-trivial inverse context, and framing.
//!
//! Expansion, `toRdf`, `fromRdf`, and compaction are swept over node count
//! (16 / 64 / 256 / 1024 nodes) so a future regression shows up as a change
//! of *slope*, not just a change of number: a per-node cost that turns
//! quadratic is visible in the sweep long before it is visible in any single
//! measurement.
//!
//! One further document, [`scoped_document`], exercises the paths the crate
//! documents as expensive — type-scoped and property-scoped contexts with
//! `@propagate`, and the `@index`/`@id`/`@type`/`@graph` container maps —
//! because those re-process a context per node instead of once per
//! document.
//!
//! Every input is built *outside* the timed closure; the closures do
//! nothing but call the API under test.

use std::hint::black_box;

use arrow_array::RecordBatch;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use jsonld_fast_core::{JsonLdOptions, compact, expand, frame, from_quads, to_quads};
use serde_json::{Map, Number, Value};

/// Node counts swept by every size-sensitive benchmark.
const SIZES: &[usize] = &[16, 64, 256, 1024];

/// Builds a JSON object from key/value pairs.
fn object(pairs: Vec<(String, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key, value);
    }
    Value::Object(map)
}

/// Builds a JSON string value.
fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

/// A context with the term-definition variety real vocabularies have.
///
/// Prefixes, type coercions (`@id`, `@vocab`, a datatype IRI), a language
/// mapping, `@set`/`@list`/`@index` containers, and a `@reverse` term — so
/// inverse-context construction and term selection both have real work.
fn rich_context() -> Value {
    object(vec![
        ("schema".to_owned(), text("http://schema.org/")),
        ("xsd".to_owned(), text("http://www.w3.org/2001/XMLSchema#")),
        ("name".to_owned(), text("http://schema.org/name")),
        (
            "label".to_owned(),
            object(vec![
                (
                    "@id".to_owned(),
                    text("http://www.w3.org/2000/01/rdf-schema#label"),
                ),
                ("@language".to_owned(), text("en")),
            ]),
        ),
        (
            "homepage".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://schema.org/url")),
                ("@type".to_owned(), text("@id")),
            ]),
        ),
        (
            "knows".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://schema.org/knows")),
                ("@type".to_owned(), text("@id")),
                ("@container".to_owned(), text("@set")),
            ]),
        ),
        (
            "age".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://schema.org/age")),
                (
                    "@type".to_owned(),
                    text("http://www.w3.org/2001/XMLSchema#integer"),
                ),
            ]),
        ),
        (
            "keywords".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://schema.org/keywords")),
                ("@container".to_owned(), text("@list")),
            ]),
        ),
        (
            "byIndex".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://example.com/byIndex")),
                ("@container".to_owned(), text("@index")),
            ]),
        ),
        (
            "employees".to_owned(),
            object(vec![
                ("@reverse".to_owned(), text("http://schema.org/worksFor")),
                ("@container".to_owned(), text("@set")),
            ]),
        ),
    ])
}

/// A document of `nodes` interlinked people under [`rich_context`].
///
/// Each node carries a type, a plain literal, a language literal, a typed
/// integer, an IRI-coerced reference, a `@set` of references, a `@list`, and
/// an `@index` map — the mix a real record has, so no single code path
/// dominates the measurement.
fn people_document(nodes: usize) -> Value {
    let mut graph = Vec::with_capacity(nodes);
    for index in 0..nodes {
        let next = (index + 1) % nodes.max(1);
        graph.push(object(vec![
            (
                "@id".to_owned(),
                text(&format!("http://example.com/person/{index}")),
            ),
            ("@type".to_owned(), text("schema:Person")),
            ("name".to_owned(), text(&format!("Person {index}"))),
            ("label".to_owned(), text(&format!("person number {index}"))),
            (
                "age".to_owned(),
                Value::Number(Number::from(20 + (index % 50))),
            ),
            (
                "homepage".to_owned(),
                text(&format!("http://example.com/person/{index}/home")),
            ),
            (
                "knows".to_owned(),
                Value::Array(vec![
                    text(&format!("http://example.com/person/{next}")),
                    text(&format!(
                        "http://example.com/person/{}",
                        (index + 2) % nodes.max(1)
                    )),
                ]),
            ),
            (
                "keywords".to_owned(),
                Value::Array(vec![text("alpha"), text("beta"), text("gamma")]),
            ),
            (
                "byIndex".to_owned(),
                object(vec![
                    ("primary".to_owned(), text(&format!("value {index}"))),
                    ("secondary".to_owned(), text("shared")),
                ]),
            ),
        ]));
    }
    object(vec![
        ("@context".to_owned(), rich_context()),
        ("@graph".to_owned(), Value::Array(graph)),
    ])
}

/// A document built entirely from the paths the crate calls expensive.
///
/// A type-scoped context (re-processed on every node of that type), a
/// property-scoped context with `@propagate: false`, and all four container
/// maps: `@index`, `@id`, `@type`, and `@graph`.
fn scoped_document(nodes: usize) -> Value {
    let scoped_context = object(vec![
        (
            "detail".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://example.com/detail")),
                ("@container".to_owned(), text("@index")),
            ]),
        ),
        (
            "byId".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://example.com/byId")),
                ("@container".to_owned(), text("@id")),
            ]),
        ),
    ]);
    let context = object(vec![
        (
            "@version".to_owned(),
            Number::from_f64(1.1).map_or(Value::Null, Value::Number),
        ),
        ("ex".to_owned(), text("http://example.com/")),
        (
            "Record".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://example.com/Record")),
                // Type-scoped: re-processed for every node of this type.
                ("@context".to_owned(), scoped_context),
            ]),
        ),
        (
            "payload".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://example.com/payload")),
                // Property-scoped, non-propagating: reverts on every node.
                (
                    "@context".to_owned(),
                    object(vec![
                        ("@propagate".to_owned(), Value::Bool(false)),
                        ("inner".to_owned(), text("http://example.com/inner")),
                    ]),
                ),
            ]),
        ),
        (
            "byType".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://example.com/byType")),
                ("@container".to_owned(), text("@type")),
            ]),
        ),
        (
            "graphs".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://example.com/graphs")),
                (
                    "@container".to_owned(),
                    Value::Array(vec![text("@graph"), text("@id")]),
                ),
            ]),
        ),
    ]);
    let mut graph = Vec::with_capacity(nodes);
    for index in 0..nodes {
        graph.push(object(vec![
            (
                "@id".to_owned(),
                text(&format!("http://example.com/record/{index}")),
            ),
            ("@type".to_owned(), text("Record")),
            (
                "detail".to_owned(),
                object(vec![
                    ("first".to_owned(), text(&format!("detail {index}"))),
                    ("second".to_owned(), text("shared detail")),
                ]),
            ),
            (
                "byId".to_owned(),
                object(vec![(
                    format!("http://example.com/keyed/{index}"),
                    object(vec![("ex:note".to_owned(), text("keyed"))]),
                )]),
            ),
            (
                "byType".to_owned(),
                object(vec![(
                    "http://example.com/Kind".to_owned(),
                    object(vec![("ex:note".to_owned(), text("typed"))]),
                )]),
            ),
            (
                "graphs".to_owned(),
                object(vec![(
                    format!("http://example.com/graph/{index}"),
                    object(vec![
                        (
                            "@id".to_owned(),
                            text(&format!("http://example.com/inGraph/{index}")),
                        ),
                        ("ex:note".to_owned(), text("in a named graph")),
                    ]),
                )]),
            ),
            (
                "payload".to_owned(),
                object(vec![
                    (
                        "@id".to_owned(),
                        text(&format!("http://example.com/payload/{index}")),
                    ),
                    ("inner".to_owned(), text("scoped inner value")),
                ]),
            ),
        ]));
    }
    object(vec![
        ("@context".to_owned(), context),
        ("@graph".to_owned(), Value::Array(graph)),
    ])
}

/// Expansion over the representative document, swept by node count.
fn bench_expand(criterion: &mut Criterion) {
    let options = JsonLdOptions::default();
    let mut group = criterion.benchmark_group("expand");
    for &size in SIZES {
        let document = people_document(size);
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &document,
            |bencher, doc| {
                bencher.iter(|| expand(black_box(doc), black_box(&options)).expect("expands"));
            },
        );
    }
    group.finish();
}

/// `toRdf`: expansion plus quad emission into an `UnsignedQuadStream` batch.
fn bench_to_quads(criterion: &mut Criterion) {
    let options = JsonLdOptions::default();
    let mut group = criterion.benchmark_group("to_rdf");
    for &size in SIZES {
        let document = people_document(size);
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &document,
            |bencher, doc| {
                bencher.iter(|| {
                    to_quads(black_box(doc), black_box(&options), None).expect("deserializes")
                });
            },
        );
    }
    group.finish();
}

/// `fromRdf`: quad batches back to an expanded document.
fn bench_from_quads(criterion: &mut Criterion) {
    let options = JsonLdOptions::default();
    let mut group = criterion.benchmark_group("from_rdf");
    for &size in SIZES {
        let batches: Vec<RecordBatch> =
            to_quads(&people_document(size), &options, None).expect("deserializes");
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &batches,
            |bencher, input| {
                bencher.iter(|| from_quads(black_box(input)).expect("serializes"));
            },
        );
    }
    group.finish();
}

/// Compaction against the non-trivial inverse context of [`rich_context`].
fn bench_compact(criterion: &mut Criterion) {
    let options = JsonLdOptions::default();
    let context = rich_context();
    let mut group = criterion.benchmark_group("compact");
    for &size in SIZES {
        // Compaction is measured over *expanded* input, so the sweep times
        // compaction rather than the expansion that precedes it.
        let expanded = expand(&people_document(size), &options).expect("expands");
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &expanded,
            |bencher, doc| {
                bencher.iter(|| {
                    compact(black_box(doc), black_box(&context), black_box(&options))
                        .expect("compacts")
                });
            },
        );
    }
    group.finish();
}

/// Framing: node-map generation, matching, embedding, and output compaction.
fn bench_frame(criterion: &mut Criterion) {
    let options = JsonLdOptions::default();
    let frame_value = object(vec![
        ("@context".to_owned(), rich_context()),
        ("@type".to_owned(), text("schema:Person")),
        (
            "knows".to_owned(),
            object(vec![("@embed".to_owned(), text("@once"))]),
        ),
    ]);
    let mut group = criterion.benchmark_group("frame");
    for &size in SIZES {
        let document = people_document(size);
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &document,
            |bencher, doc| {
                bencher.iter(|| {
                    frame(black_box(doc), black_box(&frame_value), black_box(&options))
                        .expect("frames")
                });
            },
        );
    }
    group.finish();
}

/// The scoped-context and container-map paths, expansion and `toRdf`.
///
/// Separate from the sweeps above because these paths re-process a context
/// per node: their cost per node is the number worth watching.
fn bench_scoped_and_containers(criterion: &mut Criterion) {
    let options = JsonLdOptions::default();
    let mut group = criterion.benchmark_group("scoped_contexts_and_container_maps");
    for &size in SIZES {
        let document = scoped_document(size);
        group.bench_with_input(
            BenchmarkId::new("expand", size),
            &document,
            |bencher, doc| {
                bencher.iter(|| expand(black_box(doc), black_box(&options)).expect("expands"));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("to_rdf", size),
            &document,
            |bencher, doc| {
                bencher.iter(|| {
                    to_quads(black_box(doc), black_box(&options), None).expect("deserializes")
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    jsonld,
    bench_expand,
    bench_to_quads,
    bench_from_quads,
    bench_compact,
    bench_frame,
    bench_scoped_and_containers
);
criterion_main!(jsonld);
