// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Named hostile inputs for the Jelly stream and patch decoders.
//!
//! Every shape runs under a 1 GiB live-allocation cap, and the recursion
//! shapes run on a 256 KiB thread, so an unbounded decoder aborts the test
//! binary instead of exhausting the machine.

#[path = "../../tools/mutation_smoke.rs"]
mod smoke;

#[global_allocator]
static ALLOCATOR: smoke::CappedAllocator = smoke::CappedAllocator;

use jelly_fast_core::{
    JellyDecoder, JellyDecoderOptions, JellyError, JellyPatchDecoder, JellyPatchDecoderOptions,
    PATCH_PROTOCOL_VERSION, PROTOCOL_VERSION,
    proto::{
        LogicalStreamType, PhysicalStreamType, RdfDefaultGraph, RdfIri, RdfNameEntry,
        RdfPrefixEntry, RdfQuad, RdfStreamFrame, RdfStreamOptions, RdfStreamRow, RdfTriple,
        patch::{
            PatchStatementType, PatchStreamType, RdfPatchFrame, RdfPatchOptions, RdfPatchRow,
            rdf_patch_row,
        },
        rdf_quad, rdf_stream_row, rdf_triple,
    },
};
use prost::Message;

fn stream_options(prefix: u32, name: u32, datatype: u32, rdf_star: bool) -> RdfStreamOptions {
    RdfStreamOptions {
        stream_name: String::new(),
        physical_type: PhysicalStreamType::Quads.into(),
        generalized_statements: false,
        rdf_star,
        max_name_table_size: name,
        max_prefix_table_size: prefix,
        max_datatype_table_size: datatype,
        logical_type: LogicalStreamType::FlatQuads.into(),
        version: PROTOCOL_VERSION,
    }
}

fn row(row: rdf_stream_row::Row) -> RdfStreamRow {
    RdfStreamRow { row: Some(row) }
}

fn frame(rows: Vec<RdfStreamRow>) -> RdfStreamFrame {
    RdfStreamFrame {
        rows,
        metadata: std::collections::HashMap::new(),
    }
}

fn iri(prefix_id: u32, name_id: u32) -> RdfIri {
    RdfIri { prefix_id, name_id }
}

fn permissive_options() -> JellyDecoderOptions {
    JellyDecoderOptions {
        max_prefix_table_size: u32::MAX,
        max_name_table_size: u32::MAX,
        max_datatype_table_size: u32::MAX,
        ..JellyDecoderOptions::default()
    }
}

/// A decoder configured to accept any table size must still not allocate
/// the declared size before a single entry arrives.
#[test]
fn declared_table_sizes_allocate_only_what_arrives() {
    let _serial = smoke::measure_alone();
    let options = stream_options(u32::MAX, u32::MAX, u32::MAX, false);
    let hostile = frame(vec![
        row(rdf_stream_row::Row::Options(options)),
        row(rdf_stream_row::Row::Name(RdfNameEntry {
            id: u32::MAX,
            value: "x".into(),
        })),
        row(rdf_stream_row::Row::Prefix(RdfPrefixEntry {
            id: u32::MAX,
            value: "http://e/".into(),
        })),
    ]);
    let before = smoke::total_allocated();
    let result = JellyDecoder::new(permissive_options()).decode_frame(&hostile);
    let spent = smoke::total_allocated().saturating_sub(before);
    // Either a typed refusal or an empty batch; never a 100 GB allocation.
    assert!(
        result.is_err() || result.as_ref().is_ok_and(|batch| batch.num_rows() == 0),
        "{result:?}"
    );
    assert!(spent < 64 << 20, "decoder allocated {spent} bytes");
}

/// The same for the patch decoder.
#[test]
fn patch_declared_table_sizes_allocate_only_what_arrives() {
    let _serial = smoke::measure_alone();
    let options = RdfPatchOptions {
        statement_type: PatchStatementType::Quads.into(),
        stream_type: PatchStreamType::Flat.into(),
        generalized_statements: false,
        rdf_star: false,
        max_name_table_size: u32::MAX,
        max_prefix_table_size: u32::MAX,
        max_datatype_table_size: u32::MAX,
        version: PATCH_PROTOCOL_VERSION,
    };
    let hostile = RdfPatchFrame {
        rows: vec![RdfPatchRow {
            row: Some(rdf_patch_row::Row::Options(options)),
        }],
    };
    let decoder_options = JellyPatchDecoderOptions {
        max_prefix_table_size: u32::MAX,
        max_name_table_size: u32::MAX,
        max_datatype_table_size: u32::MAX,
        ..JellyPatchDecoderOptions::default()
    };
    let before = smoke::total_allocated();
    let result = JellyPatchDecoder::new(decoder_options).decode_frame(&hostile);
    let spent = smoke::total_allocated().saturating_sub(before);
    assert!(result.is_ok(), "{result:?}");
    assert!(spent < 64 << 20, "decoder allocated {spent} bytes");
}

/// Ten thousand tiny frames, each re-declaring the largest tables: only
/// the first options row is accepted and live memory stays flat.
///
/// Each refused frame still allocates (and frees) an empty batch builder,
/// about 300 KiB of untouched capacity, so the bound is on live bytes.
#[test]
fn many_tiny_frames_redeclaring_tables_are_refused() {
    let _serial = smoke::measure_alone();
    let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
    let options = stream_options(128, 4000, 32, false);
    let first = decoder.decode_frame(&frame(vec![row(rdf_stream_row::Row::Options(
        options.clone(),
    ))]));
    assert!(first.is_ok(), "{first:?}");
    let before = smoke::live_allocated();
    let mut peak = before;
    for _ in 0..10_000 {
        let again = decoder.decode_frame(&frame(vec![row(rdf_stream_row::Row::Options(
            options.clone(),
        ))]));
        assert!(matches!(again, Err(JellyError::Options(_))), "{again:?}");
        peak = peak.max(smoke::live_allocated());
    }
    let grown = peak.saturating_sub(before);
    assert!(
        grown < 64 << 20,
        "re-declarations grew live memory by {grown} bytes"
    );
}

/// Lookup references out of range, or to identifiers never assigned.
#[test]
fn lookup_misses_fail_closed() {
    let _serial = smoke::measure_alone();
    for (prefix_id, name_id) in [(0, 9), (200, 1), (1, 4001), (1, u32::MAX), (2, 1)] {
        let hostile = frame(vec![
            row(rdf_stream_row::Row::Options(stream_options(
                128, 4000, 32, false,
            ))),
            row(rdf_stream_row::Row::Prefix(RdfPrefixEntry {
                id: 1,
                value: "http://e/".into(),
            })),
            row(rdf_stream_row::Row::Name(RdfNameEntry {
                id: 1,
                value: "x".into(),
            })),
            row(rdf_stream_row::Row::Quad(RdfQuad {
                subject: Some(rdf_quad::Subject::SIri(iri(prefix_id, name_id))),
                predicate: Some(rdf_quad::Predicate::PIri(iri(1, 1))),
                object: Some(rdf_quad::Object::OIri(iri(1, 1))),
                graph: Some(rdf_quad::Graph::GDefaultGraph(RdfDefaultGraph {})),
            })),
        ]);
        let result = JellyDecoder::new(JellyDecoderOptions::default()).decode_frame(&hostile);
        assert!(
            matches!(result, Err(JellyError::Lookup(_))),
            "({prefix_id}, {name_id}): {result:?}"
        );
    }
}

fn nested_triple_bytes(depth: usize) -> Vec<u8> {
    // Builds the protobuf bytes of a quad row whose object nests `depth`
    // triple terms, by hand, so the builder itself never recurses.
    let leaf = RdfTriple {
        subject: Some(rdf_triple::Subject::SIri(iri(1, 1))),
        predicate: Some(rdf_triple::Predicate::PIri(iri(1, 1))),
        object: Some(rdf_triple::Object::OIri(iri(1, 1))),
    }
    .encode_to_vec();
    let head = RdfTriple {
        subject: Some(rdf_triple::Subject::SIri(iri(1, 1))),
        predicate: Some(rdf_triple::Predicate::PIri(iri(1, 1))),
        object: None,
    }
    .encode_to_vec();
    let mut triple = leaf;
    for _ in 1..depth {
        // RdfTriple.o_triple_term is field 12 (wire type 2).
        let mut next = head.clone();
        prost::encoding::encode_key(12, prost::encoding::WireType::LengthDelimited, &mut next);
        prost::encoding::encode_varint(triple.len() as u64, &mut next);
        next.extend_from_slice(&triple);
        triple = next;
    }
    let mut quad = RdfQuad {
        subject: Some(rdf_quad::Subject::SIri(iri(1, 1))),
        predicate: Some(rdf_quad::Predicate::PIri(iri(1, 1))),
        object: None,
        graph: Some(rdf_quad::Graph::GDefaultGraph(RdfDefaultGraph {})),
    }
    .encode_to_vec();
    // RdfQuad.o_triple_term is field 12 as well.
    prost::encoding::encode_key(12, prost::encoding::WireType::LengthDelimited, &mut quad);
    prost::encoding::encode_varint(quad_len(&triple), &mut quad);
    quad.extend_from_slice(&triple);
    let mut out = frame(vec![
        row(rdf_stream_row::Row::Options(stream_options(
            128, 4000, 32, true,
        ))),
        row(rdf_stream_row::Row::Prefix(RdfPrefixEntry {
            id: 1,
            value: "http://e/".into(),
        })),
        row(rdf_stream_row::Row::Name(RdfNameEntry {
            id: 1,
            value: "x".into(),
        })),
    ])
    .encode_to_vec();
    // RdfStreamRow.quad is field 3; RdfStreamFrame.rows is field 1.
    let mut row_bytes = Vec::new();
    prost::encoding::encode_key(
        3,
        prost::encoding::WireType::LengthDelimited,
        &mut row_bytes,
    );
    prost::encoding::encode_varint(quad.len() as u64, &mut row_bytes);
    row_bytes.extend_from_slice(&quad);
    prost::encoding::encode_key(1, prost::encoding::WireType::LengthDelimited, &mut out);
    prost::encoding::encode_varint(row_bytes.len() as u64, &mut out);
    out.extend_from_slice(&row_bytes);
    out
}

fn quad_len(bytes: &[u8]) -> u64 {
    bytes.len() as u64
}

/// Deeply nested quoted triples: prost's recursion limit and the decoder's
/// `max_quoted_depth` must both hold on a 256 KiB debug-build stack.
#[test]
fn nested_quoted_triples_fail_closed_on_a_small_stack() {
    let _serial = smoke::measure_alone();
    smoke::run_on_small_stack(|| {
        for depth in [5, 8, 9, 50, 99, 100, 101, 10_000] {
            let bytes = nested_triple_bytes(depth);
            let decoded = RdfStreamFrame::decode(bytes.as_slice());
            let Ok(decoded) = decoded else {
                assert!(depth >= 99, "depth {depth} refused by prost");
                continue;
            };
            let result = JellyDecoder::new(JellyDecoderOptions::default()).decode_frame(&decoded);
            if depth <= 8 {
                assert!(result.is_ok(), "depth {depth}: {result:?}");
            } else {
                assert!(
                    matches!(result, Err(JellyError::ResourceLimit { .. })),
                    "depth {depth}: {result:?}"
                );
            }
        }
    });
}

/// A frame of half a million empty rows (1 MB on the wire).
///
/// Reports how much memory prost materializes; the decoder must refuse the
/// payload-less rows with a typed error.
#[test]
fn empty_rows_are_refused() {
    let _serial = smoke::measure_alone();
    let mut bytes = Vec::with_capacity(1_000_000);
    for _ in 0..500_000 {
        bytes.extend_from_slice(&[0x0a, 0x00]);
    }
    let decoded = RdfStreamFrame::decode(bytes.as_slice()).expect("prost accepts empty rows");
    let result = JellyDecoder::new(JellyDecoderOptions::default()).decode_frame(&decoded);
    assert!(result.is_err(), "{result:?}");
}

/// Alternating add and delete rows: every run becomes its own batch.
///
/// 20,000 rows of about six bytes each must not materialize tens of
/// thousands of Arrow batches without a per-frame bound.
#[test]
fn alternating_patch_runs_are_bounded() {
    let _serial = smoke::measure_alone();
    let options = RdfPatchOptions {
        statement_type: PatchStatementType::Quads.into(),
        stream_type: PatchStreamType::Flat.into(),
        generalized_statements: false,
        rdf_star: false,
        max_name_table_size: 4000,
        max_prefix_table_size: 128,
        max_datatype_table_size: 32,
        version: PATCH_PROTOCOL_VERSION,
    };
    let quad = RdfQuad {
        subject: Some(rdf_quad::Subject::SIri(iri(1, 1))),
        predicate: Some(rdf_quad::Predicate::PIri(iri(1, 1))),
        object: Some(rdf_quad::Object::OIri(iri(1, 1))),
        graph: Some(rdf_quad::Graph::GDefaultGraph(RdfDefaultGraph {})),
    };
    let mut rows = vec![
        RdfPatchRow {
            row: Some(rdf_patch_row::Row::Options(options)),
        },
        RdfPatchRow {
            row: Some(rdf_patch_row::Row::Prefix(RdfPrefixEntry {
                id: 1,
                value: "http://e/".into(),
            })),
        },
        RdfPatchRow {
            row: Some(rdf_patch_row::Row::Name(RdfNameEntry {
                id: 1,
                value: "x".into(),
            })),
        },
        RdfPatchRow {
            row: Some(rdf_patch_row::Row::StatementAdd(quad)),
        },
    ];
    for index in 0..20_000 {
        let empty = RdfQuad::default();
        rows.push(RdfPatchRow {
            row: Some(if index % 2 == 0 {
                rdf_patch_row::Row::StatementDelete(empty)
            } else {
                rdf_patch_row::Row::StatementAdd(empty)
            }),
        });
    }
    let hostile = RdfPatchFrame { rows };
    let wire = hostile.encode_to_vec().len();
    let before = smoke::total_allocated();
    let result = JellyPatchDecoder::new(JellyPatchDecoderOptions::default()).decode_frame(&hostile);
    let spent = smoke::total_allocated().saturating_sub(before);
    let ops = result.as_ref().map_or(0, Vec::len);
    eprintln!("alternating runs: {wire} wire bytes, {ops} ops, {spent} bytes allocated");
    assert!(
        matches!(&result, Err(JellyError::ResourceLimit { resource, .. }) if resource.as_str() == "patch_ops"),
        "{ops} ops from {wire} wire bytes allocated {spent} bytes"
    );
}
