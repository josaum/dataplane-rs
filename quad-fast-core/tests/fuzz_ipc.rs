// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Deterministic, seeded fuzzing of the Arrow IPC / contract read path.
//!
//! `read_ipc_stream` plus [`QuadStreamReader`] is the crate's whole foreign
//! input surface: a Flight `DoPut` body, a gRPC frame, or a file on disk
//! reaches the term model through exactly these two calls. Everything an
//! attacker controls is a byte in that payload.
//!
//! Invariants asserted here:
//!
//! 1. **Never panic.** Corrupted IPC must produce a typed [`QuadError`].
//!    Arrow's decoder panics freely on malformed input, so the crate wraps it
//!    in a barrier; this harness proves the barrier holds by catching a panic
//!    itself and failing with the reproducing seed.
//! 2. **Never hang or exhaust.** A small payload must not drive a large
//!    allocation: every declared length is bounded by the bytes present
//!    *before* any array data is touched. Asserted by a wall-clock budget
//!    over payloads whose length fields have been set to `u32::MAX`.
//! 3. **Round-trip.** `read(write(batch))` returns the same quads and the
//!    same provenance, for randomly generated batches.
//! 4. **Idempotent refusal.** A rejected payload is rejected identically
//!    every time — same error code, same message.
//! 5. **No silent mutation.** A successful decode invents nothing and drops
//!    nothing: every quad, every provenance field, and the contract metadata
//!    are compared exactly.
//!
//! Iteration counts are named at each loop and sized to keep the file to a
//! few seconds in a debug build.

mod support;

use std::{
    sync::{Arc, Once},
    time::{Duration, Instant},
};

use arrow_array::{
    ArrayRef, RecordBatch,
    builder::{
        FixedSizeBinaryBuilder, StringBuilder, StringDictionaryBuilder,
        TimestampMicrosecondBuilder, UInt64Builder,
    },
    types::UInt32Type,
};
use arrow_ipc::writer::StreamWriter;
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use oxrdf::Quad;
use quad_fast_core::{
    DEFAULT_MAX_IPC_BYTES, FEATURE_BASE_DIRECTION, QuadBatchBuilder, QuadError, QuadLimits,
    QuadStreamReader, SourceProvenance, quad_stream_schema, read_ipc_stream, write_ipc_stream,
};
use support::{BOUNDARY_U32, Rng, random_provenance, random_quad};

/// Master seed. Constant on purpose: the suite must be reproducible.
const MASTER_SEED: u64 = 0x1BC0_DE5E_ED00_0001;

/// Wall-clock budget for one decode attempt.
const DECODE_BUDGET: Duration = Duration::from_secs(2);

/// Silences panics raised *inside* the arrow crates.
///
/// `read_ipc_stream` catches those panics and returns a typed error, but the
/// panic hook still runs first and would print thousands of backtraces during
/// a fuzz run. Panics from anywhere else — this file's assertions included —
/// keep the default hook, so a real failure still prints in full. Installed
/// once; this binary contains only fuzz tests.
fn silence_arrow_panics() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let inside_arrow = info.location().is_some_and(|location| {
                let file = location.file();
                [
                    "arrow-buffer",
                    "arrow-data",
                    "arrow-ipc",
                    "arrow-array",
                    "arrow-schema",
                ]
                .iter()
                .any(|crate_dir| file.contains(crate_dir))
            });
            if !inside_arrow {
                default(info);
            }
        }));
    });
}

/// Everything the read path can be asked to do with one payload.
///
/// Exercising only `read_ipc_stream` would miss the row decoders, which are
/// where the term validation lives.
fn read_everything(bytes: &[u8]) -> Result<usize, QuadError> {
    let batches = read_ipc_stream(bytes)?;
    let mut rows = 0usize;
    for batch in &batches {
        let reader = QuadStreamReader::new(batch)?;
        let _scan = reader.contains_triple_terms();
        for row in 0..reader.len() {
            let _borrowed = reader.quad(row);
            let _owned = reader.quad_owned(row, QuadLimits::default());
            let _provenance = reader.provenance(row);
            rows += 1;
        }
        for item in reader.iter() {
            let _ = item;
        }
        for item in reader.iter_owned(QuadLimits::default()) {
            let _ = item;
        }
    }
    Ok(rows)
}

/// Reads twice, asserting no panic (1), a bounded runtime (2), and an
/// identical outcome both times (4).
fn read_idempotently(seed: u64, bytes: &[u8]) -> Result<usize, QuadError> {
    let started = Instant::now();
    let first = match std::panic::catch_unwind(|| read_everything(bytes)) {
        Ok(result) => result,
        Err(_payload) => panic!(
            "PANIC escaped the IPC read path.\n  seed = {seed:#018x}\n  len = {}\n  \
             prefix = {:02x?}",
            bytes.len(),
            &bytes[..bytes.len().min(64)]
        ),
    };
    let elapsed = started.elapsed();
    assert!(
        elapsed < DECODE_BUDGET,
        "decoding a {}-byte payload took {elapsed:?}; work is not bounded by input size.\n  \
         seed = {seed:#018x}",
        bytes.len()
    );
    let second = match std::panic::catch_unwind(|| read_everything(bytes)) {
        Ok(result) => result,
        Err(_payload) => panic!(
            "PANIC on the second read of a payload the first read survived.\n  \
             seed = {seed:#018x}"
        ),
    };
    match (&first, &second) {
        (Ok(left), Ok(right)) => assert_eq!(
            left, right,
            "non-deterministic accept.\n  seed = {seed:#018x}"
        ),
        (Err(left), Err(right)) => {
            assert_eq!(
                left.code(),
                right.code(),
                "non-deterministic refusal code.\n  seed = {seed:#018x}"
            );
            assert_eq!(
                left.to_string(),
                right.to_string(),
                "non-deterministic refusal message.\n  seed = {seed:#018x}"
            );
        }
        _ => panic!("same payload both accepted and refused.\n  seed = {seed:#018x}"),
    }
    first
}

/// Builds a representative batch: repeated dictionary values, triple terms,
/// boundary-valued provenance, and default/named/blank graphs.
///
/// Returns the quads that were actually accepted, so the round-trip check
/// compares against what the builder took, not what the generator offered.
fn random_batch(
    rng: &mut Rng,
    rows: usize,
) -> (RecordBatch, Vec<(Quad, Option<SourceProvenance>)>) {
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    let mut accepted = Vec::with_capacity(rows);
    for _ in 0..rows {
        let quad = random_quad(rng, 3);
        let provenance = random_provenance(rng);
        match builder.push(quad.as_ref(), provenance.as_ref()) {
            Ok(()) => accepted.push((quad, provenance)),
            Err(QuadError::Unsupported { feature, .. }) => {
                // The only refusal the generator can provoke: an RDF 1.2
                // directional literal in the top-level object position has no
                // column to live in, so it is refused rather than flattened.
                assert_eq!(
                    feature, FEATURE_BASE_DIRECTION,
                    "unexpected builder refusal"
                );
            }
            Err(other) => panic!("builder refused a generated quad: {other}"),
        }
    }
    (builder.finish().expect("finish must succeed"), accepted)
}

// --- round-trip -----------------------------------------------------------

/// 400 randomly generated batches must survive write → read unchanged.
#[test]
fn random_batches_round_trip_without_mutation() {
    const CASES: u64 = 400;
    silence_arrow_panics();
    for case in 0..CASES {
        let seed = Rng::seed_for(MASTER_SEED, case);
        let mut rng = Rng::new(seed);
        let rows = rng.between(0, 24);
        let (batch, expected) = random_batch(&mut rng, rows);
        let bytes = write_ipc_stream(&[batch], DEFAULT_MAX_IPC_BYTES).expect("write must succeed");
        let decoded = read_ipc_stream(&bytes).expect("a self-written stream must read back");
        assert_eq!(decoded.len(), 1, "seed = {seed:#018x}");
        let reader = QuadStreamReader::new(&decoded[0]).expect("contract must hold");
        assert_eq!(
            reader.len(),
            expected.len(),
            "row count changed across IPC.\n  seed = {seed:#018x}"
        );
        for (row, (quad, provenance)) in expected.iter().enumerate() {
            let (decoded_quad, decoded_provenance) = reader
                .iter_owned(QuadLimits::default())
                .nth(row)
                .expect("row must exist")
                .expect("row must decode");
            assert_eq!(
                &decoded_quad, quad,
                "quad changed across IPC.\n  seed = {seed:#018x}\n  row = {row}"
            );
            let expected_provenance = provenance.clone().unwrap_or_default();
            assert_eq!(
                decoded_provenance.source_artifact_iri,
                expected_provenance.source_artifact_iri.as_deref(),
                "artifact IRI changed.\n  seed = {seed:#018x}\n  row = {row}"
            );
            assert_eq!(
                decoded_provenance.source_content_sha256,
                expected_provenance
                    .source_content_sha256
                    .as_ref()
                    .map(<[u8; 32]>::as_slice),
                "digest changed.\n  seed = {seed:#018x}\n  row = {row}"
            );
            assert_eq!(
                decoded_provenance.source_offset_start, expected_provenance.source_offset_start,
                "offset start changed.\n  seed = {seed:#018x}\n  row = {row}"
            );
            assert_eq!(
                decoded_provenance.source_offset_end, expected_provenance.source_offset_end,
                "offset end changed.\n  seed = {seed:#018x}\n  row = {row}"
            );
            assert_eq!(
                decoded_provenance.observed_at_micros, expected_provenance.observed_at_micros,
                "timestamp changed.\n  seed = {seed:#018x}\n  row = {row}"
            );
        }
    }
}

// --- dumb generator: arbitrary bytes --------------------------------------

/// 1 500 unstructured payloads, some carrying a valid stream prefix.
#[test]
fn arbitrary_bytes_never_panic() {
    const CASES: u64 = 1_500;
    silence_arrow_panics();
    let mut rng_seed = Rng::new(MASTER_SEED ^ 0xD0D0);
    let valid = valid_stream(&mut rng_seed, 8);
    for case in 0..CASES {
        let seed = Rng::seed_for(MASTER_SEED ^ 0xD0D0, case);
        let mut rng = Rng::new(seed);
        let mut bytes = Vec::new();
        if rng.chance(3) {
            let prefix = rng.below(valid.len().min(96) + 1);
            bytes.extend_from_slice(&valid[..prefix]);
        }
        let extra = rng.between(0, 192);
        for _ in 0..extra {
            bytes.push(if rng.chance(4) { 0xFF } else { rng.byte() });
        }
        let decoded = read_idempotently(seed, &bytes);
        assert!(
            decoded.is_err() || bytes.is_empty(),
            "unstructured bytes decoded as a contract stream.\n  seed = {seed:#018x}"
        );
    }
}

// --- structure-aware generator --------------------------------------------

fn valid_stream(rng: &mut Rng, rows: usize) -> Vec<u8> {
    let (batch, _accepted) = random_batch(rng, rows);
    write_ipc_stream(&[batch], DEFAULT_MAX_IPC_BYTES).expect("write must succeed")
}

/// Corruptions aimed at the encapsulated-message framing.
#[derive(Clone, Copy, Debug)]
enum Corruption {
    /// Flip one bit anywhere.
    BitFlip,
    /// Overwrite a little-endian `u32` with a boundary value: this is what
    /// turns a metadata or continuation field into a hostile length.
    LengthField,
    /// Overwrite eight bytes with an `i64` boundary: the `bodyLength` field.
    BodyLength,
    /// Cut the payload short.
    Truncate,
    /// Splice a run of bytes over itself (duplicated ids, repeated frames).
    Duplicate,
    /// Zero a run — a very common real-world corruption.
    ZeroRun,
    /// Insert random bytes in the middle, shifting every later offset.
    Insert,
}

const CORRUPTIONS: [Corruption; 7] = [
    Corruption::BitFlip,
    Corruption::LengthField,
    Corruption::BodyLength,
    Corruption::Truncate,
    Corruption::Duplicate,
    Corruption::ZeroRun,
    Corruption::Insert,
];

fn corrupt(rng: &mut Rng, kind: Corruption, base: &[u8]) -> Vec<u8> {
    let mut bytes = base.to_vec();
    if bytes.is_empty() {
        return bytes;
    }
    match kind {
        Corruption::BitFlip => {
            let flips = rng.between(1, 6);
            for _ in 0..flips {
                let index = rng.below(bytes.len());
                bytes[index] ^= 1u8 << rng.below(8);
            }
        }
        Corruption::LengthField => {
            let index = rng.below(bytes.len().saturating_sub(4).max(1));
            if index + 4 <= bytes.len() {
                let value = *rng.pick(&BOUNDARY_U32);
                bytes[index..index + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        Corruption::BodyLength => {
            let index = rng.below(bytes.len().saturating_sub(8).max(1));
            if index + 8 <= bytes.len() {
                let value = *rng.pick(&[0i64, 1, -1, i64::MIN, i64::MAX, 1 << 48, 1 << 60]);
                bytes[index..index + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        Corruption::Truncate => bytes.truncate(rng.below(bytes.len())),
        Corruption::Duplicate => {
            let start = rng.below(bytes.len());
            let end = (start + rng.between(1, 32)).min(bytes.len());
            let run = bytes[start..end].to_vec();
            bytes.splice(end..end, run);
        }
        Corruption::ZeroRun => {
            let start = rng.below(bytes.len());
            let end = (start + rng.between(1, 24)).min(bytes.len());
            for slot in &mut bytes[start..end] {
                *slot = 0;
            }
        }
        Corruption::Insert => {
            let index = rng.below(bytes.len());
            let count = rng.between(1, 16);
            let noise: Vec<u8> = (0..count).map(|_| rng.byte()).collect();
            bytes.splice(index..index, noise);
        }
    }
    bytes
}

/// 700 cases x 7 corruption kinds over a real contract stream.
#[test]
fn corrupted_contract_streams_never_panic_and_refuse_idempotently() {
    const CASES: u64 = 700;
    silence_arrow_panics();
    let mut base_rng = Rng::new(MASTER_SEED ^ 0xC0DE);
    let base = valid_stream(&mut base_rng, 12);
    for case in 0..CASES {
        let seed = Rng::seed_for(MASTER_SEED ^ 0xC0DE, case);
        let mut rng = Rng::new(seed);
        let kind = *rng.pick(&CORRUPTIONS);
        let mutant = corrupt(&mut rng, kind, &base);
        if mutant == base {
            continue;
        }
        let _outcome = read_idempotently(seed, &mutant);
    }
}

/// Every truncation of a real stream, one byte at a time.
///
/// Truncation is the corruption a network actually produces, and it walks the
/// decoder through every partial state of every message.
#[test]
fn every_truncation_of_a_valid_stream_is_survivable() {
    silence_arrow_panics();
    let mut rng = Rng::new(MASTER_SEED ^ 0x7A11);
    let base = valid_stream(&mut rng, 6);
    // Every byte across the framing-dense head (schema, dictionaries, the
    // record-batch header), then every third byte through the body: the head
    // is where a partial length field changes the decoder's mind, the body is
    // long and uniform.
    let head = base.len().min(600);
    let steps = (0..head).chain((head..base.len()).step_by(3));
    for length in steps {
        let _outcome = read_idempotently(u64::try_from(length).unwrap_or(0), &base[..length]);
    }
    assert!(
        read_ipc_stream(&base).is_ok(),
        "the untruncated stream must still read"
    );
}

// --- contract violations --------------------------------------------------

/// Builds a batch under `schema` with the contract's own column values.
///
/// Returns `None` when the mutated schema cannot host those columns at all;
/// that mutation is already refused one layer lower, by Arrow.
fn batch_under(schema: Arc<Schema>) -> Option<RecordBatch> {
    let mut subject_kind = StringDictionaryBuilder::<UInt32Type>::new();
    let mut subject_value = StringDictionaryBuilder::<UInt32Type>::new();
    let mut predicate = StringDictionaryBuilder::<UInt32Type>::new();
    let mut object_kind = StringDictionaryBuilder::<UInt32Type>::new();
    let mut object_value = StringBuilder::new();
    let mut object_datatype = StringDictionaryBuilder::<UInt32Type>::new();
    let mut object_language = StringDictionaryBuilder::<UInt32Type>::new();
    let mut graph_kind = StringDictionaryBuilder::<UInt32Type>::new();
    let mut graph_value = StringDictionaryBuilder::<UInt32Type>::new();
    let mut source_artifact = StringDictionaryBuilder::<UInt32Type>::new();
    let mut source_sha256 = FixedSizeBinaryBuilder::new(32);
    let mut offset_start = UInt64Builder::new();
    let mut offset_end = UInt64Builder::new();
    let mut observed_at = TimestampMicrosecondBuilder::new().with_timezone("UTC");

    subject_kind.append_value("iri");
    subject_value.append_value("http://example.com/s");
    predicate.append_value("http://example.com/p");
    object_kind.append_value("literal");
    object_value.append_value("value");
    object_datatype.append_value("http://www.w3.org/2001/XMLSchema#string");
    object_language.append_null();
    graph_kind.append_value("default");
    graph_value.append_null();
    source_artifact.append_null();
    source_sha256.append_null();
    offset_start.append_null();
    offset_end.append_null();
    observed_at.append_null();

    let columns: Vec<ArrayRef> = vec![
        Arc::new(subject_kind.finish()),
        Arc::new(subject_value.finish()),
        Arc::new(predicate.finish()),
        Arc::new(object_kind.finish()),
        Arc::new(object_value.finish()),
        Arc::new(object_datatype.finish()),
        Arc::new(object_language.finish()),
        Arc::new(graph_kind.finish()),
        Arc::new(graph_value.finish()),
        Arc::new(source_artifact.finish()),
        Arc::new(source_sha256.finish()),
        Arc::new(offset_start.finish()),
        Arc::new(offset_end.finish()),
        Arc::new(observed_at.finish()),
    ];
    RecordBatch::try_new(schema, columns).ok()
}

/// Systematic schema mutations: renamed fields, flipped nullability, swapped
/// types, tampered metadata, reordered columns.
#[test]
fn schema_and_metadata_mutations_are_refused_as_contract_errors() {
    silence_arrow_panics();
    let contract = quad_stream_schema();
    let mut mutants: Vec<(String, Arc<Schema>)> = Vec::new();

    for index in 0..contract.fields().len() {
        for (label, mutate) in mutation_table() {
            let mut fields: Vec<Field> = contract
                .fields()
                .iter()
                .map(|field| field.as_ref().clone())
                .collect();
            let Some(mutated) = mutate(&fields[index]) else {
                continue;
            };
            fields[index] = mutated;
            mutants.push((
                format!("field {index} {label}"),
                Arc::new(Schema::new_with_metadata(
                    fields,
                    contract.metadata().clone(),
                )),
            ));
        }
    }
    // Column order carries meaning: the decoder addresses columns by index.
    let mut swapped: Vec<Field> = contract
        .fields()
        .iter()
        .map(|field| field.as_ref().clone())
        .collect();
    swapped.swap(0, 1);
    mutants.push((
        "columns 0 and 1 swapped".into(),
        Arc::new(Schema::new_with_metadata(
            swapped,
            contract.metadata().clone(),
        )),
    ));
    // Metadata is the assurance boundary: every tamper must be refused.
    for key in [
        "dataplane.contract",
        "dataplane.contract_version",
        "dataplane.assurance",
        "dataplane.arrow_version",
    ] {
        for replacement in [None, Some("2"), Some("signed"), Some("")] {
            let mut metadata = contract.metadata().clone();
            match replacement {
                None => {
                    metadata.remove(key);
                }
                Some(value) => {
                    metadata.insert(key.to_owned(), value.to_owned());
                }
            }
            if metadata == *contract.metadata() {
                continue;
            }
            let fields: Vec<Field> = contract
                .fields()
                .iter()
                .map(|field| field.as_ref().clone())
                .collect();
            mutants.push((
                format!("metadata {key} = {replacement:?}"),
                Arc::new(Schema::new_with_metadata(fields, metadata)),
            ));
        }
    }
    {
        let mut metadata = contract.metadata().clone();
        metadata.insert("dataplane.extra".into(), "no".into());
        let fields: Vec<Field> = contract
            .fields()
            .iter()
            .map(|field| field.as_ref().clone())
            .collect();
        mutants.push((
            "extra metadata key dataplane.extra".into(),
            Arc::new(Schema::new_with_metadata(fields, metadata)),
        ));
    }

    let mut checked = 0usize;
    for (label, schema) in mutants {
        let Some(batch) = batch_under(Arc::clone(&schema)) else {
            continue;
        };
        checked += 1;
        let reader = QuadStreamReader::new(&batch);
        let error = reader.err().unwrap_or_else(|| {
            panic!("mutation `{label}` was accepted as an UnsignedQuadStream batch")
        });
        assert_eq!(
            error.code(),
            "contract",
            "mutation `{label}` refused as {error}"
        );

        // The same mutation must be refused after a real IPC round-trip, not
        // only in memory: this is the path a foreign producer takes.
        let mut writer = StreamWriter::try_new(Vec::new(), schema.as_ref())
            .expect("arrow must accept its own schema");
        writer
            .write(&batch)
            .expect("arrow must accept its own batch");
        writer.finish().expect("arrow must finish its own stream");
        let bytes = writer.into_inner().expect("stream bytes");
        let error = read_ipc_stream(&bytes)
            .err()
            .unwrap_or_else(|| panic!("mutation `{label}` survived an IPC round-trip"));
        assert_eq!(
            error.code(),
            "contract",
            "mutation `{label}` refused as {error} over IPC"
        );
    }
    assert!(
        checked > 30,
        "expected a broad mutation sweep, only {checked} mutants were constructible"
    );
}

type Mutator = fn(&Field) -> Option<Field>;

fn mutation_table() -> Vec<(&'static str, Mutator)> {
    vec![
        ("renamed", |field| {
            Some(Field::new(
                format!("{}_x", field.name()),
                field.data_type().clone(),
                field.is_nullable(),
            ))
        }),
        ("nullability flipped", |field| {
            Some(Field::new(
                field.name(),
                field.data_type().clone(),
                !field.is_nullable(),
            ))
        }),
        ("dictionary key widened", |field| match field.data_type() {
            DataType::Dictionary(_, value) => Some(Field::new(
                field.name(),
                DataType::Dictionary(Box::new(DataType::UInt64), value.clone()),
                field.is_nullable(),
            )),
            _ => None,
        }),
        ("dictionary flattened to utf8", |field| {
            match field.data_type() {
                DataType::Dictionary(_, _) => Some(Field::new(
                    field.name(),
                    DataType::Utf8,
                    field.is_nullable(),
                )),
                _ => None,
            }
        }),
        ("timestamp unit changed", |field| match field.data_type() {
            DataType::Timestamp(_, zone) => Some(Field::new(
                field.name(),
                DataType::Timestamp(TimeUnit::Nanosecond, zone.clone()),
                field.is_nullable(),
            )),
            _ => None,
        }),
        ("fixed binary width changed", |field| {
            match field.data_type() {
                DataType::FixedSizeBinary(_) => Some(Field::new(
                    field.name(),
                    DataType::FixedSizeBinary(16),
                    field.is_nullable(),
                )),
                _ => None,
            }
        }),
        ("uint64 narrowed", |field| match field.data_type() {
            DataType::UInt64 => Some(Field::new(
                field.name(),
                DataType::UInt32,
                field.is_nullable(),
            )),
            _ => None,
        }),
    ]
}

// --- regressions ----------------------------------------------------------

/// Regression, `corrupted_contract_streams_never_panic_and_refuse_idempotently`
/// master seed `MASTER_SEED ^ 0xC0DE`, cases 7 and
/// 13 of the pre-fix harness: a handful of bit flips in a real contract
/// stream made `read_ipc_stream` panic inside `arrow-buffer`
/// (`Buffer::slice_with_length`, "the offset of the new Buffer cannot exceed
/// the existing length"), and a corrupted `bodyLength` made the *process
/// abort* on a 576 PB allocation — an abort no `catch_unwind` can intercept.
///
/// The minimal reproducers below are hand-reduced from those seeds so the
/// regression does not depend on the generator staying byte-identical.
#[test]
fn regression_hostile_ipc_lengths_are_refused_not_fatal() {
    silence_arrow_panics();
    let mut rng = Rng::new(MASTER_SEED ^ 0xBADD);
    let base = valid_stream(&mut rng, 4);

    // A message declaring a 4 GiB body inside a few-hundred-byte payload.
    // Pre-fix this reached arrow's allocator; now the pre-flight refuses it.
    let mut oversized_body = base.clone();
    let body_field = 8 + 8; // continuation + metadata length, then into the flatbuffer
    assert!(oversized_body.len() > body_field + 8);
    for value in [i64::MAX, 1i64 << 60, 1i64 << 48, -1i64] {
        let mut payload = oversized_body.clone();
        // Sweep the field across the first message's metadata: whichever
        // 8-byte window lands on `bodyLength`, the answer must be a typed
        // error and the answer must arrive quickly.
        for offset in (8..payload.len().min(256) - 8).step_by(8) {
            payload[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            let started = Instant::now();
            let outcome = std::panic::catch_unwind(|| read_ipc_stream(&payload));
            assert!(
                outcome.is_ok(),
                "hostile bodyLength {value} at offset {offset} panicked out of the read path"
            );
            assert!(
                started.elapsed() < DECODE_BUDGET,
                "hostile bodyLength {value} at offset {offset} took unbounded time"
            );
            payload[offset..offset + 8].copy_from_slice(&base[offset..offset + 8]);
        }
        oversized_body.clone_from(&base);
    }

    // A hostile metadata length: 0xFFFF_FFFF metadata bytes in a short payload.
    let mut hostile_metadata = base.clone();
    hostile_metadata[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    let error = read_ipc_stream(&hostile_metadata)
        .expect_err("a metadata length larger than the payload must be refused");
    assert_eq!(error.code(), "ipc", "unexpected refusal class: {error}");

    // Legacy framing (no continuation marker) is refused, not guessed at.
    let mut legacy = base.clone();
    legacy[0..4].copy_from_slice(&64u32.to_le_bytes());
    let error = read_ipc_stream(&legacy).expect_err("legacy framing must be refused");
    assert_eq!(error.code(), "ipc", "unexpected refusal class: {error}");
}

/// Regression: an RDF 1.2 directional language-tagged string used to be
/// written into the flat object columns with its base direction silently
/// dropped, so `read(write(q)) != q` with no error anywhere. The contract has
/// no column for a direction and v1 is frozen, so it is now a typed refusal.
#[test]
fn regression_directional_object_is_refused_not_silently_flattened() {
    use oxrdf::{BaseDirection, GraphName, Literal, NamedNode, Term};

    let literal =
        Literal::new_directional_language_tagged_literal("hello", "en", BaseDirection::Rtl)
            .expect("directional literal must build");
    let quad = Quad::new(
        NamedNode::new("http://example.com/s").expect("valid IRI"),
        NamedNode::new("http://example.com/p").expect("valid IRI"),
        Term::Literal(literal),
        GraphName::DefaultGraph,
    );
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    let error = builder
        .push(quad.as_ref(), None)
        .expect_err("a directional object must be refused, not flattened");
    match error {
        QuadError::Unsupported { feature, .. } => {
            assert_eq!(feature, FEATURE_BASE_DIRECTION, "wrong feature name");
        }
        other => panic!("expected an unsupported-feature refusal, got {other}"),
    }
    assert!(
        builder.is_empty(),
        "the refused quad must not be half-written"
    );
}

/// The pre-flight must not narrow the *valid* surface: a schema-only stream
/// (zero batches) and a multi-batch stream both still read.
///
/// A framing check is only safe if it accepts everything the writer emits,
/// and a multi-batch stream is the case that re-emits dictionary messages
/// between record batches — the shape most likely to trip a hand-rolled walk.
#[test]
fn valid_stream_shapes_still_read() {
    silence_arrow_panics();
    let mut rng = Rng::new(MASTER_SEED ^ 0x5AFE);

    let empty = write_ipc_stream(&[], DEFAULT_MAX_IPC_BYTES).expect("schema-only write");
    assert!(
        read_ipc_stream(&empty)
            .expect("schema-only stream must read")
            .is_empty(),
        "a schema-only stream must decode to zero batches"
    );

    let mut batches = Vec::new();
    let mut expected_rows = 0usize;
    for rows in [0usize, 1, 7, 33] {
        let (batch, accepted) = random_batch(&mut rng, rows);
        expected_rows += accepted.len();
        batches.push(batch);
    }
    let bytes = write_ipc_stream(&batches, DEFAULT_MAX_IPC_BYTES).expect("multi-batch write");
    let decoded = read_ipc_stream(&bytes).expect("multi-batch stream must read");
    assert_eq!(
        decoded.len(),
        batches.len(),
        "batch count changed across IPC"
    );
    let total: usize = decoded.iter().map(|batch| batch.num_rows()).sum();
    assert_eq!(total, expected_rows, "row count changed across IPC");
    assert_eq!(
        read_everything(&bytes).expect("every row must decode"),
        expected_rows,
        "the row decoders disagree with the batch row counts"
    );
}

// --- dictionary deltas ----------------------------------------------------

/// A stream whose later dictionaries are deltas is refused.
///
/// Arrow re-concatenates the whole dictionary on every delta, so a payload of
/// many tiny deltas costs quadratic copying. No writer in the workspace emits
/// deltas, so refusing them narrows nothing a producer here relies on.
#[test]
fn delta_dictionary_streams_are_refused() {
    silence_arrow_panics();
    let mut rng = Rng::new(MASTER_SEED ^ 0xDE17A);
    let (first, accepted) = random_batch(&mut rng, 5);
    // The second batch repeats the first one's quads before adding more, so
    // each dictionary of the second extends the first's and is sent as a delta.
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    for (quad, provenance) in &accepted {
        builder
            .push(quad.as_ref(), provenance.as_ref())
            .expect("replay");
    }
    for _ in 0..5 {
        let quad = random_quad(&mut rng, 1);
        drop(builder.push(quad.as_ref(), None));
    }
    let second = builder.finish().expect("second batch");
    let options = arrow_ipc::writer::IpcWriteOptions::default()
        .with_dictionary_handling(arrow_ipc::writer::DictionaryHandling::Delta);
    let schema = quad_stream_schema();
    let mut writer =
        StreamWriter::try_new_with_options(Vec::new(), schema.as_ref(), options).expect("writer");
    writer.write(&first).expect("first batch");
    writer.write(&second).expect("second batch");
    writer.finish().expect("finish");
    let bytes = writer.into_inner().expect("bytes");

    let error = read_ipc_stream(&bytes).expect_err("a delta-dictionary stream must be refused");
    assert!(
        error.to_string().contains("delta"),
        "refusal must name the delta: {error}"
    );
}
