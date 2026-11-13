// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Deterministic, seeded fuzz harness for the Jelly frame and patch codecs.
//!
//! Everything here runs as an ordinary `cargo test` target on a stable
//! toolchain: no `cargo-fuzz`, no libfuzzer, no `arbitrary`/`proptest`, and
//! no thread- or clock-derived randomness. Cases are drawn from an
//! xorshift64\* PRNG seeded by a per-target **constant**, so a failure is
//! reproducible from the seed printed in the assertion message. The five
//! generated targets draw **10,100 cases per run** (1,000 round-trip, 6,000
//! dumb-bytes, 1,200 hostile-frame, 700 patch round-trip, 1,200 hostile
//! patch — see each target's `ITERATIONS` constant); the hostile targets
//! probe up to three frames per case and every decode runs twice for the
//! determinism check, so the codec sees several times that many calls. The
//! whole file stays around two seconds in a debug build. The harness has additionally
//! been soaked at 10x or more of every one of these counts with no further
//! findings; raising a constant is the way to widen the search, and every
//! committed seed range is a prefix of a soaked one.
//!
//! Two generators feed every decoder target:
//!
//! * a **dumb-bytes** generator that throws random byte strings — and real
//!   frames damaged by bit flips, overwrites, deletions, insertions,
//!   cross-frame splices, and truncation — straight at `prost` and then at
//!   the frame decoder, and
//! * a **structure-aware** generator that encodes a well-formed stream and
//!   then applies one targeted mutation — truncation, byte flips, lookup
//!   identifier corruption, options-row removal or duplication, out-of-range
//!   versions, table sizes beyond the configured maxima, id-0 delta chains
//!   referencing unset identifiers, repeated-term elision with nothing to
//!   repeat, quad counts beyond the batch limit, triple terms on a stream
//!   that never announced `rdf_star`, and triple-term depth explosion.
//!
//! The assertions, not the iteration count, are the point:
//!
//! 1. **Never panic.** Every case runs inside [`catch_unwind`]; a panic is
//!    reported with its seed instead of being allowed to look like a normal
//!    test failure. Malformed input must produce a typed [`JellyError`].
//! 2. **Never hang or exhaust.** Declared table sizes and triple-term
//!    nesting depth are refused *before* the allocation or the recursion
//!    they would drive; dedicated tests pin those two.
//! 3. **Round-trip.** `quads(decode(encode(batch))) == quads(batch)` for
//!    every batch the encoder accepts, across frame boundaries and across
//!    several batches sharing one encoder/decoder pair.
//! 4. **Idempotent refusal.** The same bytes through a fresh decoder yield
//!    the same outcome, down to the error code and rendered message.
//! 5. **No silent mutation.** A successful decode invents no rows (decoded
//!    rows never exceed the frame's statement rows), leaves provenance null,
//!    and produces a contract-valid batch.
//!
//! [`catch_unwind`]: std::panic::catch_unwind

use std::panic::{AssertUnwindSafe, catch_unwind};

#[path = "../../tools/mutation_smoke.rs"]
mod smoke;

/// Every test in this binary runs under the shared 1 GiB live-allocation
/// cap, so a decoder that sizes an allocation from a hostile field aborts
/// with a message instead of exhausting the machine.
#[global_allocator]
static ALLOCATOR: smoke::CappedAllocator = smoke::CappedAllocator;

use arrow_array::RecordBatch;
use jelly_fast_core::{
    JellyDecoder, JellyDecoderOptions, JellyEncoder, JellyEncoderOptions, JellyError,
    JellyPatchDecoder, JellyPatchDecoderOptions, JellyPatchEncoder, JellyPatchEncoderOptions,
    PATCH_PROTOCOL_VERSION, PROTOCOL_VERSION, PatchOp,
    proto::{
        LogicalStreamType, PhysicalStreamType, RdfDatatypeEntry, RdfDefaultGraph, RdfGraphEnd,
        RdfGraphStart, RdfIri, RdfLiteral, RdfNameEntry, RdfNamespaceDeclaration, RdfPrefixEntry,
        RdfQuad, RdfStreamFrame, RdfStreamOptions, RdfStreamRow, RdfTriple,
        patch::{
            PatchStatementType, PatchStreamType, RdfPatchFrame, RdfPatchHeader, RdfPatchNamespace,
            RdfPatchOptions, RdfPatchPunctuation, RdfPatchRow, RdfPatchTransactionAbort,
            RdfPatchTransactionCommit, RdfPatchTransactionStart, rdf_patch_header, rdf_patch_row,
        },
        rdf_literal, rdf_quad, rdf_stream_row, rdf_triple,
    },
};
use oxrdf::{BlankNode, GraphName, Literal, NamedNode, Quad, Term, Triple};
use prost::Message;
use quad_fast_core::{QuadBatchBuilder, QuadLimits, QuadStreamReader};

// ---------------------------------------------------------------------------
// Deterministic PRNG
// ---------------------------------------------------------------------------

/// xorshift64\* generator: deterministic, seeded by a constant, no clock.
struct Rng {
    state: u64,
}

impl Rng {
    /// Creates a generator for `seed` (forced nonzero, as xorshift needs).
    fn new(seed: u64) -> Self {
        Self {
            state: seed | 0x9E37_79B9_7F4A_7C15,
        }
    }

    /// Draws the next 64-bit word.
    fn next_u64(&mut self) -> u64 {
        let mut state = self.state;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.state = state;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Draws a value in `0..bound` (`bound` must be nonzero).
    fn below(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "bound must be nonzero");
        usize::try_from(self.next_u64() % bound as u64).unwrap_or(0)
    }

    /// Draws one byte.
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    /// Draws a boolean, true with probability `1/odds`.
    fn chance(&mut self, odds: usize) -> bool {
        self.below(odds) == 0
    }

    /// Picks one element of a non-empty slice.
    fn pick<'a, T>(&mut self, values: &'a [T]) -> &'a T {
        let index = self.below(values.len());
        &values[index]
    }

    /// Draws a `u32` biased toward boundary values (0, 1, max, near-max).
    fn boundary_u32(&mut self) -> u32 {
        const BOUNDARIES: &[u32] = &[
            0,
            1,
            2,
            7,
            8,
            9,
            127,
            128,
            129,
            4000,
            4001,
            65_535,
            u32::MAX - 1,
            u32::MAX,
        ];
        if self.chance(2) {
            *self.pick(BOUNDARIES)
        } else {
            (self.next_u64() >> 32) as u32
        }
    }
}

/// Runs `body`, converting any panic into a failure that names the seed.
///
/// Invariant 1 ("never panic") is checked here explicitly rather than being
/// left to the test harness, so a discovery is always reproducible.
fn guarded<F: FnOnce()>(target: &str, seed: u64, body: F) {
    if catch_unwind(AssertUnwindSafe(body)).is_err() {
        panic!("fuzz target `{target}` PANICKED — reproduce with seed 0x{seed:016x}");
    }
}

/// Renders a decode outcome for comparison and for failure messages.
fn outcome<T>(result: &Result<T, JellyError>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(error) => format!("{}|{error}", error.code()),
    }
}

// ---------------------------------------------------------------------------
// Structure-aware RDF generators
// ---------------------------------------------------------------------------

/// IRI prefixes, including one with no `#`/`/` delimiter at all.
const PREFIXES: &[&str] = &[
    "http://alpha.example/",
    "http://beta.example/ns#",
    "http://gamma.example/data/",
    "https://delta.example/v1/deep/",
    "urn:example:",
];

/// Local names, including one shared across prefixes and one long name.
const NAMES: &[&str] = &[
    "a",
    "b",
    "c",
    "shared",
    "item-42",
    "aVeryLongLocalNameThatDoesNotCompressParticularlyWell",
];

/// Datatype IRIs used by generated typed literals.
const DATATYPES: &[&str] = &[
    "http://www.w3.org/2001/XMLSchema#integer",
    "http://www.w3.org/2001/XMLSchema#double",
    "http://www.w3.org/2001/XMLSchema#dateTime",
    "http://www.w3.org/2001/XMLSchema#boolean",
    "http://example.com/custom/Datatype",
];

/// Language tags used by generated language-tagged literals.
const LANGUAGES: &[&str] = &["en", "pt-BR", "de", "ja"];

/// Blank node labels drawn from a small pool so repeats occur.
const BNODES: &[&str] = &["b0", "b1", "b2", "g0"];

/// Builds one IRI from the prefix/name pools.
fn gen_iri(rng: &mut Rng) -> NamedNode {
    let iri = format!("{}{}", rng.pick(PREFIXES), rng.pick(NAMES));
    NamedNode::new(iri).expect("generated IRI is valid")
}

/// Builds one blank node from the label pool.
fn gen_bnode(rng: &mut Rng) -> BlankNode {
    BlankNode::new(*rng.pick(BNODES)).expect("generated blank node label is valid")
}

/// Builds one literal: simple, language-tagged, or datatyped.
fn gen_literal(rng: &mut Rng) -> Literal {
    let lexical = *rng.pick(&["", "0", "1", "-1", "text", "líng\u{fc}a", "  spaced  "]);
    match rng.below(3) {
        0 => Literal::new_simple_literal(lexical),
        1 => Literal::new_language_tagged_literal(lexical, *rng.pick(LANGUAGES))
            .expect("generated language tag is valid"),
        _ => Literal::new_typed_literal(
            lexical,
            NamedNode::new(*rng.pick(DATATYPES)).expect("generated datatype IRI is valid"),
        ),
    }
}

/// Builds one object term, nesting triple terms up to `depth_budget`.
fn gen_object(rng: &mut Rng, depth_budget: usize) -> Term {
    match rng.below(4) {
        0 => Term::NamedNode(gen_iri(rng)),
        1 => Term::BlankNode(gen_bnode(rng)),
        2 => Term::Literal(gen_literal(rng)),
        _ => {
            if depth_budget == 0 {
                return Term::Literal(gen_literal(rng));
            }
            Term::Triple(Box::new(Triple::new(
                gen_iri(rng),
                gen_iri(rng),
                gen_object(rng, depth_budget - 1),
            )))
        }
    }
}

/// Builds one quad, reusing terms of `previous` so elision is exercised.
fn gen_quad(rng: &mut Rng, previous: Option<&Quad>, quoted_depth: usize) -> Quad {
    let subject = match previous {
        Some(quad) if rng.chance(3) => quad.subject.clone(),
        _ if rng.chance(4) => oxrdf::NamedOrBlankNode::BlankNode(gen_bnode(rng)),
        _ => oxrdf::NamedOrBlankNode::NamedNode(gen_iri(rng)),
    };
    let predicate = match previous {
        Some(quad) if rng.chance(2) => quad.predicate.clone(),
        _ => gen_iri(rng),
    };
    let object = match previous {
        Some(quad) if rng.chance(4) => quad.object.clone(),
        _ => gen_object(rng, quoted_depth),
    };
    let graph_name = match previous {
        Some(quad) if rng.chance(2) => quad.graph_name.clone(),
        _ => match rng.below(3) {
            0 => GraphName::DefaultGraph,
            1 => GraphName::NamedNode(gen_iri(rng)),
            _ => GraphName::BlankNode(gen_bnode(rng)),
        },
    };
    Quad::new(subject, predicate, object, graph_name)
}

/// Builds a run of quads, threading the previous quad for elision.
fn gen_quads(rng: &mut Rng, count: usize, quoted_depth: usize) -> Vec<Quad> {
    let mut quads: Vec<Quad> = Vec::with_capacity(count);
    for _ in 0..count {
        let quad = gen_quad(rng, quads.last(), quoted_depth);
        quads.push(quad);
    }
    quads
}

/// Packs quads into one contract-valid batch.
fn batch_of(quads: &[Quad]) -> RecordBatch {
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    for quad in quads {
        builder.push(quad.as_ref(), None).expect("quad accepted");
    }
    builder.finish().expect("batch built")
}

/// Reads every quad back out of a decoded batch.
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

/// Asserts a decoded batch carries no provenance (invariant: null on decode).
fn assert_decoded_batch_clean(batch: &RecordBatch, context: &str) {
    let reader = QuadStreamReader::new(batch)
        .unwrap_or_else(|error| panic!("{context}: decoded batch is not contract-valid: {error}"));
    for row in 0..reader.len() {
        let provenance = reader.provenance(row);
        assert!(
            provenance.source_artifact_iri.is_none()
                && provenance.source_content_sha256.is_none()
                && provenance.source_offset_start.is_none()
                && provenance.source_offset_end.is_none()
                && provenance.observed_at_micros.is_none(),
            "{context}: decoded batch row {row} invented provenance"
        );
    }
}

/// Counts the statement rows of a frame (the upper bound on decoded rows).
fn quad_rows(frame: &RdfStreamFrame) -> usize {
    frame
        .rows
        .iter()
        .filter(|row| matches!(row.row, Some(rdf_stream_row::Row::Quad(_))))
        .count()
}

// ---------------------------------------------------------------------------
// Target 1 — RDF stream round-trip (invariants 3 and 5)
// ---------------------------------------------------------------------------

/// Seed for [`fuzz_rdf_round_trip`]; change only to widen the search.
const ROUND_TRIP_SEED: u64 = 0x0BAD_C0DE_1234_5678;

/// Cases for [`fuzz_rdf_round_trip`]; kept small enough to stay under ~2s.
const ROUND_TRIP_ITERATIONS: u64 = 1000;

/// One round-trip case: table sizing, framing, and RDF-star all vary.
struct RoundTripCase {
    encoder: JellyEncoderOptions,
    decoder: JellyDecoderOptions,
    batches: Vec<RecordBatch>,
    quads: Vec<Quad>,
}

/// Draws one round-trip case from `rng`.
fn gen_round_trip_case(rng: &mut Rng) -> RoundTripCase {
    // Deliberately includes table sizes far below the per-statement term
    // count, which is exactly where lookup-identifier reassignment bites.
    let max_prefix_table_size = *rng.pick(&[1_u32, 2, 3, 8, 16, 128]);
    let max_name_table_size = *rng.pick(&[8_u32, 9, 16, 64, 4000]);
    let max_datatype_table_size = *rng.pick(&[1_u32, 2, 4, 32]);
    let rdf_star = rng.chance(2);
    let quoted_depth = if rdf_star { rng.below(4) } else { 0 };
    let quads_per_frame = *rng.pick(&[1_usize, 2, 3, 7, 64, 8192]);

    let encoder = JellyEncoderOptions {
        stream_name: if rng.chance(3) {
            Some("fuzz-topic".to_owned())
        } else {
            None
        },
        max_prefix_table_size,
        max_name_table_size,
        max_datatype_table_size,
        quads_per_frame,
        allow_provenance_loss: false,
        rdf_star,
        ..JellyEncoderOptions::default()
    };
    let decoder = JellyDecoderOptions {
        max_prefix_table_size,
        max_name_table_size,
        max_datatype_table_size,
        quad_limits: QuadLimits::default(),
    };

    let batch_count = 1 + rng.below(3);
    let mut batches = Vec::with_capacity(batch_count);
    let mut quads = Vec::new();
    for _ in 0..batch_count {
        let run_length = rng.below(12);
        let run = gen_quads(rng, run_length, quoted_depth);
        batches.push(batch_of(&run));
        quads.extend(run);
    }
    RoundTripCase {
        encoder,
        decoder,
        batches,
        quads,
    }
}

/// Encodes every batch through one encoder, or reports the first refusal.
fn encode_case(case: &RoundTripCase) -> Result<Vec<RdfStreamFrame>, JellyError> {
    let mut encoder = JellyEncoder::new(case.encoder.clone())?;
    let mut frames = Vec::new();
    for batch in &case.batches {
        frames.extend(encoder.encode_batch(batch)?);
    }
    Ok(frames)
}

#[test]
fn fuzz_rdf_round_trip() {
    for iteration in 0..ROUND_TRIP_ITERATIONS {
        let seed = ROUND_TRIP_SEED ^ iteration.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        guarded("rdf_round_trip", seed, || {
            let mut rng = Rng::new(seed);
            let case = gen_round_trip_case(&mut rng);

            let frames = match encode_case(&case) {
                Ok(frames) => frames,
                Err(error) => {
                    // Invariant 4: a refusal is a refusal every time, with
                    // the same code and the same rendered message.
                    let again = encode_case(&case)
                        .err()
                        .map(|repeat| format!("{}|{repeat}", repeat.code()));
                    assert_eq!(
                        again,
                        Some(format!("{}|{error}", error.code())),
                        "seed 0x{seed:016x}: encode refusal is not deterministic"
                    );
                    // A refusal must be a resource limit on a lookup table:
                    // nothing else in this generator is refusable.
                    assert!(
                        matches!(error, JellyError::ResourceLimit { .. }),
                        "seed 0x{seed:016x}: unexpected encode refusal: {error}"
                    );
                    return;
                }
            };

            let mut decoder = JellyDecoder::new(case.decoder.clone());
            let mut decoded = Vec::new();
            for (index, frame) in frames.iter().enumerate() {
                let batch = decoder.decode_frame(frame).unwrap_or_else(|error| {
                    panic!(
                        "seed 0x{seed:016x}: frame {index} of a self-encoded stream was \
                         rejected: {error} (prefix={} name={} datatype={} per_frame={} \
                         rdf_star={})",
                        case.encoder.max_prefix_table_size,
                        case.encoder.max_name_table_size,
                        case.encoder.max_datatype_table_size,
                        case.encoder.quads_per_frame,
                        case.encoder.rdf_star,
                    )
                });
                assert!(
                    batch.num_rows() <= quad_rows(frame),
                    "seed 0x{seed:016x}: frame {index} decoded {} rows from {} statement rows",
                    batch.num_rows(),
                    quad_rows(frame)
                );
                assert_decoded_batch_clean(&batch, &format!("seed 0x{seed:016x} frame {index}"));
                decoded.extend(quads_of(&batch));
            }

            // Invariants 3 and 5: every accepted quad comes back byte-for-byte,
            // in order, with nothing dropped, altered, or invented.
            assert_eq!(
                decoded.len(),
                case.quads.len(),
                "seed 0x{seed:016x}: round trip changed the quad count \
                 (prefix={} name={} datatype={} per_frame={} rdf_star={})",
                case.encoder.max_prefix_table_size,
                case.encoder.max_name_table_size,
                case.encoder.max_datatype_table_size,
                case.encoder.quads_per_frame,
                case.encoder.rdf_star,
            );
            for (index, (got, want)) in decoded.iter().zip(&case.quads).enumerate() {
                assert_eq!(
                    got,
                    want,
                    "seed 0x{seed:016x}: quad {index} changed across the round trip \
                     (prefix={} name={} datatype={} per_frame={} rdf_star={})",
                    case.encoder.max_prefix_table_size,
                    case.encoder.max_name_table_size,
                    case.encoder.max_datatype_table_size,
                    case.encoder.quads_per_frame,
                    case.encoder.rdf_star,
                );
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Target 2 — RDF frame decoder over random bytes (invariants 1, 2, 4, 5)
// ---------------------------------------------------------------------------

/// Seed for [`fuzz_rdf_frame_dumb_bytes`].
const DUMB_BYTES_SEED: u64 = 0x1357_9BDF_2468_ACE0;

/// Cases for [`fuzz_rdf_frame_dumb_bytes`].
const DUMB_BYTES_ITERATIONS: u64 = 6000;

/// Draws a byte string with no structure at all.
///
/// Almost none of these survive `prost`, which is the point: the decoder
/// must be safe on bytes that were never a frame. Reaching the codec's own
/// validation is [`corrupt_bytes`]'s job.
fn gen_dumb_bytes(rng: &mut Rng) -> Vec<u8> {
    let length = rng.below(112);
    let mut bytes = Vec::with_capacity(length + 2);
    if rng.chance(3) {
        // Field 1 (`rows`), wire type 2 — a plausible opening tag.
        bytes.push(0x0A);
        bytes.push(rng.byte());
    }
    for _ in 0..length {
        bytes.push(rng.byte());
    }
    bytes
}

/// Corrupts a real serialized frame at the byte level.
///
/// This is the generator that actually exercises the protobuf-decode →
/// codec-decode path: starting from valid wire bytes and damaging them
/// keeps enough structure that a good fraction still parse into frames with
/// *rows*, which is where the codec's own validation lives. Damage kinds:
/// bit flips, byte overwrites, deletions, insertions, splices from a second
/// frame, and truncation.
fn corrupt_bytes(rng: &mut Rng, seed_bytes: &[u8], other: &[u8]) -> Vec<u8> {
    let mut bytes = seed_bytes.to_vec();
    if bytes.is_empty() {
        return bytes;
    }
    // Weighted toward single in-place edits: those keep enough of the
    // protobuf length framing intact that the damaged bytes still parse into
    // a frame *with rows*, which is where the codec's own validation lives.
    // Structural damage (delete/insert/splice/truncate) is rarer but present.
    // Measured reach: roughly one corrupted case in ten still parses into a
    // frame, and the frames that do carry rows the codec must validate
    // (~2,400 rows and ~240 accepted frames per 2,000 corrupted cases).
    let damage = if rng.chance(2) { 1 } else { 2 + rng.below(3) };
    for _ in 0..damage {
        if bytes.is_empty() {
            break;
        }
        match rng.below(10) {
            0..=3 => {
                let index = rng.below(bytes.len());
                bytes[index] ^= 1 << rng.below(8);
            }
            4..=6 => {
                let index = rng.below(bytes.len());
                bytes[index] = rng.byte();
            }
            7 => {
                let index = rng.below(bytes.len());
                bytes.remove(index);
            }
            8 => {
                let index = rng.below(bytes.len() + 1);
                let byte = rng.byte();
                bytes.insert(index, byte);
            }
            _ if !other.is_empty() && rng.chance(2) => {
                // Splice: protobuf repeated fields concatenate, so grafting
                // another frame's tail often yields a parseable frame whose
                // rows arrive in an order no encoder would produce.
                let at = rng.below(bytes.len());
                let from = rng.below(other.len());
                let take = 1 + rng.below(other.len() - from);
                bytes.truncate(at);
                bytes.extend_from_slice(&other[from..from + take]);
            }
            _ => {
                let keep = rng.below(bytes.len());
                bytes.truncate(keep);
            }
        }
    }
    bytes
}

/// Decodes one frame twice through fresh decoders and checks every invariant.
fn probe_rdf_frame(seed: u64, frame: &RdfStreamFrame, options: &JellyDecoderOptions) {
    let first = JellyDecoder::new(options.clone()).decode_frame(frame);
    let second = JellyDecoder::new(options.clone()).decode_frame(frame);
    assert_eq!(
        outcome(&first),
        outcome(&second),
        "seed 0x{seed:016x}: decoding is not deterministic"
    );
    if let Ok(batch) = first {
        assert!(
            batch.num_rows() <= quad_rows(frame),
            "seed 0x{seed:016x}: decoder invented rows ({} from {} statement rows)",
            batch.num_rows(),
            quad_rows(frame)
        );
        assert_decoded_batch_clean(&batch, &format!("seed 0x{seed:016x}"));
    }
}

/// Serialized frames used as the corruption corpus.
///
/// Deliberately varied: an options-only frame, a plain-quad frame, an
/// RDF-star frame, and one with metadata, so a splice can graft a row kind
/// onto a stream that never announced it.
fn seed_corpus() -> Vec<Vec<u8>> {
    let mut rng = Rng::new(0xC0FF_EE00_5EED_C0DE);
    let mut corpus = Vec::new();
    for rdf_star in [false, true] {
        for count in [0_usize, 1, 5] {
            let quads = gen_quads(&mut rng, count, if rdf_star { 2 } else { 0 });
            let batch = batch_of(&quads);
            let mut encoder = JellyEncoder::new(JellyEncoderOptions {
                rdf_star,
                ..JellyEncoderOptions::default()
            })
            .expect("valid encoder options");
            for mut frame in encoder.encode_batch(&batch).expect("batch encodes") {
                if rdf_star {
                    frame
                        .metadata
                        .insert("note".to_owned(), vec![0xFF, 0x00, 0x7F]);
                }
                corpus.push(frame.encode_to_vec());
            }
        }
    }
    corpus
}

#[test]
fn fuzz_rdf_frame_dumb_bytes() {
    let options = JellyDecoderOptions::default();
    let corpus = seed_corpus();
    for iteration in 0..DUMB_BYTES_ITERATIONS {
        let seed = DUMB_BYTES_SEED ^ iteration.wrapping_mul(0xD1B5_4A32_D192_ED03);
        guarded("rdf_frame_dumb_bytes", seed, || {
            let mut rng = Rng::new(seed);
            // Half unstructured bytes (nothing may panic on any input), half
            // corrupted real frames (which actually reach the codec).
            let bytes = if rng.chance(2) {
                gen_dumb_bytes(&mut rng)
            } else {
                let base = rng.pick(&corpus).clone();
                let other = rng.pick(&corpus).clone();
                corrupt_bytes(&mut rng, &base, &other)
            };
            // Protobuf framing errors are the expected outcome for many
            // inputs; what matters is that nothing below panics or hangs.
            if let Ok(frame) = RdfStreamFrame::decode(bytes.as_slice()) {
                probe_rdf_frame(seed, &frame, &options);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Target 3 — hostile but structurally plausible RDF frames
// ---------------------------------------------------------------------------

/// Seed for [`fuzz_rdf_frame_hostile`].
const HOSTILE_SEED: u64 = 0x7E57_1234_FEED_BEEF;

/// Cases for [`fuzz_rdf_frame_hostile`]; each applies one mutation.
const HOSTILE_ITERATIONS: u64 = 1200;

/// Number of distinct mutations [`mutate_frame`] can apply.
const MUTATION_KINDS: usize = 22;

/// Builds a well-formed multi-row frame to mutate.
fn gen_base_frame(rng: &mut Rng) -> RdfStreamFrame {
    let count = 1 + rng.below(6);
    let depth = if rng.chance(2) { 2 } else { 0 };
    let quads = gen_quads(rng, count, depth);
    let batch = batch_of(&quads);
    let mut encoder = JellyEncoder::new(JellyEncoderOptions {
        rdf_star: true,
        quads_per_frame: 8192,
        ..JellyEncoderOptions::default()
    })
    .expect("valid encoder options");
    let mut frames = encoder.encode_batch(&batch).expect("batch encodes");
    frames.pop().unwrap_or(RdfStreamFrame {
        rows: Vec::new(),
        metadata: std::collections::HashMap::new(),
    })
}

/// Returns the frame's options row, if it has one.
fn options_of(frame: &RdfStreamFrame) -> RdfStreamOptions {
    frame
        .rows
        .iter()
        .find_map(|row| match &row.row {
            Some(rdf_stream_row::Row::Options(options)) => Some(options.clone()),
            _ => None,
        })
        .unwrap_or(RdfStreamOptions {
            stream_name: String::new(),
            physical_type: PhysicalStreamType::Quads.into(),
            generalized_statements: false,
            rdf_star: false,
            max_name_table_size: 4000,
            max_prefix_table_size: 128,
            max_datatype_table_size: 32,
            logical_type: LogicalStreamType::FlatQuads.into(),
            version: PROTOCOL_VERSION,
        })
}

/// Replaces the frame's options row in place.
fn set_options(frame: &mut RdfStreamFrame, options: RdfStreamOptions) {
    for row in &mut frame.rows {
        if matches!(row.row, Some(rdf_stream_row::Row::Options(_))) {
            row.row = Some(rdf_stream_row::Row::Options(options));
            return;
        }
    }
    frame.rows.insert(
        0,
        RdfStreamRow {
            row: Some(rdf_stream_row::Row::Options(options)),
        },
    );
}

/// Builds an `RdfTriple` nested `depth` levels deep.
///
/// Depth stays in the low hundreds on purpose: both `prost` encoding and the
/// `Box` chain's own `Drop` recurse, so a five-figure chain would blow the
/// stack inside the *harness* and mask what it is meant to measure.
fn nested_triple(depth: usize) -> RdfTriple {
    let mut triple = RdfTriple {
        subject: Some(rdf_triple::Subject::SIri(RdfIri {
            prefix_id: 1,
            name_id: 1,
        })),
        predicate: Some(rdf_triple::Predicate::PIri(RdfIri {
            prefix_id: 1,
            name_id: 1,
        })),
        object: Some(rdf_triple::Object::OIri(RdfIri {
            prefix_id: 1,
            name_id: 1,
        })),
    };
    for _ in 1..depth {
        triple = RdfTriple {
            subject: Some(rdf_triple::Subject::SIri(RdfIri {
                prefix_id: 1,
                name_id: 1,
            })),
            predicate: Some(rdf_triple::Predicate::PIri(RdfIri {
                prefix_id: 1,
                name_id: 1,
            })),
            object: Some(rdf_triple::Object::OTripleTerm(Box::new(triple))),
        };
    }
    triple
}

/// Applies exactly one targeted mutation to `frame`.
fn mutate_frame(rng: &mut Rng, frame: &mut RdfStreamFrame, kind: usize) {
    match kind {
        // Missing / misplaced / duplicated options row.
        0 => frame
            .rows
            .retain(|row| !matches!(row.row, Some(rdf_stream_row::Row::Options(_)))),
        1 => {
            if !frame.rows.is_empty() {
                let last = frame.rows.len() - 1;
                frame.rows.swap(0, last);
            }
        }
        2 => {
            let options = options_of(frame);
            frame.rows.push(RdfStreamRow {
                row: Some(rdf_stream_row::Row::Options(options)),
            });
        }
        // Version out of range, including 0 and u32::MAX.
        3 => {
            let mut options = options_of(frame);
            options.version = *rng.pick(&[0_u32, 3, 4, 99, 10_000, u32::MAX]);
            set_options(frame, options);
        }
        // Physical / logical stream type, including unknown enum numbers.
        4 => {
            let mut options = options_of(frame);
            options.physical_type = *rng.pick(&[0_i32, 1, 2, 3, 7, -1, i32::MAX]);
            set_options(frame, options);
        }
        5 => {
            let mut options = options_of(frame);
            options.logical_type = *rng.pick(&[0_i32, 1, 80, -5, i32::MIN]);
            set_options(frame, options);
        }
        6 => {
            let mut options = options_of(frame);
            options.generalized_statements = true;
            set_options(frame, options);
        }
        // Table sizes beyond the configured maxima, or below the spec floor.
        7 => {
            let mut options = options_of(frame);
            options.max_name_table_size = rng.boundary_u32();
            set_options(frame, options);
        }
        8 => {
            let mut options = options_of(frame);
            options.max_prefix_table_size = rng.boundary_u32();
            set_options(frame, options);
        }
        9 => {
            let mut options = options_of(frame);
            options.max_datatype_table_size = rng.boundary_u32();
            set_options(frame, options);
        }
        // Lookup entry identifiers: id-0 delta chains, duplicates, overflow.
        10 => {
            for row in &mut frame.rows {
                match &mut row.row {
                    Some(rdf_stream_row::Row::Name(entry)) => entry.id = rng.boundary_u32(),
                    Some(rdf_stream_row::Row::Prefix(entry)) => entry.id = rng.boundary_u32(),
                    Some(rdf_stream_row::Row::Datatype(entry)) => entry.id = rng.boundary_u32(),
                    _ => {}
                }
            }
        }
        // Drop every entry row: statement rows now reference unset ids.
        11 => frame.rows.retain(|row| {
            !matches!(
                row.row,
                Some(
                    rdf_stream_row::Row::Name(_)
                        | rdf_stream_row::Row::Prefix(_)
                        | rdf_stream_row::Row::Datatype(_)
                )
            )
        }),
        // Repeated-term elision with nothing to repeat.
        12 => frame.rows.insert(
            usize::from(!frame.rows.is_empty()),
            RdfStreamRow {
                row: Some(rdf_stream_row::Row::Quad(RdfQuad {
                    subject: None,
                    predicate: None,
                    object: None,
                    graph: None,
                })),
            },
        ),
        // Lookup references with boundary identifiers.
        13 => {
            let iri = RdfIri {
                prefix_id: rng.boundary_u32(),
                name_id: rng.boundary_u32(),
            };
            frame.rows.push(RdfStreamRow {
                row: Some(rdf_stream_row::Row::Quad(RdfQuad {
                    subject: Some(rdf_quad::Subject::SIri(iri)),
                    predicate: Some(rdf_quad::Predicate::PIri(iri)),
                    object: Some(rdf_quad::Object::OIri(iri)),
                    graph: Some(rdf_quad::Graph::GDefaultGraph(RdfDefaultGraph {})),
                })),
            });
        }
        // Literal datatype id 0 / out of range, and a hostile language tag.
        14 => frame.rows.push(RdfStreamRow {
            row: Some(rdf_stream_row::Row::Quad(RdfQuad {
                subject: None,
                predicate: None,
                object: Some(rdf_quad::Object::OLiteral(RdfLiteral {
                    lex: "x".to_owned(),
                    literal_kind: Some(if rng.chance(2) {
                        rdf_literal::LiteralKind::Datatype(rng.boundary_u32())
                    } else {
                        rdf_literal::LiteralKind::Langtag(
                            (*rng.pick(&["", "e", "en-", "1234567890abcdef", "en_US", "☃"]))
                                .to_owned(),
                        )
                    }),
                })),
                graph: None,
            })),
        }),
        // Hostile blank node labels.
        15 => frame.rows.push(RdfStreamRow {
            row: Some(rdf_stream_row::Row::Quad(RdfQuad {
                subject: Some(rdf_quad::Subject::SBnode(
                    (*rng.pick(&["", " ", "-bad", "b 1", "☃", "b1"])).to_owned(),
                )),
                predicate: None,
                object: None,
                graph: None,
            })),
        }),
        // A triple term on a stream whose options row may deny rdf_star.
        16 => {
            let mut options = options_of(frame);
            options.rdf_star = rng.chance(2);
            set_options(frame, options);
            frame.rows.push(RdfStreamRow {
                row: Some(rdf_stream_row::Row::Quad(RdfQuad {
                    subject: None,
                    predicate: None,
                    object: Some(rdf_quad::Object::OTripleTerm(nested_triple(1))),
                    graph: None,
                })),
            });
        }
        // Depth explosion: the limit must trip before the recursion.
        17 => {
            let mut options = options_of(frame);
            options.rdf_star = true;
            set_options(frame, options);
            frame.rows.push(RdfStreamRow {
                row: Some(rdf_stream_row::Row::Quad(RdfQuad {
                    subject: None,
                    predicate: None,
                    object: Some(rdf_quad::Object::OTripleTerm(nested_triple(
                        32 + rng.below(96),
                    ))),
                    graph: None,
                })),
            });
        }
        // Triple terms in positions RDF 1.2 forbids.
        18 => frame.rows.push(RdfStreamRow {
            row: Some(rdf_stream_row::Row::Quad(RdfQuad {
                subject: Some(rdf_quad::Subject::STripleTerm(nested_triple(1))),
                predicate: None,
                object: None,
                graph: None,
            })),
        }),
        // Row kinds this QUADS decoder refuses outright.
        19 => frame.rows.push(RdfStreamRow {
            row: Some(match rng.below(4) {
                0 => rdf_stream_row::Row::Namespace(RdfNamespaceDeclaration {
                    name: "ex".to_owned(),
                    value: Some(RdfIri {
                        prefix_id: 1,
                        name_id: 1,
                    }),
                }),
                1 => rdf_stream_row::Row::Triple(nested_triple(1)),
                2 => rdf_stream_row::Row::GraphStart(RdfGraphStart { graph: None }),
                _ => rdf_stream_row::Row::GraphEnd(RdfGraphEnd {}),
            }),
        }),
        // A row with no payload at all.
        20 => frame.rows.push(RdfStreamRow { row: None }),
        // Duplicate lookup entries claiming the same explicit identifier.
        _ => {
            let id = 1 + rng.below(3) as u32;
            let value = (*rng.pick(&["http://one.example/", "http://two.example/", ""])).to_owned();
            frame.rows.push(RdfStreamRow {
                row: Some(match rng.below(3) {
                    0 => rdf_stream_row::Row::Prefix(RdfPrefixEntry {
                        id,
                        value: value.clone(),
                    }),
                    1 => rdf_stream_row::Row::Name(RdfNameEntry { id, value }),
                    _ => rdf_stream_row::Row::Datatype(RdfDatatypeEntry { id, value }),
                }),
            });
        }
    }
}

#[test]
fn fuzz_rdf_frame_hostile() {
    for iteration in 0..HOSTILE_ITERATIONS {
        let seed = HOSTILE_SEED ^ iteration.wrapping_mul(0xA076_1D64_78BD_642F);
        guarded("rdf_frame_hostile", seed, || {
            let mut rng = Rng::new(seed);
            let mut frame = gen_base_frame(&mut rng);
            let mutation = rng.below(MUTATION_KINDS);
            mutate_frame(&mut rng, &mut frame, mutation);

            // Small quad budget so "more quads than the batch limit allows"
            // is reachable from a handful of statement rows.
            let options = JellyDecoderOptions {
                quad_limits: QuadLimits {
                    max_quads: *rng.pick(&[1_usize, 2, 4, 1_000_000]),
                    max_quoted_depth: *rng.pick(&[0_usize, 1, 2, 8]),
                    ..QuadLimits::default()
                },
                ..JellyDecoderOptions::default()
            };
            probe_rdf_frame(seed, &frame, &options);

            // The same frame, re-serialized and truncated at a random point:
            // a length-delimited stream cut mid-message must fail closed.
            let bytes = frame.encode_to_vec();
            if !bytes.is_empty() {
                let mut truncated = bytes.clone();
                truncated.truncate(rng.below(bytes.len()));
                if let Ok(frame) = RdfStreamFrame::decode(truncated.as_slice()) {
                    probe_rdf_frame(seed, &frame, &options);
                }
                // And with a single byte flipped somewhere in the middle.
                let mut flipped = bytes;
                let index = rng.below(flipped.len());
                flipped[index] ^= 1 << rng.below(8);
                if let Ok(frame) = RdfStreamFrame::decode(flipped.as_slice()) {
                    probe_rdf_frame(seed, &frame, &options);
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Target 4 — patch codec round-trip
// ---------------------------------------------------------------------------

/// Seed for [`fuzz_patch_round_trip`].
const PATCH_ROUND_TRIP_SEED: u64 = 0x2468_ACE0_1357_9BDF;

/// Cases for [`fuzz_patch_round_trip`].
const PATCH_ROUND_TRIP_ITERATIONS: u64 = 700;

/// One patch operation flattened to a per-quad event.
///
/// Decoding collapses maximal runs of same-kind statement rows into one
/// batch, so batch *boundaries* are not part of the round-trip contract;
/// the event sequence is.
#[derive(Clone, Debug, PartialEq)]
enum PatchEvent {
    /// `TX`.
    Start,
    /// `TC`.
    Commit,
    /// `TA`.
    Abort,
    /// `H` with its key and value.
    Header(String, Term),
    /// One quad of an `A` row.
    Add(Quad),
    /// One quad of a `D` row.
    Delete(Quad),
}

/// Flattens patch operations into comparable per-quad events.
fn events_of(ops: &[PatchOp]) -> Vec<PatchEvent> {
    let mut events = Vec::new();
    for op in ops {
        match op {
            PatchOp::TransactionStart => events.push(PatchEvent::Start),
            PatchOp::TransactionCommit => events.push(PatchEvent::Commit),
            PatchOp::TransactionAbort => events.push(PatchEvent::Abort),
            PatchOp::Header { key, value } => {
                events.push(PatchEvent::Header(key.clone(), value.clone()));
            }
            PatchOp::Add(batch) => {
                events.extend(quads_of(batch).into_iter().map(PatchEvent::Add));
            }
            PatchOp::Delete(batch) => {
                events.extend(quads_of(batch).into_iter().map(PatchEvent::Delete));
            }
        }
    }
    events
}

/// Draws a well-formed patch operation sequence (headers first, balanced tx).
fn gen_patch_ops(rng: &mut Rng, rdf_star: bool, quoted_depth: usize) -> Vec<PatchOp> {
    let mut ops = Vec::new();
    for _ in 0..rng.below(3) {
        let value = match rng.below(4) {
            0 => Term::NamedNode(gen_iri(rng)),
            1 => Term::BlankNode(gen_bnode(rng)),
            2 => Term::Literal(gen_literal(rng)),
            _ if rdf_star && quoted_depth > 0 => Term::Triple(Box::new(Triple::new(
                gen_iri(rng),
                gen_iri(rng),
                gen_object(rng, quoted_depth - 1),
            ))),
            _ => Term::Literal(gen_literal(rng)),
        };
        ops.push(PatchOp::Header {
            key: (*rng.pick(&["k", "source", "id"])).to_owned(),
            value,
        });
    }
    let mut in_transaction = false;
    for _ in 0..rng.below(8) {
        match rng.below(5) {
            0 if !in_transaction => {
                in_transaction = true;
                ops.push(PatchOp::TransactionStart);
            }
            1 if in_transaction => {
                in_transaction = false;
                ops.push(PatchOp::TransactionCommit);
            }
            2 if in_transaction => {
                in_transaction = false;
                ops.push(PatchOp::TransactionAbort);
            }
            _ => {
                let count = 1 + rng.below(4);
                let quads = gen_quads(rng, count, quoted_depth);
                let batch = batch_of(&quads);
                ops.push(if rng.chance(2) {
                    PatchOp::Add(batch)
                } else {
                    PatchOp::Delete(batch)
                });
            }
        }
    }
    if in_transaction {
        ops.push(PatchOp::TransactionCommit);
    }
    ops
}

#[test]
fn fuzz_patch_round_trip() {
    for iteration in 0..PATCH_ROUND_TRIP_ITERATIONS {
        let seed = PATCH_ROUND_TRIP_SEED ^ iteration.wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
        guarded("patch_round_trip", seed, || {
            let mut rng = Rng::new(seed);
            let max_prefix_table_size = *rng.pick(&[1_u32, 2, 8, 128]);
            let max_name_table_size = *rng.pick(&[8_u32, 16, 4000]);
            let max_datatype_table_size = *rng.pick(&[1_u32, 4, 32]);
            let rdf_star = rng.chance(2);
            let quoted_depth = if rdf_star { rng.below(3) } else { 0 };
            let encoder_options = JellyPatchEncoderOptions {
                max_prefix_table_size,
                max_name_table_size,
                max_datatype_table_size,
                rows_per_frame: *rng.pick(&[1_usize, 2, 5, 8192]),
                allow_provenance_loss: false,
                rdf_star,
                ..JellyPatchEncoderOptions::default()
            };
            let ops = gen_patch_ops(&mut rng, rdf_star, quoted_depth);

            let mut encoder =
                JellyPatchEncoder::new(encoder_options.clone()).expect("valid encoder options");
            let frames = match encoder.encode_ops(&ops) {
                Ok(frames) => frames,
                Err(error) => {
                    let mut again = JellyPatchEncoder::new(encoder_options.clone())
                        .expect("valid encoder options");
                    let repeat = again.encode_ops(&ops).err();
                    assert_eq!(
                        repeat.map(|repeat| format!("{}|{repeat}", repeat.code())),
                        Some(format!("{}|{error}", error.code())),
                        "seed 0x{seed:016x}: patch encode refusal is not deterministic"
                    );
                    assert!(
                        matches!(error, JellyError::ResourceLimit { .. }),
                        "seed 0x{seed:016x}: unexpected patch encode refusal: {error}"
                    );
                    return;
                }
            };
            encoder
                .finish()
                .unwrap_or_else(|error| panic!("seed 0x{seed:016x}: balanced patch: {error}"));

            let mut decoder = JellyPatchDecoder::new(JellyPatchDecoderOptions {
                max_prefix_table_size,
                max_name_table_size,
                max_datatype_table_size,
                quad_limits: QuadLimits::default(),
                ..JellyPatchDecoderOptions::default()
            });
            let mut decoded = Vec::new();
            for (index, frame) in frames.iter().enumerate() {
                let ops = decoder.decode_frame(frame).unwrap_or_else(|error| {
                    panic!(
                        "seed 0x{seed:016x}: frame {index} of a self-encoded patch was \
                         rejected: {error}"
                    )
                });
                for op in &ops {
                    if let PatchOp::Add(batch) | PatchOp::Delete(batch) = op {
                        assert_decoded_batch_clean(
                            batch,
                            &format!("seed 0x{seed:016x} patch frame {index}"),
                        );
                    }
                }
                decoded.extend(ops);
            }
            decoder
                .finish()
                .unwrap_or_else(|error| panic!("seed 0x{seed:016x}: balanced patch: {error}"));

            assert_eq!(
                events_of(&decoded),
                events_of(&ops),
                "seed 0x{seed:016x}: patch round trip changed the operation sequence"
            );
        });
    }
}

// ---------------------------------------------------------------------------
// Target 5 — patch decoder over random and hostile input
// ---------------------------------------------------------------------------

/// Seed for [`fuzz_patch_frame_hostile`].
const PATCH_HOSTILE_SEED: u64 = 0x0FF1_CE00_DEAD_2BAD;

/// Cases for [`fuzz_patch_frame_hostile`].
const PATCH_HOSTILE_ITERATIONS: u64 = 1200;

/// Decodes a patch frame twice through fresh decoders, checking invariants.
fn probe_patch_frame(seed: u64, frame: &RdfPatchFrame, options: &JellyPatchDecoderOptions) {
    let mut first_decoder = JellyPatchDecoder::new(options.clone());
    let first = first_decoder.decode_frame(frame);
    let mut second_decoder = JellyPatchDecoder::new(options.clone());
    let second = second_decoder.decode_frame(frame);
    assert_eq!(
        outcome(&first),
        outcome(&second),
        "seed 0x{seed:016x}: patch decoding is not deterministic"
    );
    assert_eq!(
        outcome(&first_decoder.finish()),
        outcome(&second_decoder.finish()),
        "seed 0x{seed:016x}: patch end-of-stream check is not deterministic"
    );
    if let Ok(ops) = first {
        let statement_rows = frame
            .rows
            .iter()
            .filter(|row| {
                matches!(
                    row.row,
                    Some(
                        rdf_patch_row::Row::StatementAdd(_)
                            | rdf_patch_row::Row::StatementDelete(_)
                    )
                )
            })
            .count();
        let mut decoded_quads = 0;
        for op in &ops {
            if let PatchOp::Add(batch) | PatchOp::Delete(batch) = op {
                decoded_quads += batch.num_rows();
                assert_decoded_batch_clean(batch, &format!("seed 0x{seed:016x} patch"));
            }
        }
        assert!(
            decoded_quads <= statement_rows,
            "seed 0x{seed:016x}: patch decoder invented {decoded_quads} quads from \
             {statement_rows} statement rows"
        );
    }
}

/// Builds a well-formed patch frame to mutate.
fn gen_base_patch_frame(rng: &mut Rng) -> RdfPatchFrame {
    let ops = gen_patch_ops(rng, true, 2);
    let mut encoder = JellyPatchEncoder::new(JellyPatchEncoderOptions {
        rdf_star: true,
        rows_per_frame: 8192,
        ..JellyPatchEncoderOptions::default()
    })
    .expect("valid encoder options");
    let mut frames = encoder
        .encode_ops(&ops)
        .unwrap_or_else(|_| vec![RdfPatchFrame { rows: Vec::new() }]);
    frames.pop().unwrap_or(RdfPatchFrame { rows: Vec::new() })
}

/// Returns the frame's patch options row, or a plausible default.
fn patch_options_of(frame: &RdfPatchFrame) -> RdfPatchOptions {
    frame
        .rows
        .iter()
        .find_map(|row| match &row.row {
            Some(rdf_patch_row::Row::Options(options)) => Some(*options),
            _ => None,
        })
        .unwrap_or(RdfPatchOptions {
            statement_type: PatchStatementType::Quads.into(),
            stream_type: PatchStreamType::Flat.into(),
            generalized_statements: false,
            rdf_star: false,
            max_name_table_size: 4000,
            max_prefix_table_size: 128,
            max_datatype_table_size: 32,
            version: PATCH_PROTOCOL_VERSION,
        })
}

/// Replaces the frame's patch options row in place.
fn set_patch_options(frame: &mut RdfPatchFrame, options: RdfPatchOptions) {
    for row in &mut frame.rows {
        if matches!(row.row, Some(rdf_patch_row::Row::Options(_))) {
            row.row = Some(rdf_patch_row::Row::Options(options));
            return;
        }
    }
    frame.rows.insert(
        0,
        RdfPatchRow {
            row: Some(rdf_patch_row::Row::Options(options)),
        },
    );
}

/// Number of distinct mutations [`mutate_patch_frame`] can apply.
const PATCH_MUTATION_KINDS: usize = 14;

/// Applies exactly one targeted mutation to a patch frame.
fn mutate_patch_frame(rng: &mut Rng, frame: &mut RdfPatchFrame, kind: usize) {
    match kind {
        0 => frame
            .rows
            .retain(|row| !matches!(row.row, Some(rdf_patch_row::Row::Options(_)))),
        1 => {
            let options = patch_options_of(frame);
            frame.rows.push(RdfPatchRow {
                row: Some(rdf_patch_row::Row::Options(options)),
            });
        }
        2 => {
            let mut options = patch_options_of(frame);
            options.version = *rng.pick(&[0_u32, 2, 3, 9999, 10_000, u32::MAX]);
            set_patch_options(frame, options);
        }
        3 => {
            let mut options = patch_options_of(frame);
            options.statement_type = *rng.pick(&[0_i32, 1, 2, 5, -1]);
            set_patch_options(frame, options);
        }
        4 => {
            let mut options = patch_options_of(frame);
            options.stream_type = *rng.pick(&[0_i32, 1, 2, 3, 7, -3]);
            set_patch_options(frame, options);
        }
        5 => {
            let mut options = patch_options_of(frame);
            options.max_name_table_size = rng.boundary_u32();
            options.max_prefix_table_size = rng.boundary_u32();
            options.max_datatype_table_size = rng.boundary_u32();
            set_patch_options(frame, options);
        }
        // A transaction opened and never committed: `finish` must refuse.
        6 => frame.rows.push(RdfPatchRow {
            row: Some(rdf_patch_row::Row::TransactionStart(
                RdfPatchTransactionStart {},
            )),
        }),
        // Commit or abort with no open transaction, and ops after an abort.
        7 => {
            frame.rows.push(RdfPatchRow {
                row: Some(if rng.chance(2) {
                    rdf_patch_row::Row::TransactionCommit(RdfPatchTransactionCommit {})
                } else {
                    rdf_patch_row::Row::TransactionAbort(RdfPatchTransactionAbort {})
                }),
            });
            frame.rows.push(RdfPatchRow {
                row: Some(rdf_patch_row::Row::StatementAdd(RdfQuad {
                    subject: None,
                    predicate: None,
                    object: None,
                    graph: None,
                })),
            });
        }
        // Header placement and content violations.
        8 => frame.rows.push(RdfPatchRow {
            row: Some(rdf_patch_row::Row::Header(RdfPatchHeader {
                key: (*rng.pick(&["", "k"])).to_owned(),
                value: if rng.chance(3) {
                    None
                } else {
                    Some(match rng.below(4) {
                        0 => rdf_patch_header::Value::HIri(RdfIri {
                            prefix_id: rng.boundary_u32(),
                            name_id: rng.boundary_u32(),
                        }),
                        1 => rdf_patch_header::Value::HBnode(
                            (*rng.pick(&["", "b1", "-x"])).to_owned(),
                        ),
                        2 => rdf_patch_header::Value::HLiteral(RdfLiteral {
                            lex: "v".to_owned(),
                            literal_kind: Some(rdf_literal::LiteralKind::Datatype(
                                rng.boundary_u32(),
                            )),
                        }),
                        _ => rdf_patch_header::Value::HTripleTerm(nested_triple(1 + rng.below(64))),
                    })
                },
            })),
        }),
        // Row kinds the FLAT/QUADS patch decoder refuses.
        9 => frame.rows.push(RdfPatchRow {
            row: Some(rdf_patch_row::Row::Punctuation(RdfPatchPunctuation {})),
        }),
        10 => frame.rows.push(RdfPatchRow {
            row: Some(if rng.chance(2) {
                rdf_patch_row::Row::NamespaceAdd(RdfPatchNamespace {
                    name: "ex".to_owned(),
                    value: None,
                    graph: None,
                })
            } else {
                rdf_patch_row::Row::NamespaceDelete(RdfPatchNamespace {
                    name: String::new(),
                    value: None,
                    graph: None,
                })
            }),
        }),
        11 => frame.rows.push(RdfPatchRow { row: None }),
        // Lookup entry identifier corruption.
        12 => {
            for row in &mut frame.rows {
                match &mut row.row {
                    Some(rdf_patch_row::Row::Name(entry)) => entry.id = rng.boundary_u32(),
                    Some(rdf_patch_row::Row::Prefix(entry)) => entry.id = rng.boundary_u32(),
                    Some(rdf_patch_row::Row::Datatype(entry)) => entry.id = rng.boundary_u32(),
                    _ => {}
                }
            }
        }
        // Drop every entry row so statement rows reference unset ids.
        _ => frame.rows.retain(|row| {
            !matches!(
                row.row,
                Some(
                    rdf_patch_row::Row::Name(_)
                        | rdf_patch_row::Row::Prefix(_)
                        | rdf_patch_row::Row::Datatype(_)
                )
            )
        }),
    }
}

#[test]
fn fuzz_patch_frame_hostile() {
    for iteration in 0..PATCH_HOSTILE_ITERATIONS {
        let seed = PATCH_HOSTILE_SEED ^ iteration.wrapping_mul(0x8EBC_6AF0_9C88_C6E3);
        guarded("patch_frame_hostile", seed, || {
            let mut rng = Rng::new(seed);
            let options = JellyPatchDecoderOptions {
                quad_limits: QuadLimits {
                    max_quads: *rng.pick(&[1_usize, 3, 1_000_000]),
                    max_quoted_depth: *rng.pick(&[0_usize, 1, 8]),
                    ..QuadLimits::default()
                },
                ..JellyPatchDecoderOptions::default()
            };

            if rng.chance(3) {
                // Unstructured and corrupted bytes straight at the patch
                // frame decoder.
                let base = gen_base_patch_frame(&mut rng).encode_to_vec();
                let bytes = if rng.chance(2) {
                    gen_dumb_bytes(&mut rng)
                } else {
                    corrupt_bytes(&mut rng, &base, &base)
                };
                if let Ok(frame) = RdfPatchFrame::decode(bytes.as_slice()) {
                    probe_patch_frame(seed, &frame, &options);
                }
                return;
            }

            let mut frame = gen_base_patch_frame(&mut rng);
            let mutation = rng.below(PATCH_MUTATION_KINDS);
            mutate_patch_frame(&mut rng, &mut frame, mutation);
            probe_patch_frame(seed, &frame, &options);

            let bytes = frame.encode_to_vec();
            if !bytes.is_empty() {
                let mut truncated = bytes;
                truncated.truncate(rng.below(truncated.len()));
                if let Ok(frame) = RdfPatchFrame::decode(truncated.as_slice()) {
                    probe_patch_frame(seed, &frame, &options);
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Bounded-work tests (invariant 2), pinned rather than sampled
// ---------------------------------------------------------------------------

/// Builds a minimal frame carrying `options` plus `rows`.
fn frame_with(options: RdfStreamOptions, rows: Vec<RdfStreamRow>) -> RdfStreamFrame {
    let mut all = vec![RdfStreamRow {
        row: Some(rdf_stream_row::Row::Options(options)),
    }];
    all.extend(rows);
    RdfStreamFrame {
        rows: all,
        metadata: std::collections::HashMap::new(),
    }
}

/// A frame that declares `u32::MAX` table slots must be refused *before* the
/// decoder allocates them; if the check moved after allocation this test
/// would exhaust memory rather than fail.
#[test]
fn declared_table_sizes_are_refused_before_allocation() {
    for (prefix, name, datatype) in [
        (u32::MAX, 4000, 32),
        (128, u32::MAX, 32),
        (128, 4000, u32::MAX),
    ] {
        let options = RdfStreamOptions {
            stream_name: String::new(),
            physical_type: PhysicalStreamType::Quads.into(),
            generalized_statements: false,
            rdf_star: false,
            max_name_table_size: name,
            max_prefix_table_size: prefix,
            max_datatype_table_size: datatype,
            logical_type: LogicalStreamType::FlatQuads.into(),
            version: PROTOCOL_VERSION,
        };
        let frame = frame_with(options, Vec::new());
        let error = JellyDecoder::new(JellyDecoderOptions::default())
            .decode_frame(&frame)
            .expect_err("hostile table size must be refused");
        assert!(
            matches!(error, JellyError::ResourceLimit { .. }),
            "expected a resource limit, got {error}"
        );
    }
}

/// Triple-term nesting deeper than `max_quoted_depth` must trip the limit
/// before the recursive decoder walks the chain.
#[test]
fn triple_term_depth_is_refused_before_recursion() {
    let options = RdfStreamOptions {
        stream_name: String::new(),
        physical_type: PhysicalStreamType::Quads.into(),
        generalized_statements: false,
        rdf_star: true,
        max_name_table_size: 4000,
        max_prefix_table_size: 128,
        max_datatype_table_size: 32,
        logical_type: LogicalStreamType::FlatQuads.into(),
        version: PROTOCOL_VERSION,
    };
    let frame = frame_with(
        options,
        vec![
            RdfStreamRow {
                row: Some(rdf_stream_row::Row::Prefix(RdfPrefixEntry {
                    id: 1,
                    value: "http://example.com/".to_owned(),
                })),
            },
            RdfStreamRow {
                row: Some(rdf_stream_row::Row::Name(RdfNameEntry {
                    id: 1,
                    value: "x".to_owned(),
                })),
            },
            RdfStreamRow {
                row: Some(rdf_stream_row::Row::Quad(RdfQuad {
                    subject: Some(rdf_quad::Subject::SIri(RdfIri {
                        prefix_id: 1,
                        name_id: 1,
                    })),
                    predicate: Some(rdf_quad::Predicate::PIri(RdfIri {
                        prefix_id: 1,
                        name_id: 1,
                    })),
                    object: Some(rdf_quad::Object::OTripleTerm(nested_triple(200))),
                    graph: Some(rdf_quad::Graph::GDefaultGraph(RdfDefaultGraph {})),
                })),
            },
        ],
    );
    let error = JellyDecoder::new(JellyDecoderOptions::default())
        .decode_frame(&frame)
        .expect_err("200 levels of nesting must be refused");
    assert_eq!(error.code(), "resource_limit", "got {error}");
}

/// More statement rows than `QuadLimits::max_quads` allows must fail closed
/// on the batch limit rather than growing the batch without bound.
#[test]
fn quads_beyond_the_batch_limit_are_refused() {
    let quads = gen_quads(&mut Rng::new(0x51E5_1234_5678_9ABC), 12, 0);
    let batch = batch_of(&quads);
    let mut encoder = JellyEncoder::new(JellyEncoderOptions::default()).expect("valid options");
    let frames = encoder.encode_batch(&batch).expect("batch encodes");
    let mut decoder = JellyDecoder::new(JellyDecoderOptions {
        quad_limits: QuadLimits {
            max_quads: 4,
            ..QuadLimits::default()
        },
        ..JellyDecoderOptions::default()
    });
    let error = decoder
        .decode_frame(&frames[0])
        .expect_err("12 quads must not fit a 4-quad budget");
    assert_eq!(error.code(), "quad", "got {error}");
}

// ---------------------------------------------------------------------------
// Regression: lookup identifier reassignment inside one statement row
// ---------------------------------------------------------------------------

/// The case [`fuzz_rdf_round_trip`] discovered, replayed by its exact seed.
///
/// Seed `0x582994cc693d32eb` (iteration 7 of [`fuzz_rdf_round_trip`]) draws
/// a one-entry prefix table and an eight-entry name table. Before the fix, encoding it produced a stream
/// that decoded *without any error* into different IRIs: every lookup entry
/// row for a statement precedes that statement on the wire, so when a
/// statement's terms needed more distinct prefixes than the table held, the
/// encoder emitted two entry rows claiming the same identifier and the
/// decoder — which resolves a statement's identifiers at the statement row,
/// as the wire format requires — saw only the later value. Jelly's
/// identifier reassignment is defined *between* rows; there is no encoding
/// for "one row, one identifier, two values", so the encoder now fails
/// closed rather than emitting a stream that means something else.
#[test]
fn regression_round_trip_seed_582994cc693d32eb() {
    let seed = 0x5829_94cc_693d_32eb_u64;
    let mut rng = Rng::new(seed);
    let case = gen_round_trip_case(&mut rng);
    assert_eq!(
        case.encoder.max_prefix_table_size, 1,
        "the discovering seed must still draw the one-entry prefix table"
    );
    match encode_case(&case) {
        Err(JellyError::ResourceLimit { .. }) => {}
        Err(other) => panic!("expected a resource limit, got {other}"),
        Ok(frames) => {
            // Encoding is only allowed to succeed if the round trip is exact.
            let mut decoder = JellyDecoder::new(case.decoder.clone());
            let mut decoded = Vec::new();
            for frame in &frames {
                decoded.extend(quads_of(
                    &decoder.decode_frame(frame).expect("self-encoded frame"),
                ));
            }
            assert_eq!(
                decoded, case.quads,
                "seed 0x{seed:016x} silently rewrote quads"
            );
        }
    }
}

/// The minimized form of the same defect: one quad, three distinct prefixes,
/// a one-entry prefix table.
#[test]
fn regression_lookup_reassignment_within_one_statement_is_refused() {
    let quad = Quad::new(
        NamedNode::new("http://alpha.example/x").expect("valid IRI"),
        NamedNode::new("http://beta.example/y").expect("valid IRI"),
        NamedNode::new("http://gamma.example/z").expect("valid IRI"),
        GraphName::DefaultGraph,
    );
    let batch = batch_of(std::slice::from_ref(&quad));
    let mut encoder = JellyEncoder::new(JellyEncoderOptions {
        max_prefix_table_size: 1,
        ..JellyEncoderOptions::default()
    })
    .expect("valid options");
    let error = encoder
        .encode_batch(&batch)
        .expect_err("three distinct prefixes cannot share a one-entry table");
    assert!(
        matches!(
            error,
            JellyError::ResourceLimit {
                resource: jelly_fast_core::JellyResource::PrefixTable,
                ..
            }
        ),
        "expected a prefix-table resource limit, got {error}"
    );
}

/// The boundary case the refusal must not swallow: a statement whose distinct
/// prefix count exactly equals the table capacity still round-trips.
#[test]
fn regression_statement_at_exact_table_capacity_round_trips() {
    let quad = Quad::new(
        NamedNode::new("http://alpha.example/x").expect("valid IRI"),
        NamedNode::new("http://beta.example/y").expect("valid IRI"),
        NamedNode::new("http://gamma.example/z").expect("valid IRI"),
        GraphName::NamedNode(NamedNode::new("http://delta.example/g").expect("valid IRI")),
    );
    let batch = batch_of(std::slice::from_ref(&quad));
    let options = JellyEncoderOptions {
        max_prefix_table_size: 4,
        max_name_table_size: 8,
        ..JellyEncoderOptions::default()
    };
    let mut encoder = JellyEncoder::new(options).expect("valid options");
    let frames = encoder
        .encode_batch(&batch)
        .expect("exactly four prefixes fit");
    let mut decoder = JellyDecoder::new(JellyDecoderOptions {
        max_prefix_table_size: 4,
        max_name_table_size: 8,
        ..JellyDecoderOptions::default()
    });
    let decoded = decoder.decode_frame(&frames[0]).expect("frame decodes");
    assert_eq!(quads_of(&decoded), vec![quad]);
}

/// The same defect on the patch codec's statement rows, which share
/// `terms.rs` with the RDF stream codec.
#[test]
fn regression_patch_lookup_reassignment_within_one_statement_is_refused() {
    let quad = Quad::new(
        NamedNode::new("http://alpha.example/x").expect("valid IRI"),
        NamedNode::new("http://beta.example/y").expect("valid IRI"),
        NamedNode::new("http://gamma.example/z").expect("valid IRI"),
        GraphName::DefaultGraph,
    );
    let batch = batch_of(std::slice::from_ref(&quad));
    let mut encoder = JellyPatchEncoder::new(JellyPatchEncoderOptions {
        max_prefix_table_size: 1,
        ..JellyPatchEncoderOptions::default()
    })
    .expect("valid options");
    let error = encoder
        .encode_ops(&[PatchOp::Add(batch)])
        .expect_err("three distinct prefixes cannot share a one-entry table");
    assert_eq!(error.code(), "resource_limit", "got {error}");
}

/// Seeds for the patch mutation smoke: encoder output for generated ops.
fn patch_seed_corpus() -> Vec<Vec<u8>> {
    let mut rng = Rng::new(0x5EED_0000_DA7A_0001);
    let mut corpus = Vec::new();
    for rdf_star in [false, true] {
        for _ in 0..8 {
            let ops = gen_patch_ops(&mut rng, rdf_star, usize::from(rdf_star) * 2);
            let Ok(mut encoder) = JellyPatchEncoder::new(JellyPatchEncoderOptions {
                rdf_star,
                ..JellyPatchEncoderOptions::default()
            }) else {
                continue;
            };
            if let Ok(frames) = encoder.encode_ops(&ops) {
                corpus.extend(frames.iter().map(Message::encode_to_vec));
            }
        }
    }
    corpus
}

/// Mutated encoder output through every public decode entry point
/// (`RdfStreamFrame::decode` then `JellyDecoder::decode_frame` over a
/// two-frame stream; `RdfPatchFrame::decode` then
/// `JellyPatchDecoder::decode_frame` and `finish`), with bytes flipped,
/// truncated, duplicated, and inserted, on a 256 KiB thread under the
/// 1 GiB allocation cap: no panic, no abort.
#[test]
fn mutation_smoke_on_a_small_stack_under_the_allocation_cap() {
    smoke::run_on_small_stack(|| {
        let stream_seeds = seed_corpus();
        let first = stream_seeds.first().cloned().unwrap_or_default();
        smoke::assert_no_panics("jelly-stream", &stream_seeds, 10_000, |bytes| {
            let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
            if let Ok(frame) = RdfStreamFrame::decode(first.as_slice()) {
                let _ = decoder.decode_frame(&frame);
            }
            if let Ok(frame) = RdfStreamFrame::decode(bytes) {
                let _ = decoder.decode_frame(&frame);
                let _ = JellyDecoder::new(JellyDecoderOptions::default()).decode_frame(&frame);
            }
        });
        let patch_seeds = patch_seed_corpus();
        assert!(!patch_seeds.is_empty(), "patch encoder produced no seeds");
        smoke::assert_no_panics("jelly-patch", &patch_seeds, 10_000, |bytes| {
            if let Ok(frame) = RdfPatchFrame::decode(bytes) {
                let mut decoder = JellyPatchDecoder::new(JellyPatchDecoderOptions::default());
                let _ = decoder.decode_frame(&frame);
                let _ = decoder.finish();
            }
        });
    });
}
