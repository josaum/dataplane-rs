// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Deterministic, seeded fuzz harness for the CBOR reader and CBOR-LD layer.
//!
//! Everything here runs under an ordinary `cargo test`: no nightly, no
//! `cargo-fuzz`, no `arbitrary`/`proptest`/`quickcheck`. Randomness comes
//! from `Rng`, an xorshift64 generator seeded by the compile-time
//! constants in `SEEDS`, so a failure is reproducible by re-running the
//! same test and every assertion message carries its seed and input.
//!
//! # Iteration budget
//!
//! Roughly 33,000 cases total in debug mode, split as: 8,000 dumb-byte
//! decodes; 3,000 structure-aware CBOR values, each round-tripped and then
//! decoded again under four byte mutations (12,000 mutant decodes); 2,000
//! hostile CBOR-LD envelopes decompressed under two option sets; and 1,400
//! generated JSON-LD documents round-tripped, each of whose *real*
//! envelopes is then mutated three more ways. The whole file runs in about
//! a second; the counts are sized to stay well inside a five-second budget
//! even on a machine that is busy compiling something else.
//!
//! # Invariants asserted
//!
//! 1. **Never panic.** Every call into the crate runs inside `guard`,
//!    which converts a panic into a failure that names the seed and the
//!    input. Malformed input must produce a typed `CborldError`.
//! 2. **Bounded work.** Inputs are capped at `FUZZ_MAX_INPUT` bytes and
//!    limits are tightened, so a declared length or nesting depth beyond
//!    budget must trip a typed error *before* the allocation or the
//!    recursion, not after. `check_cbor_bytes` additionally proves
//!    the decoder cannot inflate its input: the canonical re-encoding of
//!    anything it accepts is never longer than the bytes it accepted.
//! 3. **Round-trip.** `encode_canonical` → `decode` → `encode_canonical` is
//!    a fixed point at the CBOR layer, and `decompress(compress(doc))` is
//!    byte-for-byte `doc` at the CBOR-LD layer.
//! 4. **Idempotent refusal.** Every input is processed twice and the two
//!    outcomes must be identical, error text included.
//! 5. **No silent mutation.** The round-trip comparisons are exact JSON and
//!    exact byte equality, so a dropped, invented, or altered member fails.
//!
//! # Regression seeds
//!
//! `cross_scope_term_reuse_round_trips` pins the defect this harness was
//! written against: a term name reused in a sibling subtree's `@context`
//! made the compressor emit an identifier the decompressor had not yet
//! assigned, so `compress` succeeded and `decompress` failed with
//! `unknown_term_id`. The generator in `generated_documents_round_trip`
//! produces that shape by construction (see `TERM_NAMES`), so the class
//! stays covered and not just the one document.

use std::fmt::Write as _;

use cborld_fast_core::{
    CborldOptions, CompressionMode, ProvidedContexts, ProvisionalEntries,
    cbor::{CborLimits, CborValue, decode, encode_canonical},
    compress, decompress,
};
use serde_json::{Map, Value, json};

/// Constant seeds; every test derives its stream from one of these.
///
/// The values are arbitrary odd 64-bit constants. They must stay constant:
/// a time- or thread-derived seed would make a discovery unreproducible,
/// which is the one thing this harness cannot afford.
const SEEDS: [u64; 4] = [
    0x0BAD_C0DE_DEAD_BEEF,
    0x5EED_1234_9876_ABCD,
    0xCB1D_CB1D_CB1D_CB1D,
    0x0123_4567_89AB_CDEF,
];

/// Largest fuzz input in bytes; keeps one case's work bounded and small.
const FUZZ_MAX_INPUT: usize = 1024;

/// Limits for the document round-trip fuzzer.
///
/// `max_input_bytes` governs the *decoder* only — `compress` has no input
/// budget — so the round-trip fuzzer must leave room for the envelope a
/// generated document produces. Depth and value budgets stay tight; only
/// the input ceiling is raised, to 64 KiB.
fn document_limits() -> CborLimits {
    CborLimits {
        max_input_bytes: 64 * 1024,
        ..fuzz_limits()
    }
}

/// Tightened limits for fuzzing: small enough that a limit trip is cheap.
fn fuzz_limits() -> CborLimits {
    CborLimits {
        max_input_bytes: FUZZ_MAX_INPUT,
        max_depth: 16,
        max_items: 4096,
        max_value_bytes: 256,
    }
}

// ---------------------------------------------------------------------------
// Deterministic PRNG
// ---------------------------------------------------------------------------

/// Seeded xorshift64 generator: reproducible, allocation-free, no I/O.
struct Rng {
    state: u64,
}

impl Rng {
    /// Creates a generator for `seed` (zero is remapped, xorshift fixes it).
    const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    /// Returns the next 64-bit output of the xorshift64 recurrence.
    fn next_u64(&mut self) -> u64 {
        let mut state = self.state;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.state = state;
        state
    }

    /// Returns a value in `0..bound`; `bound` of zero yields zero.
    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        usize::try_from(self.next_u64() % bound as u64).unwrap_or(0)
    }

    /// Returns one pseudo-random byte.
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }

    /// Returns `true` with probability `1 / one_in`.
    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }

    /// Returns a reference to one element of `items`.
    fn pick<'items, T>(&mut self, items: &'items [T]) -> &'items T {
        &items[self.below(items.len())]
    }
}

// ---------------------------------------------------------------------------
// Panic guard and formatting helpers
// ---------------------------------------------------------------------------

/// Runs `body`, turning any panic into a failure naming seed and input.
///
/// # Panics
///
/// Panics when `body` panics, which is itself the defect being reported:
/// the crate must return a typed error for every input, never unwind.
fn guard<T>(seed: u64, what: &str, input: &str, body: impl FnOnce() -> T) -> T {
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    match caught {
        Ok(value) => value,
        Err(_payload) => panic!(
            "PANIC in {what} — malformed input must be a typed error, never an unwind\n  \
             seed  = {seed:#018x}\n  input = {input}"
        ),
    }
}

/// Lowercase hex rendering of `bytes` for reproducible failure messages.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// Comparable outcome of one fallible call: canonical bytes, or error text.
type Outcome = Result<Vec<u8>, String>;

// ---------------------------------------------------------------------------
// Byte-level codec helpers (canonical inputs the crate's own are private)
// ---------------------------------------------------------------------------

/// base58btc alphabet, matching `cborld_fast_core::registry`.
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encodes `bytes` as canonical base58btc, so generated `did:`/multibase
/// values actually take the compressing branch instead of passing through.
fn base58_encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut().rev() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.insert(0, (carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for digit in digits {
        out.push(char::from(BASE58[usize::from(digit)]));
    }
    out
}

/// Encodes `bytes` with `alphabet`, padding to a multiple of four when asked.
fn base64_encode(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = chunk.get(1).map(|byte| u32::from(*byte));
        let third = chunk.get(2).map(|byte| u32::from(*byte));
        out.push(char::from(alphabet[(first >> 2) as usize]));
        out.push(char::from(
            alphabet[((first << 4 | second.unwrap_or(0) >> 4) & 0x3f) as usize],
        ));
        match second {
            Some(second) => out.push(char::from(
                alphabet[((second << 2 | third.unwrap_or(0) >> 6) & 0x3f) as usize],
            )),
            None if pad => out.push('='),
            None => {}
        }
        match third {
            Some(third) => out.push(char::from(alphabet[(third & 0x3f) as usize])),
            None if pad => out.push('='),
            None => {}
        }
    }
    out
}

/// RFC 4648 §4 padded encode, for `data:` URL payloads.
fn base64_std(bytes: &[u8]) -> String {
    base64_encode(
        bytes,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        true,
    )
}

/// RFC 4648 §5 unpadded encode, for multibase `u` values.
fn base64_url(bytes: &[u8]) -> String {
    base64_encode(
        bytes,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        false,
    )
}

// ---------------------------------------------------------------------------
// Invariant checks — CBOR layer
// ---------------------------------------------------------------------------

/// Decodes `bytes` and returns the canonical re-encoding, or the error text.
///
/// A successful decode whose value cannot be re-encoded is a defect in its
/// own right (the decoder would have accepted something the encoder cannot
/// express), so this reports it as a failure rather than folding it into
/// the error branch.
fn decode_outcome(seed: u64, bytes: &[u8], limits: &CborLimits) -> Outcome {
    let label = hex(bytes);
    let decoded = guard(seed, "cbor::decode", &label, || decode(bytes, limits));
    match decoded {
        Ok(value) => {
            let encoded = guard(seed, "cbor::encode_canonical", &label, || {
                encode_canonical(&value, limits)
            });
            match encoded {
                Ok(canonical) => Ok(canonical),
                Err(error) => panic!(
                    "decode accepted an item encode_canonical refuses: {error}\n  \
                     seed  = {seed:#018x}\n  input = {label}"
                ),
            }
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Asserts every CBOR-layer invariant for one input byte string.
///
/// Checks, in order: no panic (via [`decode_outcome`]), idempotent refusal,
/// no amplification, and canonical-form fixed point.
fn check_cbor_bytes(seed: u64, bytes: &[u8], limits: &CborLimits) {
    let label = hex(bytes);
    let first = decode_outcome(seed, bytes, limits);
    let second = decode_outcome(seed, bytes, limits);
    assert_eq!(
        first, second,
        "nondeterministic decode: the same bytes gave two outcomes\n  \
         seed  = {seed:#018x}\n  input = {label}"
    );
    let Ok(canonical) = first else {
        return;
    };
    assert!(
        canonical.len() <= bytes.len(),
        "decode amplified its input: {} accepted bytes re-encode to {}\n  \
         seed  = {seed:#018x}\n  input = {label}",
        bytes.len(),
        canonical.len()
    );
    let again = decode_outcome(seed, &canonical, limits);
    assert_eq!(
        again,
        Ok(canonical.clone()),
        "canonical form is not a fixed point\n  seed  = {seed:#018x}\n  input = {label}"
    );
}

// ---------------------------------------------------------------------------
// Structure-aware CBOR generation and mutation
// ---------------------------------------------------------------------------

/// Integer arguments that sit on a CBOR head boundary, plus the extremes.
const BOUNDARY_ARGUMENTS: [u64; 13] = [
    0,
    1,
    23,
    24,
    255,
    256,
    65_535,
    65_536,
    4_294_967_295,
    4_294_967_296,
    i64::MAX as u64,
    i64::MAX as u64 + 1,
    u64::MAX,
];

/// Floats that exercise every branch of the preferred-serialization rules.
const BOUNDARY_FLOATS: [f64; 10] = [
    0.0,
    -0.0,
    1.0,
    -1.0,
    65_504.0,
    5.960_464_477_539_063e-8,
    1.0e300,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
];

/// Returns a boundary-heavy 64-bit argument.
fn gen_argument(rng: &mut Rng) -> u64 {
    if rng.chance(3) {
        rng.next_u64()
    } else {
        *rng.pick(&BOUNDARY_ARGUMENTS)
    }
}

/// Returns a short byte string.
fn gen_bytes(rng: &mut Rng, max: usize) -> Vec<u8> {
    let length = rng.below(max + 1);
    (0..length).map(|_| rng.byte()).collect()
}

/// Returns a short text string, sometimes with non-ASCII scalars.
fn gen_text(rng: &mut Rng) -> String {
    let length = rng.below(6);
    (0..length)
        .map(|_| {
            if rng.chance(4) {
                *rng.pick(&['é', 'λ', '𝄞', '\u{0}'])
            } else {
                char::from(b'a' + u8::try_from(rng.below(26)).unwrap_or(0))
            }
        })
        .collect()
}

/// Generates one CBOR value; recursion stops at `depth` four.
fn gen_cbor(rng: &mut Rng, depth: usize, limits: &CborLimits) -> CborValue {
    let leaves = 7;
    let choice = if depth >= 4 {
        rng.below(leaves)
    } else {
        rng.below(leaves + 3)
    };
    match choice {
        0 => CborValue::Unsigned(gen_argument(rng)),
        1 => CborValue::Negative(gen_argument(rng)),
        2 => CborValue::Bytes(gen_bytes(rng, 8)),
        3 => CborValue::Text(gen_text(rng)),
        4 => CborValue::Bool(rng.chance(2)),
        5 => CborValue::Null,
        6 => CborValue::Float(if rng.chance(3) {
            f64::from_bits(rng.next_u64())
        } else {
            *rng.pick(&BOUNDARY_FLOATS)
        }),
        7 => CborValue::Tag(
            gen_argument(rng),
            Box::new(gen_cbor(rng, depth + 1, limits)),
        ),
        8 => {
            let count = rng.below(4);
            CborValue::Array(
                (0..count)
                    .map(|_| gen_cbor(rng, depth + 1, limits))
                    .collect(),
            )
        }
        _ => gen_map(rng, depth, limits),
    }
}

/// Generates a map with distinct keys, so `encode_canonical` accepts it.
fn gen_map(rng: &mut Rng, depth: usize, limits: &CborLimits) -> CborValue {
    let count = rng.below(4);
    let mut entries: Vec<(CborValue, CborValue)> = Vec::with_capacity(count);
    let mut seen: Vec<Vec<u8>> = Vec::with_capacity(count);
    for _ in 0..count {
        let key = gen_cbor(rng, depth + 1, limits);
        let Ok(encoded) = encode_canonical(&key, limits) else {
            continue;
        };
        if seen.contains(&encoded) {
            continue;
        }
        seen.push(encoded);
        entries.push((key, gen_cbor(rng, depth + 1, limits)));
    }
    CborValue::Map(entries)
}

/// Applies one targeted mutation to well-formed bytes.
///
/// The mutation menu is the one the assignment names: truncation, bit
/// flips, an indefinite-length head spliced over a definite one, a length
/// field corrupted to a huge 64-bit argument, and inserted or appended
/// junk. Every mutant must still decode to a typed error or a value.
fn mutate(rng: &mut Rng, bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if out.is_empty() {
        out.push(rng.byte());
        return out;
    }
    let index = rng.below(out.len());
    match rng.below(6) {
        0 => out.truncate(index),
        1 => out[index] ^= 1 << rng.below(8),
        2 => out[index] = (out[index] & 0xe0) | 0x1f,
        3 => {
            out[index] = (out[index] & 0xe0) | 27;
            let huge = [0xff_u8; 8];
            out.splice(index + 1..index + 1, huge);
        }
        4 => out.push(rng.byte()),
        _ => out.insert(index, rng.byte()),
    }
    out.truncate(FUZZ_MAX_INPUT);
    out
}

// ---------------------------------------------------------------------------
// CBOR-LD envelope generation
// ---------------------------------------------------------------------------

/// Registry identifiers worth aiming an envelope at: the two reserved
/// entries, every vendored provisional entry, and identifiers that are not
/// vendored at all (including the `u64` extreme).
const ENVELOPE_ENTRY_IDS: [u64; 14] = [
    0,
    1,
    100,
    10_001,
    10_002,
    10_003,
    31_000_000,
    31_000_001,
    32_000_000,
    2,
    99,
    10_004,
    32_000_001,
    u64::MAX,
];

/// Generates a hostile compressed payload map: plausible keys, wild values.
fn gen_payload(rng: &mut Rng, depth: usize, limits: &CborLimits) -> CborValue {
    let count = rng.below(5);
    let mut entries: Vec<(CborValue, CborValue)> = Vec::with_capacity(count);
    let mut seen: Vec<Vec<u8>> = Vec::with_capacity(count);
    for _ in 0..count {
        let key = match rng.below(6) {
            // Singular and plural `@context` keys, including the illegal
            // "both at once" shape the decoder must refuse.
            0 => CborValue::Unsigned(u64::try_from(rng.below(2)).unwrap_or(0)),
            // Keyword ids, in both singular and plural spelling.
            1 => CborValue::Unsigned(u64::try_from(rng.below(56)).unwrap_or(0)),
            // Auto-assigned term ids, mostly ones no context defined.
            2 | 3 => CborValue::Unsigned(
                100 + u64::try_from(rng.below(24)).unwrap_or(0) * rng.below(3) as u64,
            ),
            4 => CborValue::Text(gen_text(rng)),
            _ => gen_cbor(rng, depth + 1, limits),
        };
        let Ok(encoded) = encode_canonical(&key, limits) else {
            continue;
        };
        if seen.contains(&encoded) {
            continue;
        }
        seen.push(encoded);
        entries.push((key, gen_payload_value(rng, depth, limits)));
    }
    CborValue::Map(entries)
}

/// Generates a value shaped like something a codec would have produced.
fn gen_payload_value(rng: &mut Rng, depth: usize, limits: &CborLimits) -> CborValue {
    match rng.below(10) {
        // URL codec arrays: valid and invalid prefix ids, wrong arities.
        0 | 1 => {
            let prefix = *rng.pick(&[1_u64, 2, 3, 4, 1024, 1025, 5, 0, u64::MAX]);
            let arity = rng.below(4);
            let mut items = vec![CborValue::Unsigned(prefix)];
            for _ in 0..arity {
                items.push(gen_cbor(rng, depth + 2, limits));
            }
            CborValue::Array(items)
        }
        // xsd:dateTime pairs, including the out-of-range millisecond field.
        2 => CborValue::Array(vec![
            CborValue::Unsigned(gen_argument(rng)),
            CborValue::Unsigned(*rng.pick(&[0_u64, 1, 999, 1000, 5000, u64::MAX])),
        ]),
        // Multibase byte strings, including unvendored header bytes.
        3 => {
            let mut bytes = vec![*rng.pick(&[b'z', b'u', b'b', b'f', 0])];
            bytes.extend(gen_bytes(rng, 12));
            CborValue::Bytes(bytes)
        }
        // Sub-table identifiers in both shapes, shortest and not.
        4 => CborValue::Bytes(gen_bytes(rng, 10)),
        5 => CborValue::Unsigned(gen_argument(rng)),
        6 if depth < 3 => gen_payload(rng, depth + 1, limits),
        _ => gen_cbor(rng, depth + 1, limits),
    }
}

/// Wraps `payload` in an envelope whose tag and arity may both be wrong.
fn gen_envelope(rng: &mut Rng, limits: &CborLimits) -> CborValue {
    let payload = if rng.chance(6) {
        gen_cbor(rng, 1, limits)
    } else {
        gen_payload(rng, 1, limits)
    };
    let tag = if rng.chance(5) {
        *rng.pick(&[0_u64, 1, 999, 51_996, 51_998, u64::MAX])
    } else {
        0xCB1D
    };
    let mut elements = vec![CborValue::Unsigned(*rng.pick(&ENVELOPE_ENTRY_IDS)), payload];
    match rng.below(8) {
        0 => {
            elements.truncate(1);
        }
        1 => elements.push(CborValue::Null),
        2 => elements[0] = CborValue::Text("1".to_string()),
        _ => {}
    }
    CborValue::Tag(tag, Box::new(CborValue::Array(elements)))
}

/// Options that accept every vendored provisional entry, for the branch of
/// the fuzzer that exercises sub-tables rather than the opt-in refusal.
fn permissive_options(limits: CborLimits) -> CborldOptions {
    let mut accepted = ProvisionalEntries::new();
    for id in [
        100, 10_001, 10_002, 10_003, 31_000_000, 31_000_001, 32_000_000,
    ] {
        accepted.accept(id);
    }
    CborldOptions {
        limits,
        accepted_provisional_entries: accepted,
        provided_contexts: registry_contexts(),
        ..CborldOptions::default()
    }
}

/// Caller-supplied content for the context IRIs the vendored entries list.
///
/// The codec never fetches, so a registry-compressed context is only usable
/// when its content is supplied here; each document is a small term map.
fn registry_contexts() -> ProvidedContexts {
    let mut provided = ProvidedContexts::new();
    for iri in [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/vc-barcodes/v1",
        "https://w3id.org/utopia/v2",
        "https://w3id.org/vdl/v1",
        "https://w3id.org/vdl/aamva/v1",
    ] {
        provided.insert(
            iri,
            json!({
                "name": "https://example.org/vocab#name",
                "proof": {"@id": "https://w3id.org/security#proof"},
                "cryptosuite": {
                    "@id": "https://w3id.org/security#cryptosuite",
                    "@type": "https://w3id.org/security#cryptosuiteString"
                }
            }),
        );
    }
    provided
}

/// Decompresses under `options`, returning a comparable outcome.
fn decompress_outcome(seed: u64, bytes: &[u8], options: &CborldOptions) -> Result<String, String> {
    let label = hex(bytes);
    let result = guard(seed, "decompress", &label, || decompress(bytes, options));
    match result {
        Ok(value) => Ok(value.to_string()),
        Err(error) => Err(format!("{}: {error}", error.code())),
    }
}

// ---------------------------------------------------------------------------
// JSON-LD document generation
// ---------------------------------------------------------------------------

/// Term names drawn on for generated contexts.
///
/// The pool is deliberately tiny so the same name recurs in a nested node's
/// `@context` while an ancestor or sibling also uses it — the shape that
/// produced the cross-scope identifier defect this harness pins.
const TERM_NAMES: [&str; 6] = ["alpha", "beta", "gamma", "delta", "alpha2", "b"];

/// JSON-LD `@type` values that select a value codec, plus the neutral ones.
const TERM_TYPES: [&str; 6] = [
    "@id",
    "@vocab",
    "http://www.w3.org/2001/XMLSchema#date",
    "http://www.w3.org/2001/XMLSchema#dateTime",
    "https://w3id.org/security#multibase",
    "https://w3id.org/security#cryptosuiteString",
];

/// Builds one inline `@context` object and returns it with its term names.
fn gen_context(rng: &mut Rng) -> (Value, Vec<String>) {
    let count = 1 + rng.below(3);
    let mut object = Map::new();
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        let name = (*rng.pick(&TERM_NAMES)).to_string();
        let iri = format!("https://example.org/vocab#{name}");
        let definition = match rng.below(5) {
            0 => Value::String(iri),
            1 => Value::Null,
            _ => {
                let mut members = Map::new();
                members.insert("@id".to_string(), Value::String(iri));
                if rng.chance(2) {
                    members.insert(
                        "@type".to_string(),
                        Value::String((*rng.pick(&TERM_TYPES)).to_string()),
                    );
                }
                Value::Object(members)
            }
        };
        if !matches!(definition, Value::Null) {
            names.push(name.clone());
        }
        object.insert(name, definition);
    }
    (Value::Object(object), names)
}

/// Generates one scalar value, weighted toward every codec's input shape.
fn gen_scalar(rng: &mut Rng) -> Value {
    match rng.below(20) {
        0 => Value::String(format!("plain-{}", rng.below(1000))),
        1 => Value::String(format!("http://example.org/{}", rng.below(1000))),
        2 => Value::String(format!("https://example.org/a/b/{}", rng.below(1000))),
        3 => Value::String("https://example.org:8443/with-port".to_string()),
        4 => Value::String(format!(
            "urn:uuid:{:08x}-0000-4000-8000-{:012x}",
            rng.below(0xffff_ffff),
            rng.below(0xffff_ffff)
        )),
        5 => Value::String("urn:uuid:NOT-A-UUID".to_string()),
        6 => Value::String(format!("did:key:z{}", base58_encode(&gen_bytes(rng, 24)))),
        7 => Value::String(format!(
            "did:v1:nym:z{}#z{}",
            base58_encode(&gen_bytes(rng, 12)),
            base58_encode(&gen_bytes(rng, 12))
        )),
        8 => Value::String("did:key:z0OIl-not-base58".to_string()),
        9 => Value::String(format!(
            "data:text/plain;base64,{}",
            base64_std(&gen_bytes(rng, 20))
        )),
        10 => Value::String("data:text/plain,literal;base64,junk".to_string()),
        11 => Value::String(format!("z{}", base58_encode(&gen_bytes(rng, 20)))),
        12 => Value::String(format!("u{}", base64_url(&gen_bytes(rng, 20)))),
        13 => Value::String("b-unknown-multibase-header".to_string()),
        14 => Value::String(
            (*rng.pick(&[
                "2026-09-01",
                "0000-01-01",
                "9999-12-31",
                "1969-12-31",
                "2026-13-45",
                "26-09-01",
            ]))
            .to_string(),
        ),
        15 => Value::String(
            (*rng.pick(&[
                "2026-09-01T12:34:56Z",
                "1970-01-01T00:00:00.000Z",
                "1969-12-31T23:59:59.999Z",
                "0000-01-01T00:00:00Z",
                "9999-12-31T23:59:59.001Z",
                "2026-09-01T12:34:56+01:00",
                "not-a-datetime",
            ]))
            .to_string(),
        ),
        16 => Value::String(
            (*rng.pick(&["ecdsa-rdfc-2019", "eddsa-rdfc-2022", "unlisted-suite"])).to_string(),
        ),
        17 => Value::Number(
            (*rng.pick(&[0_i64, 1, -1, i64::MAX, i64::MIN, 999, -999_999_999])).into(),
        ),
        18 => Value::Bool(rng.chance(2)),
        _ => Value::Null,
    }
}

/// Generates one JSON-LD node object with an optional inline `@context`.
fn gen_node(rng: &mut Rng, depth: usize, inherited: &[String]) -> Value {
    let mut object = Map::new();
    let mut names: Vec<String> = inherited.to_vec();
    if depth == 0 || rng.chance(2) {
        let (context, defined) = gen_context(rng);
        object.insert("@context".to_string(), context);
        names.extend(defined);
    }
    // A key not defined anywhere still has to survive the round trip.
    if rng.chance(3) {
        names.push(format!("undefined{}", rng.below(4)));
    }
    if rng.chance(4) {
        names.push("@id".to_string());
    }
    let count = 1 + rng.below(4);
    for _ in 0..count {
        if names.is_empty() {
            break;
        }
        let key = rng.pick(&names).clone();
        let value = match rng.below(8) {
            0 | 1 if depth < 3 => gen_node(rng, depth + 1, &names),
            2 => {
                let items = rng.below(3);
                Value::Array((0..items).map(|_| gen_scalar(rng)).collect())
            }
            3 if depth < 3 => Value::Array(vec![gen_node(rng, depth + 1, &names)]),
            _ => gen_scalar(rng),
        };
        object.insert(key, value);
    }
    Value::Object(object)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// 4,096 random byte strings into the hand-rolled CBOR reader.
#[test]
fn dumb_bytes_never_panic_and_decode_deterministically() {
    let limits = fuzz_limits();
    let seed = SEEDS[0];
    let mut rng = Rng::new(seed);
    let mut accepted = 0_usize;
    for _ in 0..8_000 {
        // Short inputs dominate: they are where a truncation or a bad head
        // is most likely to reach an unguarded slice.
        let length = if rng.chance(8) {
            rng.below(FUZZ_MAX_INPUT)
        } else {
            rng.below(24)
        };
        let bytes: Vec<u8> = (0..length).map(|_| rng.byte()).collect();
        check_cbor_bytes(seed, &bytes, &limits);
        if decode(&bytes, &limits).is_ok() {
            accepted += 1;
        }
    }
    // Random bytes are mostly invalid CBOR; a run that accepted *nothing*
    // would mean the generator never reached the success path at all.
    assert!(
        accepted > 0,
        "no random byte string decoded; the fuzzer only exercised the error path"
    );
}

/// 1,536 generated CBOR values, each round-tripped and then mutated four ways.
#[test]
fn structured_cbor_round_trips_and_survives_mutation() {
    let limits = fuzz_limits();
    let seed = SEEDS[1];
    let mut rng = Rng::new(seed);
    let mut round_tripped = 0_usize;
    for _ in 0..3_000 {
        let value = gen_cbor(&mut rng, 1, &limits);
        let Ok(bytes) = encode_canonical(&value, &limits) else {
            continue;
        };
        if bytes.len() > FUZZ_MAX_INPUT {
            continue;
        }
        // Round-trip: the canonical bytes must survive decode + re-encode
        // unchanged. Comparing bytes rather than values is deliberate — it
        // covers NaN payloads and map ordering, which value equality cannot.
        let label = hex(&bytes);
        let outcome = decode_outcome(seed, &bytes, &limits);
        assert_eq!(
            outcome,
            Ok(bytes.clone()),
            "generated value did not round-trip\n  seed  = {seed:#018x}\n  input = {label}"
        );
        round_tripped += 1;
        check_cbor_bytes(seed, &bytes, &limits);
        for _ in 0..4 {
            let mutant = mutate(&mut rng, &bytes);
            check_cbor_bytes(seed, &mutant, &limits);
        }
    }
    assert!(
        round_tripped * 2 > 3_000,
        "only {round_tripped} generated values round-tripped; the generator is \
         producing mostly unencodable values"
    );
}

/// 1,024 hostile CBOR-LD envelopes, decompressed under two option sets.
#[test]
fn hostile_envelopes_fail_closed_without_panicking() {
    let limits = fuzz_limits();
    let seed = SEEDS[2];
    let mut rng = Rng::new(seed);
    let strict = CborldOptions {
        limits,
        ..CborldOptions::default()
    };
    let permissive = permissive_options(limits);
    let mut accepted = 0_usize;
    for _ in 0..2_000 {
        let envelope = gen_envelope(&mut rng, &limits);
        let Ok(bytes) = encode_canonical(&envelope, &limits) else {
            continue;
        };
        if bytes.len() > FUZZ_MAX_INPUT {
            continue;
        }
        let label = hex(&bytes);
        for options in [&strict, &permissive] {
            let first = decompress_outcome(seed, &bytes, options);
            let second = decompress_outcome(seed, &bytes, options);
            assert_eq!(
                first, second,
                "nondeterministic decompress\n  seed  = {seed:#018x}\n  input = {label}"
            );
            if first.is_ok() {
                accepted += 1;
            }
        }
    }
    // Envelope-shaped input must sometimes be *accepted*, or the fuzzer is
    // only proving that garbage is rejected.
    assert!(
        accepted > 0,
        "no generated envelope decompressed; only the refusal path was fuzzed"
    );
}

/// 768 generated JSON-LD documents, checked for the unconditional round trip.
#[test]
fn generated_documents_round_trip() {
    let limits = document_limits();
    let seed = SEEDS[3];
    let mut rng = Rng::new(seed);
    let plain = CborldOptions {
        limits,
        ..CborldOptions::default()
    };
    let registry = CborldOptions {
        mode: CompressionMode::RegistryEntry(100),
        ..permissive_options(limits)
    };
    let mut accepted = 0_usize;
    let attempts = 1_400;
    for _ in 0..attempts {
        let document = gen_node(&mut rng, 0, &[]);
        let options = if rng.chance(3) { &registry } else { &plain };
        let label = document.to_string();
        let compressed = guard(seed, "compress", &label, || compress(&document, options));
        let Ok(bytes) = compressed else {
            continue;
        };
        accepted += 1;
        let hexed = hex(&bytes);
        let decompressed = guard(seed, "decompress", &hexed, || decompress(&bytes, options));
        match decompressed {
            Ok(back) => assert_eq!(
                back, document,
                "round-trip mismatch: decompress(compress(doc)) != doc\n  \
                 seed     = {seed:#018x}\n  document = {label}\n  envelope = {hexed}"
            ),
            Err(error) => panic!(
                "compress accepted a document decompress refuses ({}): {error}\n  \
                 seed     = {seed:#018x}\n  document = {label}\n  envelope = {hexed}",
                error.code()
            ),
        }
        // Idempotent acceptance: the same document must compress to the
        // same bytes every time, or the wire form is not deterministic.
        let again = compress(&document, options).expect("second compress of an accepted document");
        assert_eq!(
            again, bytes,
            "nondeterministic compress\n  seed = {seed:#018x}\n  document = {label}"
        );
        // Near-valid bytes are the highest-value hostile input there is:
        // mutate a *real* envelope and require the same fail-closed,
        // deterministic behaviour as for synthetic ones.
        for _ in 0..3 {
            let mutant = mutate(&mut rng, &bytes);
            let first = decompress_outcome(seed, &mutant, options);
            let second = decompress_outcome(seed, &mutant, options);
            assert_eq!(
                first,
                second,
                "nondeterministic decompress of a mutated envelope\n  \
                 seed  = {seed:#018x}\n  input = {}",
                hex(&mutant)
            );
        }
    }
    // Honesty guard: a generator whose documents are mostly refused would
    // exercise the error path only, and the round-trip assertion above
    // would silently stop meaning anything.
    assert!(
        accepted * 2 > attempts,
        "only {accepted} of {attempts} generated documents were accepted by compress"
    );
}

/// Named byte-level cases the assignment calls out, each with its expected code.
#[test]
fn named_hostile_cbor_inputs_produce_typed_errors() {
    let limits = fuzz_limits();
    let seed = SEEDS[0];
    let cases: [(&str, &[u8], &str); 13] = [
        (
            "indefinite byte string",
            &[0x5f, 0x41, 0x00, 0xff],
            "cbor_decode",
        ),
        (
            "indefinite text string",
            &[0x7f, 0x61, 0x61, 0xff],
            "cbor_decode",
        ),
        ("indefinite array", &[0x9f, 0x01, 0xff], "cbor_decode"),
        ("indefinite map", &[0xbf, 0x01, 0x01, 0xff], "cbor_decode"),
        ("bare break", &[0xff], "cbor_decode"),
        ("reserved additional info 28", &[0x1c], "cbor_decode"),
        ("simple value undefined", &[0xf7], "cbor_decode"),
        ("unassigned simple value", &[0xf8, 0xff], "cbor_decode"),
        ("truncated head", &[0x19, 0x01], "cbor_decode"),
        ("trailing bytes", &[0x01, 0x01], "cbor_decode"),
        // A two-entry map whose keys are both `1`: the generators dedupe
        // map keys so they can round-trip, so the duplicate-key refusal
        // needs a named case rather than a chance discovery.
        (
            "duplicate map key",
            &[0xa2, 0x01, 0x01, 0x01, 0x02],
            "cbor_decode",
        ),
        (
            // A three-byte payload declaring a 2^64-1 byte string: the
            // length must be refused against the remaining input *before*
            // any buffer is reserved for it.
            "huge declared byte-string length",
            &[
                0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
            ],
            "cbor_decode",
        ),
        (
            "huge declared array length",
            &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00],
            "cbor_decode",
        ),
    ];
    for (name, bytes, expected) in cases {
        check_cbor_bytes(seed, bytes, &limits);
        let error = guard(seed, name, &hex(bytes), || {
            decode(bytes, &limits).expect_err("must fail closed")
        });
        assert_eq!(error.code(), expected, "{name}: {error}");
    }

    // A depth bomb must trip the depth budget as a typed resource limit,
    // never as a stack overflow: 64 nested one-element arrays against a
    // 16-deep budget, in 64 bytes of input.
    let bomb: Vec<u8> = std::iter::repeat_n(0x81_u8, 64).chain([0x00]).collect();
    check_cbor_bytes(seed, &bomb, &limits);
    let error = decode(&bomb, &limits).expect_err("depth bomb must fail closed");
    assert_eq!(error.code(), "resource_limit", "{error}");

    // Non-shortest integer heads are accepted by design (documented in
    // `cbor`), so the invariant is canonicalization, not refusal.
    for (non_shortest, canonical) in [
        (vec![0x18_u8, 0x17], vec![0x17_u8]),
        (vec![0x19, 0x00, 0x17], vec![0x17]),
        (vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 0x17], vec![0x17]),
        (vec![0x3b, 0, 0, 0, 0, 0, 0, 0, 0x00], vec![0x20]),
    ] {
        let value = decode(&non_shortest, &limits).expect("non-shortest head is accepted");
        assert_eq!(
            encode_canonical(&value, &limits).expect("re-encode"),
            canonical,
            "non-shortest head {} did not canonicalize",
            hex(&non_shortest)
        );
    }
}

/// Named envelope-layer cases, each pinned to the error code it must raise.
#[test]
fn named_hostile_envelopes_produce_typed_errors() {
    let limits = fuzz_limits();
    let strict = CborldOptions {
        limits,
        ..CborldOptions::default()
    };
    let permissive = permissive_options(limits);

    /// Builds `tag(tag, [entry, payload])` bytes for one hostile case.
    fn envelope(tag: u64, elements: Vec<CborValue>, limits: &CborLimits) -> Vec<u8> {
        encode_canonical(
            &CborValue::Tag(tag, Box::new(CborValue::Array(elements))),
            limits,
        )
        .expect("hostile envelope encodes")
    }

    let entry_1 =
        |payload: CborValue| envelope(0xCB1D, vec![CborValue::Unsigned(1), payload], &limits);

    let cases: [(&str, Vec<u8>, &str); 9] = [
        (
            "wrong tag",
            envelope(
                0xCB1E,
                vec![CborValue::Unsigned(1), CborValue::Map(Vec::new())],
                &limits,
            ),
            "envelope",
        ),
        (
            "wrong arity",
            envelope(0xCB1D, vec![CborValue::Unsigned(1)], &limits),
            "envelope",
        ),
        (
            "unvendored registry entry",
            envelope(
                0xCB1D,
                vec![CborValue::Unsigned(4242), CborValue::Map(Vec::new())],
                &limits,
            ),
            "unknown_registry_entry",
        ),
        (
            "provisional entry without opt-in",
            envelope(
                0xCB1D,
                vec![CborValue::Unsigned(100), CborValue::Map(Vec::new())],
                &limits,
            ),
            "provisional_registry_entry",
        ),
        (
            "unknown term id",
            entry_1(CborValue::Map(vec![(
                CborValue::Unsigned(200),
                CborValue::Text("x".to_string()),
            )])),
            "unknown_term_id",
        ),
        (
            "unknown URL prefix identifier",
            entry_1(CborValue::Map(vec![(
                CborValue::Unsigned(4),
                CborValue::Array(vec![
                    CborValue::Unsigned(77),
                    CborValue::Text("x".to_string()),
                ]),
            )])),
            "envelope",
        ),
        (
            "data: codec with a wrong arity",
            entry_1(CborValue::Map(vec![(
                CborValue::Unsigned(4),
                CborValue::Array(vec![
                    CborValue::Unsigned(4),
                    CborValue::Text("text/plain".to_string()),
                    CborValue::Bytes(vec![1]),
                    CborValue::Bytes(vec![2]),
                ]),
            )])),
            "envelope",
        ),
        (
            "both singular and plural @context keys",
            entry_1(CborValue::Map(vec![
                (CborValue::Unsigned(0), CborValue::Map(Vec::new())),
                (CborValue::Unsigned(1), CborValue::Array(Vec::new())),
            ])),
            "envelope",
        ),
        (
            "urn:uuid: codec with the wrong byte count",
            entry_1(CborValue::Map(vec![(
                CborValue::Unsigned(4),
                CborValue::Array(vec![CborValue::Unsigned(3), CborValue::Bytes(vec![0; 15])]),
            )])),
            "envelope",
        ),
    ];

    for (name, bytes, expected) in cases {
        let error = guard(SEEDS[2], name, &hex(&bytes), || {
            decompress(&bytes, &strict).expect_err("must fail closed")
        });
        assert_eq!(error.code(), expected, "{name}: {error}");
        // Idempotent refusal: same input, same refusal, every time.
        let repeat = decompress(&bytes, &strict).expect_err("must fail closed again");
        assert_eq!(repeat.to_string(), error.to_string(), "{name}");
    }

    // A `sec:multibase`-typed value carrying an unvendored header byte is a
    // typed refusal, not a guessed alphabet.
    let mut payload = vec![(
        CborValue::Unsigned(0),
        CborValue::Map(vec![(
            CborValue::Text("key".to_string()),
            CborValue::Map(vec![
                (
                    CborValue::Text("@id".to_string()),
                    CborValue::Text("https://example.org/key".to_string()),
                ),
                (
                    CborValue::Text("@type".to_string()),
                    CborValue::Text("https://w3id.org/security#multibase".to_string()),
                ),
            ]),
        )]),
    )];
    payload.push((
        CborValue::Unsigned(100),
        CborValue::Bytes(vec![b'q', 1, 2, 3]),
    ));
    let bytes = encode_canonical(
        &CborValue::Tag(
            0xCB1D,
            Box::new(CborValue::Array(vec![
                CborValue::Unsigned(1),
                CborValue::Map(payload),
            ])),
        ),
        &limits,
    )
    .expect("envelope encodes");
    let error = decompress(&bytes, &strict).expect_err("unvendored multibase header");
    assert_eq!(error.code(), "unsupported", "{error}");

    // Cross-entry identifier reuse: an identifier valid under entry 10001 is
    // refused under entry 10003 rather than resolved against the wrong table.
    let cross = envelope(
        0xCB1D,
        vec![
            CborValue::Unsigned(10_003),
            CborValue::Map(vec![(CborValue::Unsigned(0), CborValue::Unsigned(60_000))]),
        ],
        &limits,
    );
    let error = decompress(&cross, &permissive).expect_err("cross-entry id must not resolve");
    assert_eq!(error.code(), "unknown_compressed_context", "{error}");
}

/// Regression: a term name reused across sibling scopes must round-trip.
///
/// The compressor consults a conversion-global identifier registry, but the
/// decompressor resolves every key of a node before descending into that
/// node's values. Before the fix, the top-level `z` picked up the
/// identifier that the nested `@context` under `a` had just assigned, and
/// decompression failed with `unknown_term_id` on a document `compress`
/// had accepted.
#[test]
fn cross_scope_term_reuse_round_trips() {
    let options = CborldOptions::default();
    let document = json!({
        "@context": {"a": "http://example.org/a"},
        "a": {
            "@context": {"z": "http://example.org/z"},
            "z": "inner"
        },
        "z": "top"
    });
    let bytes = compress(&document, &options).expect("compress");
    let back = decompress(&bytes, &options).expect("decompress must accept what compress emitted");
    assert_eq!(back, document);

    // The out-of-scope name rides as text, and the in-scope one as an id.
    let CborValue::Tag(0xCB1D, inner) = decode(&bytes, &CborLimits::default()).expect("envelope")
    else {
        panic!("expected a CBOR-LD tag");
    };
    let CborValue::Array(elements) = *inner else {
        panic!("expected the envelope array");
    };
    let CborValue::Map(entries) = &elements[1] else {
        panic!("expected a compressed map payload");
    };
    assert!(
        entries
            .iter()
            .any(|(key, _)| *key == CborValue::Text("z".to_string())),
        "the out-of-scope term must ride as text: {entries:?}"
    );
    assert!(
        entries
            .iter()
            .any(|(key, _)| *key == CborValue::Unsigned(100)),
        "the in-scope term must still compress to an identifier: {entries:?}"
    );
}
