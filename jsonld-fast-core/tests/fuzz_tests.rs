// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Deterministic seeded fuzzing of the JSON-LD processor (task-graph N12).
//!
//! Stable-toolchain only: no `cargo-fuzz`, no `libfuzzer`, no `proptest` —
//! a hand-rolled xorshift PRNG seeded by a constant, so every case is
//! reproducible from its printed seed and `cargo test` alone reruns it.
//!
//! Two generators feed the same invariant battery:
//!
//! - a **dumb-bytes** generator, whose output goes through
//!   [`parse_document`] (byte soup, and byte-level mutations of
//!   well-formed documents: truncation, flips, escape and length
//!   corruption), and
//! - a **structure-aware** generator, which builds well-formed-ish JSON-LD
//!   and then corrupts it on purpose: keyword redefinition, `@protected`
//!   violations, prefix cycles and prefix chains, malformed IRIs and
//!   language tags, duplicate `@id`s, boundary integers, depth explosion,
//!   and huge `@list` chains.
//!
//! The invariants — not the iteration count — are the point:
//!
//! 1. **Never panic.** Every call is wrapped in [`catch_unwind`]; any
//!    malformed input must produce a typed [`JsonLdError`].
//! 2. **Bounded work.** Depth, node, and context-recursion budgets must
//!    trip as typed errors *before* the expensive operation. Generated
//!    depth bombs run against tightened limits so the trip is observable.
//! 3. **Round-trip.** `expand(compact(doc)) == expand(doc)` for every
//!    document that survives expansion, and the quad set survives
//!    `from_quads(to_quads(·))`.
//! 4. **Idempotent refusal.** A rejected input is rejected with the same
//!    error code every time.
//! 5. **No silent mutation.** A successful decode reproduces the same quad
//!    set; a `@json` literal reproduces its own canonical form.
//!
//! Harness rules that exist because breaking them produces false failures:
//! generated values are assembled with [`Value::Object`]/[`Value::Array`]
//! directly and **never** interpolated into `json!` (which re-serializes
//! recursively and would overflow the scaffolding's own stack), and
//! generated nesting stays at or below [`MAX_GENERATED_DEPTH`], well under
//! the depth at which `serde_json`'s own recursive `Drop` aborts.

use std::{
    collections::BTreeSet,
    panic::{AssertUnwindSafe, catch_unwind},
};

use arrow_array::RecordBatch;
use jsonld_fast_core::{
    JsonLdError, JsonLdLimits, JsonLdOptions, compact, expand, frame, from_quads, parse_document,
    to_quads,
};
use oxrdf::TermRef;
use quad_fast_core::{QuadLimits, QuadStreamReader};
use serde_json::{Map, Number, Value};

// ===========================================================================
// PRNG — xorshift64*, seeded by constants so every case is reproducible
// ===========================================================================

/// Deterministic xorshift64* generator.
///
/// Never seeded from the clock or a thread id: a failure prints its seed
/// and the same seed replays the same case forever.
struct Rng(u64);

impl Rng {
    /// Seeds the generator; a zero seed is remapped (xorshift fixes at 0).
    const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        self.0 = state;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish value in `0..bound` (`0` when `bound` is `0`).
    fn below(&mut self, bound: usize) -> usize {
        let Ok(bound) = u64::try_from(bound) else {
            return 0;
        };
        if bound == 0 {
            return 0;
        }
        usize::try_from(self.next_u64() % bound).unwrap_or(0)
    }

    /// Picks one element of a non-empty slice.
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// True with probability `1/odds`.
    fn chance(&mut self, odds: usize) -> bool {
        self.below(odds) == 0
    }
}

// ===========================================================================
// Budgets and harness constants
// ===========================================================================

/// Root seed of the structure-aware corpus. Constant, never time-derived.
const STRUCTURED_SEED: u64 = 0x5EED_0000_1234_5678;
/// Root seed of the dumb-bytes corpus.
const DUMB_SEED: u64 = 0x0BAD_C0DE_DEAD_BEEF;
/// Root seed of the byte-mutation corpus.
const MUTATION_SEED: u64 = 0x00FF_1CE0_5EED_1111;
/// Root seed of the canonical-JSON corpus.
const CANON_SEED: u64 = 0x8785_8785_8785_0001;

/// Structure-aware cases per run. Sized to keep the test under ~4 s in an
/// unoptimized `cargo test` build; every case runs the full battery
/// (expand twice, compact, re-expand, to_quads, from_quads, to_quads, frame).
const STRUCTURED_CASES: usize = 800;
/// Dumb-bytes cases per run.
const DUMB_CASES: usize = 3_000;
/// Byte-mutation cases per run.
const MUTATION_CASES: usize = 1_500;
/// Canonical-JSON cases per run.
const CANON_CASES: usize = 1_200;

/// Hard ceiling on generated JSON nesting.
///
/// `serde_json::Value` drops recursively, so a generator that builds a
/// value deeper than a few thousand levels aborts the *test process* in its
/// own scaffolding — an accusation against the crate that the crate did not
/// earn. Measured drop-safe well past 6,000 on this target; 400 leaves an
/// order of magnitude of headroom while still overshooting every budget
/// under test by 6x.
const MAX_GENERATED_DEPTH: usize = 400;

/// Draws a finite `f64` whose canonical decimal `serde_json` reads back
/// exactly.
///
/// `serde_json` 1.0.151's float parser is not correctly rounded at extreme
/// exponents: it reads `8.845495561575861e+187` one ulp away from the value
/// Rust's own correctly-rounded `str::parse::<f64>` produces. That is an
/// upstream property of the parser, not of this codec's serializer — the
/// serializer's own correctness is asserted separately (and over the whole
/// `f64` bit space) by [`json_numbers_round_trip_exactly`]. Cases whose
/// decimal form `serde_json` cannot read back are excluded here so the
/// idempotence and decode assertions stay sharp instead of being weakened
/// to accommodate an upstream rounding error.
fn faithful_float(rng: &mut Rng) -> Option<Number> {
    for _ in 0..8 {
        let candidate = f64::from_bits(rng.next_u64());
        if !candidate.is_finite() {
            continue;
        }
        let rendered = format!("{candidate:e}");
        let reread: Option<f64> = serde_json::from_str(&rendered).ok();
        if reread.map(f64::to_bits) == Some(candidate.to_bits()) {
            return Number::from_f64(candidate);
        }
    }
    None
}

/// How two JSON values relate after a canonicalize/reparse cycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Agreement {
    /// Identical, numbers included (compared as doubles: `5.0` and `5` are
    /// the same number and canonicalize to the same bytes).
    Exact,
    /// Same shape, same keys, same strings — one or more numbers moved.
    /// The only known cause is the upstream parser (see [`faithful_float`]).
    NumbersDiffer,
    /// Something other than a number changed: data was lost or invented.
    Different,
}

/// Compares two values, separating a numeric drift from a structural change.
fn agreement(left: &Value, right: &Value) -> Agreement {
    match (left, right) {
        (Value::Number(one), Value::Number(two)) => {
            if one.as_f64() == two.as_f64() {
                Agreement::Exact
            } else {
                Agreement::NumbersDiffer
            }
        }
        (Value::Array(one), Value::Array(two)) => {
            if one.len() != two.len() {
                return Agreement::Different;
            }
            one.iter()
                .zip(two)
                .map(|(a, b)| agreement(a, b))
                .fold(Agreement::Exact, worst)
        }
        (Value::Object(one), Value::Object(two)) => {
            if one.len() != two.len() {
                return Agreement::Different;
            }
            let mut worst_so_far = Agreement::Exact;
            for (key, a) in one {
                let Some(b) = two.get(key) else {
                    return Agreement::Different;
                };
                worst_so_far = worst(worst_so_far, agreement(a, b));
            }
            worst_so_far
        }
        (one, two) if one == two => Agreement::Exact,
        _ => Agreement::Different,
    }
}

const fn worst(left: Agreement, right: Agreement) -> Agreement {
    match (left, right) {
        (Agreement::Different, _) | (_, Agreement::Different) => Agreement::Different,
        (Agreement::NumbersDiffer, _) | (_, Agreement::NumbersDiffer) => Agreement::NumbersDiffer,
        _ => Agreement::Exact,
    }
}

/// Tightened limits so budget trips are reachable inside the time budget.
fn fuzz_options() -> JsonLdOptions {
    JsonLdOptions {
        base: Some("http://fuzz.example/base/".to_owned()),
        limits: JsonLdLimits {
            max_input_bytes: 1 << 20,
            max_nodes: 20_000,
            max_depth: 64,
            max_output_bytes: None,
        },
        quad_limits: QuadLimits {
            max_quads: 20_000,
            max_retained_term_bytes: 1 << 22,
            ..QuadLimits::default()
        },
        compact_arrays: true,
    }
}

// ===========================================================================
// Invariant 1 — never panic: every call goes through this guard
// ===========================================================================

/// Runs `body`, converting a typed failure to its stable error code and a
/// panic to a test failure that names the seed and the offending input.
fn guarded<T>(
    seed: u64,
    stage: &str,
    input: &str,
    body: impl FnOnce() -> Result<T, JsonLdError>,
) -> Result<T, &'static str> {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.code()),
        Err(_) => panic!("PANIC in `{stage}`\n  seed: {seed:#018x}\n  input: {input}"),
    }
}

// ===========================================================================
// Quad-set comparison (blank node labels masked)
// ===========================================================================

/// Renders quads as a set of N-Quads-ish lines with `_:bN` labels masked.
///
/// Blank node labels are reissued on every deserialization run, so the
/// labels themselves carry no information across a round trip; masking them
/// compares the graphs, not the naming.
fn masked_quad_set(batches: &[RecordBatch]) -> Result<BTreeSet<String>, &'static str> {
    let mut lines = BTreeSet::new();
    for batch in batches {
        let reader =
            QuadStreamReader::new(batch).map_err(|_error| "batch failed contract validation")?;
        for row in 0..reader.len() {
            let quad = reader.quad(row).map_err(|_error| "row failed to decode")?;
            lines.insert(mask_blank_labels(&quad.to_string()));
        }
    }
    Ok(lines)
}

/// Replaces every `_:b<digits>` run with `_:_`.
fn mask_blank_labels(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut masked = String::with_capacity(line.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"_:b") {
            let mut end = index + 3;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > index + 3 {
                masked.push_str("_:_");
                index = end;
                continue;
            }
        }
        // Byte-at-a-time is safe here: the ASCII prefix match above never
        // splits a multi-byte sequence, so `index` stays on a boundary.
        let rest = &line[index..];
        let character = rest.chars().next().unwrap_or('\u{FFFD}');
        masked.push(character);
        index += character.len_utf8();
    }
    masked
}

// ===========================================================================
// The invariant battery
// ===========================================================================

/// Runs every invariant that applies to `document`.
fn check_document(seed: u64, document: &Value) {
    let options = fuzz_options();
    let rendered = document.to_string();
    let rendered = if rendered.len() > 4_000 {
        format!(
            "{}… ({} bytes)",
            &rendered[..rendered.floor_char_boundary(4_000)],
            rendered.len()
        )
    } else {
        rendered
    };

    // Invariant 1 + 4: expansion never panics, and refusal is idempotent.
    let first = guarded(seed, "expand", &rendered, || expand(document, &options));
    let second = guarded(seed, "expand (replay)", &rendered, || {
        expand(document, &options)
    });
    match (&first, &second) {
        (Ok(left), Ok(right)) => assert_eq!(
            left, right,
            "expansion is not deterministic\n  seed: {seed:#018x}\n  input: {rendered}"
        ),
        (Err(left), Err(right)) => assert_eq!(
            left, right,
            "refusal is not idempotent\n  seed: {seed:#018x}\n  input: {rendered}"
        ),
        _ => panic!(
            "expansion succeeded once and failed once\n  seed: {seed:#018x}\n  input: {rendered}"
        ),
    }
    let Ok(expanded) = first else {
        // Invariant 1 also covers the refused path: the other entry points
        // must refuse it too, and must refuse it without panicking.
        let context = document
            .get("@context")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        let _ = guarded(seed, "compact (refused doc)", &rendered, || {
            compact(document, &context, &options)
        });
        let _ = guarded(seed, "to_quads (refused doc)", &rendered, || {
            to_quads(document, &options, None)
        });
        let _ = guarded(seed, "frame (refused doc)", &rendered, || {
            frame(document, &Value::Object(Map::new()), &options)
        });
        return;
    };

    assert!(
        expanded.is_array(),
        "expanded form must be an array\n  seed: {seed:#018x}\n  input: {rendered}"
    );

    // Invariant 3: expand(compact(doc)) == expand(doc).
    let context = document
        .get("@context")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    if let Ok(compacted) = guarded(seed, "compact", &rendered, || {
        compact(document, &context, &options)
    }) {
        match guarded(seed, "expand(compact)", &rendered, || {
            expand(&compacted, &options)
        }) {
            Ok(re_expanded) => assert_eq!(
                re_expanded, expanded,
                "expand(compact(doc)) != expand(doc)\n  seed: {seed:#018x}\n  input: {rendered}\n  compacted: {compacted}"
            ),
            Err(code) => panic!(
                "a compacted document failed to re-expand ({code})\n  seed: {seed:#018x}\n  input: {rendered}\n  compacted: {compacted}"
            ),
        }
    }

    // Invariants 3 + 5: the quad set survives from_quads/to_quads unchanged.
    if let Ok(batches) = guarded(seed, "to_quads", &rendered, || {
        to_quads(document, &options, None)
    }) {
        let before = masked_quad_set(&batches)
            .unwrap_or_else(|why| panic!("{why}\n  seed: {seed:#018x}\n  input: {rendered}"));
        match guarded(seed, "from_quads", &rendered, || from_quads(&batches)) {
            Ok(recovered) => {
                let again = guarded(seed, "to_quads (replay)", &rendered, || {
                    to_quads(&recovered, &options, None)
                })
                .unwrap_or_else(|code| {
                    panic!(
                        "from_quads produced a document to_quads refuses ({code})\n  seed: {seed:#018x}\n  input: {rendered}\n  recovered: {recovered}"
                    )
                });
                let after = masked_quad_set(&again).unwrap_or_else(|why| {
                    panic!("{why}\n  seed: {seed:#018x}\n  input: {rendered}")
                });
                assert_eq!(
                    before, after,
                    "quads changed across from_quads/to_quads\n  seed: {seed:#018x}\n  input: {rendered}\n  recovered: {recovered}"
                );
            }
            Err(code) => panic!(
                "from_quads refused this codec's own output ({code})\n  seed: {seed:#018x}\n  input: {rendered}"
            ),
        }
    }

    // Invariant 1 over framing: any typed outcome is fine, a panic is not.
    let mut frame_value = Map::new();
    frame_value.insert("@context".to_owned(), context);
    let _ = guarded(seed, "frame", &rendered, || {
        frame(document, &Value::Object(frame_value), &options)
    });
}

// ===========================================================================
// Structure-aware generator
// ===========================================================================

/// Well-formed IRIs the generator draws from.
const IRIS: &[&str] = &[
    "http://example.com/p",
    "http://example.com/q",
    "https://schema.org/name",
    "http://example.com/",
    "http://example.com/ns#",
    "urn:example:1",
];

/// IRI-shaped strings that are malformed, relative, or hostile.
const HOSTILE_IRIS: &[&str] = &[
    "",
    " ",
    "relative/path",
    "http://",
    ":",
    "_:b0",
    "_:",
    "a b",
    "#fragment",
    "//authority/x",
    "http://example.com/ spaced",
    "\u{202e}rtl-override",
    "HTTP://EXAMPLE.COM/",
    "x:",
    "../../up",
    "\u{0000}nul",
];

/// Language tags, valid and malformed.
const LANG_TAGS: &[&str] = &[
    "en",
    "en-US",
    "de-DE-1901",
    "zh-Hant-TW",
    "",
    "1",
    "e n",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "en_US",
    "-en",
    "en-",
    "EN",
    "i-klingon",
];

/// `@container` values, including language maps.
const CONTAINERS: &[&str] = &[
    "@list",
    "@set",
    "@index",
    "@id",
    "@type",
    "@graph",
    "@language",
    "@none",
    "@nest",
];

/// Keywords the generator tries to redefine or alias.
const KEYWORDS: &[&str] = &[
    "@type",
    "@id",
    "@value",
    "@list",
    "@set",
    "@context",
    "@graph",
    "@base",
    "@vocab",
    "@json",
    "@none",
    "@nest",
    "@reverse",
    "@protected",
];

/// Integers at and beyond the exact IEEE 754 double boundary.
const BOUNDARY_INTEGERS: &[i64] = &[
    0,
    1,
    -1,
    9_007_199_254_740_992,  // 2^53
    9_007_199_254_740_993,  // 2^53 + 1 — not exactly representable
    -9_007_199_254_740_993, // -(2^53 + 1)
    i64::MAX,
    i64::MIN,
    4_294_967_295,
    4_294_967_296,
];

fn object(pairs: Vec<(String, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key, value);
    }
    Value::Object(map)
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

/// Builds `[[[…]]]` (or `{"k":{"k":…}}`) `depth` levels deep, iteratively.
fn nested_bomb(rng: &mut Rng, depth: usize) -> Value {
    let use_objects = rng.chance(2);
    let mut value = Value::Number(Number::from(1));
    for _ in 0..depth {
        value = if use_objects {
            object(vec![("k".to_owned(), value)])
        } else {
            Value::Array(vec![value])
        };
    }
    value
}

/// A term definition, from plain string shorthand to a hostile object form.
fn generate_term_definition(rng: &mut Rng, depth: usize) -> Value {
    match rng.below(6) {
        0 => text(rng.pick(IRIS)),
        1 => text(rng.pick(HOSTILE_IRIS)),
        2 => Value::Null,
        3 => text(&format!("{}:suffix", rng.pick(&["t0", "t1", "t2", "ex"]))),
        _ => {
            let mut entries: Vec<(String, Value)> = Vec::new();
            entries.push(("@id".to_owned(), {
                if rng.chance(4) {
                    text(rng.pick(HOSTILE_IRIS))
                } else {
                    text(rng.pick(IRIS))
                }
            }));
            if rng.chance(3) {
                let mapping = *rng.pick(&["@id", "@vocab", "@json", "@none", IRIS[0]]);
                entries.push(("@type".to_owned(), text(mapping)));
            }
            if rng.chance(3) {
                entries.push(("@container".to_owned(), {
                    if rng.chance(3) {
                        Value::Array(vec![text(rng.pick(CONTAINERS)), text("@set")])
                    } else {
                        text(rng.pick(CONTAINERS))
                    }
                }));
            }
            if rng.chance(4) {
                entries.push(("@language".to_owned(), text(rng.pick(LANG_TAGS))));
            }
            if rng.chance(5) {
                entries.push((
                    "@direction".to_owned(),
                    text(rng.pick(&["ltr", "rtl", "up"])),
                ));
            }
            if rng.chance(4) {
                entries.push(("@protected".to_owned(), Value::Bool(rng.chance(2))));
            }
            if rng.chance(5) {
                entries.push(("@prefix".to_owned(), Value::Bool(rng.chance(2))));
            }
            if rng.chance(6) {
                entries.push(("@index".to_owned(), text("idx")));
            }
            if rng.chance(6) {
                entries.push(("@nest".to_owned(), text("@nest")));
            }
            if rng.chance(6) {
                entries.push(("@reverse".to_owned(), text(rng.pick(IRIS))));
            }
            // Scoped contexts nest the context grammar into itself.
            if depth < 3 && rng.chance(4) {
                entries.push((
                    "@context".to_owned(),
                    generate_context(rng, depth.saturating_add(1)),
                ));
            }
            object(entries)
        }
    }
}

/// A `{"t0": …, "t1": …}` context, sometimes an array, sometimes a chain.
fn generate_context(rng: &mut Rng, depth: usize) -> Value {
    // A prefix chain in flat JSON: `{"t0":"t1:x","t1":"t2:x", …}`.
    if rng.chance(12) {
        let length = rng.below(60);
        let mut entries = Vec::with_capacity(length + 1);
        for index in 0..length {
            entries.push((
                format!("t{index}"),
                text(&format!("t{}:x", index.saturating_add(1))),
            ));
        }
        entries.push((format!("t{length}"), text("http://example.com/chain#")));
        return object(entries);
    }
    // A prefix cycle: two terms that define each other.
    if rng.chance(12) {
        return object(vec![
            ("a".to_owned(), text("b:x")),
            ("b".to_owned(), text("a:x")),
        ]);
    }
    let mut entries: Vec<(String, Value)> = Vec::new();
    if rng.chance(4) {
        entries.push(("@version".to_owned(), {
            if rng.chance(3) {
                Value::Number(Number::from(2))
            } else {
                Number::from_f64(1.1).map_or(Value::Null, Value::Number)
            }
        }));
    }
    if rng.chance(3) {
        entries.push(("@vocab".to_owned(), text(rng.pick(IRIS))));
    }
    if rng.chance(4) {
        entries.push(("@base".to_owned(), text(rng.pick(HOSTILE_IRIS))));
    }
    if rng.chance(5) {
        entries.push(("@protected".to_owned(), Value::Bool(true)));
    }
    if rng.chance(5) {
        entries.push(("@language".to_owned(), text(rng.pick(LANG_TAGS))));
    }
    if rng.chance(6) {
        entries.push(("@propagate".to_owned(), Value::Bool(rng.chance(2))));
    }
    // Keyword redefinition and keyword aliasing.
    if rng.chance(5) {
        entries.push(((*rng.pick(KEYWORDS)).to_owned(), text(rng.pick(IRIS))));
    }
    if rng.chance(5) {
        entries.push(("alias".to_owned(), text(rng.pick(KEYWORDS))));
    }
    let terms = 1 + rng.below(4);
    for index in 0..terms {
        entries.push((format!("t{index}"), generate_term_definition(rng, depth)));
    }
    let base = object(entries);
    if rng.chance(6) {
        // An array context: the second entry re-defines the first's terms,
        // which is exactly the `@protected` violation path.
        let mut redefined = Vec::new();
        for index in 0..terms {
            redefined.push((format!("t{index}"), generate_term_definition(rng, depth)));
        }
        if rng.chance(3) {
            return Value::Array(vec![base, Value::Null]);
        }
        return Value::Array(vec![base, object(redefined)]);
    }
    base
}

/// A property value: scalars, value objects, node objects, lists, bombs.
fn generate_value(rng: &mut Rng, depth: usize) -> Value {
    if depth == 0 {
        return text("leaf");
    }
    match rng.below(14) {
        0 => text("plain"),
        1 => Value::Bool(rng.chance(2)),
        2 => Value::Number(Number::from(*rng.pick(BOUNDARY_INTEGERS))),
        3 => faithful_float(rng).map_or(Value::Null, Value::Number),
        4 => Value::Null,
        5 => object(vec![
            ("@value".to_owned(), text("v")),
            ("@language".to_owned(), text(rng.pick(LANG_TAGS))),
        ]),
        6 => object(vec![
            ("@value".to_owned(), text("v")),
            ("@type".to_owned(), text(rng.pick(HOSTILE_IRIS))),
        ]),
        7 => object(vec![
            ("@value".to_owned(), text("v")),
            (
                "@direction".to_owned(),
                text(rng.pick(&["ltr", "rtl", "x"])),
            ),
            ("@language".to_owned(), text(rng.pick(LANG_TAGS))),
        ]),
        8 => object(vec![("@id".to_owned(), text(rng.pick(HOSTILE_IRIS)))]),
        9 => {
            // A node object; duplicate `@id`s across cases are deliberate.
            let mut entries = vec![(
                "@id".to_owned(),
                text(rng.pick(&["http://example.com/a", "http://example.com/b", "_:shared"])),
            )];
            entries.push((
                format!("t{}", rng.below(3)),
                generate_value(rng, depth.saturating_sub(1)),
            ));
            if rng.chance(3) {
                entries.push(("@type".to_owned(), text(rng.pick(IRIS))));
            }
            object(entries)
        }
        10 => object(vec![(
            "@list".to_owned(),
            Value::Array(
                (0..rng.below(6))
                    .map(|_| generate_value(rng, depth.saturating_sub(1)))
                    .collect(),
            ),
        )]),
        11 => Value::Array(
            (0..rng.below(5))
                .map(|_| generate_value(rng, depth.saturating_sub(1)))
                .collect(),
        ),
        12 => {
            // An index/id/type/graph container map body.
            let mut entries = Vec::new();
            for index in 0..(1 + rng.below(3)) {
                entries.push((
                    format!("k{index}"),
                    generate_value(rng, depth.saturating_sub(1)),
                ));
            }
            if rng.chance(3) {
                entries.push(("@none".to_owned(), text("none")));
            }
            object(entries)
        }
        _ => {
            // Depth explosion and huge `@list` chains: both must trip a
            // budget as a typed error rather than exhaust the machine.
            if rng.chance(2) {
                let bomb_depth = 1 + rng.below(MAX_GENERATED_DEPTH);
                nested_bomb(rng, bomb_depth)
            } else {
                let length = rng.below(2_000);
                object(vec![(
                    "@list".to_owned(),
                    Value::Array(
                        (0..length)
                            .map(|n| Value::Number(Number::from(n)))
                            .collect(),
                    ),
                )])
            }
        }
    }
}

/// A whole document: context, identity, properties, graph and reverse forms.
fn generate_document(rng: &mut Rng) -> Value {
    let mut entries: Vec<(String, Value)> = Vec::new();
    if !rng.chance(8) {
        entries.push(("@context".to_owned(), generate_context(rng, 0)));
    }
    if !rng.chance(6) {
        entries.push((
            "@id".to_owned(),
            if rng.chance(4) {
                text(rng.pick(HOSTILE_IRIS))
            } else {
                text(rng.pick(IRIS))
            },
        ));
    }
    if rng.chance(3) {
        entries.push((
            "@type".to_owned(),
            if rng.chance(3) {
                Value::Array(vec![text(rng.pick(IRIS)), text(rng.pick(HOSTILE_IRIS))])
            } else {
                text(rng.pick(IRIS))
            },
        ));
    }
    for index in 0..(1 + rng.below(4)) {
        let key = match rng.below(5) {
            0 => (*rng.pick(IRIS)).to_owned(),
            1 => (*rng.pick(KEYWORDS)).to_owned(),
            2 => "alias".to_owned(),
            3 => format!("t{}", rng.below(4)),
            _ => format!("t{index}"),
        };
        entries.push((key, generate_value(rng, 3)));
    }
    if rng.chance(5) {
        entries.push((
            "@graph".to_owned(),
            Value::Array(vec![generate_value(rng, 2)]),
        ));
    }
    if rng.chance(6) {
        entries.push((
            "@reverse".to_owned(),
            object(vec![((*rng.pick(IRIS)).to_owned(), generate_value(rng, 2))]),
        ));
    }
    if rng.chance(6) {
        entries.push((
            "@included".to_owned(),
            Value::Array(vec![generate_value(rng, 2)]),
        ));
    }
    if rng.chance(8) {
        entries.push(("@nest".to_owned(), generate_value(rng, 2)));
    }
    object(entries)
}

// ===========================================================================
// Tests
// ===========================================================================

/// 1,500 structure-aware cases against the full invariant battery.
#[test]
fn structured_documents_hold_every_invariant() {
    let mut rng = Rng::new(STRUCTURED_SEED);
    for case in 0..STRUCTURED_CASES {
        // The per-case seed is what a failure prints: reseeding from it
        // reproduces the exact document.
        let seed = rng.next_u64();
        let mut case_rng = Rng::new(seed);
        let document = generate_document(&mut case_rng);
        assert!(
            case < STRUCTURED_CASES,
            "unreachable bound check keeps `case` load-bearing"
        );
        check_document(seed, &document);
    }
}

/// 3,000 random byte strings through the text entry point.
///
/// Covers what `serde_json::Value` cannot hold at all: lone surrogate
/// escapes, non-finite number literals, out-of-range exponents, duplicate
/// object keys, and invalid UTF-8 turned lossy.
#[test]
fn dumb_bytes_never_panic() {
    let limits = fuzz_options().limits;
    let mut rng = Rng::new(DUMB_SEED);
    let seeds: &[&str] = &[
        "{\"@context\":{\"a\":\"http://e/a\"},\"a\":1}",
        "{\"@id\":\"\\ud800\"}",
        "{\"n\":NaN}",
        "{\"n\":1e999}",
        "{\"n\":-1e-999}",
        "{\"n\":9007199254740993}",
        "{\"n\":18446744073709551616}",
        "{\"a\":1,\"a\":2}",
        "{\"@context\":\"http://remote/ctx\"}",
        "{\"@context\":{\"@import\":\"http://remote/ctx\"}}",
        "[[[[[[[[[[1]]]]]]]]]]",
        "{\"\\u0000\":\"\\u001f\"}",
    ];
    for _ in 0..DUMB_CASES {
        let seed = rng.next_u64();
        let mut case_rng = Rng::new(seed);
        let text = if case_rng.chance(3) {
            (*case_rng.pick(seeds)).to_owned()
        } else {
            let length = case_rng.below(160);
            let bytes: Vec<u8> = (0..length)
                .map(|_| {
                    if case_rng.chance(2) {
                        // Bias towards JSON structure bytes so the parser
                        // gets past its first character sometimes.
                        *case_rng.pick(b"{}[]\":,0123456789.eE+-truefalsnl\\@ \t\n")
                    } else {
                        u8::try_from(case_rng.below(256)).unwrap_or(0)
                    }
                })
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let parsed = guarded(seed, "parse_document", &text, || {
            parse_document(&text, &limits)
        });
        // Invariant 4: the same bytes are refused the same way every time.
        let replay = guarded(seed, "parse_document (replay)", &text, || {
            parse_document(&text, &limits)
        });
        match (&parsed, &replay) {
            (Ok(left), Ok(right)) => assert_eq!(left, right, "parse is not deterministic: {text}"),
            (Err(left), Err(right)) => {
                assert_eq!(left, right, "parse refusal is not idempotent: {text}");
            }
            _ => panic!("parse succeeded once and failed once: {text}"),
        }
        if let Ok(document) = parsed {
            check_document(seed, &document);
        }
    }
}

/// 1,500 byte-level mutations of well-formed documents.
///
/// Truncation, byte flips, and corruption of the length-bearing parts of
/// the text (string escapes and number exponents) — the JSON analogue of a
/// corrupted length field.
#[test]
fn mutated_text_never_panics() {
    let limits = fuzz_options().limits;
    let mut rng = Rng::new(MUTATION_SEED);
    for _ in 0..MUTATION_CASES {
        let seed = rng.next_u64();
        let mut case_rng = Rng::new(seed);
        let document = generate_document(&mut case_rng);
        let Ok(serialized) = serde_json::to_string(&document) else {
            continue;
        };
        let mut bytes = serialized.into_bytes();
        if bytes.is_empty() {
            continue;
        }
        match case_rng.below(4) {
            0 => bytes.truncate(case_rng.below(bytes.len())),
            1 => {
                let index = case_rng.below(bytes.len());
                bytes[index] ^= 1 << case_rng.below(8);
            }
            2 => {
                let index = case_rng.below(bytes.len());
                bytes[index] = *case_rng.pick(b"\\\"{}[]:,eE+-0");
            }
            _ => {
                let index = case_rng.below(bytes.len());
                // Splice a hostile escape or exponent in place.
                let payload = *case_rng.pick(&[
                    "\\ud800", "\\u", "e999", "e-999", "\\", "\u{0000}", "1e", "--1",
                ]);
                bytes.splice(index..index, payload.bytes());
            }
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if let Ok(document) = guarded(seed, "parse_document (mutated)", &text, || {
            parse_document(&text, &limits)
        }) {
            check_document(seed, &document);
        }
    }
}

// ===========================================================================
// Canonical JSON (RFC 8785 / JSON-LD 1.1 section 10.2)
// ===========================================================================

/// Wraps `value` as the sole `@json`-typed literal of a one-quad document.
fn json_literal_document(value: Value) -> Value {
    object(vec![
        (
            "@context".to_owned(),
            object(vec![(
                "j".to_owned(),
                object(vec![
                    ("@id".to_owned(), text("http://example.com/j")),
                    ("@type".to_owned(), text("@json")),
                ]),
            )]),
        ),
        ("@id".to_owned(), text("http://example.com/s")),
        ("j".to_owned(), value),
    ])
}

/// Returns the canonical lexical form the codec produced for `value`.
fn canonical_form(
    seed: u64,
    value: Value,
    options: &JsonLdOptions,
) -> Result<String, &'static str> {
    let rendered = value.to_string();
    let document = json_literal_document(value);
    let batches = guarded(seed, "to_quads (@json)", &rendered, || {
        to_quads(&document, options, None)
    })?;
    let reader = QuadStreamReader::new(&batches[0]).map_err(|_error| "invalid batch")?;
    let quad = reader.quad(0).map_err(|_error| "invalid row")?;
    match quad.object {
        TermRef::Literal(literal) => {
            assert_eq!(
                literal.datatype().as_str(),
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON",
                "a @json value must carry the rdf:JSON datatype (seed {seed:#018x})"
            );
            Ok(literal.value().to_owned())
        }
        other => panic!("a @json value produced {other} (seed {seed:#018x})"),
    }
}

/// Hostile scalars for the canonicalizer.
fn generate_canon_value(rng: &mut Rng, depth: usize) -> Value {
    if depth == 0 {
        return text("leaf");
    }
    match rng.below(9) {
        0 => Value::Number(Number::from(*rng.pick(BOUNDARY_INTEGERS))),
        1 => faithful_float(rng).map_or(Value::Null, Value::Number),
        2 => Value::Number(Number::from(u64::MAX)),
        3 => text(rng.pick(&[
            "",
            "\u{0000}\u{001f}\u{0008}\u{0009}\u{000a}\u{000c}\u{000d}",
            "quote\" backslash\\ slash/",
            "\u{10000}\u{10FFFF}",
            "\u{FFFD}\u{FEFF}",
            "surrogate-pair: \u{1D11E}",
            "combining: e\u{0301}",
        ])),
        4 => Value::Bool(rng.chance(2)),
        5 => Value::Null,
        6 => Value::Array(
            (0..rng.below(5))
                .map(|_| generate_canon_value(rng, depth.saturating_sub(1)))
                .collect(),
        ),
        _ => {
            // Keys chosen so UTF-16 order differs from code-point order.
            let keys: &[&str] = &[
                "a",
                "A",
                "\u{FFFD}",
                "\u{10000}",
                "\u{1D11E}",
                "b\u{0000}",
                "",
                "\u{00e9}",
                "z",
            ];
            let mut entries = Vec::new();
            for index in 0..(1 + rng.below(5)) {
                let key = *rng.pick(keys);
                entries.push((
                    format!(
                        "{key}{}",
                        if rng.chance(2) {
                            String::new()
                        } else {
                            index.to_string()
                        }
                    ),
                    generate_canon_value(rng, depth.saturating_sub(1)),
                ));
            }
            object(entries)
        }
    }
}

/// The canonical number form round-trips over the whole `f64` bit space.
///
/// This is the sharp check on the ECMA-262 `Number::toString` implementation
/// and it deliberately does *not* go through `serde_json`'s parser: the
/// serializer is correct exactly when a **correctly rounded** reader
/// recovers the original bits, which `str::parse::<f64>` is and
/// `serde_json` (see [`faithful_float`]) is not at extreme exponents.
/// Random bit patterns are joined by the boundary values RFC 8785 appendix
/// B and ECMA-262 section 7.1.12.1 hinge on.
#[test]
fn json_numbers_round_trip_exactly() {
    let options = fuzz_options();
    let specials: &[f64] = &[
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.1,
        5.5,
        1e21,
        1e20,
        1e-6,
        1e-7,
        f64::MIN,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::from_bits(1),       // smallest subnormal
        9_007_199_254_740_992.0, // 2^53
        -9_007_199_254_740_992.0,
    ];
    let mut rng = Rng::new(CANON_SEED ^ 0xF10A_7000_0000_0001);
    for index in 0..600 {
        let seed = rng.next_u64();
        let original = if index < specials.len() {
            specials[index]
        } else {
            let candidate = f64::from_bits(seed);
            if !candidate.is_finite() {
                continue;
            }
            candidate
        };
        let Some(number) = Number::from_f64(original) else {
            continue;
        };
        let lexical = canonical_form(seed, Value::Number(number), &options)
            .unwrap_or_else(|code| panic!("a finite double was refused ({code}): {original:e}"));
        let recovered: f64 = lexical
            .parse()
            .unwrap_or_else(|error| panic!("`{lexical}` is not a JSON number ({error})"));
        assert_eq!(
            recovered.to_bits(),
            // RFC 8785 serializes -0 as "0"; every other value is exact.
            if original == 0.0 { 0.0_f64 } else { original }.to_bits(),
            "the canonical form `{lexical}` does not round-trip {original:e}"
        );
        assert!(
            !lexical.contains('E') && !lexical.starts_with('+') && !lexical.contains("e0"),
            "`{lexical}` is not in ECMAScript `Number::toString` form"
        );
    }
}

/// 1,200 hostile values through the RFC 8785 canonicalizer.
///
/// Values `serde_json::Value` cannot represent at all (non-finite numbers,
/// lone surrogates) are covered by [`dumb_bytes_never_panic`] at the text
/// level; this test covers everything representable.
#[test]
fn canonical_json_over_hostile_values() {
    let options = fuzz_options();
    let mut rng = Rng::new(CANON_SEED);
    for _ in 0..CANON_CASES {
        let seed = rng.next_u64();
        let mut case_rng = Rng::new(seed);
        let value = generate_canon_value(&mut case_rng, 4);
        let rendered = value.to_string();
        let Ok(lexical) = canonical_form(seed, value.clone(), &options) else {
            // A refusal (a lossy integer, say) must be idempotent.
            let replay = canonical_form(seed, value, &options);
            assert!(
                replay.is_err(),
                "canonicalization refused once and accepted once\n  seed: {seed:#018x}\n  value: {rendered}"
            );
            continue;
        };

        // The canonical form must itself be valid JSON.
        let reparsed: Value = serde_json::from_str(&lexical).unwrap_or_else(|error| {
            panic!(
                "canonical form is not valid JSON ({error})\n  seed: {seed:#018x}\n  value: {rendered}\n  lexical: {lexical}"
            )
        });

        // Invariant 5: the canonical form must not lose or invent data.
        // A number that moved is the upstream parser (see `faithful_float`)
        // and is tolerated *only* as a number; anything structural is a bug.
        let relation = agreement(&value, &reparsed);
        assert_ne!(
            relation,
            Agreement::Different,
            "the canonical form does not reparse to its own value\n  seed: {seed:#018x}\n  value: {rendered}\n  lexical: {lexical}"
        );

        // Idempotence: canonicalizing the reparse reproduces the same bytes.
        // (Byte equality, not `Value` equality — `5.0` canonicalizes to `5`
        // and reparses as an integer, which is correct and expected.)
        let again = canonical_form(seed, reparsed.clone(), &options).unwrap_or_else(|code| {
            panic!(
                "the canonical form of a canonical form was refused ({code})\n  seed: {seed:#018x}\n  lexical: {lexical}"
            )
        });
        if relation == Agreement::Exact {
            assert_eq!(
                lexical, again,
                "canonicalization is not idempotent\n  seed: {seed:#018x}\n  value: {rendered}"
            );
        }

        // No silent mutation: the decoder returns the same value back.
        let document = json_literal_document(reparsed.clone());
        let batches = guarded(seed, "to_quads (@json replay)", &rendered, || {
            to_quads(&document, &options, None)
        })
        .unwrap_or_else(|code| panic!("a canonical value stopped encoding ({code})"));
        let recovered = guarded(seed, "from_quads (@json)", &rendered, || {
            from_quads(&batches)
        })
        .unwrap_or_else(|code| panic!("a rdf:JSON literal failed to decode ({code})"));
        let decoded = &recovered[0]["http://example.com/j"][0]["@value"];
        assert_eq!(
            decoded, &reparsed,
            "the rdf:JSON literal did not decode to its own value\n  seed: {seed:#018x}\n  lexical: {lexical}"
        );
    }
}

// ===========================================================================
// Regression tests — every defect the fuzzing found, pinned by construction
// ===========================================================================

/// Depth of the nested-array payloads used by the depth regressions.
///
/// Chosen above every budget under test and below the depth at which
/// `serde_json`'s own recursive `Drop` would abort the test process.
const REGRESSION_BOMB_DEPTH: usize = 2_000;

/// Builds `[[[…1…]]]` `depth` levels deep without recursing.
fn deep_array(depth: usize) -> Value {
    let mut value = Value::Number(Number::from(1));
    for _ in 0..depth {
        value = Value::Array(vec![value]);
    }
    value
}

/// Regression: a `@json` literal payload escaped every processing budget.
///
/// JSON-LD 1.1 API section 5.1.2 step 13.7 copies the value of a
/// `@json`-typed entry verbatim, so its interior never reached the node or
/// depth counters. `to_quads` then recursively cloned and canonicalized it:
/// at depth 2,000 the process died with `fatal runtime error: stack
/// overflow` instead of returning a typed error, and a flat but enormous
/// payload consumed unbounded work against a `max_nodes` that never saw it.
#[test]
fn regression_json_literal_payload_is_charged_to_the_budget() {
    let options = fuzz_options();
    let document = json_literal_document(deep_array(REGRESSION_BOMB_DEPTH));
    let error = to_quads(&document, &options, None).expect_err("the depth bomb must fail closed");
    assert_eq!(error.code(), "resource_limit");
    assert!(
        error.to_string().contains("depth"),
        "the depth budget must name itself: {error}"
    );
}

/// Regression: the same payload arriving as an already-expanded value
/// object took a different code path (the `@value` keyword branch) and had
/// to be guarded separately.
#[test]
fn regression_expanded_json_literal_is_charged_to_the_budget() {
    let options = fuzz_options();
    let document = object(vec![
        ("@id".to_owned(), text("http://example.com/s")),
        (
            "http://example.com/j".to_owned(),
            object(vec![
                ("@value".to_owned(), deep_array(REGRESSION_BOMB_DEPTH)),
                ("@type".to_owned(), text("@json")),
            ]),
        ),
    ]);
    let error = expand(&document, &options).expect_err("the depth bomb must fail closed");
    assert_eq!(error.code(), "resource_limit");
}

/// Regression: a **flat** context of chained prefixes recursed once per
/// link and overflowed the stack.
///
/// `{"t0":"t1:x","t1":"t2:x",…}` is depth-2 JSON, so neither
/// `serde_json`'s own 128-level parse limit nor `JsonLdLimits::max_depth`
/// (which counts *document* nesting) ever saw it. A 7,853-byte document
/// that `parse_document` accepted killed the process. Terms are now
/// ordered dependencies-first on an explicit stack, and the chain length
/// is still bounded by `MAX_CONTEXT_RECURSION` there, before any native
/// recursion: a chain whose every link is a prefix holds quadratic bytes.
#[test]
fn regression_flat_prefix_chain_fails_closed() {
    let mut entries = Vec::new();
    let length = 5_000;
    for index in 0..length {
        entries.push((format!("t{index}"), text(&format!("t{}:x", index + 1))));
    }
    entries.push((format!("t{length}"), text("http://example.com/chain#")));
    let document = object(vec![
        ("@context".to_owned(), object(entries)),
        ("@id".to_owned(), text("http://example.com/s")),
        ("t0".to_owned(), text("v")),
    ]);
    let text_form = serde_json::to_string(&document).expect("serializes");
    let parsed = parse_document(&text_form, &JsonLdLimits::default())
        .expect("a flat prefix chain is ordinary JSON and parses");
    let error = expand(&parsed, &JsonLdOptions::default()).expect_err("the chain must fail closed");
    assert_eq!(error.code(), "resource_limit");
    assert!(
        error.to_string().contains("context_recursion"),
        "the context-recursion budget must name itself: {error}"
    );
}

/// A chain whose every link is a prefix (`"t0": "t1:x/"`) grows each IRI
/// by two bytes per link: 20,000 links held 600 MB of IRIs from about
/// 500 KB of input. It is refused by chain length before any is built.
#[test]
fn growing_prefix_chain_is_refused_before_it_is_built() {
    let mut entries = Vec::new();
    let length = 20_000;
    for index in 0..length {
        entries.push((format!("t{index}"), text(&format!("t{}:x/", index + 1))));
    }
    entries.push((format!("t{length}"), text("http://example.com/")));
    let document = object(vec![
        ("@context".to_owned(), object(entries)),
        ("t0".to_owned(), text("v")),
    ]);
    let error = expand(&document, &JsonLdOptions::default()).expect_err("refused");
    assert!(error.to_string().contains("context_recursion"), "{error}");
}

/// Regression: nested scoped contexts recursed through
/// `validate_scoped_context` -> `process_context` with no budget.
#[test]
fn regression_nested_scoped_contexts_fail_closed() {
    let mut inner = object(vec![(
        "a".to_owned(),
        object(vec![("@id".to_owned(), text("http://example.com/a"))]),
    )]);
    for _ in 0..1_000 {
        inner = object(vec![(
            "a".to_owned(),
            object(vec![
                ("@id".to_owned(), text("http://example.com/a")),
                ("@context".to_owned(), inner),
            ]),
        )]);
    }
    let document = object(vec![
        ("@context".to_owned(), inner),
        ("@id".to_owned(), text("http://example.com/s")),
    ]);
    let error = expand(&document, &JsonLdOptions::default()).expect_err("must fail closed");
    assert_eq!(error.code(), "resource_limit");
}

/// A prefix chain just inside the budget still resolves, so the fix bounds
/// the recursion without refusing legitimate contexts.
///
/// Every link ends in a gen-delim, so every link is itself a prefix and the
/// whole chain really does recurse `length` levels deep.
#[test]
fn short_prefix_chain_still_resolves() {
    let mut entries = Vec::new();
    let length = 8;
    for index in 0..length {
        entries.push((format!("t{index}"), text(&format!("t{}:", index + 1))));
    }
    entries.push((format!("t{length}"), text("http://example.com/chain#")));
    let document = object(vec![
        ("@context".to_owned(), object(entries)),
        ("@id".to_owned(), text("http://example.com/s")),
        ("t0".to_owned(), text("v")),
    ]);
    let expanded = expand(&document, &JsonLdOptions::default()).expect("a short chain resolves");
    assert_eq!(
        expanded[0]["http://example.com/chain#"][0]["@value"], "v",
        "the chain must resolve to the terminal prefix: {expanded}"
    );
}

/// Regression: term selection treated every term as a universal fallback.
///
/// IRI Compaction appends `@any` to the preferred values, and Term
/// Selection looked `@any` up in the container's *any* map — whose `@none`
/// entry every term populates for the empty-`@list` lookup — instead of in
/// the selected type or language map. A term coercing to `@type: @json`
/// was therefore selected for a plain number, and re-expanding the
/// compacted document wrapped the number in a second value object:
/// `expand(compact(doc)) != expand(doc)`.
#[test]
fn regression_json_coercing_term_is_not_selected_for_a_plain_number() {
    let options = JsonLdOptions::default();
    let context = object(vec![(
        "t1".to_owned(),
        object(vec![
            ("@id".to_owned(), text("http://example.com/j")),
            ("@type".to_owned(), text("@json")),
        ]),
    )]);
    let document = object(vec![
        ("@context".to_owned(), context.clone()),
        ("@id".to_owned(), text("http://example.com/s")),
        (
            "http://example.com/j".to_owned(),
            Value::Number(Number::from(7)),
        ),
    ]);
    let expanded = expand(&document, &options).expect("expands");
    let compacted = compact(&document, &context, &options).expect("compacts");
    let re_expanded = expand(&compacted, &options).expect("re-expands");
    assert_eq!(
        re_expanded, expanded,
        "compaction must not coerce a plain number into a JSON literal: {compacted}"
    );
}

/// Regression: a colon without a scheme was mistaken for a compact IRI.
///
/// IRI expansion returned any colon-bearing value verbatim once prefix
/// lookup failed, so `/:` — a relative reference, since `/` is not a valid
/// scheme — never reached base resolution. Compaction emits exactly that
/// shape when the base ends at an authority, so the round-trip broke.
#[test]
fn regression_colon_without_a_scheme_resolves_against_the_base() {
    let options = JsonLdOptions::default();
    let context = object(vec![("@base".to_owned(), text("http://"))]);
    let document = object(vec![
        ("@context".to_owned(), context),
        ("@id".to_owned(), text("/:")),
        ("http://example.com/p".to_owned(), text("v")),
    ]);
    let expanded = expand(&document, &options).expect("expands");
    assert_eq!(
        expanded[0]["@id"], "http:///:",
        "a scheme-less colon must resolve against @base: {expanded}"
    );
}

/// Regression: `i64::MAX` and `u64::MAX` were silently changed, not refused.
///
/// The exactness check was `(integer as f64) as i64 == integer`, but a
/// float-to-integer `as` cast **saturates**: `i64::MAX as f64` rounds up to
/// `2^63` and casts back to `i64::MAX`, so the lossy value looked exact and
/// was emitted as `9223372036854776000` — a different number, silently.
#[test]
fn regression_saturating_integer_boundaries_fail_closed() {
    let options = fuzz_options();
    for boundary in [
        Value::Number(Number::from(i64::MAX)),
        Value::Number(Number::from(u64::MAX)),
        Value::Number(Number::from(i64::MAX - 1)),
    ] {
        let rendered = boundary.to_string();
        let error = to_quads(&json_literal_document(boundary), &options, None)
            .expect_err("a lossy integer must fail closed");
        assert_eq!(error.code(), "invalid_term", "for {rendered}");
    }
    // The largest exactly representable neighbours still encode.
    for exact in [
        Value::Number(Number::from(i64::MIN)),
        Value::Number(Number::from(9_007_199_254_740_992_i64)),
        Value::Number(Number::from(1_u64 << 63)),
    ] {
        let rendered = exact.to_string();
        to_quads(&json_literal_document(exact), &options, None)
            .unwrap_or_else(|error| panic!("{rendered} is exact but was refused: {error}"));
    }
}

/// Plain document nesting trips the *document* depth budget as a typed
/// error — the control case the `@json` regressions are measured against.
#[test]
fn plain_nesting_trips_the_depth_budget() {
    let options = fuzz_options();
    let document = object(vec![
        ("@id".to_owned(), text("http://example.com/s")),
        ("http://example.com/p".to_owned(), deep_array(300)),
    ]);
    let error = expand(&document, &options).expect_err("deep nesting must fail closed");
    assert_eq!(error.code(), "resource_limit");
    assert!(
        error.to_string().contains("depth"),
        "the depth budget must name itself: {error}"
    );
}

/// Malformed `@language` tags fail closed, in a value object and in a term
/// definition alike.
///
/// The generator emits these shapes on every run, but the never-panic guard
/// alone would let a regression that *accepted* one pass unnoticed: this
/// pins the typed outcome. A fail-closed dataplane has no warning channel,
/// so the spec's "invalid language-tagged string" warning is an error here.
#[test]
fn malformed_language_tags_fail_closed() {
    let options = JsonLdOptions::default();
    for tag in ["", "e n", "-en", "en-", "en_US", "en--US"] {
        let in_value = object(vec![
            ("@id".to_owned(), text("http://example.com/s")),
            (
                "http://example.com/p".to_owned(),
                object(vec![
                    ("@value".to_owned(), text("v")),
                    ("@language".to_owned(), text(tag)),
                ]),
            ),
        ]);
        let error = expand(&in_value, &options)
            .err()
            .or_else(|| to_quads(&in_value, &options, None).err())
            .unwrap_or_else(|| panic!("the language tag {tag:?} must fail closed"));
        assert!(
            matches!(error.code(), "invalid_document" | "invalid_term"),
            "the language tag {tag:?} produced {}",
            error.code()
        );

        let in_term = object(vec![
            (
                "@context".to_owned(),
                object(vec![(
                    "p".to_owned(),
                    object(vec![
                        ("@id".to_owned(), text("http://example.com/p")),
                        ("@language".to_owned(), text(tag)),
                    ]),
                )]),
            ),
            ("@id".to_owned(), text("http://example.com/s")),
            ("p".to_owned(), text("v")),
        ]);
        let error = expand(&in_term, &options)
            .err()
            .or_else(|| to_quads(&in_term, &options, None).err())
            .unwrap_or_else(|| panic!("the term language tag {tag:?} must fail closed"));
        assert!(
            matches!(
                error.code(),
                "invalid_context" | "invalid_document" | "invalid_term"
            ),
            "the term language tag {tag:?} produced {}",
            error.code()
        );
    }
}

/// A `@protected` term redefined by the second entry of an array context is
/// refused by name.
///
/// This is the exact shape the structure-aware generator builds (a base
/// context followed by a redefining one); asserting the typed outcome keeps
/// that corpus from degenerating into a pure crash test.
#[test]
fn protected_redefinition_in_an_array_context_fails_closed() {
    let options = JsonLdOptions::default();
    let document = object(vec![
        (
            "@context".to_owned(),
            Value::Array(vec![
                object(vec![
                    ("@protected".to_owned(), Value::Bool(true)),
                    ("t0".to_owned(), text("http://example.com/first")),
                ]),
                object(vec![("t0".to_owned(), text("http://example.com/second"))]),
            ]),
        ),
        ("@id".to_owned(), text("http://example.com/s")),
        ("t0".to_owned(), text("v")),
    ]);
    let error = expand(&document, &options).expect_err("a protected redefinition must fail");
    assert_eq!(error.code(), "protected_term");

    // An identical redefinition stays legal (spec section 4.1.2 step 5.2.1).
    let identical = object(vec![
        (
            "@context".to_owned(),
            Value::Array(vec![
                object(vec![
                    ("@protected".to_owned(), Value::Bool(true)),
                    ("t0".to_owned(), text("http://example.com/first")),
                ]),
                object(vec![("t0".to_owned(), text("http://example.com/first"))]),
            ]),
        ),
        ("@id".to_owned(), text("http://example.com/s")),
        ("t0".to_owned(), text("v")),
    ]);
    let expanded = expand(&identical, &options).expect("an identical redefinition is legal");
    assert_eq!(expanded[0]["http://example.com/first"][0]["@value"], "v");
}
