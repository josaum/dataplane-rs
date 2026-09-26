// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Deterministic, seeded fuzzing of the RDF 1.2 triple-term parser.
//!
//! `quoted::parse_triple_term` is the highest-value target in this crate: it
//! is hand-rolled, recursive, and reads text that arrives inside a foreign
//! Arrow batch, so an attacker chooses every byte of it.
//!
//! Invariants asserted here, in the order the task graph cares about them:
//!
//! 1. **Never panic.** No input — random bytes, mutated encodings, truncated
//!    escapes — may unwind. Every refusal is a typed [`QuadError`].
//! 2. **Never hang or exhaust.** `max_quoted_depth` trips *before* the
//!    recursion, proven by a 200 000-deep prefix that must return
//!    [`QuadResource::QuotedDepth`] inside a wall-clock budget.
//! 3. **Round-trip.** `parse(encode(t)) == t` for every triple the encoder
//!    accepts, including RDF 1.2 directional language-tagged strings.
//! 4. **Idempotent refusal.** A rejected input is rejected identically every
//!    time, same error code and same message.
//! 5. **No silent mutation.** A successful parse re-encodes to the same bytes
//!    it was parsed from when those bytes were canonical, and never invents,
//!    drops, or rewrites a component.
//!
//! Iteration counts are sized to keep the whole file under a few seconds in
//! a debug build; each `for` loop names its count.

mod support;

use std::time::{Duration, Instant};

use oxrdf::{BaseDirection, Literal, NamedNode, Term, Triple};
use quad_fast_core::{
    DEFAULT_MAX_QUOTED_DEPTH, QuadError, QuadResource, encode_triple_term, parse_triple_term,
    term_depth,
};
use support::{AWKWARD_LEXICALS, Rng, random_iri, random_term};

/// Master seed. Constant on purpose: the suite must be reproducible.
const MASTER_SEED: u64 = 0x5177_0A3D_C0FF_EE01;

/// Wall-clock budget for any single parse. Generous by ~3 orders of
/// magnitude, so it only fires on unbounded work, never on a slow machine.
const PARSE_BUDGET: Duration = Duration::from_secs(2);

fn iri(value: &str) -> NamedNode {
    NamedNode::new(value).expect("test IRI must be valid")
}

/// Runs `body`, converting a panic into a test failure that names the seed.
fn no_panic<T>(seed: u64, input: &str, body: impl FnOnce() -> T + std::panic::UnwindSafe) -> T {
    match std::panic::catch_unwind(body) {
        Ok(value) => value,
        Err(_payload) => panic!(
            "PANIC in triple-term parser.\n  seed = {seed:#018x}\n  input = {input:?}\n  \
             input bytes = {:?}",
            input.as_bytes()
        ),
    }
}

/// Parses twice and asserts the two outcomes are identical (invariant 4).
fn parse_idempotently(seed: u64, input: &str, max_depth: usize) -> Result<Triple, QuadError> {
    let first = no_panic(seed, input, || parse_triple_term(input, max_depth));
    let second = no_panic(seed, input, || parse_triple_term(input, max_depth));
    match (&first, &second) {
        (Ok(left), Ok(right)) => assert_eq!(
            left, right,
            "non-deterministic accept.\n  seed = {seed:#018x}\n  input = {input:?}"
        ),
        (Err(left), Err(right)) => {
            assert_eq!(
                left.code(),
                right.code(),
                "non-deterministic refusal code.\n  seed = {seed:#018x}\n  input = {input:?}"
            );
            assert_eq!(
                left.to_string(),
                right.to_string(),
                "non-deterministic refusal message.\n  seed = {seed:#018x}\n  input = {input:?}"
            );
        }
        _ => panic!(
            "same input both accepted and refused.\n  seed = {seed:#018x}\n  input = {input:?}"
        ),
    }
    first
}

// --- dumb generator: arbitrary text ---------------------------------------

/// 3 000 cases of unstructured text, biased toward the parser's alphabet.
#[test]
fn arbitrary_text_never_panics_and_refuses_idempotently() {
    const CASES: u64 = 3_000;
    let alphabet: &[&str] = &[
        "<<(",
        ")>>",
        "<",
        ">",
        "\"",
        "_:",
        "@",
        "^^",
        "\\",
        "\\u",
        " ",
        "0041",
        "en",
        "--ltr",
        "--rtl",
        "http://e/x",
        "\u{1f600}",
        "\u{0}",
        "-",
        "abc",
    ];
    for case in 0..CASES {
        let seed = Rng::seed_for(MASTER_SEED, case);
        let mut rng = Rng::new(seed);
        let mut input = String::new();
        let pieces = rng.between(0, 24);
        for _ in 0..pieces {
            if rng.chance(6) {
                input.push(char::from(rng.byte().max(1)));
            } else {
                input.push_str(rng.pick(alphabet));
            }
        }
        let max_depth = rng.below(DEFAULT_MAX_QUOTED_DEPTH + 2);
        let outcome = parse_idempotently(seed, &input, max_depth);
        if let Ok(triple) = outcome {
            assert!(
                term_depth(Term::Triple(Box::new(triple.clone())).as_ref()) <= max_depth,
                "accepted a triple deeper than the limit.\n  seed = {seed:#018x}\n  \
                 input = {input:?}"
            );
        }
    }
}

/// 2 000 cases of raw bytes reinterpreted as text where they are valid UTF-8.
///
/// Byte-level mutation can only reach the parser through `str`, so cases that
/// stop being UTF-8 are re-generated rather than sliced (slicing them would
/// panic in the *harness*, not in the parser).
#[test]
fn arbitrary_bytes_never_panic() {
    const CASES: u64 = 2_000;
    let mut accepted = 0u32;
    for case in 0..CASES {
        let seed = Rng::seed_for(MASTER_SEED ^ 0xAA, case);
        let mut rng = Rng::new(seed);
        let length = rng.between(0, 64);
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            bytes.push(if rng.chance(3) {
                *rng.pick(b"<>()\"_:@^\\ ")
            } else {
                rng.byte()
            });
        }
        let Ok(input) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if parse_idempotently(seed, input, DEFAULT_MAX_QUOTED_DEPTH).is_ok() {
            accepted += 1;
        }
    }
    // Not an assertion about the parser, a guard on the harness: if this ever
    // becomes non-zero the generator started producing structure by accident
    // and the count is worth looking at.
    assert_eq!(accepted, 0, "unstructured bytes parsed as a triple term");
}

// --- structure-aware generator --------------------------------------------

/// Mutations applied to a well-formed encoding.
#[derive(Clone, Copy, Debug)]
enum Mutation {
    /// Cut the encoding short at a character boundary.
    Truncate,
    /// Flip one character to another from the parser's alphabet.
    Substitute,
    /// Drop one character.
    Delete,
    /// Duplicate a run of characters (duplicate delimiters, duplicate terms).
    Duplicate,
    /// Wrap the encoding in more `<<(` … `)>>` layers than the limit allows.
    Deepen,
    /// Corrupt a `\u` escape's hex digits.
    CorruptEscape,
    /// Append trailing content after a complete term.
    Trail,
}

const MUTATIONS: [Mutation; 7] = [
    Mutation::Truncate,
    Mutation::Substitute,
    Mutation::Delete,
    Mutation::Duplicate,
    Mutation::Deepen,
    Mutation::CorruptEscape,
    Mutation::Trail,
];

fn apply(rng: &mut Rng, mutation: Mutation, encoding: &str) -> String {
    let chars: Vec<char> = encoding.chars().collect();
    match mutation {
        Mutation::Truncate => chars[..rng.below(chars.len().max(1))].iter().collect(),
        Mutation::Substitute => {
            let mut out = chars.clone();
            if !out.is_empty() {
                let index = rng.below(out.len());
                out[index] = *rng.pick(&[
                    '<',
                    '>',
                    '(',
                    ')',
                    '"',
                    '_',
                    ':',
                    '@',
                    '^',
                    '\\',
                    ' ',
                    'u',
                    '0',
                    '\u{1f600}',
                ]);
            }
            out.into_iter().collect()
        }
        Mutation::Delete => {
            let mut out = chars.clone();
            if !out.is_empty() {
                let index = rng.below(out.len());
                out.remove(index);
            }
            out.into_iter().collect()
        }
        Mutation::Duplicate => {
            let mut out = chars.clone();
            if !out.is_empty() {
                let start = rng.below(out.len());
                let end = (start + rng.between(1, 4)).min(out.len());
                let run: Vec<char> = out[start..end].to_vec();
                out.splice(end..end, run);
            }
            out.into_iter().collect()
        }
        Mutation::Deepen => {
            let layers = rng.between(1, DEFAULT_MAX_QUOTED_DEPTH * 2);
            let mut out = String::new();
            for _ in 0..layers {
                out.push_str("<<( <http://e/s> <http://e/p> ");
            }
            out.push_str(encoding);
            for _ in 0..layers {
                out.push_str(" )>>");
            }
            out
        }
        Mutation::CorruptEscape => encoding.replace("\\u", "\\u\u{ff}").replace("\\\\", "\\z"),
        Mutation::Trail => {
            let mut out = encoding.to_owned();
            out.push_str(rng.pick(&[" ", ")>>", "<<(", "\u{0}", "junk"]));
            out
        }
    }
}

/// 4 000 cases: encode a random triple, then mutate it seven ways.
#[test]
fn well_formed_encodings_round_trip_and_mutants_never_panic() {
    const CASES: u64 = 4_000;
    for case in 0..CASES {
        let seed = Rng::seed_for(MASTER_SEED ^ 0x5151, case);
        let mut rng = Rng::new(seed);
        let depth_budget = rng.below(4);
        let triple = Triple::new(
            random_iri(&mut rng),
            random_iri(&mut rng),
            random_term(&mut rng, depth_budget),
        );
        let encoding = encode_triple_term(triple.as_ref());
        let depth = term_depth(Term::Triple(Box::new(triple.clone())).as_ref());

        // Invariant 3: round-trip under a limit that admits the term.
        let parsed = parse_idempotently(seed, &encoding, DEFAULT_MAX_QUOTED_DEPTH + 4)
            .unwrap_or_else(|error| {
                panic!(
                    "canonical encoding failed to parse.\n  seed = {seed:#018x}\n  \
                     encoding = {encoding:?}\n  error = {error}"
                )
            });
        assert_eq!(
            parsed, triple,
            "round-trip changed the triple.\n  seed = {seed:#018x}\n  encoding = {encoding:?}"
        );
        // Invariant 5: re-encoding a canonical parse reproduces the bytes.
        assert_eq!(
            encode_triple_term(parsed.as_ref()),
            encoding,
            "re-encoding a parsed triple changed its bytes.\n  seed = {seed:#018x}"
        );

        // Invariant 2 on the write path's own limit: a term deeper than the
        // limit is refused, and refused as a depth limit, not as a syntax
        // error.
        if depth > 0 {
            let error = parse_triple_term(&encoding, depth - 1)
                .expect_err("a limit below the term's depth must refuse it");
            assert!(
                matches!(
                    error,
                    QuadError::ResourceLimit {
                        resource: QuadResource::QuotedDepth,
                        ..
                    }
                ),
                "depth overflow refused as {error} instead of a quoted_depth limit.\n  \
                 seed = {seed:#018x}"
            );
        }

        for mutation in MUTATIONS {
            let mutant = apply(&mut rng, mutation, &encoding);
            let outcome = parse_idempotently(seed, &mutant, DEFAULT_MAX_QUOTED_DEPTH);
            if let Ok(accepted) = outcome {
                // Invariant 5 on mutants: whatever the parser accepted, its
                // own canonical form must parse back to the same value.
                let recoded = encode_triple_term(accepted.as_ref());
                let reparsed = parse_idempotently(seed, &recoded, DEFAULT_MAX_QUOTED_DEPTH + 4)
                    .expect("a re-encoded accepted triple must parse");
                assert_eq!(
                    reparsed, accepted,
                    "accepted value is not stable under re-encoding.\n  seed = {seed:#018x}\n  \
                     mutation = {mutation:?}\n  mutant = {mutant:?}"
                );
            }
        }
    }
}

// --- bounded work ---------------------------------------------------------

/// A 200 000-deep prefix must trip the depth limit, not the stack.
///
/// This is the load-bearing proof that the limit is checked *before* the
/// recursion: a parser that recursed first would overflow the stack here,
/// and a parser that allocated first would take unbounded time.
#[test]
fn depth_limit_trips_before_recursion() {
    const LAYERS: usize = 200_000;
    let mut input = String::with_capacity(LAYERS * 4 + 64);
    for _ in 0..LAYERS {
        input.push_str("<<( ");
    }
    input.push_str("<http://e/s> <http://e/p> \"leaf\"^^<http://www.w3.org/2001/XMLSchema#string>");

    for limit in [0, 1, DEFAULT_MAX_QUOTED_DEPTH, 64] {
        let started = Instant::now();
        let error = parse_triple_term(&input, limit)
            .expect_err("a 200 000-deep prefix must be refused at every sane limit");
        let elapsed = started.elapsed();
        assert!(
            matches!(
                error,
                QuadError::ResourceLimit {
                    resource: QuadResource::QuotedDepth,
                    ..
                }
            ),
            "deep nesting refused as `{error}` instead of a quoted_depth limit (limit {limit})"
        );
        assert!(
            elapsed < PARSE_BUDGET,
            "refusing a {LAYERS}-deep prefix took {elapsed:?} at limit {limit}; the limit is not \
             tripping before the recursion"
        );
    }
}

/// A long flat input must not cost more than linear time to refuse.
#[test]
fn long_flat_input_is_refused_in_bounded_time() {
    for filler in ["a", "\\u0041", "\"", " ", "<"] {
        let input = filler.repeat(200_000);
        let started = Instant::now();
        let outcome = parse_triple_term(&input, DEFAULT_MAX_QUOTED_DEPTH);
        assert!(
            outcome.is_err(),
            "flat filler {filler:?} parsed as a triple term"
        );
        assert!(
            started.elapsed() < PARSE_BUDGET,
            "refusing 200 000 copies of {filler:?} exceeded the budget"
        );
    }
}

// --- regressions ----------------------------------------------------------

/// Regression, seed `0x5177_0a3d_c0ff_ee01` case 0 of the round-trip leg:
/// the encoder dropped the RDF 1.2 base direction of a directional
/// language-tagged string, so `"x"@en--ltr` round-tripped to `"x"@en`.
///
/// Silent data loss, not a refusal: nothing in the pipeline reported it.
#[test]
fn regression_directional_literal_round_trips_through_a_triple_term() {
    for direction in [BaseDirection::Ltr, BaseDirection::Rtl] {
        for lexical in AWKWARD_LEXICALS {
            let literal =
                Literal::new_directional_language_tagged_literal(lexical, "en", direction)
                    .expect("directional literal must build");
            let triple = Triple::new(
                iri("http://example.com/s"),
                iri("http://example.com/p"),
                Term::Literal(literal.clone()),
            );
            let encoding = encode_triple_term(triple.as_ref());
            assert!(
                encoding.contains(if matches!(direction, BaseDirection::Ltr) {
                    "@en--ltr"
                } else {
                    "@en--rtl"
                }),
                "encoding lost the base direction: {encoding}"
            );
            let parsed = parse_triple_term(&encoding, DEFAULT_MAX_QUOTED_DEPTH)
                .expect("directional encoding must parse");
            assert_eq!(parsed, triple, "directional literal did not round-trip");
            assert_eq!(
                parsed.object,
                Term::Literal(literal),
                "direction was dropped on the way back"
            );
        }
    }
}

/// A base direction that is not `ltr` or `rtl` is a typed refusal, never a
/// language tag with an odd suffix.
#[test]
fn unknown_base_direction_is_refused() {
    for tag in ["en--", "en--LTR", "en--up", "--ltr", "en--ltr--rtl"] {
        let input = format!("<<( <http://example.com/s> <http://example.com/p> \"x\"@{tag} )>>");
        let error = parse_triple_term(&input, DEFAULT_MAX_QUOTED_DEPTH)
            .expect_err("a malformed LANG_DIR suffix must be refused");
        assert_eq!(
            error.code(),
            "term",
            "unexpected refusal class for `{tag}`: {error}"
        );
    }
}
