// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Shared, dependency-free fuzzing scaffolding for the `quad-fast-core` suites.
//!
//! Everything here is **deterministic**: the generators are driven by a
//! seeded xorshift PRNG and never read the clock, the thread id, or the
//! environment. A failing case is reproduced by re-running the same test.
//!
//! No `arbitrary`, `proptest`, or `quickcheck`: this cartridge hand-rolls its
//! readers, so it hand-rolls the harness that attacks them, and only stable
//! Rust is available (`cargo-fuzz`/libfuzzer need nightly).

#![allow(
    dead_code,
    reason = "shared by two fuzz binaries; each one exercises a subset"
)]

use oxrdf::{
    BaseDirection, BlankNode, GraphName, Literal, NamedNode, NamedOrBlankNode, Quad, Term, Triple,
};
use quad_fast_core::SourceProvenance;

/// xorshift64 PRNG with a `splitmix64` seed mixer.
///
/// Chosen over a hash-based generator so a case number maps to a stable
/// stream with no allocation and no dependency.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Seeds the generator; a zero seed is replaced by the golden ratio
    /// constant because xorshift is absorbing at zero.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { GOLDEN } else { seed },
        }
    }

    /// Derives the per-case seed for `case` under `master`.
    ///
    /// Printed on failure so one integer reproduces the exact input.
    #[must_use]
    pub fn seed_for(master: u64, case: u64) -> u64 {
        splitmix64(master ^ case.wrapping_mul(GOLDEN))
    }

    /// Returns the next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut state = self.state;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.state = state;
        state
    }

    /// Returns a value in `0..bound`, or `0` when `bound` is zero.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        usize::try_from(self.next_u64() % bound as u64).unwrap_or(0)
    }

    /// Returns a value in `low..=high`.
    pub fn between(&mut self, low: usize, high: usize) -> usize {
        low + self.below(high.saturating_sub(low) + 1)
    }

    /// Returns one uniformly random byte.
    pub fn byte(&mut self) -> u8 {
        u8::try_from(self.next_u64() >> 56).unwrap_or(0)
    }

    /// Returns `true` with probability `1 / one_in`.
    pub fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in.max(1)) == 0
    }

    /// Picks one element of `choices`.
    pub fn pick<'a, T>(&mut self, choices: &'a [T]) -> &'a T {
        &choices[self.below(choices.len())]
    }
}

/// Golden-ratio odd constant used for seeding and mixing.
const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(GOLDEN);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Integers that sit on a representation boundary.
///
/// Fed into the provenance offset columns so a decoder that truncates,
/// sign-extends, or saturates is caught rather than merely exercised.
pub const BOUNDARY_U64: [u64; 8] = [
    0,
    1,
    255,
    256,
    4_294_967_295,
    4_294_967_296,
    u64::MAX - 1,
    u64::MAX,
];

/// Signed boundaries for the microsecond timestamp column.
pub const BOUNDARY_I64: [i64; 7] = [i64::MIN, -1, 0, 1, 2_147_483_647, i64::MAX - 1, i64::MAX];

/// Little-endian `u32` boundaries used to corrupt IPC length fields.
pub const BOUNDARY_U32: [u32; 7] = [0, 1, 7, 0x7FFF_FFFF, 0x8000_0000, u32::MAX - 1, u32::MAX];

/// Lexical forms chosen to stress the escape paths of the term serializer.
pub const AWKWARD_LEXICALS: [&str; 10] = [
    "",
    "plain",
    "with \"quotes\" inside",
    "back\\slash",
    "line\nbreak\ttab\r",
    "\u{0}\u{1}\u{1f}",
    "unicode \u{1f600} \u{4e2d}\u{6587}",
    "<<( looks like a triple term )>>",
    " leading and trailing ",
    "\u{7f}\u{80}\u{a0}",
];

/// Generates one pseudo-random quad, optionally admitting triple terms.
///
/// Subjects and predicates are drawn from a small pool on purpose: repeated
/// values are what the dictionary columns are for, so a generator that never
/// repeats would leave the dictionary path untested.
pub fn random_quad(rng: &mut Rng, max_triple_depth: usize) -> Quad {
    let subject: NamedOrBlankNode = if rng.chance(4) {
        BlankNode::new(format!("b{}", rng.below(8)))
            .expect("generated blank node label is valid")
            .into()
    } else {
        random_iri(rng).into()
    };
    let predicate = NamedNode::new(format!("http://example.com/p{}", rng.below(6)))
        .expect("generated predicate IRI is valid");
    let object = random_term(rng, max_triple_depth);
    let graph_name = match rng.below(4) {
        0 => GraphName::DefaultGraph,
        1 => GraphName::BlankNode(
            BlankNode::new(format!("g{}", rng.below(4))).expect("generated graph label is valid"),
        ),
        _ => GraphName::NamedNode(random_iri(rng)),
    };
    Quad::new(subject, predicate, object, graph_name)
}

/// Generates one pseudo-random IRI from a bounded pool.
pub fn random_iri(rng: &mut Rng) -> NamedNode {
    NamedNode::new(format!(
        "http://example.com/{}/{}",
        rng.pick(&["a", "b", "c", "deep/path", "x%20y", "q?k=v#frag"]),
        rng.below(16)
    ))
    .expect("generated IRI is valid")
}

/// Generates one pseudo-random term, nesting triple terms up to `max_depth`.
pub fn random_term(rng: &mut Rng, max_depth: usize) -> Term {
    if max_depth > 0 && rng.chance(3) {
        let subject: NamedOrBlankNode = if rng.chance(3) {
            BlankNode::new(format!("q{}", rng.below(4)))
                .expect("generated blank node label is valid")
                .into()
        } else {
            random_iri(rng).into()
        };
        return Term::Triple(Box::new(Triple::new(
            subject,
            random_iri(rng),
            random_term(rng, max_depth - 1),
        )));
    }
    match rng.below(4) {
        0 => Term::NamedNode(random_iri(rng)),
        1 => Term::BlankNode(
            BlankNode::new(format!("o{}", rng.below(8))).expect("generated blank node is valid"),
        ),
        _ => Term::Literal(random_literal(rng)),
    }
}

/// Generates one pseudo-random literal, including RDF 1.2 directional ones.
pub fn random_literal(rng: &mut Rng) -> Literal {
    let lexical = (*rng.pick(&AWKWARD_LEXICALS)).to_owned();
    match rng.below(5) {
        0 => Literal::new_simple_literal(lexical),
        1 => Literal::new_typed_literal(
            lexical,
            NamedNode::new(format!(
                "http://www.w3.org/2001/XMLSchema#{}",
                rng.pick(&["integer", "double", "date", "string"])
            ))
            .expect("generated datatype IRI is valid"),
        ),
        2 => Literal::new_language_tagged_literal(lexical, *rng.pick(&["en", "de-DE", "pt-BR"]))
            .expect("generated language tag is valid"),
        _ => Literal::new_directional_language_tagged_literal(
            lexical,
            *rng.pick(&["en", "ar", "he-IL"]),
            if rng.chance(2) {
                BaseDirection::Ltr
            } else {
                BaseDirection::Rtl
            },
        )
        .expect("generated directional language tag is valid"),
    }
}

/// Generates provenance whose numeric fields sit on representation boundaries.
pub fn random_provenance(rng: &mut Rng) -> Option<SourceProvenance> {
    if rng.chance(4) {
        return None;
    }
    let mut digest = [0u8; 32];
    for slot in &mut digest {
        *slot = rng.byte();
    }
    Some(SourceProvenance {
        source_artifact_iri: if rng.chance(3) {
            None
        } else {
            Some(format!("http://example.com/artifact/{}", rng.below(4)))
        },
        source_content_sha256: if rng.chance(3) { None } else { Some(digest) },
        source_offset_start: if rng.chance(3) {
            None
        } else {
            Some(*rng.pick(&BOUNDARY_U64))
        },
        source_offset_end: if rng.chance(3) {
            None
        } else {
            Some(*rng.pick(&BOUNDARY_U64))
        },
        observed_at_micros: if rng.chance(3) {
            None
        } else {
            Some(*rng.pick(&BOUNDARY_I64))
        },
    })
}
