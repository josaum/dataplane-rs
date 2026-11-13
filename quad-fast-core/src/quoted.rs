// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Triple terms (RDF-star / RDF 1.2) inside the `UnsignedQuadStream` contract.
//!
//! # Which RDF-star?
//!
//! The dataplane's single term model is [`oxrdf`] 0.3 (workspace pin), whose
//! `rdf-12` feature implements **RDF 1.2** triple terms: `Term::Triple` exists
//! in the object position only, and the subject position stays
//! `NamedOrBlankNode`. That matches RDF 1.2 Concepts §
//! [Triple Terms](https://www.w3.org/TR/rdf12-concepts/#dfn-triple-term),
//! which admits a triple term "only in the object position of a triple",
//! unlike the 2021 RDF-star Community Group report, which also allowed quoted
//! triples as subjects.
//!
//! This crate therefore **supports** triple terms as objects and **refuses**
//! them as subjects, predicates, and graph names with a typed error. The
//! refusal is a property of the term model, not a scoping shortcut: a
//! subject-position quoted triple is unrepresentable in `oxrdf` 0.3.
//!
//! # Wire encoding
//!
//! No Arrow column was added. A triple-term object is stored as:
//!
//! * `object_kind` = [`TERM_KIND_TRIPLE`] (`"triple"`),
//! * `object_value` = the canonical serialization below,
//! * `object_datatype_iri` = null, `object_language` = null.
//!
//! The serialization is the RDF 1.2 N-Triples triple-term syntax
//! ([N-Triples 1.2 §2.5](https://www.w3.org/TR/rdf12-n-triples/), production
//! `tripleTerm`):
//!
//! ```text
//! <<( <http://example.com/s> <http://example.com/p> "o" )>>
//! ```
//!
//! with exactly one ASCII space between the delimiters and each term, terms
//! written in canonical N-Triples form (IRIs `<…>`, blank nodes `_:label`,
//! literals `"lex"`, `"lex"@tag`, `"lex"@tag--ltr`, `"lex"^^<datatype>` —
//! `xsd:string` is written explicitly, never elided), and nesting handled
//! recursively. The encoding is deterministic: the same triple always
//! produces the same bytes, which keeps batch-level hashing and dictionary
//! sharing stable.
//!
//! # Base direction, and why it lives here but not in the flat columns
//!
//! An RDF 1.2 *directional* language-tagged string carries `ltr`/`rtl`
//! alongside its language tag. This encoding is a full N-Triples
//! serialization, so it carries the direction in the `LANG_DIR` suffix
//! (`"lex"@en--ltr`) and round-trips losslessly. The flat contract columns
//! cannot: `object_value` / `object_language` / `object_datatype_iri` have no
//! slot for a direction, and the Arrow schema is frozen at
//! [`crate::CONTRACT_VERSION`]. A directional literal in the *top-level*
//! object position is therefore refused by
//! [`crate::QuadBatchBuilder::push`] with
//! [`crate::FEATURE_BASE_DIRECTION`], rather than stored with the direction
//! silently dropped. The asymmetry mirrors the existing
//! [`crate::QuadStreamReader::quad`] / `quad_owned` split: a self-describing
//! serialization can hold what a fixed column set cannot.
//!
//! # Fail-closed depth
//!
//! Nesting is bounded by [`crate::QuadLimits::max_quoted_depth`]. Depth 0 is a
//! term that is not a triple term; a triple term whose components are not
//! triple terms has depth 1. Exceeding the limit is
//! [`QuadError::ResourceLimit`] with [`crate::QuadResource::QuotedDepth`] on
//! both the write and the read path — the parser is depth-bounded before it
//! recurses, so a hostile batch cannot blow the stack.
//!
//! # Contract version
//!
//! `dataplane.contract_version` stays `"1"`. The Arrow schema is byte-identical to
//! the pre-RDF-star schema: no field, type, nullability, or metadata entry
//! changed, so every existing validator in this workspace (and downstream
//! consumers' `dataplane.arrow_version` pin, which governs the Arrow
//! format, not the term vocabulary) keeps accepting these batches, and batches
//! written before this change decode unchanged. What changed is the *value*
//! vocabulary of the `object_kind` column, which is data, not schema. A minor
//! bump would have been indistinguishable from a breaking change to
//! `validate_contract`, whose metadata check is exact equality; readers that
//! do not understand `"triple"` already fail closed on it with
//! [`QuadError::Term`]-class errors rather than mis-decoding, which is the
//! property a version bump would have been buying.

use oxrdf::{
    BaseDirection, BlankNode, BlankNodeRef, Literal, LiteralRef, NamedNode, NamedNodeRef,
    NamedOrBlankNode, Term, TermRef, Triple, TripleRef,
};

use crate::error::{QuadError, QuadResource};

/// Term kind marker for an RDF 1.2 triple term in the object position.
pub const TERM_KIND_TRIPLE: &str = "triple";

/// Opening delimiter of the N-Triples triple-term syntax.
const OPEN: &str = "<<(";
/// Closing delimiter of the N-Triples triple-term syntax.
const CLOSE: &str = ")>>";

/// Separator introducing a base direction after a language tag.
///
/// N-Triples 1.2 production `LANG_DIR` writes a directional language-tagged
/// string as `"lex"@tag--dir`. `oxrdf` rejects `--` inside a plain language
/// tag (verified against `LanguageTagParseError`), so the separator is
/// unambiguous.
const DIRECTION_SEPARATOR: &str = "--";
/// Left-to-right base direction, as written in `LANG_DIR`.
const DIRECTION_LTR: &str = "ltr";
/// Right-to-left base direction, as written in `LANG_DIR`.
const DIRECTION_RTL: &str = "rtl";

/// Default maximum triple-term nesting depth: 8.
///
/// Deep nesting has no attested use in RDF 1.2 corpora (annotation syntax
/// produces depth 1, annotations of annotations depth 2); 8 leaves generous
/// headroom while keeping the recursive serializer and parser bounded.
pub const DEFAULT_MAX_QUOTED_DEPTH: usize = 8;

/// Returns the triple-term nesting depth of `term`.
///
/// A non-triple term has depth 0; `<<( s p o )>>` with plain components has
/// depth 1. The walk is iterative on the object spine and recursive nowhere
/// else, because RDF 1.2 admits triple terms only as objects.
#[must_use]
pub fn term_depth(term: TermRef<'_>) -> usize {
    let mut depth = 0;
    let mut current = term;
    while let TermRef::Triple(triple) = current {
        depth += 1;
        current = triple.object.as_ref();
    }
    depth
}

/// Fails closed when `term` nests triple terms deeper than `max_depth`.
///
/// # Errors
///
/// Returns [`QuadError::ResourceLimit`] with resource
/// [`QuadResource::QuotedDepth`] when the depth exceeds `max_depth`.
pub fn check_depth(term: TermRef<'_>, max_depth: usize) -> Result<(), QuadError> {
    let observed = term_depth(term);
    if observed > max_depth {
        return Err(QuadError::ResourceLimit {
            resource: QuadResource::QuotedDepth,
            limit: max_depth,
            observed,
        });
    }
    Ok(())
}

/// Serializes a triple term into the canonical `object_value` encoding.
#[must_use]
pub fn encode_triple_term(triple: TripleRef<'_>) -> String {
    let mut out = String::new();
    write_triple(&mut out, triple);
    out
}

fn write_triple(out: &mut String, triple: TripleRef<'_>) {
    out.push_str(OPEN);
    out.push(' ');
    match triple.subject {
        oxrdf::NamedOrBlankNodeRef::NamedNode(node) => write_iri(out, node),
        oxrdf::NamedOrBlankNodeRef::BlankNode(node) => write_bnode(out, node),
    }
    out.push(' ');
    write_iri(out, triple.predicate);
    out.push(' ');
    write_term(out, triple.object);
    out.push(' ');
    out.push_str(CLOSE);
}

fn write_term(out: &mut String, term: TermRef<'_>) {
    match term {
        TermRef::NamedNode(node) => write_iri(out, node),
        TermRef::BlankNode(node) => write_bnode(out, node),
        TermRef::Literal(literal) => write_literal(out, literal),
        TermRef::Triple(triple) => write_triple(out, triple.as_ref()),
    }
}

fn write_iri(out: &mut String, node: NamedNodeRef<'_>) {
    out.push('<');
    for character in node.as_str().chars() {
        // N-Triples IRIREF forbids these directly; oxiri already rejects
        // them, so this is a defence-in-depth escape, not a hot path.
        match character {
            '<' | '>' | '"' | '{' | '}' | '|' | '^' | '`' | '\\' => {
                escape_unicode(out, character);
            }
            c if (c as u32) <= 0x20 => escape_unicode(out, c),
            c => out.push(c),
        }
    }
    out.push('>');
}

fn write_bnode(out: &mut String, node: BlankNodeRef<'_>) {
    out.push_str("_:");
    out.push_str(node.as_str());
}

fn write_literal(out: &mut String, literal: LiteralRef<'_>) {
    out.push('"');
    for character in literal.value().chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => escape_unicode(out, c),
            c => out.push(c),
        }
    }
    out.push('"');
    if let Some(language) = literal.language() {
        out.push('@');
        out.push_str(language);
        // RDF 1.2 directional language-tagged string. Dropping the direction
        // here would be a silent mutation, so it rides the canonical
        // `LANG_DIR` suffix and parses back losslessly.
        if let Some(direction) = literal.direction() {
            out.push_str(DIRECTION_SEPARATOR);
            out.push_str(direction_str(direction));
        }
    } else {
        out.push_str("^^");
        write_iri(out, literal.datatype());
    }
}

const fn direction_str(direction: BaseDirection) -> &'static str {
    match direction {
        BaseDirection::Ltr => DIRECTION_LTR,
        BaseDirection::Rtl => DIRECTION_RTL,
    }
}

fn escape_unicode(out: &mut String, character: char) {
    out.push_str(&format!("\\u{:04X}", character as u32));
}

/// Parses the canonical `object_value` encoding back into a triple term.
///
/// # Errors
///
/// Returns [`QuadError::Term`] when `value` is not a well-formed triple term
/// encoding or contains a term that is invalid for its position, and
/// [`QuadError::ResourceLimit`] with [`QuadResource::QuotedDepth`] when the
/// encoding nests deeper than `max_depth`. Depth is checked *before* each
/// recursion, so a malicious value cannot exhaust the stack.
pub fn parse_triple_term(value: &str, max_depth: usize) -> Result<Triple, QuadError> {
    let mut parser = Parser {
        rest: value,
        max_depth,
    };
    let triple = parser.triple(1)?;
    if !parser.rest.is_empty() {
        return Err(term_error(format!(
            "trailing content after triple term: `{}`",
            parser.rest
        )));
    }
    Ok(triple)
}

fn term_error(detail: String) -> QuadError {
    QuadError::Term(format!("triple term: {detail}"))
}

struct Parser<'a> {
    rest: &'a str,
    max_depth: usize,
}

impl Parser<'_> {
    fn eat(&mut self, token: &str) -> Result<(), QuadError> {
        match self.rest.strip_prefix(token) {
            Some(rest) => {
                self.rest = rest;
                Ok(())
            }
            None => Err(term_error(format!("expected `{token}` at `{}`", self.rest))),
        }
    }

    fn triple(&mut self, depth: usize) -> Result<Triple, QuadError> {
        if depth > self.max_depth {
            return Err(QuadError::ResourceLimit {
                resource: QuadResource::QuotedDepth,
                limit: self.max_depth,
                observed: depth,
            });
        }
        self.eat(OPEN)?;
        self.eat(" ")?;
        let subject = match self.term(depth)? {
            Term::NamedNode(node) => NamedOrBlankNode::NamedNode(node),
            Term::BlankNode(node) => NamedOrBlankNode::BlankNode(node),
            other => {
                return Err(term_error(format!(
                    "subject must be an IRI or blank node, found `{other}`"
                )));
            }
        };
        self.eat(" ")?;
        let predicate = match self.term(depth)? {
            Term::NamedNode(node) => node,
            other => {
                return Err(term_error(format!(
                    "predicate must be an IRI, found `{other}`"
                )));
            }
        };
        self.eat(" ")?;
        let object = self.term(depth)?;
        self.eat(" ")?;
        self.eat(CLOSE)?;
        Ok(Triple::new(subject, predicate, object))
    }

    fn term(&mut self, depth: usize) -> Result<Term, QuadError> {
        if self.rest.starts_with(OPEN) {
            return Ok(Term::Triple(Box::new(self.triple(depth + 1)?)));
        }
        if self.rest.starts_with('<') {
            return Ok(Term::NamedNode(self.iri()?));
        }
        if self.rest.starts_with("_:") {
            return Ok(Term::BlankNode(self.bnode()?));
        }
        if self.rest.starts_with('"') {
            return Ok(Term::Literal(self.literal()?));
        }
        Err(term_error(format!("unrecognised term at `{}`", self.rest)))
    }

    fn iri(&mut self) -> Result<NamedNode, QuadError> {
        self.eat("<")?;
        let end = self
            .rest
            .find('>')
            .ok_or_else(|| term_error("unterminated IRI".into()))?;
        let (body, rest) = self.rest.split_at(end);
        self.rest = &rest[1..];
        let body = unescape(body)?;
        NamedNode::new(body)
            .map_err(|error| term_error(format!("invalid IRI in triple term: {error}")))
    }

    fn bnode(&mut self) -> Result<BlankNode, QuadError> {
        self.eat("_:")?;
        let end = self
            .rest
            .find(' ')
            .ok_or_else(|| term_error("unterminated blank node".into()))?;
        let (label, rest) = self.rest.split_at(end);
        self.rest = rest;
        BlankNode::new(label)
            .map_err(|error| term_error(format!("invalid blank node `{label}`: {error}")))
    }

    fn literal(&mut self) -> Result<Literal, QuadError> {
        self.eat("\"")?;
        let mut lexical = String::new();
        let mut chars = self.rest.char_indices();
        let close = loop {
            let Some((index, character)) = chars.next() else {
                return Err(term_error("unterminated literal".into()));
            };
            match character {
                '"' => break index,
                '\\' => {
                    let Some((_, escape)) = chars.next() else {
                        return Err(term_error("truncated escape in literal".into()));
                    };
                    match escape {
                        '"' => lexical.push('"'),
                        '\\' => lexical.push('\\'),
                        'n' => lexical.push('\n'),
                        'r' => lexical.push('\r'),
                        't' => lexical.push('\t'),
                        'u' => {
                            let mut code = 0u32;
                            for _ in 0..4 {
                                let Some((_, digit)) = chars.next() else {
                                    return Err(term_error("truncated \\u escape".into()));
                                };
                                let value = digit.to_digit(16).ok_or_else(|| {
                                    term_error(format!("invalid hex digit `{digit}`"))
                                })?;
                                code = code * 16 + value;
                            }
                            let character = char::from_u32(code).ok_or_else(|| {
                                term_error(format!("\\u{code:04X} is not a scalar value"))
                            })?;
                            lexical.push(character);
                        }
                        other => {
                            return Err(term_error(format!("unknown escape `\\{other}`")));
                        }
                    }
                }
                other => lexical.push(other),
            }
        };
        self.rest = &self.rest[close + 1..];
        if let Some(rest) = self.rest.strip_prefix('@') {
            let end = rest
                .find(' ')
                .ok_or_else(|| term_error("unterminated language tag".into()))?;
            let (tag, remainder) = rest.split_at(end);
            self.rest = remainder;
            let Some((language, direction)) = tag.split_once(DIRECTION_SEPARATOR) else {
                return Literal::new_language_tagged_literal(lexical, tag)
                    .map_err(|error| term_error(format!("invalid language tag `{tag}`: {error}")));
            };
            let direction = match direction {
                DIRECTION_LTR => BaseDirection::Ltr,
                DIRECTION_RTL => BaseDirection::Rtl,
                other => {
                    return Err(term_error(format!(
                        "invalid base direction `{other}`, expected `{DIRECTION_LTR}` or \
                         `{DIRECTION_RTL}`"
                    )));
                }
            };
            return Literal::new_directional_language_tagged_literal(lexical, language, direction)
                .map_err(|error| {
                    term_error(format!("invalid language tag `{language}`: {error}"))
                });
        }
        if self.rest.starts_with("^^") {
            self.eat("^^")?;
            let datatype = self.iri()?;
            return Ok(Literal::new_typed_literal(lexical, datatype));
        }
        Err(term_error(
            "literal must carry an explicit datatype or language tag".into(),
        ))
    }
}

/// Reverses the IRI escaping applied by [`write_iri`].
fn unescape(body: &str) -> Result<String, QuadError> {
    if !body.contains('\\') {
        return Ok(body.to_owned());
    }
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        match chars.next() {
            Some('u') => {
                let mut code = 0u32;
                for _ in 0..4 {
                    let digit = chars
                        .next()
                        .ok_or_else(|| term_error("truncated \\u escape in IRI".into()))?;
                    let value = digit
                        .to_digit(16)
                        .ok_or_else(|| term_error(format!("invalid hex digit `{digit}`")))?;
                    code = code * 16 + value;
                }
                out.push(
                    char::from_u32(code)
                        .ok_or_else(|| term_error(format!("\\u{code:04X} is not a scalar")))?,
                );
            }
            Some(other) => return Err(term_error(format!("unknown IRI escape `\\{other}`"))),
            None => return Err(term_error("truncated escape in IRI".into())),
        }
    }
    Ok(out)
}
