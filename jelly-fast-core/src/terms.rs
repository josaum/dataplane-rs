// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Shared term-level codec state for Jelly RDF streams and Jelly patches.
//!
//! The RDF stream codec ([`crate::JellyEncoder`] / [`crate::JellyDecoder`])
//! and the patch codec ([`crate::JellyPatchEncoder`] /
//! [`crate::JellyPatchDecoder`]) compress terms with exactly the same
//! machinery: three bounded lookup tables (prefix, name, datatype), the
//! id-0 delta conventions for IRI references and table entry rows, and
//! repeated-term elision on statement rows. This module owns that state so
//! the two codecs cannot drift apart. Lookup entry rows surface as
//! [`LookupEntry`] values; each codec wraps them in its own stream row
//! type (`RdfStreamRow` or `RdfPatchRow`).

use oxrdf::{
    BlankNode, GraphName, GraphNameRef, Literal, NamedNode, NamedOrBlankNode, NamedOrBlankNodeRef,
    Quad, QuadRef, Term, TermRef, Triple, TripleRef,
};

use crate::{
    error::{JellyError, JellyResource},
    proto::{
        RdfDatatypeEntry, RdfDefaultGraph, RdfIri, RdfLiteral, RdfNameEntry, RdfPrefixEntry,
        RdfQuad, RdfTriple, rdf_literal, rdf_quad, rdf_triple,
    },
    tables::{DecoderTable, EncoderTable},
};

/// The `xsd:string` datatype IRI, mapped to Jelly simple literals.
pub(crate) const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// A lookup entry row the encoder must emit before the row referencing it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum LookupEntry {
    /// Prefix lookup table entry.
    Prefix(RdfPrefixEntry),
    /// Name lookup table entry.
    Name(RdfNameEntry),
    /// Datatype lookup table entry.
    Datatype(RdfDatatypeEntry),
}

/// Splits an IRI into `(prefix, name)` after the last `#` or `/`.
///
/// The prefix includes the delimiter; an IRI without either delimiter
/// splits into an empty prefix and the full IRI as the name.
fn split_iri(iri: &str) -> (&str, &str) {
    match iri.rfind(['#', '/']) {
        Some(index) => iri.split_at(index + 1),
        None => ("", iri),
    }
}

/// Encoder-side term compression state shared by both Jelly codecs.
///
/// Holds the three bounded lookup tables, the IRI prefix/name delta state,
/// and the last term seen per statement position for repeated-term
/// elision.
#[derive(Debug)]
pub(crate) struct TermEncoder {
    prefixes: EncoderTable,
    names: EncoderTable,
    datatypes: EncoderTable,
    last_prefix_id: Option<u32>,
    last_name_id: Option<u32>,
    last_subject: Option<NamedOrBlankNode>,
    last_predicate: Option<NamedNode>,
    last_object: Option<Term>,
    last_graph: Option<GraphName>,
    /// Monotonic identifier of the statement row being encoded.
    ///
    /// Lookup tables stamp every slot they hand out with it, so a table too
    /// small for one row is refused instead of reassigning an identifier the
    /// row has already used; see [`EncoderTable::intern`].
    row_generation: u64,
}

impl TermEncoder {
    /// Creates empty state with the given table capacities.
    pub(crate) fn new(prefix_capacity: u32, name_capacity: u32, datatype_capacity: u32) -> Self {
        Self {
            prefixes: EncoderTable::new(JellyResource::PrefixTable, prefix_capacity),
            names: EncoderTable::new(JellyResource::NameTable, name_capacity),
            datatypes: EncoderTable::new(JellyResource::DatatypeTable, datatype_capacity),
            last_prefix_id: None,
            last_name_id: None,
            last_subject: None,
            last_predicate: None,
            last_object: None,
            last_graph: None,
            row_generation: 0,
        }
    }

    /// Opens a new statement-scoped generation for lookup identifiers.
    ///
    /// [`Self::encode_quad`] calls this itself; the patch encoder calls it
    /// once per header row, which interns terms outside any statement.
    pub(crate) fn begin_row(&mut self) {
        self.row_generation = self.row_generation.wrapping_add(1);
    }

    /// Encodes one quad, appending any lookup entry rows to `entries`.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::ResourceLimit`] when one of the lookup tables
    /// is too small to hold every distinct value this single quad needs.
    pub(crate) fn encode_quad(
        &mut self,
        quad: QuadRef<'_>,
        entries: &mut Vec<LookupEntry>,
    ) -> Result<RdfQuad, JellyError> {
        self.begin_row();
        // Repeated-term elision: an unset oneof means "same term as the
        // previous quad in this position". Terms are compared on their RDF
        // value, then encoded strictly in subject, predicate, object,
        // graph order so IRI prefix/name delta state stays aligned.
        let subject = if self
            .last_subject
            .as_ref()
            .is_some_and(|last| last.as_ref() == quad.subject)
        {
            None
        } else {
            self.last_subject = Some(quad.subject.into_owned());
            Some(match quad.subject {
                NamedOrBlankNodeRef::NamedNode(node) => {
                    rdf_quad::Subject::SIri(self.encode_iri(node.as_str(), true, entries)?)
                }
                NamedOrBlankNodeRef::BlankNode(node) => {
                    rdf_quad::Subject::SBnode(node.as_str().to_owned())
                }
            })
        };
        let predicate = if self
            .last_predicate
            .as_ref()
            .is_some_and(|last| last.as_ref() == quad.predicate)
        {
            None
        } else {
            self.last_predicate = Some(quad.predicate.into_owned());
            Some(rdf_quad::Predicate::PIri(self.encode_iri(
                quad.predicate.as_str(),
                true,
                entries,
            )?))
        };
        let object =
            if self
                .last_object
                .as_ref()
                .is_some_and(|last| last.as_ref() == quad.object)
            {
                None
            } else {
                self.last_object = Some(quad.object.into_owned());
                Some(match quad.object {
                    TermRef::NamedNode(node) => {
                        rdf_quad::Object::OIri(self.encode_iri(node.as_str(), true, entries)?)
                    }
                    TermRef::BlankNode(node) => rdf_quad::Object::OBnode(node.as_str().to_owned()),
                    TermRef::Literal(literal) => {
                        rdf_quad::Object::OLiteral(self.encode_literal(literal, entries)?)
                    }
                    TermRef::Triple(triple) => rdf_quad::Object::OTripleTerm(
                        self.encode_triple_term(triple.as_ref(), true, entries)?,
                    ),
                })
            };
        let graph = if self
            .last_graph
            .as_ref()
            .is_some_and(|last| last.as_ref() == quad.graph_name)
        {
            None
        } else {
            self.last_graph = Some(quad.graph_name.into_owned());
            Some(match quad.graph_name {
                GraphNameRef::DefaultGraph => rdf_quad::Graph::GDefaultGraph(RdfDefaultGraph {}),
                GraphNameRef::NamedNode(node) => {
                    rdf_quad::Graph::GIri(self.encode_iri(node.as_str(), true, entries)?)
                }
                GraphNameRef::BlankNode(node) => rdf_quad::Graph::GBnode(node.as_str().to_owned()),
            })
        };
        Ok(RdfQuad {
            subject,
            predicate,
            object,
            graph,
        })
    }

    /// Encodes one RDF 1.2 triple term as a nested `RdfTriple`.
    ///
    /// The vendored `rdf.proto` states that "all terms must also be set in
    /// quoted triples (RDF-star)", so this never elides a nested term, and
    /// it does not touch the outer repeated-term memory. Lookup identifiers
    /// are still interned and — for statement rows (`use_delta`) — still
    /// delta-compressed, in depth-first subject, predicate, object order;
    /// the decoder resolves them in exactly the same order, so the two
    /// sides of the delta state stay aligned.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::ResourceLimit`] when a lookup table cannot hold
    /// every distinct value the enclosing statement row needs; a nested
    /// triple term shares the row's identifier generation, because the whole
    /// nest travels on one wire row.
    pub(crate) fn encode_triple_term(
        &mut self,
        triple: TripleRef<'_>,
        use_delta: bool,
        entries: &mut Vec<LookupEntry>,
    ) -> Result<RdfTriple, JellyError> {
        let subject = match triple.subject {
            NamedOrBlankNodeRef::NamedNode(node) => {
                rdf_triple::Subject::SIri(self.encode_iri(node.as_str(), use_delta, entries)?)
            }
            NamedOrBlankNodeRef::BlankNode(node) => {
                rdf_triple::Subject::SBnode(node.as_str().to_owned())
            }
        };
        let predicate = rdf_triple::Predicate::PIri(self.encode_iri(
            triple.predicate.as_str(),
            use_delta,
            entries,
        )?);
        let object = match triple.object {
            TermRef::NamedNode(node) => {
                rdf_triple::Object::OIri(self.encode_iri(node.as_str(), use_delta, entries)?)
            }
            TermRef::BlankNode(node) => rdf_triple::Object::OBnode(node.as_str().to_owned()),
            TermRef::Literal(literal) => {
                rdf_triple::Object::OLiteral(self.encode_literal(literal, entries)?)
            }
            TermRef::Triple(nested) => rdf_triple::Object::OTripleTerm(Box::new(
                self.encode_triple_term(nested.as_ref(), use_delta, entries)?,
            )),
        };
        Ok(RdfTriple {
            subject: Some(subject),
            predicate: Some(predicate),
            object: Some(object),
        })
    }

    /// Encodes one IRI reference, appending new lookup entries to `entries`.
    ///
    /// With `use_delta` set, the id-0 delta conventions compress the wire
    /// identifiers (statement terms). Without it, explicit identifiers are
    /// always emitted (patch header values, where the vendored
    /// `patch.proto` disables repeated-term compression and the
    /// non-vendored Jelly-Patch prose may not define delta state across
    /// header rows). The delta state itself is updated either way so both
    /// sides stay aligned.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::ResourceLimit`] when the prefix or name table
    /// cannot hold every distinct value the current row needs.
    pub(crate) fn encode_iri(
        &mut self,
        iri: &str,
        use_delta: bool,
        entries: &mut Vec<LookupEntry>,
    ) -> Result<RdfIri, JellyError> {
        let (prefix, name) = split_iri(iri);
        let (prefix_id, prefix_entry) = self.prefixes.intern(prefix, self.row_generation)?;
        if let Some(entry) = prefix_entry {
            entries.push(LookupEntry::Prefix(RdfPrefixEntry {
                id: entry.wire_id,
                value: entry.value,
            }));
        }
        let (name_id, name_entry) = self.names.intern(name, self.row_generation)?;
        if let Some(entry) = name_entry {
            entries.push(LookupEntry::Name(RdfNameEntry {
                id: entry.wire_id,
                value: entry.value,
            }));
        }
        // prefix_id 0 means "same prefix_id as the previous IRI"; this is
        // an identifier comparison, so it stays valid across table entry
        // reassignment (the decoder dereferences the table at use time).
        let wire_prefix_id = if use_delta && self.last_prefix_id == Some(prefix_id) {
            0
        } else {
            prefix_id
        };
        // name_id 0 means "previous IRI's name_id + 1".
        let wire_name_id = if use_delta && self.last_name_id.map(|last| last + 1) == Some(name_id) {
            0
        } else {
            name_id
        };
        self.last_prefix_id = Some(prefix_id);
        self.last_name_id = Some(name_id);
        Ok(RdfIri {
            prefix_id: wire_prefix_id,
            name_id: wire_name_id,
        })
    }

    /// Encodes one literal, appending new datatype entries to `entries`.
    ///
    /// `xsd:string` literals are emitted as Jelly simple literals (no
    /// literal kind set), matching the RDF 1.1 identity between the two.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::ResourceLimit`] when the datatype table cannot
    /// hold every distinct datatype the current row needs.
    pub(crate) fn encode_literal(
        &mut self,
        literal: oxrdf::LiteralRef<'_>,
        entries: &mut Vec<LookupEntry>,
    ) -> Result<RdfLiteral, JellyError> {
        let literal_kind = if let Some(language) = literal.language() {
            Some(rdf_literal::LiteralKind::Langtag(language.to_owned()))
        } else if literal.datatype().as_str() == XSD_STRING {
            None
        } else {
            let (datatype_id, entry) = self
                .datatypes
                .intern(literal.datatype().as_str(), self.row_generation)?;
            if let Some(entry) = entry {
                entries.push(LookupEntry::Datatype(RdfDatatypeEntry {
                    id: entry.wire_id,
                    value: entry.value,
                }));
            }
            Some(rdf_literal::LiteralKind::Datatype(datatype_id))
        };
        Ok(RdfLiteral {
            lex: literal.value().to_owned(),
            literal_kind,
        })
    }
}

/// Decoder-side term resolution state shared by both Jelly codecs.
///
/// Mirror image of [`TermEncoder`]: the same tables, delta state, and
/// repeated-term memory, resolved strictly in row order.
#[derive(Debug)]
pub(crate) struct TermDecoder {
    /// Whether the stream's options row declared RDF-star content.
    rdf_star: bool,
    /// Largest triple-term nesting depth this decoder will materialize.
    max_quoted_depth: usize,
    prefixes: DecoderTable,
    names: DecoderTable,
    datatypes: DecoderTable,
    last_prefix_id: Option<u32>,
    last_name_id: Option<u32>,
    last_subject: Option<NamedOrBlankNode>,
    last_predicate: Option<NamedNode>,
    last_object: Option<Term>,
    last_graph: Option<GraphName>,
}

impl TermDecoder {
    /// Creates empty state sized by the stream's declared table sizes.
    ///
    /// `rdf_star` mirrors the stream options flag of the same name: with it
    /// unset, a triple term on the wire is a stream that contradicts its own
    /// options row and is refused. `max_quoted_depth` bounds nesting before
    /// the recursive decoder runs, so a hostile frame cannot exhaust the
    /// stack.
    pub(crate) fn new(
        prefix_size: u32,
        name_size: u32,
        datatype_size: u32,
        rdf_star: bool,
        max_quoted_depth: usize,
    ) -> Self {
        Self {
            rdf_star,
            max_quoted_depth,
            prefixes: DecoderTable::new("prefix", prefix_size),
            names: DecoderTable::new("name", name_size),
            datatypes: DecoderTable::new("datatype", datatype_size),
            last_prefix_id: None,
            last_name_id: None,
            last_subject: None,
            last_predicate: None,
            last_object: None,
            last_graph: None,
        }
    }

    /// Assigns a prefix lookup table entry row.
    pub(crate) fn assign_prefix(&mut self, wire_id: u32, value: String) -> Result<(), JellyError> {
        self.prefixes.assign(wire_id, value)
    }

    /// Assigns a name lookup table entry row.
    pub(crate) fn assign_name(&mut self, wire_id: u32, value: String) -> Result<(), JellyError> {
        self.names.assign(wire_id, value)
    }

    /// Assigns a datatype lookup table entry row.
    pub(crate) fn assign_datatype(
        &mut self,
        wire_id: u32,
        value: String,
    ) -> Result<(), JellyError> {
        self.datatypes.assign(wire_id, value)
    }

    /// Decodes one quad row, applying repeated-term semantics.
    pub(crate) fn decode_quad(&mut self, quad: &RdfQuad) -> Result<Quad, JellyError> {
        // Terms resolve strictly in subject, predicate, object, graph
        // order so IRI prefix/name delta state matches the encoder.
        let subject = match &quad.subject {
            None => self
                .last_subject
                .clone()
                .ok_or_else(|| repeated_before_set("subject"))?,
            Some(rdf_quad::Subject::SIri(iri)) => {
                NamedOrBlankNode::NamedNode(self.resolve_iri(iri, "subject")?)
            }
            Some(rdf_quad::Subject::SBnode(label)) => {
                NamedOrBlankNode::BlankNode(blank_node(label, "subject")?)
            }
            Some(rdf_quad::Subject::SLiteral(_)) => {
                return Err(generalized("subject", "literal"));
            }
            Some(rdf_quad::Subject::STripleTerm(_)) => {
                return Err(rdf_star("subject"));
            }
        };
        self.last_subject = Some(subject.clone());

        let predicate = match &quad.predicate {
            None => self
                .last_predicate
                .clone()
                .ok_or_else(|| repeated_before_set("predicate"))?,
            Some(rdf_quad::Predicate::PIri(iri)) => self.resolve_iri(iri, "predicate")?,
            Some(rdf_quad::Predicate::PBnode(_)) => {
                return Err(generalized("predicate", "blank node"));
            }
            Some(rdf_quad::Predicate::PLiteral(_)) => {
                return Err(generalized("predicate", "literal"));
            }
            Some(rdf_quad::Predicate::PTripleTerm(_)) => {
                return Err(rdf_star("predicate"));
            }
        };
        self.last_predicate = Some(predicate.clone());

        let object = match &quad.object {
            None => self
                .last_object
                .clone()
                .ok_or_else(|| repeated_before_set("object"))?,
            Some(rdf_quad::Object::OIri(iri)) => Term::NamedNode(self.resolve_iri(iri, "object")?),
            Some(rdf_quad::Object::OBnode(label)) => Term::BlankNode(blank_node(label, "object")?),
            Some(rdf_quad::Object::OLiteral(literal)) => {
                Term::Literal(self.decode_literal(literal)?)
            }
            Some(rdf_quad::Object::OTripleTerm(triple)) => {
                Term::Triple(Box::new(self.decode_triple_term(triple, 1)?))
            }
        };
        self.last_object = Some(object.clone());

        let graph_name = match &quad.graph {
            None => self
                .last_graph
                .clone()
                .ok_or_else(|| repeated_before_set("graph"))?,
            Some(rdf_quad::Graph::GDefaultGraph(_)) => GraphName::DefaultGraph,
            Some(rdf_quad::Graph::GIri(iri)) => {
                GraphName::NamedNode(self.resolve_iri(iri, "graph")?)
            }
            Some(rdf_quad::Graph::GBnode(label)) => {
                GraphName::BlankNode(blank_node(label, "graph")?)
            }
            Some(rdf_quad::Graph::GLiteral(_)) => {
                return Err(generalized("graph", "literal"));
            }
        };
        self.last_graph = Some(graph_name.clone());

        Ok(Quad::new(subject, predicate, object, graph_name))
    }

    /// Decodes one nested `RdfTriple` into an RDF 1.2 triple term.
    ///
    /// `depth` is the 1-based nesting level of `triple`; it is checked
    /// against `max_quoted_depth` **before** recursing, so a frame that
    /// nests triple terms without bound is refused rather than overflowing
    /// the stack. Per the vendored `rdf.proto` ("All terms must also be set
    /// in quoted triples"), an unset term inside a triple term is a frame
    /// error, not a repeated term. Subject and predicate triple terms stay
    /// refused: RDF 1.2 admits a triple term only in the object position,
    /// and the [`oxrdf`] term model has no variant for them elsewhere.
    fn decode_triple_term(
        &mut self,
        triple: &RdfTriple,
        depth: usize,
    ) -> Result<Triple, JellyError> {
        if !self.rdf_star {
            return Err(JellyError::Frame(
                "triple term row in a stream whose options row did not set rdf_star".into(),
            ));
        }
        if depth > self.max_quoted_depth {
            return Err(JellyError::ResourceLimit {
                resource: JellyResource::QuotedDepth,
                limit: u32::try_from(self.max_quoted_depth).unwrap_or(u32::MAX),
                observed: u32::try_from(depth).unwrap_or(u32::MAX),
            });
        }
        let subject = match triple
            .subject
            .as_ref()
            .ok_or_else(|| unset_in_triple_term("subject"))?
        {
            rdf_triple::Subject::SIri(iri) => {
                NamedOrBlankNode::NamedNode(self.resolve_iri(iri, "quoted subject")?)
            }
            rdf_triple::Subject::SBnode(label) => {
                NamedOrBlankNode::BlankNode(blank_node(label, "quoted subject")?)
            }
            rdf_triple::Subject::SLiteral(_) => {
                return Err(generalized("quoted subject", "literal"));
            }
            rdf_triple::Subject::STripleTerm(_) => return Err(rdf_star("quoted subject")),
        };
        let predicate = match triple
            .predicate
            .as_ref()
            .ok_or_else(|| unset_in_triple_term("predicate"))?
        {
            rdf_triple::Predicate::PIri(iri) => self.resolve_iri(iri, "quoted predicate")?,
            rdf_triple::Predicate::PBnode(_) => {
                return Err(generalized("quoted predicate", "blank node"));
            }
            rdf_triple::Predicate::PLiteral(_) => {
                return Err(generalized("quoted predicate", "literal"));
            }
            rdf_triple::Predicate::PTripleTerm(_) => return Err(rdf_star("quoted predicate")),
        };
        let object = match triple
            .object
            .as_ref()
            .ok_or_else(|| unset_in_triple_term("object"))?
        {
            rdf_triple::Object::OIri(iri) => {
                Term::NamedNode(self.resolve_iri(iri, "quoted object")?)
            }
            rdf_triple::Object::OBnode(label) => {
                Term::BlankNode(blank_node(label, "quoted object")?)
            }
            rdf_triple::Object::OLiteral(literal) => Term::Literal(self.decode_literal(literal)?),
            rdf_triple::Object::OTripleTerm(nested) => Term::Triple(Box::new(
                self.decode_triple_term(nested, depth.saturating_add(1))?,
            )),
        };
        Ok(Triple::new(subject, predicate, object))
    }

    /// Decodes a patch header value that carries a triple term.
    ///
    /// Header values are not statement rows, so the vendored patch schema's
    /// "no repeated terms in headers" rule applies to the nested IRIs too:
    /// they resolve without the id-0 delta shorthand the encoder skipped.
    pub(crate) fn decode_header_triple_term(
        &mut self,
        triple: &RdfTriple,
    ) -> Result<Triple, JellyError> {
        self.decode_triple_term(triple, 1)
    }

    /// Resolves an `RdfIri` reference against the lookup tables.
    pub(crate) fn resolve_iri(
        &mut self,
        iri: &RdfIri,
        position: &str,
    ) -> Result<NamedNode, JellyError> {
        // prefix_id 0: same prefix_id as the previous IRI; before any IRI
        // has been seen (or with the prefix table disabled) it means the
        // empty prefix. The identifier is dereferenced at use time so
        // table entry reassignment stays correct.
        let prefix_id = if iri.prefix_id == 0 {
            self.last_prefix_id
        } else {
            Some(iri.prefix_id)
        };
        let prefix = match prefix_id {
            None => "",
            Some(id) => self.prefixes.get(id)?,
        };
        // name_id 0: previous IRI's name_id + 1 (1 for the first IRI).
        let name_id = if iri.name_id == 0 {
            match self.last_name_id {
                None => 1,
                Some(last) => last.checked_add(1).ok_or_else(|| {
                    JellyError::Lookup("name id delta overflows past u32::MAX".into())
                })?,
            }
        } else {
            iri.name_id
        };
        let name = self.names.get(name_id)?;
        let full = format!("{prefix}{name}");
        self.last_prefix_id = prefix_id;
        self.last_name_id = Some(name_id);
        NamedNode::new(full)
            .map_err(|error| JellyError::Term(format!("invalid {position} IRI: {error}")))
    }

    /// Decodes an `RdfLiteral`, resolving datatype table references.
    pub(crate) fn decode_literal(&mut self, literal: &RdfLiteral) -> Result<Literal, JellyError> {
        match &literal.literal_kind {
            None => Ok(Literal::new_simple_literal(&literal.lex)),
            Some(rdf_literal::LiteralKind::Langtag(language)) => {
                Literal::new_language_tagged_literal(&literal.lex, language).map_err(|error| {
                    JellyError::Term(format!("invalid language tag `{language}`: {error}"))
                })
            }
            Some(rdf_literal::LiteralKind::Datatype(id)) => {
                if *id == 0 {
                    return Err(JellyError::Lookup(
                        "literal datatype id 0 is invalid (the field is 1-based)".into(),
                    ));
                }
                let datatype = self.datatypes.get(*id)?;
                let datatype = NamedNode::new(datatype)
                    .map_err(|error| JellyError::Term(format!("invalid datatype IRI: {error}")))?;
                Ok(Literal::new_typed_literal(&literal.lex, datatype))
            }
        }
    }
}

/// Builds the error for a repeated term with no previous value.
fn repeated_before_set(position: &str) -> JellyError {
    JellyError::Frame(format!(
        "{position} is unset but no previous quad exists to repeat it from"
    ))
}

/// Builds the error for an unset term inside a triple term.
fn unset_in_triple_term(position: &str) -> JellyError {
    JellyError::Frame(format!(
        "{position} is unset inside a triple term; the vendored schema requires all terms of a \
         quoted triple to be set"
    ))
}

/// Builds the error for generalized-RDF term kinds.
pub(crate) fn generalized(position: &str, kind: &str) -> JellyError {
    JellyError::Unsupported {
        feature: "generalized_statements",
        detail: format!("{kind} in {position} position requires a generalized RDF stream"),
    }
}

/// Builds the error for a triple term in a position RDF 1.2 forbids.
///
/// RDF 1.2 admits a triple term only as the object of a triple; the
/// [`oxrdf`] term model follows it, so a wire triple term in a subject or
/// predicate position has no representation and is refused rather than
/// coerced.
pub(crate) fn rdf_star(position: &str) -> JellyError {
    JellyError::Unsupported {
        feature: "rdf_star_non_object",
        detail: format!(
            "triple term in {position} position: RDF 1.2 admits triple terms only in the object \
             position"
        ),
    }
}

/// Validates a blank node label from the wire.
pub(crate) fn blank_node(label: &str, position: &str) -> Result<BlankNode, JellyError> {
    BlankNode::new(label).map_err(|error| {
        JellyError::Term(format!("invalid {position} blank node `{label}`: {error}"))
    })
}
