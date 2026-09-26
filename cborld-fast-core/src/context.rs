// Rust guideline compliant 2026-02-21
//! Deterministic term-map construction from inline JSON-LD contexts.
//!
//! Implements the subset of the CBOR-LD 1.0 "Context Loading" algorithms
//! needed for inline (embedded) contexts: terms are collected in Unicode
//! code point order and assigned consecutive even integers starting at
//! [`crate::registry::FIRST_CUSTOM_TERM_ID`]. The identifier registry is
//! global to one conversion, while term definitions are scoped per node,
//! mirroring the split in the specification (`state.termToId` versus the
//! active context's `termMap`).
//!
//! Registered context IRIs never trigger a fetch: the caller supplies the
//! context document content keyed by IRI and [`load_context_document`]
//! applies it with the same validation as an inline context.
//!
//! Refused (fail closed): context IRIs without caller-provided content,
//! chained context references (a string `@context` inside provided
//! content), `@context: null` resets, `@import`, and property- or
//! type-scoped contexts nested inside term definitions.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{
    error::CborldError,
    registry::{FIRST_CUSTOM_TERM_ID, KEYWORD_TERM_IDS, TERM_ID_STEP},
};

/// Global term-identifier registry for one conversion.
#[derive(Debug)]
pub(crate) struct TermIdRegistry {
    term_to_id: BTreeMap<String, u64>,
    id_to_term: BTreeMap<u64, String>,
    next_id: u64,
}

impl TermIdRegistry {
    /// Creates a registry seeded with the vendored JSON-LD keyword table.
    pub(crate) fn new() -> Self {
        let mut term_to_id = BTreeMap::new();
        let mut id_to_term = BTreeMap::new();
        for (keyword, id) in KEYWORD_TERM_IDS {
            term_to_id.insert(keyword.to_string(), id);
            id_to_term.insert(id, keyword.to_string());
        }
        Self {
            term_to_id,
            id_to_term,
            next_id: FIRST_CUSTOM_TERM_ID,
        }
    }

    /// Returns the identifier assigned to `term`, if any.
    pub(crate) fn id_of(&self, term: &str) -> Option<u64> {
        self.term_to_id.get(term).copied()
    }

    /// Returns the term assigned to identifier `id`, if any.
    pub(crate) fn term_of(&self, id: u64) -> Option<&str> {
        self.id_to_term.get(&id).map(String::as_str)
    }

    /// Assigns the next even identifier to `term` if it has none yet.
    fn assign(&mut self, term: &str) {
        if self.term_to_id.contains_key(term) {
            return;
        }
        let id = self.next_id;
        self.next_id += TERM_ID_STEP;
        self.term_to_id.insert(term.to_string(), id);
        self.id_to_term.insert(id, term.to_string());
    }
}

/// Compression-relevant parts of one term definition.
#[derive(Clone, Debug, Default)]
pub(crate) struct TermDef {
    /// The `@id` member of the definition, when present.
    pub(crate) id: Option<String>,
    /// The `@type` member of the definition, when present.
    pub(crate) value_type: Option<String>,
}

/// Scoped term definitions active at one node.
#[derive(Clone, Debug, Default)]
pub(crate) struct ActiveContext {
    term_map: BTreeMap<String, TermDef>,
}

impl ActiveContext {
    /// Returns the active definition for `term`, if any.
    pub(crate) fn definition(&self, term: &str) -> Option<&TermDef> {
        self.term_map.get(term)
    }
}

/// Returns whether `term` is a vendored JSON-LD keyword.
///
/// Keywords carry pre-seeded identifiers and never enter an
/// [`ActiveContext`], so callers that ask "is this term compressible here?"
/// must test keyword membership alongside [`ActiveContext::definition`].
pub(crate) fn is_keyword(term: &str) -> bool {
    KEYWORD_TERM_IDS.iter().any(|(keyword, _)| *keyword == term)
}

/// Loads one inline `@context` value into the registry and active context.
///
/// Terms are visited in sorted (Unicode code point) order so producer and
/// consumer derive identical identifiers. Definitions that are `null` are
/// skipped for identifier assignment, matching the Add Context Algorithm.
///
/// # Errors
///
/// Returns [`CborldError::UnregisteredContext`] for a string (remote)
/// context, [`CborldError::Unsupported`] for `@context: null`, `@import`,
/// and scoped contexts, and [`CborldError::Document`] for definitions
/// outside the accepted shapes.
pub(crate) fn load_context(
    registry: &mut TermIdRegistry,
    active: &ActiveContext,
    context: &Value,
) -> Result<ActiveContext, CborldError> {
    let object = match context {
        Value::String(iri) => {
            return Err(CborldError::UnregisteredContext { iri: iri.clone() });
        }
        Value::Null => {
            return Err(CborldError::Unsupported(
                "@context: null (context reset) is outside the inline-context subset".to_string(),
            ));
        }
        Value::Object(object) => object,
        other => {
            return Err(CborldError::Document(format!(
                "@context value must be an object in this subset, found {}",
                json_kind(other)
            )));
        }
    };
    if object.contains_key("@import") {
        return Err(CborldError::Unsupported(
            "@import requires fetching a remote context and is refused".to_string(),
        ));
    }
    let mut next = active.clone();
    let mut terms: Vec<&String> = object.keys().collect();
    terms.sort_unstable();
    for term in terms {
        if is_keyword(term) {
            continue;
        }
        let definition = &object[term.as_str()];
        let def = match definition {
            Value::Null => continue,
            Value::String(iri) => TermDef {
                id: Some(iri.clone()),
                value_type: None,
            },
            Value::Object(members) => {
                if members.contains_key("@context") {
                    return Err(CborldError::Unsupported(format!(
                        "scoped context on term {term} is outside the inline-context subset"
                    )));
                }
                TermDef {
                    id: member_string(members, "@id", term)?,
                    value_type: member_string(members, "@type", term)?,
                }
            }
            other => {
                return Err(CborldError::Document(format!(
                    "definition of term {term} must be null, a string, or an object, found {}",
                    json_kind(other)
                )));
            }
        };
        registry.assign(term);
        next.term_map.insert(term.clone(), def);
    }
    Ok(next)
}

/// Loads caller-provided content for the registered context named by `iri`.
///
/// `document` may be a full context document (`{"@context": ...}`) or a
/// bare term-definition object; a wrapped `@context` may be an object or an
/// array of objects. Loading applies the same validation as an inline
/// context, so nested string references (chained registered contexts) are
/// refused rather than resolved.
///
/// # Errors
///
/// Returns [`CborldError::Document`] when `document` is not a JSON object,
/// plus every error [`load_context`] produces for the content itself.
pub(crate) fn load_context_document(
    registry: &mut TermIdRegistry,
    active: &ActiveContext,
    iri: &str,
    document: &Value,
) -> Result<ActiveContext, CborldError> {
    let Value::Object(object) = document else {
        return Err(CborldError::Document(format!(
            "provided content for context {iri} must be a JSON object, found {}",
            json_kind(document)
        )));
    };
    match object.get("@context") {
        Some(Value::Array(items)) => {
            let mut next = active.clone();
            for item in items {
                next = load_context(registry, &next, item)?;
            }
            Ok(next)
        }
        Some(wrapped) => load_context(registry, active, wrapped),
        None => load_context(registry, active, document),
    }
}

fn member_string(
    members: &serde_json::Map<String, Value>,
    key: &str,
    term: &str,
) -> Result<Option<String>, CborldError> {
    match members.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(CborldError::Document(format!(
            "{key} of term {term} must be a string, found {}",
            json_kind(other)
        ))),
    }
}

/// Short JSON kind name for error messages.
pub(crate) fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
