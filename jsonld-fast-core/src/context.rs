// Rust guideline compliant 2026-02-21
//! Inline `@context` processing for the deterministic JSON-LD 1.1 processor.
//!
//! Only inline contexts are processed. A context given as a string, or an
//! `@import` entry, names a remote document and is refused with
//! [`JsonLdError::RemoteContextRefused`] — never fetched, never skipped
//! (sovereign boundary: no network I/O in parsers).
//!
//! The implementation follows the Context Processing Algorithm (JSON-LD 1.1
//! API section 4.1.2) and Create Term Definition (section 4.2.2), including
//! `@reverse` term definitions, scoped (embedded) contexts stored on term
//! definitions, `@propagate` bookkeeping via a previous context,
//! `@direction`, `@nest` values, and the full 1.1 `@container` grammar
//! including `@language` maps and property-based `@index` (section 4.6.1.1).

use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};

use serde_json::{Map, Value};

use crate::{
    error::{JsonLdError, JsonLdResource},
    iri::{has_scheme, is_absolute_iri, is_blank_node_id, resolve},
    options::MAX_CONTEXT_RECURSION,
};

/// Fails closed when context processing has recursed too far.
///
/// The two recursive chains of the Context Processing and Create Term
/// Definition algorithms — a scoped context validated while defining a
/// term, and a term defined to resolve another term's prefix — are
/// unbounded in the spec and bounded by native stack here. Neither is
/// governed by [`crate::JsonLdLimits`]: a prefix chain is *flat* JSON, so
/// the document-nesting budget never sees it.
fn check_context_depth(depth: usize) -> Result<(), JsonLdError> {
    if depth > MAX_CONTEXT_RECURSION {
        return Err(JsonLdError::ResourceLimit {
            resource: JsonLdResource::ContextRecursion,
            limit: MAX_CONTEXT_RECURSION,
            observed: depth,
        });
    }
    Ok(())
}

/// All JSON-LD 1.1 keywords, used to separate keywords from keyword-form terms.
const KEYWORDS: &[&str] = &[
    "@annotation",
    "@base",
    "@container",
    "@context",
    "@direction",
    "@graph",
    "@id",
    "@import",
    "@included",
    "@index",
    "@json",
    "@language",
    "@list",
    "@nest",
    "@none",
    "@prefix",
    "@propagate",
    "@protected",
    "@reverse",
    "@set",
    "@type",
    "@value",
    "@version",
    "@vocab",
];

/// Context entries handled directly by [`process_context`], not term creation.
const CONTROL_KEYS: &[&str] = &[
    "@base",
    "@direction",
    "@import",
    "@language",
    "@propagate",
    "@protected",
    "@version",
    "@vocab",
];

/// RFC 3986 gen-delims; a simple term ending in one becomes a prefix.
const GEN_DELIMS: &[char] = &[':', '/', '?', '#', '[', ']', '@'];

/// Returns `true` when `value` is a JSON-LD 1.1 keyword.
#[must_use]
pub(crate) fn is_keyword(value: &str) -> bool {
    KEYWORDS.contains(&value)
}

/// Returns `true` when `value` matches the keyword production `@[a-zA-Z]+`.
#[must_use]
pub(crate) fn has_keyword_form(value: &str) -> bool {
    value.len() > 1
        && value.starts_with('@')
        && value[1..].bytes().all(|byte| byte.is_ascii_alphabetic())
}

/// Checks the character repertoire and hyphen placement of a language tag.
///
/// Full BCP 47 validation happens when [`oxrdf`] literals are constructed.
#[must_use]
pub(crate) fn language_shape_is_valid(language: &str) -> bool {
    !language.is_empty()
        && !language.starts_with('-')
        && !language.ends_with('-')
        && language
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Base direction of a string value (JSON-LD 1.1 section 4.2.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Direction {
    /// Left-to-right base direction.
    Ltr,
    /// Right-to-left base direction.
    Rtl,
}

impl Direction {
    /// Parses `"ltr"`/`"rtl"`, the only valid direction strings.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "ltr" => Some(Self::Ltr),
            "rtl" => Some(Self::Rtl),
            _ => None,
        }
    }

    /// The canonical direction string.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Ltr => "ltr",
            Self::Rtl => "rtl",
        }
    }
}

/// Container mapping of one term (JSON-LD 1.1 API section 4.2.2 step 19).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ContainerSet {
    /// `@list` member.
    pub(crate) list: bool,
    /// `@set` member.
    pub(crate) set: bool,
    /// `@index` member.
    pub(crate) index: bool,
    /// `@id` member.
    pub(crate) id: bool,
    /// `@type` member.
    pub(crate) type_: bool,
    /// `@graph` member.
    pub(crate) graph: bool,
    /// `@language` member (language maps, section 4.6.2).
    pub(crate) language: bool,
}

impl ContainerSet {
    /// Returns `true` when the container triggers index/id/type map expansion.
    ///
    /// Language maps share the object-valued shape but expand through a
    /// dedicated path (keys become `@language`, not `@index`/`@id`/`@type`).
    #[must_use]
    pub(crate) const fn is_map_container(self) -> bool {
        self.index || self.id || self.type_
    }
}

/// Tri-state language mapping of one term definition.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) enum LanguageMapping {
    /// No per-term mapping; the default language applies.
    #[default]
    Unset,
    /// `@language: null`; suppresses the default language.
    Null,
    /// An explicit language tag.
    Tag(String),
}

/// Tri-state direction mapping of one term definition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum DirectionMapping {
    /// No per-term mapping; the default base direction applies.
    #[default]
    Unset,
    /// `@direction: null`; suppresses the default base direction.
    Null,
    /// An explicit base direction.
    Fixed(Direction),
}

/// One processed term definition.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct TermDefinition {
    /// IRI mapping; `None` decouples the term (keys using it are dropped).
    pub(crate) iri: Option<String>,
    /// Type coercion: `@id`, `@vocab`, `@json`, or an absolute IRI.
    pub(crate) type_mapping: Option<String>,
    /// Per-term language mapping.
    pub(crate) language: LanguageMapping,
    /// Per-term base direction mapping.
    pub(crate) direction: DirectionMapping,
    /// Container mapping.
    pub(crate) container: ContainerSet,
    /// Property-based index mapping (section 4.6.1.1): the expanded IRI of
    /// the property that receives the map key instead of `@index`.
    pub(crate) index: Option<String>,
    /// Whether the term may be used as a compact IRI prefix.
    pub(crate) prefix: bool,
    /// Whether the definition is protected against redefinition.
    pub(crate) protected: bool,
    /// Whether the term is a reverse property (`@reverse` term definition).
    pub(crate) reverse: bool,
    /// `@nest` value; validated to be `@nest` or an alias of it.
    pub(crate) nest: Option<String>,
    /// Scoped (embedded) context, stored raw and re-applied at expansion
    /// time (JSON-LD 1.1 API section 4.2.2 step 21).
    ///
    /// Shared (`Rc`), so copying a definition per node is O(1), and its
    /// address identifies it for the expander's scoped-context cache.
    pub(crate) local_context: Option<Rc<Value>>,
}

impl TermDefinition {
    /// Compares definitions ignoring the `protected` flag (spec section 4.1.2).
    fn same_mapping(&self, other: &Self) -> bool {
        self.iri == other.iri
            && self.type_mapping == other.type_mapping
            && self.language == other.language
            && self.direction == other.direction
            && self.container == other.container
            && self.prefix == other.prefix
            && self.reverse == other.reverse
            && self.nest == other.nest
            && self.local_context == other.local_context
    }
}

/// One active context.
#[derive(Clone, Debug, Default)]
pub(crate) struct Context {
    /// Term definitions, including keyword aliases.
    ///
    /// Copy-on-write (`Rc`): cloning a context per node is O(1), and only
    /// context processing, which defines terms, makes a private copy. The
    /// map's address identifies the scope for the scoped-context cache.
    pub(crate) terms: Rc<HashMap<String, TermDefinition>>,
    /// `@vocab` mapping.
    pub(crate) vocab: Option<String>,
    /// `@base` IRI.
    pub(crate) base: Option<String>,
    /// `@language` default language.
    pub(crate) default_language: Option<String>,
    /// `@direction` default base direction.
    pub(crate) default_direction: Option<Direction>,
    /// Previous context, retained when a non-propagated context is applied
    /// (JSON-LD 1.1 API section 4.1.2 step 3).
    pub(crate) previous: Option<Rc<Context>>,
}

/// Applies the local context `local_value` on top of `active`.
///
/// `options_base` restores the API base IRI when the context is nullified.
/// `override_protected` permits redefinition of protected terms (used for
/// property-scoped contexts). `propagate` is `false` for type-scoped
/// contexts; a non-propagated result retains `active` as its previous
/// context so expansion can roll it back on the next node object. A local
/// `@propagate` entry overrides the flag (section 4.1.2 step 2).
///
/// # Errors
///
/// Returns [`JsonLdError::RemoteContextRefused`] for string contexts and
/// `@import`, [`JsonLdError::UnsupportedFeature`] for refused features,
/// [`JsonLdError::ProtectedTermRedefinition`] on protected conflicts, and
/// [`JsonLdError::InvalidContext`] for malformed entries.
pub(crate) fn process_context(
    active: &Context,
    local_value: &Value,
    options_base: Option<&str>,
    override_protected: bool,
    propagate: bool,
) -> Result<Context, JsonLdError> {
    process_context_at(
        active,
        local_value,
        options_base,
        override_protected,
        propagate,
        0,
    )
}

/// Context processing at a known recursion depth.
///
/// `depth` counts native recursion, not document nesting: it advances on a
/// scoped context validated at term-definition time (section 4.2.2 step
/// 21.2) and on a term definition created to resolve another term's prefix
/// (section 4.2.2 step 14 via [`expand_iri`]). Both chains are unbounded in
/// the spec and bounded here by [`MAX_CONTEXT_RECURSION`].
fn process_context_at(
    active: &Context,
    local_value: &Value,
    options_base: Option<&str>,
    override_protected: bool,
    propagate: bool,
    depth: usize,
) -> Result<Context, JsonLdError> {
    check_context_depth(depth)?;
    let mut result = active.clone();
    // Spec section 4.1.2 step 2: a local `@propagate` entry overrides the
    // flag; it is only inspected when the local context itself is a map.
    let mut propagate = propagate;
    if let Some(map) = local_value.as_object()
        && let Some(entry) = map.get("@propagate")
    {
        match entry {
            Value::Bool(flag) => propagate = *flag,
            _ => {
                return Err(JsonLdError::InvalidContext(
                    "@propagate must be a boolean".to_owned(),
                ));
            }
        }
    }
    // Spec section 4.1.2 step 3: retain the previous context when the local
    // context is not propagated.
    if !propagate && result.previous.is_none() {
        result.previous = Some(Rc::new(active.clone()));
    }
    let entries: Vec<&Value> = match local_value {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    for entry in entries {
        match entry {
            Value::Null => {
                // Spec section 4.1.2 step 5.1: nullification is refused when
                // protected terms exist, unless override protected is set.
                if !override_protected
                    && result.terms.values().any(|definition| definition.protected)
                {
                    return Err(JsonLdError::InvalidContext(
                        "cannot nullify a context that contains protected terms".to_owned(),
                    ));
                }
                let previous = if propagate {
                    None
                } else {
                    result.previous.clone()
                };
                result = Context {
                    base: options_base.map(str::to_owned),
                    previous,
                    ..Context::default()
                };
            }
            Value::String(iri) => {
                return Err(JsonLdError::RemoteContextRefused { iri: iri.clone() });
            }
            Value::Object(map) => {
                process_context_object(&mut result, map, override_protected, depth)?
            }
            _ => {
                return Err(JsonLdError::InvalidContext(
                    "a @context entry must be null, an object, or a string".to_owned(),
                ));
            }
        }
    }
    Ok(result)
}

fn process_context_object(
    result: &mut Context,
    map: &Map<String, Value>,
    override_protected: bool,
    depth: usize,
) -> Result<(), JsonLdError> {
    if let Some(version) = map.get("@version") {
        let valid = version.as_f64() == Some(1.1);
        if !valid {
            return Err(JsonLdError::InvalidContext(
                "@version must be the number 1.1".to_owned(),
            ));
        }
    }
    if let Some(import) = map.get("@import") {
        let iri = import.as_str().unwrap_or("<non-string @import>");
        return Err(JsonLdError::RemoteContextRefused {
            iri: iri.to_owned(),
        });
    }
    if let Some(base) = map.get("@base") {
        match base {
            Value::Null => result.base = None,
            Value::String(value) if is_absolute_iri(value) => {
                result.base = Some(value.clone());
            }
            Value::String(value) => match &result.base {
                Some(current) => result.base = Some(resolve(current, value)),
                None => {
                    return Err(JsonLdError::InvalidContext(format!(
                        "relative @base `{value}` without an established base IRI"
                    )));
                }
            },
            _ => {
                return Err(JsonLdError::InvalidContext(
                    "@base must be an IRI string or null".to_owned(),
                ));
            }
        }
    }
    if let Some(vocab) = map.get("@vocab") {
        match vocab {
            Value::Null => result.vocab = None,
            Value::String(value) => {
                let mut defined = HashMap::new();
                let expanded = expand_iri_at(result, value, true, true, None, &mut defined, depth)?;
                match expanded {
                    Some(iri) if is_absolute_iri(&iri) || is_blank_node_id(&iri) => {
                        result.vocab = Some(iri);
                    }
                    _ => {
                        return Err(JsonLdError::InvalidContext(format!(
                            "@vocab `{value}` does not expand to an absolute IRI"
                        )));
                    }
                }
            }
            _ => {
                return Err(JsonLdError::InvalidContext(
                    "@vocab must be an IRI string or null".to_owned(),
                ));
            }
        }
    }
    if let Some(language) = map.get("@language") {
        match language {
            Value::Null => result.default_language = None,
            Value::String(tag) if language_shape_is_valid(tag) => {
                result.default_language = Some(tag.clone());
            }
            _ => {
                return Err(JsonLdError::InvalidContext(
                    "@language must be a well-formed language tag or null".to_owned(),
                ));
            }
        }
    }
    // Spec section 4.1.2 step 5.10: default base direction.
    if let Some(direction) = map.get("@direction") {
        match direction {
            Value::Null => result.default_direction = None,
            Value::String(value) => match Direction::parse(value) {
                Some(parsed) => result.default_direction = Some(parsed),
                None => {
                    return Err(JsonLdError::InvalidContext(format!(
                        "@direction `{value}` must be \"ltr\", \"rtl\", or null"
                    )));
                }
            },
            _ => {
                return Err(JsonLdError::InvalidContext(
                    "@direction must be \"ltr\", \"rtl\", or null".to_owned(),
                ));
            }
        }
    }
    let protected_default = match map.get("@protected") {
        None => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => {
            return Err(JsonLdError::InvalidContext(
                "@protected must be a boolean".to_owned(),
            ));
        }
    };

    let mut defined = HashMap::new();
    let mut terms: Vec<&String> = map
        .keys()
        .filter(|key| !CONTROL_KEYS.contains(&key.as_str()))
        .collect();
    terms.sort();
    for term in dependency_order(map, &terms)? {
        create_term_definition(
            result,
            map,
            term,
            &mut defined,
            protected_default,
            override_protected,
            depth,
        )?;
    }
    Ok(())
}

/// Orders `terms` so that every term comes after the terms of the same
/// local context it depends on.
///
/// Creating a term definition defines its dependencies first (a compact
/// IRI's prefix, or a term referenced by another term's IRI), recursively;
/// a flat chain `{"t0": "t1:x", "t1": "t2:x", ...}` would recurse once per
/// link, which no document-nesting budget sees. Visiting dependencies
/// first, with an explicit stack, leaves each creation at most one level
/// of recursion for such chains. Cycles are not followed here; creating
/// their definitions still reports the cyclic IRI mapping as an error.
///
/// Behaviour change: before this ordering, a term was defined when first
/// needed, so a dependency reached through another term's IRI could be
/// defined by the recursive path, which does not apply `@protected`.
/// Defining dependencies first, on the normal path, keeps their
/// `@protected` flag; some protected-term outcomes therefore differ from
/// earlier releases, matching pyld in the cases checked.
///
/// Chain length is still bounded by [`MAX_CONTEXT_RECURSION`]: when every
/// link is a prefix (`"t0": "t1:x/"`), each IRI is longer than the next and
/// a chain of `n` links holds `O(n^2)` bytes of IRIs (600 MB from about
/// 500 KB at 20,000 links). The bound is enforced here, on the explicit
/// stack, before any definition is created.
///
/// # Errors
///
/// [`JsonLdError::ResourceLimit`] with [`JsonLdResource::ContextRecursion`]
/// when a dependency chain is longer than [`MAX_CONTEXT_RECURSION`].
fn dependency_order<'map>(
    map: &'map Map<String, Value>,
    terms: &[&'map String],
) -> Result<Vec<&'map String>, JsonLdError> {
    let mut order: Vec<&String> = Vec::with_capacity(terms.len());
    let mut chain: HashMap<&str, usize> = HashMap::new();
    let mut visiting: HashSet<&str> = HashSet::new();
    for &root in terms {
        let mut stack: Vec<(&String, bool)> = vec![(root, false)];
        while let Some((term, finished)) = stack.pop() {
            if finished {
                visiting.remove(term.as_str());
                if !chain.contains_key(term.as_str()) {
                    let length = term_dependencies(map, term)
                        .iter()
                        .filter_map(|dependency| chain.get(dependency.as_str()))
                        .max()
                        .map_or(1, |longest| longest.saturating_add(1));
                    if length > MAX_CONTEXT_RECURSION {
                        return Err(JsonLdError::ResourceLimit {
                            resource: JsonLdResource::ContextRecursion,
                            limit: MAX_CONTEXT_RECURSION,
                            observed: length,
                        });
                    }
                    chain.insert(term.as_str(), length);
                    order.push(term);
                }
                continue;
            }
            if chain.contains_key(term.as_str()) || !visiting.insert(term.as_str()) {
                continue;
            }
            stack.push((term, true));
            for dependency in term_dependencies(map, term) {
                if !chain.contains_key(dependency.as_str())
                    && !visiting.contains(dependency.as_str())
                {
                    stack.push((dependency, false));
                }
            }
        }
    }
    Ok(order)
}

/// Terms of the same local context that defining `term` would define first.
fn term_dependencies<'map>(map: &'map Map<String, Value>, term: &str) -> Vec<&'map String> {
    let mut references: Vec<&str> = Vec::new();
    if let Some((prefix, _)) = term.split_once(':') {
        references.push(prefix);
    }
    match map.get(term) {
        Some(Value::String(iri)) => references.push(iri),
        Some(Value::Object(definition)) => {
            for keyword in ["@id", "@reverse", "@type", "@index"] {
                if let Some(Value::String(iri)) = definition.get(keyword) {
                    references.push(iri);
                }
            }
        }
        _ => {}
    }
    let mut dependencies = Vec::new();
    for reference in references {
        // A reference that is itself a term of this context (`"a:b"` as a
        // key) is defined through it: define it first, on the normal path,
        // so it keeps its `@protected` flag (the recursive path in IRI
        // expansion defines terms unprotected).
        if reference != term
            && let Some((key, _)) = map.get_key_value(reference)
            && !CONTROL_KEYS.contains(&key.as_str())
        {
            dependencies.push(key);
        }
        let name = reference
            .split_once(':')
            .map_or(reference, |(prefix, _)| prefix);
        if name == term || name.starts_with('@') {
            continue;
        }
        if let Some((key, _)) = map.get_key_value(name)
            && !CONTROL_KEYS.contains(&key.as_str())
        {
            dependencies.push(key);
        }
    }
    dependencies
}

/// Creates the definition of `term` from `local`, recursing on dependencies.
///
/// `depth` is the native recursion budget described on [`process_context_at`].
fn create_term_definition(
    ctx: &mut Context,
    local: &Map<String, Value>,
    term: &str,
    defined: &mut HashMap<String, bool>,
    protected_default: bool,
    override_protected: bool,
    depth: usize,
) -> Result<(), JsonLdError> {
    check_context_depth(depth)?;
    match defined.get(term) {
        Some(true) => return Ok(()),
        Some(false) => {
            return Err(JsonLdError::InvalidContext(format!(
                "cyclic IRI mapping involving term `{term}`"
            )));
        }
        None => {}
    }
    if term.is_empty() {
        return Err(JsonLdError::InvalidContext(
            "the empty string is not a valid term".to_owned(),
        ));
    }
    if is_keyword(term) {
        return Err(JsonLdError::InvalidContext(format!(
            "keyword `{term}` cannot be redefined"
        )));
    }
    if has_keyword_form(term) {
        // Spec section 4.2.2 step 4: terms of keyword form are ignored.
        defined.insert(term.to_owned(), true);
        return Ok(());
    }
    defined.insert(term.to_owned(), false);

    let value = local.get(term).ok_or_else(|| {
        JsonLdError::InvalidContext(format!("term `{term}` is not present in the local context"))
    })?;

    let mut definition = TermDefinition {
        protected: protected_default,
        ..TermDefinition::default()
    };
    let mut simple_term = false;
    let id_string;
    let entry_map;
    let entries: &Map<String, Value> = match value {
        Value::Null => {
            entry_map = Map::new();
            &entry_map
        }
        Value::String(id) => {
            simple_term = true;
            id_string = Value::String(id.clone());
            entry_map = Map::from_iter([("@id".to_owned(), id_string)]);
            &entry_map
        }
        Value::Object(map) => map,
        _ => {
            return Err(JsonLdError::InvalidContext(format!(
                "the definition of term `{term}` must be null, a string, or an object"
            )));
        }
    };

    validate_term_definition_keys(term, entries)?;

    if let Some(Value::Bool(flag)) = entries.get("@protected") {
        definition.protected = *flag;
    } else if entries.get("@protected").is_some_and(|v| !v.is_boolean()) {
        return Err(JsonLdError::InvalidContext(format!(
            "@protected of term `{term}` must be a boolean"
        )));
    }

    // Spec section 4.2.2 step 13: `@reverse` term definitions.
    if let Some(reverse) = entries.get("@reverse") {
        return finish_reverse_definition(
            ctx,
            local,
            term,
            entries,
            reverse,
            definition,
            defined,
            override_protected,
            depth,
        );
    }

    let mut term_dropped = false;
    match entries.get("@id") {
        Some(Value::Null) => definition.iri = None,
        Some(Value::String(id)) => {
            if is_keyword(id) {
                if id == "@context" {
                    return Err(JsonLdError::InvalidContext(
                        "a term cannot alias @context".to_owned(),
                    ));
                }
                definition.iri = Some(id.clone());
            } else if has_keyword_form(id) {
                // Spec section 4.2.2 step 14.2.2: keyword-form @id values
                // drop the term.
                term_dropped = true;
            } else {
                let expanded = expand_iri_at(ctx, id, true, false, Some(local), defined, depth)?;
                match expanded {
                    Some(iri) if is_absolute_iri(&iri) || is_blank_node_id(&iri) => {
                        definition.iri = Some(iri);
                    }
                    _ => {
                        return Err(JsonLdError::InvalidContext(format!(
                            "@id of term `{term}` does not expand to an absolute IRI"
                        )));
                    }
                }
            }
        }
        Some(_) => {
            return Err(JsonLdError::InvalidContext(format!(
                "@id of term `{term}` must be a string or null"
            )));
        }
        None if value.is_null() => definition.iri = None,
        None => {
            definition.iri = Some(implicit_iri_mapping(ctx, local, term, defined, depth)?);
        }
    }

    if term_dropped {
        defined.insert(term.to_owned(), true);
        return Ok(());
    }

    if let Some(type_value) = entries.get("@type") {
        let Value::String(type_str) = type_value else {
            return Err(JsonLdError::InvalidContext(format!(
                "@type of term `{term}` must be a string"
            )));
        };
        // Spec section 4.2.2 step 12: `@id`, `@vocab`, and `@json` are valid
        // type mappings (`@none` stays outside this processor's subset).
        if type_str == "@id" || type_str == "@vocab" || type_str == "@json" {
            definition.type_mapping = Some(type_str.clone());
        } else {
            let expanded = expand_iri_at(ctx, type_str, true, false, Some(local), defined, depth)?;
            match expanded {
                Some(iri) if is_absolute_iri(&iri) => definition.type_mapping = Some(iri),
                _ => {
                    return Err(JsonLdError::InvalidContext(format!(
                        "@type of term `{term}` does not expand to an absolute IRI"
                    )));
                }
            }
        }
    }

    if let Some(language) = entries.get("@language") {
        if entries.contains_key("@type") {
            return Err(JsonLdError::InvalidContext(format!(
                "term `{term}` cannot carry both @type and @language"
            )));
        }
        match language {
            Value::Null => definition.language = LanguageMapping::Null,
            Value::String(tag) if language_shape_is_valid(tag) => {
                definition.language = LanguageMapping::Tag(tag.clone());
            }
            _ => {
                return Err(JsonLdError::InvalidContext(format!(
                    "@language of term `{term}` must be a well-formed tag or null"
                )));
            }
        }
    }

    // Spec section 4.2.2 step 22: per-term base direction.
    if let Some(direction) = entries.get("@direction") {
        if entries.contains_key("@type") {
            return Err(JsonLdError::InvalidContext(format!(
                "term `{term}` cannot carry both @type and @direction"
            )));
        }
        match direction {
            Value::Null => definition.direction = DirectionMapping::Null,
            Value::String(text) => match Direction::parse(text) {
                Some(parsed) => definition.direction = DirectionMapping::Fixed(parsed),
                None => {
                    return Err(JsonLdError::InvalidContext(format!(
                        "@direction of term `{term}` must be \"ltr\", \"rtl\", or null"
                    )));
                }
            },
            _ => {
                return Err(JsonLdError::InvalidContext(format!(
                    "@direction of term `{term}` must be \"ltr\", \"rtl\", or null"
                )));
            }
        }
    }

    if let Some(container) = entries.get("@container") {
        definition.container = parse_container(term, container)?;
        // Spec section 4.2.2 step 19.4: a @type container forces an @id or
        // @vocab type mapping, defaulting to @id.
        if definition.container.type_ {
            match definition.type_mapping.as_deref() {
                None => definition.type_mapping = Some("@id".to_owned()),
                Some("@id" | "@vocab") => {}
                Some(other) => {
                    return Err(JsonLdError::InvalidContext(format!(
                        "term `{term}` has a @type container but type mapping `{other}`"
                    )));
                }
            }
        }
    }

    // Spec section 4.2.2 step 20 / 4.6.1.1: `@index` inside a term
    // definition selects property-based data indexing. It is valid only
    // with an `@index` container, and the value must expand to an IRI.
    if let Some(index_value) = entries.get("@index") {
        if !definition.container.index {
            return Err(JsonLdError::InvalidContext(format!(
                "term `{term}` has @index without an @index container"
            )));
        }
        let Value::String(index_term) = index_value else {
            return Err(JsonLdError::InvalidContext(format!(
                "@index of term `{term}` must be a string"
            )));
        };
        let expanded = expand_iri_at(ctx, index_term, true, false, Some(local), defined, depth)?;
        match expanded {
            Some(iri) if is_absolute_iri(&iri) => definition.index = Some(iri),
            _ => {
                return Err(JsonLdError::InvalidContext(format!(
                    "@index of term `{term}` must expand to an absolute IRI"
                )));
            }
        }
    }

    // Spec section 4.2.2 step 21: scoped contexts are validated eagerly (the
    // result is discarded) and stored raw for re-application at expansion.
    if let Some(scoped) = entries.get("@context") {
        validate_scoped_context(ctx, term, scoped, depth)?;
        definition.local_context = Some(Rc::new(scoped.clone()));
    }

    // Spec section 4.2.2 step 23: `@nest` must be `@nest` itself or a value
    // of keyword form other than a keyword is invalid.
    if let Some(nest) = entries.get("@nest") {
        let Value::String(nest_value) = nest else {
            return Err(JsonLdError::InvalidContext(format!(
                "@nest of term `{term}` must be a string"
            )));
        };
        if is_keyword(nest_value) && nest_value != "@nest" {
            return Err(JsonLdError::InvalidContext(format!(
                "@nest of term `{term}` must not be a keyword other than @nest"
            )));
        }
        definition.nest = Some(nest_value.clone());
    }

    match entries.get("@prefix") {
        None => {}
        Some(Value::Bool(flag)) => {
            if *flag && (term.contains(':') || term.contains('/')) {
                return Err(JsonLdError::InvalidContext(format!(
                    "term `{term}` contains a colon or slash and cannot set @prefix"
                )));
            }
            definition.prefix = *flag;
        }
        Some(_) => {
            return Err(JsonLdError::InvalidContext(format!(
                "@prefix of term `{term}` must be a boolean"
            )));
        }
    }

    // Spec section 4.2.2 step 15: a simple term whose IRI mapping ends in a
    // gen-delim character acts as a prefix.
    if simple_term
        && !term.contains(':')
        && !term.contains('/')
        && definition
            .iri
            .as_deref()
            .is_some_and(|iri| iri.ends_with(GEN_DELIMS))
    {
        definition.prefix = true;
    }

    store_definition(ctx, term, definition, defined, override_protected)
}

/// Finishes a `@reverse` term definition (spec section 4.2.2 step 13).
#[expect(
    clippy::too_many_arguments,
    reason = "the reverse branch shares create_term_definition's full state"
)]
fn finish_reverse_definition(
    ctx: &mut Context,
    local: &Map<String, Value>,
    term: &str,
    entries: &Map<String, Value>,
    reverse: &Value,
    mut definition: TermDefinition,
    defined: &mut HashMap<String, bool>,
    override_protected: bool,
    depth: usize,
) -> Result<(), JsonLdError> {
    // Spec: @id or @nest alongside @reverse is an invalid reverse property.
    // Fail-closed extension: the spec silently ignores every other entry in
    // a reverse term definition; this processor rejects them instead.
    for key in entries.keys() {
        if !matches!(key.as_str(), "@reverse" | "@container" | "@protected") {
            return Err(JsonLdError::InvalidContext(format!(
                "entry `{key}` is not valid in the reverse term definition `{term}`"
            )));
        }
    }
    let Value::String(reverse_iri) = reverse else {
        return Err(JsonLdError::InvalidContext(format!(
            "@reverse of term `{term}` must be a string"
        )));
    };
    if has_keyword_form(reverse_iri) {
        // Spec section 4.2.2 step 13.3: keyword-form values drop the term.
        defined.insert(term.to_owned(), true);
        return Ok(());
    }
    let expanded = expand_iri_at(ctx, reverse_iri, true, false, Some(local), defined, depth)?;
    match expanded {
        Some(iri) if is_absolute_iri(&iri) || is_blank_node_id(&iri) => {
            definition.iri = Some(iri);
        }
        _ => {
            return Err(JsonLdError::InvalidContext(format!(
                "@reverse of term `{term}` does not expand to an absolute IRI"
            )));
        }
    }
    // Spec section 4.2.2 step 13.5: reverse properties only support @set and
    // @index containers (or null).
    if let Some(container) = entries.get("@container") {
        match container {
            Value::Null => {}
            Value::String(value) if value == "@set" => definition.container.set = true,
            Value::String(value) if value == "@index" => definition.container.index = true,
            _ => {
                return Err(JsonLdError::InvalidContext(format!(
                    "reverse term `{term}` only supports @set, @index, or null containers"
                )));
            }
        }
    }
    definition.reverse = true;
    store_definition(ctx, term, definition, defined, override_protected)
}

/// Validates a scoped context at definition time; the result is discarded
/// (spec section 4.2.2 step 21.2).
fn validate_scoped_context(
    ctx: &Context,
    term: &str,
    scoped: &Value,
    depth: usize,
) -> Result<(), JsonLdError> {
    match process_context_at(
        ctx,
        scoped,
        ctx.base.as_deref(),
        true,
        true,
        depth.saturating_add(1),
    ) {
        Ok(_) => Ok(()),
        // The sovereign boundary error keeps its identity (and the IRI).
        Err(refused @ JsonLdError::RemoteContextRefused { .. }) => Err(refused),
        // A budget trip keeps its identity too: a resource limit must not
        // be reported as a malformed context, or the caller cannot tell a
        // hostile document from an invalid one.
        Err(limit @ JsonLdError::ResourceLimit { .. }) => Err(limit),
        Err(error) => Err(JsonLdError::InvalidContext(format!(
            "invalid scoped context on term `{term}`: {error}"
        ))),
    }
}

/// Applies the protected-term check and stores the finished definition.
fn store_definition(
    ctx: &mut Context,
    term: &str,
    mut definition: TermDefinition,
    defined: &mut HashMap<String, bool>,
    override_protected: bool,
) -> Result<(), JsonLdError> {
    if !override_protected
        && let Some(previous) = ctx.terms.get(term)
        && previous.protected
    {
        if !previous.same_mapping(&definition) {
            return Err(JsonLdError::ProtectedTermRedefinition {
                term: term.to_owned(),
            });
        }
        definition.protected = true;
    }
    Rc::make_mut(&mut ctx.terms).insert(term.to_owned(), definition);
    defined.insert(term.to_owned(), true);
    Ok(())
}

/// Derives the IRI mapping of a term that has no `@id` entry.
fn implicit_iri_mapping(
    ctx: &mut Context,
    local: &Map<String, Value>,
    term: &str,
    defined: &mut HashMap<String, bool>,
    depth: usize,
) -> Result<String, JsonLdError> {
    if let Some(colon) = term.find(':')
        && colon > 0
    {
        let prefix = &term[..colon];
        let suffix = &term[colon + 1..];
        if local.contains_key(prefix) && defined.get(prefix) != Some(&true) {
            create_term_definition(
                ctx,
                local,
                prefix,
                defined,
                false,
                false,
                depth.saturating_add(1),
            )?;
        }
        if let Some(prefix_definition) = ctx.terms.get(prefix)
            && let Some(prefix_iri) = &prefix_definition.iri
        {
            return Ok(format!("{prefix_iri}{suffix}"));
        }
        if has_scheme(term) || is_blank_node_id(term) {
            return Ok(term.to_owned());
        }
        return Err(JsonLdError::InvalidContext(format!(
            "compact IRI term `{term}` uses an undefined prefix"
        )));
    }
    match &ctx.vocab {
        Some(vocab) => Ok(format!("{vocab}{term}")),
        None => Err(JsonLdError::InvalidContext(format!(
            "term `{term}` has no @id and no @vocab is in scope"
        ))),
    }
}

fn validate_term_definition_keys(
    term: &str,
    entries: &Map<String, Value>,
) -> Result<(), JsonLdError> {
    for key in entries.keys() {
        match key.as_str() {
            // Spec section 4.2.2 step 26 lists the valid entry set.
            "@id" | "@type" | "@language" | "@container" | "@prefix" | "@protected"
            | "@reverse" | "@context" | "@nest" | "@index" | "@direction" => {}
            other => {
                return Err(JsonLdError::InvalidContext(format!(
                    "unexpected entry `{other}` in the definition of term `{term}`"
                )));
            }
        }
    }
    Ok(())
}

/// Parses a `@container` value per spec section 4.2.2 step 19.
///
/// Valid forms: one of `@graph`/`@id`/`@index`/`@language`/`@list`/`@set`/
/// `@type`; an array of exactly one of those; `@graph` with `@id` or
/// `@index`, optionally with `@set`; or `@set` with any single one of the
/// others except `@list`. `@language` combines only with `@set`.
fn parse_container(term: &str, container: &Value) -> Result<ContainerSet, JsonLdError> {
    let entries: Vec<&Value> = match container {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    let mut set = ContainerSet::default();
    for entry in &entries {
        let Value::String(keyword) = entry else {
            return Err(JsonLdError::InvalidContext(format!(
                "@container of term `{term}` must hold keyword strings"
            )));
        };
        match keyword.as_str() {
            "@list" => set.list = true,
            "@set" => set.set = true,
            "@index" => set.index = true,
            "@id" => set.id = true,
            "@type" => set.type_ = true,
            "@graph" => set.graph = true,
            "@language" => set.language = true,
            other => {
                return Err(JsonLdError::InvalidContext(format!(
                    "invalid @container keyword `{other}` on term `{term}`"
                )));
            }
        }
    }
    let non_set = usize::from(set.list)
        + usize::from(set.index)
        + usize::from(set.id)
        + usize::from(set.type_)
        + usize::from(set.graph)
        + usize::from(set.language);
    let valid = if set.list {
        // @list combines with nothing (not even @set).
        non_set == 1 && !set.set
    } else {
        match non_set {
            0 => set.set, // bare @set (or an empty array is invalid)
            1 => true,    // one keyword, optionally with @set
            2 => set.graph && (set.id || set.index),
            _ => false,
        }
    };
    if !valid {
        return Err(JsonLdError::InvalidContext(format!(
            "invalid @container combination on term `{term}`"
        )));
    }
    Ok(set)
}

/// Expands `value` to an IRI, keyword, or blank node identifier.
///
/// Returns `Ok(None)` when the value must be dropped per the spec (a
/// keyword-form non-keyword, or a term explicitly decoupled with a null IRI
/// mapping). A returned string may still be relative; callers decide whether
/// that is an error (it is at the RDF boundary).
///
/// # Errors
///
/// Propagates term-definition errors when `local` triggers the recursive
/// creation of a dependency.
pub(crate) fn expand_iri(
    ctx: &mut Context,
    value: &str,
    vocab: bool,
    document_relative: bool,
    local: Option<&Map<String, Value>>,
    defined: &mut HashMap<String, bool>,
) -> Result<Option<String>, JsonLdError> {
    expand_iri_at(ctx, value, vocab, document_relative, local, defined, 0)
}

/// IRI expansion at a known recursion depth (see [`process_context_at`]).
fn expand_iri_at(
    ctx: &mut Context,
    value: &str,
    vocab: bool,
    document_relative: bool,
    local: Option<&Map<String, Value>>,
    defined: &mut HashMap<String, bool>,
    depth: usize,
) -> Result<Option<String>, JsonLdError> {
    if is_keyword(value) {
        return Ok(Some(value.to_owned()));
    }
    if has_keyword_form(value) {
        // Spec section 5.2.2 step 3: values that look like keywords drop.
        return Ok(None);
    }
    if let Some(local_map) = local
        && local_map.contains_key(value)
        && defined.get(value) != Some(&true)
    {
        create_term_definition(
            ctx,
            local_map,
            value,
            defined,
            false,
            false,
            depth.saturating_add(1),
        )?;
    }
    if let Some(definition) = ctx.terms.get(value) {
        if definition.iri.as_deref().is_some_and(is_keyword) {
            return Ok(definition.iri.clone());
        }
        if vocab {
            return Ok(definition.iri.clone());
        }
    }
    if let Some(colon) = value.find(':')
        && colon > 0
    {
        let prefix = &value[..colon];
        let suffix = &value[colon + 1..];
        if prefix == "_" || suffix.starts_with("//") {
            return Ok(Some(value.to_owned()));
        }
        if let Some(local_map) = local
            && local_map.contains_key(prefix)
            && defined.get(prefix) != Some(&true)
        {
            create_term_definition(
                ctx,
                local_map,
                prefix,
                defined,
                false,
                false,
                depth.saturating_add(1),
            )?;
        }
        if let Some(definition) = ctx.terms.get(prefix)
            && definition.prefix
            && let Some(prefix_iri) = &definition.iri
        {
            return Ok(Some(format!("{prefix_iri}{suffix}")));
        }
        // Spec section 5.2.2 step 6.5: return the value as-is only when it
        // really *is* an IRI, that is when the part before the colon is a
        // valid scheme. `/:` and `1:x` contain a colon but no scheme; they
        // are relative references and must fall through to `@vocab` and
        // base resolution below. Returning them verbatim would break
        // `expand(compact(doc)) == expand(doc)`, because compaction emits
        // exactly such references when the base ends at an authority.
        if has_scheme(value) {
            return Ok(Some(value.to_owned()));
        }
    }
    if vocab && let Some(vocab_iri) = &ctx.vocab {
        return Ok(Some(format!("{vocab_iri}{value}")));
    }
    if document_relative && let Some(base) = &ctx.base {
        return Ok(Some(resolve(base, value)));
    }
    Ok(Some(value.to_owned()))
}
