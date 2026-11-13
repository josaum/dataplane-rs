// Rust guideline compliant 2026-02-21
//! CBOR-LD 1.0 compression and decompression for inline-context documents.
//!
//! [`compress`] converts a JSON-LD document with inline (embedded)
//! `@context` objects into a CBOR-LD envelope; [`decompress`] inverts it.
//! The conversion follows the vendored CBOR-LD 1.0 algorithms restricted to
//! the inline-context subset documented in the crate root: term identifiers
//! are derived deterministically from the embedded contexts, JSON-LD
//! keywords map through the vendored keyword table, and `@id`/`@type` IRIs
//! compress through the term map, the URL Prefix Table, and the vendored
//! DID URL and Data URL codecs. Multibase-typed string values compress
//! through the Multibase codec.
//!
//! When the selected registry entry carries compression sub-tables, those
//! are consulted first, ahead of the generic codecs: a context IRI the
//! entry's `context` table lists rides the wire as its identifier, and a
//! value the entry's `url` or typed table lists rides as its identifier
//! rather than through prefix compression. Identifiers are scoped to one
//! entry, so an identifier the selected entry does not define is a typed
//! error rather than a lookup in some other entry's table.
//!
//! Output is unsigned by construction and the codec performs no network
//! I/O: a registered context IRI is resolved only against the
//! caller-supplied [`ProvidedContexts`] map — the registry maps the IRI to
//! an integer, never to a document — and fails with
//! [`CborldError::UnregisteredContext`] instead of being fetched.
//!
//! # Term identifiers are scoped to the node that uses them
//!
//! The identifier registry is global to one conversion, but a key rides as
//! a compressed identifier only while its term is *active at that node* —
//! a JSON-LD keyword, or a term the node's own or an ancestor's `@context`
//! defines. A name that merely happens to be defined somewhere else in the
//! document rides as text. The rule is load-bearing for the round-trip
//! guarantee: [`decompress`] resolves every key of a node before descending
//! into that node's values, so an identifier a sibling subtree's context
//! assigned would not yet exist when the decoder needed it.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::{
    cbor::{self, CborLimits, CborValue},
    context::{
        ActiveContext, TermDef, TermIdRegistry, is_keyword, json_kind, load_context,
        load_context_document,
    },
    error::{CborldError, CborldResource},
    registry::{
        CBORLD_TAG, MULTIBASE_BASE58BTC_HEADER, MULTIBASE_BASE64URL_HEADER, MULTIBASE_IRI,
        REGISTRY_ENTRY_COMPRESSED, REGISTRY_ENTRY_UNCOMPRESSED, RegistryEntry, TABLE_TYPE_CONTEXT,
        TABLE_TYPE_NONE, TABLE_TYPE_URL, URL_PREFIX_DATA, URL_PREFIX_DID_KEY,
        URL_PREFIX_DID_V1_NYM, URL_PREFIX_HTTP, URL_PREFIX_HTTPS, URL_PREFIX_URN_UUID,
        XSD_DATE_IRI, XSD_DATE_TIME_IRI, is_encoded_as_bytes, registry_entry,
    },
    table_codec::{signed_from_bytes, signed_to_bytes, unsigned_from_bytes, unsigned_to_bytes},
    value_codec::{
        DateTimeEncoding, base58btc_decode, base58btc_encode, base64pad_decode, base64pad_encode,
        base64url_nopad_decode, base64url_nopad_encode, encode_xsd_date, encode_xsd_datetime,
        format_uuid, format_xsd_date, format_xsd_datetime_millis, format_xsd_datetime_seconds,
        parse_uuid_lowercase,
    },
};

/// Envelope variant produced by [`compress`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CompressionMode {
    /// Registry entry 1: semantic compression, default processing model.
    #[default]
    Compressed,
    /// Registry entry 0: payload is the plain CBOR form of the document.
    Uncompressed,
    /// A vendored registry entry selected by identifier.
    ///
    /// The identifier selects the entry's whole set of typed compression
    /// sub-tables (see [`crate::registry::RegistryEntry`]). Identifiers 0
    /// and 1 are accepted here and behave exactly like
    /// [`CompressionMode::Uncompressed`] and
    /// [`CompressionMode::Compressed`]. Every other vendored entry is
    /// marked provisional upstream and must also appear in
    /// [`CborldOptions::accepted_provisional_entries`].
    RegistryEntry(u64),
}

impl CompressionMode {
    /// Returns the registry entry identifier this mode selects.
    #[must_use]
    pub const fn registry_entry_id(self) -> u64 {
        match self {
            Self::Compressed => REGISTRY_ENTRY_COMPRESSED,
            Self::Uncompressed => REGISTRY_ENTRY_UNCOMPRESSED,
            Self::RegistryEntry(id) => id,
        }
    }
}

/// Provisional CBOR-LD registry entries the caller explicitly accepts.
///
/// Every registry entry other than 0 and 1 is marked `provisional: true`
/// upstream, meaning it may change or be removed. This crate therefore
/// refuses a provisional entry unless the caller names it here, on both
/// [`compress`] and [`decompress`]; see the crate-root section "Provisional
/// registry entries" for the reasoning.
#[derive(Clone, Debug, Default)]
pub struct ProvisionalEntries {
    ids: BTreeSet<u64>,
}

impl ProvisionalEntries {
    /// Creates an empty set, accepting no provisional entry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts the provisional registry entry `id`.
    ///
    /// Returns whether `id` was newly added.
    pub fn accept(&mut self, id: u64) -> bool {
        self.ids.insert(id)
    }

    /// Returns whether the provisional registry entry `id` is accepted.
    #[must_use]
    pub fn contains(&self, id: u64) -> bool {
        self.ids.contains(&id)
    }
}

/// Caller-supplied context documents for registered context IRIs.
///
/// The codec never fetches a context: when a document's `@context` is a
/// string IRI, the caller must supply the content published under that
/// exact IRI (sovereign no-network boundary). Both [`compress`] and
/// [`decompress`] consult the same map, and the IRI itself rides the wire
/// as a text string. Supplying *different* content on the two sides is
/// detectable only when a compressed term identifier fails to resolve
/// ([`CborldError::UnknownTermId`]); this mirrors the specification, which
/// references contexts by URL without a content digest.
#[derive(Clone, Debug, Default)]
pub struct ProvidedContexts {
    contexts: BTreeMap<String, Value>,
}

impl ProvidedContexts {
    /// Creates an empty provided-contexts map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Supplies `document` as the content of the context named by `iri`.
    ///
    /// `document` may be a full context document (`{"@context": ...}`) or a
    /// bare term-definition object. Returns the previously supplied content
    /// for `iri`, if any.
    pub fn insert(&mut self, iri: impl Into<String>, document: Value) -> Option<Value> {
        self.contexts.insert(iri.into(), document)
    }

    /// Returns the supplied content for `iri`, if any.
    #[must_use]
    pub fn get(&self, iri: &str) -> Option<&Value> {
        self.contexts.get(iri)
    }
}

/// Options governing one [`compress`] or [`decompress`] call.
#[derive(Clone, Debug, Default)]
pub struct CborldOptions {
    /// Fail-closed resource limits (input bytes, depth, items, value bytes).
    pub limits: CborLimits,
    /// Envelope variant produced by [`compress`]; ignored by [`decompress`],
    /// which takes the registry entry identifier from the envelope itself.
    pub mode: CompressionMode,
    /// Caller-supplied content for registered context IRIs (never fetched).
    pub provided_contexts: ProvidedContexts,
    /// Provisional registry entries this call accepts; empty by default.
    pub accepted_provisional_entries: ProvisionalEntries,
}

/// Resolves one registry entry identifier against the vendored registry.
///
/// # Errors
///
/// Returns [`CborldError::UnknownRegistryEntry`] when `id` is not vendored,
/// [`CborldError::Unsupported`] when the entry declares a processing model
/// this codec does not implement, and
/// [`CborldError::ProvisionalRegistryEntry`] when the entry is provisional
/// and `accepted` does not name it.
fn resolve_registry_entry(
    id: u64,
    accepted: &ProvisionalEntries,
) -> Result<&'static RegistryEntry, CborldError> {
    let entry = registry_entry(id).ok_or(CborldError::UnknownRegistryEntry { id })?;
    if !entry.uses_default_processing_model() {
        return Err(CborldError::Unsupported(format!(
            "registry entry {id} declares processing model {mode}; only the \
             default processing model is implemented",
            mode = entry.mode
        )));
    }
    if entry.provisional && !accepted.contains(id) {
        return Err(CborldError::ProvisionalRegistryEntry {
            id,
            domain: entry.domain,
        });
    }
    // A sub-table whose identifiers ride as unsigned integers is unambiguous
    // only while the generic codec for that same type does not itself emit
    // byte strings. The specification's `typesEncodedAsBytes` covers `url`,
    // `xsd:date`, and `xsd:dateTime`, but not `sec:multibase`, whose codec
    // does emit byte strings — so a multibase sub-table would make a
    // compressed multibase value and a literal integer indistinguishable on
    // decode. No vendored entry defines one; if upstream ever adds one, fail
    // loudly here rather than silently misread it.
    if let Some(table) = entry.sub_table(MULTIBASE_IRI)
        && !is_encoded_as_bytes(table.table_type)
    {
        return Err(CborldError::Unsupported(format!(
            "registry entry {id} defines a {MULTIBASE_IRI} compression table, \
             whose identifiers would be ambiguous with the byte strings the \
             multibase codec emits"
        )));
    }
    Ok(entry)
}

fn depth_error(limits: &CborLimits, observed: usize) -> CborldError {
    CborldError::ResourceLimit {
        resource: CborldResource::Depth,
        limit: limits.max_depth,
        observed,
    }
}

/// Converts a plain JSON value to its CBOR form (no semantic compression).
fn json_to_cbor(
    value: &Value,
    limits: &CborLimits,
    depth: usize,
) -> Result<CborValue, CborldError> {
    if depth > limits.max_depth {
        return Err(depth_error(limits, depth));
    }
    Ok(match value {
        Value::Null => CborValue::Null,
        Value::Bool(flag) => CborValue::Bool(*flag),
        Value::Number(number) => number_to_cbor(number)?,
        Value::String(text) => CborValue::Text(text.clone()),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_to_cbor(item, limits, depth + 1)?);
            }
            CborValue::Array(out)
        }
        Value::Object(object) => {
            let mut entries = Vec::with_capacity(object.len());
            for (key, member) in object {
                entries.push((
                    CborValue::Text(key.clone()),
                    json_to_cbor(member, limits, depth + 1)?,
                ));
            }
            CborValue::Map(entries)
        }
    })
}

/// Converts one JSON number to the CBOR item that round-trips it exactly.
///
/// Integers stay integers; other numbers become floats and are encoded in
/// the preferred (shortest exact) serialization by the CBOR layer. A number
/// with no exact integer or finite-float form is a typed error, never a
/// silent approximation.
fn number_to_cbor(number: &serde_json::Number) -> Result<CborValue, CborldError> {
    if let Some(unsigned) = number.as_u64() {
        Ok(CborValue::Unsigned(unsigned))
    } else if let Some(signed) = number.as_i64() {
        Ok(CborValue::Negative(signed.unsigned_abs() - 1))
    } else {
        match number.as_f64() {
            Some(float) if float.is_finite() => Ok(CborValue::Float(float)),
            _ => Err(CborldError::NumberRange(format!(
                "JSON number {number} has no exact CBOR integer or float form"
            ))),
        }
    }
}

fn signed_to_cbor(value: i64) -> CborValue {
    if value >= 0 {
        CborValue::Unsigned(value as u64)
    } else {
        CborValue::Negative(value.unsigned_abs() - 1)
    }
}

fn negative_to_i64(magnitude: u64) -> Result<i64, CborldError> {
    i64::try_from(magnitude)
        .map(|n| -n - 1)
        .map_err(|_overflow| {
            CborldError::NumberRange(format!("negative integer -1-{magnitude} underflows i64"))
        })
}

/// Converts a plain CBOR value back to JSON (no semantic decompression).
fn cbor_to_json(
    value: &CborValue,
    limits: &CborLimits,
    depth: usize,
) -> Result<Value, CborldError> {
    if depth > limits.max_depth {
        return Err(depth_error(limits, depth));
    }
    Ok(match value {
        CborValue::Null => Value::Null,
        CborValue::Bool(flag) => Value::Bool(*flag),
        CborValue::Unsigned(unsigned) => Value::Number((*unsigned).into()),
        CborValue::Negative(magnitude) => Value::Number(negative_to_i64(*magnitude)?.into()),
        CborValue::Float(float) => {
            Value::Number(serde_json::Number::from_f64(*float).ok_or_else(|| {
                CborldError::NumberRange(
                    "non-finite float is not representable in JSON".to_string(),
                )
            })?)
        }
        CborValue::Text(text) => Value::String(text.clone()),
        CborValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(cbor_to_json(item, limits, depth + 1)?);
            }
            Value::Array(out)
        }
        CborValue::Map(entries) => {
            let mut object = serde_json::Map::with_capacity(entries.len());
            for (key, member) in entries {
                let CborValue::Text(key) = key else {
                    return Err(CborldError::Envelope(
                        "plain CBOR map key must be a text string".to_string(),
                    ));
                };
                if object
                    .insert(key.clone(), cbor_to_json(member, limits, depth + 1)?)
                    .is_some()
                {
                    return Err(CborldError::Envelope(format!("duplicate map key {key}")));
                }
            }
            Value::Object(object)
        }
        CborValue::Bytes(_) => {
            return Err(CborldError::Unsupported(
                "byte string is not representable in JSON in this subset".to_string(),
            ));
        }
        CborValue::Tag(tag, _) => {
            return Err(CborldError::Unsupported(format!(
                "nested CBOR tag {tag} is not supported"
            )));
        }
    })
}

/// Type-aware conversion strategy selected for one value.
enum TableType<'def> {
    /// URL codec: `@id`/`@type` positions and `@id`/`@vocab`-typed terms.
    Url,
    /// A JSON-LD type IRI from the term definition.
    Typed(&'def str),
    /// No applicable strategy: values pass through.
    None,
}

impl TableType<'_> {
    /// Returns the registry sub-table type key for this strategy.
    ///
    /// Mirrors `tableType` in the specification's "Create Value Encoder":
    /// `"url"` for URL positions, the term's JSON-LD type IRI otherwise, and
    /// `"none"` when the term carries no type.
    fn sub_table_key(&self) -> &str {
        match self {
            Self::Url => TABLE_TYPE_URL,
            Self::Typed(type_iri) => type_iri,
            Self::None => TABLE_TYPE_NONE,
        }
    }
}

fn table_type<'def>(term: &str, def: Option<&'def TermDef>) -> TableType<'def> {
    let value_type = def.and_then(|def| def.value_type.as_deref());
    let is_url = term == "@id"
        || term == "@type"
        || def.is_some_and(|def| def.id.as_deref() == Some("@type"))
        || matches!(value_type, Some("@id") | Some("@vocab"));
    if is_url {
        TableType::Url
    } else if let Some(value_type) = value_type {
        TableType::Typed(value_type)
    } else {
        TableType::None
    }
}

/// Prefixes whose codec is `[prefix id, remainder]`, checked in table order.
const COMPRESSIBLE_URL_PREFIXES: [(&str, u64); 3] =
    [URL_PREFIX_HTTP, URL_PREFIX_HTTPS, URL_PREFIX_URN_UUID];

/// DID prefixes handled by the vendored Base58 DID URL codec.
const DID_URL_PREFIXES: [(&str, u64); 2] = [URL_PREFIX_DID_V1_NYM, URL_PREFIX_DID_KEY];

struct Compressor<'opts> {
    registry: TermIdRegistry,
    limits: CborLimits,
    provided: &'opts ProvidedContexts,
    entry: &'static RegistryEntry,
}

impl Compressor<'_> {
    fn convert_node(
        &mut self,
        object: &serde_json::Map<String, Value>,
        active: &ActiveContext,
        depth: usize,
    ) -> Result<CborValue, CborldError> {
        if depth > self.limits.max_depth {
            return Err(depth_error(&self.limits, depth));
        }
        let mut entries: Vec<(CborValue, CborValue)> = Vec::with_capacity(object.len());
        let mut scoped = active.clone();
        if let Some(context) = object.get("@context") {
            let (key, encoded) = self.convert_context(context, &mut scoped, depth)?;
            entries.push((CborValue::Unsigned(key), encoded));
        }
        let mut keys: Vec<&String> = object
            .keys()
            .filter(|key| key.as_str() != "@context")
            .collect();
        keys.sort_unstable();
        for key in keys {
            let value = &object[key.as_str()];
            let plural = value.is_array();
            let def = scoped.definition(key).cloned();
            // A term identifier may be emitted only while the term is
            // *active at this node*. The identifier registry is global to
            // one conversion and grows as nested contexts are visited, but
            // the decoder resolves every key of a node before it descends
            // into any of that node's values. Consulting the registry
            // without the scope test therefore let a key pick up an
            // identifier that a *sibling subtree's* context had just
            // assigned, which the decoder had not seen yet: compression
            // succeeded and decompression failed with `unknown_term_id`,
            // breaking the crate's unconditional round-trip guarantee. An
            // out-of-scope term is not a compressible term, so it rides as
            // text, exactly as it would if the name were unique.
            let compressible = is_keyword(key) || def.is_some();
            let key_cbor = match self.registry.id_of(key).filter(|_id| compressible) {
                Some(id) => CborValue::Unsigned(id + u64::from(plural)),
                None => CborValue::Text(key.clone()),
            };
            let converted = if let Value::Array(items) = value {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.convert_value(key, def.as_ref(), &scoped, item, depth + 1)?);
                }
                CborValue::Array(out)
            } else {
                self.convert_value(key, def.as_ref(), &scoped, value, depth + 1)?
            };
            entries.push((key_cbor, converted));
        }
        Ok(CborValue::Map(entries))
    }

    /// Embeds and applies one `@context` entry; returns (key id, encoding).
    fn convert_context(
        &mut self,
        context: &Value,
        scoped: &mut ActiveContext,
        depth: usize,
    ) -> Result<(u64, CborValue), CborldError> {
        if let Value::Array(items) = context {
            let mut encoded = Vec::with_capacity(items.len());
            for item in items {
                encoded.push(self.convert_context_entry(item, scoped, depth)?);
            }
            Ok((1, CborValue::Array(encoded)))
        } else {
            Ok((0, self.convert_context_entry(context, scoped, depth)?))
        }
    }

    /// Applies one `@context` entry and returns its encoded form.
    ///
    /// A string entry is a registered context IRI. The selected registry
    /// entry's `context` sub-table decides how the IRI rides the wire — as
    /// an unsigned integer when the table assigns it one, otherwise as a
    /// text string — but it never supplies the context *document*: that
    /// still comes from the caller-supplied provided-contexts map, because
    /// the registry maps IRIs to integers and nothing more. An IRI with no
    /// provided content is refused, never fetched.
    fn convert_context_entry(
        &mut self,
        item: &Value,
        scoped: &mut ActiveContext,
        depth: usize,
    ) -> Result<CborValue, CborldError> {
        if let Value::String(iri) = item {
            let document = self
                .provided
                .get(iri)
                .ok_or_else(|| CborldError::UnregisteredContext { iri: iri.clone() })?;
            *scoped = load_context_document(&mut self.registry, scoped, iri, document)?;
            return Ok(
                match self
                    .entry
                    .sub_table(TABLE_TYPE_CONTEXT)
                    .and_then(|table| table.id_of(iri))
                {
                    Some(id) => CborValue::Unsigned(id),
                    None => CborValue::Text(iri.clone()),
                },
            );
        }
        *scoped = load_context(&mut self.registry, scoped, item)?;
        json_to_cbor(item, &self.limits, depth + 1)
    }

    /// Applies the selected registry entry's sub-table for `strategy`.
    ///
    /// Vendored from "Create Value Encoder": the sub-table lookup runs
    /// *before* the generic codecs of the processing model. A matched value
    /// becomes its identifier — a byte string for the table types listed in
    /// `typesEncodedAsBytes` (notably `url`, where an unsigned integer
    /// already means an auto-generated term identifier), an unsigned integer
    /// otherwise. A literal integer under a table-backed typed term becomes
    /// a signed byte string, which is what keeps it distinguishable from an
    /// identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CborldError::Document`] for an integer outside `i64` under
    /// a table-backed typed term, which has no unambiguous encoding.
    fn encode_from_sub_table(
        &self,
        strategy: &TableType<'_>,
        value: &Value,
    ) -> Result<Option<CborValue>, CborldError> {
        let key = strategy.sub_table_key();
        let Some(table) = self.entry.sub_table(key) else {
            return Ok(None);
        };
        if let Value::String(text) = value
            && let Some(id) = table.id_of(text)
        {
            return Ok(Some(if is_encoded_as_bytes(key) {
                CborValue::Bytes(unsigned_to_bytes(id))
            } else {
                CborValue::Unsigned(id)
            }));
        }
        if key != TABLE_TYPE_NONE
            && let Value::Number(number) = value
            && (number.is_i64() || number.is_u64())
        {
            let integer = number.as_i64().ok_or_else(|| {
                CborldError::Document(format!(
                    "integer {number} under a term backed by the {key} table of \
                     registry entry {} exceeds i64 and has no unambiguous \
                     compressed form",
                    self.entry.id
                ))
            })?;
            return Ok(Some(CborValue::Bytes(signed_to_bytes(integer))));
        }
        Ok(None)
    }

    fn convert_value(
        &mut self,
        term: &str,
        def: Option<&TermDef>,
        active: &ActiveContext,
        value: &Value,
        depth: usize,
    ) -> Result<CborValue, CborldError> {
        if depth > self.limits.max_depth {
            return Err(depth_error(&self.limits, depth));
        }
        match value {
            Value::Null => Ok(CborValue::Null),
            Value::Object(object) => self.convert_node(object, active, depth + 1),
            Value::Array(items) => {
                // A nested array (an array element that is itself an array)
                // is indistinguishable from a codec-produced array under the
                // URL and xsd:dateTime strategies, so it is refused there.
                // This refusal is load-bearing for the http(s)/urn:uuid,
                // data:, and did: codecs, which all emit arrays; the
                // multibase codec emits byte strings and needs no refusal.
                if matches!(
                    table_type(term, def),
                    TableType::Url | TableType::Typed(XSD_DATE_TIME_IRI)
                ) {
                    return Err(CborldError::Document(format!(
                        "nested array under codec-typed term {term} would be \
                         ambiguous with a compressed value and is refused"
                    )));
                }
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.convert_value(term, def, active, item, depth + 1)?);
                }
                Ok(CborValue::Array(out))
            }
            Value::String(text) => self.convert_scalar_string(term, def, text),
            Value::Bool(flag) => {
                self.reject_typed_scalar(term, def, "boolean")?;
                Ok(CborValue::Bool(*flag))
            }
            Value::Number(number) => {
                self.reject_typed_scalar(term, def, "number")?;
                if let Some(encoded) = self.encode_from_sub_table(&table_type(term, def), value)? {
                    return Ok(encoded);
                }
                number_to_cbor(number)
            }
        }
    }

    /// Rejects non-string scalars under codec-typed terms (fail closed).
    fn reject_typed_scalar(
        &self,
        term: &str,
        def: Option<&TermDef>,
        kind: &str,
    ) -> Result<(), CborldError> {
        match table_type(term, def) {
            TableType::Url => Err(CborldError::Document(format!(
                "value of URL-typed term {term} must be a string, found {kind}"
            ))),
            TableType::Typed(XSD_DATE_IRI | XSD_DATE_TIME_IRI) => {
                Err(CborldError::Document(format!(
                    "value of date-typed term {term} must be a string, found {kind}; \
                     a raw {kind} would not round-trip through the date codec"
                )))
            }
            _ => Ok(()),
        }
    }

    fn convert_scalar_string(
        &mut self,
        term: &str,
        def: Option<&TermDef>,
        text: &str,
    ) -> Result<CborValue, CborldError> {
        let strategy = table_type(term, def);
        if let Some(encoded) =
            self.encode_from_sub_table(&strategy, &Value::String(text.to_string()))?
        {
            return Ok(encoded);
        }
        match strategy {
            TableType::Url => Ok(self.encode_url(text)),
            TableType::Typed(XSD_DATE_IRI) => Ok(match encode_xsd_date(text) {
                Some(seconds) => signed_to_cbor(seconds),
                None => CborValue::Text(text.to_string()),
            }),
            TableType::Typed(XSD_DATE_TIME_IRI) => Ok(match encode_xsd_datetime(text) {
                Some(DateTimeEncoding::Seconds(seconds)) => signed_to_cbor(seconds),
                Some(DateTimeEncoding::WithMillis(seconds, millis)) => CborValue::Array(vec![
                    signed_to_cbor(seconds),
                    CborValue::Unsigned(u64::from(millis)),
                ]),
                None => CborValue::Text(text.to_string()),
            }),
            TableType::Typed(MULTIBASE_IRI) => Ok(self.encode_multibase(text)),
            TableType::Typed(_) | TableType::None => Ok(CborValue::Text(text.to_string())),
        }
    }

    /// Vendored Multibase codec: `z` (base58btc) and `u` (base64url, no
    /// padding) values compress to one byte string `[header, decoded...]`,
    /// only when re-encoding reproduces the input exactly; every other
    /// string passes through verbatim.
    fn encode_multibase(&self, text: &str) -> CborValue {
        if text.len() <= self.limits.max_value_bytes {
            if let Some(body) = text.strip_prefix('z')
                && let Some(decoded) = base58btc_decode(body)
                && base58btc_encode(&decoded) == body
            {
                let mut bytes = vec![MULTIBASE_BASE58BTC_HEADER];
                bytes.extend_from_slice(&decoded);
                return CborValue::Bytes(bytes);
            }
            if let Some(body) = text.strip_prefix('u')
                && let Some(decoded) = base64url_nopad_decode(body)
                && base64url_nopad_encode(&decoded) == body
            {
                let mut bytes = vec![MULTIBASE_BASE64URL_HEADER];
                bytes.extend_from_slice(&decoded);
                return CborValue::Bytes(bytes);
            }
        }
        CborValue::Text(text.to_string())
    }

    /// Vendored URL codec: term-id match, then prefix-table compression.
    ///
    /// An `http://`/`https://`/`urn:uuid:` prefix matches only when the
    /// remainder contains no `:` (spec rule), so URLs with ports or extra
    /// scheme-like segments pass through. `data:` and `did:` URLs always
    /// take their codec's array form, which reconstructs the remainder
    /// verbatim regardless of its characters.
    fn encode_url(&self, text: &str) -> CborValue {
        if let Some(id) = self.registry.id_of(text) {
            return CborValue::Unsigned(id);
        }
        for (prefix, prefix_id) in COMPRESSIBLE_URL_PREFIXES {
            let Some(rest) = text.strip_prefix(prefix) else {
                continue;
            };
            if rest.contains(':') {
                continue;
            }
            if prefix_id == URL_PREFIX_URN_UUID.1 {
                return match parse_uuid_lowercase(rest) {
                    Some(bytes) => CborValue::Array(vec![
                        CborValue::Unsigned(prefix_id),
                        CborValue::Bytes(bytes.to_vec()),
                    ]),
                    None => CborValue::Array(vec![
                        CborValue::Unsigned(prefix_id),
                        CborValue::Text(rest.to_string()),
                    ]),
                };
            }
            return CborValue::Array(vec![
                CborValue::Unsigned(prefix_id),
                CborValue::Text(rest.to_string()),
            ]);
        }
        if let Some(rest) = text.strip_prefix(URL_PREFIX_DATA.0) {
            return self.encode_data_url(rest);
        }
        for (prefix, prefix_id) in DID_URL_PREFIXES {
            if let Some(rest) = text.strip_prefix(prefix) {
                return self.encode_did_url(prefix_id, rest);
            }
        }
        CborValue::Text(text.to_string())
    }

    /// Vendored Data URL codec: `data:[mediatype];base64,<payload>`
    /// compresses to `[4, mediatype, bytes]` when the payload is canonical
    /// base64 (re-encoding reproduces it exactly); every other data URL
    /// compresses to `[4, remainder]`. Both forms reconstruct verbatim.
    fn encode_data_url(&self, rest: &str) -> CborValue {
        if let Some(split) = rest.rfind(";base64,") {
            let mediatype = &rest[..split];
            let payload = &rest[split + ";base64,".len()..];
            if payload.len() <= self.limits.max_value_bytes
                && let Some(bytes) = base64pad_decode(payload)
                && base64pad_encode(&bytes) == payload
            {
                return CborValue::Array(vec![
                    CborValue::Unsigned(URL_PREFIX_DATA.1),
                    CborValue::Text(mediatype.to_string()),
                    CborValue::Bytes(bytes),
                ]);
            }
        }
        CborValue::Array(vec![
            CborValue::Unsigned(URL_PREFIX_DATA.1),
            CborValue::Text(rest.to_string()),
        ])
    }

    /// Vendored Base58 DID URL codec: the method-specific suffix and one
    /// optional `#` fragment become segments; each canonical base58btc
    /// multibase segment (`z` header) compresses to raw bytes, every other
    /// segment stays text.
    fn encode_did_url(&self, prefix_id: u64, rest: &str) -> CborValue {
        let mut items = vec![CborValue::Unsigned(prefix_id)];
        match rest.split_once('#') {
            Some((head, fragment)) => {
                items.push(self.encode_did_segment(head));
                items.push(self.encode_did_segment(fragment));
            }
            None => items.push(self.encode_did_segment(rest)),
        }
        CborValue::Array(items)
    }

    fn encode_did_segment(&self, segment: &str) -> CborValue {
        if let Some(body) = segment.strip_prefix('z')
            && body.len() <= self.limits.max_value_bytes
            && let Some(bytes) = base58btc_decode(body)
            && base58btc_encode(&bytes) == body
        {
            return CborValue::Bytes(bytes);
        }
        CborValue::Text(segment.to_string())
    }
}

/// Divisor turning base58 reconstruction's quadratic digit work into
/// byte-equivalents for the output budget.
///
/// An `n`-byte value costs `n * n / 16`, so the default 64 MiB budget admits
/// sixteen maximal (8 KiB) values per payload instead of the ~2,000 a 16 MiB
/// input could carry, each of which costs tens of millions of digit steps.
const BASE58_WORK_DIVISOR: usize = 16;

struct Decompressor<'opts> {
    registry: TermIdRegistry,
    limits: CborLimits,
    provided: &'opts ProvidedContexts,
    entry: &'static RegistryEntry,
    /// Bytes materialized or copied so far, against `limits.max_output_bytes`.
    output_spent: Cell<usize>,
}

impl Decompressor<'_> {
    /// Charges `bytes` against the output budget.
    ///
    /// Called wherever decompression produces more than it read: a term or
    /// IRI expanded from an identifier, a reconstructed codec value, a term
    /// definition copied per entry, or a scope copied by a context.
    fn charge(&self, bytes: usize) -> Result<(), CborldError> {
        let spent = self.output_spent.get().saturating_add(bytes);
        self.output_spent.set(spent);
        if spent > self.limits.max_output_bytes {
            return Err(CborldError::ResourceLimit {
                resource: CborldResource::OutputBytes,
                limit: self.limits.max_output_bytes,
                observed: spent,
            });
        }
        Ok(())
    }

    /// Charges a base58 reconstruction of `length` bytes at its quadratic cost.
    fn charge_base58(&self, length: usize) -> Result<(), CborldError> {
        self.charge(length.saturating_mul(length) / BASE58_WORK_DIVISOR)
    }

    fn decode_node(
        &mut self,
        entries: &[(CborValue, CborValue)],
        active: &ActiveContext,
        depth: usize,
    ) -> Result<serde_json::Map<String, Value>, CborldError> {
        if depth > self.limits.max_depth {
            return Err(depth_error(&self.limits, depth));
        }
        let mut output = serde_json::Map::new();
        let mut scoped = active.clone();
        let single = entries
            .iter()
            .find(|(key, _)| *key == CborValue::Unsigned(0));
        let plural = entries
            .iter()
            .find(|(key, _)| *key == CborValue::Unsigned(1));
        match (single, plural) {
            (Some(_), Some(_)) => {
                return Err(CborldError::Envelope(
                    "both singular (0) and plural (1) @context keys are present".to_string(),
                ));
            }
            (Some((_, value)), None) => {
                let context = self.decode_context_value(value, &mut scoped, depth)?;
                output.insert("@context".to_string(), context);
            }
            (None, Some((_, value))) => {
                let CborValue::Array(items) = value else {
                    return Err(CborldError::Envelope(
                        "plural @context (key 1) must hold an array".to_string(),
                    ));
                };
                let mut contexts = Vec::with_capacity(items.len());
                for item in items {
                    contexts.push(self.decode_context_value(item, &mut scoped, depth)?);
                }
                output.insert("@context".to_string(), Value::Array(contexts));
            }
            (None, None) => {}
        }
        let mut named: Vec<(String, bool, &CborValue)> = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            match key {
                CborValue::Unsigned(0 | 1) => {}
                CborValue::Unsigned(id) => {
                    let plural = id % 2 == 1;
                    let base = id.saturating_sub(u64::from(plural));
                    let term = self
                        .registry
                        .term_of(base)
                        .ok_or(CborldError::UnknownTermId { id: *id })?;
                    self.charge(term.len())?;
                    named.push((term.to_string(), plural, value));
                }
                CborValue::Text(term) => {
                    if term == "@context" {
                        return Err(CborldError::Envelope(
                            "@context must be carried under compressed key 0 or 1".to_string(),
                        ));
                    }
                    self.charge(term.len())?;
                    named.push((term.clone(), false, value));
                }
                other => {
                    return Err(CborldError::Envelope(format!(
                        "map key must be an unsigned integer or a text string, found {}",
                        cbor_kind(other)
                    )));
                }
            }
        }
        named.sort_by(|a, b| a.0.cmp(&b.0));
        for pair in named.windows(2) {
            if let [first, second] = pair
                && first.0 == second.0
            {
                return Err(CborldError::Envelope(format!(
                    "term {} appears under more than one key",
                    first.0
                )));
            }
        }
        for (term, plural, value) in named {
            let def = scoped.definition(&term).cloned();
            if let Some(def) = &def {
                self.charge(
                    def.id
                        .as_deref()
                        .map_or(0, str::len)
                        .saturating_add(def.value_type.as_deref().map_or(0, str::len)),
                )?;
            }
            let decoded = if plural {
                let CborValue::Array(items) = value else {
                    return Err(CborldError::Envelope(format!(
                        "plural term id for {term} must hold an array"
                    )));
                };
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.decode_value(&term, def.as_ref(), &scoped, item, depth + 1)?);
                }
                Value::Array(out)
            } else {
                self.decode_value(&term, def.as_ref(), &scoped, value, depth + 1)?
            };
            output.insert(term, decoded);
        }
        Ok(output)
    }

    /// Decodes one encoded `@context` entry and applies it.
    ///
    /// A text entry is a registered context IRI carried verbatim; an
    /// unsigned integer is a context identifier resolved through the
    /// selected registry entry's `context` sub-table (an identifier the
    /// table does not define is [`CborldError::UnknownCompressedContext`],
    /// never a guess). Either way the context *content* must be present in
    /// the provided-contexts map: the registry supplies the IRI, never the
    /// document, and nothing is ever fetched.
    fn decode_context_value(
        &mut self,
        value: &CborValue,
        scoped: &mut ActiveContext,
        depth: usize,
    ) -> Result<Value, CborldError> {
        let context = match value {
            CborValue::Text(iri) => return self.apply_context_iri(iri, scoped),
            CborValue::Unsigned(id) => {
                let iri = self
                    .entry
                    .sub_table(TABLE_TYPE_CONTEXT)
                    .and_then(|table| table.value_of(*id))
                    .ok_or(CborldError::UnknownCompressedContext {
                        id: *id,
                        registry_entry_id: self.entry.id,
                    })?;
                return self.apply_context_iri(iri, scoped);
            }
            CborValue::Map(_) => cbor_to_json(value, &self.limits, depth.saturating_add(1))?,
            other => {
                return Err(CborldError::Envelope(format!(
                    "encoded @context must be a map, a text string, or a \
                     compressed context identifier, found {}",
                    cbor_kind(other)
                )));
            }
        };
        *scoped = load_context(&mut self.registry, scoped, &context)?;
        self.charge(scoped.weight())?;
        Ok(context)
    }

    /// Applies the caller-supplied content for `iri` and returns the IRI.
    fn apply_context_iri(
        &mut self,
        iri: &str,
        scoped: &mut ActiveContext,
    ) -> Result<Value, CborldError> {
        let document = self
            .provided
            .get(iri)
            .ok_or_else(|| CborldError::UnregisteredContext {
                iri: iri.to_string(),
            })?;
        *scoped = load_context_document(&mut self.registry, scoped, iri, document)?;
        self.charge(scoped.weight().saturating_add(iri.len()))?;
        Ok(Value::String(iri.to_string()))
    }

    /// Inverts [`Compressor::encode_from_sub_table`] for one value.
    ///
    /// Vendored from "Create Value Decoder": for a table type listed in
    /// `typesEncodedAsBytes` a byte string is an identifier; for every other
    /// table type an unsigned integer is an identifier and a byte string is
    /// a literal signed integer. An identifier absent from the sub-table is
    /// [`CborldError::UnknownCompressedValue`], never a fallback.
    ///
    /// # Errors
    ///
    /// Returns [`CborldError::UnknownCompressedValue`] for an unresolvable
    /// identifier and [`CborldError::Envelope`] for a non-shortest or
    /// oversized identifier encoding.
    fn decode_from_sub_table(
        &self,
        strategy: &TableType<'_>,
        value: &CborValue,
    ) -> Result<Option<Value>, CborldError> {
        let key = strategy.sub_table_key();
        let Some(table) = self.entry.sub_table(key) else {
            return Ok(None);
        };
        let as_bytes = is_encoded_as_bytes(key);
        let id = match value {
            CborValue::Bytes(bytes) if as_bytes => {
                self.check_value_bytes(bytes.len())?;
                unsigned_from_bytes(bytes)?
            }
            CborValue::Bytes(bytes) if key != TABLE_TYPE_NONE => {
                self.check_value_bytes(bytes.len())?;
                return Ok(Some(Value::Number(signed_from_bytes(bytes)?.into())));
            }
            CborValue::Unsigned(id) if !as_bytes => *id,
            _ => return Ok(None),
        };
        let decoded = table
            .value_of(id)
            .ok_or_else(|| CborldError::UnknownCompressedValue {
                id,
                table_type: key.to_string(),
                registry_entry_id: self.entry.id,
            })?;
        self.charge(decoded.len())?;
        Ok(Some(Value::String(decoded.to_string())))
    }

    fn decode_value(
        &mut self,
        term: &str,
        def: Option<&TermDef>,
        active: &ActiveContext,
        value: &CborValue,
        depth: usize,
    ) -> Result<Value, CborldError> {
        if depth > self.limits.max_depth {
            return Err(depth_error(&self.limits, depth));
        }
        if let CborValue::Map(entries) = value {
            return Ok(Value::Object(self.decode_node(
                entries,
                active,
                depth + 1,
            )?));
        }
        if let CborValue::Null = value {
            return Ok(Value::Null);
        }
        let strategy = table_type(term, def);
        if let Some(decoded) = self.decode_from_sub_table(&strategy, value)? {
            return Ok(decoded);
        }
        match strategy {
            TableType::Url => self.decode_url(term, def, active, value, depth),
            TableType::Typed(XSD_DATE_IRI) => match value {
                CborValue::Unsigned(_) | CborValue::Negative(_) => {
                    let seconds = int_value(value)?;
                    format_xsd_date(seconds).map(Value::String).ok_or_else(|| {
                        CborldError::NumberRange(format!(
                            "xsd:date seconds {seconds} fall outside years 0000-9999"
                        ))
                    })
                }
                other => self.decode_plain(term, def, active, other, depth),
            },
            TableType::Typed(XSD_DATE_TIME_IRI) => {
                self.decode_datetime(term, def, active, value, depth)
            }
            TableType::Typed(MULTIBASE_IRI) => match value {
                CborValue::Bytes(bytes) => self.decode_multibase(bytes),
                other => self.decode_plain(term, def, active, other, depth),
            },
            TableType::Typed(_) | TableType::None => {
                self.decode_plain(term, def, active, value, depth)
            }
        }
    }

    /// Decodes a value with no applicable codec (passthrough semantics).
    fn decode_plain(
        &mut self,
        term: &str,
        def: Option<&TermDef>,
        active: &ActiveContext,
        value: &CborValue,
        depth: usize,
    ) -> Result<Value, CborldError> {
        match value {
            CborValue::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.decode_value(term, def, active, item, depth + 1)?);
                }
                Ok(Value::Array(out))
            }
            other => cbor_to_json(other, &self.limits, depth),
        }
    }

    fn decode_url(
        &mut self,
        term: &str,
        def: Option<&TermDef>,
        active: &ActiveContext,
        value: &CborValue,
        depth: usize,
    ) -> Result<Value, CborldError> {
        match value {
            CborValue::Unsigned(id) => {
                let term = self
                    .registry
                    .term_of(*id)
                    .ok_or(CborldError::UnknownTermId { id: *id })?;
                self.charge(term.len())?;
                Ok(Value::String(term.to_string()))
            }
            CborValue::Text(text) => Ok(Value::String(text.clone())),
            CborValue::Array(items) => match items.first() {
                Some(CborValue::Unsigned(prefix_id)) => {
                    let decoded = self.decode_url_array(*prefix_id, items)?;
                    self.charge(decoded.as_str().map_or(0, str::len))?;
                    Ok(decoded)
                }
                _ => self.decode_plain(term, def, active, value, depth),
            },
            other => Err(CborldError::Envelope(format!(
                "unexpected {} for URL-typed value of term {term}",
                cbor_kind(other)
            ))),
        }
    }

    fn decode_url_array(&self, prefix_id: u64, items: &[CborValue]) -> Result<Value, CborldError> {
        if prefix_id == URL_PREFIX_HTTP.1 || prefix_id == URL_PREFIX_HTTPS.1 {
            let prefix = if prefix_id == URL_PREFIX_HTTP.1 {
                URL_PREFIX_HTTP.0
            } else {
                URL_PREFIX_HTTPS.0
            };
            if let [_, CborValue::Text(rest)] = items {
                return Ok(Value::String(format!("{prefix}{rest}")));
            }
            return Err(CborldError::Envelope(
                "http(s) URL codec expects [prefix, text]".to_string(),
            ));
        }
        if prefix_id == URL_PREFIX_URN_UUID.1 {
            return match items {
                [_, CborValue::Bytes(bytes)] => {
                    let bytes: &[u8; 16] = bytes.as_slice().try_into().map_err(|_size| {
                        CborldError::Envelope(format!(
                            "urn:uuid: codec expects 16 bytes, found {}",
                            bytes.len()
                        ))
                    })?;
                    Ok(Value::String(format!("urn:uuid:{}", format_uuid(bytes))))
                }
                [_, CborValue::Text(rest)] => Ok(Value::String(format!("urn:uuid:{rest}"))),
                _ => Err(CborldError::Envelope(
                    "urn:uuid: codec expects [3, bytes-or-text]".to_string(),
                )),
            };
        }
        if prefix_id == URL_PREFIX_DATA.1 {
            return match items {
                [_, CborValue::Text(rest)] => Ok(Value::String(format!("data:{rest}"))),
                [_, CborValue::Text(mediatype), CborValue::Bytes(bytes)] => {
                    self.check_value_bytes(bytes.len())?;
                    Ok(Value::String(format!(
                        "data:{mediatype};base64,{}",
                        base64pad_encode(bytes)
                    )))
                }
                _ => Err(CborldError::Envelope(
                    "data: codec expects [4, text] or [4, mediatype-text, bytes]".to_string(),
                )),
            };
        }
        for (prefix, id) in DID_URL_PREFIXES {
            if prefix_id != id {
                continue;
            }
            return match items {
                [_, head] => Ok(Value::String(format!(
                    "{prefix}{}",
                    self.decode_did_segment(head)?
                ))),
                [_, head, fragment] => Ok(Value::String(format!(
                    "{prefix}{}#{}",
                    self.decode_did_segment(head)?,
                    self.decode_did_segment(fragment)?
                ))),
                _ => Err(CborldError::Envelope(format!(
                    "{prefix} codec expects [prefix, segment] or [prefix, segment, fragment]"
                ))),
            };
        }
        Err(CborldError::Envelope(format!(
            "unknown URL prefix identifier {prefix_id}"
        )))
    }

    /// Reconstructs one DID URL segment: bytes are canonical base58btc
    /// multibase (`z` header restored), text passes through verbatim.
    fn decode_did_segment(&self, segment: &CborValue) -> Result<String, CborldError> {
        match segment {
            CborValue::Text(text) => Ok(text.clone()),
            CborValue::Bytes(bytes) => {
                self.check_value_bytes(bytes.len())?;
                self.charge_base58(bytes.len())?;
                Ok(format!("z{}", base58btc_encode(bytes)))
            }
            other => Err(CborldError::Envelope(format!(
                "did: codec segment must be a text or byte string, found {}",
                cbor_kind(other)
            ))),
        }
    }

    /// Reconstructs one multibase value from `[header, decoded bytes...]`.
    ///
    /// Only the vendored headers `z` (base58btc) and `u` (base64url, no
    /// padding) decode; any other header is a typed error, never a guess.
    fn decode_multibase(&self, bytes: &[u8]) -> Result<Value, CborldError> {
        self.check_value_bytes(bytes.len())?;
        let [header, body @ ..] = bytes else {
            return Err(CborldError::Envelope(
                "multibase byte string must carry a header byte".to_string(),
            ));
        };
        match *header {
            MULTIBASE_BASE58BTC_HEADER => {
                self.charge_base58(body.len())?;
                Ok(Value::String(format!("z{}", base58btc_encode(body))))
            }
            MULTIBASE_BASE64URL_HEADER => {
                self.charge(body.len().div_ceil(3).saturating_mul(4))?;
                Ok(Value::String(format!("u{}", base64url_nopad_encode(body))))
            }
            other => Err(CborldError::Unsupported(format!(
                "multibase header {other:#04x} is outside the vendored subset (z, u)"
            ))),
        }
    }

    /// Enforces the fail-closed byte budget for one value codec payload.
    fn check_value_bytes(&self, observed: usize) -> Result<(), CborldError> {
        if observed > self.limits.max_value_bytes {
            return Err(CborldError::ResourceLimit {
                resource: CborldResource::ValueBytes,
                limit: self.limits.max_value_bytes,
                observed,
            });
        }
        Ok(())
    }

    fn decode_datetime(
        &mut self,
        term: &str,
        def: Option<&TermDef>,
        active: &ActiveContext,
        value: &CborValue,
        depth: usize,
    ) -> Result<Value, CborldError> {
        match value {
            CborValue::Unsigned(_) | CborValue::Negative(_) => {
                let seconds = int_value(value)?;
                format_xsd_datetime_seconds(seconds)
                    .map(Value::String)
                    .ok_or_else(|| {
                        CborldError::NumberRange(format!(
                            "xsd:dateTime seconds {seconds} fall outside years 0000-9999"
                        ))
                    })
            }
            CborValue::Array(items) => match items.as_slice() {
                [
                    seconds @ (CborValue::Unsigned(_) | CborValue::Negative(_)),
                    CborValue::Unsigned(millis),
                ] => {
                    // The millisecond field is a fraction of the adjacent second,
                    // so only 0..=999 is well formed. Folding a larger value into
                    // `total` would silently re-attribute it to the seconds field
                    // (e.g. `[0, 5000]` reading back as 00:00:05Z), which is the
                    // lenient coercion this codec refuses: decode fails closed on
                    // input the encoder can never produce.
                    if *millis > 999 {
                        return Err(CborldError::NumberRange(format!(
                            "xsd:dateTime millisecond field {millis} is not in 0..=999"
                        )));
                    }
                    let total = i128::from(int_value(seconds)?) * 1000 + i128::from(*millis);
                    format_xsd_datetime_millis(total)
                        .map(Value::String)
                        .ok_or_else(|| {
                            CborldError::NumberRange(format!(
                                "xsd:dateTime instant {total} ms falls outside years 0000-9999"
                            ))
                        })
                }
                _ => self.decode_plain(term, def, active, value, depth),
            },
            other => self.decode_plain(term, def, active, other, depth),
        }
    }
}

fn int_value(value: &CborValue) -> Result<i64, CborldError> {
    match value {
        CborValue::Unsigned(unsigned) => i64::try_from(*unsigned).map_err(|_overflow| {
            CborldError::NumberRange(format!("integer {unsigned} overflows i64 seconds"))
        }),
        CborValue::Negative(magnitude) => negative_to_i64(*magnitude),
        _ => Err(CborldError::Envelope(
            "expected an integer item".to_string(),
        )),
    }
}

fn cbor_kind(value: &CborValue) -> &'static str {
    match value {
        CborValue::Unsigned(_) => "unsigned integer",
        CborValue::Negative(_) => "negative integer",
        CborValue::Bytes(_) => "byte string",
        CborValue::Text(_) => "text string",
        CborValue::Array(_) => "array",
        CborValue::Map(_) => "map",
        CborValue::Tag(..) => "tag",
        CborValue::Bool(_) => "boolean",
        CborValue::Null => "null",
        CborValue::Float(_) => "float",
    }
}

/// Compresses a JSON-LD document with inline contexts into CBOR-LD bytes.
///
/// `options.mode` selects the registry entry. In
/// [`CompressionMode::Compressed`] (entry 1) and under any other
/// semantically compressing entry, the document must be a JSON object; its
/// inline `@context` objects drive deterministic term-map construction, the
/// selected entry's sub-tables compress listed contexts and values, and the
/// payload is wrapped as `tag(0xCB1D, [entryId, payload])`. In
/// [`CompressionMode::Uncompressed`] (entry 0) any JSON document is embedded
/// as plain CBOR. The output is unsigned by construction.
///
/// # Errors
///
/// Returns [`CborldError::UnknownRegistryEntry`] for an identifier outside
/// the vendored registry, [`CborldError::ProvisionalRegistryEntry`] for a
/// provisional entry absent from `options.accepted_provisional_entries`,
/// [`CborldError::UnregisteredContext`] for registered context IRIs whose
/// content is not in `options.provided_contexts` (never fetched),
/// [`CborldError::Unsupported`] for spec features outside the vendored
/// subset, [`CborldError::Document`] for documents outside the accepted
/// shapes, [`CborldError::NumberRange`] for numbers with no exact CBOR
/// form, and [`CborldError::ResourceLimit`] when a depth budget is
/// exceeded.
pub fn compress(document: &Value, options: &CborldOptions) -> Result<Vec<u8>, CborldError> {
    let entry = resolve_registry_entry(
        options.mode.registry_entry_id(),
        &options.accepted_provisional_entries,
    )?;
    let payload = if entry.uses_semantic_compression() {
        let Value::Object(object) = document else {
            return Err(CborldError::Document(format!(
                "compressed CBOR-LD requires a JSON object document, found {}",
                json_kind(document)
            )));
        };
        let mut compressor = Compressor {
            registry: TermIdRegistry::new(),
            limits: options.limits,
            provided: &options.provided_contexts,
            entry,
        };
        compressor.convert_node(object, &ActiveContext::default(), 1)?
    } else {
        json_to_cbor(document, &options.limits, 1)?
    };
    let envelope = CborValue::Tag(
        CBORLD_TAG,
        Box::new(CborValue::Array(vec![
            CborValue::Unsigned(entry.id),
            payload,
        ])),
    );
    cbor::encode_canonical(&envelope, &options.limits)
}

/// Decompresses CBOR-LD bytes back into a JSON-LD document.
///
/// Accepts envelopes `tag(0xCB1D, [id, payload])` for every vendored
/// registry entry; `id` comes from the envelope itself, not from
/// `options.mode`. The entry's sub-tables resolve compressed context and
/// value identifiers, and the term map is rebuilt deterministically from
/// the embedded inline contexts plus the caller-supplied content for
/// registered context IRIs (never fetched; the same content must be
/// supplied on both sides).
///
/// # Errors
///
/// Returns [`CborldError::ResourceLimit`] and [`CborldError::Decode`] for
/// oversized or malformed CBOR, [`CborldError::ResourceLimit`] for
/// `output_bytes` when expanding identifiers, codec values, or applied
/// contexts would exceed `limits.max_output_bytes`,
/// [`CborldError::Envelope`] for payloads that
/// are not the vendored envelope shape,
/// [`CborldError::UnknownRegistryEntry`] for an identifier outside the
/// vendored registry, [`CborldError::ProvisionalRegistryEntry`] for a
/// provisional entry absent from `options.accepted_provisional_entries`,
/// [`CborldError::UnregisteredContext`] for context IRIs without content in
/// `options.provided_contexts`, [`CborldError::UnknownCompressedContext`]
/// and [`CborldError::UnknownCompressedValue`] for identifiers the selected
/// entry's tables do not define, [`CborldError::UnknownTermId`] for
/// undefined compressed term ids, and [`CborldError::Unsupported`] for
/// compressed forms whose codec is outside the vendored subset.
pub fn decompress(bytes: &[u8], options: &CborldOptions) -> Result<Value, CborldError> {
    let decoded = cbor::decode(bytes, &options.limits)?;
    let CborValue::Tag(tag, inner) = decoded else {
        return Err(CborldError::Envelope(
            "expected a CBOR-LD envelope tagged 51997 (0xcb1d)".to_string(),
        ));
    };
    if tag != CBORLD_TAG {
        return Err(CborldError::Envelope(format!(
            "expected CBOR-LD tag 51997 (0xcb1d), found tag {tag}"
        )));
    }
    let CborValue::Array(elements) = inner.as_ref() else {
        return Err(CborldError::Envelope(
            "tagged item must be a two-element array".to_string(),
        ));
    };
    let [CborValue::Unsigned(entry), payload] = elements.as_slice() else {
        return Err(CborldError::Envelope(
            "tagged array must be [unsigned registry entry id, payload]".to_string(),
        ));
    };
    let entry = resolve_registry_entry(*entry, &options.accepted_provisional_entries)?;
    if !entry.uses_semantic_compression() {
        return cbor_to_json(payload, &options.limits, 1);
    }
    let CborValue::Map(entries) = payload else {
        return Err(CborldError::Envelope(format!(
            "compressed payload must be a map, found {}",
            cbor_kind(payload)
        )));
    };
    let mut decompressor = Decompressor {
        registry: TermIdRegistry::new(),
        limits: options.limits,
        provided: &options.provided_contexts,
        entry,
        output_spent: Cell::new(0),
    };
    let object = decompressor.decode_node(entries, &ActiveContext::default(), 1)?;
    Ok(Value::Object(object))
}
