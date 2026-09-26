// Rust guideline compliant 2026-02-21
//! Vendored normative constants from the CBOR-LD 1.0 specification.
//!
//! Provenance (wire formats are vendored, never recalled):
//!
//! - Specification: "CBOR-LD 1.0" W3C Editor's Draft,
//!   <https://w3c.github.io/cbor-ld/>, retrieved 2026-08-31, repository
//!   `w3c/cbor-ld` at commit `9e1bea64a3b81c6b98a19c6374ea527e6e28a955`
//!   (2026-08-26). Sections vendored: "CBOR Tags for CBOR-LD", "CBOR Tag
//!   Processing", "Initialize Context Loader Algorithm" (JSON-LD keyword
//!   table), "Add Context Algorithm" (term-id assignment start/step),
//!   "URL Prefix Table", "Codec Identifiers" (type bindings of the
//!   default processing model), "Initialize Conversion Algorithm"
//!   (`typesEncodedAsBytes`), the "Context Codec" and "Value Codec"
//!   sections (registry sub-table lookup and its precedence over the
//!   generic codecs, retrieved 2026-09-01), and the value codec sections
//!   "Data URL Codec", "DID URL Codec", and "Multibase Codec" (compressed
//!   shapes and multibase headers).
//! - Registry: "The CBOR-LD Registry",
//!   <https://json-ld.github.io/cborld-registry/>, retrieved 2026-09-01,
//!   repository `json-ld/cborld-registry` at commit
//!   `c7ece75bae6ef40c23e19ce111b5c51f3cf38950` (2026-07-30). All nine
//!   `tables/*.yml` entries are vendored verbatim under
//!   `vendor/cborld-registry/` and transcribed into [`REGISTRY_ENTRIES`];
//!   see `vendor/cborld-registry/PROVENANCE.md`.

#[doc(inline)]
pub use crate::registry_tables::REGISTRY_ENTRIES;

/// CBOR tag `0xCB1D` (51997) marking a CBOR-LD envelope.
///
/// The tagged item is a two-element array `[registryEntryId, payload]`.
pub const CBORLD_TAG: u64 = 0xCB1D;

/// Registry entry 0: uncompressed CBOR-LD (payload is plain CBOR).
pub const REGISTRY_ENTRY_UNCOMPRESSED: u64 = 0;

/// Registry entry 1: compressed CBOR-LD, default processing model.
pub const REGISTRY_ENTRY_COMPRESSED: u64 = 1;

/// First term identifier assigned to context-defined terms.
pub const FIRST_CUSTOM_TERM_ID: u64 = 100;

/// Distance between consecutive term identifiers (odd ids mark plurals).
pub const TERM_ID_STEP: u64 = 2;

/// JSON-LD keyword table from the Initialize Context Loader Algorithm.
///
/// Every keyword maps to an even integer; `id + 1` marks an array-valued
/// ("plural") use of the same keyword.
pub const KEYWORD_TERM_IDS: [(&str, u64); 28] = [
    ("@context", 0),
    ("@type", 2),
    ("@id", 4),
    ("@value", 6),
    ("@direction", 8),
    ("@graph", 10),
    ("@included", 12),
    ("@index", 14),
    ("@json", 16),
    ("@language", 18),
    ("@list", 20),
    ("@nest", 22),
    ("@reverse", 24),
    ("@base", 26),
    ("@container", 28),
    ("@default", 30),
    ("@embed", 32),
    ("@explicit", 34),
    ("@none", 36),
    ("@omitDefault", 38),
    ("@prefix", 40),
    ("@preserve", 42),
    ("@protected", 44),
    ("@requireAll", 46),
    ("@set", 48),
    ("@version", 50),
    ("@vocab", 52),
    ("@propagate", 54),
];

/// URL Prefix Table entry: `http://` compresses to integer 1.
pub const URL_PREFIX_HTTP: (&str, u64) = ("http://", 1);

/// URL Prefix Table entry: `https://` compresses to integer 2.
pub const URL_PREFIX_HTTPS: (&str, u64) = ("https://", 2);

/// URL Prefix Table entry: `urn:uuid:` compresses to integer 3.
pub const URL_PREFIX_URN_UUID: (&str, u64) = ("urn:uuid:", 3);

/// URL Prefix Table entry: `data:` compresses to integer 4.
pub const URL_PREFIX_DATA: (&str, u64) = ("data:", 4);

/// URL Prefix Table entry: `did:v1:nym:` compresses to integer 1024.
pub const URL_PREFIX_DID_V1_NYM: (&str, u64) = ("did:v1:nym:", 1024);

/// URL Prefix Table entry: `did:key:` compresses to integer 1025.
pub const URL_PREFIX_DID_KEY: (&str, u64) = ("did:key:", 1025);

/// JSON-LD type bound to the XSD Date Codec in the default processing model.
pub const XSD_DATE_IRI: &str = "http://www.w3.org/2001/XMLSchema#date";

/// JSON-LD type bound to the XSD DateTime Codec in the default model.
pub const XSD_DATE_TIME_IRI: &str = "http://www.w3.org/2001/XMLSchema#dateTime";

/// JSON-LD type bound to the Multibase Codec in the default model.
pub const MULTIBASE_IRI: &str = "https://w3id.org/security#multibase";

/// Base58btc alphabet used by the DID URL and Multibase codecs.
///
/// Provenance: the "base58btc" encoding referenced normatively by the
/// vendored "Multibase Codec" and "DID URL Codec" sections (same draft and
/// commit as above); alphabet as listed in the multiformats multibase
/// registry (`multiformats/multibase`, row `base58btc`, header `z`).
pub const BASE58_BTC_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Multibase header byte for base58btc (`z`), from the Multibase Codec.
pub const MULTIBASE_BASE58BTC_HEADER: u8 = b'z';

/// Multibase header byte for base64url without padding (`u`), from the
/// Multibase Codec.
pub const MULTIBASE_BASE64URL_HEADER: u8 = b'u';

/// Reserved sub-table type applying to `@context` values.
pub const TABLE_TYPE_CONTEXT: &str = "context";

/// Reserved sub-table type applying to `@id`-typed URL values.
pub const TABLE_TYPE_URL: &str = "url";

/// Sub-table type standing for "the term carries no JSON-LD type".
pub const TABLE_TYPE_NONE: &str = "none";

/// Processing model this codec implements; the only one it accepts.
pub const PROCESSING_MODEL_DEFAULT: &str = "default";

/// Table types whose sub-table identifiers ride the wire as byte strings.
///
/// Vendored from the "Initialize Conversion Algorithm"
/// (`state.typesEncodedAsBytes`). The distinction is load-bearing: in an
/// `@id`/`@type` position an unsigned integer is an auto-generated term
/// identifier, so a `url` sub-table identifier must take the byte-string
/// form to stay unambiguous.
pub const TYPES_ENCODED_AS_BYTES: [&str; 4] = [
    TABLE_TYPE_NONE,
    XSD_DATE_IRI,
    XSD_DATE_TIME_IRI,
    TABLE_TYPE_URL,
];

/// Returns whether sub-table identifiers of `table_type` are byte strings.
#[must_use]
pub fn is_encoded_as_bytes(table_type: &str) -> bool {
    TYPES_ENCODED_AS_BYTES.contains(&table_type)
}

/// One typed compression sub-table of a CBOR-LD registry entry.
///
/// A registry entry identifier does not name a single context: it selects a
/// whole set of these sub-tables, each keyed by a [`SubTable::table_type`]
/// and each mapping small integers to values of that type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubTable {
    /// Table type: [`TABLE_TYPE_CONTEXT`], [`TABLE_TYPE_URL`], or a
    /// JSON-LD type IRI, verbatim from the registry's `type` field.
    pub table_type: &'static str,
    /// Identifier-to-value pairs, ascending by identifier.
    pub entries: &'static [(u64, &'static str)],
}

impl SubTable {
    /// Returns the identifier this sub-table assigns to `value`, if any.
    #[must_use]
    pub fn id_of(&self, value: &str) -> Option<u64> {
        self.entries
            .iter()
            .find(|(_, candidate)| *candidate == value)
            .map(|(id, _)| *id)
    }

    /// Returns the value this sub-table assigns to `id`, if any.
    #[must_use]
    pub fn value_of(&self, id: u64) -> Option<&'static str> {
        self.entries
            .binary_search_by_key(&id, |(candidate, _)| *candidate)
            .ok()
            .map(|index| self.entries[index].1)
    }
}

/// One entry of the CBOR-LD registry, transcribed from vendored YAML.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryEntry {
    /// Registry entry identifier carried in the CBOR-LD envelope.
    pub id: u64,
    /// Use case, from the registry's `domain` field.
    pub domain: &'static str,
    /// Processing model, from the registry's `mode` field.
    pub mode: &'static str,
    /// Whether upstream marks this entry as subject to change or removal.
    pub provisional: bool,
    /// Typed compression sub-tables selected by this entry.
    pub sub_tables: &'static [SubTable],
}

impl RegistryEntry {
    /// Returns this entry's sub-table for `table_type`, if it has one.
    #[must_use]
    pub fn sub_table(&self, table_type: &str) -> Option<&'static SubTable> {
        self.sub_tables
            .iter()
            .find(|table| table.table_type == table_type)
    }

    /// Returns whether this entry applies the default processing model.
    #[must_use]
    pub fn uses_default_processing_model(&self) -> bool {
        self.mode == PROCESSING_MODEL_DEFAULT
    }

    /// Returns whether this entry applies semantic compression.
    ///
    /// Entry 0 is the uncompressed mode: its payload is plain CBOR. Every
    /// other vendored entry uses the default processing model, in which
    /// semantic compression is enabled.
    #[must_use]
    pub fn uses_semantic_compression(&self) -> bool {
        self.id != REGISTRY_ENTRY_UNCOMPRESSED
    }
}

/// Returns the vendored registry entry with identifier `id`, if any.
///
/// An identifier absent from this lookup is not vendored: the codec refuses
/// it rather than guessing a compression table for it.
#[must_use]
pub fn registry_entry(id: u64) -> Option<&'static RegistryEntry> {
    REGISTRY_ENTRIES.iter().find(|entry| entry.id == id)
}
