// Rust guideline compliant 2026-02-21
//! CBOR-LD 1.0 codec for JSON-LD documents with inline contexts.
//!
//! This crate implements node N5 of the semantic dataplane: a deterministic
//! CBOR-LD 1.0 compressor and decompressor built on a hand-rolled, minimal
//! CBOR subset (definite lengths only, fail closed on everything else). It
//! deliberately takes no external CBOR dependency.
//!
//! # Scope
//!
//! Supported: the CBOR-LD envelope `tag(0xCB1D, [registryEntryId, payload])`
//! for **all nine registry entries vendored from the pinned upstream
//! commit** — 0 (uncompressed), 1 (compressed), 100, 10001, 10002, 10003,
//! 31000000, 31000001, and 32000000, each under the default processing
//! model; deterministic term maps built from inline `@context` objects
//! (terms sorted into Unicode code point order, consecutive even identifiers
//! from 100); registered context IRIs resolved against caller-supplied
//! content ([`ProvidedContexts`], never fetched); the vendored JSON-LD
//! keyword table; plural (odd) term identifiers for array values; the URL
//! codec for `@id`/`@type` positions (`http://`, `https://`, and `urn:uuid:`
//! prefixes plus term-id substitution, the `data:` URL codec, and the base58
//! DID URL codec for `did:key:`/`did:v1:nym:`); the multibase codec (`z`,
//! `u`) for `sec:multibase`-typed values; the `xsd:date` / `xsd:dateTime`
//! codecs; and RFC 8949 preferred (shortest exact) float serialization.
//!
//! # Registry entries select table *sets*, not contexts
//!
//! A registry entry identifier does not name one context IRI. It selects an
//! entire set of typed compression sub-tables (see
//! [`registry::RegistryEntry`]), each keyed by a table type — `context`,
//! `url`, or a JSON-LD type IRI such as
//! `https://w3id.org/security#cryptosuiteString` — and each mapping small
//! integers to values of that type. Entry 100, for example, carries a
//! `context` table numbering three IRIs from 32768 and a cryptosuite table
//! numbering four strings from 1. Identifiers are meaningful only inside one
//! entry: 32768 names the VC v2 context under entry 100 and nothing at all
//! under entry 10001, which numbers its own context table from 1.
//!
//! Sub-table lookup runs ahead of the generic codecs, so a value the
//! selected entry lists wins over prefix compression. Following the
//! specification's `typesEncodedAsBytes` set, `url` identifiers ride the
//! wire as byte strings — in an `@id` position an unsigned integer already
//! means an auto-generated term identifier — while `context` and typed
//! identifiers ride as unsigned integers.
//!
//! A registry entry supplies the IRI-to-integer mapping and **never the
//! context document**. Compressing or decompressing a registered context
//! still requires the caller to supply its content through
//! [`ProvidedContexts`]; the sovereign no-network boundary is unchanged.
//!
//! # Provisional registry entries are opt-in
//!
//! Entries 0 and 1 are the reserved, non-provisional default modes owned by
//! the W3C JSON-LD Working Group and carry no compression table. **Every
//! other entry is marked `provisional: true` upstream**, meaning it may
//! change or be removed. This crate therefore refuses a provisional entry
//! unless the caller names it in
//! [`CborldOptions::accepted_provisional_entries`], on both [`compress`] and
//! [`decompress`], failing with [`CborldError::ProvisionalRegistryEntry`]
//! otherwise.
//!
//! The reasoning is the one that motivates the rest of this codec. A
//! vendored snapshot of a mutable table is a silent-corruption hazard: a
//! payload compressed against one snapshot and decompressed against a later
//! one yields *different IRIs with no error at all*, because each side
//! considers its own table authoritative. That is exactly the failure mode a
//! fail-closed codec exists to prevent, and unlike a malformed payload it
//! cannot be detected after the fact. Making acceptance explicit — and
//! per-identifier, rather than one global "trust provisional entries" switch
//! — means the risk is taken deliberately, is recorded at the call site, and
//! is greppable. Whichever entries a caller opts into, an identifier that is
//! not vendored remains [`CborldError::UnknownRegistryEntry`].
//!
//! # Refusals
//!
//! Refused with explicit typed errors (never fetched, never guessed):
//! context IRIs without caller-provided content
//! ([`CborldError::UnregisteredContext`]), chained registered-context
//! references inside provided content, registry entry identifiers outside
//! the vendored nine ([`CborldError::UnknownRegistryEntry`]), vendored
//! provisional entries without an explicit opt-in
//! ([`CborldError::ProvisionalRegistryEntry`]), compressed context
//! identifiers absent from the selected entry's `context` table
//! ([`CborldError::UnknownCompressedContext`]), sub-table identifiers absent
//! from the selected entry's table for that type — including one replayed
//! from a different entry or presented in the wrong sub-table
//! ([`CborldError::UnknownCompressedValue`]), non-shortest or oversized
//! sub-table identifier encodings, `@import`, scoped contexts,
//! `@context: null`, multibase headers other than `z`/`u`, and value codec
//! payloads beyond the configured byte budget on decode. See [`compress`]
//! and [`decompress`] for the per-call error surface.
//!
//! Registry data is vendored, never recalled: the nine entries live under
//! `vendor/cborld-registry/` exactly as published, with their provenance in
//! `vendor/cborld-registry/PROVENANCE.md`, and are transcribed into
//! [`registry::REGISTRY_ENTRIES`] by a vendor-time script whose output is
//! checked against that YAML by `tests/registry_tables.rs`.
//!
//! # Dataplane invariants
//!
//! Codec output is **unsigned by construction**: compression preserves the
//! document byte-for-byte semantics but never certifies, approves, or
//! promotes its content. The codec performs
//! **no network I/O**: spec constants are vendored at authoring time (see
//! [`registry`]) and remote or unresolvable contexts are explicit errors;
//! registered context content comes only from the caller.
//!
//! # Round-trip guarantee
//!
//! For every document accepted by [`compress`],
//! `decompress(compress(doc)) == doc` under semantic JSON equality.
//!
//! # Examples
//!
//! ```
//! use cborld_fast_core::{CborldOptions, compress, decompress};
//! use serde_json::json;
//!
//! # fn main() -> Result<(), cborld_fast_core::CborldError> {
//! let doc = json!({
//!     "@context": {"name": "http://schema.org/name"},
//!     "name": "Example"
//! });
//! let options = CborldOptions::default();
//! let bytes = compress(&doc, &options)?;
//! assert_eq!(decompress(&bytes, &options)?, doc);
//! # Ok(())
//! # }
//! ```
//!
//! Selecting a provisional registry entry requires naming it, and supplying
//! the content of any context it compresses:
//!
//! ```
//! use cborld_fast_core::{
//!     CborldOptions, CompressionMode, ProvidedContexts, ProvisionalEntries,
//!     compress, decompress,
//! };
//! use serde_json::json;
//!
//! # fn main() -> Result<(), cborld_fast_core::CborldError> {
//! let iri = "https://www.w3.org/ns/credentials/v2";
//! let mut provided = ProvidedContexts::new();
//! provided.insert(iri, json!({"name": "https://example.org/vocab#name"}));
//!
//! let mut accepted = ProvisionalEntries::new();
//! accepted.accept(100);
//!
//! let options = CborldOptions {
//!     mode: CompressionMode::RegistryEntry(100),
//!     provided_contexts: provided,
//!     accepted_provisional_entries: accepted,
//!     ..CborldOptions::default()
//! };
//!
//! let doc = json!({"@context": iri, "name": "Example"});
//! let bytes = compress(&doc, &options)?;
//! assert_eq!(decompress(&bytes, &options)?, doc);
//!
//! // Without the opt-in the same call is refused, not silently trusted.
//! let strict = CborldOptions {
//!     mode: CompressionMode::RegistryEntry(100),
//!     ..CborldOptions::default()
//! };
//! assert_eq!(
//!     compress(&doc, &strict).unwrap_err().code(),
//!     "provisional_registry_entry"
//! );
//! # Ok(())
//! # }
//! ```

pub mod cbor;
mod codec;
mod context;
mod error;
pub mod registry;
mod registry_tables;
mod table_codec;
mod value_codec;

#[doc(inline)]
pub use codec::{
    CborldOptions, CompressionMode, ProvidedContexts, ProvisionalEntries, compress, decompress,
};
#[doc(inline)]
pub use error::{CborldError, CborldResource};
