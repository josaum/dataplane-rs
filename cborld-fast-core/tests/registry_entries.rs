// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Compression through registry-selected tables, and its fail-closed edges.
//!
//! Every test names the CBOR-LD registry entry it exercises. The entries
//! themselves come from `vendor/cborld-registry/`, pinned to
//! `json-ld/cborld-registry` commit
//! `c7ece75bae6ef40c23e19ce111b5c51f3cf38950`.
//!
//! Context *documents* are test-local stand-ins. The registry maps a context
//! IRI to an integer and nothing more, so the codec still requires the
//! caller to supply the content under that IRI; supplying a realistic-looking
//! copy of a real context here would be recalling a wire format, which the
//! project forbids. What these tests prove is the mapping and the envelope,
//! not the contents of anyone's published context.

use cborld_fast_core::{
    CborldOptions, CompressionMode, ProvidedContexts, ProvisionalEntries,
    cbor::{CborLimits, CborValue, decode, encode_canonical},
    compress, decompress,
    registry::{CBORLD_TAG, REGISTRY_ENTRIES, TABLE_TYPE_CONTEXT, TABLE_TYPE_URL, registry_entry},
};
use serde_json::{Value, json};

const CRYPTOSUITE: &str = "https://w3id.org/security#cryptosuiteString";

/// A test-local context document; see the module note on why it is a
/// stand-in rather than a copy of any published context.
fn stand_in_context() -> Value {
    json!({
        "@context": {
            "name": "https://example.invalid/vocab#name",
            "issuer": {"@id": "https://example.invalid/vocab#issuer", "@type": "@id"},
            "cryptosuite": {"@id": "https://example.invalid/vocab#cryptosuite", "@type": CRYPTOSUITE},
        }
    })
}

/// Options for `entry`, with every context IRI it can name pre-supplied.
fn options_for(entry_id: u64) -> CborldOptions {
    let mut provided = ProvidedContexts::new();
    for entry in &REGISTRY_ENTRIES {
        let Some(table) = entry.sub_table(TABLE_TYPE_CONTEXT) else {
            continue;
        };
        for (_, iri) in table.entries {
            provided.insert(*iri, stand_in_context());
        }
    }
    let mut accepted = ProvisionalEntries::new();
    accepted.accept(entry_id);
    CborldOptions {
        mode: CompressionMode::RegistryEntry(entry_id),
        provided_contexts: provided,
        accepted_provisional_entries: accepted,
        ..CborldOptions::default()
    }
}

/// Compresses and decompresses `document`, asserting an exact round-trip.
fn roundtrip(document: &Value, options: &CborldOptions) -> Vec<u8> {
    let bytes = compress(document, options).expect("compress");
    let decoded = decompress(&bytes, options).expect("decompress");
    assert_eq!(&decoded, document, "round-trip mismatch");
    bytes
}

/// Returns the compressed payload map of one envelope, checking its entry id.
fn payload_entries(bytes: &[u8], entry_id: u64) -> Vec<(CborValue, CborValue)> {
    let value = decode(bytes, &CborLimits::default()).expect("well-formed envelope");
    let CborValue::Tag(CBORLD_TAG, inner) = value else {
        panic!("expected the CBOR-LD tag");
    };
    let CborValue::Array(elements) = *inner else {
        panic!("expected a two-element array");
    };
    assert_eq!(
        elements[0],
        CborValue::Unsigned(entry_id),
        "envelope carries the selected registry entry id"
    );
    let CborValue::Map(entries) = elements[1].clone() else {
        panic!("expected a map payload");
    };
    entries
}

fn entry_value(entries: &[(CborValue, CborValue)], key: u64) -> CborValue {
    entries
        .iter()
        .find(|(candidate, _)| *candidate == CborValue::Unsigned(key))
        .unwrap_or_else(|| panic!("payload has no key {key}"))
        .1
        .clone()
}

/// Builds a raw envelope around `payload` for decode-side tests.
fn envelope(entry_id: u64, payload: CborValue) -> Vec<u8> {
    let value = CborValue::Tag(
        CBORLD_TAG,
        Box::new(CborValue::Array(vec![
            CborValue::Unsigned(entry_id),
            payload,
        ])),
    );
    encode_canonical(&value, &CborLimits::default()).expect("encode")
}

#[test]
fn entry_100_compresses_a_context_iri_to_its_table_identifier() {
    // Registry entry 100 assigns 32768 to the VC v2 context IRI.
    let options = options_for(100);
    let document = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "name": "Example",
    });
    let bytes = roundtrip(&document, &options);
    assert_eq!(
        entry_value(&payload_entries(&bytes, 100), 0),
        CborValue::Unsigned(32_768),
        "entry 100 maps the context IRI to identifier 32768"
    );
}

#[test]
fn entry_10001_compresses_the_same_iri_to_a_different_identifier() {
    // Registry entry 10001 assigns 1 to the same context IRI that entry 100
    // assigns 32768: identifiers are meaningful only inside one entry.
    let options = options_for(10001);
    let document = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "name": "Example",
    });
    let bytes = roundtrip(&document, &options);
    assert_eq!(
        entry_value(&payload_entries(&bytes, 10001), 0),
        CborValue::Unsigned(1),
        "entry 10001 maps the context IRI to identifier 1"
    );
}

#[test]
fn entry_10001_compresses_a_url_table_value_to_a_byte_string() {
    // In an @id position an unsigned integer already means an auto-generated
    // term identifier, so a `url` sub-table identifier takes the byte-string
    // form (`typesEncodedAsBytes` in the spec). Entry 10001 assigns url
    // identifier 1 to this did:key value.
    let options = options_for(10001);
    let did = registry_entry(10001)
        .expect("entry 10001")
        .sub_table(TABLE_TYPE_URL)
        .expect("url table")
        .value_of(1)
        .expect("url identifier 1");
    let document = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "issuer": did,
    });
    let bytes = roundtrip(&document, &options);
    // Terms sort into "cryptosuite", "issuer", "name", so "issuer" is the
    // second custom term identifier: 102.
    let issuer = entry_value(&payload_entries(&bytes, 10001), 102);
    assert_eq!(
        issuer,
        CborValue::Bytes(vec![1]),
        "the url table beats the generic did: codec, and rides as bytes"
    );
}

#[test]
fn entry_10001_falls_through_to_the_generic_did_codec_off_table() {
    // A did: URL the entry's url table does not list must still compress,
    // through the vendored Base58 DID URL codec, and still round-trip.
    let options = options_for(10001);
    let document = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "issuer": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    });
    let bytes = roundtrip(&document, &options);
    // Terms sort into "cryptosuite", "issuer", "name", so "issuer" is the
    // second custom term identifier: 102.
    let issuer = entry_value(&payload_entries(&bytes, 10001), 102);
    assert!(
        matches!(issuer, CborValue::Array(ref items) if items[0] == CborValue::Unsigned(1025)),
        "off-table did:key values take the generic codec, found {issuer:?}"
    );
}

#[test]
fn entry_100_compresses_a_cryptosuite_string_to_an_unsigned_identifier() {
    // Entry 100's `https://w3id.org/security#cryptosuiteString` sub-table
    // assigns 2 to "ecdsa-sd-2023". That table type is not encoded as bytes,
    // so the identifier rides as an unsigned integer.
    let options = options_for(100);
    let document = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "cryptosuite": "ecdsa-sd-2023",
    });
    let bytes = roundtrip(&document, &options);
    assert_eq!(
        entry_value(&payload_entries(&bytes, 100), 100),
        CborValue::Unsigned(2),
        "entry 100 maps ecdsa-sd-2023 to identifier 2"
    );
}

#[test]
fn off_table_typed_strings_pass_through_verbatim() {
    // Entry 10003's cryptosuiteString table lists only ecdsa-rdfc-2019.
    let options = options_for(10003);
    let document = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "cryptosuite": "bbs-2023",
    });
    let bytes = roundtrip(&document, &options);
    assert_eq!(
        entry_value(&payload_entries(&bytes, 10003), 100),
        CborValue::Text("bbs-2023".to_string()),
        "a value the sub-table does not list is carried verbatim"
    );
}

#[test]
fn integers_under_a_table_backed_term_stay_distinct_from_identifiers() {
    // Under entry 100, an unsigned integer in a cryptosuiteString position
    // means "sub-table identifier". A literal integer value therefore takes
    // the signed byte-string form, so the two can never be confused.
    let options = options_for(100);
    let document = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "cryptosuite": 2,
    });
    let bytes = roundtrip(&document, &options);
    assert_eq!(
        entry_value(&payload_entries(&bytes, 100), 100),
        CborValue::Bytes(vec![2]),
        "a literal 2 must not encode like sub-table identifier 2"
    );

    let negative = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "cryptosuite": -1,
    });
    let bytes = roundtrip(&negative, &options);
    assert_eq!(
        entry_value(&payload_entries(&bytes, 100), 100),
        CborValue::Bytes(vec![0xFF]),
        "negative literals use the two's-complement form"
    );
}

#[test]
fn every_vendored_entry_round_trips_a_document_through_its_own_tables() {
    // Per-entry coverage: for each of the nine vendored entries, build a
    // document out of that entry's own table values and require an exact
    // round-trip. Entry 0 carries plain CBOR and needs no context.
    for entry in &REGISTRY_ENTRIES {
        let options = options_for(entry.id);
        if !entry.uses_semantic_compression() {
            roundtrip(&json!({"any": ["plain", "cbor", 1, true, null]}), &options);
            continue;
        }
        let mut document = serde_json::Map::new();
        if let Some(context) = entry.sub_table(TABLE_TYPE_CONTEXT) {
            let (_, iri) = context.entries[0];
            document.insert("@context".to_string(), json!(iri));
        } else {
            document.insert(
                "@context".to_string(),
                stand_in_context()["@context"].clone(),
            );
        }
        document.insert("name".to_string(), json!("Example"));
        if let Some(url) = entry.sub_table(TABLE_TYPE_URL) {
            document.insert("issuer".to_string(), json!(url.entries[0].1));
        }
        if let Some(suite) = entry.sub_table(CRYPTOSUITE) {
            document.insert("cryptosuite".to_string(), json!(suite.entries[0].1));
        }
        let document = Value::Object(document);
        let bytes = roundtrip(&document, &options);
        assert!(
            !payload_entries(&bytes, entry.id).is_empty(),
            "entry {}: payload must not be empty",
            entry.id
        );
    }
}

#[test]
fn provisional_entries_are_refused_without_an_explicit_opt_in() {
    // Entry 100 is marked `provisional: true` upstream, so it is opt-in on
    // both directions rather than silently trusted.
    let mut options = options_for(100);
    options.accepted_provisional_entries = ProvisionalEntries::new();
    let document = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "name": "Example",
    });
    let error = compress(&document, &options).expect_err("compress must refuse");
    assert_eq!(error.code(), "provisional_registry_entry");
    assert!(
        error.to_string().contains("Verifiable Credential Barcodes"),
        "the refusal names the entry's use case, found {error}"
    );

    let bytes = compress(&document, &options_for(100)).expect("compress with opt-in");
    let error = decompress(&bytes, &options).expect_err("decompress must refuse");
    assert_eq!(error.code(), "provisional_registry_entry");
}

#[test]
fn opting_in_to_one_provisional_entry_does_not_admit_another() {
    let bytes = compress(
        &json!({"@context": "https://www.w3.org/ns/credentials/v2", "name": "Example"}),
        &options_for(10001),
    )
    .expect("compress under entry 10001");
    // Accepting 100 says nothing about 10001.
    let error = decompress(&bytes, &options_for(100)).expect_err("must refuse");
    assert_eq!(error.code(), "provisional_registry_entry");
}

#[test]
fn entries_0_and_1_need_no_opt_in() {
    // The two reserved, non-provisional W3C default modes stay usable with
    // default options, unchanged by the registry work.
    let document = json!({"@context": {"name": "http://schema.org/name"}, "name": "Example"});
    let options = CborldOptions::default();
    roundtrip(&document, &options);
    let uncompressed = CborldOptions {
        mode: CompressionMode::Uncompressed,
        ..CborldOptions::default()
    };
    roundtrip(&document, &uncompressed);
    let explicit = CborldOptions {
        mode: CompressionMode::RegistryEntry(1),
        ..CborldOptions::default()
    };
    roundtrip(&document, &explicit);
}

#[test]
fn unvendored_registry_ids_are_refused_on_both_directions() {
    for id in [2, 7, 99, 10004, 31000002, 32000001] {
        let mut options = options_for(id);
        options.mode = CompressionMode::RegistryEntry(id);
        let error = compress(&json!({"name": "Example"}), &options).expect_err("must refuse");
        assert_eq!(
            error.code(),
            "unknown_registry_entry",
            "identifier {id} is not vendored"
        );
        let error =
            decompress(&envelope(id, CborValue::Map(vec![])), &options).expect_err("must refuse");
        assert_eq!(error.code(), "unknown_registry_entry");
    }
}

#[test]
fn context_identifiers_do_not_carry_across_entries() {
    // 32768 is entry 100's identifier for the VC v2 context. Entry 10001
    // numbers its context table from 1, so the same integer must not resolve
    // there to some plausible-looking neighbour.
    let payload = CborValue::Map(vec![(CborValue::Unsigned(0), CborValue::Unsigned(32_768))]);
    let error =
        decompress(&envelope(10001, payload), &options_for(10001)).expect_err("must refuse");
    assert_eq!(error.code(), "unknown_compressed_context");
    assert!(
        error.to_string().contains("registry entry 10001"),
        "the refusal names the entry consulted, found {error}"
    );
}

#[test]
fn url_identifiers_do_not_carry_across_entries() {
    // Entry 31000000's url table runs to 28; entry 32000000's stops at 3.
    let payload = CborValue::Map(vec![
        (CborValue::Unsigned(0), CborValue::Unsigned(1)),
        (CborValue::Unsigned(4), CborValue::Bytes(vec![28])),
    ]);
    let bytes = envelope(31000000, payload.clone());
    decompress(&bytes, &options_for(31000000)).expect("identifier 28 resolves under 31000000");

    let error =
        decompress(&envelope(32000000, payload), &options_for(32000000)).expect_err("must refuse");
    assert_eq!(error.code(), "unknown_compressed_value");
    assert!(
        error
            .to_string()
            .contains("url table of registry entry 32000000"),
        "the refusal names the sub-table and entry, found {error}"
    );
}

#[test]
fn a_url_identifier_is_refused_by_an_entry_with_no_url_table() {
    // Entry 100 has `context` and `cryptosuiteString` sub-tables but no
    // `url` table, so a byte string in an @id position has no meaning here.
    let payload = CborValue::Map(vec![
        (CborValue::Unsigned(0), CborValue::Unsigned(32_768)),
        (CborValue::Unsigned(4), CborValue::Bytes(vec![1])),
    ]);
    let error = decompress(&envelope(100, payload), &options_for(100)).expect_err("must refuse");
    assert_eq!(error.code(), "envelope");
    assert!(
        error.to_string().contains("byte string"),
        "the refusal names the offending shape, found {error}"
    );
}

#[test]
fn a_context_identifier_is_refused_in_a_cryptosuite_position() {
    // Entry 100 numbers contexts from 32768 and cryptosuites from 1..=4.
    // Identifier 32768 in a cryptosuiteString position must not borrow the
    // context table.
    let payload = CborValue::Map(vec![
        (CborValue::Unsigned(0), CborValue::Unsigned(32_768)),
        (CborValue::Unsigned(100), CborValue::Unsigned(32_768)),
    ]);
    let error = decompress(&envelope(100, payload), &options_for(100)).expect_err("must refuse");
    assert_eq!(error.code(), "unknown_compressed_value");
    assert!(
        error.to_string().contains(CRYPTOSUITE),
        "the refusal names the sub-table consulted, found {error}"
    );
}

#[test]
fn non_shortest_table_identifier_bytes_are_refused() {
    // Identifier 1 spelled as two bytes is not the canonical form entry
    // 10001's url table would ever produce.
    let payload = CborValue::Map(vec![
        (CborValue::Unsigned(0), CborValue::Unsigned(1)),
        (CborValue::Unsigned(4), CborValue::Bytes(vec![0, 1])),
    ]);
    let error =
        decompress(&envelope(10001, payload), &options_for(10001)).expect_err("must refuse");
    assert_eq!(error.code(), "envelope");
    assert!(
        error.to_string().contains("shortest byte form"),
        "found {error}"
    );
}

#[test]
fn registered_contexts_still_require_caller_supplied_content() {
    // The registry maps an IRI to an integer; it never supplies the context
    // document. The no-network boundary is unchanged by table support.
    let mut accepted = ProvisionalEntries::new();
    accepted.accept(100);
    let options = CborldOptions {
        mode: CompressionMode::RegistryEntry(100),
        accepted_provisional_entries: accepted,
        ..CborldOptions::default()
    };
    let document = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "name": "Example",
    });
    let error = compress(&document, &options).expect_err("must refuse");
    assert_eq!(error.code(), "unregistered_context");

    // Same on the decode side, even though the identifier itself resolves.
    let payload = CborValue::Map(vec![(CborValue::Unsigned(0), CborValue::Unsigned(32_768))]);
    let error = decompress(&envelope(100, payload), &options).expect_err("must refuse");
    assert_eq!(error.code(), "unregistered_context");
}
