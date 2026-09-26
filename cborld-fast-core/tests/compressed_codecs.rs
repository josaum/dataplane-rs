// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Coverage for registered contexts, the DID/Data URL and Multibase value
//! codecs, and preferred-float analysis: spec-anchored positives,
//! fail-closed error paths, and strict round-trips.

use cborld_fast_core::{
    CborldOptions, ProvidedContexts,
    cbor::{CborLimits, CborValue, encode_canonical},
    compress, decompress,
};
use serde_json::{Value, json};

const CTX_IRI: &str = "https://example.com/contexts/v1";
const MULTIBASE_IRI: &str = "https://w3id.org/security#multibase";

fn options() -> CborldOptions {
    CborldOptions::default()
}

/// Options carrying one provided context document under [`CTX_IRI`].
fn options_with_context(document: Value) -> CborldOptions {
    let mut provided = ProvidedContexts::new();
    provided.insert(CTX_IRI, document);
    CborldOptions {
        provided_contexts: provided,
        ..CborldOptions::default()
    }
}

fn roundtrip_with(document: &Value, options: &CborldOptions) -> Vec<u8> {
    let bytes = compress(document, options).expect("compress");
    let decoded = decompress(&bytes, options).expect("decompress");
    assert_eq!(&decoded, document, "round-trip mismatch");
    bytes
}

fn roundtrip(document: &Value) -> Vec<u8> {
    roundtrip_with(document, &options())
}

/// Decodes the compressed payload map of one envelope for inspection.
fn payload_entries(bytes: &[u8]) -> Vec<(CborValue, CborValue)> {
    let value = cborld_fast_core::cbor::decode(bytes, &CborLimits::default()).expect("well-formed");
    let CborValue::Tag(51997, inner) = value else {
        panic!("expected tag 51997, found {value:?}");
    };
    let CborValue::Array(elements) = *inner else {
        panic!("expected two-element array");
    };
    let CborValue::Map(entries) = elements[1].clone() else {
        panic!("expected map payload");
    };
    entries
}

fn entry_value(entries: &[(CborValue, CborValue)], key: &CborValue) -> CborValue {
    entries
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| panic!("missing key {key:?}"))
}

/// Builds an envelope `tag(0xCB1D, [entry, payload])` for error tests.
fn envelope(entry: u64, payload: CborValue) -> Vec<u8> {
    let tagged = CborValue::Tag(
        0xCB1D,
        Box::new(CborValue::Array(vec![CborValue::Unsigned(entry), payload])),
    );
    encode_canonical(&tagged, &CborLimits::default()).expect("encode")
}

/// Payload with one inline context defining a multibase-typed term `mb`
/// (term id 100) whose value is `value`.
fn multibase_payload(value: CborValue) -> CborValue {
    CborValue::Map(vec![
        (
            CborValue::Unsigned(0),
            CborValue::Map(vec![(
                CborValue::Text("mb".to_string()),
                CborValue::Map(vec![
                    (
                        CborValue::Text("@id".to_string()),
                        CborValue::Text("http://example.com/mb".to_string()),
                    ),
                    (
                        CborValue::Text("@type".to_string()),
                        CborValue::Text(MULTIBASE_IRI.to_string()),
                    ),
                ]),
            )]),
        ),
        (CborValue::Unsigned(100), value),
    ])
}

// --- Registered context IRIs (provided contexts, never fetched) ----------

#[test]
fn registered_context_roundtrips_with_provided_content() {
    let doc = json!({
        "@context": CTX_IRI,
        "name": "Atlas"
    });
    let opts = options_with_context(json!({
        "@context": {"name": "http://schema.org/name"}
    }));
    let bytes = roundtrip_with(&doc, &opts);
    let entries = payload_entries(&bytes);
    // The IRI itself rides the wire as a text string under context key 0.
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(0)),
        CborValue::Text(CTX_IRI.to_string())
    );
    // The provided context drives term-map construction: name = 100.
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(100)),
        CborValue::Text("Atlas".to_string())
    );
}

#[test]
fn registered_context_content_may_be_bare_or_wrapped() {
    let doc = json!({"@context": CTX_IRI, "name": "x"});
    // Bare term-definition object.
    roundtrip_with(
        &doc,
        &options_with_context(json!({"name": "http://schema.org/name"})),
    );
    // Wrapped context document whose @context is an array of objects.
    roundtrip_with(
        &doc,
        &options_with_context(json!({
            "@context": [{"name": "http://schema.org/name"}]
        })),
    );
}

#[test]
fn registered_context_mixes_with_inline_contexts_in_arrays() {
    let doc = json!({
        "@context": [CTX_IRI, {"b": "http://example.com/b"}],
        "name": "x",
        "b": 2
    });
    let opts = options_with_context(json!({
        "@context": {"name": "http://schema.org/name"}
    }));
    let bytes = roundtrip_with(&doc, &opts);
    let entries = payload_entries(&bytes);
    let CborValue::Array(contexts) = entry_value(&entries, &CborValue::Unsigned(1)) else {
        panic!("plural @context must hold an array");
    };
    assert_eq!(contexts[0], CborValue::Text(CTX_IRI.to_string()));
    assert!(matches!(contexts[1], CborValue::Map(_)));
}

#[test]
fn missing_provided_content_is_refused_on_compress() {
    let doc = json!({"@context": CTX_IRI, "name": "x"});
    let error = compress(&doc, &options()).expect_err("must fail");
    assert_eq!(error.code(), "unregistered_context");
    assert!(error.to_string().contains(CTX_IRI));
}

#[test]
fn missing_provided_content_is_refused_on_decompress() {
    let doc = json!({"@context": CTX_IRI, "name": "x"});
    let opts = options_with_context(json!({"name": "http://schema.org/name"}));
    let bytes = compress(&doc, &opts).expect("compress");
    // Decoding without the provided content must refuse, never fetch.
    let error = decompress(&bytes, &options()).expect_err("must fail");
    assert_eq!(error.code(), "unregistered_context");
    assert!(error.to_string().contains(CTX_IRI));
}

#[test]
fn mismatched_provided_content_fails_on_unresolved_term_ids() {
    let doc = json!({"@context": CTX_IRI, "name": "x"});
    let bytes = compress(
        &doc,
        &options_with_context(json!({"name": "http://schema.org/name"})),
    )
    .expect("compress");
    // Content that defines no terms leaves term id 100 unresolvable.
    let error = decompress(&bytes, &options_with_context(json!({}))).expect_err("must fail");
    assert_eq!(error.code(), "unknown_term_id");
}

#[test]
fn chained_context_references_inside_provided_content_are_refused() {
    let doc = json!({"@context": CTX_IRI, "name": "x"});
    let opts = options_with_context(json!({"@context": "https://example.com/other"}));
    let error = compress(&doc, &opts).expect_err("must fail");
    assert_eq!(error.code(), "unregistered_context");
    assert!(error.to_string().contains("https://example.com/other"));
}

#[test]
fn non_object_provided_content_is_refused() {
    let doc = json!({"@context": CTX_IRI});
    let error =
        compress(&doc, &options_with_context(json!("not a context"))).expect_err("must fail");
    assert_eq!(error.code(), "document");
}

// --- Base58 DID URL codec -------------------------------------------------

#[test]
fn did_key_urls_compress_to_base58_bytes() {
    let doc = json!({
        "@context": {},
        "@id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    let CborValue::Array(items) = entry_value(&entries, &CborValue::Unsigned(4)) else {
        panic!("did: codec must produce an array");
    };
    assert_eq!(items[0], CborValue::Unsigned(1025), "did:key: prefix id");
    assert!(
        matches!(&items[1], CborValue::Bytes(bytes) if !bytes.is_empty()),
        "canonical base58btc suffix must compress to bytes"
    );
}

#[test]
fn did_urls_with_fragments_and_nym_prefix_roundtrip() {
    // base58btc "Ldp" decodes to [1, 2, 3].
    let doc = json!({
        "@context": {},
        "@id": "did:v1:nym:zLdp#zLdp"
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(4)),
        CborValue::Array(vec![
            CborValue::Unsigned(1024),
            CborValue::Bytes(vec![1, 2, 3]),
            CborValue::Bytes(vec![1, 2, 3]),
        ])
    );
}

#[test]
fn non_base58_did_suffixes_stay_text_and_roundtrip() {
    // "0OIl" are outside the base58btc alphabet; "web" has no z header.
    for iri in ["did:key:web:example.com", "did:key:z0OIl", "did:key:"] {
        let doc = json!({"@context": {}, "@id": iri});
        let bytes = roundtrip(&doc);
        let entries = payload_entries(&bytes);
        let CborValue::Array(items) = entry_value(&entries, &CborValue::Unsigned(4)) else {
            panic!("did: codec must produce an array");
        };
        assert!(
            matches!(items[1], CborValue::Text(_)),
            "{iri} suffix must stay text"
        );
    }
}

#[test]
fn did_decode_reconstructs_the_canonical_multibase_form() {
    let payload = CborValue::Map(vec![(
        CborValue::Unsigned(4),
        CborValue::Array(vec![
            CborValue::Unsigned(1025),
            CborValue::Bytes(vec![1, 2, 3]),
        ]),
    )]);
    let decoded = decompress(&envelope(1, payload), &options()).expect("decode");
    assert_eq!(decoded, json!({"@id": "did:key:zLdp"}));
    // Strict round-trip: re-compressing reproduces the same wire bytes.
    let recompressed = compress(&decoded, &options()).expect("compress");
    assert_eq!(
        decompress(&recompressed, &options()).expect("decode"),
        decoded
    );
}

#[test]
fn malformed_did_codec_shapes_are_refused_on_decode() {
    // Wrong arity (no segments).
    let no_segments = CborValue::Map(vec![(
        CborValue::Unsigned(4),
        CborValue::Array(vec![CborValue::Unsigned(1025)]),
    )]);
    let error = decompress(&envelope(1, no_segments), &options()).expect_err("must fail");
    assert_eq!(error.code(), "envelope");
    // Wrong segment type.
    let bad_segment = CborValue::Map(vec![(
        CborValue::Unsigned(4),
        CborValue::Array(vec![CborValue::Unsigned(1024), CborValue::Unsigned(7)]),
    )]);
    let error = decompress(&envelope(1, bad_segment), &options()).expect_err("must fail");
    assert_eq!(error.code(), "envelope");
    assert!(error.to_string().contains("segment"));
}

#[test]
fn oversized_did_bytes_are_refused_on_decode() {
    let tight = CborldOptions {
        limits: CborLimits {
            max_value_bytes: 4,
            ..CborLimits::default()
        },
        ..CborldOptions::default()
    };
    let payload = CborValue::Map(vec![(
        CborValue::Unsigned(4),
        CborValue::Array(vec![
            CborValue::Unsigned(1025),
            CborValue::Bytes(vec![0u8; 8]),
        ]),
    )]);
    let error = decompress(&envelope(1, payload), &tight).expect_err("must fail");
    assert_eq!(error.code(), "resource_limit");
    assert!(error.to_string().contains("value_bytes"));
}

#[test]
fn oversized_base58_suffixes_pass_through_on_encode() {
    // Above the byte budget the encoder skips base58 work (lossless
    // passthrough as text); the round-trip property is unaffected.
    let tight = CborldOptions {
        limits: CborLimits {
            max_value_bytes: 4,
            ..CborLimits::default()
        },
        ..CborldOptions::default()
    };
    let doc = json!({"@context": {}, "@id": "did:key:zzzzzzz"});
    let bytes = roundtrip_with(&doc, &tight);
    let entries = payload_entries(&bytes);
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(4)),
        CborValue::Array(vec![
            CborValue::Unsigned(1025),
            CborValue::Text("zzzzzzz".to_string()),
        ])
    );
}

// --- Data URL codec --------------------------------------------------------

#[test]
fn base64_data_urls_compress_to_bytes() {
    let doc = json!({
        "@context": {},
        "@id": "data:text/plain;base64,SGVsbG8="
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(4)),
        CborValue::Array(vec![
            CborValue::Unsigned(4),
            CborValue::Text("text/plain".to_string()),
            CborValue::Bytes(b"Hello".to_vec()),
        ])
    );
}

#[test]
fn non_canonical_and_non_base64_data_urls_stay_text() {
    // Missing padding (non-canonical base64) and a plain-text data URL.
    for iri in ["data:text/plain;base64,SGVsbG8", "data:,plain%20text"] {
        let doc = json!({"@context": {}, "@id": iri});
        let bytes = roundtrip(&doc);
        let entries = payload_entries(&bytes);
        let CborValue::Array(items) = entry_value(&entries, &CborValue::Unsigned(4)) else {
            panic!("data: codec must produce an array");
        };
        assert_eq!(items.len(), 2, "{iri} must take the text form");
        assert!(matches!(items[1], CborValue::Text(_)));
    }
}

#[test]
fn empty_mediatype_base64_data_urls_compress_and_roundtrip() {
    let doc = json!({"@context": {}, "@id": "data:;base64,AQI="});
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(4)),
        CborValue::Array(vec![
            CborValue::Unsigned(4),
            CborValue::Text(String::new()),
            CborValue::Bytes(vec![1, 2]),
        ])
    );
    // The empty payload is canonical base64 for zero bytes and compresses.
    let doc = json!({"@context": {}, "@id": "data:;base64,"});
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(4)),
        CborValue::Array(vec![
            CborValue::Unsigned(4),
            CborValue::Text(String::new()),
            CborValue::Bytes(vec![]),
        ])
    );
}

#[test]
fn malformed_data_codec_shapes_are_refused_on_decode() {
    let bad = CborValue::Map(vec![(
        CborValue::Unsigned(4),
        CborValue::Array(vec![CborValue::Unsigned(4), CborValue::Unsigned(1)]),
    )]);
    let error = decompress(&envelope(1, bad), &options()).expect_err("must fail");
    assert_eq!(error.code(), "envelope");
    assert!(error.to_string().contains("data:"));
}

// --- Multibase codec --------------------------------------------------------

#[test]
fn multibase_values_compress_to_headered_bytes() {
    // "z2" is base58btc for [1]; "uAQI" is base64url for [1, 2].
    let doc = json!({
        "@context": {"mb": {"@id": "http://example.com/mb",
                             "@type": MULTIBASE_IRI}},
        "mb": ["z2", "uAQI"]
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(101)),
        CborValue::Array(vec![
            CborValue::Bytes(vec![b'z', 1]),
            CborValue::Bytes(vec![b'u', 1, 2]),
        ])
    );
}

#[test]
fn non_canonical_multibase_values_stay_text() {
    // "uAR" has non-zero trailing bits; "zl" uses an out-of-alphabet char;
    // "Mzg" uses a header outside the vendored subset.
    let doc = json!({
        "@context": {"mb": {"@id": "http://example.com/mb",
                             "@type": MULTIBASE_IRI}},
        "mb": ["uAR", "zl", "Mzg"]
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    let CborValue::Array(items) = entry_value(&entries, &CborValue::Unsigned(101)) else {
        panic!("plural term must hold an array");
    };
    assert!(items.iter().all(|item| matches!(item, CborValue::Text(_))));
}

#[test]
fn multibase_decode_failures_are_typed() {
    // Empty byte string: no header to dispatch on.
    let error = decompress(
        &envelope(1, multibase_payload(CborValue::Bytes(vec![]))),
        &options(),
    )
    .expect_err("must fail");
    assert_eq!(error.code(), "envelope");
    // Unknown multibase header (base64pad `M` is outside the subset).
    let error = decompress(
        &envelope(1, multibase_payload(CborValue::Bytes(vec![b'M', 1]))),
        &options(),
    )
    .expect_err("must fail");
    assert_eq!(error.code(), "unsupported");
    // Oversized payload against a tight byte budget.
    let tight = CborldOptions {
        limits: CborLimits {
            max_value_bytes: 4,
            ..CborLimits::default()
        },
        ..CborldOptions::default()
    };
    let error = decompress(
        &envelope(1, multibase_payload(CborValue::Bytes(vec![b'z'; 8]))),
        &tight,
    )
    .expect_err("must fail");
    assert_eq!(error.code(), "resource_limit");
    assert!(error.to_string().contains("value_bytes"));
}

#[test]
fn multibase_typed_non_strings_pass_through() {
    let doc = json!({
        "@context": {"mb": {"@id": "http://example.com/mb",
                             "@type": MULTIBASE_IRI}},
        "mb": 42
    });
    roundtrip(&doc);
}

// --- Preferred floats through the CBOR-LD layer -----------------------------

#[test]
fn float_documents_roundtrip_through_preferred_serialization() {
    let doc = json!({
        "@context": {},
        "halves": [1.5, -0.0, 65504.0],
        "singles": [0.5f64 + f64::from(f32::EPSILON)],
        "doubles": [0.1, -2.5e300]
    });
    roundtrip(&doc);
}

#[test]
fn non_finite_floats_are_refused_on_decompress() {
    // A foreign envelope carrying NaN cannot become a JSON number.
    let bytes = envelope(0, CborValue::Float(f64::NAN));
    let error = decompress(&bytes, &options()).expect_err("must fail");
    assert_eq!(error.code(), "number_range");
}
