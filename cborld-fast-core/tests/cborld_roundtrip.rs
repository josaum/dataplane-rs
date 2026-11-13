// Rust guideline compliant 2026-02-21
//! CBOR-LD envelope round-trips and fail-closed rejections.

use cborld_fast_core::{
    CborldOptions, CompressionMode,
    cbor::{CborLimits, CborValue, decode, encode_canonical},
    compress, decompress,
};
use serde_json::{Value, json};

fn options() -> CborldOptions {
    CborldOptions::default()
}

fn roundtrip(document: &Value) -> Vec<u8> {
    let bytes = compress(document, &options()).expect("compress");
    let decoded = decompress(&bytes, &options()).expect("decompress");
    assert_eq!(&decoded, document, "round-trip mismatch");
    bytes
}

/// Decodes the compressed payload map of one envelope for inspection.
fn payload_entries(bytes: &[u8]) -> Vec<(CborValue, CborValue)> {
    let value = decode(bytes, &CborLimits::default()).expect("well-formed envelope");
    let CborValue::Tag(51997, inner) = value else {
        panic!("expected tag 51997, found {value:?}");
    };
    let CborValue::Array(elements) = *inner else {
        panic!("expected two-element array");
    };
    assert_eq!(elements[0], CborValue::Unsigned(1), "registry entry id");
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

#[test]
fn simple_document_roundtrips_with_vendored_envelope_prefix() {
    let doc = json!({
        "@context": {"name": "http://schema.org/name"},
        "name": "Example"
    });
    let bytes = roundtrip(&doc);
    // tag 0xCB1D (0xd9 0xcb 0x1d), array(2) (0x82), registry entry 1 (0x01).
    assert_eq!(&bytes[0..5], &[0xd9, 0xcb, 0x1d, 0x82, 0x01]);
    let entries = payload_entries(&bytes);
    // "@context" compresses to key 0; the first custom term to id 100.
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(100)),
        CborValue::Text("Example".to_string())
    );
}

#[test]
fn ids_types_and_plural_terms_compress_through_the_term_map() {
    let doc = json!({
        "@context": {
            "Person": "http://schema.org/Person",
            "knows": {"@id": "http://schema.org/knows", "@type": "@id"},
            "name": "http://schema.org/name"
        },
        "@id": "https://example.com/alice",
        "@type": "Person",
        "name": "Alice",
        "knows": ["https://example.com/bob", "https://example.com/carol"]
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    // Sorted term assignment: Person=100, knows=102, name=104.
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(2)),
        CborValue::Unsigned(100),
        "@type value must be the Person term id"
    );
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(4)),
        CborValue::Array(vec![
            CborValue::Unsigned(2),
            CborValue::Text("example.com/alice".to_string()),
        ]),
        "@id value must use the https:// prefix entry"
    );
    // Plural array value uses the odd id knows+1 = 103.
    let CborValue::Array(knows) = entry_value(&entries, &CborValue::Unsigned(103)) else {
        panic!("plural term must hold an array");
    };
    assert_eq!(knows.len(), 2);
}

#[test]
fn nested_objects_language_maps_and_mixed_scalars_roundtrip() {
    let doc = json!({
        "@context": {
            "label": {"@id": "http://www.w3.org/2000/01/rdf-schema#label",
                       "@container": "@language"},
            "depth": "http://example.com/depth"
        },
        "label": {"en": "Chart", "de": ["Chart", "Karte"]},
        "depth": {
            "@value": 42,
            "@type": "http://example.com/level"
        },
        "unmapped-term": [true, false, null, 1.5, -7, {"inner": "x"}],
        "big": u64::MAX,
        "small": i64::MIN
    });
    roundtrip(&doc);
}

#[test]
fn nested_node_contexts_extend_the_term_map_deterministically() {
    let doc = json!({
        "@context": {"a": "http://example.com/a"},
        "a": {
            "@context": {"b": "http://example.com/b"},
            "b": {"a": "again", "b": "deep"}
        }
    });
    roundtrip(&doc);
}

#[test]
fn context_arrays_keep_their_shape() {
    let single = json!({
        "@context": [{"a": "http://example.com/a"}],
        "a": 1
    });
    let bytes = roundtrip(&single);
    let entries = payload_entries(&bytes);
    // A one-element context array is carried under plural key 1, not key 0.
    assert!(matches!(
        entry_value(&entries, &CborValue::Unsigned(1)),
        CborValue::Array(_)
    ));
    let double = json!({
        "@context": [
            {"a": "http://example.com/a"},
            {"b": "http://example.com/b"}
        ],
        "a": 1,
        "b": 2
    });
    roundtrip(&double);
}

#[test]
fn xsd_date_and_datetime_values_compress_losslessly() {
    let doc = json!({
        "@context": {
            "born": {"@id": "http://example.com/born",
                      "@type": "http://www.w3.org/2001/XMLSchema#date"},
            "created": {"@id": "http://purl.org/dc/terms/created",
                         "@type": "http://www.w3.org/2001/XMLSchema#dateTime"}
        },
        "born": "2020-03-01",
        "created": "2020-03-01T12:34:56Z"
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    // born=100, created=102; 2020-03-01 = 18322 days = 1583020800 s.
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(100)),
        CborValue::Unsigned(1_583_020_800)
    );
    assert!(matches!(
        entry_value(&entries, &CborValue::Unsigned(102)),
        CborValue::Unsigned(_)
    ));
}

#[test]
fn pre_epoch_and_millisecond_datetimes_roundtrip() {
    let doc = json!({
        "@context": {
            "created": {"@id": "http://purl.org/dc/terms/created",
                         "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
            "born": {"@id": "http://example.com/born",
                      "@type": "http://www.w3.org/2001/XMLSchema#date"}
        },
        "born": "1969-12-31",
        "created": "1969-12-31T23:59:59.999Z"
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    // created=102: floor semantics give [-1 s, 999 ms] = [Negative(0), 999].
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(102)),
        CborValue::Array(vec![CborValue::Negative(0), CborValue::Unsigned(999)])
    );
    let millis = json!({
        "@context": {
            "created": {"@id": "http://purl.org/dc/terms/created",
                         "@type": "http://www.w3.org/2001/XMLSchema#dateTime"}
        },
        "created": ["2020-03-01T12:34:56.000Z", "2020-03-01T12:34:56.123Z"]
    });
    roundtrip(&millis);
}

/// The millisecond field of a compressed `xsd:dateTime` is a fraction of the
/// adjacent second, so only `0..=999` is well formed. A larger value must be
/// refused rather than folded into the seconds field: `[seconds, 5000]` would
/// otherwise read back as `seconds + 5`, silently re-attributing the overflow
/// and inventing a timestamp the encoder never wrote.
#[test]
fn out_of_range_datetime_millis_is_refused_not_folded_into_seconds() {
    let doc = json!({
        "@context": {
            "created": {"@id": "http://purl.org/dc/terms/created",
                         "@type": "http://www.w3.org/2001/XMLSchema#dateTime"}
        },
        "created": "2020-03-01T12:34:56.123Z"
    });
    let bytes = compress(&doc, &options()).expect("compress");
    let entries = payload_entries(&bytes);
    // Locate the compressed instant by shape — the term id depends on how many
    // terms the context defines, which is not what this test is pinning.
    let (key, seconds) = entries
        .iter()
        .find_map(|(key, value)| match value {
            CborValue::Array(parts) => match parts.as_slice() {
                [seconds, CborValue::Unsigned(123)] => Some((key.clone(), seconds.clone())),
                _ => None,
            },
            _ => None,
        })
        .expect("a [seconds, 123 ms] pair in the payload");

    // Same envelope, same seconds — only the millisecond field is out of range.
    let tampered: Vec<(CborValue, CborValue)> = entries
        .iter()
        .map(|(candidate, value)| {
            if candidate == &key {
                let overflowed =
                    CborValue::Array(vec![seconds.clone(), CborValue::Unsigned(5_000)]);
                (candidate.clone(), overflowed)
            } else {
                (candidate.clone(), value.clone())
            }
        })
        .collect();
    let error = decompress(&envelope(1, CborValue::Map(tampered)), &options())
        .expect_err("out-of-range millis must fail closed");
    assert_eq!(error.code(), "number_range");
    assert!(error.to_string().contains("5000"), "{error}");
}

#[test]
fn non_canonical_date_strings_pass_through_verbatim() {
    let doc = json!({
        "@context": {
            "born": {"@id": "http://example.com/born",
                      "@type": "http://www.w3.org/2001/XMLSchema#date"},
            "created": {"@id": "http://purl.org/dc/terms/created",
                         "@type": "http://www.w3.org/2001/XMLSchema#dateTime"}
        },
        "born": "2020-3-1",
        "created": "2020-03-01T12:34:56+02:00"
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(100)),
        CborValue::Text("2020-3-1".to_string())
    );
}

#[test]
fn uuid_urns_compress_to_bytes_only_when_lowercase() {
    let doc = json!({
        "@context": {"knows": {"@id": "http://schema.org/knows", "@type": "@id"}},
        "knows": [
            "urn:uuid:c828c352-cc57-4b6c-b1f2-2c9b976fbc86",
            "urn:uuid:C828C352-CC57-4B6C-B1F2-2C9B976FBC86"
        ]
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    let CborValue::Array(values) = entry_value(&entries, &CborValue::Unsigned(101)) else {
        panic!("plural term must hold an array");
    };
    assert!(
        matches!(&values[0], CborValue::Array(parts)
            if matches!(&parts[1], CborValue::Bytes(bytes) if bytes.len() == 16)),
        "lowercase UUID must compress to 16 bytes"
    );
    assert!(
        matches!(&values[1], CborValue::Array(parts)
            if matches!(&parts[1], CborValue::Text(_))),
        "uppercase UUID must stay text"
    );
}

#[test]
fn urls_with_ports_pass_through_uncompressed() {
    // The prefix rule requires the remainder to contain no ':' character.
    let doc = json!({
        "@context": {},
        "@id": "https://example.com:8080/x"
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(4)),
        CborValue::Text("https://example.com:8080/x".to_string())
    );
}

#[test]
fn uncompressed_mode_embeds_plain_cbor_under_registry_entry_zero() {
    let doc = json!([1, {"a": null}, "x", -2.5]);
    let opts = CborldOptions {
        mode: CompressionMode::Uncompressed,
        ..CborldOptions::default()
    };
    let bytes = compress(&doc, &opts).expect("compress");
    assert_eq!(&bytes[0..5], &[0xd9, 0xcb, 0x1d, 0x82, 0x00]);
    assert_eq!(decompress(&bytes, &opts).expect("decompress"), doc);
}

#[test]
fn remote_contexts_are_refused_never_fetched() {
    let top = json!({"@context": "https://schema.org", "name": "x"});
    let error = compress(&top, &options()).expect_err("must fail");
    assert_eq!(error.code(), "unregistered_context");
    assert!(error.to_string().contains("https://schema.org"));

    let in_array = json!({
        "@context": [{"a": "http://example.com/a"}, "https://schema.org"],
        "a": 1
    });
    let error = compress(&in_array, &options()).expect_err("must fail");
    assert_eq!(error.code(), "unregistered_context");
}

#[test]
fn unsupported_context_features_are_refused() {
    let import = json!({"@context": {"@import": "https://example.com/ctx"}});
    assert_eq!(
        compress(&import, &options()).expect_err("import").code(),
        "unsupported"
    );
    let scoped = json!({
        "@context": {"a": {"@id": "http://example.com/a",
                            "@context": {"b": "http://example.com/b"}}},
        "a": 1
    });
    assert_eq!(
        compress(&scoped, &options()).expect_err("scoped").code(),
        "unsupported"
    );
    let reset = json!({"@context": null, "a": 1});
    assert_eq!(
        compress(&reset, &options()).expect_err("reset").code(),
        "unsupported"
    );
}

#[test]
fn unknown_tags_and_registry_entries_are_refused() {
    let wrong_tag = CborValue::Tag(
        999,
        Box::new(CborValue::Array(vec![
            CborValue::Unsigned(1),
            CborValue::Map(vec![]),
        ])),
    );
    let bytes = encode_canonical(&wrong_tag, &CborLimits::default()).expect("encode");
    let error = decompress(&bytes, &options()).expect_err("must fail");
    assert_eq!(error.code(), "envelope");
    assert!(error.to_string().contains("found tag 999"));

    let bytes = envelope(7, CborValue::Map(vec![]));
    let error = decompress(&bytes, &options()).expect_err("must fail");
    assert_eq!(error.code(), "unknown_registry_entry");
}

#[test]
fn conflicting_context_keys_are_refused() {
    let payload = CborValue::Map(vec![
        (CborValue::Unsigned(0), CborValue::Map(vec![])),
        (CborValue::Unsigned(1), CborValue::Array(vec![])),
    ]);
    let error = decompress(&envelope(1, payload), &options()).expect_err("must fail");
    assert_eq!(error.code(), "envelope");
}

#[test]
fn compressed_context_ids_are_refused_under_entry_1() {
    // Registry entries 0 and 1 carry no compression table at all, so an
    // integer context identifier has nothing to resolve against. Identifier
    // 32768 is real — registry entry 100 assigns it to the VC v2 context —
    // which is exactly why replaying it under entry 1 must fail rather than
    // reach across entries for a plausible-looking answer.
    let compressed_context =
        CborValue::Map(vec![(CborValue::Unsigned(0), CborValue::Unsigned(32_768))]);
    let error = decompress(&envelope(1, compressed_context), &options()).expect_err("must fail");
    assert_eq!(error.code(), "unknown_compressed_context");
}

#[test]
fn unknown_term_ids_are_refused_on_decode() {
    let payload = CborValue::Map(vec![(CborValue::Unsigned(100), CborValue::Null)]);
    let error = decompress(&envelope(1, payload), &options()).expect_err("must fail");
    assert_eq!(error.code(), "unknown_term_id");
}

#[test]
fn non_string_scalars_under_codec_typed_terms_are_refused() {
    let doc = json!({
        "@context": {"knows": {"@id": "http://schema.org/knows", "@type": "@id"}},
        "knows": 5
    });
    assert_eq!(
        compress(&doc, &options()).expect_err("must fail").code(),
        "document"
    );
    let doc = json!({
        "@context": {"born": {"@id": "http://example.com/born",
                               "@type": "http://www.w3.org/2001/XMLSchema#date"}},
        "born": 12345
    });
    assert_eq!(
        compress(&doc, &options()).expect_err("must fail").code(),
        "document"
    );
}

#[test]
fn non_object_documents_are_refused_in_compressed_mode() {
    let error = compress(&json!([1, 2]), &options()).expect_err("must fail");
    assert_eq!(error.code(), "document");
}

#[test]
fn depth_limits_are_enforced_on_compress_and_decompress() {
    let mut doc = json!({"leaf": true});
    for _ in 0..20 {
        doc = json!({"nested": doc});
    }
    let tight = CborldOptions {
        limits: CborLimits {
            max_depth: 8,
            ..CborLimits::default()
        },
        ..CborldOptions::default()
    };
    assert_eq!(
        compress(&doc, &tight).expect_err("must fail").code(),
        "resource_limit"
    );
    let bytes = compress(&doc, &options()).expect("compress within default limits");
    assert_eq!(
        decompress(&bytes, &tight).expect_err("must fail").code(),
        "resource_limit"
    );
}

#[test]
fn trailing_bytes_after_the_envelope_are_refused() {
    let mut bytes = compress(&json!({"a": 1}), &options()).expect("compress");
    bytes.push(0x00);
    let error = decompress(&bytes, &options()).expect_err("must fail");
    assert_eq!(error.code(), "cbor_decode");
}

#[test]
fn term_id_substitution_takes_precedence_over_prefix_compression() {
    // The URL codec must check the term map before the prefix table
    // (spec: Create URL Encoder, steps 2-3 before step 5).
    let doc = json!({
        "@context": {"http://schema.org/x": "http://schema.org/x"},
        "@id": "http://schema.org/x"
    });
    let bytes = roundtrip(&doc);
    let entries = payload_entries(&bytes);
    assert_eq!(
        entry_value(&entries, &CborValue::Unsigned(4)),
        CborValue::Unsigned(100),
        "term-id match must win over http:// prefix compression"
    );
}

#[test]
fn invalid_term_definitions_fail_identically_on_decode() {
    // A hand-built envelope embedding a context with a numeric term
    // definition must route through the same load_context validation.
    let doc = json!({"@context": {"bad": 7}, "bad": 1});
    let encode_error = compress(&doc, &options()).expect_err("encode must fail");
    assert_eq!(encode_error.code(), "document");
    let payload = CborValue::Map(vec![(
        CborValue::Unsigned(0),
        CborValue::Map(vec![(
            CborValue::Text("bad".to_string()),
            CborValue::Unsigned(7),
        )]),
    )]);
    let decode_error = decompress(&envelope(1, payload), &options()).expect_err("decode must fail");
    assert_eq!(decode_error.code(), "document");
}

#[test]
fn keyword_values_and_empty_documents_roundtrip() {
    roundtrip(&json!({}));
    roundtrip(&json!({
        "@context": {"Person": "http://schema.org/Person",
                      "Thing": "http://schema.org/Thing"},
        "@type": ["Person", "Thing", "http://example.org/Other"],
        "@value": null
    }));
}
