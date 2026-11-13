// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Named hostile inputs for the CBOR reader and the CBOR-LD decompressor.
//!
//! Every shape runs under a 1 GiB live-allocation cap, and the recursion
//! shapes run on a 256 KiB thread, so an unbounded decoder aborts the test
//! binary instead of exhausting the machine. Work-amplification shapes
//! assert a typed `ResourceLimit` (or a bounded cumulative allocation),
//! never a wall-clock time.

#[path = "../../tools/mutation_smoke.rs"]
mod smoke;

#[global_allocator]
static ALLOCATOR: smoke::CappedAllocator = smoke::CappedAllocator;

use cborld_fast_core::{
    CborldError, CborldOptions, ProvidedContexts,
    cbor::{CborLimits, CborValue, decode, encode_canonical},
    decompress,
};
use serde_json::{Map, Value, json};

/// CBOR-LD envelope tag (51997).
const CBORLD_TAG: u64 = 0xCB1D;

/// First identifier the term registry assigns to a custom term.
const FIRST_TERM_ID: u64 = 100;

/// Encodes `payload` inside the registry-entry-1 envelope.
fn envelope(payload: CborValue) -> Vec<u8> {
    let limits = CborLimits {
        max_depth: 1024,
        ..CborLimits::default()
    };
    encode_canonical(
        &CborValue::Tag(
            CBORLD_TAG,
            Box::new(CborValue::Array(vec![CborValue::Unsigned(1), payload])),
        ),
        &limits,
    )
    .expect("encode hostile envelope")
}

fn text(value: &str) -> CborValue {
    CborValue::Text(value.to_string())
}

/// Whether `result` is a `ResourceLimit` for the resource named `name`.
///
/// Matches on the rendered name so this file compiles against a crate that
/// does not yet define the resource (the test must be seen failing first).
fn is_resource<T>(result: &Result<T, CborldError>, name: &str) -> bool {
    matches!(result, Err(CborldError::ResourceLimit { resource, .. }) if resource.to_string() == name)
}

fn nested(open: &[u8], body: &[u8], depth: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(depth * open.len() + body.len());
    for _ in 0..depth {
        out.extend_from_slice(open);
    }
    out.extend_from_slice(body);
    out
}

#[test]
fn hundred_thousand_nested_containers_fail_closed_on_a_small_stack() {
    let _serial = smoke::measure_alone();
    smoke::run_on_small_stack(|| {
        let limits = CborLimits::default();
        for (name, open) in [
            ("array", &[0x81u8][..]),
            ("map", &[0xa1, 0x00][..]),
            ("tag", &[0xc6][..]),
            ("tag-in-tag-cborld", &[0xd9, 0xcb, 0x1d][..]),
        ] {
            let bytes = nested(open, &[0x00], 100_000);
            let result = decode(&bytes, &limits);
            assert!(is_resource(&result, "depth"), "{name}: {result:?}");
            let result = decompress(&bytes, &CborldOptions::default());
            assert!(
                is_resource(&result, "depth"),
                "{name} via decompress: {result:?}"
            );
        }
    });
}

#[test]
fn declared_lengths_of_two_pow_63_are_refused_before_allocating() {
    let _serial = smoke::measure_alone();
    let limits = CborLimits::default();
    for head in [0x5bu8, 0x7b, 0x9b, 0xbb] {
        let mut bytes = vec![head, 0x80, 0, 0, 0, 0, 0, 0, 0];
        bytes.push(0x00);
        let before = smoke::total_allocated();
        let result = decode(&bytes, &limits);
        let spent = smoke::total_allocated().saturating_sub(before);
        assert!(
            matches!(result, Err(CborldError::Decode { .. })),
            "{head:#x}: {result:?}"
        );
        // Other tests allocate concurrently; 64 MiB is far below 2^63.
        assert!(spent < 64 << 20, "{head:#x} allocated {spent} bytes");
    }
}

#[test]
fn indefinite_items_reserved_values_and_undefined_are_refused() {
    let _serial = smoke::measure_alone();
    let limits = CborLimits::default();
    for bytes in [
        &[0x9f, 0x00, 0x00][..],
        &[0xbf, 0x00][..],
        &[0x5f, 0x41, 0x00][..],
        &[0x7f, 0x61, 0x61][..],
        &[0x1c][..],
        &[0xf7][..],
        &[0xff][..],
        &[0xf8, 0x20][..],
    ] {
        let result = decode(bytes, &limits);
        assert!(
            matches!(result, Err(CborldError::Decode { .. })),
            "{bytes:x?}: {result:?}"
        );
    }
}

#[test]
fn scalar_edge_cases_decode_exactly() {
    let _serial = smoke::measure_alone();
    let limits = CborLimits::default();
    // Half-precision floats widen exactly; non-shortest integer heads are
    // accepted by design (documented in the module docs).
    assert_eq!(
        decode(&[0xf9, 0x3c, 0x00], &limits).ok(),
        Some(CborValue::Float(1.0))
    );
    assert_eq!(
        decode(&[0xf9, 0x7c, 0x00], &limits).ok(),
        Some(CborValue::Float(f64::INFINITY))
    );
    assert_eq!(
        decode(&[0x18, 0x01], &limits).ok(),
        Some(CborValue::Unsigned(1))
    );
    assert_eq!(
        decode(&[0x1b, 0, 0, 0, 0, 0, 0, 0, 1], &limits).ok(),
        Some(CborValue::Unsigned(1))
    );
    // Invalid UTF-8 and duplicate keys are refused.
    assert!(matches!(
        decode(&[0x62, 0xc3, 0x28], &limits),
        Err(CborldError::Decode { .. })
    ));
    assert!(matches!(
        decode(&[0xa2, 0x00, 0x00, 0x00, 0x01], &limits),
        Err(CborldError::Decode { .. })
    ));
    // Non-finite floats have no JSON form.
    let inf = envelope(CborValue::Map(vec![(
        text("x"),
        CborValue::Float(f64::INFINITY),
    )]));
    assert!(decompress(&inf, &CborldOptions::default()).is_err());
}

#[test]
fn bignum_tags_are_refused_with_a_typed_error() {
    let _serial = smoke::measure_alone();
    for tag in [2u64, 3] {
        let bytes = envelope(CborValue::Map(vec![(
            text("@context"),
            CborValue::Tag(tag, Box::new(CborValue::Bytes(vec![1; 9]))),
        )]));
        let result = decompress(&bytes, &CborldOptions::default());
        assert!(result.is_err(), "tag {tag}: {result:?}");
        // A plain (entry 0) payload carrying a bignum is refused too.
        let plain = encode_canonical(
            &CborValue::Tag(
                CBORLD_TAG,
                Box::new(CborValue::Array(vec![
                    CborValue::Unsigned(0),
                    CborValue::Tag(tag, Box::new(CborValue::Bytes(vec![1; 9]))),
                ])),
            ),
            &CborLimits::default(),
        )
        .expect("encode");
        let result = decompress(&plain, &CborldOptions::default());
        assert!(
            matches!(result, Err(CborldError::Unsupported(_))),
            "plain tag {tag}: {result:?}"
        );
    }
}

/// The deepest document `compress` accepts must decompress on a small stack.
#[test]
fn deepest_accepted_document_decompresses_on_a_small_stack() {
    let _serial = smoke::measure_alone();
    smoke::run_on_small_stack(|| {
        let options = CborldOptions::default();
        // Nested nodes: the deepest chain the depth budget admits.
        let mut deepest = None;
        for levels in 1..200 {
            let mut node = json!({"v": 1});
            for _ in 0..levels {
                node = json!({"@context": {"n": "http://e/n"}, "n": node});
            }
            match cborld_fast_core::compress(&node, &options) {
                Ok(bytes) => deepest = Some((node, bytes)),
                Err(_) => break,
            }
        }
        let (document, bytes) = deepest.expect("some depth compresses");
        assert_eq!(decompress(&bytes, &options).ok(), Some(document));
        // Nested plain arrays down the decode_plain chain.
        let mut array = json!(1);
        let mut deepest_array = None;
        for _ in 0..200 {
            array = json!([array]);
            let document = json!({"@context": {"n": "http://e/n"}, "n": array.clone()});
            match cborld_fast_core::compress(&document, &options) {
                Ok(bytes) => deepest_array = Some((document, bytes)),
                Err(_) => break,
            }
        }
        let (document, bytes) = deepest_array.expect("some array depth compresses");
        assert_eq!(decompress(&bytes, &options).ok(), Some(document));
    });
}

/// A 64 KiB term name referenced 20,000 times by a two-byte identifier.
///
/// Without an output budget the decompressor materializes 1.25 GiB of
/// strings from about 110 KiB of input.
#[test]
fn short_code_expanding_to_a_long_term_is_budgeted() {
    let _serial = smoke::measure_alone();
    let long_term = "t".repeat(64 * 1024);
    let context = CborValue::Map(vec![(text(&long_term), text("http://e/x"))]);
    let references = vec![CborValue::Unsigned(FIRST_TERM_ID); 20_000];
    // Key 3 is the plural form of `@type` (keyword id 2).
    let bytes = envelope(CborValue::Map(vec![
        (CborValue::Unsigned(0), context),
        (CborValue::Unsigned(3), CborValue::Array(references)),
    ]));
    assert!(bytes.len() < 128 * 1024, "input is {} bytes", bytes.len());
    let result = decompress(&bytes, &CborldOptions::default());
    assert!(
        is_resource(&result, "output_bytes"),
        "{:?}",
        result.as_ref().map(|_| "decoded")
    );
}

/// The same long term used as the key of 20,000 nested one-entry nodes.
#[test]
fn long_term_as_a_repeated_node_key_is_budgeted() {
    let _serial = smoke::measure_alone();
    let long_term = "k".repeat(64 * 1024);
    let context = CborValue::Map(vec![(text(&long_term), text("http://e/x"))]);
    let node = CborValue::Map(vec![(
        CborValue::Unsigned(FIRST_TERM_ID),
        CborValue::Unsigned(0),
    )]);
    let bytes = envelope(CborValue::Map(vec![
        (CborValue::Unsigned(0), context),
        (
            CborValue::Unsigned(FIRST_TERM_ID + 1),
            CborValue::Array(vec![node; 20_000]),
        ),
    ]));
    assert!(bytes.len() < 256 * 1024, "input is {} bytes", bytes.len());
    let result = decompress(&bytes, &CborldOptions::default());
    assert!(
        is_resource(&result, "output_bytes"),
        "{:?}",
        result.as_ref().map(|_| "decoded")
    );
}

/// A 3,000-term inline context followed by 3,000 empty child nodes.
///
/// Cloning the whole scope for every node costs 9 million term copies; the
/// decompressor must share an unchanged scope instead of copying it.
#[test]
fn unchanged_scope_is_not_copied_per_node() {
    let _serial = smoke::measure_alone();
    let mut context = Vec::new();
    for index in 0..3_000 {
        context.push((text(&format!("t{index:05}")), text("http://e/x")));
    }
    let empty = CborValue::Map(Vec::new());
    let bytes = envelope(CborValue::Map(vec![
        (CborValue::Unsigned(0), CborValue::Map(context)),
        (
            CborValue::Unsigned(FIRST_TERM_ID + 1),
            CborValue::Array(vec![empty; 3_000]),
        ),
    ]));
    let before = smoke::total_allocated();
    let result = decompress(&bytes, &CborldOptions::default());
    let spent = smoke::total_allocated().saturating_sub(before);
    assert!(result.is_ok(), "{result:?}");
    assert!(spent < 256 << 20, "decompress allocated {spent} bytes");
}

/// A registered 2,000-term context re-applied by 5,000 nodes of ~15 bytes.
#[test]
fn repeated_registered_context_application_is_budgeted() {
    let _serial = smoke::measure_alone();
    let mut terms = Map::new();
    for index in 0..2_000 {
        terms.insert(
            format!("p{index:05}"),
            Value::String(format!("http://e/{index}")),
        );
    }
    let mut provided = ProvidedContexts::new();
    provided.insert("urn:c", Value::Object(terms));
    let options = CborldOptions {
        provided_contexts: provided,
        ..CborldOptions::default()
    };
    let node = CborValue::Map(vec![(CborValue::Unsigned(0), text("urn:c"))]);
    let bytes = envelope(CborValue::Map(vec![
        (CborValue::Unsigned(0), text("urn:c")),
        (
            CborValue::Unsigned(FIRST_TERM_ID + 1),
            CborValue::Array(vec![node; 5_000]),
        ),
    ]));
    let before = smoke::total_allocated();
    let result = decompress(&bytes, &options);
    let spent = smoke::total_allocated().saturating_sub(before);
    assert!(
        is_resource(&result, "output_bytes") || spent < 256 << 20,
        "result {:?}, allocated {spent} bytes",
        result.as_ref().map(|_| "decoded")
    );
}
