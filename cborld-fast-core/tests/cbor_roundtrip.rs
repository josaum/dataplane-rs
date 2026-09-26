// Rust guideline compliant 2026-02-21
//! CBOR primitive layer: round-trips, canonical bytes, limits, rejections.

use cborld_fast_core::{
    CborldError,
    cbor::{CborLimits, CborValue, decode, encode_canonical},
};

fn roundtrip(value: &CborValue) -> CborValue {
    let limits = CborLimits::default();
    let bytes = encode_canonical(value, &limits).expect("encode");
    decode(&bytes, &limits).expect("decode")
}

fn encode_bytes(value: &CborValue) -> Vec<u8> {
    encode_canonical(value, &CborLimits::default()).expect("encode")
}

fn decode_err(bytes: &[u8]) -> CborldError {
    decode(bytes, &CborLimits::default()).expect_err("must fail")
}

#[test]
fn edge_integers_roundtrip_and_use_shortest_form() {
    let cases: [(u64, &[u8]); 8] = [
        (0, &[0x00]),
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (255, &[0x18, 0xff]),
        (256, &[0x19, 0x01, 0x00]),
        (65_535, &[0x19, 0xff, 0xff]),
        (65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        (
            u64::MAX,
            &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ];
    for (value, expected) in cases {
        let item = CborValue::Unsigned(value);
        assert_eq!(encode_bytes(&item), expected, "canonical bytes for {value}");
        assert_eq!(roundtrip(&item), item);
    }
}

#[test]
fn negative_integers_roundtrip_and_use_shortest_form() {
    // -1 encodes as Negative(0); i64::MIN encodes as Negative(i64::MAX).
    assert_eq!(encode_bytes(&CborValue::Negative(0)), [0x20]);
    assert_eq!(
        encode_bytes(&CborValue::Negative(i64::MAX as u64)),
        [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    for magnitude in [0u64, 23, 24, 255, 256, 65_535, 65_536, u64::MAX] {
        let item = CborValue::Negative(magnitude);
        assert_eq!(roundtrip(&item), item);
    }
}

#[test]
fn strings_arrays_maps_tags_and_simples_roundtrip() {
    // Entries are given in canonical (bytewise key) order, which the
    // encoder preserves and the decoder reports in wire order.
    let value = CborValue::Map(vec![
        (
            CborValue::Unsigned(7),
            CborValue::Array(vec![
                CborValue::Bool(true),
                CborValue::Bool(false),
                CborValue::Null,
                CborValue::Bytes(vec![0, 1, 2, 255]),
                CborValue::Tag(1234, Box::new(CborValue::Unsigned(5))),
            ]),
        ),
        (CborValue::Unsigned(8), CborValue::Float(1.5)),
        (
            CborValue::Text("text".to_string()),
            CborValue::Text("héllo".to_string()),
        ),
    ]);
    assert_eq!(roundtrip(&value), value);
}

#[test]
fn canonical_map_orders_keys_bytewise() {
    // Integer keys sort before text keys; entries are re-ordered on encode.
    let value = CborValue::Map(vec![
        (CborValue::Text("a".to_string()), CborValue::Unsigned(1)),
        (CborValue::Unsigned(10), CborValue::Unsigned(2)),
    ]);
    assert_eq!(encode_bytes(&value), [0xa2, 0x0a, 0x02, 0x61, b'a', 0x01]);
}

#[test]
fn duplicate_map_keys_are_rejected_on_encode() {
    let value = CborValue::Map(vec![
        (CborValue::Unsigned(1), CborValue::Null),
        (CborValue::Unsigned(1), CborValue::Bool(true)),
    ]);
    let error = encode_canonical(&value, &CborLimits::default()).expect_err("must fail");
    assert_eq!(error.code(), "cbor_encode");
}

#[test]
fn duplicate_map_keys_are_rejected_on_decode() {
    // {10: 0, 10: 1} with the second key in non-shortest form (0x18 0x0a).
    let error = decode_err(&[0xa2, 0x0a, 0x00, 0x18, 0x0a, 0x01]);
    assert_eq!(error.code(), "cbor_decode");
    assert!(error.to_string().contains("duplicate map key"));
}

#[test]
fn non_shortest_integer_heads_are_accepted_on_decode() {
    let limits = CborLimits::default();
    assert_eq!(
        decode(&[0x18, 0x00], &limits).expect("decode"),
        CborValue::Unsigned(0)
    );
}

#[test]
fn floats_roundtrip_and_halves_widen() {
    let limits = CborLimits::default();
    // 1.5 is exactly half-precision-representable: preferred form 0xf93e00.
    assert_eq!(encode_bytes(&CborValue::Float(1.5)), [0xf9, 0x3e, 0x00]);
    // f16 1.0 = 0x3c00; f32 -2.5 = 0xc0200000.
    assert_eq!(
        decode(&[0xf9, 0x3c, 0x00], &limits).expect("f16"),
        CborValue::Float(1.0)
    );
    assert_eq!(
        decode(&[0xfa, 0xc0, 0x20, 0x00, 0x00], &limits).expect("f32"),
        CborValue::Float(-2.5)
    );
    assert_eq!(roundtrip(&CborValue::Float(-0.1)), CborValue::Float(-0.1));
}

#[test]
fn preferred_float_serialization_picks_the_shortest_exact_form() {
    // RFC 8949 §4.2.1: shortest of half, single, double that is exact.
    let single_only = f64::from(f32::from_bits(0x3dcc_cccd)); // ~0.1f32
    assert_eq!(
        encode_bytes(&CborValue::Float(single_only)),
        [0xfa, 0x3d, 0xcc, 0xcc, 0xcd]
    );
    assert_eq!(
        encode_bytes(&CborValue::Float(-0.1)),
        [0xfb, 0xbf, 0xb9, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a]
    );
    assert_eq!(
        encode_bytes(&CborValue::Float(f64::INFINITY)),
        [0xf9, 0x7c, 0x00]
    );
    assert_eq!(
        encode_bytes(&CborValue::Float(f64::NEG_INFINITY)),
        [0xf9, 0xfc, 0x00]
    );
    assert_eq!(
        encode_bytes(&CborValue::Float(f64::NAN)),
        [0xf9, 0x7e, 0x00]
    );
    // Signed zero survives the narrowing to half precision.
    assert_eq!(encode_bytes(&CborValue::Float(0.0)), [0xf9, 0x00, 0x00]);
    assert_eq!(encode_bytes(&CborValue::Float(-0.0)), [0xf9, 0x80, 0x00]);
    // Smallest half subnormal (2^-24) and a value one ulp beyond it.
    let subnormal = (-24f64).exp2();
    assert_eq!(
        encode_bytes(&CborValue::Float(subnormal)),
        [0xf9, 0x00, 0x01]
    );
    assert_eq!(
        encode_bytes(&CborValue::Float((-25f64).exp2()))[0],
        0xfa,
        "2^-25 is not half-representable and must widen"
    );
}

#[test]
fn every_half_precision_value_reencodes_to_itself() {
    // Exhaustive inverse check: decoding any non-NaN half and re-encoding
    // it canonically must reproduce the original three bytes.
    let limits = CborLimits::default();
    for half in 0..=u16::MAX {
        let exponent = (half >> 10) & 0x1f;
        let mantissa = half & 0x3ff;
        if exponent == 0x1f && mantissa != 0 {
            continue; // NaN payloads canonicalize to 0x7e00.
        }
        let [hi, lo] = half.to_be_bytes();
        let decoded = decode(&[0xf9, hi, lo], &limits).expect("decode half");
        assert_eq!(
            encode_canonical(&decoded, &limits).expect("encode"),
            [0xf9, hi, lo],
            "half {half:#06x} must re-encode to itself"
        );
    }
}

#[test]
fn indefinite_length_items_are_rejected() {
    for lead in [0x5f, 0x7f, 0x9f, 0xbf] {
        let error = decode_err(&[lead, 0xff]);
        assert_eq!(error.code(), "cbor_decode", "lead byte {lead:#x}");
        assert!(error.to_string().contains("indefinite"));
    }
}

#[test]
fn truncated_inputs_are_rejected() {
    for bytes in [
        &[0x18][..],             // integer head without payload
        &[0x62, b'a'][..],       // text declared 2 bytes, has 1
        &[0x82, 0x01][..],       // array declared 2 items, has 1
        &[0x59, 0xff, 0xff][..], // byte string declared 65535 bytes
        &[0xfb, 0x00, 0x00][..], // f64 head without 8 bytes
    ] {
        assert_eq!(decode_err(bytes).code(), "cbor_decode");
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let error = decode_err(&[0x01, 0x02]);
    assert!(error.to_string().contains("trailing"));
}

#[test]
fn refused_simple_values_and_reserved_heads_are_rejected() {
    assert_eq!(decode_err(&[0xf7]).code(), "cbor_decode"); // undefined
    assert_eq!(decode_err(&[0xf0]).code(), "cbor_decode"); // simple 16
    assert_eq!(decode_err(&[0xf8, 0x20]).code(), "cbor_decode"); // simple 32
    assert_eq!(decode_err(&[0x1c]).code(), "cbor_decode"); // reserved ai 28
    assert_eq!(decode_err(&[0xff]).code(), "cbor_decode"); // stray break
}

#[test]
fn invalid_utf8_text_is_rejected() {
    let error = decode_err(&[0x62, 0xff, 0xfe]);
    assert!(error.to_string().contains("UTF-8"));
}

#[test]
fn input_byte_limit_is_enforced() {
    let limits = CborLimits {
        max_input_bytes: 4,
        ..CborLimits::default()
    };
    let error = decode(&[0x45, 1, 2, 3, 4, 5], &limits).expect_err("must fail");
    assert_eq!(error.code(), "resource_limit");
    assert!(error.to_string().contains("input_bytes"));
}

#[test]
fn depth_limit_is_enforced_on_decode() {
    // [[[[0]]]] has depth 5; limit 4 must reject it and limit 5 accept it.
    let bytes = [0x81, 0x81, 0x81, 0x81, 0x00];
    let tight = CborLimits {
        max_depth: 4,
        ..CborLimits::default()
    };
    let error = decode(&bytes, &tight).expect_err("must fail");
    assert_eq!(error.code(), "resource_limit");
    assert!(error.to_string().contains("depth"));
    let loose = CborLimits {
        max_depth: 5,
        ..CborLimits::default()
    };
    assert!(decode(&bytes, &loose).is_ok());
}

#[test]
fn depth_limit_is_enforced_on_encode() {
    let mut value = CborValue::Unsigned(0);
    for _ in 0..10 {
        value = CborValue::Array(vec![value]);
    }
    let limits = CborLimits {
        max_depth: 5,
        ..CborLimits::default()
    };
    let error = encode_canonical(&value, &limits).expect_err("must fail");
    assert_eq!(error.code(), "resource_limit");
}

#[test]
fn item_limit_is_enforced_on_decode() {
    let bytes = [0x84, 0x00, 0x01, 0x02, 0x03]; // 5 items total
    let limits = CborLimits {
        max_items: 4,
        ..CborLimits::default()
    };
    let error = decode(&bytes, &limits).expect_err("must fail");
    assert_eq!(error.code(), "resource_limit");
    assert!(error.to_string().contains("items"));
}
