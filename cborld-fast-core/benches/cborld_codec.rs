// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Criterion benchmarks for the CBOR-LD hot paths.
//!
//! Three groups, each an input-size sweep so a regression shows up as a
//! change of slope rather than a single number that has to be remembered:
//!
//! - `cborld_document` — [`compress`] and [`decompress`] over a verifiable
//!   credential shaped like the ones the vendored registry entries target
//!   (inline `@context`, `did:key:` issuer, `xsd:date`/`xsd:dateTime`
//!   terms, a `sec:multibase` proof value), swept over 1, 4, 16, and 64
//!   credential subjects. Throughput is the JSON byte length, so the
//!   reported figure is comparable across sizes.
//! - `cbor_subset` — the hand-rolled [`encode_canonical`]/[`decode`] pair
//!   on their own, over maps of 16, 64, 256, and 1,024 mixed-type entries.
//!   Both directions sort and de-duplicate map keys, so this sweep is where
//!   an accidental quadratic in the canonical-form machinery would show.
//! - `value_codec` — the base58btc and base64 value codecs, reached through
//!   the public API by way of a `did:key:` value and a `data:` URL.
//!
//! # Why the value-codec sweep runs to the limit
//!
//! base58btc has no chunk boundary: every digit carries into the whole
//! accumulator, so both directions are quadratic in the string length. The
//! only thing standing between that and a denial of service is
//! `CborLimits::max_value_bytes`, whose default is 8 KiB. The sweep
//! therefore runs 1, 2, 4, and 8 KiB — the last sitting exactly on the
//! bound — so the cost the bound actually admits is measured rather than
//! assumed. The base64 sweep uses the identical sizes as the linear
//! control: the two curves diverging is the point.
//!
//! `compress` costs roughly twice `decompress` for the same value, because
//! compression is guarded by a decode → re-encode → compare check before it
//! will emit a compressed form at all.

use std::{hint::black_box, time::Duration};

use cborld_fast_core::{
    CborldOptions,
    cbor::{CborLimits, CborValue, decode, encode_canonical},
    compress, decompress,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde_json::{Value, json};

/// Deterministic byte source; benchmarks must not vary run to run.
///
/// A 64-bit linear congruential generator with the constants Donald Knuth
/// lists in TAOCP volume 2, chosen only because they are well known and
/// full-period. No cryptographic property is needed or claimed.
struct Lcg {
    state: u64,
}

impl Lcg {
    /// Creates a generator from a fixed seed.
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next byte of the sequence.
    fn byte(&mut self) -> u8 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.state >> 33) as u8
    }

    /// Returns `count` deterministic bytes.
    fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| self.byte()).collect()
    }
}

/// base58btc alphabet, matching `cborld_fast_core::registry`.
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// RFC 4648 §4 alphabet, for the `data:` URL payloads.
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `bytes` as canonical base58btc.
///
/// The crate's own encoder is private, and a benchmark that fed the codec a
/// *non-canonical* string would measure the passthrough branch instead of
/// the compressing one — so the input has to be built here.
fn base58_encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut().rev() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.insert(0, (carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for digit in digits {
        out.push(char::from(BASE58[usize::from(digit)]));
    }
    out
}

/// Encodes `bytes` as padded RFC 4648 §4 base64.
fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = chunk.get(1).map(|byte| u32::from(*byte));
        let third = chunk.get(2).map(|byte| u32::from(*byte));
        out.push(char::from(BASE64[(first >> 2) as usize]));
        out.push(char::from(
            BASE64[((first << 4 | second.unwrap_or(0) >> 4) & 0x3f) as usize],
        ));
        match second {
            Some(second) => out.push(char::from(
                BASE64[((second << 2 | third.unwrap_or(0) >> 6) & 0x3f) as usize],
            )),
            None => out.push('='),
        }
        match third {
            Some(third) => out.push(char::from(BASE64[(third & 0x3f) as usize])),
            None => out.push('='),
        }
    }
    out
}

/// Returns a canonical base58btc string of at most `max_chars` characters.
///
/// base58 expands one byte to about 1.365 characters, so the byte count is
/// estimated and then trimmed until the encoding fits. Staying under the
/// bound matters: one character over `max_value_bytes` and the codec passes
/// the value through untouched, which would benchmark nothing at all.
fn base58_body(max_chars: usize) -> String {
    let mut count = max_chars * 3 / 4;
    loop {
        let mut source = Lcg::new(0x5EED_0BAD_C0DE_1234);
        let text = base58_encode(&source.bytes(count));
        if text.len() <= max_chars {
            return text;
        }
        count -= count / 16 + 1;
    }
}

/// Returns a canonical padded base64 string of at most `max_chars` bytes.
fn base64_body(max_chars: usize) -> String {
    let mut source = Lcg::new(0x0BAD_5EED_1234_C0DE);
    base64_encode(&source.bytes(max_chars / 4 * 3))
}

/// Counts byte strings of 256 bytes or more in an encoded envelope.
///
/// A value the base58 or base64 codec compressed rides as a CBOR byte
/// string; one that passed through stays a text string. Counting the large
/// byte strings is therefore a direct check that the benchmark is timing
/// the codec rather than a `String` clone.
fn decoded_byte_strings(envelope: &[u8]) -> usize {
    /// Recursively counts qualifying byte strings in one decoded item.
    fn walk(value: &CborValue) -> usize {
        match value {
            CborValue::Bytes(bytes) => usize::from(bytes.len() >= 256),
            CborValue::Array(items) => items.iter().map(walk).sum(),
            CborValue::Map(entries) => entries
                .iter()
                .map(|(key, member)| walk(key) + walk(member))
                .sum(),
            CborValue::Tag(_, inner) => walk(inner),
            _ => 0,
        }
    }
    let limits = CborLimits::default();
    walk(&decode(envelope, &limits).expect("benchmark envelope decodes"))
}

/// Sizes swept by the value-codec group, in characters.
///
/// The last entry is `CborLimits::max_value_bytes`'s default, so the
/// measurement covers the most expensive value the bound still admits.
const VALUE_SIZES: [usize; 4] = [1024, 2048, 4096, 8192];

/// Builds a verifiable credential with `subjects` credential subjects.
///
/// The context is inline (the codec never fetches) and exercises every
/// codec the default processing model binds: the URL codec through
/// `@type: @id`, the XSD date and dateTime codecs, and the multibase codec
/// through a `sec:multibase` proof value.
fn credential(subjects: usize) -> Value {
    // Node identifiers use the literal `@id` key rather than the customary
    // `"id": "@id"` alias: `table_type` gives the URL codec to `@id`/`@type`
    // keys, to a `@type` alias, and to terms typed `@id`/`@vocab` — but not
    // to an `@id` alias, so the aliased spelling would benchmark the
    // passthrough branch instead of the codec.
    let context = json!({
        "type": "@type",
        "issuer": {"@id": "https://example.org/vocab#issuer", "@type": "@id"},
        "validFrom": {
            "@id": "https://example.org/vocab#validFrom",
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "birthDate": {
            "@id": "https://example.org/vocab#birthDate",
            "@type": "http://www.w3.org/2001/XMLSchema#date"
        },
        "name": "https://example.org/vocab#name",
        "score": "https://example.org/vocab#score",
        "credentialSubject": {
            "@id": "https://example.org/vocab#credentialSubject",
            "@type": "@id"
        },
        "proofValue": {
            "@id": "https://w3id.org/security#proofValue",
            "@type": "https://w3id.org/security#multibase"
        }
    });
    let mut source = Lcg::new(0xC0DE_C0DE_C0DE_C0DE);
    let subjects: Vec<Value> = (0..subjects)
        .map(|index| {
            json!({
                "@id": format!("https://example.org/subjects/{index}"),
                "name": format!("Subject {index}"),
                "birthDate": "1988-04-17",
                "score": index,
                "proofValue": format!("z{}", base58_encode(&source.bytes(32)))
            })
        })
        .collect();
    json!({
        "@context": context,
        "@id": format!("urn:uuid:{:08x}-1111-4222-8333-444455556666", subjects.len()),
        "type": "https://example.org/vocab#ExampleCredential",
        "issuer": format!("did:key:z{}", base58_encode(&source.bytes(34))),
        "validFrom": "2026-09-01T12:34:56Z",
        "credentialSubject": subjects
    })
}

/// Builds a CBOR map of `entries` mixed-type members for the subset bench.
fn cbor_map(entries: usize) -> CborValue {
    let mut source = Lcg::new(0x1234_5678_9ABC_DEF0);
    let members = (0..entries)
        .map(|index| {
            let key = CborValue::Text(format!("member-{index:05}"));
            let value = match index % 6 {
                0 => CborValue::Unsigned(u64::try_from(index).unwrap_or(0) * 1_000_003),
                1 => CborValue::Negative(u64::try_from(index).unwrap_or(0)),
                2 => CborValue::Text(format!("https://example.org/values/{index}")),
                3 => CborValue::Bytes(source.bytes(24)),
                4 => CborValue::Float(f64::from(u32::try_from(index).unwrap_or(0)) / 8.0),
                _ => CborValue::Array(vec![
                    CborValue::Bool(index.is_multiple_of(2)),
                    CborValue::Null,
                    CborValue::Unsigned(u64::try_from(index).unwrap_or(0)),
                ]),
            };
            (key, value)
        })
        .collect();
    CborValue::Map(members)
}

/// Benchmarks `compress`/`decompress` over a swept credential document.
fn bench_document_codec(criterion: &mut Criterion) {
    let options = CborldOptions::default();
    let mut group = criterion.benchmark_group("cborld_document");
    for subjects in [1_usize, 4, 16, 64] {
        let document = credential(subjects);
        let json_len = document.to_string().len();
        let envelope = compress(&document, &options).expect("representative credential compresses");
        group.throughput(Throughput::Bytes(json_len as u64));
        group.bench_with_input(
            BenchmarkId::new("compress", subjects),
            &document,
            |bencher, document| {
                bencher.iter(|| compress(black_box(document), black_box(&options)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("decompress", subjects),
            &envelope,
            |bencher, envelope| {
                bencher.iter(|| decompress(black_box(envelope.as_slice()), black_box(&options)));
            },
        );
    }
    group.finish();
}

/// Benchmarks the hand-rolled CBOR encoder and decoder in isolation.
fn bench_cbor_subset(criterion: &mut Criterion) {
    let limits = CborLimits::default();
    let mut group = criterion.benchmark_group("cbor_subset");
    for entries in [16_usize, 64, 256, 1024] {
        let value = cbor_map(entries);
        let bytes = encode_canonical(&value, &limits).expect("generated map encodes");
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("encode_canonical", entries),
            &value,
            |bencher, value| {
                bencher.iter(|| encode_canonical(black_box(value), black_box(&limits)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("decode", entries),
            &bytes,
            |bencher, bytes| {
                bencher.iter(|| decode(black_box(bytes.as_slice()), black_box(&limits)));
            },
        );
    }
    group.finish();
}

/// Benchmarks the base58btc and base64 value codecs against the byte bound.
fn bench_value_codecs(criterion: &mut Criterion) {
    let options = CborldOptions::default();
    let mut group = criterion.benchmark_group("value_codec");
    // The 8 KiB base58 point costs hundreds of milliseconds an iteration,
    // which is the finding, not an accident; the default 100 samples would
    // turn one run into minutes.
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));

    for size in VALUE_SIZES {
        let did = format!("did:key:z{}", base58_body(size));
        let data = format!("data:application/octet-stream;base64,{}", base64_body(size));
        let document = json!({
            "@context": {
                "issuer": {"@id": "https://example.org/vocab#issuer", "@type": "@id"},
                "attachment": {"@id": "https://example.org/vocab#attachment", "@type": "@id"}
            },
            "issuer": did,
            "attachment": data
        });
        let envelope = compress(&document, &options).expect("value-codec document compresses");
        // Both values must have taken their *compressing* branch, or the
        // sweep silently measures a string copy. A passthrough leaves the
        // value a text string, so requiring a byte string longer than half
        // the input pins the codec down: base58 and base64 both shrink by
        // less than half, and nothing else in this document emits bytes.
        assert!(
            decoded_byte_strings(&envelope) >= 2,
            "value at {size} characters did not take the codec branch"
        );
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("base58_and_base64/compress", size),
            &document,
            |bencher, document| {
                bencher.iter(|| compress(black_box(document), black_box(&options)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("base58_and_base64/decompress", size),
            &envelope,
            |bencher, envelope| {
                bencher.iter(|| decompress(black_box(envelope.as_slice()), black_box(&options)));
            },
        );

        // base64 on its own, as the linear control the base58 curve is
        // meant to be read against.
        let base64_only = json!({
            "@context": {"attachment": {
                "@id": "https://example.org/vocab#attachment",
                "@type": "@id"
            }},
            "attachment": format!("data:application/octet-stream;base64,{}", base64_body(size))
        });
        let base64_envelope =
            compress(&base64_only, &options).expect("data URL document compresses");
        group.bench_with_input(
            BenchmarkId::new("base64_only/compress", size),
            &base64_only,
            |bencher, document| {
                bencher.iter(|| compress(black_box(document), black_box(&options)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("base64_only/decompress", size),
            &base64_envelope,
            |bencher, envelope| {
                bencher.iter(|| decompress(black_box(envelope.as_slice()), black_box(&options)));
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_document_codec,
    bench_cbor_subset,
    bench_value_codecs
);
criterion_main!(benches);
