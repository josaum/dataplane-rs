// Rust guideline compliant 2026-02-21
//! Minimal, fail-closed CBOR encoder and decoder for the CBOR-LD data model.
//!
//! This module hand-rolls the CBOR subset required by CBOR-LD 1.0 instead of
//! pulling in an external CBOR crate. The supported data model is: unsigned
//! and negative integers, byte strings, text strings, arrays, maps, tags,
//! `false`/`true`/`null`, and 64-bit floats.
//!
//! # Canonical form
//!
//! [`encode_canonical`] implements the following RFC 8949 §4.2.1 core
//! deterministic encoding requirements:
//!
//! - integer heads (values, lengths, and tag numbers) use the shortest form;
//! - indefinite-length items are never produced;
//! - map keys are sorted by the bytewise lexicographic order of their
//!   canonical encodings, and duplicate keys are rejected;
//! - floats use the preferred serialization: the shortest of half, single,
//!   and double precision that preserves the exact value (analysis rejects
//!   any narrowing that would not widen back bit-identically), and NaN
//!   encodes as the canonical half-precision NaN `0xf97e00`.
//!
//! # Fail-closed decoding
//!
//! [`decode`] enforces [`CborLimits`] and rejects, with explicit errors:
//! indefinite-length items, reserved additional-information values, simple
//! values other than `false`/`true`/`null` (including `undefined`), invalid
//! UTF-8 in text strings, truncated input, trailing bytes, and duplicate map
//! keys. Non-shortest-form integer heads are accepted on decode so payloads
//! from encoders that do not apply preferred serialization still parse.
//! Half- and single-precision floats are accepted and widened to `f64`.

use crate::error::{CborldError, CborldResource};

/// Default maximum encoded input size accepted by the decoder: 16 MiB.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// Default maximum nesting depth for CBOR items and JSON values.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// Default maximum number of CBOR data items decoded from one payload.
pub const DEFAULT_MAX_ITEMS: usize = 1_048_576;

/// Default maximum byte length of one compressed value codec payload: 8 KiB.
pub const DEFAULT_MAX_VALUE_BYTES: usize = 8 * 1024;

/// Fail-closed limits for CBOR decoding and CBOR-LD conversion.
#[derive(Clone, Copy, Debug)]
pub struct CborLimits {
    /// Maximum encoded input size in bytes accepted by the decoder.
    pub max_input_bytes: usize,
    /// Maximum nesting depth of CBOR items and JSON values.
    pub max_depth: usize,
    /// Maximum number of CBOR data items decoded from one payload.
    pub max_items: usize,
    /// Maximum byte length of one compressed value codec payload (the
    /// base58/base64 work done by the DID URL, Data URL, and Multibase
    /// codecs). Longer strings pass through uncompressed on encode; longer
    /// byte strings are a typed error on decode.
    pub max_value_bytes: usize,
}

impl Default for CborLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_items: DEFAULT_MAX_ITEMS,
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
        }
    }
}

/// One CBOR data item in the subset used by CBOR-LD.
#[derive(Clone, Debug, PartialEq)]
pub enum CborValue {
    /// Major type 0: unsigned integer.
    Unsigned(u64),
    /// Major type 1: negative integer; `Negative(n)` denotes `-1 - n`.
    Negative(u64),
    /// Major type 2: byte string.
    Bytes(Vec<u8>),
    /// Major type 3: text string.
    Text(String),
    /// Major type 4: array.
    Array(Vec<CborValue>),
    /// Major type 5: map, as an entry list in wire order.
    Map(Vec<(CborValue, CborValue)>),
    /// Major type 6: tagged item.
    Tag(u64, Box<CborValue>),
    /// Major type 7: `false` (0xf4) or `true` (0xf5).
    Bool(bool),
    /// Major type 7: `null` (0xf6).
    Null,
    /// Major type 7: floating-point number, widened to `f64`.
    Float(f64),
}

fn depth_error(limit: usize, observed: usize) -> CborldError {
    CborldError::ResourceLimit {
        resource: CborldResource::Depth,
        limit,
        observed,
    }
}

fn write_head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let major = major << 5;
    if argument < 24 {
        out.push(major | u8::try_from(argument).unwrap_or(23));
    } else if argument <= u64::from(u8::MAX) {
        out.push(major | 24);
        out.push(argument as u8);
    } else if argument <= u64::from(u16::MAX) {
        out.push(major | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= u64::from(u32::MAX) {
        out.push(major | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

fn encode_into(
    value: &CborValue,
    out: &mut Vec<u8>,
    limits: &CborLimits,
    depth: usize,
) -> Result<(), CborldError> {
    if depth > limits.max_depth {
        return Err(depth_error(limits.max_depth, depth));
    }
    match value {
        CborValue::Unsigned(n) => write_head(out, 0, *n),
        CborValue::Negative(n) => write_head(out, 1, *n),
        CborValue::Bytes(bytes) => {
            write_head(out, 2, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        CborValue::Text(text) => {
            write_head(out, 3, text.len() as u64);
            out.extend_from_slice(text.as_bytes());
        }
        CborValue::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out, limits, depth + 1)?;
            }
        }
        CborValue::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
            for (key, val) in entries {
                let mut key_bytes = Vec::new();
                encode_into(key, &mut key_bytes, limits, depth + 1)?;
                let mut val_bytes = Vec::new();
                encode_into(val, &mut val_bytes, limits, depth + 1)?;
                encoded.push((key_bytes, val_bytes));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            for pair in encoded.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(CborldError::Encode("duplicate map key".to_string()));
                }
            }
            write_head(out, 5, encoded.len() as u64);
            for (key_bytes, val_bytes) in encoded {
                out.extend_from_slice(&key_bytes);
                out.extend_from_slice(&val_bytes);
            }
        }
        CborValue::Tag(tag, inner) => {
            write_head(out, 6, *tag);
            encode_into(inner, out, limits, depth + 1)?;
        }
        CborValue::Bool(flag) => out.push(if *flag { 0xf5 } else { 0xf4 }),
        CborValue::Null => out.push(0xf6),
        CborValue::Float(number) => write_float_preferred(out, *number),
    }
    Ok(())
}

/// Writes one float in the RFC 8949 §4.2.1 preferred serialization: the
/// shortest of half, single, and double precision whose widening back to
/// `f64` reproduces the exact bit pattern. NaN encodes as the canonical
/// half-precision NaN `0xf97e00`.
fn write_float_preferred(out: &mut Vec<u8>, value: f64) {
    if value.is_nan() {
        out.extend_from_slice(&[0xf9, 0x7e, 0x00]);
    } else if let Some(half) = f64_to_half(value) {
        out.push(0xf9);
        out.extend_from_slice(&half.to_be_bytes());
    } else if f64::from(value as f32).to_bits() == value.to_bits() {
        out.push(0xfa);
        out.extend_from_slice(&(value as f32).to_bits().to_be_bytes());
    } else {
        out.push(0xfb);
        out.extend_from_slice(&value.to_bits().to_be_bytes());
    }
}

/// Returns the half-precision bit pattern of `value` when the narrowing is
/// exact (the inverse of [`half_to_f64`]), `None` otherwise. The caller
/// handles NaN before calling.
fn f64_to_half(value: f64) -> Option<u16> {
    let bits = value.to_bits();
    let sign = ((bits >> 48) & 0x8000) as u16;
    if value == 0.0 {
        return Some(sign);
    }
    if value.is_infinite() {
        return Some(sign | 0x7c00);
    }
    let exponent = ((bits >> 52) & 0x7ff) as i64 - 1023;
    let fraction = bits & 0x000f_ffff_ffff_ffff;
    if (-14..=15).contains(&exponent) {
        // Normal half: the 52-bit fraction must fit in 10 mantissa bits.
        if fraction & ((1 << 42) - 1) != 0 {
            return None;
        }
        let mantissa = (fraction >> 42) as u16;
        return Some(sign | ((exponent + 15) as u16) << 10 | mantissa);
    }
    if (-24..-14).contains(&exponent) {
        // Subnormal half: the value must be an exact multiple of 2^-24.
        let drop = u32::try_from(28 - exponent).expect("range checked above");
        let significand = (1u64 << 52) | fraction;
        if significand & ((1u64 << drop) - 1) != 0 {
            return None;
        }
        return Some(sign | (significand >> drop) as u16);
    }
    None
}

/// Encodes one CBOR item in the canonical form documented for this module.
///
/// # Errors
///
/// Returns [`CborldError::ResourceLimit`] when nesting exceeds
/// `limits.max_depth`, and [`CborldError::Encode`] when a map contains
/// duplicate keys.
pub fn encode_canonical(value: &CborValue, limits: &CborLimits) -> Result<Vec<u8>, CborldError> {
    let mut out = Vec::new();
    encode_into(value, &mut out, limits, 1)?;
    Ok(out)
}

struct Decoder<'bytes> {
    bytes: &'bytes [u8],
    pos: usize,
    items: usize,
    limits: CborLimits,
}

impl<'bytes> Decoder<'bytes> {
    fn error(&self, detail: impl Into<String>) -> CborldError {
        CborldError::Decode {
            offset: self.pos,
            detail: detail.into(),
        }
    }

    fn take(&mut self, count: usize) -> Result<&'bytes [u8], CborldError> {
        let end = self
            .pos
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| self.error("truncated input"))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, CborldError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => Ok(u64::from(self.take(1)?[0])),
            25 => Ok(u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().expect("length checked"),
            ))),
            26 => Ok(u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().expect("length checked"),
            ))),
            27 => Ok(u64::from_be_bytes(
                self.take(8)?.try_into().expect("length checked"),
            )),
            28..=30 => Err(self.error("reserved additional-information value")),
            _ => Err(self.error("indefinite-length item is refused")),
        }
    }

    fn read_length(&mut self, additional: u8, what: &str) -> Result<usize, CborldError> {
        let length = self.read_argument(additional)?;
        let remaining = (self.bytes.len() - self.pos) as u64;
        if length > remaining {
            return Err(self.error(format!("{what} length {length} exceeds remaining input")));
        }
        Ok(usize::try_from(length).expect("bounded by input size"))
    }

    fn count_item(&mut self) -> Result<(), CborldError> {
        self.items += 1;
        if self.items > self.limits.max_items {
            return Err(CborldError::ResourceLimit {
                resource: CborldResource::Items,
                limit: self.limits.max_items,
                observed: self.items,
            });
        }
        Ok(())
    }

    fn decode_item(&mut self, depth: usize) -> Result<CborValue, CborldError> {
        if depth > self.limits.max_depth {
            return Err(depth_error(self.limits.max_depth, depth));
        }
        self.count_item()?;
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(CborValue::Unsigned(self.read_argument(additional)?)),
            1 => Ok(CborValue::Negative(self.read_argument(additional)?)),
            2 => {
                let length = self.read_length(additional, "byte string")?;
                Ok(CborValue::Bytes(self.take(length)?.to_vec()))
            }
            3 => {
                let length = self.read_length(additional, "text string")?;
                let start = self.pos;
                let raw = self.take(length)?;
                match std::str::from_utf8(raw) {
                    Ok(text) => Ok(CborValue::Text(text.to_string())),
                    Err(_) => Err(CborldError::Decode {
                        offset: start,
                        detail: "text string is not valid UTF-8".to_string(),
                    }),
                }
            }
            4 => {
                let length = self.read_length(additional, "array")?;
                let mut items = Vec::with_capacity(length.min(4096));
                for _ in 0..length {
                    items.push(self.decode_item(depth + 1)?);
                }
                Ok(CborValue::Array(items))
            }
            5 => {
                let length = self.read_length(additional, "map")?;
                let mut entries = Vec::with_capacity(length.min(4096));
                for _ in 0..length {
                    let key = self.decode_item(depth + 1)?;
                    let value = self.decode_item(depth + 1)?;
                    entries.push((key, value));
                }
                self.check_duplicate_keys(&entries, depth)?;
                Ok(CborValue::Map(entries))
            }
            6 => {
                let tag = self.read_argument(additional)?;
                let inner = self.decode_item(depth + 1)?;
                Ok(CborValue::Tag(tag, Box::new(inner)))
            }
            _ => self.decode_simple_or_float(additional),
        }
    }

    fn decode_simple_or_float(&mut self, additional: u8) -> Result<CborValue, CborldError> {
        match additional {
            20 => Ok(CborValue::Bool(false)),
            21 => Ok(CborValue::Bool(true)),
            22 => Ok(CborValue::Null),
            23 => Err(self.error("simple value undefined (0xf7) is refused")),
            25 => {
                let raw = u16::from_be_bytes(self.take(2)?.try_into().expect("length checked"));
                Ok(CborValue::Float(half_to_f64(raw)))
            }
            26 => {
                let raw = u32::from_be_bytes(self.take(4)?.try_into().expect("length checked"));
                Ok(CborValue::Float(f64::from(f32::from_bits(raw))))
            }
            27 => {
                let raw = u64::from_be_bytes(self.take(8)?.try_into().expect("length checked"));
                Ok(CborValue::Float(f64::from_bits(raw)))
            }
            31 => Err(self.error("indefinite-length break (0xff) is refused")),
            other => Err(self.error(format!("unassigned simple value {other} is refused"))),
        }
    }

    fn check_duplicate_keys(
        &self,
        entries: &[(CborValue, CborValue)],
        depth: usize,
    ) -> Result<(), CborldError> {
        let mut encoded_keys: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
        for (key, _) in entries {
            let mut bytes = Vec::new();
            encode_into(key, &mut bytes, &self.limits, depth + 1)?;
            encoded_keys.push(bytes);
        }
        encoded_keys.sort_unstable();
        for pair in encoded_keys.windows(2) {
            if pair[0] == pair[1] {
                return Err(CborldError::Decode {
                    offset: self.pos,
                    detail: "duplicate map key".to_string(),
                });
            }
        }
        Ok(())
    }
}

fn half_to_f64(raw: u16) -> f64 {
    let sign = if raw & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exponent = (raw >> 10) & 0x1f;
    let mantissa = f64::from(raw & 0x3ff);
    let magnitude = match exponent {
        0 => mantissa * (-24f64).exp2(),
        0x1f => {
            if mantissa == 0.0 {
                f64::INFINITY
            } else {
                f64::NAN
            }
        }
        _ => (1.0 + mantissa / 1024.0) * f64::from(i32::from(exponent) - 15).exp2(),
    };
    sign * magnitude
}

/// Decodes exactly one CBOR item from `bytes`, consuming all input.
///
/// # Errors
///
/// Returns [`CborldError::ResourceLimit`] when `bytes` exceeds
/// `limits.max_input_bytes` or decoding exceeds the depth or item budget,
/// and [`CborldError::Decode`] for malformed input: truncation, trailing
/// bytes, indefinite-length items, reserved additional-information values,
/// refused simple values, invalid UTF-8, and duplicate map keys.
pub fn decode(bytes: &[u8], limits: &CborLimits) -> Result<CborValue, CborldError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(CborldError::ResourceLimit {
            resource: CborldResource::InputBytes,
            limit: limits.max_input_bytes,
            observed: bytes.len(),
        });
    }
    let mut decoder = Decoder {
        bytes,
        pos: 0,
        items: 0,
        limits: *limits,
    };
    let value = decoder.decode_item(1)?;
    if decoder.pos != bytes.len() {
        return Err(CborldError::Decode {
            offset: decoder.pos,
            detail: "trailing bytes after top-level item".to_string(),
        });
    }
    Ok(value)
}
