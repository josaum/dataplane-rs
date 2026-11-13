// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Integer/byte-string conversions for registry compression sub-tables.
//!
//! CBOR-LD 1.0's "Value Codec" encodes a sub-table identifier either as a
//! CBOR unsigned integer or, for the table types listed in
//! [`crate::registry::TYPES_ENCODED_AS_BYTES`], as a CBOR byte string
//! holding the integer's binary form. The same section encodes a *literal*
//! integer value under a table-backed typed term as a signed byte string,
//! which is what keeps it distinguishable from a table identifier.
//!
//! The specification does not fix a byte length, so this module defines the
//! shortest form and refuses every other spelling on decode, matching the
//! canonical-shortest-form discipline the CBOR layer already enforces.

use crate::error::CborldError;

/// Encodes `value` as the shortest big-endian unsigned byte string.
///
/// Zero encodes as a single `0x00` byte; no other encoding carries a leading
/// zero byte.
pub(crate) fn unsigned_to_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let full = value.to_be_bytes();
    let first = full
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(full.len() - 1);
    full[first..].to_vec()
}

/// Decodes a shortest-form big-endian unsigned byte string.
///
/// # Errors
///
/// Returns [`CborldError::Envelope`] for an empty string, for more than
/// eight bytes, and for a non-shortest spelling (a leading zero byte).
pub(crate) fn unsigned_from_bytes(bytes: &[u8]) -> Result<u64, CborldError> {
    let [first, rest @ ..] = bytes else {
        return Err(CborldError::Envelope(
            "compression table identifier must not be an empty byte string".to_string(),
        ));
    };
    if bytes.len() > 8 {
        return Err(CborldError::Envelope(format!(
            "compression table identifier of {} bytes exceeds 8",
            bytes.len()
        )));
    }
    if *first == 0 && !rest.is_empty() {
        return Err(CborldError::Envelope(
            "compression table identifier is not in shortest byte form".to_string(),
        ));
    }
    Ok(bytes.iter().fold(0_u64, |accumulator, byte| {
        (accumulator << 8) | u64::from(*byte)
    }))
}

/// Encodes `value` as the shortest two's-complement big-endian byte string.
///
/// A leading byte is dropped only while it is a redundant sign extension of
/// the byte that follows it, so exactly one byte always remains.
pub(crate) fn signed_to_bytes(value: i64) -> Vec<u8> {
    let full = value.to_be_bytes();
    let mut first = 0;
    while first + 1 < full.len() {
        let redundant = match full[first] {
            0x00 => full[first + 1] & 0x80 == 0,
            0xFF => full[first + 1] & 0x80 != 0,
            _ => false,
        };
        if !redundant {
            break;
        }
        first += 1;
    }
    full[first..].to_vec()
}

/// Decodes a shortest-form two's-complement big-endian byte string.
///
/// # Errors
///
/// Returns [`CborldError::Envelope`] for an empty string, for more than
/// eight bytes, and for a non-shortest spelling (a redundant sign byte).
pub(crate) fn signed_from_bytes(bytes: &[u8]) -> Result<i64, CborldError> {
    if bytes.is_empty() {
        return Err(CborldError::Envelope(
            "compression table integer must not be an empty byte string".to_string(),
        ));
    }
    if bytes.len() > 8 {
        return Err(CborldError::Envelope(format!(
            "compression table integer of {} bytes exceeds 8",
            bytes.len()
        )));
    }
    let negative = bytes.first().is_some_and(|byte| byte & 0x80 != 0);
    let mut value: i64 = if negative { -1 } else { 0 };
    for byte in bytes {
        value = (value << 8) | i64::from(*byte);
    }
    if signed_to_bytes(value) != bytes {
        return Err(CborldError::Envelope(
            "compression table integer is not in shortest byte form".to_string(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{signed_from_bytes, signed_to_bytes, unsigned_from_bytes, unsigned_to_bytes};

    #[test]
    fn unsigned_identifiers_use_the_shortest_big_endian_form() {
        // Registry entry 31000000 assigns `url` identifiers 1..=28, which all
        // fit one byte; 100's `context` identifiers 32768..=32770 take two.
        assert_eq!(unsigned_to_bytes(0), vec![0]);
        assert_eq!(unsigned_to_bytes(1), vec![1]);
        assert_eq!(unsigned_to_bytes(28), vec![28]);
        assert_eq!(unsigned_to_bytes(32770), vec![0x80, 0x02]);
        assert_eq!(unsigned_to_bytes(u64::MAX), vec![0xFF; 8]);
        for value in [0, 1, 28, 255, 256, 32770, u64::MAX] {
            let bytes = unsigned_to_bytes(value);
            assert_eq!(unsigned_from_bytes(&bytes).expect("round-trip"), value);
        }
    }

    #[test]
    fn non_shortest_and_oversized_identifier_bytes_are_refused() {
        assert!(unsigned_from_bytes(&[]).is_err());
        assert!(unsigned_from_bytes(&[0, 1]).is_err());
        assert!(unsigned_from_bytes(&[1; 9]).is_err());
        assert!(unsigned_from_bytes(&[0]).is_ok());
    }

    #[test]
    fn signed_integers_round_trip_in_shortest_two_complement_form() {
        for value in [0_i64, 1, -1, 127, 128, -128, -129, i64::MIN, i64::MAX] {
            let bytes = signed_to_bytes(value);
            assert_eq!(signed_from_bytes(&bytes).expect("round-trip"), value);
        }
        assert_eq!(signed_to_bytes(0), vec![0]);
        assert_eq!(signed_to_bytes(-1), vec![0xFF]);
        assert_eq!(signed_to_bytes(128), vec![0x00, 0x80]);
        assert_eq!(signed_to_bytes(-129), vec![0xFF, 0x7F]);
    }

    #[test]
    fn non_shortest_signed_bytes_are_refused() {
        assert!(signed_from_bytes(&[]).is_err());
        assert!(signed_from_bytes(&[0x00, 0x01]).is_err());
        assert!(signed_from_bytes(&[0xFF, 0xFF]).is_err());
        assert!(signed_from_bytes(&[0x00; 9]).is_err());
    }
}
