// Rust guideline compliant 2026-02-21
//! Pure helpers for the vendored XSD date/dateTime and UUID value codecs.
//!
//! Implements the lossless-only compression rule of the CBOR-LD 1.0 "XSD
//! Date Codec", "XSD DateTime Codec", and "UUID URN Codec": a string is
//! compressed only when the canonical string form reconstructed from the
//! compressed integers is byte-identical to the input; every other string
//! passes through verbatim. Calendar math uses the proleptic Gregorian
//! calendar (Howard Hinnant's `days_from_civil` / `civil_from_days`).
//!
//! Also hosts the base-N primitives behind the "DID URL Codec", "Data URL
//! Codec", and "Multibase Codec": base58btc (alphabet vendored in
//! [`crate::registry`]) plus base64 (RFC 4648 §4, padded, for `data:` URLs)
//! and base64url (RFC 4648 §5, unpadded, for multibase `u` values). The
//! same lossless-only rule applies: callers compress only when re-encoding
//! the decoded bytes reproduces the input string byte-for-byte, so
//! `decompress(compress(doc)) == doc` never depends on the encoding being
//! canonical by construction.

use crate::registry::BASE58_BTC_ALPHABET;

/// Compressed form of one `xsd:dateTime` string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DateTimeEncoding {
    /// Second-precision value: seconds since the Unix epoch.
    Seconds(i64),
    /// Millisecond-precision value: whole seconds plus 0..=999 milliseconds.
    WithMillis(i64, u32),
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = (year - era * 400) as u64;
    let month_shifted = u64::from(if month > 2 { month - 3 } else { month + 9 });
    let day_of_year = (153 * month_shifted + 2) / 5 + u64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era as i64 - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_shifted = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_shifted + 2) / 5 + 1) as u32;
    let month_unshifted = if month_shifted < 10 {
        month_shifted + 3
    } else {
        month_shifted - 9
    };
    let month = month_unshifted as u32;
    (year + i64::from(month <= 2), month, day)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn digits(bytes: &[u8]) -> Option<u32> {
    let mut value: u32 = 0;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}

/// Parses a strict canonical `YYYY-MM-DD` string into (year, month, day).
fn parse_civil(bytes: &[u8]) -> Option<(i64, u32, u32)> {
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year = digits(&bytes[0..4])?;
    let month = digits(&bytes[5..7])?;
    let day = digits(&bytes[8..10])?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(i64::from(year), month) {
        return None;
    }
    Some((i64::from(year), month, day))
}

/// Compresses a canonical `xsd:date` string to epoch seconds, when lossless.
///
/// Returns `None` when the string is not in strict canonical `YYYY-MM-DD`
/// form, in which case the caller passes the string through verbatim.
pub(crate) fn encode_xsd_date(value: &str) -> Option<i64> {
    let (year, month, day) = parse_civil(value.as_bytes())?;
    Some(days_from_civil(year, month, day) * 86_400)
}

/// Formats epoch seconds as the date part of the corresponding UTC instant.
///
/// Returns `None` when the year falls outside 0..=9999, the range that
/// round-trips through the canonical four-digit form.
pub(crate) fn format_xsd_date(seconds: i64) -> Option<String> {
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    if !(0..=9999).contains(&year) {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

/// Compresses a canonical `xsd:dateTime` string, when lossless.
///
/// Accepts exactly `YYYY-MM-DDTHH:MM:SSZ` (second precision) or
/// `YYYY-MM-DDTHH:MM:SS.mmmZ` (three millisecond digits). Returns `None`
/// for every other string, in which case the caller passes it through.
pub(crate) fn encode_xsd_datetime(value: &str) -> Option<DateTimeEncoding> {
    let bytes = value.as_bytes();
    let millis = match bytes.len() {
        20 => None,
        24 => {
            if bytes[19] != b'.' {
                return None;
            }
            Some(digits(&bytes[20..23])?)
        }
        _ => return None,
    };
    if bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':' || *bytes.last()? != b'Z' {
        return None;
    }
    let (year, month, day) = parse_civil(&bytes[0..10])?;
    let hour = digits(&bytes[11..13])?;
    let minute = digits(&bytes[14..16])?;
    let second = digits(&bytes[17..19])?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400
        + i64::from(hour) * 3600
        + i64::from(minute) * 60
        + i64::from(second);
    Some(match millis {
        None => DateTimeEncoding::Seconds(seconds),
        Some(millis) => DateTimeEncoding::WithMillis(seconds, millis),
    })
}

fn format_instant(seconds: i64, millis: Option<u32>) -> Option<String> {
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    if !(0..=9999).contains(&year) {
        return None;
    }
    let of_day = seconds.rem_euclid(86_400);
    let (hour, minute, second) = (of_day / 3600, of_day % 3600 / 60, of_day % 60);
    let base = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
    Some(match millis {
        None => format!("{base}Z"),
        Some(millis) => format!("{base}.{millis:03}Z"),
    })
}

/// Formats a second-precision compressed `xsd:dateTime` value.
///
/// Mirrors the decoder rule "replace `.000Z` with `Z`": the output never
/// carries a millisecond component. Returns `None` outside years 0..=9999.
pub(crate) fn format_xsd_datetime_seconds(seconds: i64) -> Option<String> {
    format_instant(seconds, None)
}

/// Formats a millisecond-precision compressed `xsd:dateTime` value.
///
/// The instant is `total_millis` milliseconds since the Unix epoch; the
/// output always carries a three-digit millisecond component. Returns
/// `None` outside years 0..=9999 or outside the `i64` second range.
pub(crate) fn format_xsd_datetime_millis(total_millis: i128) -> Option<String> {
    let seconds = i64::try_from(total_millis.div_euclid(1000)).ok()?;
    let millis = total_millis.rem_euclid(1000) as u32;
    format_instant(seconds, Some(millis))
}

/// Parses an all-lowercase canonical UUID string into its 16 bytes.
///
/// Returns `None` for any other form (including uppercase hex), in which
/// case the caller keeps the text form, mirroring the UUID URN Codec.
pub(crate) fn parse_uuid_lowercase(value: &str) -> Option<[u8; 16]> {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut cursor = 0usize;
    for (index, chunk) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *chunk != b'-' {
                return None;
            }
            continue;
        }
        let nibble = match chunk {
            b'0'..=b'9' => chunk - b'0',
            b'a'..=b'f' => chunk - b'a' + 10,
            _ => return None,
        };
        if cursor.is_multiple_of(2) {
            out[cursor / 2] = nibble << 4;
        } else {
            out[cursor / 2] |= nibble;
        }
        cursor += 1;
    }
    Some(out)
}

/// Formats 16 UUID bytes in canonical lowercase hyphenated form.
pub(crate) fn format_uuid(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Decodes a base58btc string; `None` on any character outside the alphabet.
///
/// Leading `1` characters map to leading zero bytes, mirroring
/// [`base58btc_encode`]. Quadratic in the input length, so callers bound the
/// input with `CborLimits::max_value_bytes` before calling.
pub(crate) fn base58btc_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let zeros = bytes.iter().take_while(|byte| **byte == b'1').count();
    let mut number: Vec<u8> = Vec::new();
    for &ch in bytes {
        let digit = BASE58_BTC_ALPHABET.iter().position(|entry| *entry == ch)? as u32;
        let mut carry = digit;
        for byte in number.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            number.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend_from_slice(&number);
    Some(out)
}

/// Encodes bytes as base58btc (leading zero bytes become `1` characters).
pub(crate) fn base58btc_encode(bytes: &[u8]) -> String {
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
        out.push(char::from(BASE58_BTC_ALPHABET[usize::from(digit)]));
    }
    out
}

/// Base64 alphabet of RFC 4648 §4 (the `data:` URL payload encoding).
const BASE64_STD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64url alphabet of RFC 4648 §5 (the multibase `u` encoding).
const BASE64_URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64_encode(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = chunk.get(1).map(|byte| u32::from(*byte));
        let third = chunk.get(2).map(|byte| u32::from(*byte));
        out.push(char::from(alphabet[(first >> 2) as usize]));
        out.push(char::from(
            alphabet[((first << 4 | second.unwrap_or(0) >> 4) & 0x3f) as usize],
        ));
        match second {
            Some(second) => out.push(char::from(
                alphabet[((second << 2 | third.unwrap_or(0) >> 6) & 0x3f) as usize],
            )),
            None if pad => out.push('='),
            None => {}
        }
        match third {
            Some(third) => out.push(char::from(alphabet[(third & 0x3f) as usize])),
            None if pad => out.push('='),
            None => {}
        }
    }
    out
}

fn base64_decode(text: &str, alphabet: &[u8; 64], pad: bool) -> Option<Vec<u8>> {
    let raw = text.as_bytes();
    let data = if pad {
        if !raw.len().is_multiple_of(4) {
            return None;
        }
        let padding = raw.iter().rev().take_while(|byte| **byte == b'=').count();
        if padding > 2 {
            return None;
        }
        &raw[..raw.len() - padding]
    } else {
        raw
    };
    if data.len() % 4 == 1 || data.contains(&b'=') {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &ch in data {
        let value = alphabet.iter().position(|entry| *entry == ch)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    // Non-zero leftover bits make re-encoding differ, which the caller's
    // strict round-trip comparison turns into a verbatim passthrough.
    Some(out)
}

/// Strict RFC 4648 §4 (padded) decode for `data:` URL payloads.
pub(crate) fn base64pad_decode(text: &str) -> Option<Vec<u8>> {
    base64_decode(text, BASE64_STD_ALPHABET, true)
}

/// RFC 4648 §4 (padded) encode for `data:` URL payloads.
pub(crate) fn base64pad_encode(bytes: &[u8]) -> String {
    base64_encode(bytes, BASE64_STD_ALPHABET, true)
}

/// Strict RFC 4648 §5 (unpadded) decode for multibase `u` values.
pub(crate) fn base64url_nopad_decode(text: &str) -> Option<Vec<u8>> {
    base64_decode(text, BASE64_URL_ALPHABET, false)
}

/// RFC 4648 §5 (unpadded) encode for multibase `u` values.
pub(crate) fn base64url_nopad_encode(bytes: &[u8]) -> String {
    base64_encode(bytes, BASE64_URL_ALPHABET, false)
}
