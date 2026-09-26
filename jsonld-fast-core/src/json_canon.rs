// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Canonical JSON serialization for `rdf:JSON` literals.
//!
//! Implements the value-space constraints of the `rdf:JSON` datatype
//! (JSON-LD 1.1 section 10.2), which mirror the JSON Canonicalization
//! Scheme (RFC 8785): no whitespace, object keys sorted lexicographically
//! by UTF-16 code units, numbers in ECMAScript `Number::toString` form
//! (ECMA-262 section 7.1.12.1), and strings escaped minimally with
//! lowercase `\u00xx` for control characters.
//!
//! Numbers are treated as IEEE 754 doubles, as both RFC 8785 and the
//! ECMAScript number-to-string algorithm require. An integer that cannot be
//! represented exactly as a double fails closed with
//! [`JsonLdError::InvalidTerm`] instead of silently changing value.

use serde_json::Value;

use crate::error::JsonLdError;

/// Serializes `value` into the canonical `rdf:JSON` lexical form.
///
/// # Errors
///
/// Returns [`JsonLdError::InvalidTerm`] when an integer in `value` cannot be
/// represented exactly as an IEEE 754 double (the number model both RFC 8785
/// and ECMA-262 serialization are defined over).
pub(crate) fn canonical_json(value: &Value) -> Result<String, JsonLdError> {
    let mut output = String::new();
    write_value(value, &mut output)?;
    Ok(output)
}

fn write_value(value: &Value, output: &mut String) -> Result<(), JsonLdError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(true) => output.push_str("true"),
        Value::Bool(false) => output.push_str("false"),
        Value::Number(number) => output.push_str(&canonical_number(number)?),
        Value::String(text) => write_string(text, output),
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_value(item, output)?;
            }
            output.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 section 3.2.3: keys sort by UTF-16 code units.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| {
                left.encode_utf16()
                    .collect::<Vec<u16>>()
                    .cmp(&right.encode_utf16().collect::<Vec<u16>>())
            });
            output.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_string(key, output);
                output.push(':');
                write_value(&map[key.as_str()], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

/// Escapes `text` per JSON-LD 1.1 section 10.2 / RFC 8785 section 3.2.2.2.
fn write_string(text: &str, output: &mut String) {
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{0009}' => output.push_str("\\t"),
            '\u{000A}' => output.push_str("\\n"),
            '\u{000C}' => output.push_str("\\f"),
            '\u{000D}' => output.push_str("\\r"),
            control if control < '\u{0020}' => {
                output.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

/// Serializes a JSON number in ECMAScript `Number::toString` form.
fn canonical_number(number: &serde_json::Number) -> Result<String, JsonLdError> {
    // The number model is IEEE 754 double (RFC 8785 section 3.2.2.3);
    // integers outside exact double range fail closed.
    if let Some(integer) = number.as_i64() {
        let Some(exact) = exact_double_from_i64(integer) else {
            return Err(JsonLdError::InvalidTerm(format!(
                "JSON literal integer {integer} is not exactly representable as a double"
            )));
        };
        return Ok(es6_number(exact));
    }
    if let Some(integer) = number.as_u64() {
        let Some(exact) = exact_double_from_u64(integer) else {
            return Err(JsonLdError::InvalidTerm(format!(
                "JSON literal integer {integer} is not exactly representable as a double"
            )));
        };
        return Ok(es6_number(exact));
    }
    // serde_json numbers are always finite.
    Ok(es6_number(number.as_f64().unwrap_or_default()))
}

/// `2^63`, the first `i64`-range boundary a `f64 as i64` cast saturates at.
const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;
/// `2^64`, the first `u64`-range boundary a `f64 as u64` cast saturates at.
const TWO_POW_64: f64 = 18_446_744_073_709_551_616.0;

/// Returns `integer` as a double when the conversion is exact.
///
/// The obvious test — `(integer as f64) as i64 == integer` — is **unsound**
/// at the ends of the range: a float-to-integer `as` cast saturates rather
/// than wrapping, so `i64::MAX as f64` (which rounds *up*, to `2^63`) casts
/// back to `i64::MAX` and the value looks exact when it is not. Range is
/// therefore checked before the cast back, and only then is the cast
/// meaningful.
fn exact_double_from_i64(integer: i64) -> Option<f64> {
    #[expect(
        clippy::cast_precision_loss,
        reason = "the exactness of this very conversion is what is under test"
    )]
    let as_double = integer as f64;
    if !(-TWO_POW_63..TWO_POW_63).contains(&as_double) {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the range check above rules out a saturating cast"
    )]
    let back = as_double as i64;
    (back == integer).then_some(as_double)
}

/// Returns `integer` as a double when the conversion is exact.
///
/// Same saturation hazard as [`exact_double_from_i64`]: `u64::MAX as f64`
/// rounds up to `2^64` and casts back to `u64::MAX`.
fn exact_double_from_u64(integer: u64) -> Option<f64> {
    #[expect(
        clippy::cast_precision_loss,
        reason = "the exactness of this very conversion is what is under test"
    )]
    let as_double = integer as f64;
    if !(0.0..TWO_POW_64).contains(&as_double) {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the range check above rules out a saturating cast"
    )]
    let back = as_double as u64;
    (back == integer).then_some(as_double)
}

/// Formats a finite double per ECMA-262 section 7.1.12.1 (`Number::toString`).
fn es6_number(value: f64) -> String {
    if value == 0.0 {
        // Covers negative zero: RFC 8785 serializes -0 as "0".
        return "0".to_owned();
    }
    let negative = value < 0.0;
    // Rust's `{:e}` formatting yields the shortest digit string that
    // round-trips, the same digit selection ECMA-262 requires.
    let formatted = format!("{:e}", value.abs());
    let (mantissa, exponent) = formatted
        .split_once('e')
        .expect("`{:e}` always contains an exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let exponent: i64 = exponent.parse().expect("`{:e}` exponent is an integer");
    // ECMA-262 notation: value = digits * 10^(n - k).
    let k = i64::try_from(digits.len()).expect("digit count fits i64");
    let n = exponent + 1;
    let mut body = String::new();
    if k <= n && n <= 21 {
        // Integer with trailing zeros.
        body.push_str(&digits);
        for _ in 0..(n - k) {
            body.push('0');
        }
    } else if 0 < n && n <= 21 {
        // Decimal point inside the digits.
        let split = usize::try_from(n).expect("0 < n <= 21");
        body.push_str(&digits[..split]);
        body.push('.');
        body.push_str(&digits[split..]);
    } else if -6 < n && n <= 0 {
        // Leading zeros after "0.".
        body.push_str("0.");
        for _ in 0..(-n) {
            body.push('0');
        }
        body.push_str(&digits);
    } else {
        // Exponential notation.
        body.push_str(&digits[..1]);
        if digits.len() > 1 {
            body.push('.');
            body.push_str(&digits[1..]);
        }
        body.push('e');
        if n > 0 {
            body.push('+');
        }
        body.push_str(&(n - 1).to_string());
    }
    if negative { format!("-{body}") } else { body }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{canonical_json, es6_number};

    /// ECMA-262 section 7.1.12.1 number forms (RFC 8785 appendix B values).
    #[test]
    fn es6_number_forms() {
        assert_eq!(es6_number(0.0), "0");
        assert_eq!(es6_number(-0.0), "0");
        assert_eq!(es6_number(1.0), "1");
        assert_eq!(es6_number(-1.0), "-1");
        assert_eq!(es6_number(5.5), "5.5");
        assert_eq!(es6_number(333_333_333.333_333_3), "333333333.3333333");
        assert_eq!(es6_number(1e21), "1e+21");
        assert_eq!(es6_number(1e20), "100000000000000000000");
        assert_eq!(es6_number(1e-6), "0.000001");
        assert_eq!(es6_number(1e-7), "1e-7");
        assert_eq!(es6_number(-2.5e-3), "-0.0025");
        assert_eq!(es6_number(9.007_199_254_740_992e15), "9007199254740992");
    }

    /// JSON-LD 1.1 section 10.2: sorted keys, no whitespace, minimal escapes.
    #[test]
    fn canonical_object_form() {
        let value = json!({"b": 2, "a": {"y": true, "x": null}, "list": [1.5, "z"]});
        assert_eq!(
            canonical_json(&value).expect("canonical form"),
            r#"{"a":{"x":null,"y":true},"b":2,"list":[1.5,"z"]}"#
        );
    }

    /// JSON-LD 1.1 section 10.2: control characters use lowercase \u00xx,
    /// with the five predefined short escapes preferred.
    #[test]
    fn canonical_string_escapes() {
        let value = json!("a\"b\\c\u{0008}\u{0009}\u{000A}\u{000C}\u{000D}\u{001F}\u{20AC}");
        assert_eq!(
            canonical_json(&value).expect("canonical form"),
            "\"a\\\"b\\\\c\\b\\t\\n\\f\\r\\u001f\u{20AC}\""
        );
    }

    /// RFC 8785 section 3.2.3: keys sort by UTF-16 code units, not code
    /// points — a supplementary-plane character encodes as surrogates
    /// (0xD800..) and therefore sorts *before* U+FFFD (0xFFFD), the
    /// opposite of code-point (Rust `str`) ordering.
    #[test]
    fn keys_sort_by_utf16_code_units() {
        let value = json!({"\u{10000}": 1, "\u{FFFD}": 2});
        assert_eq!(
            canonical_json(&value).expect("canonical form"),
            "{\"\u{10000}\":1,\"\u{FFFD}\":2}"
        );
        assert!("\u{FFFD}" < "\u{10000}", "code-point order is the reverse");
    }

    /// Fail-closed: integers outside exact double range are refused.
    #[test]
    fn lossy_integer_fails_closed() {
        let value = json!(9_007_199_254_740_993_i64); // 2^53 + 1
        let error = canonical_json(&value).expect_err("lossy integer must fail");
        assert_eq!(error.code(), "invalid_term");
    }
}
