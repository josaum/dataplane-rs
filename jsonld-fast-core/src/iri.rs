// Rust guideline compliant 2026-02-21
//! Minimal RFC 3986 reference resolution for JSON-LD `@base` handling.
//!
//! The workspace pins no general-purpose IRI crate, so this module implements
//! the reference-resolution algorithm of RFC 3986 section 5.2 (including
//! `remove_dot_segments`) directly. It performs no character-level IRI
//! validation: final term validation is delegated to [`oxrdf`] when quads are
//! emitted, which keeps this module a pure string transformation.

/// Split components of one IRI reference.
#[derive(Debug, Default, PartialEq, Eq)]
struct Parts<'a> {
    scheme: Option<&'a str>,
    authority: Option<&'a str>,
    path: &'a str,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

/// Returns `true` when `value` starts with an RFC 3986 `scheme:` production.
#[must_use]
pub(crate) fn has_scheme(value: &str) -> bool {
    let Some(colon) = value.find(':') else {
        return false;
    };
    let candidate = &value[..colon];
    let mut bytes = candidate.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// Returns `true` when `value` is usable as an absolute IRI in this subset.
///
/// The check is structural (scheme presence); full validation happens when
/// [`oxrdf`] terms are constructed at the RDF boundary.
#[must_use]
pub(crate) fn is_absolute_iri(value: &str) -> bool {
    has_scheme(value)
}

/// Returns `true` when `value` is a blank node identifier (`_:` prefixed).
#[must_use]
pub(crate) fn is_blank_node_id(value: &str) -> bool {
    value.starts_with("_:")
}

fn parse(reference: &str) -> Parts<'_> {
    let mut rest = reference;
    let mut parts = Parts::default();

    if let Some(hash) = rest.find('#') {
        parts.fragment = Some(&rest[hash + 1..]);
        rest = &rest[..hash];
    }
    if let Some(question) = rest.find('?') {
        parts.query = Some(&rest[question + 1..]);
        rest = &rest[..question];
    }
    if has_scheme(rest) {
        // `has_scheme` guarantees the colon exists.
        let colon = rest.find(':').unwrap_or(0);
        parts.scheme = Some(&rest[..colon]);
        rest = &rest[colon + 1..];
    }
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find('/').unwrap_or(after.len());
        parts.authority = Some(&after[..end]);
        rest = &after[end..];
    }
    parts.path = rest;
    parts
}

/// Removes `.` and `..` segments per RFC 3986 section 5.2.4.
fn remove_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut output = String::with_capacity(path.len());
    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../") {
            input = rest;
        } else if let Some(rest) = input.strip_prefix("./") {
            input = rest;
        } else if input.starts_with("/./") {
            // Replace the `/./` prefix with `/` by skipping two bytes.
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.strip_prefix("/../").is_some() || input == "/.." {
            if let Some(last_slash) = output.rfind('/') {
                output.truncate(last_slash);
            } else {
                output.clear();
            }
            if input == "/.." {
                input = "/";
            } else {
                input = &input[3..];
            }
        } else if input == "." || input == ".." {
            input = "";
        } else {
            let start = usize::from(input.starts_with('/'));
            let end = input[start..]
                .find('/')
                .map_or(input.len(), |offset| offset + start);
            output.push_str(&input[..end]);
            input = &input[end..];
        }
    }
    output
}

fn merge_paths(base_authority: Option<&str>, base_path: &str, reference_path: &str) -> String {
    if base_authority.is_some() && base_path.is_empty() {
        return format!("/{reference_path}");
    }
    match base_path.rfind('/') {
        Some(last_slash) => format!("{}{}", &base_path[..=last_slash], reference_path),
        None => reference_path.to_owned(),
    }
}

fn recompose(parts: &Parts<'_>) -> String {
    let mut result = String::new();
    if let Some(scheme) = parts.scheme {
        result.push_str(scheme);
        result.push(':');
    }
    if let Some(authority) = parts.authority {
        result.push_str("//");
        result.push_str(authority);
    }
    result.push_str(parts.path);
    if let Some(query) = parts.query {
        result.push('?');
        result.push_str(query);
    }
    if let Some(fragment) = parts.fragment {
        result.push('#');
        result.push_str(fragment);
    }
    result
}

/// Resolves `reference` against `base` per RFC 3986 section 5.2.2.
#[must_use]
pub(crate) fn resolve(base: &str, reference: &str) -> String {
    let base_parts = parse(base);
    let ref_parts = parse(reference);

    let resolved_path;
    let target = if ref_parts.scheme.is_some() {
        resolved_path = remove_dot_segments(ref_parts.path);
        Parts {
            scheme: ref_parts.scheme,
            authority: ref_parts.authority,
            path: &resolved_path,
            query: ref_parts.query,
            fragment: ref_parts.fragment,
        }
    } else if ref_parts.authority.is_some() {
        resolved_path = remove_dot_segments(ref_parts.path);
        Parts {
            scheme: base_parts.scheme,
            authority: ref_parts.authority,
            path: &resolved_path,
            query: ref_parts.query,
            fragment: ref_parts.fragment,
        }
    } else if ref_parts.path.is_empty() {
        resolved_path = base_parts.path.to_owned();
        Parts {
            scheme: base_parts.scheme,
            authority: base_parts.authority,
            path: &resolved_path,
            query: ref_parts.query.or(base_parts.query),
            fragment: ref_parts.fragment,
        }
    } else {
        resolved_path = if ref_parts.path.starts_with('/') {
            remove_dot_segments(ref_parts.path)
        } else {
            remove_dot_segments(&merge_paths(
                base_parts.authority,
                base_parts.path,
                ref_parts.path,
            ))
        };
        Parts {
            scheme: base_parts.scheme,
            authority: base_parts.authority,
            path: &resolved_path,
            query: ref_parts.query,
            fragment: ref_parts.fragment,
        }
    };
    recompose(&target)
}

/// Makes `iri` relative to `base` for IRI compaction, when safely possible.
///
/// Implements the inverse transformation of [`resolve`] conservatively:
/// every candidate reference is verified with `resolve(base, candidate) ==
/// iri` before being returned, so compaction can never emit a reference
/// that fails to expand back to the original IRI. Returns `None` (the
/// caller keeps the absolute form) when base and IRI differ in scheme or
/// authority, or when no verified candidate exists.
#[must_use]
pub(crate) fn relativize(base: &str, iri: &str) -> Option<String> {
    let base_parts = parse(base);
    let iri_parts = parse(iri);
    if base_parts.scheme != iri_parts.scheme || base_parts.authority != iri_parts.authority {
        return None;
    }
    let mut candidates: Vec<String> = Vec::new();
    if base_parts.path == iri_parts.path && base_parts.query == iri_parts.query {
        match iri_parts.fragment {
            Some(fragment) => candidates.push(format!("#{fragment}")),
            None => candidates.push(String::new()),
        }
    }
    if base_parts.path == iri_parts.path
        && let Some(query) = iri_parts.query
    {
        let mut candidate = format!("?{query}");
        if let Some(fragment) = iri_parts.fragment {
            candidate.push('#');
            candidate.push_str(fragment);
        }
        candidates.push(candidate);
    }
    // Path-relative form: strip the common directory prefix, then climb with
    // `../` for every remaining base directory segment.
    let base_dir_end = base_parts.path.rfind('/').map_or(0, |slash| slash + 1);
    let base_dir = &base_parts.path[..base_dir_end];
    let mut common = 0;
    let mut offset = 0;
    while let Some(slash) = base_dir[offset..].find('/') {
        let end = offset + slash + 1;
        if iri_parts.path.len() >= end && iri_parts.path[..end] == base_dir[..end] {
            common = end;
            offset = end;
        } else {
            break;
        }
    }
    let ups = base_dir[common..].matches('/').count();
    let mut relative_path = "../".repeat(ups);
    relative_path.push_str(&iri_parts.path[common.min(iri_parts.path.len())..]);
    let mut suffix = String::new();
    if let Some(query) = iri_parts.query {
        suffix.push('?');
        suffix.push_str(query);
    }
    if let Some(fragment) = iri_parts.fragment {
        suffix.push('#');
        suffix.push_str(fragment);
    }
    if !relative_path.is_empty() || !suffix.is_empty() {
        candidates.push(format!("{relative_path}{suffix}"));
        // A first segment containing `:` would parse as a scheme; `./`
        // disambiguates. Verification below picks whichever form resolves.
        candidates.push(format!("./{relative_path}{suffix}"));
    }
    candidates
        .into_iter()
        .find(|candidate| resolve(base, candidate) == iri)
}

#[cfg(test)]
mod tests {
    use super::{has_scheme, relativize, resolve};

    const BASE: &str = "http://a/b/c/d;p?q";

    #[test]
    fn scheme_detection() {
        assert!(has_scheme("http://example.com/"));
        assert!(has_scheme("urn:isbn:0451450523"));
        assert!(!has_scheme("//example.com/"));
        assert!(!has_scheme("path/to/thing"));
        assert!(!has_scheme("1http://bad"));
        assert!(!has_scheme("./relative:looking"));
    }

    /// RFC 3986 section 5.4.1 normal examples.
    #[test]
    fn rfc3986_normal_examples() {
        let cases = [
            ("g:h", "g:h"),
            ("g", "http://a/b/c/g"),
            ("./g", "http://a/b/c/g"),
            ("g/", "http://a/b/c/g/"),
            ("/g", "http://a/g"),
            ("//g", "http://g"),
            ("?y", "http://a/b/c/d;p?y"),
            ("g?y", "http://a/b/c/g?y"),
            ("#s", "http://a/b/c/d;p?q#s"),
            ("g#s", "http://a/b/c/g#s"),
            ("g?y#s", "http://a/b/c/g?y#s"),
            (";x", "http://a/b/c/;x"),
            ("g;x", "http://a/b/c/g;x"),
            ("g;x?y#s", "http://a/b/c/g;x?y#s"),
            ("", "http://a/b/c/d;p?q"),
            (".", "http://a/b/c/"),
            ("./", "http://a/b/c/"),
            ("..", "http://a/b/"),
            ("../", "http://a/b/"),
            ("../g", "http://a/b/g"),
            ("../..", "http://a/"),
            ("../../", "http://a/"),
            ("../../g", "http://a/g"),
        ];
        for (reference, expected) in cases {
            assert_eq!(resolve(BASE, reference), expected, "reference {reference}");
        }
    }

    /// `relativize` inverts `resolve` and never returns an unverified form.
    #[test]
    fn relativize_round_trips_through_resolve() {
        let cases = [
            "http://a/b/c/d;p?q",
            "http://a/b/c/d;p?q#frag",
            "http://a/b/c/g",
            "http://a/b/c/g?y#s",
            "http://a/b/other/deep/g",
            "http://a/",
            "http://a/x",
        ];
        for iri in cases {
            let relative = relativize(BASE, iri).expect("relative form exists");
            assert_eq!(resolve(BASE, &relative), iri, "candidate {relative}");
        }
        // Different authority or scheme: no relative form.
        assert_eq!(relativize(BASE, "http://other/b"), None);
        assert_eq!(relativize(BASE, "urn:isbn:0451450523"), None);
    }

    /// RFC 3986 section 5.4.2 abnormal examples.
    #[test]
    fn rfc3986_abnormal_examples() {
        let cases = [
            ("../../../g", "http://a/g"),
            ("../../../../g", "http://a/g"),
            ("/./g", "http://a/g"),
            ("/../g", "http://a/g"),
            ("g.", "http://a/b/c/g."),
            (".g", "http://a/b/c/.g"),
            ("g..", "http://a/b/c/g.."),
            ("..g", "http://a/b/c/..g"),
            ("./../g", "http://a/b/g"),
            ("./g/.", "http://a/b/c/g/"),
            ("g/./h", "http://a/b/c/g/h"),
            ("g/../h", "http://a/b/c/h"),
            ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
            ("g;x=1/../y", "http://a/b/c/y"),
            ("g?y/./x", "http://a/b/c/g?y/./x"),
            ("g?y/../x", "http://a/b/c/g?y/../x"),
            ("g#s/./x", "http://a/b/c/g#s/./x"),
            ("g#s/../x", "http://a/b/c/g#s/../x"),
        ];
        for (reference, expected) in cases {
            assert_eq!(resolve(BASE, reference), expected, "reference {reference}");
        }
    }
}
