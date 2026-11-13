// Rust guideline compliant 2026-02-21
//! Iterative pre-scans that bound native recursion before it starts.
//!
//! Expansion, compaction, framing, and the serializers recurse once per
//! JSON nesting level. Their own depth counters fire only after the native
//! stack has already grown by that many frames, and a caller can hand over a
//! [`Value`] of any depth (`serde_json`'s parser stops at 128, but a value
//! built in code has no such bound; `Clone`, `Drop`, and `==` on it recurse
//! too). Every caller-supplied value is therefore measured here, with an
//! explicit heap stack, before any recursive code — including a `clone` —
//! touches it.

use serde_json::Value;

use crate::error::{JsonLdError, JsonLdResource};

/// Fails when a container (array or object) of `value` nests deeper than
/// `max_depth`.
///
/// Depth counts like expansion's own budget: the root value is depth 0 and
/// every array element or object member is one level deeper than its
/// container. Only containers are checked: a scalar cannot drive recursion,
/// and expansion still applies its own check to scalars it visits, so this
/// scan never refuses a document that expansion would accept.
///
/// The scan runs in time linear in the number of containers and uses heap
/// memory proportional to the widest pending frontier, never native stack.
///
/// # Errors
///
/// [`JsonLdError::ResourceLimit`] with [`JsonLdResource::Depth`], reporting
/// the first depth beyond `max_depth`, exactly as expansion would.
pub(crate) fn check_nesting(value: &Value, max_depth: usize) -> Result<(), JsonLdError> {
    let mut pending: Vec<(&Value, usize)> = Vec::new();
    push_if_container(&mut pending, value, 0, max_depth)?;
    while let Some((current, depth)) = pending.pop() {
        let child_depth = depth.saturating_add(1);
        match current {
            Value::Array(items) => {
                for item in items {
                    push_if_container(&mut pending, item, child_depth, max_depth)?;
                }
            }
            Value::Object(map) => {
                for item in map.values() {
                    push_if_container(&mut pending, item, child_depth, max_depth)?;
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn push_if_container<'value>(
    pending: &mut Vec<(&'value Value, usize)>,
    value: &'value Value,
    depth: usize,
    max_depth: usize,
) -> Result<(), JsonLdError> {
    if !matches!(value, Value::Array(_) | Value::Object(_)) {
        return Ok(());
    }
    if depth > max_depth {
        return Err(JsonLdError::ResourceLimit {
            resource: JsonLdResource::Depth,
            limit: max_depth,
            observed: depth,
        });
    }
    pending.push((value, depth));
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::check_nesting;

    #[test]
    fn accepts_containers_at_the_limit_and_refuses_one_deeper() {
        let at_limit = json!([[["leaf"]]]);
        assert!(check_nesting(&at_limit, 2).is_ok());
        let error = check_nesting(&at_limit, 1).expect_err("depth 2 container exceeds 1");
        assert_eq!(error.code(), "resource_limit");
    }

    #[test]
    fn scalars_do_not_count_toward_the_limit() {
        assert!(check_nesting(&json!({"a": "b"}), 0).is_ok());
        assert!(check_nesting(&json!({"a": {}}), 0).is_err());
    }
}
