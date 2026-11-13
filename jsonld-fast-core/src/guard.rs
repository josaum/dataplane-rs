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
/// It is deliberately structural: containers inside `@context`, and under
/// keys that expansion would later drop, count too, because `clone`,
/// `Drop`, and context processing recurse into them as well. JSON *text*
/// is unaffected in practice, since `serde_json` already stops parsing at
/// 128 levels, the default limit; only values built in code can exceed it.
///
/// # Errors
///
/// [`JsonLdError::ResourceLimit`] with [`JsonLdResource::Depth`], reporting
/// the first depth beyond `max_depth`, exactly as expansion would.
pub(crate) fn check_nesting(value: &Value, max_depth: usize) -> Result<usize, JsonLdError> {
    let mut pending: Vec<(&Value, usize)> = Vec::new();
    let mut deepest = 0_usize;
    push_if_container(&mut pending, value, 0, max_depth)?;
    while let Some((current, depth)) = pending.pop() {
        deepest = deepest.max(depth);
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
    Ok(deepest)
}

/// Container depth processed on the caller's own thread.
///
/// Expansion, compaction, node-map generation, and RDF conversion recurse
/// once or twice per nesting level; an unoptimized build measured about
/// 17 KiB of native stack per object level, so 8 levels stay well inside a
/// 256 KiB caller stack. Optimized frames are several times smaller.
const INLINE_DEPTH: usize = if cfg!(debug_assertions) { 8 } else { 32 };

/// Native stack reserved per container level on the worker: 128 KiB.
///
/// A level costs up to two recursive passes (the input, then the expanded
/// output, which nests about twice as deep) at about 17 KiB per frame
/// chain unoptimized; 128 KiB keeps a margin of more than three.
const STACK_PER_LEVEL: usize = 128 * 1024;

/// Fixed native stack of the worker for its non-recursive frames: 2 MiB.
const WORKER_BASE_STACK: usize = 2 * 1024 * 1024;

/// Largest worker stack reserved: 1 GiB of address space.
///
/// Committed only as the recursion touches it. It covers about 8,000
/// levels; a caller that raises [`crate::JsonLdLimits::max_depth`] past
/// that has deeper input refused here instead of overflowing.
const MAX_WORKER_STACK: usize = 1 << 30;

/// Runs `job`, which recurses about once per level of `depth`, on a stack
/// that fits it.
///
/// Inputs up to [`INLINE_DEPTH`] run inline at no cost. Deeper ones run on
/// a scoped worker thread whose stack is sized from the measured `depth`,
/// so a legal document never depends on how small the caller's stack is.
///
/// # Errors
///
/// `job`'s own error; [`JsonLdError::ResourceLimit`] with
/// [`JsonLdResource::Depth`] when `depth` needs more than
/// [`MAX_WORKER_STACK`] (the limit reported is the depth that fits);
/// [`JsonLdError::WorkerUnavailable`] when the worker cannot be spawned.
pub(crate) fn run_sized<T, F>(depth: usize, job: F) -> Result<T, JsonLdError>
where
    T: Send,
    F: FnOnce() -> Result<T, JsonLdError> + Send,
{
    if depth <= INLINE_DEPTH {
        return job();
    }
    let max_levels = MAX_WORKER_STACK.saturating_sub(WORKER_BASE_STACK) / STACK_PER_LEVEL;
    if depth > max_levels {
        return Err(JsonLdError::ResourceLimit {
            resource: JsonLdResource::Depth,
            limit: max_levels,
            observed: depth,
        });
    }
    let stack_bytes = depth
        .saturating_mul(STACK_PER_LEVEL)
        .saturating_add(WORKER_BASE_STACK);
    std::thread::scope(|scope| {
        let spawned = std::thread::Builder::new()
            .name("jsonld-deep".to_owned())
            .stack_size(stack_bytes)
            .spawn_scoped(scope, job);
        // No worker stack: refuse rather than recurse on a caller stack
        // that was never sized for this depth.
        let Ok(handle) = spawned else {
            return Err(JsonLdError::WorkerUnavailable { stack_bytes, depth });
        };
        match handle.join() {
            Ok(result) => result,
            // A panic on the worker is a bug; propagate it unchanged.
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
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
    fn reports_the_deepest_container() {
        assert_eq!(check_nesting(&json!({"a": [{"b": []}]}), 8).ok(), Some(3));
    }

    #[test]
    fn scalars_do_not_count_toward_the_limit() {
        assert!(check_nesting(&json!({"a": "b"}), 0).is_ok());
        assert!(check_nesting(&json!({"a": {}}), 0).is_err());
    }
}
