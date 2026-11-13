// Rust guideline compliant 2026-02-21
//! Deep and chained input on a 256 KiB thread must fail closed, never
//! overflow the native stack.
//!
//! Each case runs in a child process (this same test binary, filtered to the
//! one case), so a stack-overflow abort is observed as a failed test instead
//! of killing the whole test run. Inputs are 100,000 levels deep (or 100,000
//! nodes long for chained graphs) and the build is unoptimized, which is the
//! worst case for native frame size.

use std::process::Command;

use jsonld_fast_core::{
    JsonLdOptions, YamlLdOptions, YamlLdProfile, compact, expand, expand_streaming, frame,
    from_quads, parse_yaml_ld, to_quads, to_yaml_ld, validate_streaming_form,
    write_streaming_document,
};
use serde_json::{Map, Value, json};

/// Nesting depth of every hostile shape.
const DEPTH: usize = 100_000;

/// Stack size of the thread that runs one case.
const SMALL_STACK: usize = 256 * 1024;

/// Environment variable naming the case a child process must run.
const CHILD_CASE: &str = "JSONLD_DEEP_CHILD_CASE";

/// Runs `case` in a child process on a 256 KiB thread and fails when the
/// child does not exit cleanly (a stack overflow aborts it).
fn isolated(name: &str, case: fn()) {
    isolated_on(name, SMALL_STACK, case);
}

/// [`isolated`] with an explicit thread stack size.
fn isolated_on(name: &str, stack: usize, case: fn()) {
    if std::env::var(CHILD_CASE).as_deref() == Ok(name) {
        let handle = std::thread::Builder::new()
            .stack_size(stack)
            .spawn(case)
            .expect("spawn the small-stack thread");
        handle.join().expect("the case must not panic");
        return;
    }
    let exe = std::env::current_exe().expect("locate the test binary");
    let output = Command::new(exe)
        .args([name, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_CASE, name)
        .output()
        .expect("spawn the child test process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "case `{name}` did not exit cleanly ({:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
}

/// Wraps `leaf` `DEPTH` times with `wrap`, iteratively.
fn nest(leaf: Value, wrap: impl Fn(Value) -> Value) -> Value {
    let mut value = leaf;
    for _ in 0..DEPTH {
        value = wrap(value);
    }
    value
}

fn object(key: &str, value: Value) -> Value {
    let mut map = Map::new();
    map.insert(key.to_owned(), value);
    Value::Object(map)
}

/// Builds a map by moving `entries` in. `json!` must not interpolate a deep
/// value: it re-serializes the expression through `to_value`, recursively.
fn entries(entries: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}

/// A term definition for `p` carrying `inner` as its scoped context.
fn scoped_term(inner: Value) -> Value {
    object(
        "p",
        entries(vec![
            ("@id", json!("http://example.com/p")),
            ("@context", inner),
        ]),
    )
}

/// Leaks a value whose recursive `Drop` would itself overflow the small
/// stack; the harness owns that value, not the library under test.
fn leak<T>(value: T) {
    std::mem::forget(value);
}

/// Asserts the call failed closed, then leaks both sides.
fn expect_err<T: std::fmt::Debug>(input: Value, result: Result<T, jsonld_fast_core::JsonLdError>) {
    match result {
        Ok(output) => {
            leak(output);
            leak(input);
            panic!("deep input must be refused");
        }
        Err(error) => {
            println!("refused: {error}");
            leak(input);
        }
    }
}

fn opts() -> JsonLdOptions {
    JsonLdOptions::default()
}

fn deep_property() -> Value {
    nest(json!("leaf"), |inner| object("http://example.com/p", inner))
}

// ---------------------------------------------------------------------------
// Expansion (and every entry point that expands first).
// ---------------------------------------------------------------------------

#[test]
fn expand_nested_arrays() {
    isolated("expand_nested_arrays", || {
        let input = nest(json!("leaf"), |inner| Value::Array(vec![inner]));
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_objects() {
    isolated("expand_nested_objects", || {
        let input = deep_property();
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_graph() {
    isolated("expand_nested_graph", || {
        let input = nest(json!({}), |inner| object("@graph", inner));
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_list() {
    isolated("expand_nested_list", || {
        let lists = nest(json!("leaf"), |inner| object("@list", inner));
        let input = object("http://example.com/p", lists);
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_set() {
    isolated("expand_nested_set", || {
        let sets = nest(json!("leaf"), |inner| object("@set", inner));
        let input = object("http://example.com/p", sets);
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_scoped_contexts() {
    isolated("expand_nested_scoped_contexts", || {
        let context = nest(json!({}), scoped_term);
        let input = entries(vec![("@context", context), ("p", json!("x"))]);
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_context_arrays() {
    isolated("expand_nested_context_arrays", || {
        let context = nest(json!({}), |inner| Value::Array(vec![inner]));
        let input = entries(vec![
            ("@context", context),
            ("http://example.com/p", json!("x")),
        ]);
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_nest() {
    isolated("expand_nested_nest", || {
        let nests = nest(json!({"http://example.com/p": "x"}), |inner| {
            object("n", inner)
        });
        let input = entries(vec![("@context", json!({"n": "@nest"})), ("n", nests)]);
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_json_literal() {
    isolated("expand_nested_json_literal", || {
        let payload = nest(json!(1), |inner| Value::Array(vec![inner]));
        let input = entries(vec![
            (
                "@context",
                json!({"j": {"@id": "http://example.com/j", "@type": "@json"}}),
            ),
            ("j", payload),
        ]);
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_value_payload() {
    isolated("expand_nested_value_payload", || {
        let payload = nest(json!(1), |inner| Value::Array(vec![inner]));
        let input = object("http://example.com/p", object("@value", payload));
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_embedded_id() {
    isolated("expand_nested_embedded_id", || {
        let embedded = nest(json!("http://example.com/o"), |inner| object("@id", inner));
        let input = entries(vec![
            ("@id", json!("http://example.com/s")),
            ("http://example.com/p", embedded),
        ]);
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_included() {
    isolated("expand_nested_included", || {
        let input = nest(json!({"@id": "http://example.com/x"}), |inner| {
            object("@included", inner)
        });
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn expand_nested_reverse() {
    isolated("expand_nested_reverse", || {
        let input = nest(json!({"@id": "http://example.com/x"}), |inner| {
            object("@reverse", object("http://example.com/p", inner))
        });
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn to_quads_nested_objects() {
    isolated("to_quads_nested_objects", || {
        let input = deep_property();
        let result = to_quads(&input, &opts(), None);
        expect_err(input, result);
    });
}

// ---------------------------------------------------------------------------
// Compaction and framing inputs that expansion does not see.
// ---------------------------------------------------------------------------

#[test]
fn compact_nested_context() {
    isolated("compact_nested_context", || {
        let context = nest(json!({}), scoped_term);
        let document = json!({"http://example.com/p": "x"});
        let result = compact(&document, &context, &opts());
        expect_err(context, result);
    });
}

#[test]
fn compact_nested_context_array() {
    isolated("compact_nested_context_array", || {
        let context = nest(json!({}), |inner| Value::Array(vec![inner]));
        let document = json!({"http://example.com/p": "x"});
        let result = compact(&document, &context, &opts());
        expect_err(context, result);
    });
}

#[test]
fn frame_nested_frame() {
    isolated("frame_nested_frame", || {
        let frame_value = deep_property();
        let document = json!({"@id": "http://example.com/s", "http://example.com/p": "x"});
        let result = frame(&document, &frame_value, &opts());
        expect_err(frame_value, result);
    });
}

/// A flat `@graph` of `DEPTH` nodes, each referencing the next.
fn chained_graph() -> Value {
    let nodes: Vec<Value> = (0..DEPTH)
        .map(|index| {
            json!({
                "@id": format!("http://example.com/n{index}"),
                "http://example.com/next": {"@id": format!("http://example.com/n{}", index + 1)}
            })
        })
        .collect();
    json!({"@graph": nodes})
}

#[test]
fn frame_chained_graph_embeds() {
    isolated("frame_chained_graph_embeds", || {
        let document = chained_graph();
        let frame_value = json!({"@id": "http://example.com/n0"});
        let result = frame(&document, &frame_value, &opts());
        expect_err(document, result);
    });
}

// ---------------------------------------------------------------------------
// RDF deserialization: list chains are flat quads but nest on output.
// ---------------------------------------------------------------------------

#[test]
fn from_quads_nested_lists() {
    isolated("from_quads_nested_lists", || {
        let rdf = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
        let mut nodes: Vec<Value> = (0..DEPTH)
            .map(|index| {
                json!({
                    "@id": format!("_:l{index}"),
                    format!("{rdf}first"): {"@id": format!("_:l{}", index + 1)},
                    format!("{rdf}rest"): {"@id": format!("{rdf}nil")}
                })
            })
            .collect();
        nodes.push(json!({"@id": "http://example.com/s", "http://example.com/p": {"@id": "_:l0"}}));
        let document = json!({"@graph": nodes});
        let batches = to_quads(&document, &opts(), None).expect("flat quads convert");
        let result = from_quads(&batches);
        expect_err(document, result);
    });
}

// ---------------------------------------------------------------------------
// Serializers that accept a caller-built value.
// ---------------------------------------------------------------------------

#[test]
fn to_yaml_ld_nested_value() {
    isolated("to_yaml_ld_nested_value", || {
        let input = deep_property();
        let result = to_yaml_ld(&input);
        expect_err(input, result);
    });
}

#[test]
fn write_streaming_document_nested_value() {
    isolated("write_streaming_document_nested_value", || {
        let input = deep_property();
        let text = write_streaming_document(&input);
        println!("wrote {} bytes", text.len());
        leak(input);
    });
}

// ---------------------------------------------------------------------------
// Text entry points.
// ---------------------------------------------------------------------------

fn deep_json_text() -> String {
    let mut text = String::with_capacity(DEPTH * 2 + 2);
    for _ in 0..DEPTH {
        text.push('[');
    }
    text.push('1');
    for _ in 0..DEPTH {
        text.push(']');
    }
    text
}

#[test]
fn streaming_nested_text() {
    isolated("streaming_nested_text", || {
        let text = deep_json_text();
        let options = opts();
        assert!(validate_streaming_form(&text, &options.limits).is_err());
        assert!(expand_streaming(&text, &options).is_err());
    });
}

#[test]
fn yaml_nested_flow_sequences() {
    isolated("yaml_nested_flow_sequences", || {
        let text = deep_json_text();
        for profile in [YamlLdProfile::Basic, YamlLdProfile::Extended] {
            let options = YamlLdOptions {
                profile,
                ..YamlLdOptions::default()
            };
            let error = parse_yaml_ld(&text, &options).expect_err("deep YAML is refused");
            println!("refused: {error}");
        }
    });
}

#[test]
fn yaml_nested_block_sequences() {
    isolated("yaml_nested_block_sequences", || {
        // `- - - x` is three nested block sequences on one line; block
        // nesting has no parser limit in saphyr (flow nesting stops at 255).
        let mut text = "- ".repeat(DEPTH);
        text.push_str("x\n");
        for profile in [YamlLdProfile::Basic, YamlLdProfile::Extended] {
            let options = YamlLdOptions {
                profile,
                ..YamlLdOptions::default()
            };
            let error = parse_yaml_ld(&text, &options).expect_err("deep YAML is refused");
            println!("refused: {error}");
        }
    });
}

// ---------------------------------------------------------------------------
// Inputs within the default depth limit must not depend on the caller's
// stack either: 60 levels is legal, and does not fit a 256 KiB debug stack
// inline (about 15 object levels do).
// ---------------------------------------------------------------------------

/// Nesting just under the default `max_depth` of 128.
const LEGAL_DEPTH: usize = 60;

fn legal_deep_property() -> Value {
    let mut value = json!("leaf");
    for _ in 0..LEGAL_DEPTH {
        value = object("http://example.com/p", value);
    }
    value
}

#[test]
fn within_limit_expand_compact_to_quads_frame() {
    isolated("within_limit_expand_compact_to_quads_frame", || {
        let input = legal_deep_property();
        let options = opts();
        let expanded = expand(&input, &options).expect("legal depth expands");
        leak(expanded);
        let compacted = compact(&input, &json!({"p": "http://example.com/p"}), &options)
            .expect("legal depth compacts");
        leak(compacted);
        let quads = to_quads(&input, &options, None).expect("legal depth converts");
        assert_eq!(quads[0].num_rows(), LEGAL_DEPTH);
        let framed = frame(&input, &json!({}), &options).expect("legal depth frames");
        leak(framed);
        leak(input);
    });
}

// ---------------------------------------------------------------------------
// Flat inputs whose processing could still recurse per element.
// ---------------------------------------------------------------------------

#[test]
fn prefix_chain_in_flat_context() {
    isolated("prefix_chain_in_flat_context", || {
        // `t0` is `t1:x`, `t1` is `t2:x`, ...: flat JSON, but defining `t0`
        // resolves the whole chain.
        let mut terms = Map::new();
        for index in 0..DEPTH {
            terms.insert(format!("t{index}"), json!(format!("t{}:x", index + 1)));
        }
        terms.insert(format!("t{DEPTH}"), json!("http://example.com/"));
        let input = entries(vec![("@context", Value::Object(terms)), ("t0", json!("v"))]);
        // Refused by chain length on an explicit stack, never by overflow.
        let result = expand(&input, &opts());
        expect_err(input, result);
    });
}

#[test]
fn long_flat_list_to_quads() {
    isolated("long_flat_list_to_quads", || {
        let items: Vec<Value> = (0..DEPTH).map(|index| json!(index)).collect();
        let input = entries(vec![
            ("@id", json!("http://example.com/s")),
            ("http://example.com/p", object("@list", Value::Array(items))),
        ]);
        let batches = to_quads(&input, &opts(), None).expect("a flat list converts");
        assert_eq!(batches[0].num_rows(), DEPTH * 2 + 1);
        let round_tripped = from_quads(&batches).expect("a flat list reassembles");
        leak(round_tripped);
        leak(input);
    });
}

// ---------------------------------------------------------------------------
// YAML aliases nest too: each alias composes a full copy of its anchor.
// ---------------------------------------------------------------------------

/// 100 anchors, each 120 flow levels deep around an alias of the previous
/// one: about 25 KB that composes to roughly 12,000 levels.
fn yaml_alias_depth_chain() -> String {
    let mut text = String::new();
    for anchor in 0..100 {
        text.push_str(&format!("- &a{anchor} "));
        text.push_str(&"[".repeat(120));
        if anchor == 0 {
            text.push('x');
        } else {
            text.push_str(&format!("*a{}", anchor - 1));
        }
        text.push_str(&"]".repeat(120));
        text.push('\n');
    }
    text
}

fn refuse_yaml_alias_depth_chain() {
    let options = YamlLdOptions {
        profile: YamlLdProfile::Extended,
        ..YamlLdOptions::default()
    };
    let error = parse_yaml_ld(&yaml_alias_depth_chain(), &options)
        .expect_err("an alias chain composing past max_depth is refused");
    println!("refused: {error}");
}

#[test]
fn yaml_alias_depth_chain_small_stack() {
    isolated(
        "yaml_alias_depth_chain_small_stack",
        refuse_yaml_alias_depth_chain,
    );
}

#[test]
fn yaml_alias_depth_chain_8_mib_stack() {
    isolated_on(
        "yaml_alias_depth_chain_8_mib_stack",
        8 * 1024 * 1024,
        refuse_yaml_alias_depth_chain,
    );
}
