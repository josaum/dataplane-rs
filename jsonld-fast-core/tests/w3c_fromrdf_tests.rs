// Rust guideline compliant 2026-02-21
//! W3C JSON-LD 1.1 API `fromRdf` list tests (see `tests/w3c/fromrdf`).
//!
//! The currently passing tests are pinned so none can regress; the rest are
//! printed with their difference, not asserted.

use std::collections::BTreeSet;
use std::path::Path;

use jsonld_fast_core::{JsonLdOptions, from_quads, to_quads};
use serde_json::{Map, Value};

/// Tests this processor passes today; each must keep passing.
const PINNED: &[&str] = &[
    "0001", "0004", "0005", "0010", "0012", "0015", "0016", "0022", "0023", "li02",
];

/// Normalizes blank node labels and the order of unordered arrays.
///
/// Arrays are sets in expanded JSON-LD except under `@list`, so they are
/// sorted; blank node labels are issuer-dependent, so they are erased.
fn normalize(value: &Value, in_list: bool) -> Value {
    match value {
        Value::String(text) if text.starts_with("_:") => Value::String("_:".to_owned()),
        Value::Array(items) => {
            let mut out: Vec<Value> = items.iter().map(|item| normalize(item, false)).collect();
            if !in_list {
                out.sort_by_key(ToString::to_string);
            }
            Value::Array(out)
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), normalize(item, key == "@list")))
                .collect::<Map<String, Value>>(),
        ),
        other => other.clone(),
    }
}

fn load(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).expect("fixture is readable");
    serde_json::from_str(&text).expect("fixture is JSON")
}

#[test]
fn w3c_from_rdf_list_tests_do_not_regress() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/w3c/fromrdf");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("fixture directory")
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            name.strip_suffix("-in.json").map(str::to_owned)
        })
        .collect();
    names.sort();
    assert_eq!(names.len(), 18, "all 18 fixtures are present");

    let mut passing = BTreeSet::new();
    for name in &names {
        let input = load(&dir.join(format!("{name}-in.json")));
        let expected = load(&dir.join(format!("{name}-out.json")));
        let batches = to_quads(&input, &JsonLdOptions::default(), None).expect("input converts");
        match from_quads(&batches) {
            Ok(got) if normalize(&got, false) == normalize(&expected, false) => {
                passing.insert(name.clone());
                println!("W3C fromRdf {name}: pass");
            }
            Ok(got) => println!("W3C fromRdf {name}: FAIL\n   got: {got}\n  want: {expected}"),
            Err(error) => println!("W3C fromRdf {name}: ERROR {error}"),
        }
    }
    println!("W3C fromRdf: {} of {} pass", passing.len(), names.len());
    let missing: Vec<&str> = PINNED
        .iter()
        .copied()
        .filter(|name| !passing.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "pinned W3C fromRdf tests regressed: {missing:?}"
    );
}
