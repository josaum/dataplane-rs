// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Integrity of the vendored CBOR-LD registry against its source YAML.
//!
//! `src/registry_tables.rs` is transcribed from
//! `vendor/cborld-registry/tables/*.yml` by a vendor-time script. These
//! tests re-parse the same YAML files with an independent parser written
//! here and assert that the transcription still matches, entry for entry
//! and row for row, so it cannot drift silently from the vendored bytes.
//!
//! Upstream: `json-ld/cborld-registry` at commit
//! `c7ece75bae6ef40c23e19ce111b5c51f3cf38950`, retrieved 2026-09-01. See
//! `vendor/cborld-registry/PROVENANCE.md`.

use cborld_fast_core::registry::{
    MULTIBASE_IRI, REGISTRY_ENTRIES, RegistryEntry, TABLE_TYPE_CONTEXT, TABLE_TYPE_NONE,
    TABLE_TYPE_URL, registry_entry,
};

/// One registry entry as parsed straight from the vendored YAML.
#[derive(Debug, Default)]
struct ParsedEntry {
    domain: String,
    mode: String,
    provisional: bool,
    tables: Vec<(String, Vec<(u64, String)>)>,
}

/// Parses the registry's YAML subset: top-level scalars, a `contact` list,
/// and `compressionTable` as a sequence of `{type, table}` mappings.
///
/// Deliberately independent of the vendor-time Python transcriber, so that
/// a bug in one is not reproduced by the other.
fn parse_entry(text: &str) -> ParsedEntry {
    let mut entry = ParsedEntry::default();
    let mut in_tables = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line == "---" {
            continue;
        }
        let indent = raw.len() - raw.trim_start_matches(' ').len();
        if indent == 0 {
            let (key, value) = line.split_once(':').expect("top-level `key: value`");
            let value = value.trim();
            in_tables = key == "compressionTable";
            match key {
                "domain" => entry.domain = value.to_string(),
                "mode" => entry.mode = value.to_string(),
                "provisional" => {
                    entry.provisional = match value {
                        "true" => true,
                        "false" => false,
                        other => panic!("`provisional` must be a boolean, found {other:?}"),
                    };
                }
                _ => {}
            }
            continue;
        }
        if !in_tables {
            continue; // `contact` list items are registration metadata, not wire format
        }
        if let Some(table_type) = line.strip_prefix("- type:") {
            entry
                .tables
                .push((table_type.trim().to_string(), Vec::new()));
            continue;
        }
        if line == "table:" {
            continue;
        }
        let (id, value) = line.split_once(':').expect("`<id>: <value>` table row");
        let id: u64 = id.trim().parse().expect("integer table identifier");
        entry
            .tables
            .last_mut()
            .expect("table row inside a compressionTable entry")
            .1
            .push((id, value.trim().to_string()));
    }
    entry
}

/// Asserts that the transcribed entry `id` matches its vendored YAML.
fn assert_matches_vendored(id: u64, yaml: &str, expected_tables: &[(&str, usize)]) {
    let parsed = parse_entry(yaml);
    let entry = registry_entry(id).unwrap_or_else(|| panic!("registry entry {id} is vendored"));

    assert_eq!(entry.id, id, "entry {id}: identifier");
    assert_eq!(entry.domain, parsed.domain, "entry {id}: domain");
    assert_eq!(entry.mode, parsed.mode, "entry {id}: processing model");
    assert_eq!(
        entry.provisional, parsed.provisional,
        "entry {id}: provisional flag"
    );

    assert_eq!(
        entry.sub_tables.len(),
        parsed.tables.len(),
        "entry {id}: sub-table count"
    );
    for (table, (table_type, rows)) in entry.sub_tables.iter().zip(&parsed.tables) {
        assert_eq!(table.table_type, table_type, "entry {id}: sub-table type");
        assert_eq!(
            table.entries.len(),
            rows.len(),
            "entry {id}: {table_type} row count"
        );
        for (transcribed, parsed_row) in table.entries.iter().zip(rows) {
            assert_eq!(
                (transcribed.0, transcribed.1),
                (parsed_row.0, parsed_row.1.as_str()),
                "entry {id}: {table_type} row"
            );
            assert_eq!(
                table.value_of(parsed_row.0),
                Some(parsed_row.1.as_str()),
                "entry {id}: {table_type} lookup by identifier"
            );
            assert_eq!(
                table.id_of(&parsed_row.1),
                Some(parsed_row.0),
                "entry {id}: {table_type} lookup by value"
            );
        }
    }

    // The shape assertion is written out by hand from the YAML so that a
    // matched pair of parser and transcriber bugs still fails this test.
    let shape: Vec<(&str, usize)> = entry
        .sub_tables
        .iter()
        .map(|table| (table.table_type, table.entries.len()))
        .collect();
    assert_eq!(shape, expected_tables, "entry {id}: expected shape");
}

const CRYPTOSUITE: &str = "https://w3id.org/security#cryptosuiteString";

#[test]
fn entry_0_is_the_uncompressed_default_mode_with_no_table() {
    assert_matches_vendored(
        0,
        include_str!("../vendor/cborld-registry/tables/0.yml"),
        &[],
    );
    let entry = registry_entry(0).expect("entry 0");
    assert!(!entry.provisional, "entry 0 is reserved, not provisional");
    assert!(
        !entry.uses_semantic_compression(),
        "entry 0 carries plain CBOR"
    );
}

#[test]
fn entry_1_is_the_compressed_default_mode_with_no_table() {
    assert_matches_vendored(
        1,
        include_str!("../vendor/cborld-registry/tables/1.yml"),
        &[],
    );
    let entry = registry_entry(1).expect("entry 1");
    assert!(!entry.provisional, "entry 1 is reserved, not provisional");
    assert!(entry.uses_semantic_compression(), "entry 1 compresses");
}

#[test]
fn entry_100_verifiable_credential_barcodes_examples() {
    assert_matches_vendored(
        100,
        include_str!("../vendor/cborld-registry/tables/100.yml"),
        &[(TABLE_TYPE_CONTEXT, 3), (CRYPTOSUITE, 4)],
    );
    let entry = registry_entry(100).expect("entry 100");
    assert_eq!(
        entry
            .sub_table(TABLE_TYPE_CONTEXT)
            .and_then(|table| table.value_of(32_768)),
        Some("https://www.w3.org/ns/credentials/v2"),
        "entry 100 starts its context identifiers at 32768"
    );
    assert!(
        entry.sub_table(TABLE_TYPE_URL).is_none(),
        "entry 100 defines no url table"
    );
}

#[test]
fn entry_10001_provisional_california_dmv_test_credentials() {
    assert_matches_vendored(
        10001,
        include_str!("../vendor/cborld-registry/tables/10001.yml"),
        &[
            (TABLE_TYPE_CONTEXT, 4),
            (CRYPTOSUITE, 1),
            (TABLE_TYPE_URL, 3),
        ],
    );
}

#[test]
fn entry_10002_provisional_first_responder_credentials() {
    assert_matches_vendored(
        10002,
        include_str!("../vendor/cborld-registry/tables/10002.yml"),
        &[
            (TABLE_TYPE_CONTEXT, 5),
            (CRYPTOSUITE, 1),
            (TABLE_TYPE_URL, 3),
        ],
    );
}

#[test]
fn entry_10003_california_instant_identity_credentials() {
    assert_matches_vendored(
        10003,
        include_str!("../vendor/cborld-registry/tables/10003.yml"),
        &[(TABLE_TYPE_CONTEXT, 3), (CRYPTOSUITE, 1)],
    );
}

#[test]
fn entry_31000000_california_dmv_physical_identification_documents() {
    assert_matches_vendored(
        31000000,
        include_str!("../vendor/cborld-registry/tables/31000000.yml"),
        &[
            (TABLE_TYPE_CONTEXT, 2),
            (CRYPTOSUITE, 1),
            (TABLE_TYPE_URL, 28),
        ],
    );
}

#[test]
fn entry_31000001_california_dmv_disabled_person_parking_placards() {
    assert_matches_vendored(
        31000001,
        include_str!("../vendor/cborld-registry/tables/31000001.yml"),
        &[
            (TABLE_TYPE_CONTEXT, 3),
            (CRYPTOSUITE, 1),
            (TABLE_TYPE_URL, 28),
        ],
    );
}

#[test]
fn entry_32000000_utopia_demo_verifiable_credentials() {
    assert_matches_vendored(
        32000000,
        include_str!("../vendor/cborld-registry/tables/32000000.yml"),
        &[
            (TABLE_TYPE_CONTEXT, 4),
            (CRYPTOSUITE, 2),
            (TABLE_TYPE_URL, 3),
        ],
    );
}

#[test]
fn the_registry_holds_exactly_the_nine_vendored_entries() {
    let ids: Vec<u64> = REGISTRY_ENTRIES.iter().map(|entry| entry.id).collect();
    assert_eq!(
        ids,
        vec![0, 1, 100, 10001, 10002, 10003, 31000000, 31000001, 32000000],
        "the pinned upstream commit publishes exactly these nine entries"
    );
}

#[test]
fn only_entries_0_and_1_are_non_provisional() {
    for entry in &REGISTRY_ENTRIES {
        let expected = entry.id > 1;
        assert_eq!(
            entry.provisional, expected,
            "entry {}: entries 0 and 1 are the reserved W3C default modes; \
             every other vendored entry is marked provisional upstream",
            entry.id
        );
    }
}

#[test]
fn every_vendored_entry_uses_the_default_processing_model() {
    for entry in &REGISTRY_ENTRIES {
        assert!(
            entry.uses_default_processing_model(),
            "entry {}: this codec implements only the default processing \
             model and must refuse anything else",
            entry.id
        );
    }
}

#[test]
fn sub_table_identifiers_are_ascending_and_unique() {
    // `SubTable::value_of` binary-searches by identifier, so ascending order
    // is a correctness precondition, not a formatting preference.
    for entry in &REGISTRY_ENTRIES {
        for table in entry.sub_tables {
            let ids: Vec<u64> = table.entries.iter().map(|(id, _)| *id).collect();
            let mut sorted = ids.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                ids, sorted,
                "entry {}: {} identifiers must ascend without duplicates",
                entry.id, table.table_type
            );
        }
    }
}

#[test]
fn sub_table_values_are_unique_within_a_table() {
    // `SubTable::id_of` returns the first match, so a duplicated value would
    // make the encode direction depend on row order.
    for entry in &REGISTRY_ENTRIES {
        for table in entry.sub_tables {
            let mut values: Vec<&str> = table.entries.iter().map(|(_, value)| *value).collect();
            let before = values.len();
            values.sort_unstable();
            values.dedup();
            assert_eq!(
                values.len(),
                before,
                "entry {}: {} maps two identifiers to one value",
                entry.id,
                table.table_type
            );
        }
    }
}

#[test]
fn sub_table_types_are_context_url_or_a_json_ld_type_iri() {
    for entry in &REGISTRY_ENTRIES {
        for table in entry.sub_tables {
            assert_ne!(
                table.table_type, TABLE_TYPE_NONE,
                "entry {}: `none` is the codec's stand-in for an untyped \
                 term and must never name a registry sub-table",
                entry.id
            );
            let reserved =
                table.table_type == TABLE_TYPE_CONTEXT || table.table_type == TABLE_TYPE_URL;
            assert!(
                reserved || table.table_type.contains(':'),
                "entry {}: sub-table type {:?} is neither reserved nor an IRI",
                entry.id,
                table.table_type
            );
        }
    }
}

#[test]
fn no_vendored_entry_defines_a_multibase_sub_table() {
    // `sec:multibase` is absent from the spec's `typesEncodedAsBytes`, so a
    // sub-table identifier for it would ride as an unsigned integer while the
    // multibase codec's own output rides as a byte string — leaving a
    // compressed multibase value and a literal integer indistinguishable on
    // decode. `resolve_registry_entry` refuses such an entry outright; this
    // test records that no vendored entry needs that refusal today, so the
    // guard stays a tripwire rather than a live restriction.
    for entry in &REGISTRY_ENTRIES {
        assert!(
            entry.sub_table(MULTIBASE_IRI).is_none(),
            "entry {}: a multibase sub-table appeared upstream; the codec now \
             refuses this entry, and the ambiguity must be resolved before it \
             can be supported again",
            entry.id
        );
    }
}

#[test]
fn unvendored_identifiers_have_no_registry_entry() {
    // Neighbours of real entries, which is where a fabricated table would
    // most plausibly be invented.
    for id in [
        2,
        7,
        99,
        101,
        10000,
        10004,
        30999999,
        31000002,
        32000001,
        u64::MAX,
    ] {
        assert!(
            registry_entry(id).is_none(),
            "identifier {id} is not vendored and must not resolve"
        );
    }
}

#[test]
fn entries_expose_their_tables_by_type_only() {
    let entry: &RegistryEntry = registry_entry(10001).expect("entry 10001");
    assert!(entry.sub_table(TABLE_TYPE_URL).is_some());
    assert!(entry.sub_table(CRYPTOSUITE).is_some());
    assert!(
        entry.sub_table("https://example.invalid/absent").is_none(),
        "an unlisted table type must not resolve to some other table"
    );
}
