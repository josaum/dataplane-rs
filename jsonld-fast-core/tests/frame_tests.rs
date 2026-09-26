// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Framing coverage (JSON-LD 1.1 Framing REC): the Framing Algorithm
//! (section 4.1), Frame Matching (section 4.2), and Value Pattern Matching
//! (section 4.3), plus the fail-closed frame grammar errors
//! (`invalid frame`, `invalid @embed value`).

use jsonld_fast_core::{JsonLdError, JsonLdOptions, expand, frame};
use serde_json::{Value, json};

fn frame_ok(document: &Value, frame_value: &Value) -> Value {
    frame(document, frame_value, &JsonLdOptions::default()).expect("framing succeeds")
}

fn frame_err(document: &Value, frame_value: &Value) -> JsonLdError {
    frame(document, frame_value, &JsonLdOptions::default()).expect_err("framing fails closed")
}

/// A small library document reused across the matching tests.
fn library() -> Value {
    json!({
        "@context": {"ex": "http://example.org/"},
        "@graph": [
            {
                "@id": "http://example.org/library",
                "@type": "ex:Library",
                "ex:contains": {"@id": "http://example.org/book"}
            },
            {
                "@id": "http://example.org/book",
                "@type": "ex:Book",
                "ex:title": "Moby Dick",
                "ex:contains": {"@id": "http://example.org/chapter"}
            },
            {
                "@id": "http://example.org/chapter",
                "@type": "ex:Chapter",
                "ex:title": "Loomings"
            }
        ]
    })
}

// ===========================================================================
// 1. Frame matching (Framing section 4.2)
// ===========================================================================

/// Framing section 4.2: a frame with `@type` matches nodes carrying that
/// type, and matched nodes embed their referenced objects (section 4.1).
#[test]
fn type_frame_matches_and_embeds() {
    let framed = frame_ok(
        &library(),
        &json!({"@context": {"ex": "http://example.org/"}, "@type": "ex:Library"}),
    );
    assert_eq!(framed["@id"], "ex:library");
    assert_eq!(framed["@type"], "ex:Library");
    assert_eq!(framed["ex:contains"]["@id"], "ex:book");
    assert_eq!(framed["ex:contains"]["ex:title"], "Moby Dick");
}

/// Framing section 4.2: an `@id` node pattern selects exactly that subject.
#[test]
fn id_frame_selects_one_subject() {
    let framed = frame_ok(
        &library(),
        &json!({
            "@context": {"ex": "http://example.org/"},
            "@id": "http://example.org/chapter"
        }),
    );
    assert_eq!(framed["@id"], "ex:chapter");
    assert_eq!(framed["ex:title"], "Loomings");
}

/// Framing section 4.2: the empty frame is a wildcard matching every node.
#[test]
fn empty_frame_is_a_wildcard() {
    let framed = frame_ok(
        &library(),
        &json!({"@context": {"ex": "http://example.org/"}}),
    );
    assert_eq!(framed["@graph"].as_array().expect("array").len(), 3);
}

/// Framing section 4.2: a property with an empty map is a wildcard on that
/// property (node must have some value).
#[test]
fn property_wildcard_requires_a_value() {
    let framed = frame_ok(
        &library(),
        &json!({"@context": {"ex": "http://example.org/"}, "ex:title": {}}),
    );
    let ids: Vec<&Value> = framed["@graph"]
        .as_array()
        .expect("array")
        .iter()
        .map(|node| &node["@id"])
        .collect();
    assert_eq!(ids, vec![&json!("ex:book"), &json!("ex:chapter")]);
}

/// Framing section 4.2: a property framed with an empty array is match-none
/// — only nodes lacking the property match.
#[test]
fn match_none_selects_nodes_without_the_property() {
    let framed = frame_ok(
        &library(),
        &json!({"@context": {"ex": "http://example.org/"}, "ex:title": []}),
    );
    assert_eq!(framed["@id"], "ex:library");
    assert!(framed.get("@graph").is_none());
}

/// Framing section 4.2: with `@requireAll`, every listed property must be
/// present, not merely one of them.
#[test]
fn require_all_demands_every_property() {
    let document = json!({
        "@context": {"ex": "http://example.org/"},
        "@graph": [
            {"@id": "ex:a", "ex:p": "1", "ex:q": "2"},
            {"@id": "ex:b", "ex:p": "1"}
        ]
    });
    let strict = frame_ok(
        &document,
        &json!({
            "@context": {"ex": "http://example.org/"},
            "@requireAll": true,
            "ex:p": {},
            "ex:q": {}
        }),
    );
    assert_eq!(strict["@id"], "ex:a");

    let loose = frame_ok(
        &document,
        &json!({
            "@context": {"ex": "http://example.org/"},
            "ex:p": {},
            "ex:q": {}
        }),
    );
    assert_eq!(loose["@graph"].as_array().expect("array").len(), 2);
}

/// Framing section 4.3: a value pattern matches on the concrete value.
#[test]
fn value_pattern_matching() {
    let hit = frame_ok(
        &library(),
        &json!({"@context": {"ex": "http://example.org/"}, "ex:title": "Loomings"}),
    );
    assert_eq!(hit["@id"], "ex:chapter");

    let miss = frame(
        &library(),
        &json!({"@context": {"ex": "http://example.org/"}, "ex:title": "Nothing"}),
        &JsonLdOptions::default(),
    )
    .expect("framing succeeds");
    assert!(
        miss.get("@graph")
            .is_none_or(|graph| graph.as_array().expect("array").is_empty())
    );
}

// ===========================================================================
// 2. @embed, @explicit, @default, @omitDefault (Framing section 4.1)
// ===========================================================================

/// Framing section 4.1: `@embed: @never` leaves node references unexpanded.
#[test]
fn embed_never_keeps_node_references() {
    let framed = frame_ok(
        &library(),
        &json!({
            "@context": {"ex": "http://example.org/"},
            "@type": "ex:Library",
            "@embed": "@never"
        }),
    );
    // A top-level `@embed: @never` match is emitted as a node reference.
    assert_eq!(framed["@id"], "ex:library");
    assert!(framed.get("ex:contains").is_none());
}

/// Framing section 4.1: `@embed: @once` embeds a node the first time only.
#[test]
fn embed_once_embeds_a_node_a_single_time() {
    let document = json!({
        "@context": {"ex": "http://example.org/"},
        "@graph": [
            {"@id": "ex:a", "ex:p": {"@id": "ex:shared"}},
            {"@id": "ex:b", "ex:p": {"@id": "ex:shared"}},
            {"@id": "ex:shared", "ex:name": "shared"}
        ]
    });
    let framed = frame_ok(
        &document,
        &json!({"@context": {"ex": "http://example.org/"}, "@embed": "@once"}),
    );
    let embedded = framed["@graph"]
        .as_array()
        .expect("array")
        .iter()
        .filter(|node| node["ex:p"].get("ex:name").is_some())
        .count();
    assert_eq!(embedded, 1);
}

/// Framing section 4.1: `@embed: @always` embeds at every reference.
#[test]
fn embed_always_embeds_every_reference() {
    let document = json!({
        "@context": {"ex": "http://example.org/"},
        "@graph": [
            {"@id": "ex:a", "ex:p": {"@id": "ex:shared"}},
            {"@id": "ex:b", "ex:p": {"@id": "ex:shared"}},
            {"@id": "ex:shared", "ex:name": "shared"}
        ]
    });
    let framed = frame_ok(
        &document,
        &json!({"@context": {"ex": "http://example.org/"}, "@embed": "@always"}),
    );
    let embedded = framed["@graph"]
        .as_array()
        .expect("array")
        .iter()
        .filter(|node| node["ex:p"].get("ex:name").is_some())
        .count();
    assert_eq!(embedded, 2);
}

/// Framing section 4.1: `@explicit: true` keeps only the framed properties.
#[test]
fn explicit_drops_unframed_properties() {
    let framed = frame_ok(
        &library(),
        &json!({
            "@context": {"ex": "http://example.org/"},
            "@explicit": true,
            "@type": "ex:Book",
            "ex:title": {}
        }),
    );
    assert_eq!(framed["ex:title"], "Moby Dick");
    assert!(framed.get("ex:contains").is_none());
}

/// Framing section 4.1: `@default` supplies a value for a missing property.
#[test]
fn default_value_fills_missing_property() {
    let framed = frame_ok(
        &library(),
        &json!({
            "@context": {"ex": "http://example.org/"},
            "@type": "ex:Library",
            "ex:title": {"@default": "Untitled"}
        }),
    );
    assert_eq!(framed["ex:title"], "Untitled");
}

/// Framing section 4.1: `@omitDefault: true` omits the property entirely
/// instead of inserting `@null`/a default.
#[test]
fn omit_default_removes_the_missing_property() {
    let framed = frame_ok(
        &library(),
        &json!({
            "@context": {"ex": "http://example.org/"},
            "@type": "ex:Library",
            "@omitDefault": true,
            "ex:title": {}
        }),
    );
    assert!(framed.get("ex:title").is_none());
}

// ===========================================================================
// 3. Determinism, blank nodes, graphs, and compaction of the output
// ===========================================================================

/// Framing section 4.1: blank nodes are relabeled deterministically and
/// single-use identifiers are pruned from the output.
#[test]
fn blank_nodes_are_deterministic_and_pruned() {
    let document = json!({
        "@context": {"ex": "http://example.org/"},
        "@id": "http://example.org/root",
        "ex:p": {"ex:name": "anonymous"}
    });
    let frame_value =
        json!({"@context": {"ex": "http://example.org/"}, "@id": "http://example.org/root"});
    let first = frame_ok(&document, &frame_value);
    let second = frame_ok(&document, &frame_value);
    assert_eq!(first, second);
    assert_eq!(first["ex:p"]["ex:name"], "anonymous");
    assert!(
        first["ex:p"].get("@id").is_none(),
        "single-use blank node pruned: {first}"
    );
}

/// Framing section 4.1: output ordering is stable across runs and sorted by
/// subject.
#[test]
fn framed_output_is_ordered_and_stable() {
    let document = json!({
        "@context": {"ex": "http://example.org/"},
        "@graph": [
            {"@id": "http://example.org/c", "ex:p": "3"},
            {"@id": "http://example.org/a", "ex:p": "1"},
            {"@id": "http://example.org/b", "ex:p": "2"}
        ]
    });
    let framed = frame_ok(
        &document,
        &json!({"@context": {"ex": "http://example.org/"}}),
    );
    let ids: Vec<&str> = framed["@graph"]
        .as_array()
        .expect("array")
        .iter()
        .map(|node| node["@id"].as_str().expect("id"))
        .collect();
    assert_eq!(ids, vec!["ex:a", "ex:b", "ex:c"]);
}

/// Framing section 4.1: the framed output is compacted with the frame's own
/// context, including keyword aliasing.
#[test]
fn output_is_compacted_with_the_frame_context() {
    let framed = frame_ok(
        &library(),
        &json!({
            "@context": {"ex": "http://example.org/", "id": "@id", "kind": "@type", "title": "ex:title"},
            "kind": "ex:Chapter"
        }),
    );
    assert_eq!(framed["id"], "ex:chapter");
    assert_eq!(framed["title"], "Loomings");
}

/// The framed output re-expands to a subset of the input's expansion: the
/// selected node keeps its original expanded shape.
#[test]
fn framed_output_round_trips_through_expansion() {
    let options = JsonLdOptions::default();
    let framed = frame_ok(
        &library(),
        &json!({
            "@context": {"ex": "http://example.org/"},
            "@id": "http://example.org/chapter"
        }),
    );
    let expanded = expand(&framed, &options).expect("framed output expands");
    assert_eq!(
        expanded,
        json!([{
            "@id": "http://example.org/chapter",
            "@type": ["http://example.org/Chapter"],
            "http://example.org/title": [{"@value": "Loomings"}]
        }])
    );
}

// ===========================================================================
// 4. Fail-closed frame grammar and refusals
// ===========================================================================

/// Framing section 4.1: a non-map frame is the `invalid frame` error.
#[test]
fn non_map_frame_is_invalid() {
    let error = frame_err(&library(), &json!(["not a frame"]));
    assert!(matches!(error, JsonLdError::InvalidFrame(_)), "{error:?}");
    assert_eq!(error.code(), "invalid_frame");
}

/// Framing section 4.1: `@embed` must be one of `@once`, `@always`,
/// `@never` — anything else is `invalid @embed value`.
#[test]
fn bad_embed_value_is_refused() {
    let error = frame_err(
        &library(),
        &json!({"@context": {"ex": "http://example.org/"}, "@embed": "@sometimes"}),
    );
    assert!(
        matches!(error, JsonLdError::InvalidEmbedValue { .. }),
        "{error:?}"
    );
    assert_eq!(error.code(), "invalid_embed_value");
}

/// The sovereign no-network boundary: a remote frame context is refused,
/// naming the IRI, never fetched.
#[test]
fn remote_frame_context_is_refused() {
    let error = frame_err(
        &library(),
        &json!({"@context": "https://example.com/frame-context.jsonld"}),
    );
    match error {
        JsonLdError::RemoteContextRefused { ref iri } => {
            assert_eq!(iri, "https://example.com/frame-context.jsonld");
        }
        other => panic!("expected a remote context refusal, got {other:?}"),
    }
}

/// Framing section 2.3: `@reverse` matches incoming edges and embeds the
/// referring nodes.
#[test]
fn reverse_frame_embeds_incoming_nodes() {
    let framed = frame_ok(
        &library(),
        &json!({
            "@context": {"ex": "http://example.org/"},
            "@id": "http://example.org/book",
            "@reverse": {"ex:contains": {}}
        }),
    );
    assert_eq!(framed["@id"], "ex:book");
    assert_eq!(framed["@reverse"]["ex:contains"]["@id"], "ex:library");
    assert_eq!(framed["@reverse"]["ex:contains"]["@type"], "ex:Library");
}

/// Framing section 2.3: a reverse term in the frame context expands to
/// `@reverse` and compact reconstitutes the term.
#[test]
fn reverse_term_in_a_frame_context_round_trips() {
    let framed = frame_ok(
        &library(),
        &json!({
            "@context": {
                "ex": "http://example.org/",
                "containedIn": {"@reverse": "ex:contains"}
            },
            "@id": "http://example.org/book",
            "containedIn": {}
        }),
    );
    assert_eq!(framed["@id"], "ex:book");
    assert_eq!(framed["containedIn"]["@id"], "ex:library");
}

/// Language maps in a frame's context expand and compact through the frame.
#[test]
fn language_map_container_in_a_frame_context() {
    let document = json!({
        "@context": {
            "ex": "http://example.org/",
            "title": {"@id": "ex:title", "@container": "@language"}
        },
        "@id": "http://example.org/book",
        "@type": "ex:Book",
        "title": {"en": "Moby Dick", "de": "Moby Dick"}
    });
    let framed = frame_ok(
        &document,
        &json!({
            "@context": {
                "ex": "http://example.org/",
                "title": {"@id": "ex:title", "@container": "@language"}
            },
            "@type": "ex:Book"
        }),
    );
    assert_eq!(framed["@type"], "ex:Book");
    assert_eq!(framed["title"]["de"], "Moby Dick");
    assert_eq!(framed["title"]["en"], "Moby Dick");
}

/// Property-based indexing in a frame's context reconstitutes the index map.
#[test]
fn property_indexing_in_a_frame_context() {
    let document = json!({
        "@context": {
            "ex": "http://example.org/",
            "contains": {
                "@id": "ex:contains",
                "@container": "@index",
                "@index": "ex:title"
            }
        },
        "@id": "http://example.org/library",
        "@type": "ex:Library",
        "contains": {
            "Moby Dick": {"@id": "http://example.org/book"}
        }
    });
    let framed = frame_ok(
        &document,
        &json!({
            "@context": {
                "ex": "http://example.org/",
                "contains": {
                    "@id": "ex:contains",
                    "@container": "@index",
                    "@index": "ex:title"
                }
            },
            "@type": "ex:Library"
        }),
    );
    assert_eq!(framed["@type"], "ex:Library");
    assert_eq!(framed["contains"]["Moby Dick"]["@id"], "ex:book");
}
