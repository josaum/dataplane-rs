// Rust guideline compliant 2026-09-01
//! Telemetry audit interop: emitted JSON-LD event lines decode to quads.
//!
//! The fixture below represents one line of a durable JSON-LD event log
//! with an inline context, absolute named-graph IRIs, and nested blank-node
//! observation details.
//!
//! The context is inline (sovereign requirement), every graph reference
//! is an absolute IRI, and the audit contract is that nothing in the line is
//! silently dropped at expansion.

use jsonld_fast_core::{JsonLdOptions, from_quads, to_quads};
use quad_fast_core::QuadStreamReader;
use serde_json::{Value, json};

const EVENT_LINE: &str = r#"{"@context":{"@version":1.1,"@vocab":"urn:dataplane:","dp":"urn:dataplane:","xsd":"http://www.w3.org/2001/XMLSchema#","id":"@id","type":"@type","named_graph":{"@id":"dp:namedGraph","@type":"@id"},"occurred_at":{"@id":"dp:occurredAt","@type":"xsd:dateTime"},"metric_id":"dp:metricId","target_metric_id":"dp:metricId","entity_id":"dp:entityId","source":"dp:source","detail":"dp:detail","question":"dp:question","persona":"dp:persona","status":"dp:status","grain":"dp:grain","event_id":{"@id":"dp:eventId","@type":"@id"},"trace_id":{"@id":"dp:traceId","@type":"@id"},"hypotheses":{"@id":"dp:hypotheses","@container":"@set"},"paths":{"@id":"dp:paths","@container":"@set"},"signed_by":"dp:signedBy","corrected_label":"dp:correctedLabel"},"id":"urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e","type":"ObservationRecorded","named_graph":"urn:dataplane:graph:events:v1","occurred_at":"2026-09-01T19:34:35.499204Z","metric_id":"latency_ms","source":"telemetry","entity_id":"sensor:S100","detail":{"value":3.6,"grain":"sensor","asOf":"2026-09-01T19:34:35.499035+00:00"}}"#;

fn event_document() -> Value {
    serde_json::from_str(EVENT_LINE).expect("fixture is valid JSON")
}

fn sorted_quad_lines(batches: &[arrow_array::RecordBatch]) -> Vec<String> {
    let mut lines = Vec::new();
    for batch in batches {
        let reader = QuadStreamReader::new(batch).expect("valid batch");
        for row in 0..reader.len() {
            lines.push(reader.quad(row).expect("valid quad").to_string());
        }
    }
    lines.sort();
    lines
}

#[test]
fn telemetry_event_line_decodes_to_audit_quads() {
    let batches = to_quads(&event_document(), &JsonLdOptions::default(), None)
        .expect("event line expands to quads");
    assert_eq!(sorted_quad_lines(&batches), vec![
        // The event node: identity, type, and the named-graph link survive.
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <urn:dataplane:ObservationRecorded>".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:dataplane:detail> _:b0".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:dataplane:entityId> \"sensor:S100\"".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:dataplane:metricId> \"latency_ms\"".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:dataplane:namedGraph> <urn:dataplane:graph:events:v1>".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:dataplane:occurredAt> \"2026-09-01T19:34:35.499204Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime>".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:dataplane:source> \"telemetry\"".to_string(),
        // The detail block rides @vocab on a blank node: no silent loss.
        "_:b0 <urn:dataplane:asOf> \"2026-09-01T19:34:35.499035+00:00\"".to_string(),
        "_:b0 <urn:dataplane:grain> \"sensor\"".to_string(),
        "_:b0 <urn:dataplane:value> \"3.6E0\"^^<http://www.w3.org/2001/XMLSchema#double>".to_string(),
    ]);
}

#[test]
fn telemetry_event_line_round_trips_through_quads() {
    let batches = to_quads(&event_document(), &JsonLdOptions::default(), None)
        .expect("event line expands to quads");
    let expanded = from_quads(&batches).expect("quads serialize back to JSON-LD");

    let event = expanded
        .as_array()
        .expect("expanded document is an array")
        .iter()
        .find(|node| {
            node.get("@id") == Some(&json!("urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e"))
        })
        .expect("event node survives the round trip");
    assert_eq!(
        event.get("urn:dataplane:namedGraph"),
        Some(&json!([{"@id": "urn:dataplane:graph:events:v1"}]))
    );
    assert_eq!(
        event.get("@type"),
        Some(&json!(["urn:dataplane:ObservationRecorded"]))
    );
    assert_eq!(
        event.get("urn:dataplane:detail"),
        Some(&json!([{"@id": "_:b0"}]))
    );
}
