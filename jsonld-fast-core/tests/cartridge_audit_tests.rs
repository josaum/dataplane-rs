// Rust guideline compliant 2026-09-01
//! Cartridge audit interop: emitted Atlas Brain event lines decode to quads.
//!
//! The fixture below is one line of the durable cartridge event log
//! (`cartridges/atlas/events.jsonl` shape: `<data_root>/events/
//! atlas_events.jsonl`), captured from the real emission path on 2026-09-01.
//! Regenerate with the workspace root as cwd:
//!
//! ```text
//! uv run --project . python -c "
//! import tempfile
//! from pathlib import Path
//! from cartridges.atlas.config import AtlasConfig
//! from cartridges.atlas.events import record_observation
//! from cartridges.atlas.types import MetricGrain, MetricObservation, SourceName
//! with tempfile.TemporaryDirectory() as td:
//!     record_observation(MetricObservation(metric_id='roas',
//!         source=SourceName.PACVUE, entity_id='asin:B0XYZ',
//!         grain=MetricGrain.ASIN, value=3.6), config=AtlasConfig(data_root=td))
//!     print((Path(td) / 'events' / 'atlas_events.jsonl').read_text().strip())
//! "
//! ```
//!
//! The event identifier and timestamps change per run; the quad shape does
//! not. The context is inline (sovereign requirement), every graph reference
//! is an absolute IRI, and the audit contract is that nothing in the line is
//! silently dropped at expansion.

use jsonld_fast_core::{JsonLdOptions, from_quads, to_quads};
use quad_fast_core::QuadStreamReader;
use serde_json::{Value, json};

const EVENT_LINE: &str = r#"{"@context":{"@version":1.1,"@vocab":"urn:atlas:","atlas":"urn:atlas:","xsd":"http://www.w3.org/2001/XMLSchema#","id":"@id","type":"@type","named_graph":{"@id":"atlas:namedGraph","@type":"@id"},"occurred_at":{"@id":"atlas:occurredAt","@type":"xsd:dateTime"},"metric_id":"atlas:metricId","target_metric_id":"atlas:metricId","entity_id":"atlas:entityId","source":"atlas:source","detail":"atlas:detail","question":"atlas:question","persona":"atlas:persona","status":"atlas:status","grain":"atlas:grain","event_id":{"@id":"atlas:eventId","@type":"@id"},"trace_id":{"@id":"atlas:traceId","@type":"@id"},"hypotheses":{"@id":"atlas:hypotheses","@container":"@set"},"paths":{"@id":"atlas:paths","@container":"@set"},"signed_by":"atlas:signedBy","corrected_label":"atlas:correctedLabel"},"id":"urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e","type":"ObservationRecorded","named_graph":"urn:atlas:graph:events:v1","occurred_at":"2026-09-01T19:34:35.499204Z","metric_id":"roas","source":"pacvue","entity_id":"asin:B0XYZ","detail":{"value":3.6,"grain":"asin","asOf":"2026-09-01T19:34:35.499035+00:00"}}"#;

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
fn cartridge_event_line_decodes_to_audit_quads() {
    let batches = to_quads(&event_document(), &JsonLdOptions::default(), None)
        .expect("event line expands to quads");
    assert_eq!(sorted_quad_lines(&batches), vec![
        // The event node: identity, type, and the named-graph link survive.
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <urn:atlas:ObservationRecorded>".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:atlas:detail> _:b0".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:atlas:entityId> \"asin:B0XYZ\"".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:atlas:metricId> \"roas\"".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:atlas:namedGraph> <urn:atlas:graph:events:v1>".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:atlas:occurredAt> \"2026-09-01T19:34:35.499204Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime>".to_string(),
        "<urn:uuid:7bb73a56-9116-44e7-a5d3-0c5061ed805e> <urn:atlas:source> \"pacvue\"".to_string(),
        // The detail block rides @vocab on a blank node: no silent loss.
        "_:b0 <urn:atlas:asOf> \"2026-09-01T19:34:35.499035+00:00\"".to_string(),
        "_:b0 <urn:atlas:grain> \"asin\"".to_string(),
        "_:b0 <urn:atlas:value> \"3.6E0\"^^<http://www.w3.org/2001/XMLSchema#double>".to_string(),
    ]);
}

#[test]
fn cartridge_event_line_round_trips_through_quads() {
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
        event.get("urn:atlas:namedGraph"),
        Some(&json!([{"@id": "urn:atlas:graph:events:v1"}]))
    );
    assert_eq!(
        event.get("@type"),
        Some(&json!(["urn:atlas:ObservationRecorded"]))
    );
    assert_eq!(
        event.get("urn:atlas:detail"),
        Some(&json!([{"@id": "_:b0"}]))
    );
}
