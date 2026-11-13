// Rust guideline compliant 2026-02-21
//! The `UnsignedQuadStream` v1 Arrow contract schema.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use arrow_schema::{DataType, Field, Schema, TimeUnit};

use crate::error::QuadError;

/// Contract name recorded in schema metadata.
pub const CONTRACT_NAME: &str = "UnsignedQuadStream";

/// Contract version recorded in schema metadata.
///
/// Stays `"1"` across the RDF 1.2 triple-term extension: that change added a
/// value (`"triple"`) to the `object_kind` vocabulary and touched no field,
/// type, nullability, or metadata entry, so v1 batches written before it
/// decode unchanged and every existing validator still accepts. See
/// [`crate::quoted`] for the full rationale.
pub const CONTRACT_VERSION: &str = "1";

/// Arrow major.minor.patch this contract is pinned to.
///
/// Must match the workspace pin and the `dataplane.arrow_version` used by
/// downstream contracts so IPC payloads stay byte-compatible across
/// planes.
const ARROW_VERSION: &str = "58.3.0";

/// Term kind marker for IRIs.
pub const TERM_KIND_IRI: &str = "iri";
/// Term kind marker for blank nodes.
pub const TERM_KIND_BNODE: &str = "bnode";
/// Term kind marker for literals.
pub const TERM_KIND_LITERAL: &str = "literal";
/// Graph kind marker for the default graph.
pub const GRAPH_KIND_DEFAULT: &str = "default";
/// Graph kind marker for IRI-named graphs.
pub const GRAPH_KIND_IRI: &str = TERM_KIND_IRI;
/// Graph kind marker for blank-node-named graphs.
pub const GRAPH_KIND_BNODE: &str = TERM_KIND_BNODE;

/// Column index of `subject_kind`.
pub(crate) const COL_SUBJECT_KIND: usize = 0;
/// Column index of `subject_value`.
pub(crate) const COL_SUBJECT_VALUE: usize = 1;
/// Column index of `predicate_iri`.
pub(crate) const COL_PREDICATE_IRI: usize = 2;
/// Column index of `object_kind`.
pub(crate) const COL_OBJECT_KIND: usize = 3;
/// Column index of `object_value`.
pub(crate) const COL_OBJECT_VALUE: usize = 4;
/// Column index of `object_datatype_iri`.
pub(crate) const COL_OBJECT_DATATYPE: usize = 5;
/// Column index of `object_language`.
pub(crate) const COL_OBJECT_LANGUAGE: usize = 6;
/// Column index of `graph_kind`.
pub(crate) const COL_GRAPH_KIND: usize = 7;
/// Column index of `graph_value`.
pub(crate) const COL_GRAPH_VALUE: usize = 8;
/// Column index of `source_artifact_iri`.
pub(crate) const COL_SOURCE_ARTIFACT: usize = 9;
/// Column index of `source_content_sha256`.
pub(crate) const COL_SOURCE_SHA256: usize = 10;
/// Column index of `source_offset_start`.
pub(crate) const COL_SOURCE_OFFSET_START: usize = 11;
/// Column index of `source_offset_end`.
pub(crate) const COL_SOURCE_OFFSET_END: usize = 12;
/// Column index of `observed_at`.
pub(crate) const COL_OBSERVED_AT: usize = 13;

fn dict_utf8(name: &str, nullable: bool) -> Field {
    Field::new(
        name,
        DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
        nullable,
    )
}

fn metadata() -> HashMap<String, String> {
    HashMap::from([
        ("dataplane.contract".into(), CONTRACT_NAME.into()),
        ("dataplane.contract_version".into(), CONTRACT_VERSION.into()),
        ("dataplane.arrow_version".into(), ARROW_VERSION.into()),
        ("dataplane.assurance".into(), "unsigned".into()),
    ])
}

/// Returns the `UnsignedQuadStream` v1 schema.
///
/// Term columns are dictionary-encoded (`Dictionary<UInt32, Utf8>`) except
/// `object_value`, which is plain `Utf8` because literal lexical forms are
/// high-cardinality and rarely repeat.
#[must_use]
pub fn quad_stream_schema() -> Arc<Schema> {
    Arc::new(Schema::new_with_metadata(
        vec![
            dict_utf8("subject_kind", false),
            dict_utf8("subject_value", false),
            dict_utf8("predicate_iri", false),
            dict_utf8("object_kind", false),
            Field::new("object_value", DataType::Utf8, false),
            dict_utf8("object_datatype_iri", true),
            dict_utf8("object_language", true),
            dict_utf8("graph_kind", false),
            dict_utf8("graph_value", true),
            dict_utf8("source_artifact_iri", true),
            Field::new("source_content_sha256", DataType::FixedSizeBinary(32), true),
            Field::new("source_offset_start", DataType::UInt64, true),
            Field::new("source_offset_end", DataType::UInt64, true),
            Field::new(
                "observed_at",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                true,
            ),
        ],
        metadata(),
    ))
}

/// Validates that `schema` is exactly the `UnsignedQuadStream` v1 contract.
///
/// Field identity and the full metadata map are compared. Extra keys, a
/// drifted `dataplane.arrow_version`, or a missing `dataplane.assurance` are all
/// contract errors — the same exact-schema rule downstream consumers use.
///
/// # Errors
///
/// Returns [`QuadError::Contract`] when field names, types, nullability, or
/// the contract metadata do not match the pinned contract.
pub fn validate_contract(schema: &Schema) -> Result<(), QuadError> {
    let expected = quad_stream_schema();
    if schema.fields() != expected.fields() {
        return Err(QuadError::Contract(format!(
            "schema fields do not match {CONTRACT_NAME} v{CONTRACT_VERSION}"
        )));
    }
    if schema.metadata() != expected.metadata() {
        // Rendered through a BTreeMap: `Schema::metadata` is a `HashMap`, whose
        // iteration order varies between calls, so formatting it directly makes
        // the same rejection produce a different message each time. Refusals
        // must be byte-identical to be comparable across runs and diffable in a
        // log, so the ordering is imposed here rather than left to chance.
        let got: BTreeMap<&str, &str> = schema
            .metadata()
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let want: BTreeMap<&str, &str> = expected
            .metadata()
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        return Err(QuadError::Contract(format!(
            "schema metadata does not match {CONTRACT_NAME} v{CONTRACT_VERSION}: got {got:?}, expected {want:?}"
        )));
    }
    Ok(())
}
