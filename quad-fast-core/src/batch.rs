// Rust guideline compliant 2026-02-21
//! Sealed `UnsignedQuadStream` batch wrapper.
//!
//! [`RecordBatch::clone`] only bumps Arrow `Arc` buffers. That alias is
//! transport identity, not a signature, not an assurance upgrade, and not a
//! new certified observation. This newtype makes that contract visible at the
//! type level: a downstream composite `RecordBatch` cannot enter a store typed
//! as [`UnsignedQuadBatch`] without passing [`UnsignedQuadBatch::try_from_batch`],
//! which re-runs [`crate::validate_contract`] and column-encoding checks.

use arrow_array::RecordBatch;
use arrow_schema::SchemaRef;

use crate::{error::QuadError, reader::QuadStreamReader};

/// A `RecordBatch` that has been checked as `UnsignedQuadStream` v1.
///
/// Construct only through [`Self::try_from_batch`]. [`Clone`] shares the
/// same Arrow buffers; it does not rewrite `dataplane.assurance` and must not
/// be treated as authority.
#[derive(Clone, Debug)]
pub struct UnsignedQuadBatch {
    batch: RecordBatch,
}

impl UnsignedQuadBatch {
    /// Validates `batch` as `UnsignedQuadStream` v1 and wraps it.
    ///
    /// # Errors
    ///
    /// Returns [`QuadError::Contract`] when the schema metadata, field
    /// layout, or column encodings do not match the pinned contract.
    pub fn try_from_batch(batch: RecordBatch) -> Result<Self, QuadError> {
        QuadStreamReader::new(&batch)?;
        Ok(Self { batch })
    }

    /// Borrow the inner Arrow batch at an IPC, Flight, or reader edge.
    #[must_use]
    pub fn as_batch(&self) -> &RecordBatch {
        &self.batch
    }

    /// Unwrap the inner Arrow batch at an IPC, Flight, or reader edge.
    #[must_use]
    pub fn into_inner(self) -> RecordBatch {
        self.batch
    }

    /// Row count of the inner batch.
    #[must_use]
    pub fn num_rows(&self) -> usize {
        self.batch.num_rows()
    }

    /// Schema of the inner batch (`dataplane.assurance` remains `"unsigned"`).
    #[must_use]
    pub fn schema(&self) -> SchemaRef {
        self.batch.schema()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use arrow_array::{ArrayRef, Int64Array, RecordBatch};
    use arrow_schema::{Field, Schema};
    use oxrdf::{NamedNode, Quad};

    use crate::{QuadBatchBuilder, QuadError, QuadLimits, UnsignedQuadBatch, validate_contract};

    fn sample_quad() -> Quad {
        Quad::new(
            NamedNode::new("http://example.com/s").unwrap(),
            NamedNode::new("http://example.com/p").unwrap(),
            NamedNode::new("http://example.com/o").unwrap(),
            oxrdf::GraphName::DefaultGraph,
        )
    }

    fn finished_batch() -> RecordBatch {
        let mut builder = QuadBatchBuilder::new(QuadLimits::default());
        builder
            .push(sample_quad().as_ref(), None)
            .expect("push must succeed");
        builder.finish().expect("finish must succeed")
    }

    #[test]
    fn try_from_batch_accepts_a_builder_finished_batch() {
        let wrapped = UnsignedQuadBatch::try_from_batch(finished_batch()).expect("contract batch");
        assert_eq!(wrapped.num_rows(), 1);
        validate_contract(wrapped.schema().as_ref()).expect("metadata stays unsigned");
        assert_eq!(
            wrapped
                .schema()
                .metadata()
                .get("dataplane.assurance")
                .map(String::as_str),
            Some("unsigned")
        );
    }

    #[test]
    fn clone_shares_arrow_buffers_and_does_not_upgrade_assurance() {
        let original = UnsignedQuadBatch::try_from_batch(finished_batch()).expect("contract batch");
        let cloned = original.clone();
        assert!(
            Arc::ptr_eq(original.as_batch().column(0), cloned.as_batch().column(0)),
            "clone must bump ArrayRef, not rebuild columns"
        );
        assert_eq!(
            cloned
                .schema()
                .metadata()
                .get("dataplane.assurance")
                .map(String::as_str),
            Some("unsigned")
        );
    }

    #[test]
    fn try_from_batch_refuses_a_foreign_schema() {
        let foreign = RecordBatch::try_from_iter([(
            "n",
            Arc::new(Int64Array::from(vec![1_i64])) as ArrayRef,
        )])
        .expect("foreign batch");
        let error = UnsignedQuadBatch::try_from_batch(foreign).expect_err("must refuse");
        assert!(matches!(error, QuadError::Contract(_)));
        assert_eq!(error.code(), "contract");
    }

    fn batch_with_metadata(batch: &RecordBatch, metadata: HashMap<String, String>) -> RecordBatch {
        let fields: Vec<Field> = batch
            .schema()
            .fields()
            .iter()
            .map(|field| field.as_ref().clone())
            .collect();
        RecordBatch::try_new(
            Arc::new(Schema::new_with_metadata(fields, metadata)),
            batch.columns().to_vec(),
        )
        .expect("same columns must rebuild")
    }

    #[test]
    fn try_from_batch_refuses_arrow_version_drift_and_extra_metadata() {
        let batch = finished_batch();
        let mut drifted = batch.schema().metadata().clone();
        drifted.insert("dataplane.arrow_version".into(), "57.0.0".into());
        let error = UnsignedQuadBatch::try_from_batch(batch_with_metadata(&batch, drifted))
            .expect_err("arrow_version is contract-checked");
        assert_eq!(error.code(), "contract");

        let mut extra = batch.schema().metadata().clone();
        extra.insert("dataplane.extra".into(), "no".into());
        let error = UnsignedQuadBatch::try_from_batch(batch_with_metadata(&batch, extra))
            .expect_err("extra metadata keys are contract-checked");
        assert_eq!(error.code(), "contract");
    }

    /// The workspace manifest, which pins every Arrow crate.
    const WORKSPACE_MANIFEST: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml"));

    /// The major of the exact `arrow-ipc` pin in a workspace manifest.
    fn pinned_arrow_ipc_major(manifest: &str) -> Option<&str> {
        let line = manifest
            .lines()
            .find(|line| line.trim_start().starts_with("arrow-ipc ="))?;
        let version = line.split("\"=").nth(1)?.split('"').next()?;
        version.split('.').next()
    }

    /// Checks that the stamp names the same Arrow major as the pin.
    fn stamp_follows_pin(stamp: &str, manifest: &str) -> Result<(), String> {
        let pin = pinned_arrow_ipc_major(manifest)
            .ok_or_else(|| "no exact `arrow-ipc = \"=X.Y.Z\"` pin in the manifest".to_owned())?;
        let stamp_major = stamp.split('.').next().unwrap_or_default();
        if stamp_major == pin {
            Ok(())
        } else {
            Err(format!(
                "the workspace pins Arrow {pin} but batches are stamped \
                 dataplane.arrow_version = {stamp:?}: decide the stamp for the new major \
                 with the downstream readers that check it exactly (see ARROW_VERSION in \
                 src/schema.rs)"
            ))
        }
    }

    #[test]
    fn arrow_version_stamp_follows_the_pinned_arrow_major() {
        let batch = finished_batch();
        let stamp = batch
            .schema()
            .metadata()
            .get("dataplane.arrow_version")
            .cloned()
            .expect("every batch carries the stamp");
        assert_eq!(
            stamp, "58.3.0",
            "dataplane.arrow_version is a wire contract that downstream readers check \
             exactly; it changes only in step with them (see ARROW_VERSION in src/schema.rs)"
        );
        if let Err(message) = stamp_follows_pin(&stamp, WORKSPACE_MANIFEST) {
            panic!("{message}");
        }
    }

    #[test]
    fn the_stamp_check_refuses_a_new_arrow_major() {
        let next_major = WORKSPACE_MANIFEST.replace(
            "arrow-ipc = { version = \"=58.",
            "arrow-ipc = { version = \"=59.",
        );
        assert_ne!(
            next_major, WORKSPACE_MANIFEST,
            "the arrow-ipc pin must be found"
        );
        let error =
            stamp_follows_pin("58.3.0", &next_major).expect_err("Arrow 59 needs a stamp decision");
        assert!(error.contains("pins Arrow 59"), "{error}");
        assert!(stamp_follows_pin("58.3.0", "[workspace.dependencies]\n").is_err());
        assert!(stamp_follows_pin("59.0.0", WORKSPACE_MANIFEST).is_err());
    }
}
