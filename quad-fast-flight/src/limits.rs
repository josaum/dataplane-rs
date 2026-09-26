// Rust guideline compliant 2026-02-21
//! Fail-closed limits for the in-memory quad-dataset store.

/// Default maximum number of datasets held by one service.
///
/// Sized so a fully populated store of default-sized datasets stays within
/// the memory envelope of one dataplane process. Raising this only moves the
/// point at which `DoPut` fails closed with `RESOURCE_EXHAUSTED`.
pub const DEFAULT_MAX_DATASETS: usize = 1_024;

/// Default maximum record batches accepted into one dataset.
///
/// Bounds the per-dataset batch vector independently of quad counts so that
/// pathological many-tiny-batch uploads fail closed. Matches the order of
/// magnitude used by `owl-fast-core` statement budgets.
pub const DEFAULT_MAX_BATCHES_PER_DATASET: usize = 4_096;

/// Default maximum total quads accepted into one dataset.
///
/// Sixteen full batches at `quad_fast_core::DEFAULT_MAX_QUADS` (1 Mi quads
/// per batch); changing one default without the other skews the batch/quad
/// ratio a single `DoPut` can reach before failing closed.
pub const DEFAULT_MAX_QUADS_PER_DATASET: u64 = 16 * 1_048_576;

/// Fail-closed limits governing the quad-dataset store.
///
/// Every limit is enforced on ingest (`DoPut`) and on the `DoExchange`
/// transform hook; exceeding any of them rejects the request with
/// `RESOURCE_EXHAUSTED` and leaves the store unchanged.
#[derive(Clone, Copy, Debug)]
pub struct DatasetLimits {
    /// Maximum datasets held by the store at once.
    pub max_datasets: usize,
    /// Maximum record batches accepted into one dataset.
    pub max_batches_per_dataset: usize,
    /// Maximum total quads accepted into one dataset.
    pub max_quads_per_dataset: u64,
}

impl Default for DatasetLimits {
    fn default() -> Self {
        Self {
            max_datasets: DEFAULT_MAX_DATASETS,
            max_batches_per_dataset: DEFAULT_MAX_BATCHES_PER_DATASET,
            max_quads_per_dataset: DEFAULT_MAX_QUADS_PER_DATASET,
        }
    }
}
