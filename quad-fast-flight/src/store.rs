// Rust guideline compliant 2026-02-21
//! In-memory store of unsigned quad datasets with atomic replacement.

use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use quad_fast_core::UnsignedQuadBatch;
use tonic::Status;

use crate::limits::DatasetLimits;

/// Bytes charged against the store-wide budget: stored, in flight, and
/// still held by readers.
#[derive(Debug, Default)]
pub(crate) struct ByteBudget {
    used: AtomicUsize,
}

impl ByteBudget {
    /// Charges `bytes` when the total stays within `limit`.
    fn try_charge(&self, bytes: usize, limit: usize) -> bool {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|total| *total <= limit)
            })
            .is_ok()
    }

    /// Returns `bytes` to the budget.
    fn release(&self, bytes: usize) {
        // Saturating: a release never exceeds what was charged, but an
        // underflow here must not wrap into an exhausted budget.
        let _ = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_sub(bytes))
            });
    }
}

/// The bytes one dataset holds against the store budget.
///
/// Created when its upload starts and charged message by message. It lives
/// as long as the last holder of the dataset's batches: the upload, the
/// stored [`Dataset`], and every `DoGet` stream reading it share one
/// [`Arc`]. Dropping or replacing a dataset therefore frees its bytes only
/// once no reader still holds them.
#[derive(Debug)]
pub(crate) struct Reservation {
    budget: Arc<ByteBudget>,
    limits: DatasetLimits,
    charged: AtomicUsize,
}

impl Reservation {
    /// Starts an empty charge against `budget`.
    pub(crate) fn new(budget: Arc<ByteBudget>, limits: DatasetLimits) -> Self {
        Self {
            budget,
            limits,
            charged: AtomicUsize::new(0),
        }
    }

    /// Charges one received message against the dataset and store budgets.
    pub(crate) fn charge(&self, bytes: usize) -> Result<(), Status> {
        let dataset = self.charged.load(Ordering::Acquire).saturating_add(bytes);
        if dataset > self.limits.max_dataset_bytes {
            return Err(Status::resource_exhausted(format!(
                "resource_limit: dataset_bytes: observed {dataset} exceeds limit {}",
                self.limits.max_dataset_bytes
            )));
        }
        if !self.budget.try_charge(bytes, self.limits.max_store_bytes) {
            return Err(Status::resource_exhausted(format!(
                "resource_limit: store_bytes: store would exceed its limit of {} bytes",
                self.limits.max_store_bytes
            )));
        }
        self.charged.store(dataset, Ordering::Release);
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.release(self.charged.load(Ordering::Acquire));
    }
}

/// One fully ingested, contract-validated, unsigned dataset.
///
/// Instances only exist for uploads that decoded and validated completely;
/// a `DoPut` that fails mid-stream never materializes a `Dataset`.
/// Batches are [`UnsignedQuadBatch`]: a reasoner composite `RecordBatch`
/// cannot be stored without passing `try_from_batch`, and [`Clone`] of a
/// dataset only aliases Arrow buffers — it is not a signature.
#[derive(Debug)]
pub(crate) struct Dataset {
    /// Contract-valid batches in arrival order.
    pub(crate) batches: Vec<UnsignedQuadBatch>,
    /// Total quads across all batches.
    pub(crate) total_quads: u64,
    /// The dataset's charge against the store byte budget, released when
    /// the last holder of this dataset is gone.
    #[expect(
        dead_code,
        reason = "held only for its Drop, which returns the dataset's bytes to the budget"
    )]
    pub(crate) charge: Arc<Reservation>,
}

/// Name-keyed dataset store enforcing the fail-closed dataset limits.
///
/// Iteration order is the lexicographic dataset-name order, which keeps
/// `ListFlights` output deterministic. Lookups return [`Arc<Dataset>`] so
/// `DoGet` leaves the lock with an identity bump; that alias is not a
/// signature.
#[derive(Debug, Default)]
pub(crate) struct DatasetStore {
    datasets: BTreeMap<String, Arc<Dataset>>,
}

impl DatasetStore {
    /// Atomically inserts or replaces `name` with a fully validated dataset.
    ///
    /// Replacing an existing dataset never counts against `max_datasets`;
    /// only a store already holding `max_datasets` distinct names rejects a
    /// new name with `RESOURCE_EXHAUSTED`. Returns the replaced dataset, so
    /// the caller can release its bytes.
    pub(crate) fn insert(
        &mut self,
        name: String,
        dataset: Dataset,
        limits: &DatasetLimits,
    ) -> Result<Option<Arc<Dataset>>, Status> {
        self.ensure_room_for(&name, limits)?;
        Ok(self.datasets.insert(name, Arc::new(dataset)))
    }

    /// Fails closed when `name` is new and the store is already full.
    ///
    /// Checked before an upload is read, so a full store refuses a new name
    /// without buffering it first, and again at insert.
    pub(crate) fn ensure_room_for(&self, name: &str, limits: &DatasetLimits) -> Result<(), Status> {
        if !self.datasets.contains_key(name) && self.datasets.len() >= limits.max_datasets {
            return Err(Status::resource_exhausted(format!(
                "resource_limit: datasets: store already holds the maximum of {} datasets",
                limits.max_datasets
            )));
        }
        Ok(())
    }

    /// Returns a shared handle to the dataset stored under `name`, if any.
    pub(crate) fn get(&self, name: &str) -> Option<Arc<Dataset>> {
        self.datasets.get(name).cloned()
    }

    /// Removes and returns the shared handle stored under `name`, if any.
    pub(crate) fn remove(&mut self, name: &str) -> Option<Arc<Dataset>> {
        self.datasets.remove(name)
    }

    /// Removes every dataset and returns how many were dropped.
    pub(crate) fn reset(&mut self) -> usize {
        let dropped = self.datasets.len();
        self.datasets.clear();
        dropped
    }

    /// Iterates datasets in lexicographic name order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&String, &Dataset)> {
        self.datasets
            .iter()
            .map(|(name, dataset)| (name, dataset.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dataset(total_quads: u64) -> Dataset {
        Dataset {
            batches: Vec::new(),
            total_quads,
            charge: Arc::new(Reservation::new(
                Arc::new(ByteBudget::default()),
                DatasetLimits::default(),
            )),
        }
    }

    fn tiny_limits() -> DatasetLimits {
        DatasetLimits {
            max_datasets: 2,
            ..DatasetLimits::default()
        }
    }

    #[test]
    fn insert_enforces_max_datasets_for_new_names_only() {
        let limits = tiny_limits();
        let mut store = DatasetStore::default();
        store.insert("a".to_owned(), dataset(1), &limits).unwrap();
        store.insert("b".to_owned(), dataset(2), &limits).unwrap();

        let rejected = store
            .insert("c".to_owned(), dataset(3), &limits)
            .unwrap_err();
        assert_eq!(rejected.code(), tonic::Code::ResourceExhausted);

        // Replacement of an existing name stays allowed at capacity.
        store.insert("a".to_owned(), dataset(9), &limits).unwrap();
        assert_eq!(store.get("a").unwrap().total_quads, 9);
    }

    #[test]
    fn remove_and_reset_drop_datasets() {
        let limits = DatasetLimits::default();
        let mut store = DatasetStore::default();
        store.insert("a".to_owned(), dataset(1), &limits).unwrap();
        store.insert("b".to_owned(), dataset(2), &limits).unwrap();

        assert!(store.remove("a").is_some());
        assert!(store.remove("a").is_none());
        assert_eq!(store.reset(), 1);
        assert!(store.get("b").is_none());
    }

    #[test]
    fn iter_is_sorted_by_name() {
        let limits = DatasetLimits::default();
        let mut store = DatasetStore::default();
        store
            .insert("zeta".to_owned(), dataset(1), &limits)
            .unwrap();
        store
            .insert("alpha".to_owned(), dataset(2), &limits)
            .unwrap();

        let names: Vec<&String> = store.iter().map(|(name, _)| name).collect();
        assert_eq!(names, ["alpha", "zeta"]);
    }

    #[test]
    fn get_clones_share_one_dataset_allocation() {
        let limits = DatasetLimits::default();
        let mut store = DatasetStore::default();
        store.insert("a".to_owned(), dataset(1), &limits).unwrap();
        let first = store.get("a").expect("inserted");
        let second = store.get("a").expect("inserted");
        assert!(
            Arc::ptr_eq(&first, &second),
            "lookups must bump Arc, not clone Dataset"
        );
    }

    #[test]
    fn a_dropped_dataset_stays_charged_while_a_reader_holds_it() {
        let budget = Arc::new(ByteBudget::default());
        let limits = DatasetLimits::default();
        let charge = Arc::new(Reservation::new(Arc::clone(&budget), limits));
        charge.charge(100).unwrap();
        let mut store = DatasetStore::default();
        let dataset = Dataset {
            batches: Vec::new(),
            total_quads: 0,
            charge,
        };
        drop(store.insert("a".to_owned(), dataset, &limits).unwrap());
        let reader = store.get("a").unwrap();

        drop(store.remove("a"));
        assert_eq!(budget.used.load(Ordering::Acquire), 100);
        drop(reader);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }
}
