// Rust guideline compliant 2026-02-21
//! Fail-closed limits for the in-memory quad-dataset store and its transport.

use std::time::Duration;

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

/// Default maximum decoded Arrow memory of one dataset: 1 GiB.
///
/// Quad and batch counts do not bound bytes: one row may carry a
/// multi-megabyte literal, so 4 096 batches at the message limit reach
/// 16 GiB. 1 GiB holds a full `DEFAULT_MAX_QUADS_PER_DATASET` dataset at
/// 64 bytes of Arrow memory per quad, which dictionary encoding keeps typical
/// quads under.
pub const DEFAULT_MAX_DATASET_BYTES: usize = 1 << 30;

/// Default maximum decoded Arrow memory across the whole store: 4 GiB.
///
/// Counts stored datasets *and* uploads still in flight, so concurrent
/// `DoPut`s cannot each buffer a full dataset before the store-wide check.
/// Four default-sized datasets; size it to the process memory envelope.
pub const DEFAULT_MAX_STORE_BYTES: usize = 4 << 30;

/// Default maximum `FlightData` messages in one `DoPut` or `DoExchange`.
///
/// Dictionary and schema messages are not record batches, so the batch limit
/// alone does not bound them. A contract batch sent with
/// `DictionaryHandling::Resend` is one record batch plus one dictionary batch
/// per dictionary column (nine), so this admits a full
/// `DEFAULT_MAX_BATCHES_PER_DATASET` upload with room to spare.
pub const DEFAULT_MAX_MESSAGES_PER_STREAM: usize = 65_536;

/// Default maximum encoded gRPC message, in either direction: 4 MiB.
///
/// This is tonic's own decoding default, stated explicitly and applied to
/// encoding as well (tonic's encoding default is unbounded). `DoGet` output
/// stays under it because the Flight encoder splits batches at 2 MiB.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// Default maximum dataset name length, in bytes.
///
/// Names are map keys and appear in `ListFlights`; nothing legitimate needs
/// more, and an unbounded name is an unbounded allocation per dataset.
pub const DEFAULT_MAX_NAME_BYTES: usize = 256;

/// Default longest wait for the next message of an ingest stream: 30 s.
///
/// A client that opens `DoPut` or `DoExchange` and then goes quiet holds its
/// reservation of store memory; this releases it. Raise it for producers that
/// legitimately pause between batches.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default concurrent requests served on one connection.
///
/// Bounds how much work a single client can start at once; tonic's own
/// default is unbounded.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CONNECTION: usize = 32;

/// Fail-closed limits governing the quad-dataset store and its transport.
///
/// Every limit is enforced on ingest (`DoPut`) and, where it applies, on the
/// `DoExchange` transform hook; exceeding any of them rejects the request
/// with `RESOURCE_EXHAUSTED` (or `DEADLINE_EXCEEDED` for the idle timeout)
/// and leaves the store unchanged. The message-size and concurrency limits
/// apply to every RPC.
#[derive(Clone, Copy, Debug)]
pub struct DatasetLimits {
    /// Maximum datasets held by the store at once.
    pub max_datasets: usize,
    /// Maximum record batches accepted into one dataset.
    pub max_batches_per_dataset: usize,
    /// Maximum total quads accepted into one dataset.
    pub max_quads_per_dataset: u64,
    /// Maximum decoded Arrow memory of one dataset, in bytes.
    pub max_dataset_bytes: usize,
    /// Maximum decoded Arrow memory of all stored and in-flight datasets.
    pub max_store_bytes: usize,
    /// Maximum `FlightData` messages in one ingest stream.
    pub max_messages_per_stream: usize,
    /// Maximum encoded gRPC message size, applied to decoding and encoding.
    pub max_message_bytes: usize,
    /// Maximum dataset name length, in bytes.
    pub max_name_bytes: usize,
    /// Longest wait for the next message of an ingest stream.
    pub idle_timeout: Duration,
    /// Maximum concurrent requests on one connection.
    pub max_concurrent_requests_per_connection: usize,
}

impl Default for DatasetLimits {
    fn default() -> Self {
        Self {
            max_datasets: DEFAULT_MAX_DATASETS,
            max_batches_per_dataset: DEFAULT_MAX_BATCHES_PER_DATASET,
            max_quads_per_dataset: DEFAULT_MAX_QUADS_PER_DATASET,
            max_dataset_bytes: DEFAULT_MAX_DATASET_BYTES,
            max_store_bytes: DEFAULT_MAX_STORE_BYTES,
            max_messages_per_stream: DEFAULT_MAX_MESSAGES_PER_STREAM,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_name_bytes: DEFAULT_MAX_NAME_BYTES,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_concurrent_requests_per_connection: DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CONNECTION,
        }
    }
}
