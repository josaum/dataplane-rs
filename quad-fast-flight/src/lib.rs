// Rust guideline compliant 2026-02-21
//! Arrow Flight transport for unsigned quad datasets.
//!
//! This crate exposes an in-memory store of RDF quad datasets over Arrow
//! Flight (`arrow-flight` 58.4.1 on `tonic` 0.14). The only payload on any
//! RPC is the `UnsignedQuadStream` v1 Arrow contract from [`quad_fast_core`]:
//! ingest validates the contract on every incoming schema and record batch
//! and rejects non-conforming payloads with `INVALID_ARGUMENT`, so a batch
//! that fails validation is never stored and never served.
//!
//! Everything this service stores and serves is **unsigned by construction**:
//! quads carry their provenance, but the transport never certifies a source,
//! approves a rule, or promotes a fact. The `DoPut` receipt is informational
//! JSON, not a signature.
//!
//! # RPC surface
//!
//! - `DoPut` — atomic ingest of one named dataset. The first frame's PATH
//!   descriptor names the dataset (`["datasets", <name>]` or `[<name>]`).
//! - `DoGet` — stream a dataset back; the ticket is the UTF-8 dataset name.
//! - `GetSchema` — the IPC-encoded `UnsignedQuadStream` v1 schema.
//! - `GetFlightInfo` / `ListFlights` — dataset discovery with quad counts.
//! - `DoExchange` — validate-and-echo transform hook for future dataplane
//!   transforms.
//! - `DoAction` — [`ACTION_DROP_DATASET`] and [`ACTION_RESET`].
//! - `Handshake` / `PollFlightInfo` — `UNIMPLEMENTED` for now.
//!
//! All store growth is fail-closed behind [`DatasetLimits`] (maximum
//! datasets, batches, quads and bytes per dataset, bytes across the store,
//! messages per ingest stream, name length, message size, idle time and
//! per-connection concurrency); exceeding a limit yields `RESOURCE_EXHAUSTED`
//! (`DEADLINE_EXCEEDED` for the idle timeout) and leaves the store unchanged.
//!
//! # Authentication
//!
//! [`serve_with_verifier`] runs every RPC behind the shared `flight-auth`
//! JWT metadata verifier and refuses to start with a verifier that does not
//! require authentication or lacks an issuer and audience. [`serve`] and
//! [`serve_with_limits`] authenticate nothing and therefore bind only a
//! loopback address.
//!
//! The transport is term-agnostic: it validates the `UnsignedQuadStream`
//! schema and column encodings, never a term, so batches carrying RDF 1.2
//! triple terms (`object_kind = "triple"`) are stored and served unchanged.
//!
//! # Features
//!
//! - `auth` — retained for compatibility and now empty: [`serve_with_verifier`]
//!   is always available.
//!
//! # Examples
//!
//! ```no_run
//! # async fn example() -> Result<(), quad_fast_flight::ServeError> {
//! let server = quad_fast_flight::serve("127.0.0.1:0".parse().unwrap()).await?;
//! let endpoint = format!("http://{}", server.local_addr());
//! // ... connect an arrow-flight client to `endpoint` ...
//! server.shutdown().await?;
//! # Ok(())
//! # }
//! ```

mod limits;
mod serve;
mod service;
mod store;

pub use limits::{
    DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_BATCHES_PER_DATASET,
    DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CONNECTION, DEFAULT_MAX_DATASET_BYTES,
    DEFAULT_MAX_DATASETS, DEFAULT_MAX_MESSAGE_BYTES, DEFAULT_MAX_MESSAGES_PER_STREAM,
    DEFAULT_MAX_NAME_BYTES, DEFAULT_MAX_QUADS_PER_DATASET, DEFAULT_MAX_STORE_BYTES, DatasetLimits,
};
pub use serve::{FlightServer, ServeError, serve, serve_with_limits, serve_with_verifier};
pub use service::{ACTION_DROP_DATASET, ACTION_RESET, QuadFlightService};
