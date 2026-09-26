// Rust guideline compliant 2026-02-21
//! Arrow Flight transport for unsigned quad datasets.
//!
//! This crate exposes an in-memory store of RDF quad datasets over Arrow
//! Flight (`arrow-flight` 58.3.0 on `tonic` 0.14). The only payload on any
//! RPC is the `UnsignedQuadStream` v1 Arrow contract from [`quad_fast_core`]:
//! ingest validates the contract on every incoming schema and record batch
//! and rejects non-conforming payloads with `INVALID_ARGUMENT`, so a batch
//! that fails validation is never stored and never served.
//!
//! Everything this service stores and serves is **unsigned by construction**
//! (Atlas product invariant 7): quads carry their provenance, but the
//! transport never certifies a source, approves a rule, or promotes a fact.
//! The `DoPut` receipt is informational JSON, not a signature.
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
//! datasets, batches per dataset, and quads per dataset); exceeding a limit
//! yields `RESOURCE_EXHAUSTED` and leaves the store unchanged.
//!
//! The transport is term-agnostic: it validates the `UnsignedQuadStream`
//! schema and column encodings, never a term, so batches carrying RDF 1.2
//! triple terms (`object_kind = "triple"`) are stored and served unchanged.
//!
//! # Features
//!
//! - `auth` — adds [`serve_with_verifier`], wiring the shared `flight-auth`
//!   JWT metadata verifier from `office-parsers-rs` in front of every RPC.
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
    DEFAULT_MAX_BATCHES_PER_DATASET, DEFAULT_MAX_DATASETS, DEFAULT_MAX_QUADS_PER_DATASET,
    DatasetLimits,
};
#[cfg(feature = "auth")]
pub use serve::serve_with_verifier;
pub use serve::{FlightServer, ServeError, serve, serve_with_limits};
pub use service::{ACTION_DROP_DATASET, ACTION_RESET, QuadFlightService};
