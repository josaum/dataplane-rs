// Rust guideline compliant 2026-02-21
//! Jelly gRPC pub/sub: `RdfStreamService` over the frame codec.
//!
//! Implements the Jelly gRPC streaming protocol 1.0.0 (`grpc.proto`,
//! vendored in `jelly-fast-core`) as a topic-based pub/sub service:
//! `PublishRdf` routes client streams to the topic named by their stream
//! options, and `SubscribeRdf` relays frames to subscribers through
//! bounded broadcast channels. [`JellyClient`] composes the
//! `jelly-fast-core` encoder and decoder so applications exchange
//! `UnsignedQuadStream` batches directly.
//!
//! Everything relayed here is **unsigned by construction**: the transport
//! moves frames and never certifies, approves, or promotes their content.
//!
//! # Authentication and limits
//!
//! `bind_with_verifier` on [`JellyServer`] and [`JellyPatchServer`] gates
//! every RPC behind the shared `flight-auth` JWT verifier and refuses a
//! verifier that does not require authentication with an issuer and
//! audience; plain `bind` authenticates nothing and binds only loopback.
//! Clients attach credentials with `connect_with_authorization`. Messages
//! are capped at [`DEFAULT_MAX_MESSAGE_BYTES`] both ways, publish streams
//! have no idle bound unless one is set (see
//! [`DEFAULT_PUBLISH_IDLE_TIMEOUT`]), and each registry holds at most [`DEFAULT_MAX_TOPICS`] live topics whose
//! names are at most [`MAX_TOPIC_NAME_BYTES`] bytes.
//!
//! Not provided: TLS (the transport is plaintext HTTP/2; put it behind a
//! TLS-terminating proxy or a mesh), tenant scoping (any token with
//! `flight:invoke` can publish or subscribe to any topic), and expiry of open
//! streams (a token is checked when a stream opens and an open subscription
//! outlives its `exp`). [`JellyStreamService::new`] and
//! [`JellyPatchStreamService::new`] are unguarded when mounted directly.
//!
//! The transport is codec-transparent: [`JellyClient`] passes
//! `jelly-fast-core` encoder and decoder options straight through, so RDF
//! 1.2 triple terms (RDF-star) cross the wire whenever the publisher sets
//! `rdf_star` on its encoder options. This crate holds no term logic of its
//! own to refuse or corrupt them.
//!
//! Failure behavior is explicit, never silent: incompatible
//! `requested_options` answer with `INVALID_ARGUMENT` per the
//! `grpc.proto` contract, subscribers that outrun the bounded channel get
//! a `DATA_LOSS` status with the lag count, and publishes without a
//! leading options row (or without a `stream_name` topic) are rejected.
//! The only at-most-once behavior is standard pub/sub delivery: frames
//! published while a topic has no subscriber are not retained, as
//! documented on [`TopicRegistry`].
//!
//! The crate also serves the Jelly-Patch protocol (task graph N7) with
//! the same pub/sub structure: [`JellyPatchStreamService`] implements the
//! dataplane `PatchStreamService` (see
//! `jelly-fast-core/proto/dataplane_patch_grpc.proto` — the vendored
//! `patch.proto` defines no service and its options carry no topic, so
//! the publish envelope names the topic explicitly), and
//! [`JellyPatchClient`] composes the patch codec so applications exchange
//! [`jelly_fast_core::PatchOp`] sequences directly. Publishes that would
//! end with an open transaction are refused client-side, and a relay that
//! ends mid-transaction surfaces as a typed error on the subscriber.

mod client;
mod error;
mod patch_client;
mod patch_service;
mod registry;
mod service;
mod transport;

pub use client::{JellyClient, QuadBatchSubscription};
pub use error::JellyGrpcError;
pub use patch_client::{JellyPatchClient, PatchOpSubscription};
pub use patch_service::{JellyPatchServer, JellyPatchStreamService};
pub use registry::{
    DEFAULT_MAX_TOPICS, DEFAULT_TOPIC_CAPACITY, MAX_TOPIC_NAME_BYTES, PatchTopicRegistry,
    TopicRegistry,
};
pub use service::{JellyServer, JellyStreamService};
pub use transport::{DEFAULT_MAX_MESSAGE_BYTES, DEFAULT_PUBLISH_IDLE_TIMEOUT};
