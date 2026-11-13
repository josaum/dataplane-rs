// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Tonic implementation of the dataplane `PatchStreamService` and a serve helper.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use flight_auth::FlightRequestAuthVerifier;
use futures::{Stream, StreamExt};
use jelly_fast_core::proto::patch::{
    RdfPatchFrame, RdfPatchOptions,
    grpc::{
        PatchPublish, PatchReceived, PatchSubscribe,
        patch_stream_service_server::{PatchStreamService, PatchStreamServiceServer},
    },
    rdf_patch_row,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::{
    BroadcastStream, TcpListenerStream, errors::BroadcastStreamRecvError,
};
use tonic::{Request, Response, Status, Streaming, service::interceptor::InterceptedService};

use crate::{
    error::JellyGrpcError,
    registry::{PatchTopicRegistry, check_requested_patch_options},
    transport::{
        DEFAULT_MAX_MESSAGE_BYTES, DEFAULT_PUBLISH_IDLE_TIMEOUT, auth_gate, next_message,
        require_loopback, require_verifier, server_builder,
    },
};

/// Pub/sub implementation of the dataplane `PatchStreamService`.
///
/// `PublishPatches` routes each client stream to the topic named by the
/// first publish envelope (the vendored `RdfPatchOptions` carries no
/// stream name, so the dataplane service carries the topic
/// explicitly); the first frame must open with the patch options row.
/// `SubscribePatches` relays frames published to a topic after the
/// subscription was established; incompatible `requested_options` yield
/// `INVALID_ARGUMENT`, and subscribers that lag beyond the registry's
/// bounded capacity receive an explicit `DATA_LOSS` status — frames are
/// never dropped silently.
#[derive(Clone, Debug)]
pub struct JellyPatchStreamService {
    registry: Arc<PatchTopicRegistry>,
}

impl JellyPatchStreamService {
    /// Creates a service that routes streams through `registry`.
    #[must_use]
    pub fn new(registry: Arc<PatchTopicRegistry>) -> Self {
        Self { registry }
    }
}

/// Extracts the options row that must open a published patch stream.
fn leading_patch_options(frame: &RdfPatchFrame) -> Result<&RdfPatchOptions, Status> {
    match frame.rows.first().and_then(|row| row.row.as_ref()) {
        Some(rdf_patch_row::Row::Options(options)) => Ok(options),
        _ => Err(Status::invalid_argument(
            "the first row of a published patch stream must be the patch options",
        )),
    }
}

/// Validates a relayed frame's options rows against a subscriber request.
fn patch_frame_matches_request(
    frame: &RdfPatchFrame,
    requested: &RdfPatchOptions,
) -> Result<(), Status> {
    for row in &frame.rows {
        if let Some(rdf_patch_row::Row::Options(published)) = row.row.as_ref() {
            check_requested_patch_options(requested, published)
                .map_err(Status::invalid_argument)?;
        }
    }
    Ok(())
}

#[tonic::async_trait]
impl PatchStreamService for JellyPatchStreamService {
    type SubscribePatchesStream =
        Pin<Box<dyn Stream<Item = Result<RdfPatchFrame, Status>> + Send + 'static>>;

    async fn subscribe_patches(
        &self,
        request: Request<PatchSubscribe>,
    ) -> Result<Response<Self::SubscribePatchesStream>, Status> {
        let subscribe = request.into_inner();
        if subscribe.topic.is_empty() {
            return Err(Status::invalid_argument("topic must not be empty"));
        }
        let (receiver, published) = self.registry.subscribe(&subscribe.topic)?;
        let requested = subscribe.requested_options;
        if let (Some(requested), Some(published)) = (&requested, &published) {
            check_requested_patch_options(requested, published)
                .map_err(Status::invalid_argument)?;
        }
        let stream = BroadcastStream::new(receiver).map(move |item| match item {
            Ok(frame) => {
                if let Some(requested) = &requested {
                    // Re-check whenever a publisher (re)announces options
                    // mid-subscription; a topic that only becomes
                    // incompatible later still fails loudly.
                    patch_frame_matches_request(frame.as_ref(), requested)?;
                }
                Ok(Arc::unwrap_or_clone(frame))
            }
            Err(BroadcastStreamRecvError::Lagged(skipped)) => Err(Status::data_loss(format!(
                "subscriber lagged behind by {skipped} frames on a bounded topic channel; \
                 resubscribe to continue from live frames"
            ))),
        });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn publish_patches(
        &self,
        request: Request<Streaming<PatchPublish>>,
    ) -> Result<Response<PatchReceived>, Status> {
        let mut messages = request.into_inner();
        let first = next_message(&mut messages, DEFAULT_PUBLISH_IDLE_TIMEOUT)
            .await?
            .ok_or_else(|| {
                Status::invalid_argument("published patch stream contained no messages")
            })?;
        let frame = first
            .frame
            .ok_or_else(|| Status::invalid_argument("publish message must carry a patch frame"))?;
        if first.topic.is_empty() {
            return Err(Status::invalid_argument(
                "the first publish message must carry a non-empty topic",
            ));
        }
        let options = leading_patch_options(&frame)?;
        let sender = self.registry.register_publisher(&first.topic, options)?;
        let topic = first.topic;
        // A send error only means no subscriber is currently attached;
        // at-most-once relay semantics are documented on the registry.
        let _ = sender.send(Arc::new(frame));
        while let Some(message) = next_message(&mut messages, DEFAULT_PUBLISH_IDLE_TIMEOUT).await? {
            let frame = message.frame.ok_or_else(|| {
                Status::invalid_argument("publish message must carry a patch frame")
            })?;
            if !message.topic.is_empty() && message.topic != topic {
                return Err(Status::invalid_argument(
                    "publish stream switched topics mid-stream",
                ));
            }
            let _ = sender.send(Arc::new(frame));
        }
        Ok(Response::new(PatchReceived {}))
    }
}

/// A bound, not-yet-running Jelly patch pub/sub server.
///
/// Binding is separated from serving so callers can bind port 0 and learn
/// the assigned address before the accept loop starts.
/// [`JellyPatchServer::bind`] authenticates nothing and so binds only
/// loopback; [`JellyPatchServer::bind_with_verifier`] gates every RPC behind
/// the shared `flight-auth` JWT verifier.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use jelly_fast_grpc::{JellyPatchServer, PatchTopicRegistry};
///
/// # async fn run() -> Result<(), jelly_fast_grpc::JellyGrpcError> {
/// let server = JellyPatchServer::bind(
///     "127.0.0.1:0".parse().expect("valid address"),
///     Arc::new(PatchTopicRegistry::default()),
/// )
/// .await?;
/// let addr = server.local_addr();
/// tokio::spawn(server.serve());
/// # let _ = addr;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct JellyPatchServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    registry: Arc<PatchTopicRegistry>,
    verifier: Option<FlightRequestAuthVerifier>,
}

impl JellyPatchServer {
    /// Binds an unauthenticated listener on a loopback `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Auth`] when `addr` is not loopback and
    /// [`JellyGrpcError::Transport`] when the socket cannot be bound or its
    /// local address cannot be resolved.
    pub async fn bind(
        addr: SocketAddr,
        registry: Arc<PatchTopicRegistry>,
    ) -> Result<Self, JellyGrpcError> {
        require_loopback(addr)?;
        Self::bind_inner(addr, registry, None).await
    }

    /// Binds a listener whose every RPC is verified by `verifier`.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Auth`] when `verifier` does not require
    /// authentication or lacks an issuer or audience, and
    /// [`JellyGrpcError::Transport`] when the socket cannot be bound.
    pub async fn bind_with_verifier(
        addr: SocketAddr,
        registry: Arc<PatchTopicRegistry>,
        verifier: FlightRequestAuthVerifier,
    ) -> Result<Self, JellyGrpcError> {
        let verifier = require_verifier(verifier)?;
        Self::bind_inner(addr, registry, Some(verifier)).await
    }

    async fn bind_inner(
        addr: SocketAddr,
        registry: Arc<PatchTopicRegistry>,
        verifier: Option<FlightRequestAuthVerifier>,
    ) -> Result<Self, JellyGrpcError> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
            registry,
            verifier,
        })
    }

    /// Address the server is bound to (useful after binding port 0).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Runs the gRPC server until the transport fails.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Transport`] when the tonic server stops
    /// with a transport error.
    pub async fn serve(self) -> Result<(), JellyGrpcError> {
        let service = PatchStreamServiceServer::new(JellyPatchStreamService::new(self.registry))
            .max_decoding_message_size(DEFAULT_MAX_MESSAGE_BYTES)
            .max_encoding_message_size(DEFAULT_MAX_MESSAGE_BYTES);
        server_builder()
            .add_service(InterceptedService::new(service, auth_gate(self.verifier)))
            .serve_with_incoming(TcpListenerStream::new(self.listener))
            .await?;
        Ok(())
    }
}
