// Rust guideline compliant 2026-02-21
//! Tonic implementation of the Jelly `RdfStreamService` and a serve helper.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use flight_auth::FlightRequestAuthVerifier;
use futures::{Stream, StreamExt};
use jelly_fast_core::proto::{
    RdfStreamFrame, RdfStreamOptions, RdfStreamReceived, RdfStreamSubscribe, rdf_stream_row,
    rdf_stream_service_server::{RdfStreamService, RdfStreamServiceServer},
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::{
    BroadcastStream, TcpListenerStream, errors::BroadcastStreamRecvError,
};
use tonic::{Request, Response, Status, Streaming, service::interceptor::InterceptedService};

use crate::{
    error::JellyGrpcError,
    registry::{TopicRegistry, check_requested_options},
    transport::{
        DEFAULT_MAX_MESSAGE_BYTES, DEFAULT_PUBLISH_IDLE_TIMEOUT, auth_gate, next_message,
        require_loopback, require_verifier, server_builder,
    },
};

/// Pub/sub implementation of the Jelly `RdfStreamService`.
///
/// `PublishRdf` routes each client stream to the topic named by the
/// `stream_name` of the options row that must open the stream's first
/// frame. `SubscribeRdf` relays frames published to a topic after the
/// subscription was established; incompatible `requested_options` yield
/// `INVALID_ARGUMENT` per the `grpc.proto` contract, and subscribers that
/// lag beyond the registry's bounded capacity receive an explicit
/// `DATA_LOSS` status — frames are never dropped silently.
///
/// # Mounting it yourself
///
/// This service enforces nothing about who calls it. [`JellyServer`] wraps it in
/// the authentication gate, the loopback rule for unauthenticated binds, the
/// message-size caps and the connection limits; mounting the service on a
/// custom tonic server skips all of them, so do that only behind equivalent
/// controls of your own.
#[derive(Clone, Debug)]
pub struct JellyStreamService {
    registry: Arc<TopicRegistry>,
    publish_idle_timeout: Option<Duration>,
}

impl JellyStreamService {
    /// Creates a service that routes streams through `registry`.
    ///
    /// Unguarded: see the type documentation before mounting it directly.
    #[must_use]
    pub fn new(registry: Arc<TopicRegistry>) -> Self {
        Self {
            registry,
            publish_idle_timeout: DEFAULT_PUBLISH_IDLE_TIMEOUT,
        }
    }

    /// Ends a publish stream that sends nothing for `timeout`.
    ///
    /// `None`, the default, waits indefinitely; see
    /// [`crate::DEFAULT_PUBLISH_IDLE_TIMEOUT`] for why.
    #[must_use]
    pub fn with_publish_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.publish_idle_timeout = timeout;
        self
    }
}

/// Extracts the options row that must open a published stream.
fn leading_options(frame: &RdfStreamFrame) -> Result<&RdfStreamOptions, Status> {
    match frame.rows.first().and_then(|row| row.row.as_ref()) {
        Some(rdf_stream_row::Row::Options(options)) => Ok(options),
        _ => Err(Status::invalid_argument(
            "the first row of a published stream must be the stream options",
        )),
    }
}

/// Validates a relayed frame's options rows against a subscriber request.
fn frame_matches_request(
    frame: &RdfStreamFrame,
    requested: &RdfStreamOptions,
) -> Result<(), Status> {
    for row in &frame.rows {
        if let Some(rdf_stream_row::Row::Options(published)) = row.row.as_ref() {
            check_requested_options(requested, published).map_err(Status::invalid_argument)?;
        }
    }
    Ok(())
}

#[tonic::async_trait]
impl RdfStreamService for JellyStreamService {
    type SubscribeRdfStream =
        Pin<Box<dyn Stream<Item = Result<RdfStreamFrame, Status>> + Send + 'static>>;

    async fn subscribe_rdf(
        &self,
        request: Request<RdfStreamSubscribe>,
    ) -> Result<Response<Self::SubscribeRdfStream>, Status> {
        let subscribe = request.into_inner();
        if subscribe.topic.is_empty() {
            return Err(Status::invalid_argument("topic must not be empty"));
        }
        let (receiver, published) = self.registry.subscribe(&subscribe.topic)?;
        let requested = subscribe.requested_options;
        if let (Some(requested), Some(published)) = (&requested, &published) {
            check_requested_options(requested, published).map_err(Status::invalid_argument)?;
        }
        let stream = BroadcastStream::new(receiver).map(move |item| match item {
            Ok(frame) => {
                if let Some(requested) = &requested {
                    // Re-check whenever a publisher (re)announces options
                    // mid-subscription; a topic that only becomes
                    // incompatible later still fails loudly.
                    frame_matches_request(frame.as_ref(), requested)?;
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

    async fn publish_rdf(
        &self,
        request: Request<Streaming<RdfStreamFrame>>,
    ) -> Result<Response<RdfStreamReceived>, Status> {
        let mut frames = request.into_inner();
        let first = next_message(&mut frames, self.publish_idle_timeout)
            .await?
            .ok_or_else(|| Status::invalid_argument("published stream contained no frames"))?;
        let options = leading_options(&first)?;
        if options.stream_name.is_empty() {
            return Err(Status::invalid_argument(
                "stream options must carry a non-empty stream_name to use as the topic",
            ));
        }
        let sender = self
            .registry
            .register_publisher(&options.stream_name, options)?;
        // A send error only means no subscriber is currently attached;
        // at-most-once relay semantics are documented on TopicRegistry.
        let _ = sender.send(Arc::new(first));
        while let Some(frame) = next_message(&mut frames, self.publish_idle_timeout).await? {
            let _ = sender.send(Arc::new(frame));
        }
        Ok(Response::new(RdfStreamReceived {}))
    }
}

/// A bound, not-yet-running Jelly pub/sub server.
///
/// Binding is separated from serving so callers can bind port 0 and learn
/// the assigned address before the accept loop starts. [`JellyServer::bind`]
/// authenticates nothing and so binds only loopback;
/// [`JellyServer::bind_with_verifier`] gates every RPC behind the shared
/// `flight-auth` JWT verifier.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use jelly_fast_grpc::{JellyServer, TopicRegistry};
///
/// # async fn run() -> Result<(), jelly_fast_grpc::JellyGrpcError> {
/// let server = JellyServer::bind(
///     "127.0.0.1:0".parse().expect("valid address"),
///     Arc::new(TopicRegistry::default()),
/// )
/// .await?;
/// let addr = server.local_addr();
/// tokio::spawn(server.serve());
/// # let _ = addr;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct JellyServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    registry: Arc<TopicRegistry>,
    verifier: Option<FlightRequestAuthVerifier>,
    publish_idle_timeout: Option<Duration>,
}

impl JellyServer {
    /// Binds an unauthenticated listener on a loopback `addr`.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Auth`] when `addr` is not loopback and
    /// [`JellyGrpcError::Transport`] when the socket cannot be bound or its
    /// local address cannot be resolved.
    pub async fn bind(
        addr: SocketAddr,
        registry: Arc<TopicRegistry>,
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
        registry: Arc<TopicRegistry>,
        verifier: FlightRequestAuthVerifier,
    ) -> Result<Self, JellyGrpcError> {
        let verifier = require_verifier(verifier)?;
        Self::bind_inner(addr, registry, Some(verifier)).await
    }

    async fn bind_inner(
        addr: SocketAddr,
        registry: Arc<TopicRegistry>,
        verifier: Option<FlightRequestAuthVerifier>,
    ) -> Result<Self, JellyGrpcError> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
            registry,
            verifier,
            publish_idle_timeout: DEFAULT_PUBLISH_IDLE_TIMEOUT,
        })
    }

    /// Ends a publish stream that sends nothing for `timeout`.
    ///
    /// `None`, the default, waits indefinitely and leaves liveness to HTTP/2
    /// keepalive; see [`crate::DEFAULT_PUBLISH_IDLE_TIMEOUT`].
    #[must_use]
    pub fn with_publish_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.publish_idle_timeout = timeout;
        self
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
        let service = RdfStreamServiceServer::new(
            JellyStreamService::new(self.registry)
                .with_publish_idle_timeout(self.publish_idle_timeout),
        )
        .max_decoding_message_size(DEFAULT_MAX_MESSAGE_BYTES)
        .max_encoding_message_size(DEFAULT_MAX_MESSAGE_BYTES);
        server_builder()
            .add_service(InterceptedService::new(service, auth_gate(self.verifier)))
            .serve_with_incoming(TcpListenerStream::new(self.listener))
            .await?;
        Ok(())
    }
}
