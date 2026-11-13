// Rust guideline compliant 2026-02-21
//! Binding the quad Flight service to a local TCP address.
//!
//! Two entry points, one policy: [`serve_with_verifier`] refuses to start
//! unless its verifier actually requires authentication with a configured
//! issuer and audience, and the unauthenticated [`serve`] and
//! [`serve_with_limits`] refuse every address that is not loopback.
//!
//! What these entry points do not do:
//!
//! - **TLS.** The transport is plaintext HTTP/2; put it behind a
//!   TLS-terminating proxy or a service mesh.
//! - **Tenant scoping.** Any token with `flight:invoke` can read, drop or
//!   `reset` any dataset.
//! - **Expiry of open streams.** A token is checked when a stream opens; an
//!   open stream outlives the token's `exp`.
//!
//! The store byte budget counts encoded wire bytes (`FlightData` header plus
//! body as received, plus the uncompressed size any zstd buffer declares),
//! and a dataset stays charged until its last reader is gone.

use std::{net::SocketAddr, time::Duration};

use arrow_flight::flight_service_server::FlightServiceServer;
use flight_auth::FlightRequestAuthVerifier;
use thiserror::Error;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{service::interceptor::InterceptedService, transport::Server};

use crate::{
    limits::{DatasetLimits, decode_limit},
    service::QuadFlightService,
};

/// Interval between HTTP/2 keepalive pings sent to an idle peer.
///
/// With [`HTTP2_KEEPALIVE_TIMEOUT`] this closes connections whose peer
/// vanished without a FIN, which would otherwise hold their streams forever.
const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// How long a keepalive ping may go unanswered before the connection closes.
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// TCP keepalive idle time, a second line under the HTTP/2 pings.
const TCP_KEEPALIVE: Duration = Duration::from_secs(60);

/// Closed error surface for starting and stopping the Flight server.
#[derive(Debug, Error)]
pub enum ServeError {
    /// Binding or inspecting the TCP listener failed.
    #[error("bind: {0}")]
    Bind(std::io::Error),
    /// The tonic transport failed while serving.
    #[error("transport: {0}")]
    Transport(String),
    /// The server task aborted or panicked before finishing.
    #[error("join: {0}")]
    Join(String),
    /// The requested server would accept unauthenticated network traffic.
    ///
    /// Raised by [`serve_with_verifier`] for a verifier that does not require
    /// authentication or has no issuer or audience, and by [`serve`] and
    /// [`serve_with_limits`] for an address that is not loopback.
    #[error("auth: {0}")]
    Auth(String),
}

impl ServeError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Bind(_) => "bind",
            Self::Transport(_) => "transport",
            Self::Join(_) => "join",
            Self::Auth(_) => "auth",
        }
    }
}

/// Running Flight server with its bound address and a shutdown handle.
///
/// Dropping the handle without calling [`FlightServer::shutdown`] leaves the
/// server running until the process exits (the shutdown sender is dropped,
/// which also triggers graceful shutdown of the accept loop).
#[derive(Debug)]
pub struct FlightServer {
    local_addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl FlightServer {
    /// Returns the actually bound local address (resolves `:0` requests).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Gracefully stops the server and waits for the task to finish.
    ///
    /// # Errors
    ///
    /// Returns [`ServeError::Transport`] when the transport failed while
    /// serving and [`ServeError::Join`] when the server task panicked.
    pub async fn shutdown(self) -> Result<(), ServeError> {
        // A closed receiver means the task already stopped; that is fine.
        let _ = self.shutdown.send(());
        self.task
            .await
            .map_err(|error| ServeError::Join(error.to_string()))?
            .map_err(|error| ServeError::Transport(error.to_string()))
    }
}

/// Serves the quad Flight service with default limits on a loopback `addr`.
///
/// This entry point performs no authentication, so it refuses any address
/// that is not loopback. Binding `127.0.0.1:0` is supported; the resolved
/// address is available through [`FlightServer::local_addr`].
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), quad_fast_flight::ServeError> {
/// let server = quad_fast_flight::serve("127.0.0.1:0".parse().unwrap()).await?;
/// println!("flight endpoint: {}", server.local_addr());
/// server.shutdown().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`ServeError::Auth`] when `addr` is not loopback and
/// [`ServeError::Bind`] when the TCP listener cannot be created.
pub async fn serve(addr: SocketAddr) -> Result<FlightServer, ServeError> {
    serve_with_limits(addr, DatasetLimits::default()).await
}

/// Serves the quad Flight service with explicit limits on a loopback `addr`.
///
/// # Errors
///
/// Returns [`ServeError::Auth`] when `addr` is not loopback and
/// [`ServeError::Bind`] when the TCP listener cannot be created.
pub async fn serve_with_limits(
    addr: SocketAddr,
    limits: DatasetLimits,
) -> Result<FlightServer, ServeError> {
    if !addr.ip().is_loopback() {
        return Err(ServeError::Auth(
            "an unauthenticated Flight server binds only a loopback address; use \
             serve_with_verifier for any other"
                .to_owned(),
        ));
    }
    spawn(addr, limits, None).await
}

/// Serves the quad Flight service behind the shared JWT metadata verifier.
///
/// Every RPC is intercepted and its `authorization` metadata is validated by
/// `flight-auth` before the service runs. Authentication gates transport
/// access only; it never signs or promotes the unsigned payloads.
///
/// A surface that advertises authentication must never start without it, so
/// the verifier must pass [`FlightRequestAuthVerifier::require_enabled`]:
/// authentication required, with a non-empty issuer and audience.
///
/// # Errors
///
/// Returns [`ServeError::Auth`] when `verifier` does not require
/// authentication or lacks an issuer or audience, and [`ServeError::Bind`]
/// when the TCP listener cannot be created.
pub async fn serve_with_verifier(
    addr: SocketAddr,
    limits: DatasetLimits,
    verifier: FlightRequestAuthVerifier,
) -> Result<FlightServer, ServeError> {
    let verifier = verifier
        .require_enabled()
        .map_err(|error| ServeError::Auth(error.to_string()))?;
    spawn(addr, limits, Some(verifier)).await
}

/// Binds `addr` and runs the service, verifying metadata when given a verifier.
async fn spawn(
    addr: SocketAddr,
    limits: DatasetLimits,
    verifier: Option<FlightRequestAuthVerifier>,
) -> Result<FlightServer, ServeError> {
    let listener = TcpListener::bind(addr).await.map_err(ServeError::Bind)?;
    let local_addr = listener.local_addr().map_err(ServeError::Bind)?;
    let (shutdown, signal) = oneshot::channel::<()>();
    let flight = FlightServiceServer::new(QuadFlightService::new(limits))
        // Accept slightly less than we send, so a re-encoded single-row batch
        // (which the Flight encoder cannot split) always fits on the way out.
        .max_decoding_message_size(decode_limit(limits.max_message_bytes))
        .max_encoding_message_size(limits.max_message_bytes);
    let service = InterceptedService::new(flight, move |request: tonic::Request<()>| {
        if let Some(verifier) = &verifier {
            verifier.verify_metadata(request.metadata())?;
        }
        Ok(request)
    });
    let max_streams = u32::try_from(limits.max_concurrent_requests_per_connection).ok();
    let task = tokio::spawn(async move {
        Server::builder()
            .concurrency_limit_per_connection(limits.max_concurrent_requests_per_connection)
            .max_concurrent_streams(max_streams)
            .http2_keepalive_interval(Some(HTTP2_KEEPALIVE_INTERVAL))
            .http2_keepalive_timeout(Some(HTTP2_KEEPALIVE_TIMEOUT))
            .tcp_keepalive(Some(TCP_KEEPALIVE))
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                // Both an explicit shutdown and a dropped sender stop the loop.
                drop(signal.await);
            })
            .await
    });
    Ok(FlightServer {
        local_addr,
        shutdown,
        task,
    })
}
