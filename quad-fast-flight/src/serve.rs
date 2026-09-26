// Rust guideline compliant 2026-02-21
//! Binding the quad Flight service to a local TCP address.

use std::net::SocketAddr;

use arrow_flight::flight_service_server::FlightServiceServer;
use thiserror::Error;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use crate::{limits::DatasetLimits, service::QuadFlightService};

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
}

impl ServeError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Bind(_) => "bind",
            Self::Transport(_) => "transport",
            Self::Join(_) => "join",
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

/// Binds `listener`-backed serving for an already routed tonic service.
async fn bind(addr: SocketAddr) -> Result<(TcpListener, SocketAddr), ServeError> {
    let listener = TcpListener::bind(addr).await.map_err(ServeError::Bind)?;
    let local_addr = listener.local_addr().map_err(ServeError::Bind)?;
    Ok((listener, local_addr))
}

/// Serves the quad Flight service with default limits on `addr`.
///
/// Binding `127.0.0.1:0` is supported; the resolved address is available
/// through [`FlightServer::local_addr`].
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
/// Returns [`ServeError::Bind`] when the TCP listener cannot be created.
pub async fn serve(addr: SocketAddr) -> Result<FlightServer, ServeError> {
    serve_with_limits(addr, DatasetLimits::default()).await
}

/// Serves the quad Flight service with explicit fail-closed limits.
///
/// # Errors
///
/// Returns [`ServeError::Bind`] when the TCP listener cannot be created.
pub async fn serve_with_limits(
    addr: SocketAddr,
    limits: DatasetLimits,
) -> Result<FlightServer, ServeError> {
    let (listener, local_addr) = bind(addr).await?;
    let (shutdown, signal) = oneshot::channel::<()>();
    let service = FlightServiceServer::new(QuadFlightService::new(limits));
    let task = tokio::spawn(async move {
        Server::builder()
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

/// Serves the quad Flight service behind the shared JWT metadata verifier.
///
/// Every RPC is intercepted and its `authorization` metadata is validated by
/// `flight-auth` (the verifier reused from `office-parsers-rs`) before the
/// service runs. Authentication gates transport access only; it never signs
/// or promotes the unsigned payloads.
///
/// # Errors
///
/// Returns [`ServeError::Bind`] when the TCP listener cannot be created.
#[cfg(feature = "auth")]
pub async fn serve_with_verifier(
    addr: SocketAddr,
    limits: DatasetLimits,
    verifier: flight_auth::FlightRequestAuthVerifier,
) -> Result<FlightServer, ServeError> {
    let (listener, local_addr) = bind(addr).await?;
    let (shutdown, signal) = oneshot::channel::<()>();
    let service = FlightServiceServer::with_interceptor(
        QuadFlightService::new(limits),
        move |request: tonic::Request<()>| {
            verifier.verify_metadata(request.metadata())?;
            Ok(request)
        },
    );
    let task = tokio::spawn(async move {
        Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
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
