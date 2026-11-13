// Rust guideline compliant 2026-02-21
//! Transport limits and the authentication gate shared by both servers.

use std::{net::SocketAddr, time::Duration};

use flight_auth::FlightRequestAuthVerifier;
use tonic::{Request, Status, Streaming, transport::Server};

use crate::error::JellyGrpcError;

/// Maximum encoded gRPC message, in either direction: 4 MiB.
///
/// tonic's own decoding default, stated explicitly and applied to encoding
/// too (tonic's encoding default is unbounded). A relayed frame is
/// re-encoded unchanged, so the server never needs a larger encode limit than
/// it accepted, and a client refuses an oversized publish before sending it.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// Default longest wait for the next message of a publish stream: none.
///
/// A publish stream is often a change feed that is legitimately quiet for
/// minutes, so no fixed default fits; a wrong one silently cuts live
/// publishers off. Liveness is left to HTTP/2 keepalive (a ping every 30 s,
/// the connection closed after 10 s without an answer), which ends a
/// publisher whose peer vanished. Set a bound with `with_publish_idle_timeout`
/// on the server to also end publishers that stay connected but send nothing.
///
/// A subscription outlives any one publisher: when a publisher ends, for
/// whatever reason, its subscribers receive no end-of-stream and keep
/// waiting for the topic's next publisher.
pub const DEFAULT_PUBLISH_IDLE_TIMEOUT: Option<Duration> = None;

/// Concurrent requests served on one connection (tonic default: unbounded).
const MAX_CONCURRENT_REQUESTS_PER_CONNECTION: usize = 64;

/// HTTP/2 keepalive interval; with the timeout it closes vanished peers.
const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// How long a keepalive ping may go unanswered.
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// TCP keepalive idle time.
const TCP_KEEPALIVE: Duration = Duration::from_secs(60);

/// Returns the server builder every Jelly server runs on.
pub(crate) fn server_builder() -> Server {
    Server::builder()
        .concurrency_limit_per_connection(MAX_CONCURRENT_REQUESTS_PER_CONNECTION)
        .max_concurrent_streams(u32::try_from(MAX_CONCURRENT_REQUESTS_PER_CONNECTION).ok())
        .http2_keepalive_interval(Some(HTTP2_KEEPALIVE_INTERVAL))
        .http2_keepalive_timeout(Some(HTTP2_KEEPALIVE_TIMEOUT))
        .tcp_keepalive(Some(TCP_KEEPALIVE))
}

/// Refuses a non-loopback address for a server that authenticates nothing.
pub(crate) fn require_loopback(addr: SocketAddr) -> Result<(), JellyGrpcError> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    Err(JellyGrpcError::Auth(
        "an unauthenticated Jelly server binds only a loopback address; use \
         bind_with_verifier for any other"
            .to_owned(),
    ))
}

/// Accepts only a verifier that requires authentication with issuer and audience.
pub(crate) fn require_verifier(
    verifier: FlightRequestAuthVerifier,
) -> Result<FlightRequestAuthVerifier, JellyGrpcError> {
    verifier
        .require_enabled()
        .map_err(|error| JellyGrpcError::Auth(error.to_string()))
}

/// Builds the interceptor that verifies `authorization` metadata, if any.
pub(crate) fn auth_gate(
    verifier: Option<FlightRequestAuthVerifier>,
) -> impl FnMut(Request<()>) -> Result<Request<()>, Status> + Clone {
    move |request: Request<()>| {
        if let Some(verifier) = &verifier {
            verifier.verify_metadata(request.metadata())?;
        }
        Ok(request)
    }
}

/// Receives the next message, failing when none arrives within `idle`.
pub(crate) async fn next_message<T>(
    stream: &mut Streaming<T>,
    idle: Option<Duration>,
) -> Result<Option<T>, Status> {
    let Some(idle) = idle else {
        return stream.message().await;
    };
    tokio::time::timeout(idle, stream.message())
        .await
        .map_err(|_elapsed| {
            Status::deadline_exceeded("publish: no message arrived within the idle timeout")
        })?
}
