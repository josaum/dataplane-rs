// Rust guideline compliant 2026-02-21
//! Closed error surface for the Jelly gRPC transport.

use jelly_fast_core::JellyError;
use thiserror::Error;

/// Closed error surface for serving and consuming Jelly RDF streams.
///
/// Every variant carries a stable machine-readable code as the first token
/// of its rendered message; [`JellyGrpcError::code`] returns the same
/// token.
#[derive(Debug, Error)]
pub enum JellyGrpcError {
    /// Binding, connecting, or driving the gRPC transport failed.
    #[error("transport: {0}")]
    Transport(String),
    /// The remote peer answered an RPC with a gRPC status.
    #[error("status: {0}")]
    Status(#[from] tonic::Status),
    /// Encoding or decoding Jelly frames failed.
    #[error("codec: {0}")]
    Codec(#[from] JellyError),
    /// A publish request is structurally invalid before leaving the client.
    #[error("publish: {0}")]
    Publish(String),
    /// A server would accept unauthenticated traffic from the network.
    ///
    /// Raised for an unauthenticated bind on a non-loopback address and for
    /// a verifier that does not require authentication with an issuer and
    /// audience.
    #[error("auth: {0}")]
    Auth(String),
}

impl JellyGrpcError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Transport(_) => "transport",
            Self::Status(_) => "status",
            Self::Codec(_) => "codec",
            Self::Publish(_) => "publish",
            Self::Auth(_) => "auth",
        }
    }
}

impl From<tonic::transport::Error> for JellyGrpcError {
    fn from(error: tonic::transport::Error) -> Self {
        Self::Transport(error.to_string())
    }
}

impl From<std::io::Error> for JellyGrpcError {
    fn from(error: std::io::Error) -> Self {
        Self::Transport(error.to_string())
    }
}
