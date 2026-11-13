// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Thin client wrapper publishing and subscribing patch operations.

use flight_auth::FlightAuthorizationMetadata;
use jelly_fast_core::{
    JellyPatchDecoder, JellyPatchDecoderOptions, JellyPatchEncoder, JellyPatchEncoderOptions,
    PatchOp,
    proto::patch::{
        RdfPatchFrame, RdfPatchOptions,
        grpc::{
            PatchPublish, PatchSubscribe, patch_stream_service_client::PatchStreamServiceClient,
        },
    },
};
use tonic::{Request, Streaming, transport::Channel};

use crate::{error::JellyGrpcError, transport::DEFAULT_MAX_MESSAGE_BYTES};

/// Client for publishing and subscribing [`PatchOp`] sequences.
///
/// Composes the `jelly-fast-core` patch encoder and decoder over the
/// generated `PatchStreamService` client so callers exchange patch
/// operations (quads carried as `UnsignedQuadStream` batches), never raw
/// frames. Operations stay unsigned end to end; the transport adds no
/// assurance.
#[derive(Clone, Debug)]
pub struct JellyPatchClient {
    inner: PatchStreamServiceClient<Channel>,
    authorization: Option<FlightAuthorizationMetadata>,
}

impl JellyPatchClient {
    /// Connects to a Jelly patch pub/sub server at `endpoint`.
    ///
    /// The endpoint is a full URI such as `http://127.0.0.1:50051`. Messages
    /// are capped at [`crate::DEFAULT_MAX_MESSAGE_BYTES`] in both directions.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Transport`] when the connection cannot be
    /// established.
    pub async fn connect(endpoint: String) -> Result<Self, JellyGrpcError> {
        let inner = PatchStreamServiceClient::connect(endpoint)
            .await?
            .max_decoding_message_size(DEFAULT_MAX_MESSAGE_BYTES)
            .max_encoding_message_size(DEFAULT_MAX_MESSAGE_BYTES);
        Ok(Self {
            inner,
            authorization: None,
        })
    }

    /// Connects and attaches `authorization` to every request.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Transport`] when the connection cannot be
    /// established.
    pub async fn connect_with_authorization(
        endpoint: String,
        authorization: FlightAuthorizationMetadata,
    ) -> Result<Self, JellyGrpcError> {
        let mut client = Self::connect(endpoint).await?;
        client.authorization = Some(authorization);
        Ok(client)
    }

    fn request<T>(&self, payload: T) -> Request<T> {
        match &self.authorization {
            Some(authorization) => authorization.request(payload),
            None => Request::new(payload),
        }
    }

    /// Publishes `ops` as one self-contained patch stream on `topic`.
    ///
    /// A fresh encoder is used per call, so every publish starts with an
    /// options row and full lookup tables — subscribers can decode any
    /// publish they witnessed from its first frame. The topic rides the
    /// publish envelope (first message), not the options row: the vendored
    /// `RdfPatchOptions` has no stream name field.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Publish`] when `topic` is empty,
    /// [`JellyGrpcError::Codec`] when encoding fails or the operation
    /// sequence would end with an open transaction (a torn patch is never
    /// sent), and [`JellyGrpcError::Status`] when the server rejects the
    /// stream.
    pub async fn publish_ops(
        &mut self,
        topic: &str,
        ops: &[PatchOp],
        encoder_options: JellyPatchEncoderOptions,
    ) -> Result<(), JellyGrpcError> {
        if topic.is_empty() {
            return Err(JellyGrpcError::Publish("topic must not be empty".into()));
        }
        let mut encoder = JellyPatchEncoder::new(encoder_options)?;
        let frames = encoder.encode_ops(ops)?;
        encoder.finish()?;
        let topic = topic.to_owned();
        let messages: Vec<PatchPublish> = frames
            .into_iter()
            .enumerate()
            .map(|(index, frame)| PatchPublish {
                // The envelope carries the topic on the first message only;
                // the service pins later messages to it.
                topic: if index == 0 {
                    topic.clone()
                } else {
                    String::new()
                },
                frame: Some(frame),
            })
            .collect();
        let request = self.request(tokio_stream::iter(messages));
        self.inner.publish_patches(request).await?;
        Ok(())
    }

    /// Subscribes to `topic`, returning a decoding patch subscription.
    ///
    /// `requested_options`, when provided, are forwarded to the server,
    /// which answers `INVALID_ARGUMENT` if it cannot serve a matching
    /// stream. Only frames published after the subscription is established
    /// are delivered.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Status`] when the server rejects the
    /// subscription (including incompatible `requested_options`).
    pub async fn subscribe(
        &mut self,
        topic: &str,
        requested_options: Option<RdfPatchOptions>,
        decoder_options: JellyPatchDecoderOptions,
    ) -> Result<PatchOpSubscription, JellyGrpcError> {
        let request = self.request(PatchSubscribe {
            topic: topic.to_owned(),
            requested_options,
        });
        let response = self.inner.subscribe_patches(request).await?;
        Ok(PatchOpSubscription {
            frames: response.into_inner(),
            decoder: JellyPatchDecoder::new(decoder_options),
        })
    }
}

/// A live subscription decoding relayed frames into patch operations.
///
/// One frame decodes into one operation sequence; the decoder carries
/// lookup table, repeated-term, and transaction state across frames, so
/// sequences must be pulled in order. One subscription decodes one
/// publish's stream: a second publish on the topic re-announces options,
/// which surfaces as an explicit duplicate-options error — resubscribe to
/// follow it.
#[derive(Debug)]
pub struct PatchOpSubscription {
    frames: Streaming<RdfPatchFrame>,
    decoder: JellyPatchDecoder,
}

impl PatchOpSubscription {
    /// Receives and decodes the next frame; `None` when the stream ends.
    ///
    /// When the stream ends, the decoder's end-of-stream validation runs:
    /// a patch cut off inside an open transaction is a typed error, never
    /// silence.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Status`] when the server terminates the
    /// stream with an error (including the explicit `DATA_LOSS` status for
    /// lagging subscribers) and [`JellyGrpcError::Codec`] when a relayed
    /// frame is not a valid continuation of the patch stream or the
    /// stream ends mid-transaction.
    pub async fn next_ops(&mut self) -> Result<Option<Vec<PatchOp>>, JellyGrpcError> {
        match self.frames.message().await? {
            Some(frame) => Ok(Some(self.decoder.decode_frame(&frame)?)),
            None => {
                self.decoder.finish()?;
                Ok(None)
            }
        }
    }
}
