// Rust guideline compliant 2026-02-21
//! Thin client wrapper publishing and subscribing quad batches.

use arrow_array::RecordBatch;
use flight_auth::FlightAuthorizationMetadata;
use jelly_fast_core::{
    JellyDecoder, JellyDecoderOptions, JellyEncoder, JellyEncoderOptions,
    proto::{
        RdfStreamFrame, RdfStreamOptions, RdfStreamSubscribe,
        rdf_stream_service_client::RdfStreamServiceClient,
    },
};
use tonic::{Request, Streaming, transport::Channel};

use crate::{error::JellyGrpcError, transport::DEFAULT_MAX_MESSAGE_BYTES};

/// Client for publishing and subscribing `UnsignedQuadStream` batches.
///
/// Composes the `jelly-fast-core` encoder and decoder over the generated
/// `RdfStreamService` client so callers exchange Arrow batches, never raw
/// frames. Batches stay unsigned end to end; the transport adds no
/// assurance.
#[derive(Clone, Debug)]
pub struct JellyClient {
    inner: RdfStreamServiceClient<Channel>,
    authorization: Option<FlightAuthorizationMetadata>,
}

impl JellyClient {
    /// Connects to a Jelly pub/sub server at `endpoint`.
    ///
    /// The endpoint is a full URI such as `http://127.0.0.1:50051`. Messages
    /// are capped at [`crate::DEFAULT_MAX_MESSAGE_BYTES`] in both directions.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Transport`] when the connection cannot be
    /// established.
    pub async fn connect(endpoint: String) -> Result<Self, JellyGrpcError> {
        let inner = RdfStreamServiceClient::connect(endpoint)
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

    /// Publishes `batches` as one self-contained Jelly stream on `topic`.
    ///
    /// The topic is written into the stream options as `stream_name`
    /// (overriding any name set in `encoder_options`), and a fresh encoder
    /// is used per call so every publish starts with an options row and
    /// full lookup tables — subscribers can decode any publish they
    /// witnessed from its first frame.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Publish`] when `batches` is empty (an
    /// empty publish would carry no options row and the server rejects
    /// it), [`JellyGrpcError::Codec`] when encoding fails, and
    /// [`JellyGrpcError::Status`] when the server rejects the stream.
    pub async fn publish_batches(
        &mut self,
        topic: &str,
        batches: &[RecordBatch],
        encoder_options: JellyEncoderOptions,
    ) -> Result<(), JellyGrpcError> {
        if batches.is_empty() {
            return Err(JellyGrpcError::Publish(
                "at least one batch is required per publish".into(),
            ));
        }
        let mut encoder = JellyEncoder::new(JellyEncoderOptions {
            stream_name: Some(topic.to_owned()),
            ..encoder_options
        })?;
        let mut frames = Vec::new();
        for batch in batches {
            frames.extend(encoder.encode_batch(batch)?);
        }
        let request = self.request(tokio_stream::iter(frames));
        self.inner.publish_rdf(request).await?;
        Ok(())
    }

    /// Subscribes to `topic`, returning a decoding batch subscription.
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
        requested_options: Option<RdfStreamOptions>,
        decoder_options: JellyDecoderOptions,
    ) -> Result<QuadBatchSubscription, JellyGrpcError> {
        let request = self.request(RdfStreamSubscribe {
            topic: topic.to_owned(),
            requested_options,
        });
        let response = self.inner.subscribe_rdf(request).await?;
        Ok(QuadBatchSubscription {
            frames: response.into_inner(),
            decoder: JellyDecoder::new(decoder_options),
        })
    }
}

/// A live subscription decoding relayed frames into quad batches.
///
/// One frame decodes into one batch; the decoder carries lookup table and
/// repeated-term state across frames, so batches must be pulled in order.
#[derive(Debug)]
pub struct QuadBatchSubscription {
    frames: Streaming<RdfStreamFrame>,
    decoder: JellyDecoder,
}

impl QuadBatchSubscription {
    /// Receives and decodes the next frame; `None` when the stream ends.
    ///
    /// # Errors
    ///
    /// Returns [`JellyGrpcError::Status`] when the server terminates the
    /// stream with an error (including the explicit `DATA_LOSS` status for
    /// lagging subscribers) and [`JellyGrpcError::Codec`] when a relayed
    /// frame is not a valid continuation of the Jelly stream.
    pub async fn next_batch(&mut self) -> Result<Option<RecordBatch>, JellyGrpcError> {
        match self.frames.message().await? {
            Some(frame) => Ok(Some(self.decoder.decode_frame(&frame)?)),
            None => Ok(None),
        }
    }
}
