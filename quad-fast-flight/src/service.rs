// Rust guideline compliant 2026-02-21
//! Arrow Flight service over the in-memory unsigned quad-dataset store.
//!
//! Every RPC speaks exactly one payload: the `UnsignedQuadStream` v1 Arrow
//! contract from [`quad_fast_core`]. Ingest validates the contract on every
//! incoming schema and record batch and rejects non-conforming payloads with
//! `INVALID_ARGUMENT`; a batch that fails validation is never stored and
//! never served.

use arrow_array::RecordBatch;
use arrow_flight::{
    Action, ActionType, Criteria, Empty, FlightData, FlightDescriptor, FlightEndpoint, FlightInfo,
    HandshakeRequest, HandshakeResponse, PollInfo, PutResult, Result as ActionResult, SchemaAsIpc,
    SchemaResult, Ticket,
    decode::{DecodedPayload, FlightDataDecoder},
    encode::{DictionaryHandling, FlightDataEncoderBuilder},
    error::FlightError,
    flight_descriptor::DescriptorType,
    flight_service_server::FlightService,
};
use arrow_ipc::writer::IpcWriteOptions;
use futures::{StreamExt, TryStreamExt, stream, stream::BoxStream};
use quad_fast_core::{QuadError, UnsignedQuadBatch, quad_stream_schema, validate_contract};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    limits::DatasetLimits,
    store::{Dataset, DatasetStore},
};

/// `DoAction` type that drops one dataset named by the UTF-8 action body.
pub const ACTION_DROP_DATASET: &str = "drop_dataset";

/// `DoAction` type that drops every stored dataset.
pub const ACTION_RESET: &str = "reset";

/// Boxed tonic response stream used by every streaming RPC.
type ResponseStream<T> = BoxStream<'static, Result<T, Status>>;

/// Arrow Flight service exposing an in-memory unsigned quad-dataset store.
///
/// Datasets are named by `FlightDescriptor` paths: either
/// `["datasets", <name>]` or a single-element `[<name>]` path (the first
/// convention is what the service itself advertises). `DoGet` tickets carry
/// the raw UTF-8 dataset name. Everything stored and served is **unsigned**;
/// the service never certifies, approves, or promotes a quad.
///
/// # Examples
///
/// ```
/// use quad_fast_flight::{DatasetLimits, QuadFlightService};
///
/// let service = QuadFlightService::new(DatasetLimits::default());
/// assert_eq!(service.limits().max_datasets, 1_024);
/// ```
#[derive(Debug, Default)]
pub struct QuadFlightService {
    limits: DatasetLimits,
    store: RwLock<DatasetStore>,
}

impl QuadFlightService {
    /// Creates an empty store governed by `limits`.
    #[must_use]
    pub fn new(limits: DatasetLimits) -> Self {
        Self {
            limits,
            store: RwLock::new(DatasetStore::default()),
        }
    }

    /// Returns the fail-closed limits governing this store.
    #[must_use]
    pub fn limits(&self) -> DatasetLimits {
        self.limits
    }
}

/// Maps a contract or limit error onto its canonical gRPC status.
///
/// Resource-limit violations become `RESOURCE_EXHAUSTED`; every other quad
/// error signals a non-conforming client payload and becomes
/// `INVALID_ARGUMENT`. The stable `quad_fast_core` error code stays in the
/// status message.
fn quad_status(error: &QuadError) -> Status {
    match error {
        QuadError::ResourceLimit { .. } => Status::resource_exhausted(error.to_string()),
        _ => Status::invalid_argument(error.to_string()),
    }
}

/// Maps a decode failure of client-supplied flight data onto a status.
///
/// Transport errors pass through unchanged; everything else means the client
/// sent a malformed payload and becomes `INVALID_ARGUMENT`.
fn ingest_status(error: FlightError) -> Status {
    match error {
        FlightError::Tonic(status) => *status,
        other => Status::invalid_argument(format!("flight_decode: {other}")),
    }
}

/// Wraps a status so it survives an [`FlightError`] stream unchanged.
fn status_to_flight(status: Status) -> FlightError {
    FlightError::Tonic(Box::new(status))
}

/// Accepts a decoded Flight batch only as a sealed unsigned quad batch.
///
/// [`UnsignedQuadBatch::try_from_batch`] is the compile-time store gate:
/// `Dataset` holds this type, so a reasoner-shaped `RecordBatch` cannot be
/// inserted without a conversion that re-runs the contract checks.
fn accept_unsigned_batch(batch: RecordBatch) -> Result<UnsignedQuadBatch, Status> {
    UnsignedQuadBatch::try_from_batch(batch).map_err(|error| quad_status(&error))
}

/// Fails closed when a dataset-shaped payload exceeds the store limits.
fn ensure_dataset_budget(limits: &DatasetLimits, batches: usize, quads: u64) -> Result<(), Status> {
    if batches > limits.max_batches_per_dataset {
        return Err(Status::resource_exhausted(format!(
            "resource_limit: batches_per_dataset: observed {batches} exceeds limit {}",
            limits.max_batches_per_dataset
        )));
    }
    if quads > limits.max_quads_per_dataset {
        return Err(Status::resource_exhausted(format!(
            "resource_limit: quads_per_dataset: observed {quads} exceeds limit {}",
            limits.max_quads_per_dataset
        )));
    }
    Ok(())
}

/// Extracts the dataset name from a PATH flight descriptor.
///
/// Accepted shapes are `["datasets", <name>]` and `[<name>]`; the name must
/// be non-empty. Command descriptors and other path shapes are rejected with
/// `INVALID_ARGUMENT`.
fn dataset_name_from_descriptor(descriptor: &FlightDescriptor) -> Result<String, Status> {
    if descriptor.r#type != DescriptorType::Path as i32 {
        return Err(Status::invalid_argument(
            "descriptor: datasets are named by PATH descriptors, not CMD",
        ));
    }
    let name = match descriptor.path.as_slice() {
        [name] => name,
        [collection, name] if collection == "datasets" => name,
        _ => {
            return Err(Status::invalid_argument(
                "descriptor: expected path [\"datasets\", <name>] or [<name>]",
            ));
        }
    };
    if name.is_empty() {
        return Err(Status::invalid_argument(
            "descriptor: dataset name must be non-empty",
        ));
    }
    Ok(name.clone())
}

/// Decodes a required non-empty UTF-8 dataset name from raw bytes.
fn dataset_name_from_bytes(bytes: &[u8], carrier: &str) -> Result<String, Status> {
    let name = std::str::from_utf8(bytes).map_err(|error| {
        Status::invalid_argument(format!("{carrier}: name is not valid UTF-8: {error}"))
    })?;
    if name.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{carrier}: dataset name must be non-empty"
        )));
    }
    Ok(name.to_owned())
}

/// Escapes `value` as one JSON string literal, including the quotes.
fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                escaped.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    escaped
}

/// Builds the informational (never signed) JSON receipt for one `DoPut`.
fn put_receipt(dataset: &str, batches: usize, quads: u64) -> String {
    format!(
        "{{\"dataset\":{},\"batches\":{batches},\"quads\":{quads}}}",
        json_string(dataset)
    )
}

/// Builds the `FlightInfo` advertising one stored dataset.
fn flight_info(name: &str, dataset: &Dataset) -> Result<FlightInfo, Status> {
    let descriptor = FlightDescriptor::new_path(vec!["datasets".to_owned(), name.to_owned()]);
    let endpoint = FlightEndpoint::new().with_ticket(Ticket::new(name.to_owned()));
    let info = FlightInfo::new()
        .try_with_schema(quad_stream_schema().as_ref())
        .map_err(|error| Status::internal(format!("arrow: {error}")))?;
    Ok(info
        .with_descriptor(descriptor)
        .with_endpoint(endpoint)
        .with_total_records(i64::try_from(dataset.total_quads).unwrap_or(i64::MAX)))
}

/// Encodes contract batches for the wire, preserving dictionary columns.
///
/// [`DictionaryHandling::Resend`] is load-bearing: the default `Hydrate`
/// rewrites dictionary fields to their value types, which would break the
/// `UnsignedQuadStream` contract on the receiving side.
fn encode_batches<S>(batches: S) -> BoxStream<'static, Result<FlightData, Status>>
where
    S: futures::Stream<Item = Result<RecordBatch, FlightError>> + Send + 'static,
{
    FlightDataEncoderBuilder::new()
        .with_schema(quad_stream_schema())
        .with_dictionary_handling(DictionaryHandling::Resend)
        .build(batches)
        .map_err(Status::from)
        .boxed()
}

#[tonic::async_trait]
impl FlightService for QuadFlightService {
    type HandshakeStream = ResponseStream<HandshakeResponse>;
    type ListFlightsStream = ResponseStream<FlightInfo>;
    type DoGetStream = ResponseStream<FlightData>;
    type DoPutStream = ResponseStream<PutResult>;
    type DoActionStream = ResponseStream<ActionResult>;
    type ListActionsStream = ResponseStream<ActionType>;
    type DoExchangeStream = ResponseStream<FlightData>;

    /// Not implemented; the unsigned dataplane has no handshake protocol yet.
    async fn handshake(
        &self,
        _request: Request<Streaming<HandshakeRequest>>,
    ) -> Result<Response<Self::HandshakeStream>, Status> {
        Err(Status::unimplemented(
            "handshake is not implemented; authentication uses request metadata",
        ))
    }

    /// Enumerates every stored dataset; the criteria payload is ignored.
    async fn list_flights(
        &self,
        _request: Request<Criteria>,
    ) -> Result<Response<Self::ListFlightsStream>, Status> {
        let infos: Vec<Result<FlightInfo, Status>> = {
            let store = self.store.read().await;
            store
                .iter()
                .map(|(name, dataset)| flight_info(name, dataset))
                .collect()
        };
        Ok(Response::new(stream::iter(infos).boxed()))
    }

    /// Describes one dataset: schema, one endpoint, and total quad count.
    async fn get_flight_info(
        &self,
        request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        let name = dataset_name_from_descriptor(request.get_ref())?;
        let store = self.store.read().await;
        let dataset = store
            .get(&name)
            .ok_or_else(|| Status::not_found(format!("dataset `{name}` is not stored")))?;
        Ok(Response::new(flight_info(&name, dataset.as_ref())?))
    }

    /// Not implemented; puts complete synchronously, so there is no polling.
    async fn poll_flight_info(
        &self,
        _request: Request<FlightDescriptor>,
    ) -> Result<Response<PollInfo>, Status> {
        Err(Status::unimplemented(
            "poll_flight_info is not implemented; use get_flight_info",
        ))
    }

    /// Returns the IPC-encoded `UnsignedQuadStream` v1 schema.
    ///
    /// The schema is contract-fixed, so the descriptor only needs to be
    /// well-formed; it does not have to name a stored dataset.
    async fn get_schema(
        &self,
        request: Request<FlightDescriptor>,
    ) -> Result<Response<SchemaResult>, Status> {
        dataset_name_from_descriptor(request.get_ref())?;
        let options = IpcWriteOptions::default();
        let schema = quad_stream_schema();
        let result = SchemaResult::try_from(SchemaAsIpc::new(schema.as_ref(), &options))
            .map_err(|error| Status::internal(format!("arrow: {error}")))?;
        Ok(Response::new(result))
    }

    /// Streams one stored dataset; the ticket is the UTF-8 dataset name.
    async fn do_get(
        &self,
        request: Request<Ticket>,
    ) -> Result<Response<Self::DoGetStream>, Status> {
        let name = dataset_name_from_bytes(&request.get_ref().ticket, "ticket")?;
        let dataset = {
            let store = self.store.read().await;
            store
                .get(&name)
                .ok_or_else(|| Status::not_found(format!("dataset `{name}` is not stored")))?
        };
        let batches = stream::iter(
            dataset
                .batches
                .clone()
                .into_iter()
                .map(UnsignedQuadBatch::into_inner)
                .map(Ok::<_, FlightError>),
        );
        Ok(Response::new(encode_batches(batches)))
    }

    /// Ingests one dataset atomically after validating every batch.
    ///
    /// The first flight-data frame must carry the dataset descriptor. Every
    /// decoded schema and batch is validated against the contract before
    /// anything is stored; a failure anywhere leaves the store unchanged.
    /// Re-putting an existing name replaces that dataset atomically. The
    /// single `PutResult` carries the informational JSON receipt
    /// `{"dataset", "batches", "quads"}`, which is not a signature.
    async fn do_put(
        &self,
        request: Request<Streaming<FlightData>>,
    ) -> Result<Response<Self::DoPutStream>, Status> {
        let mut incoming = request.into_inner();
        let first = incoming
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("do_put: empty flight data stream"))?;
        let descriptor = first.flight_descriptor.clone().ok_or_else(|| {
            Status::invalid_argument("do_put: first flight data frame carries no descriptor")
        })?;
        let name = dataset_name_from_descriptor(&descriptor)?;

        let head = stream::iter([Ok::<FlightData, FlightError>(first)]);
        let mut decoder = FlightDataDecoder::new(head.chain(incoming.map_err(FlightError::from)));

        let mut batches: Vec<UnsignedQuadBatch> = Vec::new();
        let mut total_quads: u64 = 0;
        while let Some(decoded) = decoder.next().await {
            let decoded = decoded.map_err(ingest_status)?;
            match decoded.payload {
                DecodedPayload::Schema(schema) => {
                    validate_contract(schema.as_ref()).map_err(|error| quad_status(&error))?;
                }
                DecodedPayload::RecordBatch(batch) => {
                    let batch = accept_unsigned_batch(batch)?;
                    let quads = total_quads + batch.num_rows() as u64;
                    ensure_dataset_budget(&self.limits, batches.len() + 1, quads)?;
                    total_quads = quads;
                    batches.push(batch);
                }
                DecodedPayload::None => {}
            }
        }

        let receipt = put_receipt(&name, batches.len(), total_quads);
        let dataset = Dataset {
            batches,
            total_quads,
        };
        self.store
            .write()
            .await
            .insert(name, dataset, &self.limits)?;

        let result = PutResult {
            app_metadata: receipt.into(),
        };
        Ok(Response::new(stream::iter([Ok(result)]).boxed()))
    }

    /// Validate-and-echo transform over contract batches.
    ///
    /// Each incoming batch is contract-validated and streamed straight back.
    /// This is the hook where future dataplane transforms (projection,
    /// graph filtering, reasoner bridging) will plug in; today the transform
    /// is the identity. Nothing is stored, and the fail-closed dataset
    /// budget applies to the exchanged stream as a whole.
    async fn do_exchange(
        &self,
        request: Request<Streaming<FlightData>>,
    ) -> Result<Response<Self::DoExchangeStream>, Status> {
        let limits = self.limits;
        let decoder = FlightDataDecoder::new(request.into_inner().map_err(FlightError::from));
        let mut seen_batches = 0_usize;
        let mut seen_quads = 0_u64;
        let validated = decoder
            .map(move |decoded| -> Result<Option<RecordBatch>, FlightError> {
                match decoded?.payload {
                    DecodedPayload::Schema(schema) => {
                        validate_contract(schema.as_ref())
                            .map_err(|error| status_to_flight(quad_status(&error)))?;
                        Ok(None)
                    }
                    DecodedPayload::RecordBatch(batch) => {
                        let batch = accept_unsigned_batch(batch).map_err(status_to_flight)?;
                        seen_batches += 1;
                        seen_quads += batch.num_rows() as u64;
                        ensure_dataset_budget(&limits, seen_batches, seen_quads)
                            .map_err(status_to_flight)?;
                        Ok(Some(batch.into_inner()))
                    }
                    DecodedPayload::None => Ok(None),
                }
            })
            .filter_map(|result| async move { result.transpose() });
        Ok(Response::new(encode_batches(validated)))
    }

    /// Runs a store action: [`ACTION_DROP_DATASET`] or [`ACTION_RESET`].
    async fn do_action(
        &self,
        request: Request<Action>,
    ) -> Result<Response<Self::DoActionStream>, Status> {
        let action = request.into_inner();
        let body = match action.r#type.as_str() {
            ACTION_DROP_DATASET => {
                let name = dataset_name_from_bytes(&action.body, "action body")?;
                let removed = self.store.write().await.remove(&name);
                if removed.is_none() {
                    return Err(Status::not_found(format!("dataset `{name}` is not stored")));
                }
                format!("{{\"dropped\":{}}}", json_string(&name))
            }
            ACTION_RESET => {
                let dropped = self.store.write().await.reset();
                format!("{{\"reset\":{dropped}}}")
            }
            other => {
                return Err(Status::unimplemented(format!("unknown action `{other}`")));
            }
        };
        let result = ActionResult { body: body.into() };
        Ok(Response::new(stream::iter([Ok(result)]).boxed()))
    }

    /// Describes the supported store actions.
    async fn list_actions(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::ListActionsStream>, Status> {
        let actions = [
            Ok(ActionType {
                r#type: ACTION_DROP_DATASET.to_owned(),
                description: "Drop one dataset; the action body is the UTF-8 dataset name."
                    .to_owned(),
            }),
            Ok(ActionType {
                r#type: ACTION_RESET.to_owned(),
                description: "Drop every stored dataset; the action body is ignored.".to_owned(),
            }),
        ];
        Ok(Response::new(stream::iter(actions).boxed()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_escapes_hostile_names() {
        assert_eq!(json_string("plain"), "\"plain\"");
        assert_eq!(json_string("a\"b\\c\nd\u{1}"), "\"a\\\"b\\\\c\\nd\\u0001\"");
    }

    #[test]
    fn put_receipt_is_wellformed_json() {
        assert_eq!(
            put_receipt("orders", 2, 8),
            "{\"dataset\":\"orders\",\"batches\":2,\"quads\":8}"
        );
    }

    #[test]
    fn descriptor_convention_accepts_both_path_shapes() {
        let long = FlightDescriptor::new_path(vec!["datasets".to_owned(), "d".to_owned()]);
        assert_eq!(dataset_name_from_descriptor(&long).unwrap(), "d");

        let short = FlightDescriptor::new_path(vec!["d".to_owned()]);
        assert_eq!(dataset_name_from_descriptor(&short).unwrap(), "d");

        let cmd = FlightDescriptor::new_cmd(vec![1_u8]);
        let error = dataset_name_from_descriptor(&cmd).unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);

        let empty = FlightDescriptor::new_path(vec![String::new()]);
        let error = dataset_name_from_descriptor(&empty).unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}
