// Rust guideline compliant 2026-02-21
//! End-to-end tests over a real localhost Arrow Flight socket.

use arrow_array::{Int64Array, RecordBatch};
use arrow_flight::{
    Action, Criteria, FlightDescriptor, Ticket,
    decode::FlightRecordBatchStream,
    encode::{DictionaryHandling, FlightDataEncoderBuilder},
    error::FlightError,
    flight_service_client::FlightServiceClient,
};
use arrow_schema::Schema;
use futures::{StreamExt, TryStreamExt, stream};
use oxrdf::{GraphName, Literal, NamedNode, Quad, Term};
use quad_fast_core::{
    QuadBatchBuilder, QuadLimits, QuadStreamReader, SourceProvenance, quad_stream_schema,
};
use quad_fast_flight::{DatasetLimits, FlightServer, serve, serve_with_limits};
use tonic::transport::Channel;

/// Deterministic provenance attached to every generated quad.
fn provenance(index: u64) -> SourceProvenance {
    SourceProvenance {
        source_artifact_iri: Some("urn:test:artifact".to_owned()),
        source_content_sha256: Some([7_u8; 32]),
        source_offset_start: Some(index * 10),
        source_offset_end: Some(index * 10 + 9),
        observed_at_micros: Some(1_700_000_000_000_000 + i64::try_from(index).unwrap()),
    }
}

/// Builds `count` distinct quads starting at ordinal `start`.
fn quads(start: u64, count: u64) -> Vec<Quad> {
    (start..start + count)
        .map(|index| {
            Quad::new(
                NamedNode::new(format!("http://example.com/s/{index}")).unwrap(),
                NamedNode::new("http://example.com/p").unwrap(),
                Term::Literal(Literal::new_simple_literal(format!("object {index}"))),
                GraphName::NamedNode(NamedNode::new("http://example.com/g").unwrap()),
            )
        })
        .collect()
}

/// Encodes `quads` into one contract batch with provenance.
fn contract_batch(quads: &[Quad], start: u64) -> RecordBatch {
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    for (offset, quad) in quads.iter().enumerate() {
        builder
            .push(quad.as_ref(), Some(&provenance(start + offset as u64)))
            .unwrap();
    }
    builder.finish().unwrap()
}

/// Connects a Flight client to a freshly served store.
async fn start(limits: Option<DatasetLimits>) -> (FlightServer, FlightServiceClient<Channel>) {
    let addr = "127.0.0.1:0".parse().unwrap();
    let server = match limits {
        Some(limits) => serve_with_limits(addr, limits).await.unwrap(),
        None => serve(addr).await.unwrap(),
    };
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let client = FlightServiceClient::new(channel);
    (server, client)
}

/// Encodes contract batches as a put/exchange stream for `dataset`.
fn put_stream(
    dataset: &str,
    batches: Vec<RecordBatch>,
) -> impl futures::Stream<Item = arrow_flight::FlightData> + Send + 'static {
    let descriptor = FlightDescriptor::new_path(vec!["datasets".to_owned(), dataset.to_owned()]);
    FlightDataEncoderBuilder::new()
        .with_flight_descriptor(Some(descriptor))
        .with_dictionary_handling(DictionaryHandling::Resend)
        .build(stream::iter(batches.into_iter().map(Ok)))
        .map(|data| data.expect("encode flight data"))
}

/// Puts `batches` under `dataset` and returns the receipt JSON.
async fn put_dataset(
    client: &mut FlightServiceClient<Channel>,
    dataset: &str,
    batches: Vec<RecordBatch>,
) -> Result<String, tonic::Status> {
    let mut results = client
        .do_put(put_stream(dataset, batches))
        .await?
        .into_inner();
    let result = results.message().await?.expect("one PutResult");
    Ok(String::from_utf8(result.app_metadata.to_vec()).unwrap())
}

/// Fetches `dataset` and decodes it back into record batches.
async fn get_dataset(
    client: &mut FlightServiceClient<Channel>,
    dataset: &str,
) -> Result<Vec<RecordBatch>, FlightError> {
    let response = client
        .do_get(Ticket::new(dataset.to_owned()))
        .await
        .map_err(FlightError::from)?;
    FlightRecordBatchStream::new_from_flight_data(response.into_inner().map_err(FlightError::from))
        .try_collect()
        .await
}

/// Collects every (quad, provenance) pair of `batches` as owned data.
fn collect_quads(batches: &[RecordBatch]) -> Vec<(Quad, SourceProvenance)> {
    let mut collected = Vec::new();
    for batch in batches {
        let reader = QuadStreamReader::new(batch).unwrap();
        for row in reader.iter() {
            let (quad, provenance) = row.unwrap();
            collected.push((
                quad.into_owned(),
                SourceProvenance {
                    source_artifact_iri: provenance.source_artifact_iri.map(str::to_owned),
                    source_content_sha256: provenance
                        .source_content_sha256
                        .map(|digest| <[u8; 32]>::try_from(digest).unwrap()),
                    source_offset_start: provenance.source_offset_start,
                    source_offset_end: provenance.source_offset_end,
                    observed_at_micros: provenance.observed_at_micros,
                },
            ));
        }
    }
    collected
}

/// Extracts the gRPC status of a failed unary or stream interaction.
fn status_of<T>(result: Result<T, tonic::Status>) -> tonic::Status {
    result.err().expect("expected an error status")
}

#[tokio::test]
async fn put_then_get_round_trips_a_multi_batch_dataset() {
    let (server, mut client) = start(None).await;

    let first = quads(0, 5);
    let second = quads(5, 3);
    let batches = vec![contract_batch(&first, 0), contract_batch(&second, 5)];
    let expected = collect_quads(&batches);

    let receipt = put_dataset(&mut client, "orders", batches).await.unwrap();
    assert_eq!(
        receipt,
        "{\"dataset\":\"orders\",\"batches\":2,\"quads\":8}"
    );

    let fetched = get_dataset(&mut client, "orders").await.unwrap();
    for batch in &fetched {
        assert_eq!(batch.schema().as_ref(), quad_stream_schema().as_ref());
    }
    assert_eq!(collect_quads(&fetched), expected);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_schema_matches_the_contract_schema() {
    let (server, mut client) = start(None).await;

    let descriptor = FlightDescriptor::new_path(vec!["datasets".to_owned(), "any".to_owned()]);
    let result = client.get_schema(descriptor).await.unwrap().into_inner();
    let schema = Schema::try_from(&result).unwrap();
    assert_eq!(&schema, quad_stream_schema().as_ref());
    assert_eq!(
        schema
            .metadata()
            .get("dataplane.assurance")
            .map(String::as_str),
        Some("unsigned")
    );

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn get_flight_info_reports_totals_and_a_fetchable_endpoint() {
    let (server, mut client) = start(None).await;
    let batch = contract_batch(&quads(0, 4), 0);
    put_dataset(&mut client, "info", vec![batch]).await.unwrap();

    let descriptor = FlightDescriptor::new_path(vec!["datasets".to_owned(), "info".to_owned()]);
    let info = client
        .get_flight_info(descriptor)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.total_records, 4);
    assert_eq!(info.endpoint.len(), 1);
    let ticket = info.endpoint[0].ticket.clone().expect("endpoint ticket");
    assert_eq!(ticket.ticket.as_ref(), b"info");

    let missing = FlightDescriptor::new_path(vec!["missing".to_owned()]);
    let status = status_of(client.get_flight_info(missing).await);
    assert_eq!(status.code(), tonic::Code::NotFound);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn list_flights_enumerates_datasets_in_name_order() {
    let (server, mut client) = start(None).await;
    put_dataset(&mut client, "zeta", vec![contract_batch(&quads(0, 1), 0)])
        .await
        .unwrap();
    put_dataset(&mut client, "alpha", vec![contract_batch(&quads(1, 2), 1)])
        .await
        .unwrap();

    let infos: Vec<_> = client
        .list_flights(Criteria::default())
        .await
        .unwrap()
        .into_inner()
        .try_collect()
        .await
        .unwrap();
    let names: Vec<Vec<String>> = infos
        .iter()
        .map(|info| info.flight_descriptor.clone().unwrap().path)
        .collect();
    assert_eq!(
        names,
        vec![
            vec!["datasets".to_owned(), "alpha".to_owned()],
            vec!["datasets".to_owned(), "zeta".to_owned()],
        ]
    );
    assert_eq!(infos[0].total_records, 2);
    assert_eq!(infos[1].total_records, 1);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn do_exchange_validates_and_echoes_contract_batches() {
    let (server, mut client) = start(None).await;

    let batches = vec![
        contract_batch(&quads(0, 3), 0),
        contract_batch(&quads(3, 2), 3),
    ];
    let expected = collect_quads(&batches);

    let response = client
        .do_exchange(put_stream("ignored", batches))
        .await
        .unwrap();
    let echoed: Vec<RecordBatch> = FlightRecordBatchStream::new_from_flight_data(
        response.into_inner().map_err(FlightError::from),
    )
    .try_collect()
    .await
    .unwrap();
    assert_eq!(collect_quads(&echoed), expected);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn do_put_rejects_a_foreign_schema_with_invalid_argument() {
    let (server, mut client) = start(None).await;

    let foreign = RecordBatch::try_from_iter([(
        "value",
        std::sync::Arc::new(Int64Array::from(vec![1_i64, 2, 3])) as arrow_array::ArrayRef,
    )])
    .unwrap();
    let descriptor = FlightDescriptor::new_path(vec!["foreign".to_owned()]);
    let outgoing = FlightDataEncoderBuilder::new()
        .with_flight_descriptor(Some(descriptor))
        .build(stream::iter([Ok(foreign)]))
        .map(|data| data.expect("encode flight data"));

    let status = match client.do_put(outgoing).await {
        Err(status) => status,
        Ok(response) => status_of(response.into_inner().message().await),
    };
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    // Nothing was stored for the failed put.
    let status = status_of(client.do_get(Ticket::new("foreign".to_owned())).await);
    assert_eq!(status.code(), tonic::Code::NotFound);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn do_exchange_rejects_a_foreign_schema_with_invalid_argument() {
    let (server, mut client) = start(None).await;

    let foreign = RecordBatch::try_from_iter([(
        "value",
        std::sync::Arc::new(Int64Array::from(vec![1_i64])) as arrow_array::ArrayRef,
    )])
    .unwrap();
    let outgoing = FlightDataEncoderBuilder::new()
        .build(stream::iter([Ok(foreign)]))
        .map(|data| data.expect("encode flight data"));

    let status = match client.do_exchange(outgoing).await {
        Err(status) => status,
        Ok(response) => {
            let collected: Result<Vec<_>, tonic::Status> =
                response.into_inner().try_collect().await;
            status_of(collected)
        }
    };
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn do_get_with_an_unknown_ticket_is_not_found() {
    let (server, mut client) = start(None).await;

    let status = status_of(client.do_get(Ticket::new("nope".to_owned())).await);
    assert_eq!(status.code(), tonic::Code::NotFound);

    let status = status_of(client.do_get(Ticket::new(vec![0xff_u8, 0xfe])).await);
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn dataset_limits_fail_closed_with_resource_exhausted() {
    let limits = DatasetLimits {
        max_datasets: 1,
        max_batches_per_dataset: 8,
        max_quads_per_dataset: 4,
    };
    let (server, mut client) = start(Some(limits)).await;

    // Quad budget: five quads exceed the four-quad dataset budget.
    let too_big = vec![contract_batch(&quads(0, 5), 0)];
    let status = match client.do_put(put_stream("big", too_big)).await {
        Err(status) => status,
        Ok(response) => status_of(response.into_inner().message().await),
    };
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);

    // Dataset budget: the second distinct name exceeds max_datasets.
    put_dataset(&mut client, "one", vec![contract_batch(&quads(0, 2), 0)])
        .await
        .unwrap();
    let status =
        status_of(put_dataset(&mut client, "two", vec![contract_batch(&quads(2, 2), 2)]).await);
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);

    // Replacing the existing dataset stays allowed at capacity.
    put_dataset(&mut client, "one", vec![contract_batch(&quads(4, 1), 4)])
        .await
        .unwrap();

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn drop_dataset_and_reset_actions_manage_the_store() {
    let (server, mut client) = start(None).await;
    put_dataset(&mut client, "keep", vec![contract_batch(&quads(0, 1), 0)])
        .await
        .unwrap();
    put_dataset(&mut client, "drop", vec![contract_batch(&quads(1, 1), 1)])
        .await
        .unwrap();

    let actions: Vec<_> = client
        .list_actions(arrow_flight::Empty {})
        .await
        .unwrap()
        .into_inner()
        .try_collect()
        .await
        .unwrap();
    let action_types: Vec<&str> = actions.iter().map(|a| a.r#type.as_str()).collect();
    assert!(action_types.contains(&"drop_dataset"));
    assert!(action_types.contains(&"reset"));

    let mut results = client
        .do_action(Action::new("drop_dataset", "drop".as_bytes().to_vec()))
        .await
        .unwrap()
        .into_inner();
    let body = results.message().await.unwrap().unwrap().body;
    assert_eq!(body.as_ref(), b"{\"dropped\":\"drop\"}");

    let status = status_of(client.do_get(Ticket::new("drop".to_owned())).await);
    assert_eq!(status.code(), tonic::Code::NotFound);

    let status = status_of(
        client
            .do_action(Action::new("drop_dataset", "drop".as_bytes().to_vec()))
            .await,
    );
    assert_eq!(status.code(), tonic::Code::NotFound);

    let mut results = client
        .do_action(Action::new("reset", Vec::new()))
        .await
        .unwrap()
        .into_inner();
    let body = results.message().await.unwrap().unwrap().body;
    assert_eq!(body.as_ref(), b"{\"reset\":1}");

    let status = status_of(client.do_get(Ticket::new("keep".to_owned())).await);
    assert_eq!(status.code(), tonic::Code::NotFound);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn handshake_and_unknown_actions_are_unimplemented() {
    let (server, mut client) = start(None).await;

    let status = status_of(
        client
            .handshake(stream::iter([arrow_flight::HandshakeRequest::default()]))
            .await,
    );
    assert_eq!(status.code(), tonic::Code::Unimplemented);

    let status = status_of(
        client
            .do_action(Action::new("mint_signature", Vec::new()))
            .await,
    );
    assert_eq!(status.code(), tonic::Code::Unimplemented);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn triple_term_batches_pass_through_unchanged() {
    // This transport is term-agnostic: an RDF 1.2 triple term rides the
    // contract's `object_kind = "triple"` rows, and DoPut/DoGet must return
    // it byte-identically rather than validating or rewriting a term.
    use oxrdf::Triple;

    let quad = Quad::new(
        NamedNode::new("http://example.com/alice").unwrap(),
        NamedNode::new("http://example.com/says").unwrap(),
        Term::Triple(Box::new(Triple::new(
            NamedNode::new("http://example.com/s").unwrap(),
            NamedNode::new("http://example.com/p").unwrap(),
            Term::Literal(Literal::new_simple_literal("o")),
        ))),
        GraphName::DefaultGraph,
    );
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    builder.push(quad.as_ref(), None).unwrap();
    let batch = builder.finish().unwrap();

    let (server, mut client) = start(None).await;
    put_dataset(&mut client, "starred", vec![batch.clone()])
        .await
        .expect("triple-term batches are accepted");
    let fetched = get_dataset(&mut client, "starred").await.expect("get");

    let reader = QuadStreamReader::new(&fetched[0]).unwrap();
    assert!(reader.contains_triple_terms());
    assert_eq!(reader.quad_owned(0, QuadLimits::default()).unwrap(), quad);
    // The borrowed path still refuses it, and the refusal names the feature.
    assert_eq!(reader.quad(0).unwrap_err().code(), "unsupported");
    server.shutdown().await.unwrap();
}
