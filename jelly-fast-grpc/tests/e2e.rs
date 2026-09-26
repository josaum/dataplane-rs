// Rust guideline compliant 2026-02-21
//! In-process end-to-end tests over a real localhost socket.

use std::sync::Arc;

use arrow_array::RecordBatch;
use jelly_fast_core::{
    JellyDecoderOptions, JellyEncoderOptions, PROTOCOL_VERSION,
    proto::{
        PhysicalStreamType, RdfStreamFrame, RdfStreamOptions,
        rdf_stream_service_client::RdfStreamServiceClient,
    },
};
use jelly_fast_grpc::{JellyClient, JellyGrpcError, JellyServer, TopicRegistry};
use oxrdf::{BlankNode, GraphName, Literal, NamedNode, Quad, vocab::xsd};
use quad_fast_core::{QuadBatchBuilder, QuadLimits, QuadStreamReader};

fn iri(value: &str) -> NamedNode {
    NamedNode::new(value).expect("valid test IRI")
}

fn batch_of(quads: &[Quad]) -> RecordBatch {
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    for quad in quads {
        builder.push(quad.as_ref(), None).expect("quad accepted");
    }
    builder.finish().expect("batch built")
}

fn quads_of(batch: &RecordBatch) -> Vec<Quad> {
    let reader = QuadStreamReader::new(batch).expect("contract-valid batch");
    (0..reader.len())
        .map(|row| reader.quad(row).expect("valid quad").into_owned())
        .collect()
}

fn corpus() -> Vec<Quad> {
    let alice = iri("http://example.com/people#alice");
    let knows = iri("http://xmlns.com/foaf/0.1/knows");
    let graph = GraphName::NamedNode(iri("http://example.com/graphs/g1"));
    vec![
        Quad::new(
            alice.clone(),
            knows.clone(),
            iri("http://example.com/people#bob"),
            GraphName::DefaultGraph,
        ),
        Quad::new(
            alice.clone(),
            iri("http://xmlns.com/foaf/0.1/name"),
            Literal::new_simple_literal("Alice"),
            GraphName::DefaultGraph,
        ),
        Quad::new(
            alice.clone(),
            iri("http://xmlns.com/foaf/0.1/age"),
            Literal::new_typed_literal("33", xsd::INTEGER),
            graph.clone(),
        ),
        Quad::new(
            BlankNode::new("b0").expect("valid bnode"),
            knows,
            alice,
            graph,
        ),
    ]
}

async fn start_server() -> (String, tokio::task::JoinHandle<()>) {
    let server = JellyServer::bind(
        "127.0.0.1:0".parse().expect("valid address"),
        Arc::new(TopicRegistry::default()),
    )
    .await
    .expect("server bound");
    let endpoint = format!("http://{}", server.local_addr());
    let handle = tokio::spawn(async move {
        server.serve().await.expect("server ran");
    });
    (endpoint, handle)
}

#[tokio::test]
async fn publish_subscribe_round_trips_quad_batches() {
    let (endpoint, server) = start_server().await;
    let quads = corpus();
    let (first, second) = quads.split_at(2);
    let batches = vec![batch_of(first), batch_of(second)];
    let expected: Vec<Quad> = batches.iter().flat_map(quads_of).collect();

    let mut subscriber = JellyClient::connect(endpoint.clone())
        .await
        .expect("subscriber connected");
    // Subscribe before publishing: relay is live, frames published earlier
    // are not retained.
    let mut subscription = subscriber
        .subscribe("quads/e2e", None, JellyDecoderOptions::default())
        .await
        .expect("subscribed");

    let mut publisher = JellyClient::connect(endpoint)
        .await
        .expect("publisher connected");
    publisher
        .publish_batches(
            "quads/e2e",
            &batches,
            JellyEncoderOptions {
                // Small frames so the round trip crosses frame boundaries.
                quads_per_frame: 2,
                ..JellyEncoderOptions::default()
            },
        )
        .await
        .expect("published");

    let mut received = Vec::new();
    while received.len() < expected.len() {
        let batch = subscription
            .next_batch()
            .await
            .expect("frame decoded")
            .expect("stream still open");
        received.extend(quads_of(&batch));
    }
    assert_eq!(received, expected);
    server.abort();
}

#[tokio::test]
async fn incompatible_requested_options_yield_invalid_argument() {
    let (endpoint, server) = start_server().await;
    let mut publisher = JellyClient::connect(endpoint.clone())
        .await
        .expect("publisher connected");
    publisher
        .publish_batches(
            "quads/options",
            &[batch_of(&corpus())],
            JellyEncoderOptions::default(),
        )
        .await
        .expect("published");

    let mut subscriber = JellyClient::connect(endpoint)
        .await
        .expect("subscriber connected");
    // Request protocol version 1 while the topic publishes version 2.
    let requested = RdfStreamOptions {
        stream_name: String::new(),
        physical_type: PhysicalStreamType::Quads.into(),
        generalized_statements: false,
        rdf_star: false,
        max_name_table_size: 0,
        max_prefix_table_size: 0,
        max_datatype_table_size: 0,
        logical_type: 0,
        version: PROTOCOL_VERSION - 1,
    };
    let error = subscriber
        .subscribe(
            "quads/options",
            Some(requested),
            JellyDecoderOptions::default(),
        )
        .await
        .expect_err("incompatible request refused");
    match error {
        JellyGrpcError::Status(status) => {
            assert_eq!(status.code(), tonic::Code::InvalidArgument);
        }
        other => panic!("expected a status error, got {other:?}"),
    }
    server.abort();
}

#[tokio::test]
async fn publish_without_leading_options_is_rejected() {
    let (endpoint, server) = start_server().await;
    let mut raw = RdfStreamServiceClient::connect(endpoint)
        .await
        .expect("raw client connected");
    let frame = RdfStreamFrame {
        rows: Vec::new(),
        metadata: std::collections::HashMap::new(),
    };
    let status = raw
        .publish_rdf(tokio_stream::iter(vec![frame]))
        .await
        .expect_err("options-less publish refused");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    server.abort();
}

#[tokio::test]
async fn publish_subscribe_round_trips_rdf12_triple_terms() {
    // The pub/sub layer passes codec options through, so RDF-star crosses
    // the wire whenever the publisher opts in; nothing in this crate needs
    // its own triple-term handling.
    use oxrdf::{Term, Triple};

    let quads = vec![Quad::new(
        iri("http://example.com/people#alice"),
        iri("http://example.com/says"),
        Term::Triple(Box::new(Triple::new(
            iri("http://example.com/people#bob"),
            iri("http://xmlns.com/foaf/0.1/name"),
            Literal::new_simple_literal("Bob"),
        ))),
        GraphName::DefaultGraph,
    )];
    let batch = batch_of(&quads);

    let (endpoint, server) = start_server().await;
    let mut subscriber = JellyClient::connect(endpoint.clone())
        .await
        .expect("subscriber connected");
    let mut subscription = subscriber
        .subscribe("quads/star", None, JellyDecoderOptions::default())
        .await
        .expect("subscribed");

    let mut publisher = JellyClient::connect(endpoint)
        .await
        .expect("publisher connected");
    publisher
        .publish_batches(
            "quads/star",
            &[batch],
            JellyEncoderOptions {
                rdf_star: true,
                ..JellyEncoderOptions::default()
            },
        )
        .await
        .expect("published");

    let received = subscription
        .next_batch()
        .await
        .expect("frame decoded")
        .expect("stream still open");
    let reader = QuadStreamReader::new(&received).expect("contract-valid batch");
    assert!(reader.contains_triple_terms());
    assert_eq!(
        reader
            .quad_owned(0, QuadLimits::default())
            .expect("valid quad"),
        quads[0]
    );
    server.abort();
}
