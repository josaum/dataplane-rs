// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! In-process patch pub/sub end-to-end tests over a real localhost socket.

use std::sync::Arc;

use arrow_array::RecordBatch;
use jelly_fast_core::{
    JellyPatchDecoderOptions, JellyPatchEncoderOptions, PATCH_PROTOCOL_VERSION, PatchOp,
    proto::patch::{
        PatchStatementType, PatchStreamType, RdfPatchFrame, RdfPatchOptions,
        atlas::{PatchPublish, patch_stream_service_client::PatchStreamServiceClient},
    },
};
use jelly_fast_grpc::{JellyGrpcError, JellyPatchClient, JellyPatchServer, PatchTopicRegistry};
use oxrdf::{BlankNode, GraphName, Literal, NamedNode, Quad, Term, vocab::xsd};
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

/// One patch operation flattened to per-quad granularity for comparison
/// (decode regroups consecutive same-kind rows, so batch boundaries are
/// not preserved).
#[derive(Clone, Debug, PartialEq)]
enum FlatOp {
    Add(Quad),
    Delete(Quad),
    TransactionStart,
    TransactionCommit,
    TransactionAbort,
    Header(String, Term),
}

fn flatten(ops: &[PatchOp]) -> Vec<FlatOp> {
    let mut flat = Vec::new();
    for op in ops {
        match op {
            PatchOp::Add(batch) => flat.extend(quads_of(batch).into_iter().map(FlatOp::Add)),
            PatchOp::Delete(batch) => {
                flat.extend(quads_of(batch).into_iter().map(FlatOp::Delete));
            }
            PatchOp::TransactionStart => flat.push(FlatOp::TransactionStart),
            PatchOp::TransactionCommit => flat.push(FlatOp::TransactionCommit),
            PatchOp::TransactionAbort => flat.push(FlatOp::TransactionAbort),
            PatchOp::Header { key, value } => {
                flat.push(FlatOp::Header(key.clone(), value.clone()));
            }
        }
    }
    flat
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

fn patch_ops() -> Vec<PatchOp> {
    let quads = corpus();
    vec![
        PatchOp::Header {
            key: "id".into(),
            value: Term::NamedNode(iri("http://example.com/patch/1")),
        },
        PatchOp::TransactionStart,
        PatchOp::Add(batch_of(&quads[..2])),
        PatchOp::Delete(batch_of(&quads[2..3])),
        PatchOp::TransactionCommit,
        PatchOp::Add(batch_of(&quads[3..])),
    ]
}

async fn start_server() -> (String, tokio::task::JoinHandle<()>) {
    let server = JellyPatchServer::bind(
        "127.0.0.1:0".parse().expect("valid address"),
        Arc::new(PatchTopicRegistry::default()),
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
async fn publish_subscribe_round_trips_patch_ops() {
    let (endpoint, server) = start_server().await;
    let ops = patch_ops();
    let expected = flatten(&ops);

    let mut subscriber = JellyPatchClient::connect(endpoint.clone())
        .await
        .expect("subscriber connected");
    // Subscribe before publishing: relay is live, frames published earlier
    // are not retained.
    let mut subscription = subscriber
        .subscribe("patches/e2e", None, JellyPatchDecoderOptions::default())
        .await
        .expect("subscribed");

    let mut publisher = JellyPatchClient::connect(endpoint)
        .await
        .expect("publisher connected");
    publisher
        .publish_ops(
            "patches/e2e",
            &ops,
            JellyPatchEncoderOptions {
                // Small frames so the round trip crosses frame boundaries.
                rows_per_frame: 2,
                ..JellyPatchEncoderOptions::default()
            },
        )
        .await
        .expect("published");

    let mut received = Vec::new();
    while received.len() < expected.len() {
        let ops = subscription
            .next_ops()
            .await
            .expect("frame decoded")
            .expect("stream still open");
        received.extend(flatten(&ops));
    }
    assert_eq!(received, expected);
    server.abort();
}

#[tokio::test]
async fn incompatible_requested_options_yield_invalid_argument() {
    let (endpoint, server) = start_server().await;
    let mut publisher = JellyPatchClient::connect(endpoint.clone())
        .await
        .expect("publisher connected");
    publisher
        .publish_ops(
            "patches/options",
            &patch_ops(),
            JellyPatchEncoderOptions::default(),
        )
        .await
        .expect("published");

    let mut subscriber = JellyPatchClient::connect(endpoint)
        .await
        .expect("subscriber connected");
    // Request TRIPLES while the topic publishes QUADS.
    let requested = RdfPatchOptions {
        statement_type: PatchStatementType::Triples.into(),
        stream_type: PatchStreamType::Flat.into(),
        generalized_statements: false,
        rdf_star: false,
        max_name_table_size: 0,
        max_prefix_table_size: 0,
        max_datatype_table_size: 0,
        version: PATCH_PROTOCOL_VERSION,
    };
    let error = subscriber
        .subscribe(
            "patches/options",
            Some(requested),
            JellyPatchDecoderOptions::default(),
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
async fn client_refuses_open_transaction_and_empty_topic() {
    let (endpoint, server) = start_server().await;
    let mut publisher = JellyPatchClient::connect(endpoint)
        .await
        .expect("publisher connected");

    // A publish that would end mid-transaction never leaves the client.
    let error = publisher
        .publish_ops(
            "patches/torn",
            &[PatchOp::TransactionStart],
            JellyPatchEncoderOptions::default(),
        )
        .await
        .expect_err("torn patch refused");
    assert_eq!(error.code(), "codec");

    let error = publisher
        .publish_ops("", &[], JellyPatchEncoderOptions::default())
        .await
        .expect_err("empty topic refused");
    assert_eq!(error.code(), "publish");
    server.abort();
}

#[tokio::test]
async fn publish_without_leading_options_is_rejected() {
    let (endpoint, server) = start_server().await;
    let mut raw = PatchStreamServiceClient::connect(endpoint)
        .await
        .expect("raw client connected");
    let message = PatchPublish {
        topic: "patches/raw".into(),
        frame: Some(RdfPatchFrame { rows: Vec::new() }),
    };
    let status = raw
        .publish_patches(tokio_stream::iter(vec![message]))
        .await
        .expect_err("options-less publish refused");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    server.abort();
}

#[tokio::test]
async fn publish_envelope_violations_are_rejected() {
    let (endpoint, server) = start_server().await;

    // First message without a topic.
    let mut raw = PatchStreamServiceClient::connect(endpoint.clone())
        .await
        .expect("raw client connected");
    let message = PatchPublish {
        topic: String::new(),
        frame: Some(RdfPatchFrame { rows: Vec::new() }),
    };
    let status = raw
        .publish_patches(tokio_stream::iter(vec![message]))
        .await
        .expect_err("topicless publish refused");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    // Frameless message.
    let mut raw = PatchStreamServiceClient::connect(endpoint.clone())
        .await
        .expect("raw client connected");
    let message = PatchPublish {
        topic: "patches/raw".into(),
        frame: None,
    };
    let status = raw
        .publish_patches(tokio_stream::iter(vec![message]))
        .await
        .expect_err("frameless publish refused");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    // Topic switch mid-stream (encode a real patch so the first message
    // passes the leading-options check).
    let mut encoder = jelly_fast_core::JellyPatchEncoder::new(JellyPatchEncoderOptions::default())
        .expect("valid options");
    let frames = encoder.encode_ops(&[]).expect("encoded");
    let mut raw = PatchStreamServiceClient::connect(endpoint)
        .await
        .expect("raw client connected");
    let messages = vec![
        PatchPublish {
            topic: "patches/a".into(),
            frame: Some(frames[0].clone()),
        },
        PatchPublish {
            topic: "patches/b".into(),
            frame: Some(RdfPatchFrame { rows: Vec::new() }),
        },
    ];
    let status = raw
        .publish_patches(tokio_stream::iter(messages))
        .await
        .expect_err("topic switch refused");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    server.abort();
}
