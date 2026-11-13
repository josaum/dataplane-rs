// Rust guideline compliant 2026-02-21
//! Every Jelly RPC is gated by the shared JWT verifier on a real socket.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use flight_auth::{AuthConfig, FlightRequestAuthVerifier, mint_local_workload_authorization};
use jelly_fast_core::proto::{
    RdfStreamFrame, RdfStreamOptions, RdfStreamRow, RdfStreamSubscribe,
    patch::{
        RdfPatchFrame, RdfPatchOptions, RdfPatchRow,
        grpc::{
            PatchPublish, PatchSubscribe, patch_stream_service_client::PatchStreamServiceClient,
        },
        rdf_patch_row,
    },
    rdf_stream_row,
    rdf_stream_service_client::RdfStreamServiceClient,
};
use jelly_fast_grpc::{
    JellyClient, JellyPatchServer, JellyServer, PatchTopicRegistry, TopicRegistry,
};
use tonic::{Code, Request};

const TEST_SECRET: &str = "jelly-fast-grpc-test-secret-0123456789abcdef";

fn config() -> AuthConfig {
    AuthConfig {
        require_auth: true,
        issuer: Some("dataplane".to_owned()),
        audience: Some("dataplane".to_owned()),
        es256_public_key_pem: None,
        legacy_hs256_secret: Some(TEST_SECRET.to_owned()),
        allow_legacy_hs256: true,
    }
}

fn verifier() -> FlightRequestAuthVerifier {
    FlightRequestAuthVerifier::new(config()).expect("valid verifier")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn header_for(now: u64) -> String {
    let (authorization, _) =
        mint_local_workload_authorization(TEST_SECRET, "tenant-a", "jelly-test", now)
            .expect("mint");
    authorization
        .request(())
        .metadata()
        .get("authorization")
        .expect("header")
        .to_str()
        .expect("ascii")
        .to_owned()
}

fn with_header<T>(payload: T, header: Option<&str>) -> Request<T> {
    let mut request = Request::new(payload);
    if let Some(header) = header {
        drop(
            request
                .metadata_mut()
                .insert("authorization", header.parse().expect("header value")),
        );
    }
    request
}

fn code_of<T>(result: Result<T, tonic::Status>) -> Code {
    match result {
        Ok(_) => Code::Ok,
        Err(status) => status.code(),
    }
}

fn rdf_frame() -> RdfStreamFrame {
    RdfStreamFrame {
        rows: vec![RdfStreamRow {
            row: Some(rdf_stream_row::Row::Options(RdfStreamOptions {
                stream_name: "t".to_owned(),
                ..RdfStreamOptions::default()
            })),
        }],
        ..RdfStreamFrame::default()
    }
}

fn patch_publish() -> PatchPublish {
    PatchPublish {
        topic: "t".to_owned(),
        frame: Some(RdfPatchFrame {
            rows: vec![RdfPatchRow {
                row: Some(rdf_patch_row::Row::Options(RdfPatchOptions::default())),
            }],
        }),
    }
}

async fn every_rpc(
    rdf: SocketAddr,
    patch: SocketAddr,
    header: Option<&str>,
) -> Vec<(&'static str, Code)> {
    let mut rdf_client = RdfStreamServiceClient::connect(format!("http://{rdf}"))
        .await
        .expect("connect");
    let mut patch_client = PatchStreamServiceClient::connect(format!("http://{patch}"))
        .await
        .expect("connect");
    vec![
        (
            "SubscribeRdf",
            code_of(
                rdf_client
                    .subscribe_rdf(with_header(
                        RdfStreamSubscribe {
                            topic: "t".to_owned(),
                            requested_options: None,
                        },
                        header,
                    ))
                    .await,
            ),
        ),
        (
            "PublishRdf",
            code_of(
                rdf_client
                    .publish_rdf(with_header(tokio_stream::iter(vec![rdf_frame()]), header))
                    .await,
            ),
        ),
        (
            "SubscribePatches",
            code_of(
                patch_client
                    .subscribe_patches(with_header(
                        PatchSubscribe {
                            topic: "t".to_owned(),
                            requested_options: None,
                        },
                        header,
                    ))
                    .await,
            ),
        ),
        (
            "PublishPatches",
            code_of(
                patch_client
                    .publish_patches(with_header(
                        tokio_stream::iter(vec![patch_publish()]),
                        header,
                    ))
                    .await,
            ),
        ),
    ]
}

#[tokio::test]
async fn every_rpc_refuses_missing_garbage_and_expired_bearers() {
    let loopback = "127.0.0.1:0".parse().expect("addr");
    let rdf =
        JellyServer::bind_with_verifier(loopback, Arc::new(TopicRegistry::default()), verifier())
            .await
            .expect("bind");
    let patch = JellyPatchServer::bind_with_verifier(
        loopback,
        Arc::new(PatchTopicRegistry::default()),
        verifier(),
    )
    .await
    .expect("bind");
    let (rdf_addr, patch_addr) = (rdf.local_addr(), patch.local_addr());
    let rdf_task = tokio::spawn(rdf.serve());
    let patch_task = tokio::spawn(patch.serve());

    let expired = header_for(unix_now() - 3_600);
    let cases: [(&str, Option<&str>); 4] = [
        ("no bearer", None),
        ("garbage bearer", Some("Bearer not-a-jwt")),
        ("expired bearer", Some(expired.as_str())),
        ("wrong scheme", Some("Basic dXNlcjpwYXNz")),
    ];
    for (label, header) in cases {
        for (rpc, code) in every_rpc(rdf_addr, patch_addr, header).await {
            eprintln!("auth-table jelly {label:>15} {rpc:<17} {code:?}");
            assert_eq!(code, Code::Unauthenticated, "{rpc} with {label}");
        }
    }
    let valid = header_for(unix_now());
    for (rpc, code) in every_rpc(rdf_addr, patch_addr, Some(valid.as_str())).await {
        eprintln!("auth-table jelly {:>15} {rpc:<17} {code:?}", "valid bearer");
        assert_eq!(code, Code::Ok, "{rpc} with a valid bearer");
    }

    // The typed client carries its authorization on every call.
    let (authorization, _) =
        mint_local_workload_authorization(TEST_SECRET, "tenant-a", "jelly-test", unix_now())
            .expect("mint");
    let mut client =
        JellyClient::connect_with_authorization(format!("http://{rdf_addr}"), authorization)
            .await
            .expect("connect");
    assert!(
        client
            .subscribe("t", None, Default::default())
            .await
            .is_ok()
    );
    let mut anonymous = JellyClient::connect(format!("http://{rdf_addr}"))
        .await
        .expect("connect");
    assert!(
        anonymous
            .subscribe("t", None, Default::default())
            .await
            .is_err()
    );

    rdf_task.abort();
    patch_task.abort();
}

#[tokio::test]
async fn verified_bind_refuses_a_disabled_or_unscoped_verifier() {
    let loopback = "127.0.0.1:0".parse().expect("addr");
    let disabled = FlightRequestAuthVerifier::new(AuthConfig::disabled()).expect("verifier");
    assert!(
        JellyServer::bind_with_verifier(loopback, Arc::new(TopicRegistry::default()), disabled)
            .await
            .is_err()
    );
    let unscoped = FlightRequestAuthVerifier::new(AuthConfig {
        issuer: None,
        audience: None,
        ..config()
    })
    .expect("verifier");
    assert!(
        JellyPatchServer::bind_with_verifier(
            loopback,
            Arc::new(PatchTopicRegistry::default()),
            unscoped
        )
        .await
        .is_err()
    );
}
