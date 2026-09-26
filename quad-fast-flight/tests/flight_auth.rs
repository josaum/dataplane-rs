// Rust guideline compliant 2026-02-21
//! End-to-end tests of the `auth` feature over a localhost socket.
#![cfg(feature = "auth")]

use std::time::{SystemTime, UNIX_EPOCH};

use arrow_flight::{Criteria, flight_service_client::FlightServiceClient};
use flight_auth::{AuthConfig, FlightRequestAuthVerifier, mint_local_workload_authorization};
use futures::TryStreamExt;
use quad_fast_flight::{DatasetLimits, serve_with_verifier};

/// Secret used only by this test; long enough for the HS256 minting policy.
const TEST_SECRET: &str = "quad-fast-flight-test-secret-0123456789abcdef";

fn verifier() -> FlightRequestAuthVerifier {
    FlightRequestAuthVerifier::new(AuthConfig {
        require_auth: true,
        issuer: Some("atlas".to_owned()),
        audience: Some("atlas".to_owned()),
        es256_public_key_pem: None,
        legacy_hs256_secret: Some(TEST_SECRET.to_owned()),
        allow_legacy_hs256: true,
    })
    .unwrap()
}

#[tokio::test]
async fn requests_are_gated_by_the_jwt_metadata_verifier() {
    let addr = "127.0.0.1:0".parse().unwrap();
    let server = serve_with_verifier(addr, DatasetLimits::default(), verifier())
        .await
        .unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = FlightServiceClient::new(channel);

    // Without authorization metadata every RPC fails closed.
    let status = client
        .list_flights(Criteria::default())
        .await
        .expect_err("unauthenticated request must fail");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);

    // With a minted tenant-scoped workload token the RPC succeeds.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (authorization, _expires_at) =
        mint_local_workload_authorization(TEST_SECRET, "tenant-a", "quad-flight-test", now)
            .unwrap();
    let infos: Vec<_> = client
        .list_flights(authorization.request(Criteria::default()))
        .await
        .unwrap()
        .into_inner()
        .try_collect()
        .await
        .unwrap();
    assert!(infos.is_empty());

    server.shutdown().await.unwrap();
}
