// Rust guideline compliant 2026-02-21
//! End-to-end tests of authentication over a localhost socket.

use std::time::{SystemTime, UNIX_EPOCH};

use arrow_flight::{
    Action, Criteria, Empty, FlightData, FlightDescriptor, HandshakeRequest, Ticket,
    flight_service_client::FlightServiceClient,
};
use flight_auth::{AuthConfig, FlightRequestAuthVerifier, mint_local_workload_authorization};
use futures::{TryStreamExt, stream};
use quad_fast_flight::{DatasetLimits, serve, serve_with_limits, serve_with_verifier};
use tonic::{Code, transport::Channel};

/// Secret used only by this test; long enough for the HS256 minting policy.
const TEST_SECRET: &str = "quad-fast-flight-test-secret-0123456789abcdef";

fn verifier() -> FlightRequestAuthVerifier {
    FlightRequestAuthVerifier::new(AuthConfig {
        require_auth: true,
        issuer: Some("dataplane".to_owned()),
        audience: Some("dataplane".to_owned()),
        es256_public_key_pem: None,
        legacy_hs256_secret: Some(TEST_SECRET.to_owned()),
        allow_legacy_hs256: true,
    })
    .unwrap()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Renders a minted authorization as its raw header value.
fn header_for(now: u64) -> String {
    let (authorization, _expires_at) =
        mint_local_workload_authorization(TEST_SECRET, "tenant-a", "quad-flight-test", now)
            .unwrap();
    let request = authorization.request(());
    request
        .metadata()
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

async fn connect(addr: std::net::SocketAddr) -> FlightServiceClient<Channel> {
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    FlightServiceClient::new(channel)
}

fn with_header<T>(payload: T, header: Option<&str>) -> tonic::Request<T> {
    let mut request = tonic::Request::new(payload);
    if let Some(header) = header {
        drop(
            request
                .metadata_mut()
                .insert("authorization", header.parse().unwrap()),
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

/// Calls every Flight RPC once and returns the status code of each.
async fn every_rpc(
    client: &mut FlightServiceClient<Channel>,
    header: Option<&str>,
) -> Vec<(&'static str, Code)> {
    let descriptor = FlightDescriptor::new_path(vec!["datasets".to_owned(), "d".to_owned()]);
    vec![
        (
            "Handshake",
            code_of(
                client
                    .handshake(with_header(
                        stream::iter(vec![HandshakeRequest::default()]),
                        header,
                    ))
                    .await,
            ),
        ),
        (
            "ListFlights",
            code_of(
                client
                    .list_flights(with_header(Criteria::default(), header))
                    .await,
            ),
        ),
        (
            "GetFlightInfo",
            code_of(
                client
                    .get_flight_info(with_header(descriptor.clone(), header))
                    .await,
            ),
        ),
        (
            "PollFlightInfo",
            code_of(
                client
                    .poll_flight_info(with_header(descriptor.clone(), header))
                    .await,
            ),
        ),
        (
            "GetSchema",
            code_of(
                client
                    .get_schema(with_header(descriptor.clone(), header))
                    .await,
            ),
        ),
        (
            "DoGet",
            code_of(
                client
                    .do_get(with_header(Ticket::new("d".to_owned()), header))
                    .await,
            ),
        ),
        (
            "DoPut",
            code_of(
                client
                    .do_put(with_header(
                        stream::iter(vec![FlightData::new().with_descriptor(descriptor.clone())]),
                        header,
                    ))
                    .await,
            ),
        ),
        (
            "DoExchange",
            code_of(
                client
                    .do_exchange(with_header(stream::iter(Vec::<FlightData>::new()), header))
                    .await,
            ),
        ),
        (
            "DoAction",
            code_of(
                client
                    .do_action(with_header(Action::new("reset", ""), header))
                    .await,
            ),
        ),
        (
            "ListActions",
            code_of(client.list_actions(with_header(Empty {}, header)).await),
        ),
    ]
}

#[tokio::test]
async fn every_rpc_refuses_missing_garbage_and_expired_bearers() {
    let addr = "127.0.0.1:0".parse().unwrap();
    let server = serve_with_verifier(addr, DatasetLimits::default(), verifier())
        .await
        .unwrap();
    let mut client = connect(server.local_addr()).await;

    let expired = header_for(unix_now() - 3_600);
    let cases: [(&str, Option<&str>); 5] = [
        ("no bearer", None),
        ("garbage bearer", Some("Bearer not-a-jwt")),
        ("expired bearer", Some(expired.as_str())),
        ("wrong scheme", Some("Basic dXNlcjpwYXNz")),
        ("empty bearer", Some("Bearer ")),
    ];
    for (label, header) in cases {
        for (rpc, code) in every_rpc(&mut client, header).await {
            eprintln!("auth-table verified {label:>15} {rpc:<15} {code:?}");
            assert_eq!(code, Code::Unauthenticated, "{rpc} with {label}");
        }
    }

    let valid = header_for(unix_now());
    for (rpc, code) in every_rpc(&mut client, Some(valid.as_str())).await {
        eprintln!(
            "auth-table verified {:>15} {rpc:<15} {code:?}",
            "valid bearer"
        );
        assert_ne!(code, Code::Unauthenticated, "{rpc} with a valid bearer");
    }

    // A streamed response still requires the bearer that opened it.
    let infos: Vec<_> = client
        .list_flights(with_header(Criteria::default(), Some(valid.as_str())))
        .await
        .unwrap()
        .into_inner()
        .try_collect()
        .await
        .unwrap();
    assert!(infos.is_empty());

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn verified_entry_point_refuses_a_disabled_verifier() {
    let addr = "127.0.0.1:0".parse().unwrap();
    let disabled = FlightRequestAuthVerifier::new(AuthConfig::disabled()).unwrap();
    let outcome = serve_with_verifier(addr, DatasetLimits::default(), disabled).await;
    if let Ok(server) = outcome {
        let mut client = connect(server.local_addr()).await;
        for (rpc, code) in every_rpc(&mut client, None).await {
            eprintln!("auth-table disabled-verifier no bearer {rpc:<15} {code:?}");
        }
        server.shutdown().await.unwrap();
        panic!("serve_with_verifier started with authentication disabled");
    }
}

#[tokio::test]
async fn verified_entry_point_refuses_an_unscoped_verifier() {
    let addr = "127.0.0.1:0".parse().unwrap();
    let unscoped = FlightRequestAuthVerifier::new(AuthConfig {
        issuer: None,
        audience: None,
        ..verifier_config()
    })
    .unwrap();
    let outcome = serve_with_verifier(addr, DatasetLimits::default(), unscoped).await;
    if let Ok(server) = outcome {
        server.shutdown().await.unwrap();
        panic!("serve_with_verifier started without issuer and audience checks");
    }
}

fn verifier_config() -> AuthConfig {
    AuthConfig {
        require_auth: true,
        issuer: Some("dataplane".to_owned()),
        audience: Some("dataplane".to_owned()),
        es256_public_key_pem: None,
        legacy_hs256_secret: Some(TEST_SECRET.to_owned()),
        allow_legacy_hs256: true,
    }
}

#[tokio::test]
async fn unauthenticated_entry_points_refuse_a_non_loopback_address() {
    let wildcard = "0.0.0.0:0".parse().unwrap();
    if let Ok(server) = serve(wildcard).await {
        let mut client = connect(([127, 0, 0, 1], server.local_addr().port()).into()).await;
        for (rpc, code) in every_rpc(&mut client, None).await {
            eprintln!("auth-table open-serve no bearer {rpc:<15} {code:?}");
        }
        server.shutdown().await.unwrap();
        panic!("serve bound a non-loopback address without authentication");
    }
    if let Ok(server) = serve_with_limits(wildcard, DatasetLimits::default()).await {
        server.shutdown().await.unwrap();
        panic!("serve_with_limits bound a non-loopback address without authentication");
    }
}
