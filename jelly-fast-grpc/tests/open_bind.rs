// Rust guideline compliant 2026-02-21
//! Unauthenticated servers stay on the loopback interface.

use std::sync::Arc;

use jelly_fast_grpc::{JellyPatchServer, JellyServer, PatchTopicRegistry, TopicRegistry};

#[tokio::test]
async fn unauthenticated_servers_refuse_a_non_loopback_address() {
    let wildcard = "0.0.0.0:0".parse().expect("valid address");
    assert!(
        JellyServer::bind(wildcard, Arc::new(TopicRegistry::default()))
            .await
            .is_err(),
        "JellyServer bound a non-loopback address without authentication"
    );
    assert!(
        JellyPatchServer::bind(wildcard, Arc::new(PatchTopicRegistry::default()))
            .await
            .is_err(),
        "JellyPatchServer bound a non-loopback address without authentication"
    );
    let loopback = "127.0.0.1:0".parse().expect("valid address");
    assert!(
        JellyServer::bind(loopback, Arc::new(TopicRegistry::default()))
            .await
            .is_ok()
    );
}
