// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use base64::Engine as _;
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use registry_platform_httputil::client::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider as _};
use registry_platform_testing::{
    ExchangeProfile, TestActorKind, TestAuthorizationServer, TestClient,
};
use serde_json::Value;
use url::Url;

use crate::{
    AuthorizationError, AuthorizationFactory as _, Delegation, DelegationOptions, VerifiedCaller,
};

const AUDIENCE: &str = "urn:breg:citizen-address-correction";
const RESOURCE: &str = "https://gateway.example.test/mcp";
const GATEWAY: &str = "citizen-gateway";
const ACTOR: &str = "6f1c2d8e-3b4a-4e59-9c7d-2a8b5e0f1d34";
const SCOPE: &str = "address-correction:self";

struct Fixture {
    server: TestAuthorizationServer,
    delegation: Delegation,
    other_key: registry_platform_crypto::PrivateJwk,
}

async fn fixture() -> Fixture {
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("key");
    let other_key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("key");
    let server = TestAuthorizationServer::builder()
        .client(
            TestClient::new(GATEWAY)
                .with_public_jwk(key.public())
                .with_resource(AUDIENCE)
                .with_resource(RESOURCE)
                .with_actor_kind(TestActorKind::Agent)
                .with_service_subject(ACTOR),
        )
        .client(
            TestClient::new("another-service")
                .with_public_jwk(other_key.public())
                .with_resource(AUDIENCE),
        )
        .client(TestClient::new("chat-host").with_resource(RESOURCE))
        .exchange_profile(ExchangeProfile::Conformant)
        .start()
        .await;
    let delegation = Delegation::new(DelegationOptions {
        token_endpoint: Url::parse(&server.token_endpoint()).expect("token endpoint"),
        client_id: GATEWAY.to_owned(),
        private_key: key.clone(),
        assertion_audience: None,
        gateway_resource: RESOURCE.to_owned(),
        downstream_resource: AUDIENCE.to_owned(),
        downstream_scopes: vec![SCOPE.to_owned()],
        attempt_timeout: Duration::from_secs(10),
        generation: "breg-mcp-v1".to_owned(),
    })
    .expect("delegation");
    Fixture {
        server,
        delegation,
        other_key,
    }
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("time")
}

fn caller(fixture: &Fixture, expires_at: i64) -> VerifiedCaller {
    let token =
        fixture
            .server
            .issue_access_token("chat-host", "citizen-a", RESOURCE, SCOPE, expires_at);
    VerifiedCaller::for_test_internal(
        &fixture.server.issuer(),
        "citizen-a",
        "chat-host",
        &token,
        expires_at,
        "principal",
        "client",
    )
}

fn claims(header: &str) -> Value {
    let token = header.strip_prefix("Bearer ").expect("bearer");
    let payload = token.split('.').nth(1).expect("payload");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64"),
    )
    .expect("claims")
}

#[allow(clippy::disallowed_methods)]
fn header(token: &registry_platform_httputil::client::BearerToken) -> String {
    token
        .authorization_header_value()
        .to_str()
        .expect("header")
        .to_owned()
}

#[tokio::test]
async fn the_exchanged_token_names_the_citizen_and_the_gateway_as_actor() {
    let fixture = fixture().await;
    let caller = caller(&fixture, now() + 300);
    let authorization = fixture
        .delegation
        .authorization(&caller)
        .expect("authorization");
    let header = header(&authorization.bearer_token().await.expect("exchange"));
    assert_ne!(header, format!("Bearer {}", caller.token()));
    let value = claims(&header);
    assert_eq!(value["sub"], "citizen-a");
    assert_eq!(value["aud"], AUDIENCE);
    assert_eq!(value["act"]["sub"], ACTOR);
    assert_eq!(value["registry_actor_kind"], "agent");
}

#[tokio::test]
async fn the_actor_token_is_requested_for_the_gateway_not_the_registry() {
    let fixture = fixture().await;
    let actor = fixture
        .delegation
        .actor_for_test()
        .bearer_token()
        .await
        .expect("actor token");
    let value = claims(&header(&actor));
    assert_eq!(value["sub"], ACTOR);
    assert_eq!(value["aud"], RESOURCE);
    assert_ne!(value["aud"], AUDIENCE);
}

#[tokio::test]
async fn the_exchange_sends_the_citizens_token_and_accepts_the_issued_token() {
    let fixture = fixture().await;
    let expires_at = now() + 30;
    let authorization = fixture
        .delegation
        .authorization(&caller(&fixture, expires_at))
        .expect("authorization");
    let value = claims(&header(
        &authorization.bearer_token().await.expect("exchange"),
    ));
    assert!(value["exp"].as_i64().expect("expiry") <= expires_at);
}

#[tokio::test]
async fn an_expired_citizen_token_is_refused_before_any_exchange() {
    let fixture = fixture().await;
    assert!(matches!(
        fixture
            .delegation
            .authorization(&caller(&fixture, now() - 1)),
        Err(AuthorizationError::Unavailable)
    ));
}

#[tokio::test]
async fn an_actor_that_is_not_the_gateway_is_refused() {
    let fixture = fixture().await;
    let foreign = PrivateKeyJwt::new(PrivateKeyJwtConfig::new(
        Url::parse(&fixture.server.token_endpoint()).expect("URL"),
        "another-service",
        fixture.other_key.clone(),
    ))
    .expect("foreign actor");
    assert!(matches!(
        fixture
            .delegation
            .authorization_with_actor_for_test(&caller(&fixture, now() + 300), Arc::new(foreign)),
        Err(AuthorizationError::Configuration)
    ));
}
