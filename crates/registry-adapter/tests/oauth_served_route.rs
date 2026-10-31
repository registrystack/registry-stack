// SPDX-License-Identifier: Apache-2.0

//! Route-level authentication over the real loopback egress transports.

#[path = "support/upstream/mod.rs"]
#[allow(dead_code)]
mod upstream;

use std::collections::BTreeMap;
use std::time::Duration;

use registry_adapter::exchange::Exchange;
use registry_adapter::route::{
    run_route_within, EndpointRuntime, RouteContext, RouteOutcome, RouteTable,
};
use registry_adapter::scripts::ScriptSet;
use registry_adapter_core::{
    AdapterRuntimeConfig, ComponentKind, CredentialPlacement, Endpoint, EndpointAuthentication,
    EndpointBinding, ErrorClass, RuntimeCredential, Step,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_yaml::{
    BoundedU64, ExternalId, LocalId, SecretReference, UniqueIdList, UniqueList, Url,
};
use serde_json::json;
use upstream::{Response, UpstreamDouble};

const JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;

fn secret(name: &str) -> SecretReference {
    SecretReference::new(format!("secret:env/{name}")).expect("secret reference")
}

fn endpoint(authentication: EndpointAuthentication) -> Endpoint {
    Endpoint {
        id: LocalId::new("source").expect("id"),
        component: ComponentKind::Http,
        authentication,
        attempt_timeout_milliseconds: BoundedU64::new(10_000).expect("attempt"),
        maximum_response_bytes: BoundedU64::new(65_536).expect("response"),
        response_headers: UniqueList::new(Vec::new()).expect("headers"),
        request_headers: UniqueList::new(Vec::new()).expect("headers"),
        operations: Vec::new(),
        tested_versions: Vec::new(),
        query_file: None,
        operation_name: None,
        variables: None,
    }
}

fn binding(double: &UpstreamDouble, credential: Option<RuntimeCredential>) -> EndpointBinding {
    EndpointBinding {
        endpoint: ExternalId::new("source").expect("id"),
        base_url: Url::new(double.url("/")).expect("url"),
        credential,
        anonymous_https: None,
        tls_trust_profile: None,
        mtls_identity: None,
        attempt_timeout_milliseconds: None,
        maximum_response_bytes: None,
    }
}

fn config(binding: EndpointBinding) -> AdapterRuntimeConfig {
    AdapterRuntimeConfig {
        id: LocalId::new("oauth-route").expect("id"), endpoints: UniqueIdList::new(vec![binding]).expect("bindings"),
        allowed_private_cidrs: UniqueList::new(Vec::new()).expect("cidrs"), outbound_tls: None,
        listener: serde_json::from_str(r#"{"bind":"127.0.0.1:8080"}"#).expect("listener"),
        database: serde_json::from_str(r#"{"runtimeUrlRef":"secret:env/OAUTH_ROUTE_DB","migrationUrlRef":"secret:env/OAUTH_ROUTE_DB"}"#).expect("database"),
        oidc: serde_json::from_str(r#"{"issuer":"https://issuer.example.invalid","audience":"oauth-route"}"#).expect("oidc"),
        allowed_clients: UniqueList::new(vec![ExternalId::new("oauth-route-client").expect("client")]).expect("clients"),
        idempotency: None,
        audit: registry_adapter_core::AuditRetention { retention_days: registry_platform_yaml::BoundedU32::<1, 3_650>::new(90).expect("retention") },
        cursor_key_ref: None, previous_cursor_key_ref: None, cursor_ttl_seconds: None,
    }
}

fn oauth(double: &UpstreamDouble) -> RuntimeCredential {
    RuntimeCredential::Oauth2ClientCredentials {
        token_endpoint: Url::new(double.url("/token")).expect("token endpoint"),
        client_id_ref: secret("OAUTH_ROUTE_CLIENT_ID"),
        client_secret_ref: secret("OAUTH_ROUTE_CLIENT_SECRET"),
        scope: None,
        audience: None,
        resource: None,
        credential_placement: CredentialPlacement::BasicHeader,
        maximum_cache_seconds: BoundedU64::<0, 86_400>::new(3600).expect("cache"),
        assumed_lifetime_seconds: None,
    }
}

fn assertion(double: &UpstreamDouble) -> RuntimeCredential {
    RuntimeCredential::Oauth2PrivateKeyJwt {
        token_endpoint: Url::new(double.url("/token")).expect("token endpoint"),
        client_id_ref: secret("OAUTH_ROUTE_ASSERTION_ID"),
        client_assertion_key_ref: secret("OAUTH_ROUTE_ASSERTION_KEY"),
        client_assertion_audience: None,
        scope: None,
        audience: None,
        resource: None,
        maximum_cache_seconds: BoundedU64::<0, 86_400>::new(3600).expect("cache"),
        assumed_lifetime_seconds: None,
    }
}

async fn run(
    double: &UpstreamDouble,
    authentication: EndpointAuthentication,
    credential: Option<RuntimeCredential>,
    sends: usize,
    deadline: Duration,
) -> RouteOutcome {
    let config = config(binding(double, credential));
    let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
    let runtime = EndpointRuntime::compile(
        config.endpoints.iter().next().expect("binding"),
        &endpoint(authentication),
        &config,
        &resolver,
    )
    .expect("endpoint compiles");
    let endpoints = BTreeMap::from([("source".to_owned(), runtime)]);
    let scripts = ScriptSet::default();
    let resilience = registry_adapter::resilience::ResilienceRuntime::empty();
    let routes = RouteTable::new();
    let context = RouteContext {
        endpoints: &endpoints,
        scripts: &scripts,
        resolver: &resolver,
        resilience: &resilience,
        routes: &routes,
        code_maps: std::sync::Arc::new(BTreeMap::new()),
        maximum_upstream_calls: 12,
        job: registry_adapter::job_sources::JobPageState::default(),
    };
    let send: Step = serde_json::from_value(
        json!({"to":{"uri":"http:source","parameters":{"httpMethod":"GET","path":"/data"}}}),
    )
    .expect("send");
    run_route_within(
        &context,
        &vec![send; sends],
        Exchange::new("oauth-route".to_owned()),
        deadline,
    )
    .await
}

fn ok(outcome: &RouteOutcome) {
    assert!(
        outcome.result.is_ok(),
        "route failed: {:?}",
        outcome.result.as_ref().err().map(|failure| failure.class)
    );
}

#[tokio::test]
async fn all_six_authentication_kinds_reach_a_data_send() {
    std::env::set_var("OAUTH_ROUTE_BASIC_USER", "user");
    std::env::set_var("OAUTH_ROUTE_BASIC_PASS", "pass");
    std::env::set_var("OAUTH_ROUTE_STATIC", "static-token");
    std::env::set_var("OAUTH_ROUTE_KEY", "api-key");
    std::env::set_var("OAUTH_ROUTE_CLIENT_ID", "client");
    std::env::set_var("OAUTH_ROUTE_CLIENT_SECRET", "client-secret");
    std::env::set_var("OAUTH_ROUTE_ASSERTION_ID", "assertion-client");
    std::env::set_var("OAUTH_ROUTE_ASSERTION_KEY", JWK);

    let none = UpstreamDouble::start();
    none.respond_with(vec![Response::json(200, "{}")]);
    ok(&run(
        &none,
        EndpointAuthentication::None {},
        Some(RuntimeCredential::None {}),
        1,
        Duration::from_secs(2),
    )
    .await);
    assert!(none.requests()[0].header("authorization").is_none());

    let basic = UpstreamDouble::start();
    basic.respond_with(vec![Response::json(200, "{}")]);
    ok(&run(
        &basic,
        EndpointAuthentication::Basic {},
        Some(RuntimeCredential::Basic {
            username_ref: secret("OAUTH_ROUTE_BASIC_USER"),
            password_ref: secret("OAUTH_ROUTE_BASIC_PASS"),
        }),
        1,
        Duration::from_secs(2),
    )
    .await);
    assert!(basic.requests()[0]
        .header("authorization")
        .is_some_and(|value| value.starts_with("Basic ")));

    let static_auth = UpstreamDouble::start();
    static_auth.respond_with(vec![Response::json(200, "{}")]);
    ok(&run(
        &static_auth,
        EndpointAuthentication::StaticAuthorization {
            scheme: Some("Token".to_owned()),
        },
        Some(RuntimeCredential::StaticAuthorization {
            token_ref: secret("OAUTH_ROUTE_STATIC"),
        }),
        1,
        Duration::from_secs(2),
    )
    .await);
    assert_eq!(
        static_auth.requests()[0].header("authorization"),
        Some("Token static-token")
    );

    let api_key = UpstreamDouble::start();
    api_key.respond_with(vec![Response::json(200, "{}")]);
    ok(&run(
        &api_key,
        EndpointAuthentication::StaticApiKey {
            header_name: "x-api-key".to_owned(),
        },
        Some(RuntimeCredential::StaticApiKey {
            value_ref: secret("OAUTH_ROUTE_KEY"),
        }),
        1,
        Duration::from_secs(2),
    )
    .await);
    assert_eq!(api_key.requests()[0].header("x-api-key"), Some("api-key"));

    let client = UpstreamDouble::start();
    client.respond_with(vec![
        Response::json(
            200,
            r#"{"access_token":"issued-client","token_type":"Bearer","expires_in":600}"#,
        ),
        Response::json(200, "{}"),
    ]);
    ok(&run(
        &client,
        EndpointAuthentication::Oauth2ClientCredentials {},
        Some(oauth(&client)),
        1,
        Duration::from_secs(2),
    )
    .await);
    assert_eq!(client.requests()[0].target, "/token");
    assert_eq!(
        client.requests()[1].header("authorization"),
        Some("Bearer issued-client")
    );

    let signed = UpstreamDouble::start();
    signed.respond_with(vec![
        Response::json(
            200,
            r#"{"access_token":"issued-signed","token_type":"Bearer","expires_in":600}"#,
        ),
        Response::json(200, "{}"),
    ]);
    ok(&run(
        &signed,
        EndpointAuthentication::Oauth2PrivateKeyJwt {},
        Some(assertion(&signed)),
        1,
        Duration::from_secs(2),
    )
    .await);
    assert!(signed.requests()[0]
        .body_text()
        .contains("client_assertion="));
    assert_eq!(
        signed.requests()[1].header("authorization"),
        Some("Bearer issued-signed")
    );
}

#[tokio::test]
async fn one_401_refreshes_once_and_journals_both_data_attempts() {
    std::env::set_var("OAUTH_ROUTE_CLIENT_ID", "client");
    std::env::set_var("OAUTH_ROUTE_CLIENT_SECRET", "client-secret");
    let double = UpstreamDouble::start();
    double.respond_with(vec![
        Response::json(
            200,
            r#"{"access_token":"first-token","token_type":"Bearer","expires_in":600}"#,
        ),
        Response::json(401, "{}"),
        Response::json(
            200,
            r#"{"access_token":"second-token","token_type":"Bearer","expires_in":600}"#,
        ),
        Response::json(200, "{}"),
    ]);
    let outcome = run(
        &double,
        EndpointAuthentication::Oauth2ClientCredentials {},
        Some(oauth(&double)),
        1,
        Duration::from_secs(2),
    )
    .await;
    ok(&outcome);
    assert_eq!(double.request_count(), 4);
    assert_eq!(
        outcome
            .events
            .iter()
            .filter(|event| event.kind == "exchangeSending")
            .count(),
        2
    );
    assert_eq!(
        outcome
            .events
            .iter()
            .filter(|event| event.kind == "exchangeSent")
            .count(),
        2
    );
    let rendered = format!("{:?}", outcome.events);
    assert!(rendered.contains("tokenInvalidatedAfterUnauthorized"));
    assert!(!rendered.contains("first-token") && !rendered.contains("second-token"));
}

#[tokio::test]
async fn token_budget_is_exchange_scoped_and_value_free() {
    std::env::set_var("OAUTH_ROUTE_CLIENT_ID", "client");
    std::env::set_var("OAUTH_ROUTE_CLIENT_SECRET", "client-secret");
    let double = UpstreamDouble::start();
    double.respond_with(vec![
        Response::json(
            200,
            r#"{"access_token":"one","token_type":"Bearer","expires_in":600}"#,
        ),
        Response::json(401, "{}"),
        Response::json(
            200,
            r#"{"access_token":"two","token_type":"Bearer","expires_in":600}"#,
        ),
        Response::json(200, "{}"),
        Response::json(401, "{}"),
    ]);
    let outcome = run(
        &double,
        EndpointAuthentication::Oauth2ClientCredentials {},
        Some(oauth(&double)),
        2,
        Duration::from_secs(2),
    )
    .await;
    let failure = outcome
        .result
        .as_ref()
        .expect_err("third token send exhausts");
    assert_eq!(failure.class, ErrorClass::BudgetExhausted, "{failure:?}");
    assert_eq!(double.request_count(), 5);
    let rendered = format!("{:?} {:?}", failure.auth, outcome.events);
    assert!(rendered.contains("tokenBudgetExhausted"));
    assert!(!rendered.contains("client-secret"));
}

#[tokio::test]
async fn token_acquisition_obeys_the_route_deadline_before_any_data_send() {
    std::env::set_var("OAUTH_ROUTE_CLIENT_ID", "client");
    std::env::set_var("OAUTH_ROUTE_CLIENT_SECRET", "client-secret");
    let double = UpstreamDouble::start();
    double.respond_with(vec![Response::json(
        200,
        r#"{"access_token":"late","token_type":"Bearer","expires_in":600}"#,
    )]);
    double.delay_answers(Duration::from_millis(100));
    let outcome = run(
        &double,
        EndpointAuthentication::Oauth2ClientCredentials {},
        Some(oauth(&double)),
        1,
        Duration::from_millis(10),
    )
    .await;
    assert_eq!(
        outcome.result.expect_err("deadline expires").class,
        ErrorClass::BudgetExhausted
    );
    assert_eq!(double.request_count(), 1);
    assert!(outcome
        .events
        .iter()
        .all(|event| event.kind != "exchangeSending"));
}

#[tokio::test]
async fn a_second_401_is_terminal_credential_rejected() {
    std::env::set_var("OAUTH_ROUTE_CLIENT_ID", "client");
    std::env::set_var("OAUTH_ROUTE_CLIENT_SECRET", "client-secret");
    let double = UpstreamDouble::start();
    double.respond_with(vec![
        Response::json(
            200,
            r#"{"access_token":"first-secret","token_type":"Bearer","expires_in":600}"#,
        ),
        Response::json(401, "{}"),
        Response::json(
            200,
            r#"{"access_token":"second-secret","token_type":"Bearer","expires_in":600}"#,
        ),
        Response::json(401, "{}"),
    ]);
    let outcome = run(
        &double,
        EndpointAuthentication::Oauth2ClientCredentials {},
        Some(oauth(&double)),
        1,
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(
        outcome.result.expect_err("second 401 is terminal").class,
        ErrorClass::CredentialRejected
    );
    assert_eq!(double.request_count(), 4);
    let rendered = format!("{:?}", outcome.events);
    assert!(rendered.contains("credentialRejected"));
    assert!(!rendered.contains("first-secret") && !rendered.contains("second-secret"));
}
