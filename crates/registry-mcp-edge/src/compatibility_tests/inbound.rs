// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::Extension,
    http::{header, HeaderValue, Request, Response, StatusCode},
    routing::post,
    Router,
};
use registry_platform_audit::AuditProfile;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    access_token_typ_set, is_access_token_typ_pair, Claims, JwksFetcher, JwksFetcherConfig,
    OidcError, VerifiedToken,
};
use registry_platform_testing::{TestAuthorizationServer, TestClient};
use serde_json::{json, Value};
use tower::ServiceExt;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    inbound::{metadata_url, require_caller, retry_after_seconds, Refusal},
    token_verifier, AccessTokenAlgorithm, RateLimitOptions, ResourceServer, ResourceServerOptions,
    TokenBucketOptions, VerifiedCaller,
};

const RESOURCE: &str = "https://gateway.example.test/mcp";
const CHAT_HOST: &str = "chat-host";
const SCOPE: &str = "address-correction:self";
const METADATA: &str = "https://gateway.example.test/.well-known/oauth-protected-resource/mcp";

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("log buffer lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

impl CapturedLogs {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("log buffer lock").clone()).expect("UTF-8 logs")
    }
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("time fits")
}

fn options(authorization: &TestAuthorizationServer) -> ResourceServerOptions {
    ResourceServerOptions {
        resource: RESOURCE.to_owned(),
        issuer: authorization.issuer(),
        allow_insecure_http: false,
        algorithms: vec![AccessTokenAlgorithm::EdDSA],
        allowed_clients: vec![CHAT_HOST.to_owned()],
        required_scopes: vec![SCOPE.to_owned()],
        scope_claim: "scope".to_owned(),
        maximum_token_lifetime: Duration::from_secs(3600),
        resource_name: "Address correction".to_owned(),
        principal_audit_namespace: "breg-mcp-principal-v1".to_owned(),
        client_audit_namespace: "breg-mcp-client-v1".to_owned(),
    }
}

fn hasher() -> registry_platform_audit::AuditKeyHasher {
    AuditProfile::production_from_secret_bytes(Zeroizing::new(vec![5; 32]))
        .expect("profile")
        .key_hasher()
}

async fn authorization_server() -> TestAuthorizationServer {
    TestAuthorizationServer::builder()
        .client(TestClient::new(CHAT_HOST))
        .client(TestClient::new("another-host"))
        .start()
        .await
}

fn resource_server_for(
    authorization: &TestAuthorizationServer,
    principal: u32,
    client: u32,
) -> Arc<ResourceServer> {
    let options = options(authorization);
    let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        authorization.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    Arc::new(
        ResourceServer::new(
            &options,
            token_verifier(&options, fetcher),
            hasher(),
            RateLimitOptions {
                per_principal: TokenBucketOptions {
                    requests_per_minute: 1,
                    burst: principal,
                },
                per_client: TokenBucketOptions {
                    requests_per_minute: 1,
                    burst: client,
                },
            },
        )
        .expect("resource server"),
    )
}

fn router_for(authorization: &TestAuthorizationServer, principal: u32, client: u32) -> Router {
    let server = resource_server_for(authorization, principal, client);
    Router::new()
        .route(
            "/mcp",
            post(
                |Extension(caller): Extension<Arc<VerifiedCaller>>,
                 headers: axum::http::HeaderMap| async move {
                    axum::Json(json!({
                        "authorization": headers.contains_key(header::AUTHORIZATION),
                        "subject": caller.identity().subject(),
                        "client": caller.context().client_pseudonym(),
                        "principal": caller.context().principal_pseudonym(),
                        "debug": format!("{caller:?}"),
                    }))
                },
            ),
        )
        .layer(axum::middleware::from_fn_with_state(server, require_caller))
}

#[tokio::test]
async fn an_issuer_without_a_trailing_slash_is_preserved_exactly() {
    let auth = authorization_server().await;
    assert!(!auth.issuer().ends_with('/'));
    let server = resource_server_for(&auth, 10, 10);
    assert_eq!(
        server.metadata()["authorization_servers"],
        json!([auth.issuer()])
    );

    let token = auth.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
    assert_eq!(
        call(&router_for(&auth, 10, 10), Some(&token))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_authored_resource_is_the_exact_audience_and_metadata_identifier() {
    const AUTHORED_RESOURCE: &str = "https://Gateway.Example:443/mcp";
    const CANONICAL_RESOURCE: &str = "https://gateway.example/mcp";

    let auth = authorization_server().await;
    let mut options = options(&auth);
    options.resource = AUTHORED_RESOURCE.to_owned();
    let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        auth.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let verifier = token_verifier(&options, fetcher);

    let exact = auth.issue_access_token(
        CHAT_HOST,
        "citizen-a",
        AUTHORED_RESOURCE,
        SCOPE,
        now() + 300,
    );
    assert!(verifier.verify(&exact).await.is_ok());

    let canonical = auth.issue_access_token(
        CHAT_HOST,
        "citizen-a",
        CANONICAL_RESOURCE,
        SCOPE,
        now() + 300,
    );
    assert!(verifier.verify(&canonical).await.is_err());

    let resource_server = ResourceServer::new(
        &options,
        verifier,
        hasher(),
        RateLimitOptions {
            per_principal: TokenBucketOptions {
                requests_per_minute: 10,
                burst: 10,
            },
            per_client: TokenBucketOptions {
                requests_per_minute: 10,
                burst: 10,
            },
        },
    )
    .expect("resource server");
    assert_eq!(
        resource_server.metadata()["resource"],
        json!(AUTHORED_RESOURCE)
    );
}

async fn call(router: &Router, token: Option<&str>) -> Response<Body> {
    let mut request = Request::post("/mcp");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    router
        .clone()
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("response")
}

fn challenge(response: &Response<Body>) -> &str {
    response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("challenge")
        .to_str()
        .expect("ASCII")
}

async fn body(response: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("JSON")
}

#[tokio::test]
async fn a_request_without_a_token_is_pointed_at_the_resource_metadata() {
    let auth = authorization_server().await;
    let response = call(&router_for(&auth, 10, 10), None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge(&response),
        format!("Bearer resource_metadata=\"{METADATA}\"")
    );
}

#[tokio::test]
async fn a_token_for_another_audience_is_refused_as_invalid() {
    let auth = authorization_server().await;
    let token =
        auth.issue_access_token(CHAT_HOST, "citizen-a", "urn:elsewhere", SCOPE, now() + 300);
    let response = call(&router_for(&auth, 10, 10), Some(&token)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge(&response),
        format!("Bearer error=\"invalid_token\", resource_metadata=\"{METADATA}\"")
    );
}

#[tokio::test]
async fn a_bearer_token_after_two_spaces_is_refused_as_invalid() {
    let auth = authorization_server().await;
    let router = router_for(&auth, 10, 10);
    let token = auth.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
    let request = Request::post("/mcp")
        .header(header::AUTHORIZATION, format!("Bearer  {token}"))
        .body(Body::empty())
        .expect("request");
    assert_eq!(
        router
            .clone()
            .oneshot(request)
            .await
            .expect("response")
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(call(&router, Some(&token)).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_client_that_is_not_admitted_is_refused() {
    let auth = authorization_server().await;
    let token = auth.issue_access_token("another-host", "citizen-a", RESOURCE, SCOPE, now() + 300);
    assert_eq!(
        call(&router_for(&auth, 10, 10), Some(&token))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_token_without_the_required_scope_is_forbidden() {
    let auth = authorization_server().await;
    let token = auth.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, "openid", now() + 300);
    let response = call(&router_for(&auth, 10, 10), Some(&token)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        challenge(&response),
        format!(
            "Bearer error=\"insufficient_scope\", scope=\"{SCOPE}\", resource_metadata=\"{METADATA}\""
        )
    );
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let auth = authorization_server().await;
    let token = auth.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() - 120);
    assert_eq!(
        call(&router_for(&auth, 10, 10), Some(&token))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_verified_caller_carries_only_its_token_identity() {
    let auth = authorization_server().await;
    let token = auth.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
    let response = call(&router_for(&auth, 10, 10), Some(&token)).await;
    let value = body(response).await;
    assert_eq!(value["subject"], "citizen-a");
    assert_eq!(value["authorization"], false);
    assert_eq!(
        value["principal"],
        hasher()
            .audit_reference_hash(
                "breg-mcp-principal-v1",
                "",
                &json!([auth.issuer(), "citizen-a"]).to_string()
            )
            .expect("pseudonym")
    );
    assert_eq!(
        value["client"],
        hasher()
            .audit_reference_hash(
                "breg-mcp-client-v1",
                "",
                &json!([auth.issuer(), CHAT_HOST]).to_string()
            )
            .expect("pseudonym")
    );
    assert!(!value["debug"].as_str().expect("debug").contains(&token));
    assert!(!value["debug"]
        .as_str()
        .expect("debug")
        .contains("citizen-a"));
}

#[tokio::test]
async fn each_citizen_has_its_own_rate_limit() {
    let auth = authorization_server().await;
    let router = router_for(&auth, 1, 10);
    let a = auth.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
    let b = auth.issue_access_token(CHAT_HOST, "citizen-b", RESOURCE, SCOPE, now() + 300);
    assert_eq!(call(&router, Some(&a)).await.status(), StatusCode::OK);
    let limited = call(&router, Some(&a)).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(call(&router, Some(&b)).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn each_client_has_its_own_rate_limit() {
    let auth = authorization_server().await;
    let router = router_for(&auth, 10, 1);
    let a = auth.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
    let b = auth.issue_access_token(CHAT_HOST, "citizen-b", RESOURCE, SCOPE, now() + 300);
    assert_eq!(call(&router, Some(&a)).await.status(), StatusCode::OK);
    assert_eq!(
        call(&router, Some(&b)).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn an_over_limit_citizen_does_not_drain_the_shared_client_limit() {
    let auth = authorization_server().await;
    let router = router_for(&auth, 1, 3);
    let noisy = auth.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
    assert_eq!(call(&router, Some(&noisy)).await.status(), StatusCode::OK);
    for _ in 0..5 {
        assert_eq!(
            call(&router, Some(&noisy)).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    for citizen in ["citizen-b", "citizen-c"] {
        let token = auth.issue_access_token(CHAT_HOST, citizen, RESOURCE, SCOPE, now() + 300);
        assert_eq!(call(&router, Some(&token)).await.status(), StatusCode::OK);
    }
}

#[test]
fn inbound_tokens_are_verified_under_both_rfc_9068_type_spellings() {
    assert!(is_access_token_typ_pair(&access_token_typ_set("at+jwt")));
}

#[tokio::test]
async fn every_refusal_is_a_problem_document() {
    let auth = authorization_server().await;
    let server = resource_server_for(&auth, 10, 10);
    let cases = [
        (Refusal::Missing, 401, "Unauthorized", "unauthorized", true),
        (
            Refusal::InvalidToken,
            401,
            "Unauthorized",
            "invalid-token",
            true,
        ),
        (
            Refusal::InsufficientScope,
            403,
            "Forbidden",
            "insufficient-scope",
            true,
        ),
        (
            Refusal::KeySource,
            503,
            "Service Unavailable",
            "temporarily-unavailable",
            false,
        ),
        (
            Refusal::Unavailable,
            503,
            "Service Unavailable",
            "temporarily-unavailable",
            false,
        ),
        (
            Refusal::RateLimited {
                retry_after_seconds: 7,
            },
            429,
            "Too Many Requests",
            "rate-limited",
            false,
        ),
    ];
    for (refusal, status, title, code, challenged) in cases {
        let response = server.refusal_response(refusal);
        assert_eq!(response.status().as_u16(), status, "{code}");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/problem+json")),
            "{code}"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store")),
            "{code}"
        );
        assert_eq!(
            response.headers().contains_key(header::WWW_AUTHENTICATE),
            challenged,
            "{code}"
        );
        assert_eq!(
            response.headers().get(header::RETRY_AFTER).is_some(),
            status == 429,
            "{code}"
        );
        let value = body(response).await;
        assert_eq!(value["type"], "about:blank", "{code}");
        assert_eq!(value["title"], title, "{code}");
        assert_eq!(value["status"], status, "{code}");
        assert_eq!(value["code"], code, "{code}");
        assert!(value["detail"].is_string(), "{code}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn an_unreachable_key_set_is_the_operators_failure() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(logs.clone())
        .finish();
    let _capture = tracing::subscriber::set_default(subscriber);
    let auth = authorization_server().await;
    let token = auth.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let closed = format!(
        "http://{}/jwks.json",
        listener.local_addr().expect("address")
    );
    drop(listener);
    let options = options(&auth);
    let server = Arc::new(
        ResourceServer::new(
            &options,
            token_verifier(
                &options,
                Arc::new(JwksFetcher::new_with_fetch_url_policy(
                    closed,
                    JwksFetcherConfig::defaults(),
                    FetchUrlPolicy::dev(),
                )),
            ),
            hasher(),
            RateLimitOptions {
                per_principal: TokenBucketOptions {
                    requests_per_minute: 1,
                    burst: 10,
                },
                per_client: TokenBucketOptions {
                    requests_per_minute: 1,
                    burst: 10,
                },
            },
        )
        .expect("server"),
    );
    let router = Router::new()
        .route("/mcp", post(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(server, require_caller));
    assert_eq!(
        call(&router, Some(&token)).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let logs = logs.text();
    assert!(
        logs.contains("the access-token key set is unavailable"),
        "{logs}"
    );
    assert!(!logs.contains("citizen-a"), "{logs}");
    assert!(!logs.contains(&token), "{logs}");
}

#[tokio::test]
async fn a_production_key_set_on_a_loopback_address_is_refused_before_any_fetch() {
    let auth = authorization_server().await;
    let token = auth.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
    let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        auth.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::strict(),
    ));
    let error = token_verifier(&options(&auth), fetcher)
        .verify(&token)
        .await
        .expect_err("a loopback key set is refused");
    assert!(matches!(error, OidcError::FetchUrl(_)), "{error:?}");
}

#[test]
fn retry_after_rounds_up_to_whole_seconds() {
    assert_eq!(retry_after_seconds(Duration::ZERO), 1);
    assert_eq!(retry_after_seconds(Duration::from_millis(1)), 1);
    assert_eq!(retry_after_seconds(Duration::from_secs(1)), 1);
    assert_eq!(retry_after_seconds(Duration::from_millis(1_001)), 2);
    assert_eq!(retry_after_seconds(Duration::from_millis(2_400)), 3);
    assert_eq!(retry_after_seconds(Duration::from_secs(7)), 7);
}

#[tokio::test]
async fn localhost_is_a_development_loopback_resource_and_issuer() {
    let auth = authorization_server().await;
    let mut options = options(&auth);
    options.resource = "http://localhost:8095/mcp".to_owned();
    options.issuer = "http://localhost:8096".to_owned();
    assert_eq!(options.validate(), Ok(()));
}

#[tokio::test]
async fn a_token_that_already_names_an_actor_is_refused() {
    let auth = authorization_server().await;
    let options = options(&auth);
    let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        auth.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let server = ResourceServer::new(
        &options,
        token_verifier(&options, fetcher),
        hasher(),
        RateLimitOptions {
            per_principal: TokenBucketOptions {
                requests_per_minute: 1,
                burst: 10,
            },
            per_client: TokenBucketOptions {
                requests_per_minute: 1,
                burst: 10,
            },
        },
    )
    .expect("server");
    let mut claims: Claims = serde_json::from_value(json!({
        "sub": "citizen-a", "exp": now() + 300, "client_id": CHAT_HOST,
        "act": {"sub": "someone-else"},
    }))
    .expect("claims");
    let delegated = VerifiedToken {
        claims: claims.clone(),
        matched_client: Some(format!("client_id:{CHAT_HOST}")),
        scopes: vec![SCOPE.to_owned()],
    };
    assert!(server.caller_for_test(&delegated, "token").is_err());
    claims.extra.remove("act");
    claims.sub = None;
    let anonymous = VerifiedToken {
        claims,
        matched_client: Some(format!("client_id:{CHAT_HOST}")),
        scopes: vec![SCOPE.to_owned()],
    };
    assert!(server.caller_for_test(&anonymous, "token").is_err());
}

#[test]
fn the_metadata_url_inserts_the_well_known_prefix() {
    assert_eq!(
        metadata_url(&Url::parse(RESOURCE).expect("URL"))
            .expect("metadata")
            .as_str(),
        METADATA
    );
}

#[tokio::test]
async fn a_malformed_authorization_header_is_refused() {
    let auth = authorization_server().await;
    let router = router_for(&auth, 10, 10);
    for value in ["Basic abc", "Bearer a b", "Bearer  a", "Bearer"] {
        let request = Request::post("/mcp")
            .header(header::AUTHORIZATION, value)
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            router
                .clone()
                .oneshot(request)
                .await
                .expect("response")
                .status(),
            StatusCode::UNAUTHORIZED,
            "{value}"
        );
    }
    let token = auth.issue_access_token(CHAT_HOST, "citizen-a", RESOURCE, SCOPE, now() + 300);
    let request = Request::post("/mcp")
        .header(header::AUTHORIZATION, format!("bearer {token}"))
        .body(Body::empty())
        .expect("request");
    assert_eq!(
        router.oneshot(request).await.expect("response").status(),
        StatusCode::OK
    );
}
