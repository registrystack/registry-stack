// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use registry_notary_client::auth::{AuthHeader, AuthProvider};
use registry_notary_client::{
    CredentialIssueResponse, NotaryClientBuildError, NotaryClientError, NotaryResponse,
    RegistryNotaryClient, RequestOptions, RetryPolicy,
};
use registry_notary_core::{
    BatchEvaluateResponse, BatchStatus, FORMAT_CLAIM_RESULT_JSON, MAX_BATCH_EVALUATION_MEMBERS_V1,
};
use secrecy::SecretString;
use serde_json::json;
use tokio::net::TcpListener;

#[tokio::test]
async fn builder_rejects_multiple_auth_modes() {
    let error = RegistryNotaryClient::builder("https://notary.example")
        .bearer_token("bearer-secret")
        .api_key("api-secret")
        .build()
        .expect_err("multiple auth modes are rejected");

    assert!(matches!(error, NotaryClientBuildError::MultipleAuthModes));
}

#[tokio::test]
async fn builder_rejects_non_loopback_http() {
    let error = RegistryNotaryClient::builder("http://example.com")
        .bearer_token("bearer-secret")
        .build()
        .expect_err("non-loopback http is rejected");

    assert!(matches!(error, NotaryClientBuildError::InsecureBaseUrl));
}

#[tokio::test]
async fn builder_preserves_encoded_base_path_when_adding_trailing_slash() {
    let app = Router::new().fallback(get(base_path_health_handler));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(format!("{base}/tenant%20one"))
        .build()
        .expect("client builds");

    let response = client.health().await.expect("health response");

    assert_eq!(response.body.status, "ok");
}

#[tokio::test]
async fn debug_redacts_auth_material() {
    let builder = RegistryNotaryClient::builder("https://notary.example")
        .bearer_token("super-secret-token")
        .api_key("another-secret");

    let rendered = format!("{builder:?}");
    assert!(!rendered.contains("super-secret-token"));
    assert!(!rendered.contains("another-secret"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn credential_issue_response_debug_redacts_credential_material() {
    let response = CredentialIssueResponse {
        credential_id: "cred-1".to_string(),
        credential_profile: "profile-1".to_string(),
        format: "application/dc+sd-jwt".to_string(),
        issuer: "did:web:notary.example".to_string(),
        expires_at: "2026-05-29T00:00:00Z".to_string(),
        credential: "issuer.jwt~disclosure-secret~".to_string(),
        issuer_signed_jwt: "issuer.jwt".to_string(),
        disclosures: vec!["disclosure-secret".to_string()],
    };

    let debug = format!("{response:?}");

    assert!(debug.contains("cred-1"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("issuer.jwt"));
    assert!(!debug.contains("disclosure-secret"));
    assert!(!debug.contains("issuer.jwt~disclosure-secret~"));

    let wrapped = NotaryResponse {
        body: response,
        status: StatusCode::OK,
        request_id: Some("req-credential".to_string()),
        retry_after: None,
    };
    let wrapped_debug = format!("{wrapped:?}");

    assert!(wrapped_debug.contains("req-credential"));
    assert!(wrapped_debug.contains("<redacted>"));
    assert!(!wrapped_debug.contains("issuer.jwt"));
    assert!(!wrapped_debug.contains("disclosure-secret"));
}

#[test]
fn serialization_build_error_has_specific_portable_code() {
    let error = NotaryClientError::Build(NotaryClientBuildError::RequestSerialization);

    assert_eq!(
        error.portable().code.as_deref(),
        Some("request.serialization_failed")
    );
}

#[test]
fn notary_response_debug_keeps_non_sensitive_body_metadata() {
    let response = NotaryResponse {
        body: registry_notary_client::HealthResponse {
            status: "ok".to_string(),
            checks: json!({ "database": "ready" }),
        },
        status: StatusCode::OK,
        request_id: Some("req-health".to_string()),
        retry_after: None,
    };

    let debug = format!("{response:?}");

    assert!(debug.contains("req-health"));
    assert!(debug.contains("ok"));
    assert!(debug.contains("database"));
    assert!(!debug.contains("<redacted>"));
}

struct FixedAuthProvider;

#[async_trait::async_trait]
impl AuthProvider for FixedAuthProvider {
    async fn auth_header(&self) -> Result<AuthHeader, NotaryClientError> {
        Ok(AuthHeader::ApiKey(SecretString::from(
            "provider-secret".to_string(),
        )))
    }
}

#[tokio::test]
async fn auth_provider_sends_redacted_dynamic_header() {
    let app = Router::new().route(
        "/healthz",
        get(|headers: HeaderMap| async move {
            assert_eq!(
                headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok()),
                Some("provider-secret")
            );
            Json(json!({ "status": "ok", "checks": {} }))
        }),
    );
    let base = spawn(app).await;
    let provider: Arc<dyn AuthProvider> = Arc::new(FixedAuthProvider);
    let client = RegistryNotaryClient::builder(base)
        .auth_provider(provider)
        .build()
        .expect("client builds");

    let response = client.health().await.expect("health succeeds");

    assert_eq!(response.body.status, "ok");
}

#[tokio::test]
async fn batch_response_family_deserializes_from_wire_json() {
    let value = json!({
        "batch_id": "batch-1",
        "status": "completed",
        "claims": ["claim-a"],
        "items": [],
        "summary": { "succeeded": 0, "failed": 0 }
    });

    let parsed: BatchEvaluateResponse =
        serde_json::from_value(value).expect("batch response deserializes");
    assert_eq!(parsed.batch_id, "batch-1");
    assert!(matches!(parsed.status, BatchStatus::Completed));
}

#[tokio::test]
async fn evaluate_sends_safe_headers_and_parses_metadata() {
    let app = Router::new().route("/v1/evaluations", post(evaluate_handler));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .default_purpose("benefits")
        .build()
        .expect("client builds");

    let response = client
        .evaluate_target("Person")
        .target_identifier("NATIONAL_ID", "subject-1")
        .target_identifier_issuer("civil_registry")
        .relationship("self")
        .request_variable_date("as_of_date", "2026-01-01")
        .claim("claim-a")
        .request_id("req-123")
        .send()
        .await
        .expect("evaluate succeeds");

    assert_eq!(response.request_id.as_deref(), Some("req-123"));
    assert!(response.body.results.is_empty());
}

#[tokio::test]
async fn ready_200_returns_typed_custody_checks() {
    let app = Router::new().route(
        "/ready",
        get(|| async {
            Json(json!({
                "status": "ready",
                "checks": readiness_checks_json(true, 0),
            }))
        }),
    );
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .build()
        .expect("client builds");

    let response = client.ready().await.expect("ready response parses");

    assert_eq!(response.body.status, "ready");
    let custody = response.body.checks.signing_providers.custody;
    assert!(custody.custody_approval_required);
    assert!(custody.custody_approved);
    assert_eq!(custody.unapproved_signing_provider_count, 0);
    assert_eq!(custody.active_provider_counts.get("pkcs11"), Some(&1));
}

#[tokio::test]
async fn ready_503_returns_problem_details() {
    let app = Router::new().route(
        "/ready",
        get(|| async {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [("content-type", "application/problem+json")],
                Json(json!({
                    "type": "https://id.registrystack.org/problems/registry-notary/readiness/not-ready",
                    "title": "Evidence runtime is not ready",
                    "status": 503,
                    "detail": "one or more readiness checks are not ready",
                    "code": "readiness.not_ready",
                    "request_id": "01J00000000000000000000000",
                    "readiness_status": "not_ready",
                    "checks": readiness_checks_json(false, 1)
                })),
            )
        }),
    );
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .build()
        .expect("client builds");

    let error = client.ready().await.expect_err("ready 503 is a problem");

    match error {
        NotaryClientError::Problem {
            status, problem, ..
        } => {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(problem.code, "readiness.not_ready");
            assert_eq!(
                problem.request_id.as_deref(),
                Some("01J00000000000000000000000")
            );
            assert_eq!(problem.readiness_status.as_deref(), Some("not_ready"));
            let custody = &problem
                .checks
                .as_ref()
                .expect("readiness checks are retained")
                .signing_providers
                .custody;
            assert!(custody.custody_approval_required);
            assert!(!custody.custody_approved);
            assert_eq!(custody.unapproved_signing_provider_count, 1);
        }
        other => panic!("expected readiness problem, got {other:?}"),
    }
}

fn readiness_checks_json(custody_approved: bool, unapproved_count: usize) -> serde_json::Value {
    json!({
        "total": 3,
        "ok": if unapproved_count == 0 { 3 } else { 1 },
        "degraded": 0,
        "failed": usize::from(unapproved_count > 0),
        "signing_providers": {
            "total": 1,
            "ok": 1,
            "failed": 0,
            "custody": {
                "active_provider_counts": {
                    "pkcs11": 1,
                },
                "signing_provider_count": 1,
                "local_software_signing_provider_count": 0,
                "custody_approval_required": true,
                "custody_approved": custody_approved,
                "unapproved_signing_provider_count": unapproved_count,
                "surfaces": {
                    "credential_issuance": {
                        "signing_provider_count": 1,
                        "local_software_signing_provider_count": 0,
                        "unapproved_signing_provider_count": unapproved_count,
                    },
                    "access_token_issuance": {
                        "enabled": false,
                        "signing_provider_count": 0,
                        "local_software_signing_provider_count": 0,
                        "unapproved_signing_provider_count": 0,
                    },
                    "federation": {
                        "enabled": false,
                        "signing_provider_count": 0,
                        "local_software_signing_provider_count": 0,
                        "unapproved_signing_provider_count": 0,
                    },
                },
            },
        },
    })
}

#[tokio::test]
async fn jwks_uses_ttl_cache_and_refresh_forces_reload() {
    let state = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/.well-known/evidence/jwks.json", get(jwks_handler))
        .with_state(Arc::clone(&state));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .build()
        .expect("client builds");

    let first = client
        .issuer_jwks(RequestOptions::default())
        .await
        .expect("first fetch succeeds");
    let second = client
        .issuer_jwks(RequestOptions::default())
        .await
        .expect("second fetch uses cache");
    let refreshed = client
        .refresh_jwks(RequestOptions::default())
        .await
        .expect("refresh fetches network");

    assert_eq!(first.body["keys"][0]["kid"], "kid-1");
    assert_eq!(second.body["keys"][0]["kid"], "kid-1");
    assert_eq!(refreshed.body["keys"][0]["kid"], "kid-2");
    assert_eq!(state.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn metrics_returns_text_body() {
    let app = Router::new().route("/metrics", get(|| async { "requests_total 1\n" }));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .build()
        .expect("client builds");

    let response = client
        .metrics(RequestOptions::default())
        .await
        .expect("metrics parses");

    assert_eq!(response.body, "requests_total 1\n");
}

#[tokio::test]
async fn typed_route_methods_parse_success_responses_and_escape_paths() {
    let app = Router::new()
        .route("/healthz", get(health_handler))
        .route("/admin/v1/reload", post(admin_reload_handler))
        .route(
            "/openapi.json",
            get(|| async { Json(json!({ "openapi": "3.1.0" })) }),
        )
        .route(
            "/.well-known/evidence-service",
            get(|| async { Json(json!({ "issuer": "notary.example" })) }),
        )
        .route("/.well-known/evidence/jwks.json", get(jwks_static_handler))
        .route("/v1/claims/{claim_id}", get(claim_handler))
        .route(
            "/v1/formats",
            get(|| async {
                Json(json!({
                    "formats": [
                        { "id": FORMAT_CLAIM_RESULT_JSON, "kind": "json", "status": "active" }
                    ]
                }))
            }),
        )
        .route(
            "/v1/evaluations/{evaluation_id}/render",
            post(render_handler),
        )
        .route("/v1/credentials", post(issue_credential_handler))
        .route(
            "/v1/credentials/{credential_id}/status",
            get(credential_status_handler),
        )
        .route(
            "/admin/v1/credentials/{credential_id}/status",
            post(update_credential_status_handler),
        );
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .api_key("api-secret")
        .build()
        .expect("client builds");

    assert_eq!(client.health().await.expect("health").body.status, "ok");
    assert_eq!(
        client
            .admin_reload(RequestOptions::default())
            .await
            .expect("admin reload")
            .body
            .status,
        "noop"
    );
    assert_eq!(
        client
            .openapi_json(RequestOptions::default())
            .await
            .expect("openapi")
            .body["openapi"],
        "3.1.0"
    );
    assert_eq!(
        client
            .service_document(RequestOptions::default())
            .await
            .expect("service document")
            .body["issuer"],
        "notary.example"
    );
    assert_eq!(
        client
            .raw_issuer_jwks(RequestOptions::default())
            .await
            .expect("raw jwks")
            .body["keys"][0]["kid"],
        "kid-static"
    );
    assert_eq!(
        client
            .get_claim("claim one", RequestOptions::default())
            .await
            .expect("claim")
            .body["id"],
        "claim one"
    );
    assert_eq!(
        client
            .list_formats(RequestOptions::default())
            .await
            .expect("formats")
            .body
            .formats[0]
            .id,
        FORMAT_CLAIM_RESULT_JSON
    );
    assert_eq!(
        client
            .render_request(
                registry_notary_core::RenderRequest {
                    evaluation_id: "eval-1".to_string(),
                    format: FORMAT_CLAIM_RESULT_JSON.to_string(),
                    disclosure: None,
                    claims: None,
                    purpose: None,
                },
                RequestOptions::default(),
            )
            .await
            .expect("render")
            .body["rendered"],
        true
    );
    assert_eq!(
        client
            .issue_credential_request(
                registry_notary_core::CredentialIssueRequest {
                    evaluation_id: "eval-1".to_string(),
                    credential_profile: None,
                    format: None,
                    claims: None,
                    disclosure: None,
                    purpose: None,
                    holder: None,
                },
                RequestOptions::default(),
            )
            .await
            .expect("credential issue")
            .body
            .credential_id,
        "cred-1"
    );
    assert_eq!(
        client
            .credential_status("cred 1", RequestOptions::default())
            .await
            .expect("credential status")
            .body
            .status,
        "valid"
    );
    assert_eq!(
        client
            .update_credential_status("cred 1", "revoked", RequestOptions::default())
            .await
            .expect("credential status update")
            .body
            .status,
        "revoked"
    );
}

#[tokio::test]
async fn purpose_conflict_fails_client_side() {
    let app = Router::new().route("/v1/evaluations", post(evaluate_handler));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .default_purpose("header-purpose")
        .build()
        .expect("client builds");

    let error = client
        .evaluate_request(
            registry_notary_core::EvaluateRequest {
                requester: None,
                target: Some(registry_notary_core::EvidenceEntity::from_subject_request(
                    "Person",
                    registry_notary_core::SubjectRequest {
                        id: "subject-1".to_string(),
                        id_type: None,
                    },
                )),
                relationship: None,
                on_behalf_of: None,
                variables: Default::default(),
                claims: vec![registry_notary_core::ClaimRef::new("claim-a")],
                disclosure: None,
                format: None,
                purpose: Some("body-purpose".to_string()),
            },
            RequestOptions::default(),
        )
        .await
        .expect_err("purpose conflict fails before request");

    assert!(matches!(
        error,
        NotaryClientError::Build(NotaryClientBuildError::PurposeConflict)
    ));
}

#[tokio::test]
async fn raw_evaluate_preserves_body_only_purpose() {
    let app = Router::new().route("/v1/evaluations", post(body_purpose_evaluate_handler));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .build()
        .expect("client builds");

    let response = client
        .evaluate_request(
            registry_notary_core::EvaluateRequest {
                requester: None,
                target: Some(registry_notary_core::EvidenceEntity::from_subject_request(
                    "Person",
                    registry_notary_core::SubjectRequest {
                        id: "subject-1".to_string(),
                        id_type: None,
                    },
                )),
                relationship: None,
                on_behalf_of: None,
                variables: Default::default(),
                claims: vec![registry_notary_core::ClaimRef::new("claim-a")],
                disclosure: None,
                format: None,
                purpose: Some("body-purpose".to_string()),
            },
            RequestOptions::default(),
        )
        .await
        .expect("evaluate succeeds");

    assert!(response.body.results.is_empty());
}

#[tokio::test]
async fn raw_batch_preserves_body_only_purpose() {
    let app = Router::new().route("/v1/batch-evaluations", post(body_purpose_batch_handler));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .build()
        .expect("client builds");

    let response = client
        .batch_evaluate_request(
            registry_notary_core::BatchEvaluateRequest {
                items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                    registry_notary_core::BatchSubjectRequest {
                        id: "subject-1".to_string(),
                        id_type: None,
                        purpose: None,
                    },
                )],
                claims: vec![registry_notary_core::ClaimRef::new("claim-a")],
                disclosure: None,
                format: None,
                purpose: Some("body-purpose".to_string()),
            },
            RequestOptions::default(),
        )
        .await
        .expect("batch evaluate succeeds");

    assert_eq!(response.body.batch_id, "batch-1");
}

#[tokio::test]
async fn typed_batch_rejects_platform_ceiling_plus_one_before_transport() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/v1/batch-evaluations",
            post(|State(calls): State<Arc<AtomicUsize>>| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                body_purpose_batch_handler(
                    HeaderMap::new(),
                    Bytes::from_static(br#"{"purpose":"body-purpose"}"#),
                )
                .await
            }),
        )
        .with_state(Arc::clone(&calls));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .build()
        .expect("client builds");
    let item = registry_notary_core::BatchEvaluateItemRequest::from(
        registry_notary_core::BatchSubjectRequest {
            id: "subject-1".to_string(),
            id_type: None,
            purpose: None,
        },
    );
    let error = client
        .batch_evaluate_request(
            registry_notary_core::BatchEvaluateRequest {
                items: vec![item; MAX_BATCH_EVALUATION_MEMBERS_V1 + 1],
                claims: vec![registry_notary_core::ClaimRef::new("claim-a")],
                disclosure: None,
                format: None,
                purpose: Some("body-purpose".to_string()),
            },
            RequestOptions::default(),
        )
        .await
        .expect_err("the typed client rejects the hard ceiling plus one");

    assert!(matches!(
        error,
        NotaryClientError::Build(NotaryClientBuildError::BatchTooLarge {
            actual,
            maximum: MAX_BATCH_EVALUATION_MEMBERS_V1,
        }) if actual == MAX_BATCH_EVALUATION_MEMBERS_V1 + 1
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn raw_credential_issue_preserves_body_only_purpose() {
    let app = Router::new().route(
        "/v1/credentials",
        post(body_purpose_issue_credential_handler),
    );
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .build()
        .expect("client builds");

    let response = client
        .issue_credential_request(
            registry_notary_core::CredentialIssueRequest {
                evaluation_id: "eval-1".to_string(),
                credential_profile: None,
                format: None,
                claims: None,
                disclosure: None,
                purpose: Some("body-purpose".to_string()),
                holder: None,
            },
            RequestOptions::default(),
        )
        .await
        .expect("credential issue succeeds");

    assert_eq!(response.body.credential_id, "cred-1");
}

#[tokio::test]
async fn idempotency_is_rejected_on_routes_that_ignore_it() {
    let app = Router::new().route(
        "/v1/evaluations/{evaluation_id}/render",
        post(|| async { Json(json!({})) }),
    );
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .build()
        .expect("client builds");

    let error = client
        .render_request(
            registry_notary_core::RenderRequest {
                evaluation_id: "eval-1".to_string(),
                format: FORMAT_CLAIM_RESULT_JSON.to_string(),
                disclosure: None,
                claims: None,
                purpose: None,
            },
            RequestOptions::builder()
                .idempotency_key("ignored-key")
                .build(),
        )
        .await
        .expect_err("unsupported idempotency is rejected");

    assert!(matches!(
        error,
        NotaryClientError::Build(NotaryClientBuildError::UnsupportedIdempotencyKey)
    ));
}

#[tokio::test]
async fn batch_retry_requires_idempotency_key() {
    let state = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/v1/batch-evaluations", post(flaky_batch_handler))
        .with_state(Arc::clone(&state));
    let base = spawn(app).await;
    let retry_policy = RetryPolicy {
        max_attempts: 2,
        retry_unavailable: true,
        ..RetryPolicy::default()
    };
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .default_purpose("benefits")
        .retry_policy(retry_policy)
        .build()
        .expect("client builds");

    let request = registry_notary_core::BatchEvaluateRequest {
        items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
            registry_notary_core::BatchSubjectRequest {
                id: "subject-1".to_string(),
                id_type: None,
                purpose: None,
            },
        )],
        claims: vec![registry_notary_core::ClaimRef::new("claim-a")],
        disclosure: None,
        format: None,
        purpose: None,
    };

    let without_key = client
        .batch_evaluate_request(request.clone(), RequestOptions::default())
        .await
        .expect_err("without key no retry occurs");
    assert!(matches!(without_key, NotaryClientError::Problem { .. }));
    assert_eq!(state.load(Ordering::SeqCst), 1);
    state.store(0, Ordering::SeqCst);

    let with_key = client
        .batch_evaluate_request(
            request,
            RequestOptions::builder()
                .idempotency_key("batch-key")
                .build(),
        )
        .await
        .expect("with idempotency key retry succeeds");
    assert_eq!(with_key.body.batch_id, "batch-1");
    assert_eq!(state.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn retry_after_delta_on_problem_controls_retry_delay() {
    let state = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/v1/claims", get(retry_after_then_claims_handler))
        .with_state(Arc::clone(&state));
    let base = spawn(app).await;
    let retry_policy = RetryPolicy {
        max_attempts: 2,
        base_delay: Duration::from_secs(5),
        max_delay: Duration::from_secs(5),
        retry_unavailable: true,
        ..RetryPolicy::default()
    };
    let client = RegistryNotaryClient::builder(base)
        .retry_policy(retry_policy)
        .build()
        .expect("client builds");

    let started = Instant::now();
    let response = client
        .list_claims(RequestOptions::default())
        .await
        .expect("retry-after zero allows immediate retry");

    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(response.body.data.is_empty());
    assert_eq!(state.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn retry_after_http_date_uses_server_date_for_retry_delay() {
    let state = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/v1/claims", get(retry_after_http_date_then_claims_handler))
        .with_state(Arc::clone(&state));
    let base = spawn(app).await;
    let retry_policy = RetryPolicy {
        max_attempts: 2,
        base_delay: Duration::from_secs(5),
        max_delay: Duration::from_secs(5),
        retry_unavailable: true,
        ..RetryPolicy::default()
    };
    let client = RegistryNotaryClient::builder(base)
        .retry_policy(retry_policy)
        .build()
        .expect("client builds");

    let started = Instant::now();
    let response = client
        .list_claims(RequestOptions::default())
        .await
        .expect("retry-after HTTP-date equal to server date allows immediate retry");

    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(response.body.data.is_empty());
    assert_eq!(state.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn accepted_status_decode_error_keeps_response_status() {
    let app = Router::new().route(
        "/ready",
        get(|| async {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [("x-request-id", "req-ready-decode")],
                "not-json",
            )
        }),
    );
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .build()
        .expect("client builds");

    let error = client.ready().await.expect_err("invalid ready JSON fails");

    match error {
        NotaryClientError::Decode { status, request_id } => {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(request_id.as_deref(), Some("req-ready-decode"));
        }
        other => panic!("expected decode error, got {other:?}"),
    }
}

#[tokio::test]
async fn decode_error_display_is_opaque() {
    let app = Router::new().route(
        "/v1/claims",
        get(|| async {
            (
                StatusCode::OK,
                [("x-request-id", "req-decode")],
                "not-json-with-secret-token",
            )
        }),
    );
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .build()
        .expect("client builds");

    let error = client
        .list_claims(RequestOptions::default())
        .await
        .expect_err("invalid JSON fails");
    assert_eq!(error.to_string(), "failed to decode response body");
    assert!(!format!("{error:?}").contains("not-json-with-secret-token"));
    assert_eq!(error.request_id(), Some("req-decode"));
}

#[tokio::test]
async fn problem_debug_redacts_detail() {
    let app = Router::new().route("/v1/claims", get(problem_with_sensitive_detail));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .build()
        .expect("client builds");

    let error = client
        .list_claims(RequestOptions::default())
        .await
        .expect_err("problem maps");
    assert!(!format!("{error:?}").contains("subj-sensitive"));
    assert!(!error.to_string().contains("subj-sensitive"));
}

#[tokio::test]
async fn body_too_large_error_is_opaque_and_carries_request_id() {
    let body = format!("credential-secret-{}", "x".repeat(80 * 1024));
    let app = Router::new().route(
        "/healthz",
        get(move || {
            let body = body.clone();
            async move { (StatusCode::OK, [("x-request-id", "req-large")], body) }
        }),
    );
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .build()
        .expect("client builds");

    let error = client.health().await.expect_err("body cap triggers");
    assert!(matches!(error, NotaryClientError::BodyTooLarge { .. }));
    assert_eq!(error.request_id(), Some("req-large"));
    assert_eq!(
        error.to_string(),
        "response body exceeded configured size limit"
    );
    assert!(!format!("{error:?}").contains("credential-secret"));
}

#[tokio::test]
async fn content_encoding_header_is_not_auto_decompressed() {
    let app = Router::new().route(
        "/v1/claims",
        get(|| async {
            (
                StatusCode::OK,
                [("content-encoding", "gzip")],
                Json(json!({ "data": [] })),
            )
        }),
    );
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .build()
        .expect("client builds");

    let response = client
        .list_claims(RequestOptions::default())
        .await
        .expect("plain body is not decompressed despite header");
    assert!(response.body.data.is_empty());
}

#[cfg(feature = "federation")]
#[tokio::test]
async fn federation_posts_already_signed_jws_without_minting() {
    let app = Router::new().route("/federation/v1/evaluations", post(federation_handler));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .build()
        .expect("client builds");

    let response = client
        .federation_evaluate_jws("header.payload.signature", RequestOptions::default())
        .await
        .expect("federation succeeds");

    assert_eq!(response.body, "signed-response-jws");
}

#[cfg(feature = "oid4vci")]
#[tokio::test]
async fn oid4vci_errors_use_oid4vci_envelope() {
    let app = Router::new().route(
        "/oid4vci/credential",
        post(|| async {
            (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                Json(json!({
                    "error": "invalid_request",
                    "error_description": "nonce request contained sensitive value subj-1"
                })),
            )
        }),
    );
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .build()
        .expect("client builds");

    let error = client
        .oid4vci_credential(
            registry_platform_oid4vci::CredentialRequest {
                format: registry_platform_oid4vci::SD_JWT_VC_FORMAT.to_string(),
                credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
                credential_configuration_id: None,
                vct: None,
                proof: registry_platform_oid4vci::CredentialRequestProof {
                    proof_type: registry_platform_oid4vci::PROOF_TYPE_JWT.to_string(),
                    jwt: "proof-jwt".to_string(),
                },
                proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
            },
            RequestOptions::default(),
        )
        .await
        .expect_err("oid4vci error maps");

    assert_eq!(error.to_string(), "openid4vci error: invalid_request");
    assert!(!format!("{error:?}").contains("subj-1"));

    match error {
        NotaryClientError::Oid4vci { error, .. } => {
            assert_eq!(error.error, "invalid_request");
            let portable = NotaryClientError::Oid4vci {
                status: StatusCode::BAD_REQUEST,
                error,
                request_id: None,
                retry_after: None,
            }
            .portable();
            let rendered = serde_json::to_value(portable).expect("portable serializes");
            assert!(rendered.get("detail").is_none());
            assert!(!rendered.to_string().contains("subj-1"));
        }
        other => panic!("expected oid4vci error, got {other:?}"),
    }
}

#[cfg(feature = "oid4vci")]
#[tokio::test]
async fn oid4vci_success_routes_parse_typed_responses() {
    let app = Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(oid4vci_metadata_handler),
        )
        .route("/oid4vci/credential", post(oid4vci_credential_handler));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .build()
        .expect("client builds");

    let metadata = client
        .oid4vci_issuer_metadata(RequestOptions::default())
        .await
        .expect("metadata");
    let credential = client
        .oid4vci_credential(
            registry_platform_oid4vci::CredentialRequest {
                format: registry_platform_oid4vci::SD_JWT_VC_FORMAT.to_string(),
                credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
                credential_configuration_id: None,
                vct: None,
                proof: registry_platform_oid4vci::CredentialRequestProof {
                    proof_type: registry_platform_oid4vci::PROOF_TYPE_JWT.to_string(),
                    jwt: "proof-jwt".to_string(),
                },
                proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
            },
            RequestOptions::default(),
        )
        .await
        .expect("credential");

    assert_eq!(metadata.body.credential_issuer, "https://issuer.example");
    assert_eq!(
        credential.body.credential,
        registry_platform_oid4vci::CredentialValue::from("sd-jwt-credential")
    );

    let metadata_debug = format!("{metadata:?}");
    assert!(metadata_debug.contains("https://issuer.example"));

    let credential_debug = format!("{credential:?}");
    assert!(credential_debug.contains("<redacted>"));
    assert!(!credential_debug.contains("sd-jwt-credential"));
    assert!(!credential_debug.contains("proof-jwt"));
}

#[cfg(all(feature = "oid4vci", feature = "verifier"))]
#[tokio::test]
async fn oid4vci_verifier_rejects_object_credential_shape_before_jwks_fetch() {
    let client = RegistryNotaryClient::builder("http://127.0.0.1:9")
        .build()
        .expect("client builds");
    let response = registry_platform_oid4vci::CredentialResponse {
        credential: registry_platform_oid4vci::CredentialValue::Object(json!({
            "credential": "not-a-compact-sd-jwt"
        })),
        credentials: Vec::new(),
        format: Some(registry_platform_oid4vci::SD_JWT_VC_FORMAT.to_string()),
        c_nonce: None,
        c_nonce_expires_in: None,
    };

    let error = client
        .verify_oid4vci_credential(
            &response,
            registry_notary_client::VerifyOptions::new("https://issuer.example"),
        )
        .await
        .expect_err("object credential shape is not a compact SD-JWT VC");

    assert_eq!(error.code(), "credential.unsupported_shape");
}

async fn evaluate_handler(headers: HeaderMap, body: Bytes) -> Response {
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer bearer-secret")
    );
    assert_eq!(
        headers.get("accept").and_then(|value| value.to_str().ok()),
        Some(FORMAT_CLAIM_RESULT_JSON)
    );
    assert_eq!(
        headers
            .get("data-purpose")
            .and_then(|value| value.to_str().ok()),
        Some("benefits")
    );
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body parses");
    assert_eq!(parsed["format"], json!(FORMAT_CLAIM_RESULT_JSON));
    assert_eq!(parsed["target"]["type"], json!("Person"));
    assert_eq!(
        parsed["target"]["identifiers"],
        json!([{
            "scheme": "NATIONAL_ID",
            "value": "subject-1",
            "issuer": "civil_registry"
        }])
    );
    assert_eq!(parsed["relationship"]["type"], json!("self"));
    assert_eq!(parsed["variables"]["as_of_date"], json!("2026-01-01"));
    (
        StatusCode::OK,
        [("x-request-id", "req-123")],
        Json(json!({ "results": [] })),
    )
        .into_response()
}

async fn body_purpose_evaluate_handler(headers: HeaderMap, body: Bytes) -> Response {
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer bearer-secret")
    );
    assert_eq!(
        headers
            .get("data-purpose")
            .and_then(|value| value.to_str().ok()),
        Some("body-purpose")
    );
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body parses");
    assert_eq!(parsed["purpose"], json!("body-purpose"));
    assert_eq!(parsed["format"], json!(FORMAT_CLAIM_RESULT_JSON));
    Json(json!({ "results": [] })).into_response()
}

async fn body_purpose_batch_handler(headers: HeaderMap, body: Bytes) -> Response {
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer bearer-secret")
    );
    assert_eq!(
        headers
            .get("data-purpose")
            .and_then(|value| value.to_str().ok()),
        Some("body-purpose")
    );
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body parses");
    assert_eq!(parsed["purpose"], json!("body-purpose"));
    assert_eq!(parsed["format"], json!(FORMAT_CLAIM_RESULT_JSON));
    Json(json!({
        "batch_id": "batch-1",
        "status": "completed",
        "claims": ["claim-a"],
        "items": [],
        "summary": { "succeeded": 0, "failed": 0 }
    }))
    .into_response()
}

async fn body_purpose_issue_credential_handler(headers: HeaderMap, body: Bytes) -> Response {
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer bearer-secret")
    );
    assert_eq!(
        headers
            .get("data-purpose")
            .and_then(|value| value.to_str().ok()),
        Some("body-purpose")
    );
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("issue body parses");
    assert_eq!(parsed["purpose"], json!("body-purpose"));
    issue_credential_json()
}

async fn health_handler() -> Response {
    Json(json!({ "status": "ok", "checks": {} })).into_response()
}

async fn base_path_health_handler(uri: Uri) -> Response {
    assert_eq!(uri.path(), "/tenant%20one/healthz");
    health_handler().await
}

async fn admin_reload_handler(headers: HeaderMap) -> Response {
    assert_eq!(
        headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok()),
        Some("api-secret")
    );
    Json(json!({ "reloaded": false, "status": "noop", "detail": "unchanged" })).into_response()
}

async fn jwks_static_handler() -> Response {
    Json(json!({ "keys": [{ "kty": "OKP", "kid": "kid-static", "crv": "Ed25519", "x": "abc" }] }))
        .into_response()
}

async fn claim_handler(Path(claim_id): Path<String>, uri: Uri) -> Response {
    assert_eq!(uri.path(), "/v1/claims/claim%20one");
    Json(json!({ "id": claim_id, "title": "Claim One" })).into_response()
}

async fn render_handler(Path(evaluation_id): Path<String>, body: Bytes) -> Response {
    assert_eq!(evaluation_id, "eval-1");
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("render body parses");
    assert!(parsed.get("evaluation_id").is_none());
    Json(json!({ "rendered": true })).into_response()
}

async fn issue_credential_handler(body: Bytes) -> Response {
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("issue body parses");
    assert_eq!(parsed["evaluation_id"], "eval-1");
    issue_credential_json()
}

fn issue_credential_json() -> Response {
    Json(json!({
        "credential_id": "cred-1",
        "credential_profile": "profile-1",
        "format": "application/dc+sd-jwt",
        "issuer": "did:web:notary.example",
        "expires_at": "2026-05-29T00:00:00Z",
        "credential": "issuer.jwt~disclosure~",
        "issuer_signed_jwt": "issuer.jwt",
        "disclosures": ["disclosure"]
    }))
    .into_response()
}

async fn credential_status_handler(Path(credential_id): Path<String>, uri: Uri) -> Response {
    assert_eq!(uri.path(), "/v1/credentials/cred%201/status");
    Json(credential_status_json(&credential_id, "valid")).into_response()
}

async fn update_credential_status_handler(
    Path(credential_id): Path<String>,
    body: Bytes,
) -> Response {
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("status body parses");
    assert_eq!(parsed["status"], "revoked");
    Json(credential_status_json(&credential_id, "revoked")).into_response()
}

fn credential_status_json(credential_id: &str, status: &str) -> serde_json::Value {
    json!({
        "credential_id": credential_id,
        "issuer": "did:web:notary.example",
        "credential_profile": "profile-1",
        "status": status,
        "issued_at": "2026-05-29T00:00:00Z",
        "expires_at": "2026-05-30T00:00:00Z",
        "updated_at": "2026-05-29T01:00:00Z"
    })
}

async fn flaky_batch_handler(
    State(counter): State<Arc<AtomicUsize>>,
    headers: HeaderMap,
) -> Response {
    let call = counter.fetch_add(1, Ordering::SeqCst) + 1;
    if call == 1 {
        return problem(StatusCode::SERVICE_UNAVAILABLE);
    }
    if headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        != Some("batch-key")
    {
        return problem(StatusCode::SERVICE_UNAVAILABLE);
    }
    Json(json!({
        "batch_id": "batch-1",
        "status": "completed",
        "claims": ["claim-a"],
        "items": [],
        "summary": { "succeeded": 0, "failed": 0 }
    }))
    .into_response()
}

async fn retry_after_then_claims_handler(State(counter): State<Arc<AtomicUsize>>) -> Response {
    let call = counter.fetch_add(1, Ordering::SeqCst) + 1;
    if call == 1 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("retry-after", "0")],
            Json(json!({
                "type": "https://id.registrystack.org/problems/registry-notary/source/unavailable",
                "title": "Evidence not available",
                "status": 503,
                "detail": "evidence not available",
                "code": "evidence.not_available"
            })),
        )
            .into_response();
    }
    Json(json!({ "data": [] })).into_response()
}

async fn retry_after_http_date_then_claims_handler(
    State(counter): State<Arc<AtomicUsize>>,
) -> Response {
    let call = counter.fetch_add(1, Ordering::SeqCst) + 1;
    if call == 1 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                ("retry-after", "Wed, 31 Dec 2099 00:00:00 GMT"),
                ("date", "Wed, 31 Dec 2099 00:00:00 GMT"),
            ],
            Json(json!({
                "type": "https://id.registrystack.org/problems/registry-notary/source/unavailable",
                "title": "Evidence not available",
                "status": 503,
                "detail": "evidence not available",
                "code": "evidence.not_available"
            })),
        )
            .into_response();
    }
    Json(json!({ "data": [] })).into_response()
}

async fn jwks_handler(State(counter): State<Arc<AtomicUsize>>) -> Response {
    let call = counter.fetch_add(1, Ordering::SeqCst) + 1;
    Json(json!({
        "keys": [
            { "kty": "OKP", "kid": format!("kid-{call}"), "crv": "Ed25519", "x": "abc" }
        ]
    }))
    .into_response()
}

#[cfg(feature = "federation")]
async fn federation_handler(headers: HeaderMap, body: Bytes) -> Response {
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/jwt")
    );
    assert_eq!(body.as_ref(), b"header.payload.signature");
    "signed-response-jws".into_response()
}

#[cfg(feature = "oid4vci")]
async fn oid4vci_metadata_handler() -> Response {
    Json(json!({
        "credential_issuer": "https://issuer.example",
        "credential_endpoint": "https://issuer.example/oid4vci/credential",
        "credential_configurations_supported": {}
    }))
    .into_response()
}

#[cfg(feature = "oid4vci")]
async fn oid4vci_credential_handler(body: Bytes) -> Response {
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("credential body parses");
    assert_eq!(parsed["proof"]["jwt"], "proof-jwt");
    Json(json!({
        "credential": "sd-jwt-credential",
        "format": "dc+sd-jwt"
    }))
    .into_response()
}

fn problem(status: StatusCode) -> Response {
    (
        status,
        [("content-type", "application/problem+json")],
        Json(json!({
            "type": "https://id.registrystack.org/problems/registry-notary/source/unavailable",
            "title": "Evidence not available",
            "status": status.as_u16(),
            "detail": "the requested evidence is unavailable",
            "code": "evidence.not_available"
        })),
    )
        .into_response()
}

async fn problem_with_sensitive_detail() -> Response {
    (
        StatusCode::NOT_FOUND,
        [("content-type", "application/problem+json")],
        Json(json!({
            "type": "https://id.registrystack.org/problems/registry-notary/source/not-found",
            "title": "Source missing",
            "status": 404,
            "detail": "subject subj-sensitive was not found",
            "code": "source.not_found"
        })),
    )
        .into_response()
}

async fn spawn(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test server binds");
    let addr: SocketAddr = listener.local_addr().expect("local addr available");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test server serves");
    });
    format!("http://{addr}")
}
