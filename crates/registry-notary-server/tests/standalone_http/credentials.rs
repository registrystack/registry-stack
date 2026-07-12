// SPDX-License-Identifier: Apache-2.0

use super::support::*;
#[allow(unused_imports)]
use super::{
    admin::*, audit::*, auth::*, federation::*, http_contracts::*, oid4vci::*, preauth::*,
    sources::*,
};

#[tokio::test]
pub(super) async fn direct_credential_pre_evaluation_denials_are_audited_and_redacted() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_oidc_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let authorization = format!("Bearer {token}");
    let invalid_classification_token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "openid",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let invalid_classification_authorization = format!("Bearer {invalid_classification_token}");
    const UNKNOWN_EVALUATION_ID: &str = "attacker-controlled-unknown-evaluation";
    const IDEMPOTENCY_EVALUATION_ID: &str = "idempotency-evaluation-not-read";
    const CLASSIFICATION_EVALUATION_ID: &str = "classification-evaluation-not-read";
    let cases = vec![
        (
            "malformed JSON",
            authorization.clone(),
            None,
            false,
            StatusCode::BAD_REQUEST,
            "request.invalid",
            "request.invalid",
            None,
            None,
        ),
        (
            "missing evaluation id",
            authorization.clone(),
            Some(json!({})),
            false,
            StatusCode::BAD_REQUEST,
            "request.invalid",
            "request.invalid",
            None,
            None,
        ),
        (
            "unsupported idempotency key",
            authorization.clone(),
            Some(json!({"evaluation_id": IDEMPOTENCY_EVALUATION_ID})),
            true,
            StatusCode::BAD_REQUEST,
            "request.invalid",
            "request.invalid",
            None,
            None,
        ),
        (
            "unknown evaluation id",
            authorization.clone(),
            Some(json!({"evaluation_id": UNKNOWN_EVALUATION_ID})),
            false,
            StatusCode::NOT_FOUND,
            "evaluation.not_found",
            "evaluation.not_found",
            None,
            None,
        ),
        (
            "self-attestation classification denial",
            invalid_classification_authorization.clone(),
            Some(json!({"evaluation_id": CLASSIFICATION_EVALUATION_ID})),
            false,
            StatusCode::FORBIDDEN,
            "self_attestation.denied",
            "self_attestation.invalid_token",
            Some("self_attestation.invalid_token"),
            Some(("self_attestation", "national_id")),
        ),
    ];

    for (
        index,
        (
            name,
            case_authorization,
            payload,
            idempotency_key,
            status,
            code,
            audit_code,
            denial_code,
            attestation_context,
        ),
    ) in cases.into_iter().enumerate()
    {
        let request = server
            .post("/v1/credentials")
            .add_header("authorization", case_authorization);
        let request = if idempotency_key {
            request.add_header("idempotency-key", "unsupported-idempotency-key")
        } else {
            request
        };
        let response = match payload {
            Some(payload) => request.json(&payload).await,
            None => {
                request
                    .add_header(header::CONTENT_TYPE, "application/json")
                    .text("{")
                    .await
            }
        };
        response.assert_status(status);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/problem+json"),
            "{name} returns problem+json"
        );
        let body: Value = response.json();
        assert_problem_identity(&body, status, code);
        for field in [
            "credential",
            "credential_id",
            "issuer_signed_jwt",
            "disclosures",
        ] {
            assert!(body.get(field).is_none(), "{name} has no {field}");
        }
        let body_text = serde_json::to_string(&body).expect("problem body serializes");
        assert!(!body_text.contains(&token), "{name} does not echo token");
        for evaluation_id in [
            UNKNOWN_EVALUATION_ID,
            IDEMPOTENCY_EVALUATION_ID,
            CLASSIFICATION_EVALUATION_ID,
        ] {
            assert!(
                !body_text.contains(evaluation_id),
                "{name} does not echo an untrusted evaluation id"
            );
        }

        let records = audit_records_from_envelopes(&audit_path);
        let credential_records = records
            .iter()
            .filter(|record| record["path"] == json!("/v1/credentials"))
            .collect::<Vec<_>>();
        assert_eq!(
            credential_records.len(),
            index + 1,
            "{name} writes one credential audit record"
        );
        let denied = credential_records
            .last()
            .expect("new credential denial audit record exists");
        assert_eq!(denied["decision"], json!("credential_denied"), "{name}");
        assert_eq!(denied["status"], json!(status.as_u16()), "{name}");
        assert_eq!(denied["error_code"], json!(audit_code), "{name}");
        assert_eq!(denied["source_read_count"], json!(0), "{name}");
        assert_eq!(denied["forwarded"], json!(false), "{name}");
        match denial_code {
            Some(denial_code) => assert_eq!(denied["denial_code"], json!(denial_code), "{name}"),
            None => assert!(denied.get("denial_code").is_none(), "{name}"),
        }
        if let Some((access_mode, token_claim_name)) = attestation_context {
            assert_eq!(denied["access_mode"], json!(access_mode), "{name}");
            assert_eq!(
                denied["token_claim_name"],
                json!(token_claim_name),
                "{name}"
            );
        }
        assert!(
            denied.get("verification_id").is_none(),
            "{name} has no untrusted verification id"
        );
        for field in [
            "credential",
            "credential_id",
            "issuer_signed_jwt",
            "disclosures",
        ] {
            assert!(denied.get(field).is_none(), "{name} audit has no {field}");
        }
        assert!(
            !audit_record_contains_text(denied, &token),
            "{name} audit does not contain the token"
        );
        assert!(
            !audit_record_contains_text(denied, UNKNOWN_EVALUATION_ID),
            "{name} audit does not contain the unknown evaluation id"
        );
        assert!(!records.iter().any(|record| {
            record["path"] == json!("/v1/credentials")
                && record["decision"] == json!("credential_issued")
        }));
    }
    let records = audit_records_from_envelopes(&audit_path);
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            &invalid_classification_token,
            &invalid_classification_authorization,
            UNKNOWN_EVALUATION_ID,
            IDEMPOTENCY_EVALUATION_ID,
            CLASSIFICATION_EVALUATION_ID,
            "unsupported-idempotency-key",
            "person-1",
            "citizen-subject",
            "source-token",
        ],
    );

    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn direct_credentials_issue_creates_retrievable_status_record() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_credential_status(&mut config);
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned")
        .to_string();
    let holder_id = holder_did_jwk();
    let proof =
        sign_direct_holder_proof(&holder_id, &evaluation_id, "direct-credential-status-jti-1");

    let issue = server
        .post("/v1/credentials")
        .add_header("authorization", authorization)
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": proof
            }
        }))
        .await;
    issue.assert_status_ok();
    let issue_body: Value = issue.json();
    assert_eq!(
        issue_body["credential_profile"],
        json!("civil_status_sd_jwt")
    );
    let issuer_signed_jwt = issue_body["issuer_signed_jwt"]
        .as_str()
        .expect("issuer signed JWT returned");
    let header_segment = issuer_signed_jwt
        .split('.')
        .next()
        .expect("issuer signed JWT has protected header");
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header_segment)
            .expect("issuer signed JWT header is base64url"),
    )
    .expect("issuer signed JWT header is JSON");
    assert_eq!(header["alg"], json!("EdDSA"));
    assert_eq!(header["typ"], json!("dc+sd-jwt"));
    assert_eq!(header["kid"], json!("did:web:issuer.example#key-1"));
    let credential_id = issue_body["credential_id"]
        .as_str()
        .expect("credential id returned");

    let status = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .await;
    status.assert_status_ok();
    let status_body: Value = status.json();
    assert_eq!(status_body["credential_id"], json!(credential_id));
    assert_eq!(status_body["status"], json!("valid"));
    assert_eq!(
        status_body["credential_profile"],
        json!("civil_status_sd_jwt")
    );

    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn direct_credential_operation_denial_is_audited_and_preserves_denial_code() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(
                move |headers: HeaderMap, query: Query<BTreeMap<String, String>>| {
                    let source_hits = Arc::clone(&source_hits_for_route);
                    async move {
                        source_hits.fetch_add(1, Ordering::SeqCst);
                        self_attestation_registry_data_api(headers, query).await
                    }
                },
            ),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    assert!(config.self_attestation.allowed_operations.evaluate);
    assert!(!config.self_attestation.allowed_operations.issue_credential);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned")
        .to_string();
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);
    let holder_id = holder_did_jwk();
    let proof = sign_direct_holder_proof(&holder_id, &evaluation_id, "operation-denied-jti-1");

    let issue = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": proof
            }
        }))
        .await;
    issue.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        issue
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let body: Value = issue.json();
    assert_problem_identity(&body, StatusCode::FORBIDDEN, "self_attestation.denied");
    for field in [
        "credential",
        "credential_id",
        "issuer_signed_jwt",
        "disclosures",
    ] {
        assert!(body.get(field).is_none(), "denial has no {field}");
    }
    assert_eq!(
        source_hits.load(Ordering::SeqCst),
        0,
        "credential denial does not read the source again"
    );

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_denied",
        StatusCode::FORBIDDEN,
        "self_attestation.operation_denied",
    );
    assert_eq!(
        denied["denial_code"],
        json!("self_attestation.operation_denied")
    );
    assert_eq!(denied["verification_id"], json!(evaluation_id));
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
    assert_eq!(denied["credential_profile"], json!("civil_status_sd_jwt"));
    assert_eq!(denied["holder_binding_mode"], json!("did"));
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    for field in [
        "credential",
        "credential_id",
        "issuer_signed_jwt",
        "disclosures",
    ] {
        assert!(denied.get(field).is_none(), "audit has no {field}");
    }
    assert!(!records.iter().any(|record| {
        record["path"] == json!("/v1/credentials")
            && record["decision"] == json!("credential_issued")
    }));
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            &proof,
            &holder_id,
            "operation-denied-jti-1",
            "person-1",
            "citizen-subject",
            "source-token",
        ],
    );

    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn direct_credential_rate_limit_is_audited_with_stored_context() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(
                move |headers: HeaderMap, query: Query<BTreeMap<String, String>>| {
                    let source_hits = Arc::clone(&source_hits_for_route);
                    async move {
                        source_hits.fetch_add(1, Ordering::SeqCst);
                        self_attestation_registry_data_api(headers, query).await
                    }
                },
            ),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .self_attestation
        .rate_limits
        .credential_issuance_per_principal_per_hour = 1;
    config.self_attestation.token_policy.max_auth_age_seconds = 60;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let authorization = format!("Bearer {token}");
    let stale_token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now - 3600,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let stale_authorization = format!("Bearer {stale_token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned")
        .to_string();
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);
    let holder_id = holder_did_jwk();
    let first_proof = sign_direct_holder_proof(&holder_id, &evaluation_id, "rate-limit-first-jti");
    let second_proof =
        sign_direct_holder_proof(&holder_id, &evaluation_id, "rate-limit-second-jti");

    let stale = server
        .post("/v1/credentials")
        .add_header("authorization", stale_authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": first_proof.clone()
            }
        }))
        .await;
    stale.assert_status(StatusCode::FORBIDDEN);
    let stale_body: Value = stale.json();
    assert_problem_identity(
        &stale_body,
        StatusCode::FORBIDDEN,
        "self_attestation.denied",
    );
    for field in [
        "credential",
        "credential_id",
        "issuer_signed_jwt",
        "disclosures",
    ] {
        assert!(
            stale_body.get(field).is_none(),
            "stale token has no {field}"
        );
    }
    let records = audit_records_from_envelopes(&audit_path);
    let assurance_denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_denied",
        StatusCode::FORBIDDEN,
        "self_attestation.assurance_denied",
    );
    assert_eq!(
        assurance_denied["denial_code"],
        json!("self_attestation.assurance_denied")
    );
    assert_eq!(assurance_denied["source_read_count"], json!(0));
    assert_eq!(assurance_denied["forwarded"], json!(false));
    assert_eq!(source_hits.load(Ordering::SeqCst), 0);
    assert!(!records.iter().any(|record| {
        record["path"] == json!("/v1/credentials")
            && record["decision"] == json!("credential_issued")
    }));

    let first = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": first_proof
            }
        }))
        .await;
    first.assert_status_ok();
    let first_body: Value = first.json();
    let issued_credential = first_body["credential"]
        .as_str()
        .expect("first credential is returned")
        .to_string();

    let limited = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": second_proof
            }
        }))
        .await;
    limited.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        limited
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let limited_body: Value = limited.json();
    assert_problem_identity(
        &limited_body,
        StatusCode::TOO_MANY_REQUESTS,
        "self_attestation.rate_limited",
    );
    for field in [
        "credential",
        "credential_id",
        "issuer_signed_jwt",
        "disclosures",
    ] {
        assert!(
            limited_body.get(field).is_none(),
            "rate limit has no {field}"
        );
    }
    assert_eq!(
        source_hits.load(Ordering::SeqCst),
        0,
        "credential requests do not read the source again"
    );

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_issue_rate_limited",
        StatusCode::TOO_MANY_REQUESTS,
        "self_attestation.rate_limited",
    );
    assert_eq!(
        denied["denial_code"],
        json!("self_attestation.rate_limited")
    );
    assert_eq!(
        denied["rate_limit_bucket"],
        json!("credential_issuance_per_principal")
    );
    assert_eq!(denied["verification_id"], json!(evaluation_id));
    assert_eq!(denied["credential_profile"], json!("civil_status_sd_jwt"));
    assert_eq!(denied["holder_binding_mode"], json!("did"));
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
    assert_eq!(denied["purposes"], json!(["citizen_self_attestation"]));
    assert!(denied["claim_hash"].as_str().is_some());
    assert_eq!(denied["target_type"], json!("Person"));
    assert!(denied["target_ref_hash"].as_str().is_some());
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    for field in [
        "credential",
        "credential_id",
        "issuer_signed_jwt",
        "disclosures",
    ] {
        assert!(denied.get(field).is_none(), "audit has no {field}");
    }
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                record["path"] == json!("/v1/credentials")
                    && record["decision"] == json!("credential_issued")
            })
            .count(),
        1,
        "only the first request issues a credential"
    );
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            &stale_token,
            &stale_authorization,
            &first_proof,
            &second_proof,
            &holder_id,
            &issued_credential,
            "rate-limit-first-jti",
            "rate-limit-second-jti",
            "person-1",
            "citizen-subject",
            "source-token",
        ],
    );

    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn direct_credential_holder_proof_replay_is_audited_and_redacted() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned")
        .to_string();
    let holder_id = holder_did_jwk();
    let proof = sign_direct_holder_proof(&holder_id, &evaluation_id, "direct-replay-jti-1");
    let credential_request = json!({
        "evaluation_id": evaluation_id,
        "credential_profile": "civil_status_sd_jwt",
        "format": "application/dc+sd-jwt",
        "claims": ["person-is-alive"],
        "disclosure": "value",
        "holder": {
            "binding": "did",
            "id": holder_id,
            "proof": proof
        }
    });

    let first = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&credential_request)
        .await;
    first.assert_status_ok();
    let first_body: Value = first.json();
    assert!(first_body["credential"].is_string());

    let replay = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&credential_request)
        .await;
    replay.assert_status(StatusCode::CONFLICT);
    assert_eq!(
        replay
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let replay_body: Value = replay.json();
    assert_problem_identity(
        &replay_body,
        StatusCode::CONFLICT,
        "credential.holder_proof_replay",
    );
    assert!(replay_body.get("credential").is_none());
    assert!(replay_body.get("credential_id").is_none());
    assert!(replay_body.get("issuer_signed_jwt").is_none());
    assert!(replay_body.get("disclosures").is_none());
    let replay_body_text = serde_json::to_string(&replay_body).expect("problem body serializes");
    assert!(!replay_body_text.contains(&token));
    assert!(!replay_body_text.contains("person-1"));
    assert!(!replay_body_text.contains("direct-replay-jti-1"));

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_denied",
        StatusCode::CONFLICT,
        "credential.holder_proof_replay",
    );
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
    assert_eq!(denied["credential_profile"], json!("civil_status_sd_jwt"));
    assert_eq!(denied["holder_binding_mode"], json!("did"));
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    assert!(denied.get("principal_id").is_none());
    assert!(denied["principal_id_hash"]
        .as_str()
        .expect("principal id hash is present")
        .starts_with("hmac-sha256:"));
    assert!(denied.get("correlation_id").is_none());
    assert!(denied["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is present")
        .starts_with("hmac-sha256:"));
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                record["path"] == json!("/v1/credentials")
                    && record["decision"] == json!("credential_issued")
            })
            .count(),
        1,
        "first use should issue exactly one credential"
    );
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            &proof,
            "direct-replay-jti-1",
            "person-1",
            "citizen-subject",
            "source-token",
        ],
    );

    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn strict_credentials_issue_rejects_oid4vci_proof_at_http_boundary() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned");
    let proof = sign_oid4vci_proof("registry-notary", "nonce-1");

    let issue = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "holder": {
                "binding": "did",
                "id": holder_did_jwk(),
                "proof": proof.clone()
            }
        }))
        .await;
    issue.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        issue
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let body: Value = issue.json();
    assert_problem_identity(
        &body,
        StatusCode::BAD_REQUEST,
        "credential.holder_proof_required",
    );
    assert!(body.get("credential").is_none());
    assert!(body.get("issuer_signed_jwt").is_none());
    assert!(body.get("disclosures").is_none());
    let body_text = serde_json::to_string(&body).expect("problem body serializes");
    assert!(!body_text.contains(&proof));
    assert!(!body_text.contains(&token));
    assert!(!body_text.contains("person-1"));

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_denied",
        StatusCode::BAD_REQUEST,
        "credential.holder_proof_required",
    );
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
    assert_eq!(denied["credential_profile"], json!("civil_status_sd_jwt"));
    assert_eq!(denied["holder_binding_mode"], json!("did"));
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    assert!(denied.get("principal_id").is_none());
    assert!(denied["principal_id_hash"]
        .as_str()
        .expect("principal id hash is present")
        .starts_with("hmac-sha256:"));
    assert!(denied.get("correlation_id").is_none());
    assert!(denied["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is present")
        .starts_with("hmac-sha256:"));
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            &proof,
            "person-1",
            "citizen-subject",
            "source-token",
            "issuer_signed_jwt",
            "disclosures",
        ],
    );
    assert!(!records.iter().any(|record| {
        record["path"] == json!("/v1/credentials")
            && record["decision"] == json!("credential_issued")
    }));

    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn direct_credential_purpose_mismatch_denial_is_audited_and_redacted() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned");

    let issue = server
        .post("/v1/credentials")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "purpose": "appeals"
        }))
        .await;
    issue.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        issue
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let body: Value = issue.json();
    assert_problem_identity(&body, StatusCode::FORBIDDEN, "evaluation.binding_mismatch");
    assert!(body.get("credential").is_none());
    assert!(body.get("credential_id").is_none());
    assert!(body.get("issuer_signed_jwt").is_none());
    assert!(body.get("disclosures").is_none());
    let body_text = serde_json::to_string(&body).expect("problem body serializes");
    assert!(!body_text.contains(&token));
    assert!(!body_text.contains("person-1"));

    let records = audit_records_from_envelopes(&audit_path);
    let denied = audit_record_with(
        &records,
        "/v1/credentials",
        "credential_denied",
        StatusCode::FORBIDDEN,
        "evaluation.binding_mismatch",
    );
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
    assert_eq!(denied["source_read_count"], json!(0));
    assert_eq!(denied["forwarded"], json!(false));
    assert!(denied.get("principal_id").is_none());
    assert!(denied["principal_id_hash"]
        .as_str()
        .expect("principal id hash is present")
        .starts_with("hmac-sha256:"));
    assert!(denied.get("correlation_id").is_none());
    assert!(denied["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is present")
        .starts_with("hmac-sha256:"));
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            "person-1",
            "citizen-subject",
            "source-token",
            "issuer_signed_jwt",
            "disclosures",
        ],
    );
    assert!(!records.iter().any(|record| {
        record["path"] == json!("/v1/credentials")
            && record["decision"] == json!("credential_issued")
    }));

    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn direct_credential_binding_denials_are_audited_and_redacted() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let authorization = format!("Bearer {token}");

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .json(&json!({
            "target": person_identifier_target("national_id", "person-1"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/dc+sd-jwt"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned");

    let cases = [
        (
            "unsupported format",
            json!({
                "evaluation_id": evaluation_id,
                "credential_profile": "civil_status_sd_jwt",
                "format": "application/json",
                "claims": ["person-is-alive"],
                "disclosure": "value"
            }),
            StatusCode::NOT_ACCEPTABLE,
            "claim.format_not_supported",
        ),
        (
            "disclosure mismatch",
            json!({
                "evaluation_id": evaluation_id,
                "credential_profile": "civil_status_sd_jwt",
                "format": "application/dc+sd-jwt",
                "claims": ["person-is-alive"],
                "disclosure": "predicate"
            }),
            StatusCode::FORBIDDEN,
            "evaluation.binding_mismatch",
        ),
        (
            "claim-set mismatch",
            json!({
                "evaluation_id": evaluation_id,
                "credential_profile": "civil_status_sd_jwt",
                "format": "application/dc+sd-jwt",
                "claims": ["person-is-dead"],
                "disclosure": "value"
            }),
            StatusCode::FORBIDDEN,
            "evaluation.binding_mismatch",
        ),
    ];

    for (name, payload, status, code) in &cases {
        let issue = server
            .post("/v1/credentials")
            .add_header("authorization", authorization.clone())
            .json(&payload)
            .await;
        issue.assert_status(*status);
        assert_eq!(
            issue
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/problem+json"),
            "{name} returns problem+json"
        );
        let body: Value = issue.json();
        assert_problem_identity(&body, *status, code);
        assert!(body.get("credential").is_none(), "{name} has no credential");
        assert!(
            body.get("credential_id").is_none(),
            "{name} has no credential id"
        );
        assert!(
            body.get("issuer_signed_jwt").is_none(),
            "{name} has no issuer JWT"
        );
        assert!(
            body.get("disclosures").is_none(),
            "{name} has no disclosures"
        );
        let body_text = serde_json::to_string(&body).expect("problem body serializes");
        assert!(!body_text.contains(&token), "{name} does not echo token");
        assert!(
            !body_text.contains("person-1"),
            "{name} does not echo subject"
        );
    }

    let records = audit_records_from_envelopes(&audit_path);
    let denied_records = records
        .iter()
        .filter(|record| {
            record["path"] == json!("/v1/credentials")
                && record["decision"] == json!("credential_denied")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        denied_records.len(),
        cases.len(),
        "every binding denial should emit credential_denied audit"
    );
    for ((name, _, status, code), denied) in cases.iter().zip(denied_records.iter()) {
        assert_eq!(
            denied["status"],
            json!(status.as_u16()),
            "{name} audit status"
        );
        assert_eq!(
            denied["error_code"],
            json!(*code),
            "{name} audit error code"
        );
        assert_eq!(denied["access_mode"], json!("self_attestation"));
        assert_eq!(denied["scopes_used"], json!(["self_attestation"]));
        assert_eq!(denied["source_read_count"], json!(0));
        assert_eq!(denied["forwarded"], json!(false));
        assert!(denied.get("principal_id").is_none());
        assert!(denied["principal_id_hash"]
            .as_str()
            .expect("principal id hash is present")
            .starts_with("hmac-sha256:"));
        assert!(denied.get("correlation_id").is_none());
        assert!(denied["correlation_id_hash"]
            .as_str()
            .expect("correlation id hash is present")
            .starts_with("hmac-sha256:"));
    }
    assert_audit_records_do_not_contain(
        &records,
        &[
            &token,
            &authorization,
            "person-1",
            "citizen-subject",
            "source-token",
            "issuer_signed_jwt",
            "disclosures",
        ],
    );
    assert!(!records.iter().any(|record| {
        record["path"] == json!("/v1/credentials")
            && record["decision"] == json!("credential_issued")
    }));

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn self_attestation_subject_mismatch_audit_names_token_claim_not_value() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_oidc_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));

    let response = server
        .post("/v1/evaluations")
        .add_header("authorization", format!("Bearer {token}"))
        .add_header("x-request-id", "bad value")
        .json(&json!({
            "target": person_identifier_target("national_id", "person-2"),
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/vnd.registry-notary.claim-result+json"
        }))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    let body: Value = response.json();
    assert_eq!(body["code"], json!("self_attestation.denied"));
    assert_eq!(
        body["type"],
        json!("https://id.registrystack.org/problems/registry-notary/self_attestation/denied")
    );

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(!audit.contains("person-1"));
    assert!(!audit.contains("person-2"));
    assert!(!audit.contains("citizen-subject"));
    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    let denied = records
        .iter()
        .find(|record| {
            record["path"] == json!("/v1/evaluations")
                && record["decision"] == json!("evaluate_denied")
                && record["status"] == json!(403)
        })
        .expect("denial audit record exists");
    assert_eq!(denied["access_mode"], json!("self_attestation"));
    assert_eq!(
        denied["denial_code"],
        json!("self_attestation.subject_mismatch")
    );
    assert_eq!(
        denied["error_code"],
        json!("self_attestation.subject_mismatch")
    );
    assert_eq!(denied["token_claim_name"], json!("national_id"));
    assert!(denied.get("correlation_id").is_none());
    assert!(denied["correlation_id_hash"].is_string());
    assert_ne!(denied["correlation_id_hash"], json!("bad value"));

    idp.stop().await;
}
