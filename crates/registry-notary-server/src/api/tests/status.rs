// SPDX-License-Identifier: Apache-2.0
//! Status API tests.

use super::*;

#[tokio::test]
async fn credential_status_list_response_is_signed_status_list_jwt() {
    let credential_status = CredentialStatusStore::from_config(&CredentialStatusConfig {
        enabled: true,
        base_url: "https://issuer.example".to_string(),
        ..CredentialStatusConfig::default()
    });
    let issued_at = OffsetDateTime::now_utc();
    credential_status
        .record_issued(
            "credential-1".to_string(),
            "did:web:issuer.example".to_string(),
            "civil_status_sd_jwt".to_string(),
            issued_at,
            issued_at + time::Duration::seconds(600),
        )
        .await
        .expect("status record writes");
    let record = credential_status
        .get("credential-1")
        .await
        .expect("status record reads")
        .expect("status record exists");
    let state = RegistryNotaryApiState::new_with_runtime_blocks(
        Arc::new(evidence_config()),
        Arc::new(SubjectAccessConfig::default()),
        Arc::new(Oid4vciConfig::default()),
        Arc::new(FederationConfig::default()),
        None,
        AuditKeyHasher::unkeyed_dev_only(),
        ReplayStores::memory(),
        credential_status,
        Arc::new(AppMetrics::default()),
        Arc::new(EvidenceStore::default()),
        Arc::new(TestIssuerResolver),
        SignerReadiness::default(),
    );

    let response = credential_status_list_response(&state, &record).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/statuslist+jwt")
    );
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("status list body reads");
    let jwt = std::str::from_utf8(&body).expect("status list JWT is UTF-8");
    let header = decode_jwt_header(jwt);
    let payload = decode_jwt_payload(jwt);
    assert_eq!(header["typ"], json!("statuslist+jwt"));
    assert_eq!(header["kid"], json!("did:web:issuer.example#key-1"));
    assert_eq!(
        payload["sub"],
        json!("https://issuer.example/v1/credentials/credential-1/status")
    );
    assert_eq!(payload["ttl"], json!(300));
    assert_eq!(payload["status_list"]["bits"], json!(8));
    assert_eq!(payload["status_list"]["lst"], json!("eJxjAAAAAQAB"));
}

#[tokio::test]
async fn credential_status_list_response_reuses_cached_signature() {
    let credential_status = CredentialStatusStore::from_config(&CredentialStatusConfig {
        enabled: true,
        base_url: "https://issuer.example".to_string(),
        ..CredentialStatusConfig::default()
    });
    let issued_at = OffsetDateTime::now_utc();
    credential_status
        .record_issued(
            "credential-cache".to_string(),
            "did:web:issuer.example".to_string(),
            "civil_status_sd_jwt".to_string(),
            issued_at,
            issued_at + time::Duration::seconds(600),
        )
        .await
        .expect("status record writes");
    let record = credential_status
        .get("credential-cache")
        .await
        .expect("status record reads")
        .expect("status record exists");
    let sign_count = Arc::new(AtomicUsize::new(0));
    let state = RegistryNotaryApiState::new_with_runtime_blocks(
        Arc::new(evidence_config()),
        Arc::new(SubjectAccessConfig::default()),
        Arc::new(Oid4vciConfig::default()),
        Arc::new(FederationConfig::default()),
        None,
        AuditKeyHasher::unkeyed_dev_only(),
        ReplayStores::memory(),
        credential_status,
        Arc::new(AppMetrics::default()),
        Arc::new(EvidenceStore::default()),
        Arc::new(CountingIssuerResolver {
            sign_count: Arc::clone(&sign_count),
        }),
        SignerReadiness::default(),
    );

    let first = credential_status_list_response(&state, &record).await;
    let second = credential_status_list_response(&state, &record).await;

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(sign_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn status_list_jwt_cache_does_not_hold_lock_while_signing() {
    let cache = Arc::new(StatusListJwtCache::default());
    let nested_cache = Arc::clone(&cache);
    let now = OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::seconds(60);

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        cache.get_or_insert_with("outer".to_string(), now, expires_at, || async move {
            nested_cache
                .get_or_insert_with("inner".to_string(), now, expires_at, || async {
                    Ok("inner-token".to_string())
                })
                .await?;
            Ok("outer-token".to_string())
        }),
    )
    .await
    .expect("cache lookup should not block behind its own signing future")
    .expect("outer token signs");

    assert_eq!(result, "outer-token");
}

#[test]
fn accepts_status_list_jwt_matches_exact_media_type() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/statuslist+jwt; q=0.8"),
    );
    assert!(accepts_status_list_jwt(&headers));

    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("Application/StatusList+JWT"),
    );
    assert!(accepts_status_list_jwt(&headers));

    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/statuslist+jwt-seq"),
    );
    assert!(!accepts_status_list_jwt(&headers));
}
