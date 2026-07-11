// SPDX-License-Identifier: Apache-2.0
//! Credential status handlers and signed status-list caching.

use super::*;

pub(super) async fn get_credential_status(
    Path(credential_id): Path<String>,
    headers: HeaderMap,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
) -> Response {
    let Some(Extension(state)) = state else {
        return credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status is unavailable",
        );
    };
    if !state.credential_status.is_enabled() {
        return credential_status_problem(
            StatusCode::NOT_FOUND,
            "credential_status.disabled",
            "Credential status disabled",
            "credential status is not enabled",
        );
    }
    match state.credential_status.get(&credential_id).await {
        Ok(Some(record)) if accepts_status_list_jwt(&headers) => {
            credential_status_list_response(&state, &record).await
        }
        Ok(Some(record)) => Json(record.response_body(OffsetDateTime::now_utc())).into_response(),
        Ok(None) => credential_status_problem(
            StatusCode::NOT_FOUND,
            "credential_status.not_found",
            "Credential status not found",
            "credential status record was not found",
        ),
        Err(_) => credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status store is unavailable",
        ),
    }
}

pub(super) fn accepts_status_list_jwt(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|part| {
                part.split(';').next().is_some_and(|media_type| {
                    media_type
                        .trim()
                        .eq_ignore_ascii_case("application/statuslist+jwt")
                })
            })
        })
}

pub(super) async fn credential_status_list_response(
    state: &RegistryNotaryApiState,
    record: &CredentialStatusRecord,
) -> Response {
    let Ok(issuer) = state.issuer_resolver().issuer(&record.credential_profile) else {
        return credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status issuer is unavailable",
        );
    };
    let now = OffsetDateTime::now_utc();
    let ttl_seconds = 300_u64;
    let Some(token_expires_at) = now.checked_add(time::Duration::seconds(ttl_seconds as i64))
    else {
        return credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status token expiry could not be calculated",
        );
    };
    let effective_status = record.effective_status(now);
    let status_list = encoded_single_entry_status_list(&effective_status);
    let status_url = state.credential_status.status_url(&record.credential_id);
    let public_jwk = issuer.public_jwk();
    let Ok(cache_key) = status_list_jwt_cache_key(
        record,
        &status_url,
        &effective_status,
        status_list,
        ttl_seconds,
        &public_jwk,
    ) else {
        return credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status cache key could not be calculated",
        );
    };
    let cache_expires_at =
        status_list_jwt_cache_expires_at(record, &effective_status, token_expires_at);
    let payload = json!({
        "sub": status_url,
        "iat": now.unix_timestamp(),
        "exp": token_expires_at.unix_timestamp(),
        "ttl": ttl_seconds,
        "status_list": {
            "bits": 8,
            "lst": status_list,
        }
    });
    let Ok(token) = state
        .status_list_jwt_cache
        .get_or_insert_with(cache_key, now, cache_expires_at, || async move {
            issuer.sign_compact_jwt("statuslist+jwt", payload).await
        })
        .await
    else {
        return credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status token could not be signed",
        );
    };
    let mut response = token.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/statuslist+jwt"),
    );
    response
}

#[derive(Debug)]
pub(super) struct StatusListJwtCache {
    pub(super) entries: tokio::sync::Mutex<BTreeMap<String, StatusListJwtCacheEntry>>,
}

#[derive(Debug)]
pub(super) struct StatusListJwtCacheEntry {
    pub(super) token: String,
    pub(super) expires_at: OffsetDateTime,
}

impl Default for StatusListJwtCache {
    fn default() -> Self {
        Self {
            entries: tokio::sync::Mutex::new(BTreeMap::new()),
        }
    }
}

impl StatusListJwtCache {
    pub(super) async fn get_or_insert_with<F, Fut>(
        &self,
        key: String,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
        sign: F,
    ) -> Result<String, EvidenceError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<String, EvidenceError>>,
    {
        {
            let mut entries = self.entries.lock().await;
            entries.retain(|_, entry| entry.expires_at > now);
            if let Some(entry) = entries.get(&key) {
                return Ok(entry.token.clone());
            }
        }

        let token = sign().await?;

        let mut entries = self.entries.lock().await;
        entries.retain(|_, entry| entry.expires_at > now);
        if let Some(entry) = entries.get(&key) {
            return Ok(entry.token.clone());
        }
        if expires_at > now {
            entries.insert(
                key,
                StatusListJwtCacheEntry {
                    token: token.clone(),
                    expires_at,
                },
            );
        }
        Ok(token)
    }
}

pub(super) fn status_list_jwt_cache_key(
    record: &CredentialStatusRecord,
    status_url: &str,
    effective_status: &str,
    status_list: &str,
    ttl_seconds: u64,
    public_jwk: &Value,
) -> Result<String, serde_json::Error> {
    let public_jwk_hash = sha256_json(public_jwk)?;
    let key_material = json!({
        "typ": "statuslist+jwt",
        "issuer": record.issuer,
        "issuer_public_jwk_sha256": public_jwk_hash,
        "audience": Value::Null,
        "credential_id": record.credential_id,
        "credential_profile": record.credential_profile,
        "status_url": status_url,
        "status": record.status,
        "effective_status": effective_status,
        "issued_at": record.issued_at,
        "expires_at": record.expires_at,
        "updated_at": record.updated_at,
        "ttl": ttl_seconds,
        "status_list": {
            "bits": 8,
            "lst": status_list,
        }
    });
    sha256_json(&key_material)
}

pub(super) fn status_list_jwt_cache_expires_at(
    record: &CredentialStatusRecord,
    effective_status: &str,
    token_expires_at: OffsetDateTime,
) -> OffsetDateTime {
    if record.status == registry_notary_core::CREDENTIAL_STATUS_VALID
        && effective_status == registry_notary_core::CREDENTIAL_STATUS_VALID
    {
        return OffsetDateTime::parse(
            &record.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()
        .filter(|credential_expires_at| *credential_expires_at < token_expires_at)
        .unwrap_or(token_expires_at);
    }
    token_expires_at
}

#[derive(Debug, Deserialize)]
pub(super) struct CredentialStatusUpdateRequest {
    pub(super) status: String,
}

pub(super) async fn update_credential_status(
    Path(credential_id): Path<String>,
    state: Option<Extension<Arc<RegistryNotaryApiState>>>,
    principal: Option<Extension<EvidencePrincipal>>,
    Json(request): Json<CredentialStatusUpdateRequest>,
) -> Response {
    let Some(Extension(principal)) = principal else {
        return evidence_error_response(EvidenceError::MissingCredential);
    };
    if !principal.has_scope(ADMIN_SCOPE) {
        return evidence_error_response(EvidenceError::ScopeDenied {
            required: ADMIN_SCOPE.to_string(),
        });
    }
    let Some(Extension(state)) = state else {
        return credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status is unavailable",
        );
    };
    if !state.credential_status.is_enabled() {
        return credential_status_problem(
            StatusCode::NOT_FOUND,
            "credential_status.disabled",
            "Credential status disabled",
            "credential status is not enabled",
        );
    }
    if !is_mutable_status(request.status.as_str()) {
        return credential_status_problem(
            StatusCode::BAD_REQUEST,
            "credential_status.invalid_status",
            "Invalid credential status",
            "status must be valid, suspended, or revoked",
        );
    }
    match state
        .credential_status
        .update_status(&credential_id, &request.status)
        .await
    {
        Ok(Some(record)) => Json(record.response_body(OffsetDateTime::now_utc())).into_response(),
        Ok(None) => credential_status_problem(
            StatusCode::NOT_FOUND,
            "credential_status.not_found",
            "Credential status not found",
            "credential status record was not found",
        ),
        Err(CredentialStatusStoreError::InvalidTransition) => credential_status_problem(
            StatusCode::CONFLICT,
            "credential_status.invalid_transition",
            "Invalid credential status transition",
            "revoked credential status is terminal",
        ),
        Err(_) => credential_status_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_status.unavailable",
            "Credential status unavailable",
            "credential status store is unavailable",
        ),
    }
}

pub(super) fn credential_status_problem(
    status: StatusCode,
    code: &'static str,
    title: &'static str,
    detail: &'static str,
) -> Response {
    let body = json!({
        "type": format!("{}/{}", crate::PROBLEM_TYPE_BASE_URL, code.replace('.', "/")),
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
        "code": code,
    });
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}
