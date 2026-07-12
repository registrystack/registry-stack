// SPDX-License-Identifier: Apache-2.0
//! Typed Registry Notary HTTP client.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use registry_notary_core::{
    BatchEvaluateRequest, ClaimRef, CredentialIssueRequest, EvaluateRequest, EvidenceEntity,
    EvidenceIdentifier, EvidenceOnBehalfOf, EvidenceRelationship, RenderEvaluationRequest,
    RenderRequest, RequestVariables, FORMAT_CLAIM_RESULT_JSON,
};
use registry_platform_httputil::read_bounded;
use reqwest::{Method, StatusCode, Url};
use secrecy::SecretString;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::auth::{Auth, AuthHeader, AuthProvider};
use crate::error::{
    parse_retry_after, NotaryClientBuildError, NotaryClientError, Oid4vciError, ProblemDetails,
};
use crate::headers;
use crate::options::{RequestOptions, RetryPolicy};
use crate::responses::{
    AdminReloadResponse, CredentialIssueResponse, CredentialStatusResponse,
    CredentialStatusUpdateRequest, EvaluateResponse, Evaluation, FormatsResponse, HealthResponse,
    ListClaimsResponse, NotaryResponse, ReadinessResponse,
};
#[cfg(feature = "verifier")]
use crate::verifier::{VerificationError, VerifiedCredential, VerifyOptions};

const LIMIT_SMALL: u64 = 64 * 1024;
const LIMIT_DISCOVERY: u64 = 2 * 1024 * 1024;
const LIMIT_OPERATION: u64 = 8 * 1024 * 1024;
const LIMIT_BATCH: u64 = 16 * 1024 * 1024;
const JWKS_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
enum AuthState {
    Static(Auth),
    Provider(Arc<dyn AuthProvider>),
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(auth) => f.debug_tuple("Static").field(auth).finish(),
            Self::Provider(_) => f.write_str("Provider(<redacted>)"),
        }
    }
}

/// Cloneable typed HTTP client for a Registry Notary service.
///
/// Construct with [`RegistryNotaryClient::builder`]. Clones share the same
/// underlying `reqwest::Client` and JWKS cache.
#[derive(Debug, Clone)]
pub struct RegistryNotaryClient {
    base_url: Url,
    http: reqwest::Client,
    auth: Option<AuthState>,
    default_purpose: Option<String>,
    retry_policy: RetryPolicy,
    jwks_cache: Arc<Mutex<Option<CachedJwks>>>,
}

#[derive(Debug, Clone)]
struct CachedJwks {
    body: serde_json::Value,
    expires_at: Instant,
}

/// Builder for [`RegistryNotaryClient`].
///
/// Exactly one authentication mode may be configured. The builder rejects
/// non-HTTPS base URLs except HTTP loopback in debug or `test-support` builds.
#[derive(Default)]
pub struct NotaryClientBuilder {
    base_url: Option<String>,
    bearer_token: Option<SecretString>,
    api_key: Option<SecretString>,
    auth_provider: Option<Arc<dyn AuthProvider>>,
    default_purpose: Option<String>,
    timeout: Option<Duration>,
    user_agent: Option<String>,
    retry_policy: Option<RetryPolicy>,
    #[cfg(any(test, feature = "test-support"))]
    reqwest_client: Option<reqwest::Client>,
}

impl std::fmt::Debug for NotaryClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotaryClientBuilder")
            .field("base_url", &self.base_url)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field(
                "auth_provider",
                &self.auth_provider.as_ref().map(|_| "<redacted>"),
            )
            .field("default_purpose", &self.default_purpose)
            .field("timeout", &self.timeout)
            .field("user_agent", &self.user_agent)
            .field("retry_policy", &self.retry_policy)
            .finish()
    }
}

impl RegistryNotaryClient {
    /// Start building a client for `base_url`.
    ///
    /// `base_url` may include a path prefix; route paths are joined under that
    /// prefix.
    #[must_use]
    pub fn builder(base_url: impl Into<String>) -> NotaryClientBuilder {
        NotaryClientBuilder {
            base_url: Some(base_url.into()),
            ..NotaryClientBuilder::default()
        }
    }

    /// Fetch `GET /healthz`.
    pub async fn health(&self) -> Result<NotaryResponse<HealthResponse>, NotaryClientError> {
        self.get_json(
            "/healthz",
            RequestOptions::default(),
            LIMIT_SMALL,
            ErrorKind::Problem,
        )
        .await
    }

    /// Fetch `GET /ready`.
    pub async fn ready(&self) -> Result<NotaryResponse<ReadinessResponse>, NotaryClientError> {
        self.get_json(
            "/ready",
            RequestOptions::default(),
            LIMIT_SMALL,
            ErrorKind::Problem,
        )
        .await
    }

    /// Trigger `POST /admin/v1/reload`.
    ///
    /// Requires the server-side admin scope or equivalent API key.
    pub async fn admin_reload(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<AdminReloadResponse>, NotaryClientError> {
        self.post_json(
            "/admin/v1/reload",
            &serde_json::json!({}),
            options,
            LIMIT_SMALL,
            RouteRetry::PostNoRetry,
            ErrorKind::Problem,
        )
        .await
    }

    /// Fetch the generated OpenAPI document from `GET /openapi.json`.
    pub async fn openapi_json(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<serde_json::Value>, NotaryClientError> {
        self.get_json(
            "/openapi.json",
            options,
            LIMIT_DISCOVERY,
            ErrorKind::Problem,
        )
        .await
    }

    /// Fetch `GET /.well-known/evidence-service`.
    pub async fn service_document(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<serde_json::Value>, NotaryClientError> {
        self.get_json(
            "/.well-known/evidence-service",
            options,
            LIMIT_DISCOVERY,
            ErrorKind::Problem,
        )
        .await
    }

    /// Fetch and cache `GET /.well-known/evidence/jwks.json`.
    ///
    /// Calls without request options use a short in-process cache. Use
    /// [`Self::refresh_jwks`] to force a refresh, or [`Self::raw_issuer_jwks`]
    /// to fetch without updating the cache.
    pub async fn issuer_jwks(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<serde_json::Value>, NotaryClientError> {
        if options.is_empty() {
            let cached = self
                .jwks_cache
                .lock()
                .expect("jwks cache lock poisoned")
                .as_ref()
                .filter(|cached| cached.expires_at > Instant::now())
                .map(|cached| cached.body.clone());
            if let Some(body) = cached {
                return Ok(NotaryResponse {
                    body,
                    status: StatusCode::OK,
                    request_id: None,
                    retry_after: None,
                });
            }
        }
        self.fetch_issuer_jwks(options).await
    }

    /// Force-refresh the evidence issuer JWKS cache.
    pub async fn refresh_jwks(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<serde_json::Value>, NotaryClientError> {
        self.fetch_issuer_jwks(options).await
    }

    /// Fetch Prometheus metrics from `GET /metrics`.
    ///
    /// Metrics are operational data and are returned as text.
    pub async fn metrics(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<String>, NotaryClientError> {
        self.reject_idempotency(&options)?;
        let response = self
            .execute(
                Method::GET,
                "/metrics",
                None,
                options,
                LIMIT_DISCOVERY,
                RouteRetry::Get,
                ErrorKind::Problem,
                None,
                None,
            )
            .await?;
        let request_id = response.request_id.clone();
        let status = response.status;
        String::from_utf8(response.body).map_or_else(
            |_| Err(NotaryClientError::Decode { status, request_id }),
            |body| {
                Ok(NotaryResponse {
                    body,
                    status,
                    request_id: response.request_id,
                    retry_after: response.retry_after,
                })
            },
        )
    }

    async fn fetch_issuer_jwks(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<serde_json::Value>, NotaryClientError> {
        let response: NotaryResponse<serde_json::Value> = self
            .get_json(
                "/.well-known/evidence/jwks.json",
                options,
                LIMIT_DISCOVERY,
                ErrorKind::Problem,
            )
            .await?;
        let cached = CachedJwks {
            body: response.body.clone(),
            expires_at: Instant::now() + JWKS_TTL,
        };
        *self.jwks_cache.lock().expect("jwks cache lock poisoned") = Some(cached);
        Ok(response)
    }

    /// Fetch the issuer JWKS without using or updating the client cache.
    pub async fn raw_issuer_jwks(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<serde_json::Value>, NotaryClientError> {
        self.get_json(
            "/.well-known/evidence/jwks.json",
            options,
            LIMIT_DISCOVERY,
            ErrorKind::Problem,
        )
        .await
    }

    #[cfg(feature = "verifier")]
    /// Explicitly verify an SD-JWT VC compact credential against issuer JWKS.
    ///
    /// This method is opt-in. Transport methods continue to decode response
    /// bodies without performing verification. Verification reuses the
    /// `issuer_jwks` TTL cache, forces one `refresh_jwks` on `key.unknown`,
    /// and never performs an unbounded refresh loop.
    pub async fn verify_sd_jwt_vc(
        &self,
        compact: &str,
        options: VerifyOptions,
    ) -> Result<VerifiedCredential, VerificationError> {
        let jwks = self
            .issuer_jwks(RequestOptions::default())
            .await
            .map_err(|_| VerificationError::jwks_unavailable())?
            .body;
        match crate::verifier::verify_sd_jwt_vc(compact, &jwks, &options) {
            Err(error) if error.is_unknown_key() => {
                let refreshed = self
                    .refresh_jwks(RequestOptions::default())
                    .await
                    .map_err(|_| VerificationError::jwks_unavailable())?
                    .body;
                crate::verifier::verify_sd_jwt_vc(compact, &refreshed, &options)
            }
            result => result,
        }
    }

    #[cfg(feature = "verifier")]
    /// Explicitly verify a direct credential-issuance response.
    pub async fn verify_credential_response(
        &self,
        response: &CredentialIssueResponse,
        options: VerifyOptions,
    ) -> Result<VerifiedCredential, VerificationError> {
        self.verify_sd_jwt_vc(&response.credential, options).await
    }

    #[cfg(feature = "oid4vci")]
    /// Fetch OpenID4VCI issuer metadata.
    ///
    /// This helper wraps the endpoint only. It does not generate holder proofs.
    pub async fn oid4vci_issuer_metadata(
        &self,
        options: RequestOptions,
    ) -> Result<
        NotaryResponse<registry_platform_oid4vci::CredentialIssuerMetadata>,
        NotaryClientError,
    > {
        self.reject_idempotency(&options)?;
        self.get_json(
            "/.well-known/openid-credential-issuer",
            options,
            LIMIT_DISCOVERY,
            ErrorKind::Oid4vci,
        )
        .await
    }

    #[cfg(feature = "oid4vci")]
    /// Fetch an OpenID4VCI credential offer.
    pub async fn oid4vci_credential_offer(
        &self,
        credential_configuration_id: Option<&str>,
        options: RequestOptions,
    ) -> Result<NotaryResponse<registry_platform_oid4vci::CredentialOffer>, NotaryClientError> {
        self.reject_idempotency(&options)?;
        let path = credential_configuration_id.map_or_else(
            || "/oid4vci/credential-offer".to_string(),
            |id| {
                format!(
                    "/oid4vci/credential-offer?credential_configuration_id={}",
                    encode_query_value(id)
                )
            },
        );
        self.get_json(&path, options, LIMIT_DISCOVERY, ErrorKind::Oid4vci)
            .await
    }

    #[cfg(feature = "oid4vci")]
    /// Request an OpenID4VCI nonce.
    pub async fn oid4vci_nonce(
        &self,
        request: Option<registry_platform_oid4vci::NonceRequest>,
        options: RequestOptions,
    ) -> Result<NotaryResponse<registry_platform_oid4vci::NonceResponse>, NotaryClientError> {
        self.reject_idempotency(&options)?;
        let body = request.unwrap_or(registry_platform_oid4vci::NonceRequest {
            credential_configuration_id: None,
        });
        self.post_json(
            "/oid4vci/nonce",
            &body,
            options,
            LIMIT_OPERATION,
            RouteRetry::PostNoRetry,
            ErrorKind::Oid4vci,
        )
        .await
    }

    #[cfg(feature = "oid4vci")]
    /// Submit an OpenID4VCI credential request.
    ///
    /// The caller is responsible for holder-key custody and proof JWT creation.
    pub async fn oid4vci_credential(
        &self,
        request: registry_platform_oid4vci::CredentialRequest,
        options: RequestOptions,
    ) -> Result<NotaryResponse<registry_platform_oid4vci::CredentialResponse>, NotaryClientError>
    {
        self.reject_idempotency(&options)?;
        self.post_json(
            "/oid4vci/credential",
            &request,
            options,
            LIMIT_OPERATION,
            RouteRetry::PostNoRetry,
            ErrorKind::Oid4vci,
        )
        .await
    }

    #[cfg(all(feature = "oid4vci", feature = "verifier"))]
    /// Explicitly verify an OpenID4VCI credential response.
    pub async fn verify_oid4vci_credential(
        &self,
        response: &registry_platform_oid4vci::CredentialResponse,
        options: VerifyOptions,
    ) -> Result<VerifiedCredential, VerificationError> {
        self.verify_sd_jwt_vc(oid4vci_compact_credential(&response.credential)?, options)
            .await
    }

    /// List configured claim definitions with `GET /v1/claims`.
    ///
    /// The current server contract returns a bounded, unpaginated list.
    pub async fn list_claims(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<ListClaimsResponse>, NotaryClientError> {
        self.get_json("/v1/claims", options, LIMIT_DISCOVERY, ErrorKind::Problem)
            .await
    }

    /// Fetch one claim definition by claim id.
    pub async fn get_claim(
        &self,
        claim_id: &str,
        options: RequestOptions,
    ) -> Result<NotaryResponse<serde_json::Value>, NotaryClientError> {
        self.get_json(
            &format!("/v1/claims/{}", encode_path_segment(claim_id)),
            options,
            LIMIT_DISCOVERY,
            ErrorKind::Problem,
        )
        .await
    }

    /// List evidence formats supported by the service.
    pub async fn list_formats(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<FormatsResponse>, NotaryClientError> {
        self.get_json("/v1/formats", options, LIMIT_DISCOVERY, ErrorKind::Problem)
            .await
    }

    /// Start the ergonomic evaluation builder for one target entity.
    #[must_use]
    pub fn evaluate_target(&self, target_type: impl Into<String>) -> EvaluateBuilder<'_> {
        EvaluateBuilder {
            client: self,
            target: EvidenceEntity::new(target_type),
            requester: None,
            relationship: None,
            on_behalf_of: None,
            variables: BTreeMap::new(),
            claims: Vec::new(),
            disclosure: None,
            format: None,
            purpose: None,
            request_id: None,
            traceparent: None,
        }
    }

    /// Start the ergonomic evaluation builder for a Person target id.
    ///
    /// This convenience helper maps to the v1 `target` request model. Prefer
    /// [`Self::evaluate_target`] when the caller needs identifiers, attributes,
    /// requester context, or non-person targets.
    #[must_use]
    pub fn evaluate(&self, subject_id: impl Into<String>) -> EvaluateBuilder<'_> {
        self.evaluate_target("Person").target_id(subject_id)
    }

    /// Submit a raw typed [`EvaluateRequest`].
    ///
    /// This method is best when the caller already has the core wire request.
    /// It applies default purpose and claim-result format handling before
    /// sending.
    pub async fn evaluate_request(
        &self,
        mut request: EvaluateRequest,
        options: RequestOptions,
    ) -> Result<NotaryResponse<EvaluateResponse>, NotaryClientError> {
        let mut options = self.prepare_purpose(options, request.purpose.as_deref())?;
        options.accept = options
            .accept
            .or_else(|| Some(FORMAT_CLAIM_RESULT_JSON.to_string()));
        if request.purpose.is_none() {
            request.purpose = options.purpose.clone();
        }
        let mut request = request;
        if request.format.is_none() {
            request.format = Some(FORMAT_CLAIM_RESULT_JSON.to_string());
        }
        self.post_json(
            "/v1/evaluations",
            &request,
            options,
            LIMIT_OPERATION,
            RouteRetry::PostNoRetry,
            ErrorKind::Problem,
        )
        .await
    }

    /// Submit a raw typed [`BatchEvaluateRequest`].
    ///
    /// Batch evaluation is the only POST route where the client allows
    /// `Idempotency-Key`; retries require that key.
    pub async fn batch_evaluate_request(
        &self,
        mut request: BatchEvaluateRequest,
        options: RequestOptions,
    ) -> Result<NotaryResponse<registry_notary_core::BatchEvaluateResponse>, NotaryClientError>
    {
        let mut options = self.prepare_purpose(options, request.purpose.as_deref())?;
        options.accept = options
            .accept
            .or_else(|| Some(FORMAT_CLAIM_RESULT_JSON.to_string()));
        if request.purpose.is_none() {
            request.purpose = options.purpose.clone();
        }
        if request.format.is_none() {
            request.format = Some(FORMAT_CLAIM_RESULT_JSON.to_string());
        }
        self.post_json(
            "/v1/batch-evaluations",
            &request,
            options,
            LIMIT_BATCH,
            RouteRetry::PostBatch,
            ErrorKind::Problem,
        )
        .await
    }

    /// Render a stored evaluation into a requested evidence format.
    ///
    /// The server models `evaluation_id` as a path parameter. This method accepts
    /// the core [`RenderRequest`] DTO for caller ergonomics, then moves
    /// `evaluation_id` into `/v1/evaluations/{evaluation_id}/render` before the
    /// request body is serialized.
    pub async fn render_request(
        &self,
        request: RenderRequest,
        options: RequestOptions,
    ) -> Result<NotaryResponse<serde_json::Value>, NotaryClientError> {
        self.reject_idempotency(&options)?;
        let path = format!(
            "/v1/evaluations/{}/render",
            encode_path_segment(&request.evaluation_id)
        );
        let body = RenderEvaluationRequest::from(request);
        self.post_json(
            &path,
            &body,
            options,
            LIMIT_OPERATION,
            RouteRetry::PostNoRetry,
            ErrorKind::Problem,
        )
        .await
    }

    /// Issue a credential from a stored evaluation.
    ///
    /// Returned credential material is present in typed fields but redacted from
    /// `Debug` output.
    pub async fn issue_credential_request(
        &self,
        mut request: CredentialIssueRequest,
        options: RequestOptions,
    ) -> Result<NotaryResponse<CredentialIssueResponse>, NotaryClientError> {
        self.reject_idempotency(&options)?;
        let options = self.prepare_purpose(options, request.purpose.as_deref())?;
        if request.purpose.is_none() {
            request.purpose = options.purpose.clone();
        }
        self.post_json(
            "/v1/credentials",
            &request,
            options,
            LIMIT_OPERATION,
            RouteRetry::PostNoRetry,
            ErrorKind::Problem,
        )
        .await
    }

    /// Fetch minimal credential status by credential id.
    pub async fn credential_status(
        &self,
        credential_id: &str,
        options: RequestOptions,
    ) -> Result<NotaryResponse<CredentialStatusResponse>, NotaryClientError> {
        self.get_json(
            &format!(
                "/v1/credentials/{}/status",
                encode_path_segment(credential_id)
            ),
            options,
            LIMIT_SMALL,
            ErrorKind::Problem,
        )
        .await
    }

    /// Update minimal credential status through the admin route.
    pub async fn update_credential_status(
        &self,
        credential_id: &str,
        status: impl Into<String>,
        options: RequestOptions,
    ) -> Result<NotaryResponse<CredentialStatusResponse>, NotaryClientError> {
        self.reject_idempotency(&options)?;
        self.post_json(
            &format!(
                "/admin/v1/credentials/{}/status",
                encode_path_segment(credential_id)
            ),
            &CredentialStatusUpdateRequest {
                status: status.into(),
            },
            options,
            LIMIT_SMALL,
            RouteRetry::PostNoRetry,
            ErrorKind::Problem,
        )
        .await
    }

    #[cfg(feature = "federation")]
    /// Submit an already-signed federation evaluation JWS.
    ///
    /// The client does not mint or sign federation JWTs.
    pub async fn federation_evaluate_jws(
        &self,
        compact_jws: &str,
        options: RequestOptions,
    ) -> Result<NotaryResponse<String>, NotaryClientError> {
        self.reject_idempotency(&options)?;
        self.execute(
            Method::POST,
            "/federation/v1/evaluations",
            Some(compact_jws.as_bytes().to_vec()),
            options,
            LIMIT_OPERATION,
            RouteRetry::PostNoRetry,
            ErrorKind::Problem,
            Some(headers::APPLICATION_JWT),
            None,
        )
        .await
        .and_then(|response| {
            let request_id = response.request_id.clone();
            let status = response.status;
            String::from_utf8(response.body).map_or_else(
                |_| Err(NotaryClientError::Decode { status, request_id }),
                |body| {
                    Ok(NotaryResponse {
                        body,
                        status,
                        request_id: response.request_id,
                        retry_after: response.retry_after,
                    })
                },
            )
        })
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        options: RequestOptions,
        limit: u64,
        error_kind: ErrorKind,
    ) -> Result<NotaryResponse<T>, NotaryClientError> {
        self.get_json_accepting_status(path, options, limit, error_kind, None)
            .await
    }

    async fn get_json_accepting_status<T: DeserializeOwned>(
        &self,
        path: &str,
        options: RequestOptions,
        limit: u64,
        error_kind: ErrorKind,
        accepted_status: Option<StatusCode>,
    ) -> Result<NotaryResponse<T>, NotaryClientError> {
        self.reject_idempotency(&options)?;
        let response = self
            .execute(
                Method::GET,
                path,
                None,
                options,
                limit,
                RouteRetry::Get,
                error_kind,
                None,
                accepted_status,
            )
            .await?;
        let body =
            serde_json::from_slice(&response.body).map_err(|_| NotaryClientError::Decode {
                status: response.status,
                request_id: response.request_id.clone(),
            })?;
        Ok(response.map(body))
    }

    async fn post_json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        mut options: RequestOptions,
        limit: u64,
        retry: RouteRetry,
        error_kind: ErrorKind,
    ) -> Result<NotaryResponse<T>, NotaryClientError> {
        if matches!(retry, RouteRetry::PostNoRetry) {
            self.reject_idempotency(&options)?;
        }
        options.accept = options
            .accept
            .or_else(|| Some(headers::APPLICATION_JSON.to_string()));
        let raw =
            serde_json::to_vec(body).map_err(|_| NotaryClientBuildError::RequestSerialization)?;
        let response = self
            .execute(
                Method::POST,
                path,
                Some(raw),
                options,
                limit,
                retry,
                error_kind,
                Some(headers::APPLICATION_JSON),
                None,
            )
            .await?;
        let body =
            serde_json::from_slice(&response.body).map_err(|_| NotaryClientError::Decode {
                status: response.status,
                request_id: response.request_id.clone(),
            })?;
        Ok(response.map(body))
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        options: RequestOptions,
        limit: u64,
        route_retry: RouteRetry,
        error_kind: ErrorKind,
        content_type: Option<&str>,
        accepted_status: Option<StatusCode>,
    ) -> Result<NotaryResponse<Vec<u8>>, NotaryClientError> {
        let attempts = allowed_attempts(&self.retry_policy, route_retry, &options);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let result = self
                .send_once(
                    method.clone(),
                    path,
                    body.clone(),
                    options.clone(),
                    limit,
                    error_kind,
                    content_type,
                    accepted_status,
                )
                .await;
            match result {
                Ok(response) => return Ok(response),
                Err(error) if attempt < attempts && should_retry(&self.retry_policy, &error) => {
                    let delay = retry_delay(&self.retry_policy, attempt, &error);
                    tokio::time::sleep(delay).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_once(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        options: RequestOptions,
        limit: u64,
        error_kind: ErrorKind,
        content_type: Option<&str>,
        accepted_status: Option<StatusCode>,
    ) -> Result<NotaryResponse<Vec<u8>>, NotaryClientError> {
        let url = self.url(path)?;
        let auth_header = match &self.auth {
            Some(AuthState::Static(auth)) => Some(auth.header()),
            Some(AuthState::Provider(provider)) => Some(provider.auth_header().await?),
            None => None,
        };
        let mut request = self.http.request(method, url);
        if let Some(auth) = auth_header {
            request = match auth {
                AuthHeader::Authorization(value) => request.header(
                    reqwest::header::AUTHORIZATION,
                    secrecy::ExposeSecret::expose_secret(&value),
                ),
                AuthHeader::ApiKey(value) => {
                    request.header("x-api-key", secrecy::ExposeSecret::expose_secret(&value))
                }
            };
        }
        if let Some(accept) = &options.accept {
            request = request.header(reqwest::header::ACCEPT, accept);
        }
        if let Some(content_type) = content_type {
            request = request.header(reqwest::header::CONTENT_TYPE, content_type);
        }
        if let Some(purpose) = &options.purpose {
            request = request.header(headers::DATA_PURPOSE, purpose);
        }
        if let Some(request_id) = &options.request_id {
            request = request.header(headers::REQUEST_ID, request_id);
        }
        if let Some(traceparent) = &options.traceparent {
            request = request.header(headers::TRACEPARENT, traceparent);
        }
        if let Some(idempotency_key) = &options.idempotency_key {
            request = request.header(headers::IDEMPOTENCY_KEY, idempotency_key);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request.send().await.map_err(NotaryClientError::Transport)?;
        let status = response.status();
        let request_id = response
            .headers()
            .get(headers::REQUEST_ID)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let retry_after = parse_retry_after(
            response
                .headers()
                .get(headers::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            response
                .headers()
                .get(headers::DATE)
                .and_then(|value| value.to_str().ok()),
        );
        let bytes =
            read_bounded(response, limit)
                .await
                .map_err(|_| NotaryClientError::BodyTooLarge {
                    request_id: request_id.clone(),
                })?;
        if status.is_success() || accepted_status == Some(status) {
            return Ok(NotaryResponse {
                body: bytes,
                status,
                request_id,
                retry_after,
            });
        }
        match error_kind {
            ErrorKind::Problem => {
                let problem = serde_json::from_slice::<ProblemDetails>(&bytes).map_err(|_| {
                    NotaryClientError::Decode {
                        status,
                        request_id: request_id.clone(),
                    }
                })?;
                Err(NotaryClientError::Problem {
                    status,
                    problem: Box::new(problem),
                    request_id,
                    retry_after,
                })
            }
            ErrorKind::Oid4vci => {
                let error = serde_json::from_slice::<Oid4vciError>(&bytes).map_err(|_| {
                    NotaryClientError::Decode {
                        status,
                        request_id: request_id.clone(),
                    }
                })?;
                Err(NotaryClientError::Oid4vci {
                    status,
                    error,
                    request_id,
                    retry_after,
                })
            }
        }
    }

    fn prepare_purpose(
        &self,
        mut options: RequestOptions,
        body_purpose: Option<&str>,
    ) -> Result<RequestOptions, NotaryClientBuildError> {
        if options.purpose.is_none() {
            options.purpose = self
                .default_purpose
                .clone()
                .or_else(|| body_purpose.map(ToOwned::to_owned));
        }
        if let (Some(header), Some(body)) = (options.purpose.as_deref(), body_purpose) {
            if header != body {
                return Err(NotaryClientBuildError::PurposeConflict);
            }
        }
        Ok(options)
    }

    fn reject_idempotency(&self, options: &RequestOptions) -> Result<(), NotaryClientBuildError> {
        if options.idempotency_key.is_some() {
            Err(NotaryClientBuildError::UnsupportedIdempotencyKey)
        } else {
            Ok(())
        }
    }

    fn url(&self, path: &str) -> Result<Url, NotaryClientBuildError> {
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|err| NotaryClientBuildError::Url(err.to_string()))
    }
}

#[cfg(all(feature = "oid4vci", feature = "verifier"))]
fn oid4vci_compact_credential(
    credential: &registry_platform_oid4vci::CredentialValue,
) -> Result<&str, VerificationError> {
    match credential {
        registry_platform_oid4vci::CredentialValue::String(compact) => Ok(compact.as_str()),
        registry_platform_oid4vci::CredentialValue::Object(_) => {
            Err(VerificationError::UnsupportedCredentialShape {
                code: "credential.unsupported_shape",
            })
        }
    }
}

impl NotaryClientBuilder {
    /// Configure bearer-token authentication.
    #[must_use]
    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(SecretString::from(token.into()));
        self
    }

    /// Configure API-key authentication.
    #[must_use]
    pub fn api_key(mut self, token: impl Into<String>) -> Self {
        self.api_key = Some(SecretString::from(token.into()));
        self
    }

    /// Configure dynamic authentication.
    #[must_use]
    pub fn auth_provider(mut self, provider: Arc<dyn AuthProvider>) -> Self {
        self.auth_provider = Some(provider);
        self
    }

    /// Configure the default data purpose for evaluation requests.
    ///
    /// A body purpose must match this value unless overridden through
    /// [`RequestOptions`].
    #[must_use]
    pub fn default_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.default_purpose = Some(purpose.into());
        self
    }

    /// Configure request timeout. Defaults to 30 seconds.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Configure the `User-Agent` header.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Configure route-aware retry behavior.
    #[must_use]
    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = Some(retry_policy);
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Override the HTTP client in tests.
    ///
    /// This is intentionally unavailable in production builds because it can
    /// bypass transport safety defaults.
    #[must_use]
    pub fn reqwest_client(mut self, client: reqwest::Client) -> Self {
        self.reqwest_client = Some(client);
        self
    }

    /// Build the client and validate base URL and auth configuration.
    pub fn build(self) -> Result<RegistryNotaryClient, NotaryClientBuildError> {
        let base_url = self.base_url.unwrap_or_default();
        let mut base_url =
            Url::parse(&base_url).map_err(|err| NotaryClientBuildError::Url(err.to_string()))?;
        if !base_url.path().ends_with('/') {
            base_url
                .path_segments_mut()
                .map_err(|_| NotaryClientBuildError::Url("base URL cannot be a base".to_string()))?
                .push("");
        }
        validate_base_url(&base_url)?;
        let auth_count = usize::from(self.bearer_token.is_some())
            + usize::from(self.api_key.is_some())
            + usize::from(self.auth_provider.is_some());
        if auth_count > 1 {
            return Err(NotaryClientBuildError::MultipleAuthModes);
        }
        let auth = if let Some(token) = self.bearer_token {
            Some(AuthState::Static(Auth::Bearer(token)))
        } else if let Some(token) = self.api_key {
            Some(AuthState::Static(Auth::ApiKey(token)))
        } else {
            self.auth_provider.map(AuthState::Provider)
        };
        #[cfg(any(test, feature = "test-support"))]
        let http = if let Some(client) = self.reqwest_client {
            client
        } else {
            build_http_client(self.timeout, self.user_agent)
        };
        #[cfg(not(any(test, feature = "test-support")))]
        let http = build_http_client(self.timeout, self.user_agent);
        Ok(RegistryNotaryClient {
            base_url,
            http,
            auth,
            default_purpose: self.default_purpose,
            retry_policy: self.retry_policy.unwrap_or_default(),
            jwks_cache: Arc::new(Mutex::new(None)),
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum ErrorKind {
    Problem,
    #[cfg_attr(not(feature = "oid4vci"), allow(dead_code))]
    Oid4vci,
}

#[derive(Debug, Clone, Copy)]
enum RouteRetry {
    Get,
    PostBatch,
    PostNoRetry,
}

fn allowed_attempts(policy: &RetryPolicy, route: RouteRetry, options: &RequestOptions) -> usize {
    match route {
        RouteRetry::Get => policy.max_attempts.max(1),
        RouteRetry::PostBatch if options.idempotency_key.is_some() => policy.max_attempts.max(1),
        RouteRetry::PostBatch | RouteRetry::PostNoRetry => 1,
    }
}

fn should_retry(policy: &RetryPolicy, error: &NotaryClientError) -> bool {
    match error {
        NotaryClientError::Transport(_) => policy.retry_transport_errors,
        NotaryClientError::Problem { status, .. } | NotaryClientError::Oid4vci { status, .. } => {
            (*status == StatusCode::TOO_MANY_REQUESTS && policy.retry_rate_limited)
                || (*status == StatusCode::SERVICE_UNAVAILABLE && policy.retry_unavailable)
        }
        _ => false,
    }
}

fn retry_delay(policy: &RetryPolicy, attempt: usize, error: &NotaryClientError) -> Duration {
    if let Some(crate::RetryAfter::Delta(delay)) = error.retry_after() {
        return (*delay).min(policy.max_delay);
    }
    let multiplier = 1_u32
        .checked_shl(attempt.saturating_sub(1) as u32)
        .unwrap_or(u32::MAX);
    policy
        .base_delay
        .saturating_mul(multiplier)
        .min(policy.max_delay)
}

fn build_http_client(timeout: Option<Duration>, user_agent: Option<String>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout.unwrap_or(Duration::from_secs(30)))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some(user_agent) = user_agent {
        builder = builder.user_agent(user_agent);
    }
    builder
        .build()
        .expect("registry notary client options are valid")
}

fn validate_base_url(url: &Url) -> Result<(), NotaryClientBuildError> {
    if url.scheme() == "https" {
        return Ok(());
    }
    #[cfg(any(debug_assertions, feature = "test-support"))]
    {
        if url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
        {
            return Ok(());
        }
    }
    Err(NotaryClientBuildError::InsecureBaseUrl)
}

fn encode_path_segment(segment: &str) -> String {
    segment
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

#[cfg_attr(not(feature = "oid4vci"), allow(dead_code))]
fn encode_query_value(value: &str) -> String {
    encode_path_segment(value).replace("%20", "+")
}

/// Fluent builder for one high-level evaluation request.
pub struct EvaluateBuilder<'a> {
    client: &'a RegistryNotaryClient,
    target: EvidenceEntity,
    requester: Option<EvidenceEntity>,
    relationship: Option<EvidenceRelationship>,
    on_behalf_of: Option<EvidenceOnBehalfOf>,
    variables: BTreeMap<String, String>,
    claims: Vec<ClaimRef>,
    disclosure: Option<String>,
    format: Option<String>,
    purpose: Option<String>,
    request_id: Option<String>,
    traceparent: Option<String>,
}

impl<'a> EvaluateBuilder<'a> {
    /// Set the target entity id.
    #[must_use]
    pub fn target_id(mut self, id: impl Into<String>) -> Self {
        self.target.id = Some(id.into());
        self
    }

    /// Add a target identifier.
    #[must_use]
    pub fn target_identifier(
        mut self,
        scheme: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.target.identifiers.push(EvidenceIdentifier {
            scheme: scheme.into(),
            value: value.into(),
            issuer: None,
            country: None,
        });
        self
    }

    /// Set the issuer on the most recently added target identifier.
    #[must_use]
    pub fn target_identifier_issuer(mut self, issuer: impl Into<String>) -> Self {
        if let Some(identifier) = self.target.identifiers.last_mut() {
            identifier.issuer = Some(issuer.into());
        }
        self
    }

    /// Set the country on the most recently added target identifier.
    #[must_use]
    pub fn target_identifier_country(mut self, country: impl Into<String>) -> Self {
        if let Some(identifier) = self.target.identifiers.last_mut() {
            identifier.country = Some(country.into());
        }
        self
    }

    /// Add a target matching attribute.
    #[must_use]
    pub fn target_attribute(
        mut self,
        name: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.target.attributes.insert(name.into(), value.into());
        self
    }

    /// Set a pre-built target entity.
    #[must_use]
    pub fn target(mut self, target: EvidenceEntity) -> Self {
        self.target = target;
        self
    }

    /// Set the requester entity.
    #[must_use]
    pub fn requester(mut self, requester: EvidenceEntity) -> Self {
        self.requester = Some(requester);
        self
    }

    /// Set the relationship type between requester and target.
    #[must_use]
    pub fn relationship(mut self, relationship_type: impl Into<String>) -> Self {
        self.relationship = Some(EvidenceRelationship {
            relationship_type: relationship_type.into(),
            attributes: BTreeMap::new(),
        });
        self
    }

    /// Add an attribute to the requester-target relationship.
    #[must_use]
    pub fn relationship_attribute(
        mut self,
        name: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        let relationship = self
            .relationship
            .get_or_insert_with(|| EvidenceRelationship {
                relationship_type: "unspecified".to_string(),
                attributes: BTreeMap::new(),
            });
        relationship.attributes.insert(name.into(), value.into());
        self
    }

    /// Set the delegated/on-behalf-of context using the frozen minimal actor
    /// envelope. Simple deployments omit this entirely.
    #[must_use]
    pub fn on_behalf_of(mut self, on_behalf_of: EvidenceOnBehalfOf) -> Self {
        self.on_behalf_of = Some(on_behalf_of);
        self
    }

    /// Add one declared RFC 3339 full-date request variable.
    #[must_use]
    pub fn request_variable_date(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.variables.insert(name.into(), value.into());
        self
    }

    /// Set the identifier type for the first target identifier.
    ///
    /// Prefer [`Self::target_identifier`] for new code.
    #[must_use]
    pub fn id_type(mut self, id_type: impl Into<String>) -> Self {
        let subject_id = self.target.id.take().unwrap_or_default();
        self.target.identifiers.insert(
            0,
            EvidenceIdentifier {
                scheme: id_type.into(),
                value: subject_id,
                issuer: None,
                country: None,
            },
        );
        self
    }

    /// Add one claim id.
    #[must_use]
    pub fn claim(mut self, claim: impl Into<String>) -> Self {
        self.claims.push(ClaimRef::new(claim.into()));
        self
    }

    /// Add multiple claim ids.
    #[must_use]
    pub fn claims<I, S>(mut self, claims: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.claims
            .extend(claims.into_iter().map(|claim| ClaimRef::new(claim.into())));
        self
    }

    /// Set the disclosure mode.
    #[must_use]
    pub fn disclosure(mut self, disclosure: impl Into<String>) -> Self {
        self.disclosure = Some(disclosure.into());
        self
    }

    /// Set the requested response format.
    #[must_use]
    pub fn format(mut self, format: impl Into<String>) -> Self {
        self.format = Some(format.into());
        self
    }

    /// Set the data purpose for this request.
    #[must_use]
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    /// Set `X-Request-Id` for this request.
    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Set W3C `traceparent` for this request.
    #[must_use]
    pub fn traceparent(mut self, traceparent: impl Into<String>) -> Self {
        self.traceparent = Some(traceparent.into());
        self
    }

    /// Send the evaluation request.
    pub async fn send(self) -> Result<NotaryResponse<Evaluation>, NotaryClientError> {
        let variables = RequestVariables::try_new(self.variables)
            .map_err(|_| NotaryClientBuildError::RequestSerialization)?;
        let request = EvaluateRequest {
            requester: self.requester,
            target: Some(self.target),
            relationship: self.relationship,
            on_behalf_of: self.on_behalf_of,
            variables,
            claims: self.claims,
            disclosure: self.disclosure,
            format: self.format,
            purpose: self.purpose.clone(),
        };
        let options = RequestOptions {
            purpose: self.purpose,
            request_id: self.request_id,
            traceparent: self.traceparent,
            accept: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            ..RequestOptions::default()
        };
        self.client
            .evaluate_request(request, options)
            .await
            .map(|response| {
                let request_id = response.request_id;
                let retry_after = response.retry_after;
                let results = response.body.results;
                NotaryResponse {
                    body: Evaluation { results },
                    status: response.status,
                    request_id,
                    retry_after,
                }
            })
    }
}
