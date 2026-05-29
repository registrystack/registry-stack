// SPDX-License-Identifier: Apache-2.0
//! Typed Registry Notary HTTP client.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use registry_notary_core::{
    BatchEvaluateRequest, ClaimRef, CredentialIssueRequest, EvaluateRequest, RenderRequest,
    SubjectRequest, FORMAT_CLAIM_RESULT_JSON,
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
    ListClaimsResponse, NotaryResponse,
};

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
    #[must_use]
    pub fn builder(base_url: impl Into<String>) -> NotaryClientBuilder {
        NotaryClientBuilder {
            base_url: Some(base_url.into()),
            ..NotaryClientBuilder::default()
        }
    }

    pub async fn health(&self) -> Result<NotaryResponse<HealthResponse>, NotaryClientError> {
        self.get_json(
            "/healthz",
            RequestOptions::default(),
            LIMIT_SMALL,
            ErrorKind::Problem,
        )
        .await
    }

    pub async fn ready(&self) -> Result<NotaryResponse<HealthResponse>, NotaryClientError> {
        self.get_json_accepting_status(
            "/ready",
            RequestOptions::default(),
            LIMIT_SMALL,
            ErrorKind::Problem,
            Some(StatusCode::SERVICE_UNAVAILABLE),
        )
        .await
    }

    pub async fn admin_reload(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<AdminReloadResponse>, NotaryClientError> {
        self.post_json(
            "/admin/reload",
            &serde_json::json!({}),
            options,
            LIMIT_SMALL,
            RouteRetry::PostNoRetry,
            ErrorKind::Problem,
        )
        .await
    }

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
                    request_id: None,
                    retry_after: None,
                });
            }
        }
        self.fetch_issuer_jwks(options).await
    }

    pub async fn refresh_jwks(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<serde_json::Value>, NotaryClientError> {
        self.fetch_issuer_jwks(options).await
    }

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
        String::from_utf8(response.body).map_or_else(
            |_| {
                Err(NotaryClientError::Decode {
                    status: StatusCode::OK,
                    request_id,
                })
            },
            |body| {
                Ok(NotaryResponse {
                    body,
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

    #[cfg(feature = "oid4vci")]
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

    pub async fn list_claims(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<ListClaimsResponse>, NotaryClientError> {
        self.get_json("/claims", options, LIMIT_DISCOVERY, ErrorKind::Problem)
            .await
    }

    pub async fn get_claim(
        &self,
        claim_id: &str,
        options: RequestOptions,
    ) -> Result<NotaryResponse<serde_json::Value>, NotaryClientError> {
        self.get_json(
            &format!("/claims/{}", encode_path_segment(claim_id)),
            options,
            LIMIT_DISCOVERY,
            ErrorKind::Problem,
        )
        .await
    }

    pub async fn list_formats(
        &self,
        options: RequestOptions,
    ) -> Result<NotaryResponse<FormatsResponse>, NotaryClientError> {
        self.get_json("/formats", options, LIMIT_DISCOVERY, ErrorKind::Problem)
            .await
    }

    #[must_use]
    pub fn evaluate(&self, subject_id: impl Into<String>) -> EvaluateBuilder<'_> {
        EvaluateBuilder {
            client: self,
            subject_id: subject_id.into(),
            id_type: None,
            claims: Vec::new(),
            disclosure: None,
            format: None,
            purpose: None,
            request_id: None,
            traceparent: None,
        }
    }

    pub async fn evaluate_dto(
        &self,
        mut request: EvaluateRequest,
        options: RequestOptions,
    ) -> Result<NotaryResponse<EvaluateResponse>, NotaryClientError> {
        let mut options = self.prepare_purpose(options, request.purpose.as_deref())?;
        options.accept = options
            .accept
            .or_else(|| Some(FORMAT_CLAIM_RESULT_JSON.to_string()));
        request.purpose = options.purpose.clone();
        let mut request = request;
        if request.format.is_none() {
            request.format = Some(FORMAT_CLAIM_RESULT_JSON.to_string());
        }
        self.post_json(
            "/claims/evaluate",
            &request,
            options,
            LIMIT_OPERATION,
            RouteRetry::PostNoRetry,
            ErrorKind::Problem,
        )
        .await
    }

    pub async fn batch_evaluate_dto(
        &self,
        mut request: BatchEvaluateRequest,
        options: RequestOptions,
    ) -> Result<NotaryResponse<registry_notary_core::BatchEvaluateResponse>, NotaryClientError>
    {
        let mut options = self.prepare_purpose(options, request.purpose.as_deref())?;
        options.accept = options
            .accept
            .or_else(|| Some(FORMAT_CLAIM_RESULT_JSON.to_string()));
        request.purpose = options.purpose.clone();
        if request.format.is_none() {
            request.format = Some(FORMAT_CLAIM_RESULT_JSON.to_string());
        }
        self.post_json(
            "/claims/batch-evaluate",
            &request,
            options,
            LIMIT_BATCH,
            RouteRetry::PostBatch,
            ErrorKind::Problem,
        )
        .await
    }

    pub async fn render_dto(
        &self,
        request: RenderRequest,
        options: RequestOptions,
    ) -> Result<NotaryResponse<serde_json::Value>, NotaryClientError> {
        self.reject_idempotency(&options)?;
        self.post_json(
            "/evidence/render",
            &request,
            options,
            LIMIT_OPERATION,
            RouteRetry::PostNoRetry,
            ErrorKind::Problem,
        )
        .await
    }

    pub async fn issue_credential_dto(
        &self,
        request: CredentialIssueRequest,
        options: RequestOptions,
    ) -> Result<NotaryResponse<CredentialIssueResponse>, NotaryClientError> {
        self.reject_idempotency(&options)?;
        self.post_json(
            "/credentials/issue",
            &request,
            options,
            LIMIT_OPERATION,
            RouteRetry::PostNoRetry,
            ErrorKind::Problem,
        )
        .await
    }

    pub async fn credential_status(
        &self,
        credential_id: &str,
        options: RequestOptions,
    ) -> Result<NotaryResponse<CredentialStatusResponse>, NotaryClientError> {
        self.get_json(
            &format!("/credentials/status/{}", encode_path_segment(credential_id)),
            options,
            LIMIT_SMALL,
            ErrorKind::Problem,
        )
        .await
    }

    pub async fn update_credential_status(
        &self,
        credential_id: &str,
        status: impl Into<String>,
        options: RequestOptions,
    ) -> Result<NotaryResponse<CredentialStatusResponse>, NotaryClientError> {
        self.reject_idempotency(&options)?;
        self.post_json(
            &format!(
                "/admin/credentials/status/{}",
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
            String::from_utf8(response.body).map_or_else(
                |_| {
                    Err(NotaryClientError::Decode {
                        status: StatusCode::OK,
                        request_id,
                    })
                },
                |body| {
                    Ok(NotaryResponse {
                        body,
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
                status: StatusCode::OK,
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
                status: StatusCode::OK,
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
            options.purpose = self.default_purpose.clone();
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

impl NotaryClientBuilder {
    #[must_use]
    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(SecretString::from(token.into()));
        self
    }

    #[must_use]
    pub fn api_key(mut self, token: impl Into<String>) -> Self {
        self.api_key = Some(SecretString::from(token.into()));
        self
    }

    #[must_use]
    pub fn auth_provider(mut self, provider: Arc<dyn AuthProvider>) -> Self {
        self.auth_provider = Some(provider);
        self
    }

    #[must_use]
    pub fn default_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.default_purpose = Some(purpose.into());
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    #[must_use]
    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = Some(retry_policy);
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn reqwest_client(mut self, client: reqwest::Client) -> Self {
        self.reqwest_client = Some(client);
        self
    }

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

pub struct EvaluateBuilder<'a> {
    client: &'a RegistryNotaryClient,
    subject_id: String,
    id_type: Option<String>,
    claims: Vec<ClaimRef>,
    disclosure: Option<String>,
    format: Option<String>,
    purpose: Option<String>,
    request_id: Option<String>,
    traceparent: Option<String>,
}

impl<'a> EvaluateBuilder<'a> {
    #[must_use]
    pub fn id_type(mut self, id_type: impl Into<String>) -> Self {
        self.id_type = Some(id_type.into());
        self
    }

    #[must_use]
    pub fn claim(mut self, claim: impl Into<String>) -> Self {
        self.claims.push(ClaimRef::new(claim.into()));
        self
    }

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

    #[must_use]
    pub fn disclosure(mut self, disclosure: impl Into<String>) -> Self {
        self.disclosure = Some(disclosure.into());
        self
    }

    #[must_use]
    pub fn format(mut self, format: impl Into<String>) -> Self {
        self.format = Some(format.into());
        self
    }

    #[must_use]
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    #[must_use]
    pub fn traceparent(mut self, traceparent: impl Into<String>) -> Self {
        self.traceparent = Some(traceparent.into());
        self
    }

    pub async fn send(self) -> Result<NotaryResponse<Evaluation>, NotaryClientError> {
        let request = EvaluateRequest {
            subject: SubjectRequest {
                id: self.subject_id,
                id_type: self.id_type,
            },
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
            .evaluate_dto(request, options)
            .await
            .map(|response| {
                let request_id = response.request_id;
                let retry_after = response.retry_after;
                let results = response.body.results;
                NotaryResponse {
                    body: Evaluation { results },
                    request_id,
                    retry_after,
                }
            })
    }
}
