// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Witness assembly, auth, audit, and HTTP source connectors.

use std::collections::BTreeMap;
use std::env;
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use registry_witness_core::sd_jwt::EvidenceIssuer;
use registry_witness_core::{
    BulkMode, DciSourceConnectionConfig, EvidenceAuditEvent, EvidenceConfig,
    EvidenceCredentialConfig, EvidenceError, EvidencePrincipal, SourceBindingConfig,
    SourceConnectorKind, StandaloneRegistryWitnessConfig, SubjectRequest,
};
use serde_json::{json, Map, Value};
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;

use crate::{
    router, EvidenceAuditContext, EvidenceErrorCodeContext, EvidenceIssuerResolver, EvidenceStore,
    RegistryWitnessApiState, SourceReader,
};

const SOURCE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SOURCE_JSON_BYTES: usize = 1024 * 1024;

pub fn standalone_router(
    config: StandaloneRegistryWitnessConfig,
) -> Result<Router, StandaloneServerError> {
    config.validate()?;
    let evidence = Arc::new(config.evidence.clone());
    let source = Arc::new(HttpEvidenceSources::from_config(&config.evidence)?);
    let store = Arc::new(EvidenceStore::default());
    let issuers = Arc::new(EvidenceIssuerRegistry::from_config(&config.evidence)?);
    let api_state = Arc::new(RegistryWitnessApiState::new(
        evidence, source, store, issuers,
    ));
    let auth_state = Arc::new(AuthAuditState::from_config(&config)?);

    Ok(router()
        .layer(axum::Extension(api_state))
        .layer(from_fn_with_state(auth_state, auth_audit_middleware)))
}

#[derive(Debug, thiserror::Error)]
pub enum StandaloneServerError {
    #[error(transparent)]
    Config(#[from] registry_witness_core::EvidenceConfigError),
    #[error("configured credential environment variable is missing or empty: {0}")]
    MissingCredentialEnv(String),
    #[error("configured source token environment variable is missing or empty: {0}")]
    MissingSourceTokenEnv(String),
    #[error("credential issuer environment variable is missing or invalid: {0}")]
    InvalidIssuerEnv(String),
    #[error("audit sink path is required when sink=file")]
    MissingAuditPath,
    #[error("audit sink file could not be opened")]
    AuditOpen(#[source] std::io::Error),
    #[error("unsupported audit sink: {0}")]
    InvalidAuditSink(String),
    #[error("failed to build HTTP source client")]
    HttpClient(#[source] reqwest::Error),
}

#[derive(Clone)]
struct ResolvedEvidenceSourceConnection {
    id: String,
    base_url: String,
    bearer_token: String,
    dci: DciSourceConnectionConfig,
    /// Process-global cap on concurrent outbound calls to this connection.
    /// Permits are acquired in `read_one` and held across retries so a flaky
    /// upstream cannot temporarily exceed the politeness cap by quick retry.
    semaphore: Arc<Semaphore>,
    max_in_flight: usize,
    /// Bulk-read mode for this connection. See `BulkMode` for the available
    /// strategies. `None` disables bulk specialization and the runtime never
    /// invokes the specialized `read_many` path for this connection.
    bulk_mode: BulkMode,
    /// Upper bound for the per-call timeout used by `read_many`.
    bulk_timeout_max: Duration,
}

impl std::fmt::Debug for ResolvedEvidenceSourceConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedEvidenceSourceConnection")
            .field("id", &self.id)
            .field("base_url", &self.base_url)
            .field("bearer_token", &"<redacted>")
            .field("dci", &self.dci)
            .field("max_in_flight", &self.max_in_flight)
            .field("bulk_mode", &self.bulk_mode)
            .field("bulk_timeout_max", &self.bulk_timeout_max)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct HttpEvidenceSources {
    client: reqwest::Client,
    request_timeout: Duration,
    source_connections: BTreeMap<String, ResolvedEvidenceSourceConnection>,
}

impl HttpEvidenceSources {
    pub fn from_config(config: &EvidenceConfig) -> Result<Self, StandaloneServerError> {
        let mut source_connections = BTreeMap::new();
        for (id, connection) in &config.source_connections {
            let bearer_token = env::var(&connection.token_env)
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    StandaloneServerError::MissingSourceTokenEnv(connection.token_env.clone())
                })?;
            source_connections.insert(
                id.clone(),
                ResolvedEvidenceSourceConnection {
                    id: id.clone(),
                    base_url: connection.base_url.clone(),
                    bearer_token,
                    dci: connection.dci.clone(),
                    semaphore: Arc::new(Semaphore::new(connection.max_in_flight)),
                    max_in_flight: connection.max_in_flight,
                    bulk_mode: connection.bulk_mode,
                    bulk_timeout_max: Duration::from_millis(connection.bulk_timeout_max_ms),
                },
            );
        }
        let client = reqwest::Client::builder()
            .timeout(SOURCE_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(StandaloneServerError::HttpClient)?;
        Ok(Self {
            client,
            request_timeout: SOURCE_REQUEST_TIMEOUT,
            source_connections,
        })
    }

    fn source_connection(
        &self,
        binding: &SourceBindingConfig,
    ) -> Option<&ResolvedEvidenceSourceConnection> {
        binding
            .connection
            .as_deref()
            .and_then(|connection| self.source_connections.get(connection))
    }
}

impl SourceReader for HttpEvidenceSources {
    fn read_one<'a>(
        &'a self,
        binding: &'a SourceBindingConfig,
        subject: &'a SubjectRequest,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            let connection = self
                .source_connection(binding)
                .ok_or(EvidenceError::SourceUnavailable)?;
            match binding.connector {
                SourceConnectorKind::RegistryDataApi => {
                    read_remote_registry_data_api_one(self, connection, binding, subject, purpose)
                        .await
                }
                SourceConnectorKind::Dci => {
                    read_external_dci_http_one(self, connection, binding, subject, purpose).await
                }
            }
        })
    }

    fn read_many<'a>(
        &'a self,
        bindings: Vec<(SourceBindingConfig, SubjectRequest)>,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
        Box::pin(async move {
            if bindings.is_empty() {
                return Vec::new();
            }
            // Determine the bulk mode from the first binding's connection.
            // The runtime guarantees every binding in this batch shares the
            // same (connection_id, dataset, entity, lookup_field, fields)
            // tuple, so they share `bulk_mode` too.
            let connection = match self.source_connection(&bindings[0].0) {
                Some(c) => c,
                None => {
                    return bindings
                        .iter()
                        .map(|_| Err(EvidenceError::SourceUnavailable))
                        .collect();
                }
            };
            tracing::info!(
                target: "registry_witness_server::bulk",
                connection_id = %connection.id,
                bulk_mode = ?connection.bulk_mode,
                bulk_request_size = bindings.len(),
                "bulk_request_size",
            );
            let outcome: Vec<Result<Value, EvidenceError>> = match connection.bulk_mode {
                BulkMode::None => {
                    tracing::info!(
                        target: "registry_witness_server::bulk",
                        connection_id = %connection.id,
                        path = "fallback",
                        "bulk_vs_fallback",
                    );
                    fallback_concurrent_read_one(self, &bindings, purpose).await
                }
                BulkMode::RdaInFilter => {
                    tracing::info!(
                        target: "registry_witness_server::bulk",
                        connection_id = %connection.id,
                        path = "bulk",
                        "bulk_vs_fallback",
                    );
                    read_remote_registry_data_api_many(self, connection, &bindings, purpose).await
                }
                BulkMode::DciBatchedSearch => {
                    tracing::info!(
                        target: "registry_witness_server::bulk",
                        connection_id = %connection.id,
                        path = "bulk",
                        "bulk_vs_fallback",
                    );
                    read_external_dci_http_many(self, connection, &bindings, purpose).await
                }
            };
            outcome
        })
    }

    fn required_scopes(
        &self,
        evidence: &EvidenceConfig,
        claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        let mut scopes = Vec::new();
        collect_claim_required_scopes(evidence, claim_id, &mut scopes)?;
        scopes.sort();
        scopes.dedup();
        Ok(scopes)
    }
}

/// Run `read_one` concurrently for each binding (collision-fallback path for
/// bulk specializations and the BulkMode::None branch).
async fn fallback_concurrent_read_one(
    sources: &HttpEvidenceSources,
    bindings: &[(SourceBindingConfig, SubjectRequest)],
    purpose: &str,
) -> Vec<Result<Value, EvidenceError>> {
    use std::task::{Context, Poll};

    if bindings.is_empty() {
        return Vec::new();
    }
    #[allow(clippy::type_complexity)]
    let mut futures: Vec<
        Option<Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + '_>>>,
    > = bindings
        .iter()
        .map(|(binding, subject)| Some(sources.read_one(binding, subject, purpose)))
        .collect();
    let mut results: Vec<Option<Result<Value, EvidenceError>>> =
        (0..futures.len()).map(|_| None).collect();
    std::future::poll_fn(move |cx: &mut Context<'_>| {
        let mut all_done = true;
        for (idx, slot) in futures.iter_mut().enumerate() {
            if let Some(fut) = slot.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        results[idx] = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => {
                        all_done = false;
                    }
                }
            }
        }
        if all_done {
            Poll::Ready(std::mem::take(&mut results))
        } else {
            Poll::Pending
        }
    })
    .await
    .into_iter()
    .map(|slot| slot.expect("every slot populated"))
    .collect()
}

/// Batch-aware timeout budget: scale the per-call timeout with N up to a
/// configured cap. Default RDA/DCI single-call timeout is
/// `SOURCE_REQUEST_TIMEOUT` (10s); a 100-subject bulk call gets 10 * ceil(100/10)
/// = 100s, capped at `bulk_timeout_max` (30s by default).
fn bulk_timeout(connection: &ResolvedEvidenceSourceConnection, batch_size: usize) -> Duration {
    let base = SOURCE_REQUEST_TIMEOUT.as_millis() as u64;
    let factor = batch_size.div_ceil(10).max(1) as u64;
    let scaled = Duration::from_millis(base.saturating_mul(factor));
    scaled.min(connection.bulk_timeout_max)
}

#[derive(Debug, Clone, Default)]
pub struct EvidenceIssuerRegistry {
    issuers: BTreeMap<String, EvidenceIssuer>,
}

impl EvidenceIssuerRegistry {
    pub fn from_config(config: &EvidenceConfig) -> Result<Self, StandaloneServerError> {
        let mut issuers = BTreeMap::new();
        for (profile_id, profile) in &config.credential_profiles {
            let raw = env::var(&profile.issuer_key_env)
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    StandaloneServerError::InvalidIssuerEnv(profile.issuer_key_env.clone())
                })?;
            let issuer = EvidenceIssuer::from_profile_key(profile, &raw).map_err(|_| {
                StandaloneServerError::InvalidIssuerEnv(profile.issuer_key_env.clone())
            })?;
            issuers.insert(profile_id.clone(), issuer);
        }
        Ok(Self { issuers })
    }
}

impl EvidenceIssuerResolver for EvidenceIssuerRegistry {
    fn issuer(&self, profile_id: &str) -> Result<EvidenceIssuer, EvidenceError> {
        self.issuers
            .get(profile_id)
            .cloned()
            .ok_or(EvidenceError::CredentialIssuerNotConfigured)
    }
}

/// Bench-internal: exposed only so `benches/auth_bench.rs` can construct
/// fixtures. Production code goes through `resolve_credentials`, which reads
/// the token from `EvidenceCredentialConfig::token_env`. Not part of the
/// public API; do not depend on this shape from outside the workspace.
#[doc(hidden)]
#[derive(Clone)]
pub struct ResolvedCredential {
    pub id: String,
    pub token: String,
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("id", &self.id)
            .field("token", &"<redacted>")
            .field("scopes", &self.scopes)
            .finish()
    }
}

#[derive(Debug)]
struct AuthAuditState {
    api_keys: Vec<ResolvedCredential>,
    bearer_tokens: Vec<ResolvedCredential>,
    audit: AuditSink,
}

impl AuthAuditState {
    fn from_config(
        config: &StandaloneRegistryWitnessConfig,
    ) -> Result<Self, StandaloneServerError> {
        Ok(Self {
            api_keys: resolve_credentials(&config.auth.api_keys)?,
            bearer_tokens: resolve_credentials(&config.auth.bearer_tokens)?,
            audit: AuditSink::from_config(&config.audit)?,
        })
    }

    fn authenticate(&self, request: &Request) -> Result<EvidencePrincipal, EvidenceError> {
        if let Some(value) = request.headers().get("x-api-key").and_then(header_str) {
            if let Some(credential) = find_credential(&self.api_keys, value) {
                return Ok(principal_from_credential(credential));
            }
        }
        if let Some(value) = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(header_str)
            .and_then(bearer_auth_token)
        {
            if let Some(credential) = find_credential(&self.bearer_tokens, value) {
                return Ok(principal_from_credential(credential));
            }
        }
        Err(EvidenceError::MissingCredential)
    }
}

enum AuditSink {
    Stdout(Mutex<Box<dyn Write + Send>>),
    File(Mutex<Box<dyn Write + Send>>),
}

impl std::fmt::Debug for AuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdout(_) => f.debug_tuple("Stdout").finish(),
            Self::File(_) => f.debug_tuple("File").finish(),
        }
    }
}

impl AuditSink {
    fn from_config(
        config: &registry_witness_core::EvidenceAuditConfig,
    ) -> Result<Self, StandaloneServerError> {
        match config.sink.as_str() {
            "stdout" => Ok(Self::Stdout(Mutex::new(Box::new(std::io::stdout())))),
            "file" | "jsonl" => {
                let path = config
                    .path
                    .as_deref()
                    .ok_or(StandaloneServerError::MissingAuditPath)?;
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(StandaloneServerError::AuditOpen)?;
                Ok(Self::File(Mutex::new(Box::new(file))))
            }
            sink => Err(StandaloneServerError::InvalidAuditSink(sink.to_string())),
        }
    }

    fn emit(&self, event: &EvidenceAuditEvent) -> io::Result<()> {
        match self {
            Self::Stdout(writer) | Self::File(writer) => {
                let mut writer = writer
                    .lock()
                    .map_err(|_| io::Error::other("audit sink mutex is poisoned"))?;
                write_audit_jsonl(&mut **writer, event)
            }
        }
    }
}

fn write_audit_jsonl<W: Write + ?Sized>(
    writer: &mut W,
    event: &EvidenceAuditEvent,
) -> io::Result<()> {
    let line = serde_json::to_vec(event).map_err(io::Error::other)?;
    writer.write_all(&line)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

async fn auth_audit_middleware(
    State(state): State<Arc<AuthAuditState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let principal = match state.authenticate(&request) {
        Ok(principal) => principal,
        Err(error) => {
            let response = crate::api::evidence_error_response(error);
            return match emit_audit(&state, None, &method, &path, &response) {
                Ok(()) => response,
                Err(error) => audit_error_response(error),
            };
        }
    };
    request.extensions_mut().insert(principal.clone());
    let response = next.run(request).await;
    match emit_audit(&state, Some(&principal), &method, &path, &response) {
        Ok(()) => response,
        Err(error) => audit_error_response(error),
    }
}

fn emit_audit(
    state: &AuthAuditState,
    principal: Option<&EvidencePrincipal>,
    method: &str,
    path: &str,
    response: &Response,
) -> io::Result<()> {
    let audit = response.extensions().get::<EvidenceAuditContext>();
    let error = response.extensions().get::<EvidenceErrorCodeContext>();
    let decision = audit
        .and_then(|context| context.verification_decision.clone())
        .unwrap_or_else(|| {
            if response.status().is_success() {
                "allowed".to_string()
            } else {
                "denied".to_string()
            }
        });
    let occurred_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    state.audit.emit(&EvidenceAuditEvent {
        event_id: Ulid::new().to_string(),
        occurred_at,
        principal_id: principal.map(|principal| principal.principal_id.clone()),
        decision,
        method: method.to_string(),
        path: path.to_string(),
        status: response.status().as_u16(),
        verification_id: audit.and_then(|context| context.verification_id.clone()),
        claim_hash: audit.and_then(|context| context.claim_hash.clone()),
        row_count: audit.and_then(|context| context.row_count),
        error_code: error.map(|context| context.0.clone()),
    })
}

fn resolve_credentials(
    credentials: &[EvidenceCredentialConfig],
) -> Result<Vec<ResolvedCredential>, StandaloneServerError> {
    credentials
        .iter()
        .map(|credential| {
            let token = env::var(&credential.token_env)
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    StandaloneServerError::MissingCredentialEnv(credential.token_env.clone())
                })?;
            Ok(ResolvedCredential {
                id: credential.id.clone(),
                token,
                scopes: credential.scopes.clone(),
            })
        })
        .collect()
}

/// Bench-internal: exposed only for `benches/auth_bench.rs`. Not part of the
/// public API.
#[doc(hidden)]
pub fn find_credential<'a>(
    credentials: &'a [ResolvedCredential],
    token: &str,
) -> Option<&'a ResolvedCredential> {
    credentials
        .iter()
        .find(|credential| credential.token.as_bytes().ct_eq(token.as_bytes()).into())
}

fn principal_from_credential(credential: &ResolvedCredential) -> EvidencePrincipal {
    EvidencePrincipal {
        principal_id: credential.id.clone(),
        scopes: credential.scopes.clone(),
    }
}

fn header_str(value: &axum::http::HeaderValue) -> Option<&str> {
    value.to_str().ok()
}

/// Bench-internal: exposed only for `benches/auth_bench.rs`. Not part of the
/// public API.
#[doc(hidden)]
pub fn bearer_auth_token(raw: &str) -> Option<&str> {
    let mut parts = raw.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if parts.next().is_some() || !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    Some(token)
}

fn audit_error_response(error: io::Error) -> Response {
    tracing::error!(target: "registry_witness_server::audit", error = %error, "audit event write failed");
    let status = StatusCode::INTERNAL_SERVER_ERROR;
    let mut response = (
        status,
        Json(json!({
            "type": "https://data.example.gov/problems/audit/write_failed",
            "title": "Audit write failed",
            "status": status.as_u16(),
            "detail": "audit event could not be written",
            "code": "audit.write_failed",
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/problem+json".parse().unwrap(),
    );
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext("audit.write_failed".to_string()));
    response
}

async fn read_remote_registry_data_api_one(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    let lookup_field = binding.lookup.field.clone();
    let lookup_value = lookup_value(binding, subject)?;
    let fields = projected_source_fields_with_lookup(binding, &lookup_field);
    let url = registry_data_api_url(&connection.base_url, binding)?;
    let query_pairs = vec![
        ("limit".to_string(), "2".to_string()),
        ("fields".to_string(), fields.join(",")),
        (lookup_field.clone(), value_query_string(&lookup_value)?),
    ];
    let body = send_request_with_retry(sources, connection, "rda", move || {
        sources
            .client
            .get(url.clone())
            .timeout(sources.request_timeout)
            .bearer_auth(&connection.bearer_token)
            .header("accept", "application/json")
            .header("data-purpose", purpose)
            .query(&query_pairs)
    })
    .await?;
    let rows = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or(EvidenceError::SourceUnavailable)?;
    match rows.len() {
        0 => Err(EvidenceError::SourceNotFound),
        1 => rows
            .first()
            .cloned()
            .ok_or(EvidenceError::SourceUnavailable),
        _ => Err(EvidenceError::SourceAmbiguous),
    }
}

async fn read_external_dci_http_one(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
    purpose: &str,
) -> Result<Value, EvidenceError> {
    let lookup_value = lookup_value(binding, subject)?;
    let url = source_url(&connection.base_url, &connection.dci.search_path)?;
    let request_body = dci_search_request_body(&connection.dci, binding, &lookup_value)?;
    let body = send_request_with_retry(sources, connection, "dci", move || {
        sources
            .client
            .post(url.clone())
            .timeout(sources.request_timeout)
            .bearer_auth(&connection.bearer_token)
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .header("data-purpose", purpose)
            .json(&request_body)
    })
    .await?;
    let rows = get_json_path(&body, &connection.dci.records_path)
        .and_then(Value::as_array)
        .ok_or(EvidenceError::SourceUnavailable)?;
    match rows.len() {
        0 => Err(EvidenceError::SourceNotFound),
        1 => project_dci_record(connection, binding, &lookup_value, &rows[0]),
        _ => Err(EvidenceError::SourceAmbiguous),
    }
}

/// RDA bulk specialization: one collection GET with an `.in` filter carrying
/// all subjects' lookup values, then split rows back to subjects by lookup
/// field equality.
///
/// If the response exceeds N rows we fall back to per-subject `read_one` for
/// the whole batch (a `bulk_collision_fallback` tracing event flags the
/// misconfiguration). This preserves correctness when an operator has
/// attested uniqueness but the upstream data violates it.
async fn read_remote_registry_data_api_many(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    bindings: &[(SourceBindingConfig, SubjectRequest)],
    purpose: &str,
) -> Vec<Result<Value, EvidenceError>> {
    let first_binding = &bindings[0].0;
    let lookup_field = first_binding.lookup.field.clone();
    let fields = projected_source_fields_with_lookup(first_binding, &lookup_field);
    let url = match registry_data_api_url(&connection.base_url, first_binding) {
        Ok(url) => url,
        Err(_) => {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect()
        }
    };
    // Compute per-subject lookup values up front. If any subject's lookup
    // cannot be derived (e.g. unsupported op), surface that error for that
    // position and exclude it from the bulk request.
    let mut lookup_values: Vec<Result<String, EvidenceError>> = Vec::with_capacity(bindings.len());
    for (binding, subject) in bindings {
        let lv = lookup_value(binding, subject)
            .and_then(|v| value_query_string(&v).map_err(|_| EvidenceError::InvalidRequest));
        lookup_values.push(lv);
    }
    // Build the in-filter CSV from the successfully-derived lookup values.
    let in_values: Vec<String> = lookup_values
        .iter()
        .filter_map(|r| r.as_ref().ok().cloned())
        .collect();
    if in_values.is_empty() {
        // Every position carries an Err already; preserve it. We can't run
        // a bulk request against an empty `.in` set.
        return lookup_values
            .into_iter()
            .map(|r| match r {
                Err(invalid) => Err(invalid),
                Ok(_) => Err(EvidenceError::InvalidRequest),
            })
            .collect();
    }
    let n = in_values.len();
    // Relay parses `<field>.in=v1,v2,...` (see registry-relay/src/api/entity.rs
    // parse_filter_name). We replicate that wire format rather than the
    // value-prefix variant.
    let filter_name = format!("{}.in", lookup_field);
    let query_pairs = vec![
        ("limit".to_string(), (n + 1).to_string()),
        ("fields".to_string(), fields.join(",")),
        (filter_name, in_values.join(",")),
    ];
    let timeout_budget = bulk_timeout(connection, n);
    let body_result = send_request_with_retry(sources, connection, "rda_bulk", move || {
        sources
            .client
            .get(url.clone())
            .timeout(timeout_budget)
            .bearer_auth(&connection.bearer_token)
            .header("accept", "application/json")
            .header("data-purpose", purpose)
            .query(&query_pairs)
    })
    .await;
    let body = match body_result {
        Ok(body) => body,
        Err(e) => {
            // Bulk call failed: log the underlying error once and surface
            // SourceUnavailable for every subject with a valid lookup;
            // preserve per-subject InvalidRequest for lookups that could
            // not be derived. We can't fan the same EvidenceError value
            // out (it isn't Clone), but the bulk failure mode is always
            // wire-level for connection scope, so SourceUnavailable is
            // the right discriminant for each affected position.
            tracing::warn!(
                target: "registry_witness_server::bulk",
                connection_id = %connection.id,
                error = %e,
                "rda_bulk_request_failed",
            );
            return lookup_values
                .into_iter()
                .map(|r| match r {
                    Err(invalid) => Err(invalid),
                    Ok(_) => Err(EvidenceError::SourceUnavailable),
                })
                .collect();
        }
    };
    let rows: Vec<Value> = body
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // Collision fallback: more rows than subjects means the upstream data
    // violates the operator's uniqueness attestation. Switch to per-subject
    // reads so each subject can still surface its own ambiguity error.
    if rows.len() > n {
        tracing::warn!(
            target: "registry_witness_server::bulk",
            connection_id = %connection.id,
            batch_size = n,
            row_count = rows.len(),
            "bulk_collision_fallback",
        );
        return fallback_concurrent_read_one(sources, bindings, purpose).await;
    }
    // Bucket rows by lookup field equality against each subject's lookup
    // value. The `data[i][lookup_field]` is compared against the string
    // form of the subject's lookup value.
    let mut results: Vec<Result<Value, EvidenceError>> = Vec::with_capacity(bindings.len());
    for lv_result in lookup_values {
        match lv_result {
            Err(e) => results.push(Err(e)),
            Ok(lv) => {
                let mut matching: Vec<&Value> = rows
                    .iter()
                    .filter(|row| {
                        row.get(&lookup_field)
                            .map(|val| value_query_string(val).ok().as_deref() == Some(lv.as_str()))
                            .unwrap_or(false)
                    })
                    .collect();
                let outcome = match matching.len() {
                    0 => Err(EvidenceError::SourceNotFound),
                    1 => Ok(matching.remove(0).clone()),
                    _ => Err(EvidenceError::SourceAmbiguous),
                };
                results.push(outcome);
            }
        }
    }
    results
}

/// DCI bulk specialization: one POST with N `search_request` entries, each
/// carrying a unique `reference_id`. Responses are matched back to subjects
/// by `reference_id`; per-entry projection runs through
/// `dci.bulk_records_path` (defaults to `/data/reg_records` inside one
/// `search_response[i]` entry).
async fn read_external_dci_http_many(
    sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    bindings: &[(SourceBindingConfig, SubjectRequest)],
    purpose: &str,
) -> Vec<Result<Value, EvidenceError>> {
    let url = match source_url(&connection.base_url, &connection.dci.search_path) {
        Ok(url) => url,
        Err(_) => {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect()
        }
    };
    // Resolve per-subject lookup values; subjects with bad lookups produce
    // an Err in the corresponding position and are excluded from the wire
    // request.
    let mut lookup_values: Vec<Result<Value, EvidenceError>> = Vec::with_capacity(bindings.len());
    for (binding, subject) in bindings {
        lookup_values.push(lookup_value(binding, subject));
    }
    // Build (reference_id, search_criteria) entries for each valid subject.
    let mut entry_ids: Vec<Option<String>> = Vec::with_capacity(bindings.len());
    let mut search_request: Vec<Value> = Vec::new();
    let n_valid = lookup_values.iter().filter(|r| r.is_ok()).count();
    let timestamp = match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(ts) => ts,
        Err(_) => {
            return bindings
                .iter()
                .map(|_| Err(EvidenceError::SourceUnavailable))
                .collect()
        }
    };
    for (idx, lv_result) in lookup_values.iter().enumerate() {
        match lv_result {
            Err(_) => entry_ids.push(None),
            Ok(lv) => {
                let binding = &bindings[idx].0;
                let reference_id = Ulid::new().to_string();
                let criteria = match dci_search_criteria(&connection.dci, binding, lv, n_valid) {
                    Ok(c) => c,
                    Err(_) => {
                        entry_ids.push(None);
                        continue;
                    }
                };
                search_request.push(json!({
                    "reference_id": reference_id,
                    "timestamp": timestamp,
                    "search_criteria": criteria,
                }));
                entry_ids.push(Some(reference_id));
            }
        }
    }
    if search_request.is_empty() {
        return lookup_values
            .into_iter()
            .map(|r| match r {
                Err(e) => Err(e),
                Ok(_) => Err(EvidenceError::SourceUnavailable),
            })
            .collect();
    }
    let message_id = Ulid::new().to_string();
    let request_body = json!({
        "header": {
            "message_id": message_id,
            "message_ts": timestamp,
            "action": "search",
            "sender_id": connection.dci.sender_id,
            "total_count": search_request.len(),
            "is_msg_encrypted": false,
        },
        "message": {
            "transaction_id": message_id,
            "search_request": search_request,
        },
    });
    let timeout_budget = bulk_timeout(connection, n_valid);
    let body_result = send_request_with_retry(sources, connection, "dci_bulk", move || {
        sources
            .client
            .post(url.clone())
            .timeout(timeout_budget)
            .bearer_auth(&connection.bearer_token)
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .header("data-purpose", purpose)
            .json(&request_body)
    })
    .await;
    let body = match body_result {
        Ok(body) => body,
        Err(e) => {
            tracing::warn!(
                target: "registry_witness_server::bulk",
                connection_id = %connection.id,
                error = %e,
                "dci_bulk_request_failed",
            );
            return lookup_values
                .into_iter()
                .map(|r| match r {
                    Err(invalid) => Err(invalid),
                    Ok(_) => Err(EvidenceError::SourceUnavailable),
                })
                .collect();
        }
    };
    // Walk message.search_response[] and index by reference_id.
    let response_entries = body
        .pointer("/message/search_response")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut by_ref: BTreeMap<String, &Value> = BTreeMap::new();
    for entry in &response_entries {
        if let Some(rid) = entry.get("reference_id").and_then(Value::as_str) {
            by_ref.insert(rid.to_string(), entry);
        }
    }
    let mut results: Vec<Result<Value, EvidenceError>> = Vec::with_capacity(bindings.len());
    for (idx, lv_result) in lookup_values.into_iter().enumerate() {
        match (lv_result, entry_ids.get(idx).cloned().flatten()) {
            (Err(e), _) => results.push(Err(e)),
            (Ok(_), None) => results.push(Err(EvidenceError::SourceUnavailable)),
            (Ok(lookup_value_for_subject), Some(reference_id)) => {
                let binding = &bindings[idx].0;
                let entry = match by_ref.get(reference_id.as_str()) {
                    Some(e) => *e,
                    None => {
                        results.push(Err(EvidenceError::SourceNotFound));
                        continue;
                    }
                };
                let rows = get_json_path(entry, &connection.dci.bulk_records_path)
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let outcome = match rows.len() {
                    0 => Err(EvidenceError::SourceNotFound),
                    1 => {
                        project_dci_record(connection, binding, &lookup_value_for_subject, &rows[0])
                    }
                    _ => Err(EvidenceError::SourceAmbiguous),
                };
                results.push(outcome);
            }
        }
    }
    results
}

/// Shared helper for building one DCI `search_criteria` object. Extracted
/// from `dci_search_request_body` so the batched path can produce N entries
/// without duplicating the query-shape logic. `page_size` is set to
/// `max(dci.max_results, batch_size)` so the upstream does not truncate
/// N-subject responses.
fn dci_search_criteria(
    dci: &DciSourceConnectionConfig,
    binding: &SourceBindingConfig,
    lookup_value: &Value,
    batch_size: usize,
) -> Result<Value, EvidenceError> {
    let query = match dci.query_type.as_str() {
        "idtype-value" => json!({
            "type": binding.lookup.field,
            "value": lookup_value,
        }),
        "expression" => json!({
            binding.lookup.field.clone(): {
                binding.lookup.op.clone(): lookup_value,
            },
        }),
        "predicate" => json!([{
            "expression1": {
                "attribute_name": binding.lookup.field,
                "operator": binding.lookup.op,
                "attribute_value": lookup_value,
            },
        }]),
        _ => return Err(EvidenceError::InvalidRequest),
    };
    let mut search_criteria = Map::from_iter([
        (
            "query_type".to_string(),
            Value::String(dci.query_type.clone()),
        ),
        ("query".to_string(), query),
        (
            "pagination".to_string(),
            json!({ "page_size": dci.max_results.max(batch_size) }),
        ),
    ]);
    if let Some(registry_type) = &dci.registry_type {
        search_criteria.insert("reg_type".to_string(), Value::String(registry_type.clone()));
    }
    if let Some(record_type) = &dci.record_type {
        search_criteria.insert(
            "reg_record_type".to_string(),
            Value::String(record_type.clone()),
        );
    }
    Ok(Value::Object(search_criteria))
}

/// Send an outbound HTTP request to a `source_connection`, holding the
/// connection's process-global semaphore permit for the full duration of the
/// call including any retries. Single retry on transport error or HTTP 5xx,
/// with 50-150ms jittered backoff. Reads the response body into a JSON value
/// on success; treats >=400 responses as `SourceUnavailable`.
async fn send_request_with_retry(
    _sources: &HttpEvidenceSources,
    connection: &ResolvedEvidenceSourceConnection,
    connector: &'static str,
    build_request: impl Fn() -> reqwest::RequestBuilder,
) -> Result<Value, EvidenceError> {
    let permit = connection
        .semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    let available = connection.semaphore.available_permits();
    let in_flight = connection.max_in_flight.saturating_sub(available);
    tracing::info!(
        target: "registry_witness_server::outbound",
        connection_id = %connection.id,
        connector = connector,
        in_flight = in_flight,
        max_in_flight = connection.max_in_flight,
        "outbound permit acquired",
    );
    let start = Instant::now();
    let mut attempt: u32 = 0;
    let max_attempts: u32 = 2; // 1 initial + 1 retry
    let result = loop {
        attempt += 1;
        let outcome = build_request().send().await;
        let retryable = match &outcome {
            Err(_) => true,
            Ok(response) => response.status().is_server_error(),
        };
        if attempt < max_attempts && retryable {
            tracing::info!(
                target: "registry_witness_server::outbound",
                connection_id = %connection.id,
                connector = connector,
                attempt = attempt,
                "retry_attempted",
            );
            tokio::time::sleep(retry_backoff()).await;
            continue;
        }
        match outcome {
            Err(_) => break Err(EvidenceError::SourceUnavailable),
            Ok(response) => {
                if !response.status().is_success() {
                    break Err(EvidenceError::SourceUnavailable);
                }
                break read_source_json(response).await;
            }
        }
    };
    let latency_ms = start.elapsed().as_millis() as u64;
    let status = match &result {
        Ok(_) => "ok",
        Err(_) => "err",
    };
    tracing::debug!(
        target: "registry_witness_server::outbound",
        connection_id = %connection.id,
        connector = connector,
        latency_ms = latency_ms,
        attempts = attempt,
        outcome = status,
        "outbound completed",
    );
    drop(permit);
    let available_after = connection.semaphore.available_permits();
    let in_flight_after = connection.max_in_flight.saturating_sub(available_after);
    tracing::info!(
        target: "registry_witness_server::outbound",
        connection_id = %connection.id,
        connector = connector,
        in_flight = in_flight_after,
        max_in_flight = connection.max_in_flight,
        "outbound permit released",
    );
    result
}

/// Backoff duration for the single permitted retry. Uniform jitter in
/// [50ms, 150ms) to spread retries across concurrent failures.
fn retry_backoff() -> Duration {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // Hash to a value in [0, 100ms) then offset by 50ms.
    let jitter_ms = (nanos as u64) % 100;
    Duration::from_millis(50 + jitter_ms)
}

async fn read_source_json(response: reqwest::Response) -> Result<Value, EvidenceError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_SOURCE_JSON_BYTES as u64)
    {
        return Err(EvidenceError::SourceUnavailable);
    }
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?
    {
        let new_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or(EvidenceError::SourceUnavailable)?;
        if new_len > MAX_SOURCE_JSON_BYTES {
            return Err(EvidenceError::SourceUnavailable);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| EvidenceError::SourceUnavailable)
}

fn registry_data_api_url(
    base_url: &str,
    binding: &SourceBindingConfig,
) -> Result<reqwest::Url, EvidenceError> {
    let mut url = reqwest::Url::parse(base_url).map_err(|_| EvidenceError::SourceUnavailable)?;
    url.path_segments_mut()
        .map_err(|_| EvidenceError::SourceUnavailable)?
        .extend([
            "datasets",
            binding.dataset.as_str(),
            binding.entity.as_str(),
        ]);
    Ok(url)
}

fn source_url(base_url: &str, path: &str) -> Result<String, EvidenceError> {
    if reqwest::Url::parse(path).is_ok() {
        return Err(EvidenceError::SourceUnavailable);
    }
    Ok(format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    ))
}

fn dci_search_request_body(
    dci: &DciSourceConnectionConfig,
    binding: &SourceBindingConfig,
    lookup_value: &Value,
) -> Result<Value, EvidenceError> {
    let message_id = Ulid::new().to_string();
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    let query = match dci.query_type.as_str() {
        "idtype-value" => json!({
            "type": binding.lookup.field,
            "value": lookup_value,
        }),
        "expression" => json!({
            binding.lookup.field.clone(): {
                binding.lookup.op.clone(): lookup_value,
            },
        }),
        "predicate" => json!([{
            "expression1": {
                "attribute_name": binding.lookup.field,
                "operator": binding.lookup.op,
                "attribute_value": lookup_value,
            },
        }]),
        _ => return Err(EvidenceError::InvalidRequest),
    };
    let mut search_criteria = Map::from_iter([
        (
            "query_type".to_string(),
            Value::String(dci.query_type.clone()),
        ),
        ("query".to_string(), query),
        (
            "pagination".to_string(),
            json!({ "page_size": dci.max_results.max(2) }),
        ),
    ]);
    if let Some(registry_type) = &dci.registry_type {
        search_criteria.insert("reg_type".to_string(), Value::String(registry_type.clone()));
    }
    if let Some(record_type) = &dci.record_type {
        search_criteria.insert(
            "reg_record_type".to_string(),
            Value::String(record_type.clone()),
        );
    }
    Ok(json!({
        "header": {
            "message_id": message_id,
            "message_ts": timestamp,
            "action": "search",
            "sender_id": dci.sender_id,
            "total_count": 1,
            "is_msg_encrypted": false,
        },
        "message": {
            "transaction_id": message_id,
            "search_request": [{
                "reference_id": message_id,
                "timestamp": timestamp,
                "search_criteria": Value::Object(search_criteria),
            }],
        },
    }))
}

fn project_dci_record(
    connection: &ResolvedEvidenceSourceConnection,
    binding: &SourceBindingConfig,
    lookup_value: &Value,
    record: &Value,
) -> Result<Value, EvidenceError> {
    let mut row = Map::new();
    insert_row_path(&mut row, &binding.lookup.field, lookup_value.clone());
    for (alias, field) in &binding.fields {
        let path = connection
            .dci
            .field_paths
            .get(&field.field)
            .or_else(|| connection.dci.field_paths.get(alias))
            .map(String::as_str)
            .unwrap_or(field.field.as_str());
        let value = get_json_path(record, path).cloned().unwrap_or(Value::Null);
        insert_row_path(&mut row, &field.field, value);
    }
    Ok(Value::Object(row))
}

pub(crate) fn get_json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path.starts_with('/') {
        return value.pointer(path);
    }
    let mut current = value;
    for part in path.split('.') {
        if part.is_empty() {
            return None;
        }
        current = match current {
            Value::Array(values) => values.get(part.parse::<usize>().ok()?)?,
            _ => current.get(part)?,
        };
    }
    Some(current)
}

fn insert_row_path(row: &mut Map<String, Value>, path: &str, value: Value) {
    let mut parts = path.split('.').filter(|part| !part.is_empty()).peekable();
    let Some(first) = parts.next() else {
        return;
    };
    if parts.peek().is_none() {
        row.insert(first.to_string(), value);
        return;
    }
    let mut current = row
        .entry(first.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            if let Value::Object(object) = current {
                object.insert(part.to_string(), value);
            }
            return;
        }
        if !current.is_object() {
            *current = Value::Object(Map::new());
        }
        current = current
            .as_object_mut()
            .expect("object was just initialized")
            .entry(part.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
}

fn value_query_string(value: &Value) -> Result<String, EvidenceError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(EvidenceError::InvalidRequest),
    }
}

fn lookup_value(
    binding: &SourceBindingConfig,
    subject: &SubjectRequest,
) -> Result<Value, EvidenceError> {
    if binding.lookup.op != "eq" {
        return Err(EvidenceError::InvalidRequest);
    }
    match binding.lookup.input.as_str() {
        "subject_id" | "subject.id" => Ok(Value::String(subject.id.clone())),
        _ => Err(EvidenceError::InvalidRequest),
    }
}

fn collect_claim_required_scopes(
    evidence: &EvidenceConfig,
    claim_id: &str,
    scopes: &mut Vec<String>,
) -> Result<(), EvidenceError> {
    let claim = crate::find_claim(evidence, claim_id)?;
    for binding in claim.source_bindings.values() {
        if let Some(scope) = binding.required_scope.as_deref() {
            scopes.push(scope.to_string());
        } else {
            scopes.push(format!("{}:evidence_verification", binding.dataset));
        }
    }
    for dep in &claim.depends_on {
        collect_claim_required_scopes(evidence, dep, scopes)?;
    }
    Ok(())
}

fn projected_source_fields_with_lookup(
    binding: &SourceBindingConfig,
    lookup_field: &str,
) -> Vec<String> {
    let mut fields = vec![lookup_field.to_string()];
    for field in binding.fields.values() {
        fields.push(field.field.clone());
    }
    fields.sort();
    fields.dedup();
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::response::Redirect;
    use axum::routing::get;
    use axum_test::TestServer;
    use registry_witness_core::{SourceConnectionConfig, SourceLookupConfig};
    use std::io::{Error, ErrorKind};

    #[derive(Clone)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("shared buffer lock")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(Error::new(ErrorKind::BrokenPipe, "audit sink unavailable"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn audit_event() -> EvidenceAuditEvent {
        EvidenceAuditEvent {
            event_id: "01HX0000000000000000000000".to_string(),
            occurred_at: "2026-05-22T00:00:00Z".to_string(),
            principal_id: Some("caseworker".to_string()),
            decision: "allowed".to_string(),
            method: "GET".to_string(),
            path: "/claims".to_string(),
            status: 200,
            verification_id: None,
            claim_hash: None,
            row_count: None,
            error_code: None,
        }
    }

    fn auth_state(audit: AuditSink) -> Arc<AuthAuditState> {
        Arc::new(AuthAuditState {
            api_keys: vec![ResolvedCredential {
                id: "caseworker".to_string(),
                token: "api-token".to_string(),
                scopes: Vec::new(),
            }],
            bearer_tokens: Vec::new(),
            audit,
        })
    }

    fn test_binding(dataset: &str, entity: &str) -> SourceBindingConfig {
        SourceBindingConfig {
            connector: SourceConnectorKind::RegistryDataApi,
            connection: Some("registry".to_string()),
            required_scope: None,
            dataset: dataset.to_string(),
            entity: entity.to_string(),
            lookup: SourceLookupConfig {
                input: "subject_id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            fields: BTreeMap::new(),
        }
    }

    #[test]
    fn stdout_audit_sink_emits_raw_jsonl() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let sink = AuditSink::Stdout(Mutex::new(Box::new(SharedBuffer(Arc::clone(&buffer)))));

        sink.emit(&audit_event()).expect("audit write succeeds");

        let output = String::from_utf8(buffer.lock().expect("buffer lock").clone())
            .expect("audit output is UTF-8");
        assert!(output.ends_with('\n'));
        assert_eq!(output.lines().count(), 1);

        let line: Value = serde_json::from_str(output.trim_end()).expect("audit line is JSON");
        assert_eq!(line["event_id"], json!("01HX0000000000000000000000"));
        assert_eq!(line["principal_id"], json!("caseworker"));
        assert!(line.get("fields").is_none());
        assert!(line.get("audit").is_none());
    }

    #[test]
    fn audit_sink_emit_surfaces_stdout_write_errors() {
        let sink = AuditSink::Stdout(Mutex::new(Box::new(FailingWriter)));

        let error = sink
            .emit(&audit_event())
            .expect_err("stdout write error is returned");

        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    }

    #[test]
    fn audit_sink_emit_surfaces_file_write_errors() {
        let sink = AuditSink::File(Mutex::new(Box::new(FailingWriter)));

        let error = sink
            .emit(&audit_event())
            .expect_err("file write error is returned");

        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn audit_write_failure_replaces_authorized_response_with_request_error() {
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(
                auth_state(AuditSink::File(Mutex::new(Box::new(FailingWriter)))),
                auth_audit_middleware,
            ));
        let server = TestServer::builder().http_transport().build(app);

        let response = server.get("/ok").add_header("x-api-key", "api-token").await;

        response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        let body: Value = response.json();
        assert_eq!(body["code"], json!("audit.write_failed"));
    }

    #[test]
    fn bearer_auth_token_accepts_case_insensitive_scheme_and_whitespace() {
        assert_eq!(bearer_auth_token("bEaReR api-token"), Some("api-token"));
        assert_eq!(bearer_auth_token("Bearer\tapi-token"), Some("api-token"));
        assert_eq!(bearer_auth_token("Bearer"), None);
        assert_eq!(bearer_auth_token("Bearer api-token extra"), None);
    }

    #[test]
    fn auth_state_accepts_case_insensitive_bearer_scheme() {
        let state = AuthAuditState {
            api_keys: Vec::new(),
            bearer_tokens: vec![ResolvedCredential {
                id: "caseworker".to_string(),
                token: "api-token".to_string(),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
            }],
            audit: AuditSink::Stdout(Mutex::new(Box::new(SharedBuffer(Arc::new(Mutex::new(
                Vec::new(),
            )))))),
        };
        let request = Request::builder()
            .uri("/claims")
            .header(header::AUTHORIZATION, "BEARER api-token")
            .body(Body::empty())
            .expect("request builds");

        let principal = state.authenticate(&request).expect("bearer auth succeeds");

        assert_eq!(principal.principal_id, "caseworker");
    }

    #[test]
    fn resolved_token_debug_output_is_redacted() {
        let credential = ResolvedCredential {
            id: "caseworker".to_string(),
            token: "api-token".to_string(),
            scopes: vec!["farmer_registry:evidence_verification".to_string()],
        };
        let connection = ResolvedEvidenceSourceConnection {
            id: "registry".to_string(),
            base_url: "https://registry.example.test".to_string(),
            bearer_token: "source-token".to_string(),
            dci: DciSourceConnectionConfig::default(),
            semaphore: Arc::new(Semaphore::new(8)),
            max_in_flight: 8,
            bulk_mode: BulkMode::None,
            bulk_timeout_max: Duration::from_secs(30),
        };

        let debug = format!("{credential:?} {connection:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("api-token"));
        assert!(!debug.contains("source-token"));
    }

    #[test]
    fn registry_data_api_url_percent_encodes_dataset_and_entity_segments() {
        let binding = test_binding("farmer/registry", "farmer?active");

        let url = registry_data_api_url("https://registry.example.test/api", &binding)
            .expect("url builds");

        assert_eq!(
            url.as_str(),
            "https://registry.example.test/api/datasets/farmer%2Fregistry/farmer%3Factive"
        );
    }

    #[test]
    fn dci_source_url_rejects_absolute_search_paths() {
        assert!(source_url(
            "https://registry.example.test",
            "https://attacker.example.test/dci/search"
        )
        .is_err());
        assert!(source_url("https://registry.example.test", "file:///tmp/search").is_err());
        assert_eq!(
            source_url("https://registry.example.test/base", "/dci/search")
                .expect("relative path is accepted"),
            "https://registry.example.test/base/dci/search"
        );
    }

    #[tokio::test]
    async fn source_json_reader_rejects_oversized_body() {
        let app = Router::new().route(
            "/too-large",
            get(|| async { "x".repeat(MAX_SOURCE_JSON_BYTES + 1) }),
        );
        let server = TestServer::builder().http_transport().build(app);
        let url = format!(
            "{}too-large",
            server
                .server_address()
                .expect("HTTP transport exposes upstream address")
        );
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client builds")
            .get(url)
            .send()
            .await
            .expect("request succeeds");

        let error = read_source_json(response)
            .await
            .expect_err("oversized body is rejected");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[tokio::test]
    async fn http_sources_do_not_follow_upstream_redirects() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_REDIRECT_TOKEN", "source-token");
        let app = Router::new()
            .route(
                "/datasets/farmer_registry/farmer",
                get(|| async { Redirect::temporary("/redirect-target") }),
            )
            .route(
                "/redirect-target",
                get(|| async {
                    Json(json!({
                        "data": [{
                            "id": "person-1",
                            "total_farmed_area": 3.5
                        }]
                    }))
                }),
            );
        let server = TestServer::builder().http_transport().build(app);
        let config = EvidenceConfig {
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                SourceConnectionConfig {
                    base_url: server
                        .server_address()
                        .expect("HTTP transport exposes upstream address")
                        .to_string(),
                    token_env: "TEST_EVIDENCE_SOURCE_REDIRECT_TOKEN".to_string(),
                    dci: DciSourceConnectionConfig::default(),
                    max_in_flight: 8,
                    bulk_mode: registry_witness_core::BulkMode::None,
                    bulk_mode_lookup_unique: false,
                    bulk_timeout_max_ms: 30_000,
                },
            )]),
            ..EvidenceConfig::default()
        };
        let sources = HttpEvidenceSources::from_config(&config).expect("source config resolves");
        let mut binding = test_binding("farmer_registry", "farmer");
        binding.fields.insert(
            "total_farmed_area".to_string(),
            registry_witness_core::SourceFieldConfig {
                field: "total_farmed_area".to_string(),
                field_type: Some("number".to_string()),
                unit: None,
                required: true,
                semantic_term: None,
            },
        );
        let subject = SubjectRequest {
            id: "person-1".to_string(),
            id_type: None,
        };

        let error = sources
            .read_one(
                &binding,
                &subject,
                "https://purpose.example.test/eligibility",
            )
            .await
            .expect_err("redirect response is not followed");

        assert!(matches!(error, EvidenceError::SourceUnavailable));
    }

    #[test]
    fn http_sources_from_config_sets_finite_request_timeout() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_TIMEOUT_TOKEN", "source-token");
        let config = EvidenceConfig {
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                registry_witness_core::SourceConnectionConfig {
                    base_url: "https://registry.example.test".to_string(),
                    token_env: "TEST_EVIDENCE_SOURCE_TIMEOUT_TOKEN".to_string(),
                    dci: DciSourceConnectionConfig::default(),
                    max_in_flight: 8,
                    bulk_mode: registry_witness_core::BulkMode::None,
                    bulk_mode_lookup_unique: false,
                    bulk_timeout_max_ms: 30_000,
                },
            )]),
            ..EvidenceConfig::default()
        };

        let sources = HttpEvidenceSources::from_config(&config).expect("source config resolves");

        assert_eq!(sources.request_timeout, SOURCE_REQUEST_TIMEOUT);
        assert!(sources.request_timeout > Duration::ZERO);
    }
}
