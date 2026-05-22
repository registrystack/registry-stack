// SPDX-License-Identifier: Apache-2.0
//! Standalone Evidence Server assembly, auth, audit, and HTTP source connectors.

use std::collections::BTreeMap;
use std::env;
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use evidence_core::sd_jwt::EvidenceIssuer;
use evidence_core::{
    DciSourceConnectionConfig, EvidenceAuditEvent, EvidenceConfig, EvidenceCredentialConfig,
    EvidenceError, EvidencePrincipal, SourceBindingConfig, SourceConnectorKind,
    StandaloneEvidenceServerConfig, SubjectRequest,
};
use serde_json::{json, Map, Value};
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;

use crate::{
    router, EvidenceApiState, EvidenceAuditContext, EvidenceErrorCodeContext,
    EvidenceIssuerResolver, EvidenceStore, SourceReader,
};

const SOURCE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub fn standalone_router(
    config: StandaloneEvidenceServerConfig,
) -> Result<Router, StandaloneServerError> {
    config.validate()?;
    let evidence = Arc::new(config.evidence.clone());
    let source = Arc::new(HttpEvidenceSources::from_config(&config.evidence)?);
    let store = Arc::new(EvidenceStore::default());
    let issuers = Arc::new(EvidenceIssuerRegistry::from_config(&config.evidence)?);
    let api_state = Arc::new(EvidenceApiState::new(evidence, source, store, issuers));
    let auth_state = Arc::new(AuthAuditState::from_config(&config)?);

    Ok(router()
        .layer(axum::Extension(api_state))
        .layer(from_fn_with_state(auth_state, auth_audit_middleware)))
}

#[derive(Debug, thiserror::Error)]
pub enum StandaloneServerError {
    #[error(transparent)]
    Config(#[from] evidence_core::EvidenceConfigError),
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

#[derive(Debug, Clone)]
struct ResolvedEvidenceSourceConnection {
    base_url: String,
    bearer_token: String,
    dci: DciSourceConnectionConfig,
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
                    base_url: connection.base_url.clone(),
                    bearer_token,
                    dci: connection.dci.clone(),
                },
            );
        }
        let client = reqwest::Client::builder()
            .timeout(SOURCE_REQUEST_TIMEOUT)
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

#[derive(Debug)]
struct ResolvedCredential {
    id: String,
    token: String,
    scopes: Vec<String>,
}

#[derive(Debug)]
struct AuthAuditState {
    api_keys: Vec<ResolvedCredential>,
    bearer_tokens: Vec<ResolvedCredential>,
    audit: AuditSink,
}

impl AuthAuditState {
    fn from_config(config: &StandaloneEvidenceServerConfig) -> Result<Self, StandaloneServerError> {
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
            .and_then(|raw| raw.strip_prefix("Bearer "))
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
        config: &evidence_core::EvidenceAuditConfig,
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
            let response = auth_error_response(error);
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

fn find_credential<'a>(
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

fn auth_error_response(error: EvidenceError) -> Response {
    let code = error.code().to_string();
    let status = StatusCode::UNAUTHORIZED;
    let mut response = (
        status,
        Json(json!({
            "type": "https://data.example.gov/problems/auth/missing_credential",
            "title": "Missing credential",
            "status": status.as_u16(),
            "detail": "missing or invalid Evidence Server credential",
            "code": code,
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/problem+json".parse().unwrap(),
    );
    response
        .extensions_mut()
        .insert(EvidenceErrorCodeContext(error.code().to_string()));
    response
}

fn audit_error_response(error: io::Error) -> Response {
    tracing::error!(target: "evidence_server::audit", error = %error, "audit event write failed");
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
    let base = connection.base_url.trim_end_matches('/');
    let url = format!("{base}/datasets/{}/{}", binding.dataset, binding.entity);
    let response = sources
        .client
        .get(url)
        .timeout(sources.request_timeout)
        .bearer_auth(&connection.bearer_token)
        .header("accept", "application/json")
        .header("data-purpose", purpose)
        .query(&[
            ("limit", "2".to_string()),
            ("fields", fields.join(",")),
            (lookup_field.as_str(), value_query_string(&lookup_value)?),
        ])
        .send()
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    if !response.status().is_success() {
        return Err(EvidenceError::SourceUnavailable);
    }
    let body = response
        .json::<Value>()
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
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
    let url = source_url(&connection.base_url, &connection.dci.search_path);
    let request_body = dci_search_request_body(&connection.dci, binding, &lookup_value)?;
    let response = sources
        .client
        .post(url)
        .timeout(sources.request_timeout)
        .bearer_auth(&connection.bearer_token)
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .header("data-purpose", purpose)
        .json(&request_body)
        .send()
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    if !response.status().is_success() {
        return Err(EvidenceError::SourceUnavailable);
    }
    let body = response
        .json::<Value>()
        .await
        .map_err(|_| EvidenceError::SourceUnavailable)?;
    let rows = get_json_path(&body, &connection.dci.records_path)
        .and_then(Value::as_array)
        .ok_or(EvidenceError::SourceUnavailable)?;
    match rows.len() {
        0 => Err(EvidenceError::SourceNotFound),
        1 => project_dci_record(connection, binding, &lookup_value, &rows[0]),
        _ => Err(EvidenceError::SourceAmbiguous),
    }
}

fn source_url(base_url: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
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

fn get_json_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
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
    use axum::routing::get;
    use axum_test::TestServer;
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
    fn http_sources_from_config_sets_finite_request_timeout() {
        std::env::set_var("TEST_EVIDENCE_SOURCE_TIMEOUT_TOKEN", "source-token");
        let config = EvidenceConfig {
            source_connections: BTreeMap::from([(
                "registry".to_string(),
                evidence_core::SourceConnectionConfig {
                    base_url: "https://registry.example.test".to_string(),
                    token_env: "TEST_EVIDENCE_SOURCE_TIMEOUT_TOKEN".to_string(),
                    dci: DciSourceConnectionConfig::default(),
                },
            )]),
            ..EvidenceConfig::default()
        };

        let sources = HttpEvidenceSources::from_config(&config).expect("source config resolves");

        assert_eq!(sources.request_timeout, SOURCE_REQUEST_TIMEOUT);
        assert!(sources.request_timeout > Duration::ZERO);
    }
}
