use axum::{
    body::{to_bytes, Body},
    extract::{Path, Query, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use crosswalk_core::{MappingRuntime, RuntimeOptions, StandaloneExpressionInput};
use hyper::service::service_fn;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as HyperBuilder,
};
use registry_notary_source_adapter_rhai::{
    Lookup, RhaiLimits, RhaiPolicy, ScriptCtx, ScriptEngine, ScriptSourceHost, SourceResponse,
    SourceScriptError,
};
use registry_platform_audit::{AuditProfile, ChainState, JsonlFileSink};
use registry_platform_authcommon::{parse_bearer_token, parse_fingerprint, verify_api_key};
use registry_platform_httputil::is_cloud_metadata_ip;
use registry_platform_ops::{AntiRollbackKey, AntiRollbackProposal, FileAntiRollbackStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::Infallible,
    fmt,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{watch, Mutex, OnceCell, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tower::ServiceExt;
use tower_http::timeout::{RequestBodyTimeoutLayer, TimeoutLayer};
use tracing::{info, warn};

#[path = "audit_metrics.rs"]
mod audit_metrics;
#[path = "config.rs"]
mod config;
#[path = "error.rs"]
mod error;
#[path = "governed.rs"]
mod governed;
#[path = "handlers.rs"]
mod handlers;
#[path = "normalization.rs"]
mod normalization;
#[path = "server.rs"]
mod server;
#[path = "state.rs"]
mod state;
#[path = "validation.rs"]
mod validation;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

use audit_metrics::*;
use config::*;
use governed::*;
use handlers::*;
use normalization::*;
use server::*;
use state::*;
use validation::*;

pub use config::SidecarConfig;
pub use error::SidecarError;
pub use governed::{
    load_startup_config, load_startup_config_with_options, render_governed_runtime_target_json,
    verify_governed_bundle_report_json,
};
pub use server::{run, sidecar_router};

fn resolve_auth_tokens(config: &SidecarConfig) -> Result<Vec<ResolvedBearerToken>, SidecarError> {
    let mut tokens = Vec::with_capacity(config.auth.bearer_tokens.len());
    for token in &config.auth.bearer_tokens {
        let Some(hash_env) = &token.hash_env else {
            return Err(SidecarError::Config(format!(
                "bearer token {} must set hash_env",
                token.id
            )));
        };
        let fingerprint =
            std::env::var(hash_env).map_err(|_| SidecarError::MissingTokenHashEnv {
                token_id: token.id.clone(),
                env: hash_env.clone(),
            })?;
        parse_fingerprint(&fingerprint).map_err(|_| SidecarError::InvalidTokenHashEnv {
            token_id: token.id.clone(),
            env: hash_env.clone(),
        })?;
        tokens.push(ResolvedBearerToken { fingerprint });
    }
    Ok(tokens)
}

fn resolve_fhir_bearer_tokens(
    config: &SidecarConfig,
) -> Result<BTreeMap<String, String>, SidecarError> {
    let mut tokens = BTreeMap::new();
    for (source_id, source) in &config.sources {
        if source.engine != SourceEngine::Fhir {
            continue;
        }
        let Some(env) = source
            .fhir
            .as_ref()
            .and_then(|fhir| fhir.bearer_token_env.as_ref())
        else {
            continue;
        };
        if tokens.contains_key(env) {
            continue;
        }
        let token = std::env::var(env).ok().filter(|token| !token.is_empty());
        let Some(token) = token else {
            return Err(SidecarError::Config(format!(
                "source {source_id} fhir.bearer_token_env {env} is missing or empty"
            )));
        };
        tokens.insert(env.clone(), token);
    }
    Ok(tokens)
}

async fn execute_source_json(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    match source.engine {
        SourceEngine::HttpJson => execute_http_json(state, source_id, source, request).await,
        SourceEngine::HttpFlow => execute_http_flow(state, source_id, source, request).await,
        SourceEngine::Fhir => execute_fhir(state, source_id, source, request).await,
        SourceEngine::ScriptRhai => execute_rhai(state, source_id, source, request).await,
    }
}

/// The async host backing a `script_rhai` run's `source.*` capabilities. It owns
/// everything the call needs by value (clones / `Arc`s), so it is `Send + Sync`
/// and outlives the bridged blocking execution. Every effect — target
/// resolution, allow-listing, SSRF policy, auth, rate limiting, bounded JSON
/// body handling — is reused from the `http_json` machinery; the script never
/// sees any of it.
struct RhaiHttpHost {
    state: AppState,
    source: SourceConfig,
    source_id: String,
    /// The resolved per-source credential object (secret fields are read by
    /// `apply_http_json_auth`). `Value::Null` when the source has no credential.
    credential: Value,
}

enum RhaiSourceRequest {
    Get,
    PostJson(Value),
}

#[async_trait::async_trait]
impl ScriptSourceHost for RhaiHttpHost {
    async fn source_get(
        &self,
        target: &str,
        path: &str,
        query: Value,
    ) -> Result<SourceResponse, SourceScriptError> {
        self.source_request(target, path, query, RhaiSourceRequest::Get)
            .await
    }

    async fn source_post_json(
        &self,
        target: &str,
        path: &str,
        query: Value,
        body: Value,
    ) -> Result<SourceResponse, SourceScriptError> {
        self.source_request(target, path, query, RhaiSourceRequest::PostJson(body))
            .await
    }
}

impl RhaiHttpHost {
    async fn source_request(
        &self,
        target: &str,
        path: &str,
        query: Value,
        request: RhaiSourceRequest,
    ) -> Result<SourceResponse, SourceScriptError> {
        let rhai = self
            .source
            .rhai
            .as_ref()
            .ok_or(SourceScriptError::HostDenied {
                reason: "missing rhai config".into(),
            })?;
        let target_config = rhai
            .targets
            .get(target)
            .ok_or(SourceScriptError::HostDenied {
                reason: "unknown target".into(),
            })?;

        // Reuse the http_json request preparation: it parses the base URL,
        // enforces `allowed_base_urls`, joins the (already canonicalized) path,
        // checks same-origin, and applies the SSRF/localhost client policy.
        let prepared = prepare_http_json_request(
            &self.state,
            &self.source_id,
            &self.source,
            &target_config.base_url,
            path,
        )
        .await
        .map_err(map_source_execution_error)?;

        let mut builder = match request {
            RhaiSourceRequest::Get => prepared.client.get(prepared.url),
            RhaiSourceRequest::PostJson(body) => {
                ensure_rhai_post_json_body_size(&body, self.state.config.limits.max_request_bytes)?;
                prepared.client.post(prepared.url).json(&body)
            }
        };
        if let Value::Object(params) = &query {
            for (name, value) in params {
                // Match the http_json contract: reject a query-parameter name
                // carrying control characters or whitespace rather than relying
                // solely on the client's URL encoder. A name can derive from
                // untrusted upstream data, so the call fails closed.
                if !is_valid_http_param_name(name) {
                    return Err(SourceScriptError::HostDenied {
                        reason: "invalid query parameter name".into(),
                    });
                }
                if let Some(rendered) = rhai_query_param_value(value) {
                    builder = builder.query(&[(name.as_str(), rendered)]);
                }
            }
        }
        // Static, operator-configured request headers (validated at startup as
        // non-restricted). Applied before auth so they can never shadow it.
        for (name, value) in &target_config.headers {
            builder = builder.header(name, value);
        }
        builder = apply_http_json_auth(
            &self.state,
            &self.source_id,
            &self.source,
            builder,
            target_config.auth.as_ref(),
            &self.credential,
        )
        .await
        .map_err(map_source_execution_error)?;

        // Honour the same rate-limit/backoff gate as http_json. A limiter
        // rejection is reported to the script as a 429 so `problem_code()`
        // surfaces `source.target_rate_limit`.
        if acquire_http_json_rate_or_error(&self.state, &self.source_id)
            .await
            .is_some()
        {
            return Err(SourceScriptError::HttpStatus { status: 429 });
        }

        let response = builder.send().await.map_err(|error| {
            if error.is_timeout() {
                SourceScriptError::Deadline
            } else {
                SourceScriptError::HttpTransport
            }
        })?;
        let status = response.status();
        let status_code = status.as_u16();

        // Per-target visibility gate: a 2xx, or a status this target explicitly
        // allows, is returned to the script; any other non-2xx terminates the
        // run as an upstream-status error (the engine's union `visible_statuses`
        // is only the ceiling — the host decides per target).
        if status.is_success() || target_config.visible_statuses.contains(&status_code) {
            let body = if status.is_success() {
                read_limited_json_or_empty_response(
                    response,
                    self.state.config.limits.max_output_bytes,
                )
                .await
                .map_err(map_source_execution_error)?
            } else {
                read_limited_optional_json_response(
                    response,
                    self.state.config.limits.max_output_bytes,
                )
                .await
                .map_err(map_source_execution_error)?
            };
            Ok(SourceResponse {
                status: status_code,
                body,
            })
        } else {
            Err(SourceScriptError::HttpStatus {
                status: status_code,
            })
        }
    }
}

fn ensure_rhai_post_json_body_size(
    body: &Value,
    max_bytes: usize,
) -> Result<(), SourceScriptError> {
    let bytes = serde_json::to_vec(body).map_err(|_| SourceScriptError::HostDenied {
        reason: "request body is not serializable".into(),
    })?;
    if bytes.len() > max_bytes {
        return Err(SourceScriptError::HostDenied {
            reason: "request body exceeds configured byte limit".into(),
        });
    }
    Ok(())
}

/// Map the http_json outbound machinery's coarse error into the script host's
/// taxonomy. A transport timeout becomes a deadline; everything else collapses
/// to a transport failure (both ultimately surface as `source.unavailable`
/// except the timeout, which surfaces as `source.timeout`).
fn map_source_execution_error(error: SourceExecutionError) -> SourceScriptError {
    match error {
        SourceExecutionError::HttpJsonTimeout => SourceScriptError::Deadline,
        SourceExecutionError::HttpJson | SourceExecutionError::HttpJsonBadRequest => {
            SourceScriptError::HttpTransport
        }
    }
}

/// Stringify a scalar query-parameter value the way http_json does; non-scalar
/// values (objects, arrays, null) are dropped, matching query-string semantics.
fn rhai_query_param_value(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

async fn execute_rhai(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    if request.get("mode").and_then(Value::as_str) == Some("batch_match") {
        let item_count = request
            .get("items")
            .and_then(Value::as_array)
            .map_or(1, |items| items.len().max(1));
        let value = tokio::time::timeout(
            http_json_batch_timeout(&state.config.limits, item_count),
            execute_rhai_batch(state, source_id, source, &request),
        )
        .await
        .map_err(|_| SourceExecutionError::HttpJsonTimeout)??;
        return Ok(SourceExecution {
            value,
            worker_id: "script_rhai".to_string(),
        });
    }

    execute_rhai_lookup(state, source_id, source, request).await
}

async fn execute_rhai_lookup(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    // Presence is also enforced at validation/compile time; guard here so a
    // misconfigured source fails closed rather than reaching the host.
    let _rhai = source.rhai.as_ref().ok_or(SourceExecutionError::HttpJson)?;
    let lookup = request
        .get("lookup")
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let lookup_field = lookup
        .get("field")
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let lookup_value = lookup
        .get("value")
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let fields = request_fields(&request)?;
    let limit = request.get("limit").and_then(Value::as_u64).unwrap_or(2);
    let purpose = request
        .get("purpose")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let dataset = request
        .get("dataset")
        .and_then(Value::as_str)
        .unwrap_or(&source.dataset)
        .to_string();
    let entity = request
        .get("entity")
        .and_then(Value::as_str)
        .unwrap_or(&source.entity)
        .to_string();

    let credential = state
        .credentials
        .get(source_id)
        .cloned()
        .unwrap_or(Value::Null);
    // The script only ever sees the whitelisted public credential fields, never
    // a raw secret (mirrors the http_json `public_credential` projection).
    let credential_public = public_credential(source, &credential);

    let ctx = ScriptCtx::new(
        source_id,
        dataset,
        entity,
        Lookup {
            field: lookup_field.to_string(),
            value: lookup_value.to_string(),
        },
        purpose,
    )
    .fields(fields)
    .limit(limit)
    .credential_public(credential_public);

    let engine = state
        .rhai_engines
        .get(source_id)
        .cloned()
        .ok_or(SourceExecutionError::HttpJson)?;

    let host = RhaiHttpHost {
        state: state.clone(),
        source: source.clone(),
        source_id: source_id.to_string(),
        credential,
    };

    match engine.execute(Arc::new(host), ctx).await {
        Ok(records) => Ok(SourceExecution {
            value: json!({ "data": records }),
            worker_id: "script_rhai".to_string(),
        }),
        // Mirror http_json: a classified script error is returned as the
        // sidecar's `{ "error": { "code": ... } }` envelope (never the script
        // source, a response body, or a secret), and the public problem code is
        // the engine's stable mapping.
        Err(error) => Ok(SourceExecution {
            value: json!({ "error": { "code": error.problem_code() } }),
            worker_id: "script_rhai".to_string(),
        }),
    }
}

async fn execute_rhai_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    match source.batch.mode {
        SourceBatchMode::SequentialLookup => {
            execute_rhai_sequential_batch(state, source_id, source, request).await
        }
        SourceBatchMode::ParallelLookup => {
            execute_rhai_parallel_batch(state, source_id, source, request).await
        }
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch => {
            Err(SourceExecutionError::HttpJsonBadRequest)
        }
    }
}

async fn execute_rhai_sequential_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let mut responses = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let lookup_request = http_json_item_lookup_request(source_id, request, lookup_field, item)?;
        let execution = execute_rhai_lookup(state, source_id, source, lookup_request).await?;
        if let Some(error) = execution.value.get("error") {
            if shared_credential_error(error) {
                return Ok(json!({ "error": error }));
            }
            responses.push(json!({ "id": id, "error": error }));
        } else if let Some(data) = execution.value.get("data") {
            responses.push(json!({ "id": id, "data": data }));
        } else {
            return Err(SourceExecutionError::HttpJson);
        }
    }
    Ok(json!({ "items": responses }))
}

async fn execute_rhai_parallel_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let max_parallel = source
        .batch
        .max_parallel
        .unwrap_or(1)
        .min(items.len().max(1));
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let state = Arc::new(state.clone());
    let source = Arc::new(source.clone());
    let source_id = source_id.to_string();
    let mut tasks = JoinSet::new();
    let mut requested_ids = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?
            .to_string();
        requested_ids.push(id.clone());
        let lookup_request =
            http_json_item_lookup_request(&source_id, request, lookup_field, item)?;
        let permit = semaphore.clone();
        let task_state = Arc::clone(&state);
        let task_source = Arc::clone(&source);
        let task_source_id = source_id.clone();
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| SourceExecutionError::HttpJson)?;
            let execution = execute_rhai_lookup(
                &task_state,
                &task_source_id,
                task_source.as_ref(),
                lookup_request,
            )
            .await?;
            Ok::<_, SourceExecutionError>((idx, id, execution.value))
        });
    }

    let mut responses = vec![Value::Null; items.len()];
    while let Some(joined) = tasks.join_next().await {
        let (idx, id, value) = joined.map_err(|_| SourceExecutionError::HttpJson)??;
        if let Some(error) = value.get("error") {
            if shared_credential_error(error) {
                tasks.abort_all();
                return Ok(json!({ "error": error }));
            }
            responses[idx] = json!({ "id": id, "error": error });
        } else if let Some(data) = value.get("data") {
            responses[idx] = json!({ "id": id, "data": data });
        } else {
            tasks.abort_all();
            return Err(SourceExecutionError::HttpJson);
        }
    }

    for (idx, response) in responses.iter_mut().enumerate() {
        if response.is_null() {
            *response = json!({
                "id": requested_ids[idx],
                "error": { "code": "source.unavailable" }
            });
        }
    }
    Ok(json!({ "items": responses }))
}

async fn execute_fhir(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    if request.get("mode").and_then(Value::as_str) == Some("batch_match") {
        let item_count = request
            .get("items")
            .and_then(Value::as_array)
            .map_or(1, |items| items.len().max(1));
        let value = tokio::time::timeout(
            http_json_batch_timeout(&state.config.limits, item_count),
            execute_fhir_batch_match(state, source_id, source, &request),
        )
        .await
        .map_err(|_| SourceExecutionError::HttpJsonTimeout)??;
        return Ok(SourceExecution {
            value,
            worker_id: "fhir".to_string(),
        });
    }

    let lookup = request
        .get("lookup")
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let lookup_field = lookup
        .get("field")
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let lookup_value = lookup
        .get("value")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let fields = request_fields(&request)?;
    let limit = request
        .get("limit")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(2);
    let purpose = request.get("purpose").and_then(Value::as_str).unwrap_or("");
    let query_values = request_query_values(&request)?;
    let data = execute_fhir_lookup(
        state,
        source_id,
        source,
        lookup_field,
        lookup_value,
        &query_values,
        &fields,
        limit,
        purpose,
    )
    .await?;
    Ok(SourceExecution {
        value: json!({ "data": data }),
        worker_id: "fhir".to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn execute_fhir_lookup(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    lookup_field: &str,
    lookup_value: Value,
    query_values: &BTreeMap<String, String>,
    fields: &[String],
    limit: usize,
    purpose: &str,
) -> Result<Vec<Value>, SourceExecutionError> {
    let fhir = source.fhir.as_ref().ok_or(SourceExecutionError::HttpJson)?;
    let mut nodes = BTreeMap::<String, Vec<Value>>::new();
    let anchor = search_fhir_node(
        state,
        source_id,
        source,
        fhir,
        &fhir.anchor,
        lookup_field,
        &lookup_value,
        query_values,
        &nodes,
        purpose,
    )
    .await?;
    match anchor.len() {
        0 => return Ok(Vec::new()),
        1 => {
            nodes.insert(fhir.anchor.id.clone(), anchor);
        }
        _ => {
            nodes.insert(fhir.anchor.id.clone(), anchor);
            return Ok(project_fhir_records(fhir, &nodes, fields, limit));
        }
    }

    for relation in &fhir.relations {
        let node = FhirNodeConfig {
            id: relation.id.clone(),
            resource_type: relation.resource_type.clone(),
            cardinality: relation.cardinality.clone(),
            search: relation.search.clone(),
        };
        let resources = search_fhir_node(
            state,
            source_id,
            source,
            fhir,
            &node,
            lookup_field,
            &lookup_value,
            query_values,
            &nodes,
            purpose,
        )
        .await?;
        if resources.is_empty() {
            if matches!(relation.cardinality.as_str(), "zero_or_one" | "any") {
                nodes.insert(relation.id.clone(), resources);
                continue;
            }
            return Ok(Vec::new());
        }
        if matches!(relation.cardinality.as_str(), "one" | "zero_or_one") && resources.len() > 1 {
            nodes.insert(relation.id.clone(), resources);
            return Ok(project_fhir_records(fhir, &nodes, fields, limit));
        }
        nodes.insert(relation.id.clone(), resources);
    }

    Ok(project_fhir_records(fhir, &nodes, fields, limit))
}

#[allow(clippy::too_many_arguments)]
async fn search_fhir_node(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    fhir: &FhirSourceConfig,
    node: &FhirNodeConfig,
    lookup_field: &str,
    lookup_value: &Value,
    query_values: &BTreeMap<String, String>,
    nodes: &BTreeMap<String, Vec<Value>>,
    purpose: &str,
) -> Result<Vec<Value>, SourceExecutionError> {
    let prepared = prepare_http_json_request(
        state,
        source_id,
        source,
        &fhir.base_url,
        &node.resource_type,
    )
    .await?;
    let mut url = prepared.url;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("_count", &(fhir.max_search_results + 1).to_string());
        for search in &node.search {
            let value = fhir_search_value(search, lookup_field, lookup_value, query_values, nodes)?;
            query.append_pair(&search.param, &value);
        }
    }
    let mut request = prepared
        .client
        .get(url)
        .header("accept", fhir.accept.as_str());
    if fhir.forward_data_purpose {
        request = request.header("data-purpose", purpose);
    }
    if let Some(env) = &fhir.bearer_token_env {
        let token = state
            .fhir_bearer_tokens
            .get(env)
            .ok_or(SourceExecutionError::HttpJson)?;
        request = request.bearer_auth(token);
    }
    if !fhir.prefer_handling.is_empty() {
        request = request.header("prefer", format!("handling={}", fhir.prefer_handling));
    }
    if acquire_http_json_rate_or_error(state, source_id)
        .await
        .is_some()
    {
        return Err(SourceExecutionError::HttpJsonTimeout);
    }
    let response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(SourceExecutionError::HttpJson);
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(state.config.limits.retry_after_seconds);
        remember_source_backoff_seconds(state, source_id, retry_after_seconds).await;
        return Err(SourceExecutionError::HttpJsonTimeout);
    }
    if !status.is_success() {
        return Err(SourceExecutionError::HttpJson);
    }
    let max_bytes = fhir
        .max_source_bundle_bytes
        .min(state.config.limits.max_output_bytes);
    let body = read_limited_json_response(response, max_bytes).await?;
    fhir_bundle_match_resources(&body, &node.resource_type, fhir.max_search_results + 1)
}

fn fhir_search_value(
    search: &FhirSearchParamConfig,
    lookup_field: &str,
    lookup_value: &Value,
    query_values: &BTreeMap<String, String>,
    nodes: &BTreeMap<String, Vec<Value>>,
) -> Result<String, SourceExecutionError> {
    let raw = if let Some(value) = &search.value {
        value.clone()
    } else if search.value_from_lookup.unwrap_or(false) {
        let _ = lookup_field;
        value_to_query_string(lookup_value)?
    } else if let Some(field) = &search.value_from_query {
        query_values
            .get(field)
            .cloned()
            .ok_or(SourceExecutionError::HttpJsonBadRequest)?
    } else if let Some(value_from_node) = &search.value_from_node {
        fhir_value_from_node(value_from_node, nodes)?
    } else {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    };
    match search.search_type.as_str() {
        "token" => Ok(search
            .system
            .as_ref()
            .map(|system| format!("{system}|{raw}"))
            .unwrap_or(raw)),
        "reference" | "string" | "date" | "code" => Ok(raw),
        _ => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

fn fhir_value_from_node(
    value_from_node: &str,
    nodes: &BTreeMap<String, Vec<Value>>,
) -> Result<String, SourceExecutionError> {
    let (node_id, selector) = value_from_node
        .split_once('.')
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let resource = nodes
        .get(node_id)
        .and_then(|resources| resources.first())
        .ok_or(SourceExecutionError::HttpJson)?;
    match selector {
        "id" => resource
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or(SourceExecutionError::HttpJson),
        "reference" => {
            let resource_type = resource
                .get("resourceType")
                .and_then(Value::as_str)
                .ok_or(SourceExecutionError::HttpJson)?;
            let id = resource
                .get("id")
                .and_then(Value::as_str)
                .ok_or(SourceExecutionError::HttpJson)?;
            Ok(format!("{resource_type}/{id}"))
        }
        pointer if pointer.starts_with('/') => resource
            .pointer(pointer)
            .ok_or(SourceExecutionError::HttpJson)
            .and_then(value_to_query_string),
        _ => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

fn value_to_query_string(value: &Value) -> Result<String, SourceExecutionError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(_) | Value::Bool(_) => Ok(value.to_string()),
        _ => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

fn fhir_bundle_match_resources(
    body: &Value,
    resource_type: &str,
    limit: usize,
) -> Result<Vec<Value>, SourceExecutionError> {
    if body.get("resourceType").and_then(Value::as_str) != Some("Bundle")
        || body.get("type").and_then(Value::as_str) != Some("searchset")
    {
        return Err(SourceExecutionError::HttpJson);
    }
    let entries = body
        .get("entry")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut resources = Vec::new();
    for entry in entries {
        if entry.pointer("/search/mode").and_then(Value::as_str) != Some("match") {
            continue;
        }
        let Some(resource) = entry.get("resource") else {
            continue;
        };
        if resource.get("resourceType").and_then(Value::as_str) != Some(resource_type) {
            return Err(SourceExecutionError::HttpJson);
        }
        resources.push(resource.clone());
        if resources.len() >= limit {
            break;
        }
    }
    Ok(resources)
}

fn project_fhir_records(
    fhir: &FhirSourceConfig,
    nodes: &BTreeMap<String, Vec<Value>>,
    fields: &[String],
    limit: usize,
) -> Vec<Value> {
    let row_count = nodes
        .values()
        .map(Vec::len)
        .max()
        .unwrap_or_default()
        .min(limit);
    (0..row_count)
        .map(|index| project_fhir_record(fhir, nodes, fields, index))
        .collect()
}

fn project_fhir_record(
    fhir: &FhirSourceConfig,
    nodes: &BTreeMap<String, Vec<Value>>,
    fields: &[String],
    index: usize,
) -> Value {
    let mut record = Map::new();
    for field in fields {
        let Some(projection) = fhir.project.get(field) else {
            continue;
        };
        let Some(resource) = nodes
            .get(&projection.node)
            .and_then(|resources| resources.get(index).or_else(|| resources.first()))
        else {
            continue;
        };
        if let Some(value) = resource.pointer(&projection.pointer) {
            record.insert(field.clone(), value.clone());
        } else if let Some(value) = &projection.default_value {
            record.insert(field.clone(), value.clone());
        }
    }
    Value::Object(record)
}

async fn execute_fhir_batch_match(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    match source.batch.mode {
        SourceBatchMode::SequentialLookup => {
            execute_fhir_sequential_batch_match(state, source_id, source, request).await
        }
        SourceBatchMode::ParallelLookup => {
            execute_fhir_parallel_batch_match(state, source_id, source, request).await
        }
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch => {
            Err(SourceExecutionError::HttpJsonBadRequest)
        }
    }
}

async fn execute_fhir_sequential_batch_match(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let query_signature: Vec<BatchQueryTerm> =
        serde_json::from_value(query_signature).map_err(|_| SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let items: Vec<BatchMatchItem> =
        serde_json::from_value(items).map_err(|_| SourceExecutionError::HttpJson)?;
    let fields = request_fields(request)?;
    let purpose = request.get("purpose").and_then(Value::as_str).unwrap_or("");
    let mut output = Vec::with_capacity(items.len());
    for item in &items {
        let query = fhir_batch_item_query(source, &query_signature, item);
        let Ok((lookup_field, lookup_value, query_values)) = query else {
            output.push(json!({
                "id": item.id,
                "error": { "code": "source_unavailable" }
            }));
            continue;
        };
        let result = execute_fhir_lookup(
            state,
            source_id,
            source,
            &lookup_field,
            Value::String(lookup_value),
            &query_values,
            &fields,
            2,
            purpose,
        )
        .await;
        match result {
            Ok(data) => output.push(json!({ "id": item.id, "data": data })),
            Err(_) => output.push(json!({
                "id": item.id,
                "error": { "code": "source_unavailable" }
            })),
        }
    }
    Ok(json!({ "items": output }))
}

async fn execute_fhir_parallel_batch_match(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let query_signature: Vec<BatchQueryTerm> =
        serde_json::from_value(query_signature).map_err(|_| SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .cloned()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let items: Vec<BatchMatchItem> =
        serde_json::from_value(items).map_err(|_| SourceExecutionError::HttpJson)?;
    let fields = Arc::new(request_fields(request)?);
    let purpose = Arc::new(
        request
            .get("purpose")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    );
    let max_parallel = source
        .batch
        .max_parallel
        .unwrap_or(1)
        .min(items.len().max(1));
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let state = Arc::new(state.clone());
    let source = Arc::new(source.clone());
    let source_id = source_id.to_string();
    let query_signature = Arc::new(query_signature);
    let mut tasks = JoinSet::new();
    let requested_ids = items.iter().map(|item| item.id.clone()).collect::<Vec<_>>();
    for (idx, item) in items.into_iter().enumerate() {
        let permit = semaphore.clone();
        let task_state = Arc::clone(&state);
        let task_source = Arc::clone(&source);
        let task_source_id = source_id.clone();
        let task_query_signature = Arc::clone(&query_signature);
        let task_fields = Arc::clone(&fields);
        let task_purpose = Arc::clone(&purpose);
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| SourceExecutionError::HttpJson)?;
            let id = item.id.clone();
            let response = match fhir_batch_item_query(
                task_source.as_ref(),
                task_query_signature.as_ref(),
                &item,
            ) {
                Ok((lookup_field, lookup_value, query_values)) => {
                    match execute_fhir_lookup(
                        &task_state,
                        &task_source_id,
                        task_source.as_ref(),
                        &lookup_field,
                        Value::String(lookup_value),
                        &query_values,
                        task_fields.as_ref(),
                        2,
                        task_purpose.as_ref(),
                    )
                    .await
                    {
                        Ok(data) => json!({ "id": id, "data": data }),
                        Err(_) => json!({
                            "id": id,
                            "error": { "code": "source_unavailable" }
                        }),
                    }
                }
                Err(_) => json!({
                    "id": id,
                    "error": { "code": "source_unavailable" }
                }),
            };
            Ok::<_, SourceExecutionError>((idx, response))
        });
    }

    let mut output = vec![Value::Null; requested_ids.len()];
    while let Some(joined) = tasks.join_next().await {
        let (idx, response) = joined.map_err(|_| SourceExecutionError::HttpJson)??;
        output[idx] = response;
    }
    for (idx, response) in output.iter_mut().enumerate() {
        if response.is_null() {
            *response = json!({
                "id": requested_ids[idx],
                "error": { "code": "source_unavailable" }
            });
        }
    }
    Ok(json!({ "items": output }))
}

fn fhir_batch_item_query(
    source: &SourceConfig,
    query_signature: &[BatchQueryTerm],
    item: &BatchMatchItem,
) -> Result<(String, String, BTreeMap<String, String>), SourceExecutionError> {
    let mut query_values = BTreeMap::new();
    for (term, value) in query_signature.iter().zip(item.values.iter()) {
        query_values.insert(term.field.clone(), value_to_query_string(value)?);
    }
    primary_lookup_value(source, &query_values).ok_or(SourceExecutionError::HttpJsonBadRequest)
}

fn request_fields(request: &Value) -> Result<Vec<String>, SourceExecutionError> {
    request
        .get("fields")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?
        .iter()
        .map(|field| {
            field
                .as_str()
                .map(str::to_string)
                .ok_or(SourceExecutionError::HttpJsonBadRequest)
        })
        .collect()
}

fn request_query_values(request: &Value) -> Result<BTreeMap<String, String>, SourceExecutionError> {
    request
        .get("query_values")
        .and_then(Value::as_object)
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| {
                    value
                        .as_str()
                        .map(|value| (key.clone(), value.to_string()))
                        .ok_or(SourceExecutionError::HttpJsonBadRequest)
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(BTreeMap::new()))
}

async fn execute_http_json(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    if request.get("mode").and_then(Value::as_str) == Some("batch_match") {
        let item_count = request
            .get("items")
            .and_then(Value::as_array)
            .map_or(1, |items| items.len().max(1));
        let value = tokio::time::timeout(
            http_json_batch_timeout(&state.config.limits, item_count),
            execute_http_json_batch(state, source_id, source, &request),
        )
        .await
        .map_err(|_| SourceExecutionError::HttpJsonTimeout)??;
        return Ok(SourceExecution {
            value,
            worker_id: "http_json".to_string(),
        });
    }
    let data = execute_http_json_lookup(state, source_id, source, &request).await?;
    if data.get("error").is_some() {
        return Ok(SourceExecution {
            value: data,
            worker_id: "http_json".to_string(),
        });
    }
    Ok(SourceExecution {
        value: json!({ "data": data }),
        worker_id: "http_json".to_string(),
    })
}

async fn execute_http_flow(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: Value,
) -> Result<SourceExecution, SourceExecutionError> {
    if request.get("mode").and_then(Value::as_str) == Some("batch_match") {
        let item_count = request
            .get("items")
            .and_then(Value::as_array)
            .map_or(1, |items| items.len().max(1));
        let value = tokio::time::timeout(
            http_json_batch_timeout(&state.config.limits, item_count),
            execute_http_flow_batch(state, source_id, source, &request),
        )
        .await
        .map_err(|_| SourceExecutionError::HttpJsonTimeout)??;
        return Ok(SourceExecution {
            value,
            worker_id: "http_flow".to_string(),
        });
    }
    let data = execute_http_flow_lookup_with_timeout(state, source_id, source, &request).await?;
    if data.get("error").is_some() {
        return Ok(SourceExecution {
            value: data,
            worker_id: "http_flow".to_string(),
        });
    }
    Ok(SourceExecution {
        value: json!({ "data": data }),
        worker_id: "http_flow".to_string(),
    })
}

async fn execute_http_flow_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    match source.batch.mode {
        SourceBatchMode::SequentialLookup => {
            execute_http_flow_sequential_batch(state, source_id, source, request).await
        }
        SourceBatchMode::ParallelLookup => {
            execute_http_flow_parallel_batch(state, source_id, source, request).await
        }
        SourceBatchMode::WorkflowBatch | SourceBatchMode::NativeBatch => {
            Err(SourceExecutionError::HttpJsonBadRequest)
        }
    }
}

async fn execute_http_flow_sequential_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let mut responses = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let lookup_request = http_json_item_lookup_request(source_id, request, lookup_field, item)?;
        let data = execute_http_flow_lookup_with_timeout(state, source_id, source, &lookup_request)
            .await?;
        if let Some(error) = data.get("error") {
            if shared_credential_error(error) {
                return Ok(json!({ "error": error }));
            }
            responses.push(json!({ "id": id, "error": error }));
        } else {
            responses.push(json!({ "id": id, "data": data }));
        }
    }
    Ok(json!({ "items": responses }))
}

async fn execute_http_flow_parallel_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let max_parallel = source
        .batch
        .max_parallel
        .unwrap_or(1)
        .min(items.len().max(1));
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let state = Arc::new(state.clone());
    let source = source.clone();
    let source_id = source_id.to_string();
    let mut tasks = JoinSet::new();
    let mut requested_ids = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?
            .to_string();
        requested_ids.push(id.clone());
        let lookup_request =
            http_json_item_lookup_request(&source_id, request, lookup_field, item)?;
        let permit = semaphore.clone();
        let task_state = Arc::clone(&state);
        let task_source = source.clone();
        let task_source_id = source_id.clone();
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| SourceExecutionError::HttpJson)?;
            let data = execute_http_flow_lookup_with_timeout(
                &task_state,
                &task_source_id,
                &task_source,
                &lookup_request,
            )
            .await?;
            Ok::<_, SourceExecutionError>((idx, id, data))
        });
    }

    let mut responses = vec![Value::Null; items.len()];
    while let Some(joined) = tasks.join_next().await {
        let (idx, id, data) = joined.map_err(|_| SourceExecutionError::HttpJson)??;
        if let Some(error) = data.get("error") {
            if shared_credential_error(error) {
                tasks.abort_all();
                return Ok(json!({ "error": error }));
            }
            responses[idx] = json!({ "id": id, "error": error });
        } else {
            responses[idx] = json!({ "id": id, "data": data });
        }
    }

    for (idx, response) in responses.iter_mut().enumerate() {
        if response.is_null() {
            *response = json!({
                "id": requested_ids[idx],
                "error": { "code": "source.unavailable" }
            });
        }
    }
    Ok(json!({ "items": responses }))
}

async fn execute_http_json_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    match source.batch.mode {
        SourceBatchMode::SequentialLookup => {
            execute_http_json_sequential_batch(state, source_id, source, request).await
        }
        SourceBatchMode::ParallelLookup => {
            execute_http_json_parallel_batch(state, source_id, source, request).await
        }
        SourceBatchMode::NativeBatch => {
            execute_http_json_native_batch(state, source_id, source, request).await
        }
        SourceBatchMode::WorkflowBatch => Err(SourceExecutionError::HttpJsonBadRequest),
    }
}

async fn execute_http_json_sequential_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let mut responses = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let lookup_request = http_json_item_lookup_request(source_id, request, lookup_field, item)?;
        let data = execute_http_json_lookup(state, source_id, source, &lookup_request).await?;
        if let Some(error) = data.get("error") {
            if shared_credential_error(error) {
                return Ok(json!({ "error": error }));
            }
            responses.push(json!({ "id": id, "error": error }));
        } else {
            responses.push(json!({ "id": id, "data": data }));
        }
    }
    Ok(json!({ "items": responses }))
}

async fn execute_http_json_parallel_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let query_signature = request
        .get("query_signature")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    if query_signature.len() != 1 {
        return Err(SourceExecutionError::HttpJsonBadRequest);
    }
    let lookup_field = query_signature
        .first()
        .and_then(|term| term.get("field"))
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;
    let max_parallel = source
        .batch
        .max_parallel
        .unwrap_or(1)
        .min(items.len().max(1));
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let state = Arc::new(state.clone());
    let source = Arc::new(source.clone());
    let source_id = source_id.to_string();
    let mut tasks = JoinSet::new();
    let mut requested_ids = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?
            .to_string();
        requested_ids.push(id.clone());
        let lookup_request =
            http_json_item_lookup_request(&source_id, request, lookup_field, item)?;
        let permit = semaphore.clone();
        let task_state = Arc::clone(&state);
        let task_source = Arc::clone(&source);
        let task_source_id = source_id.clone();
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| SourceExecutionError::HttpJson)?;
            let data = execute_http_json_lookup(
                &task_state,
                &task_source_id,
                task_source.as_ref(),
                &lookup_request,
            )
            .await?;
            Ok::<_, SourceExecutionError>((idx, id, data))
        });
    }

    let mut responses = vec![Value::Null; items.len()];
    while let Some(joined) = tasks.join_next().await {
        let (idx, id, data) = joined.map_err(|_| SourceExecutionError::HttpJson)??;
        if let Some(error) = data.get("error") {
            if shared_credential_error(error) {
                tasks.abort_all();
                return Ok(json!({ "error": error }));
            }
            responses[idx] = json!({ "id": id, "error": error });
        } else {
            responses[idx] = json!({ "id": id, "data": data });
        }
    }

    for (idx, response) in responses.iter_mut().enumerate() {
        if response.is_null() {
            *response = json!({
                "id": requested_ids[idx],
                "error": { "code": "source.unavailable" }
            });
        }
    }
    Ok(json!({ "items": responses }))
}

fn http_json_item_lookup_request(
    source_id: &str,
    batch_request: &Value,
    lookup_field: &str,
    item: &Value,
) -> Result<Value, SourceExecutionError> {
    let lookup_value = item
        .get("values")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .cloned()
        .ok_or(SourceExecutionError::HttpJson)?;
    Ok(json!({
        "source_id": source_id,
        "dataset": batch_request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": batch_request.get("entity").cloned().unwrap_or(Value::Null),
        "lookup": {
            "field": lookup_field,
            "value": lookup_value,
        },
        "fields": batch_request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "limit": 2,
        "purpose": batch_request.get("purpose").cloned().unwrap_or(Value::Null),
        "correlation_id": batch_request.get("correlation_id").cloned().unwrap_or(Value::Null),
    }))
}

async fn execute_http_json_native_batch(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let http_json = source
        .http_json
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let batch = http_json
        .batch
        .as_ref()
        .ok_or(SourceExecutionError::HttpJsonBadRequest)?;
    let credential = state
        .credentials
        .get(source_id)
        .cloned()
        .unwrap_or(Value::Null);
    let public_credential = public_credential(source, &credential);
    let bindings = http_json_bindings(request, &public_credential, None);
    let base_url = eval_http_json_string(&http_json.base_url, bindings.clone())?;
    let prepared =
        prepare_http_json_request(state, source_id, source, &base_url, &batch.path).await?;
    let mut builder = match batch.method {
        HttpJsonMethod::Get => prepared.client.get(prepared.url),
        HttpJsonMethod::Post => prepared
            .client
            .post(prepared.url)
            .json(&http_json_batch_request_body(request)),
    };
    for (name, expr) in &batch.query {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.query(&[(name.as_str(), value)]);
    }
    for (name, expr) in &batch.headers {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.header(name.as_str(), value);
    }
    builder = apply_http_json_auth(
        state,
        source_id,
        source,
        builder,
        http_json.auth.as_ref(),
        &credential,
    )
    .await?;
    if let Some(error) = acquire_http_json_rate_or_error(state, source_id).await {
        return Ok(error);
    }

    let response = builder.send().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(json!({ "error": { "code": "source.target_auth" } }));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(state.config.limits.retry_after_seconds);
        remember_source_backoff_seconds(state, source_id, retry_after_seconds).await;
        return Ok(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": retry_after_seconds
            }
        }));
    }
    if !status.is_success() {
        return Ok(json!({ "error": { "code": "source.unavailable" } }));
    }
    let body = read_limited_json_response(response, state.config.limits.max_output_bytes).await?;
    fan_out_http_json_native_batch(batch, request, &public_credential, body)
}

fn fan_out_http_json_native_batch(
    batch: &HttpJsonBatchConfig,
    request: &Value,
    public_credential: &Value,
    body: Value,
) -> Result<Value, SourceExecutionError> {
    let records = eval_http_json_value(
        &batch.response.records,
        http_json_bindings(request, public_credential, Some(body)),
    )?;
    let records = records.as_array().ok_or(SourceExecutionError::HttpJson)?;
    let items = request
        .get("items")
        .and_then(Value::as_array)
        .ok_or(SourceExecutionError::HttpJson)?;

    let mut request_keys = BTreeSet::new();
    for item in items {
        item.get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let key = eval_http_json_string(
            &batch.response.item_key,
            http_json_batch_item_bindings(request, public_credential, item, None),
        )?;
        request_keys.insert(key);
    }

    let mut grouped = BTreeMap::<String, Vec<Value>>::new();
    for record in records {
        let key = eval_http_json_string(
            &batch.response.record_key,
            http_json_batch_record_bindings(request, public_credential, record),
        )?;
        if request_keys.contains(&key) {
            grouped.entry(key).or_default().push(record.clone());
        }
    }

    let mut response_items = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SourceExecutionError::HttpJson)?;
        let key = eval_http_json_string(
            &batch.response.item_key,
            http_json_batch_item_bindings(request, public_credential, item, None),
        )?;
        response_items.push(json!({
            "id": id,
            "data": grouped.get(&key).cloned().unwrap_or_default()
        }));
    }
    Ok(json!({ "items": response_items }))
}

fn http_json_batch_timeout(limits: &LimitConfig, item_count: usize) -> Duration {
    let computed_ms = limits
        .worker_timeout_ms
        .saturating_mul(item_count.max(1) as u64);
    let timeout_ms = limits
        .batch_timeout_ms
        .map_or(computed_ms, |configured| configured.min(computed_ms));
    Duration::from_millis(timeout_ms.max(1))
}

fn shared_credential_error(error: &Value) -> bool {
    matches!(
        error.get("code").and_then(Value::as_str),
        Some(
            "target_auth" | "target_rate_limit" | "source.target_auth" | "source.target_rate_limit"
        )
    )
}

async fn execute_http_flow_lookup_with_timeout(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let timeout = http_flow_timeout(state, source)?;
    match tokio::time::timeout(
        timeout,
        execute_http_flow_lookup(state, source_id, source, request),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            record_http_flow_metric(state, source_id, None, "flow_timeout", 1).await;
            Err(SourceExecutionError::HttpJsonTimeout)
        }
    }
}

fn http_flow_timeout(
    state: &AppState,
    source: &SourceConfig,
) -> Result<Duration, SourceExecutionError> {
    let flow = source
        .http_flow
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    Ok(Duration::from_millis(
        flow.timeout_ms
            .unwrap_or(state.config.limits.worker_timeout_ms)
            .max(1),
    ))
}

async fn execute_http_flow_lookup(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let flow = source
        .http_flow
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let credential = state
        .credentials
        .get(source_id)
        .cloned()
        .unwrap_or(Value::Null);
    let public_credential = public_credential(source, &credential);
    let cache_key = http_json_cache_key(state, source_id, request)?;
    if let Some(cache_key) = cache_key.as_deref() {
        if let Some(value) = http_json_cache_get(state, source_id, cache_key).await {
            return Ok(value);
        }
    }

    let mut bindings = http_flow_initial_bindings(flow);
    for step in &flow.steps {
        if let Some(when) = &step.when {
            if !eval_http_flow_bool(
                when,
                http_flow_bindings(request, &public_credential, &bindings, None, None),
            )? {
                record_http_flow_metric(state, source_id, Some(&step.id), "step_skipped", 1).await;
                continue;
            }
        }

        let prepared = prepare_http_json_request(
            state,
            source_id,
            source,
            &step.request.base_url,
            &step.request.path,
        )
        .await?;
        let mut builder = match step.request.method {
            HttpJsonMethod::Get => prepared.client.get(prepared.url),
            HttpJsonMethod::Post => return Err(SourceExecutionError::HttpJsonBadRequest),
        };
        let request_bindings =
            http_flow_bindings(request, &public_credential, &bindings, None, None);
        for (name, expr) in &step.request.query {
            let value = eval_http_json_string(expr, request_bindings.clone())?;
            builder = builder.query(&[(name.as_str(), value)]);
        }
        for (name, expr) in &step.request.headers {
            let value = eval_http_json_string(expr, request_bindings.clone())?;
            builder = builder.header(name.as_str(), value);
        }
        builder = apply_http_json_auth(
            state,
            source_id,
            source,
            builder,
            step.request.auth.as_ref(),
            &credential,
        )
        .await?;
        if let Some(error) = acquire_http_json_rate_or_error(state, source_id).await {
            return Ok(error);
        }
        let response = builder.send().await.map_err(|error| {
            if error.is_timeout() {
                SourceExecutionError::HttpJsonTimeout
            } else {
                SourceExecutionError::HttpJson
            }
        })?;
        let status = response.status();
        match http_flow_status_action(state, step, status, response.headers())? {
            HttpFlowStepOutcome::Bind => {
                let response_headers = http_flow_headers_value(response.headers());
                let body =
                    read_limited_json_response(response, state.config.limits.max_output_bytes)
                        .await?;
                let scope = http_flow_bindings(
                    request,
                    &public_credential,
                    &bindings,
                    Some(body),
                    Some((status, response_headers)),
                );
                let mut step_bindings = BTreeMap::new();
                if let Some(response) = &step.response {
                    for (name, expr) in &response.bind {
                        let value = eval_http_json_value(expr, scope.clone())?;
                        step_bindings.insert(name.clone(), value);
                    }
                }
                bindings.extend(step_bindings);
                record_http_flow_metric(state, source_id, Some(&step.id), "step_success", 1).await;
            }
            HttpFlowStepOutcome::Continue => {
                record_http_flow_metric(state, source_id, Some(&step.id), "step_skipped", 1).await;
            }
            HttpFlowStepOutcome::NotFound => {
                record_http_flow_metric(state, source_id, Some(&step.id), "flow_not_found", 1)
                    .await;
                if let Some(cache_key) = cache_key.as_deref() {
                    http_json_cache_put(state, source_id, source, cache_key, &json!([])).await;
                }
                return Ok(json!([]));
            }
            HttpFlowStepOutcome::Error(error) => {
                record_http_flow_metric(
                    state,
                    source_id,
                    Some(&step.id),
                    http_flow_error_metric_outcome(&error),
                    1,
                )
                .await;
                remember_source_backoff(state, source_id, &error).await;
                return Ok(error);
            }
        }
    }

    let records = eval_http_json_value(
        &flow.output.records,
        http_flow_bindings(request, &public_credential, &bindings, None, None),
    )?;
    if !records.is_array() {
        record_http_flow_metric(state, source_id, None, "flow_invalid_output", 1).await;
        return Err(SourceExecutionError::HttpJson);
    }
    if let Some(cache_key) = cache_key.as_deref() {
        http_json_cache_put(state, source_id, source, cache_key, &records).await;
    }
    Ok(records)
}

fn http_flow_error_metric_outcome(error: &Value) -> &'static str {
    match error
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str)
    {
        Some("source.target_auth") => "step_target_auth",
        Some("source.target_rate_limit") => "step_target_rate_limit",
        Some("source.timeout") => "step_source_timeout",
        Some("source.unavailable") => "step_source_unavailable",
        _ => "step_source_error",
    }
}

enum HttpFlowStepOutcome {
    Bind,
    Continue,
    NotFound,
    Error(Value),
}

fn http_flow_status_action(
    state: &AppState,
    step: &HttpFlowStepConfig,
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<HttpFlowStepOutcome, SourceExecutionError> {
    let action = step.on_status.get(&status.as_u16().to_string()).copied();
    match action {
        Some(HttpFlowStatusAction::Continue) => return Ok(HttpFlowStepOutcome::Continue),
        Some(HttpFlowStatusAction::SourceUnavailable) => {
            return Ok(HttpFlowStepOutcome::Error(
                json!({ "error": { "code": "source.unavailable" } }),
            ));
        }
        Some(HttpFlowStatusAction::TargetAuth) => {
            return Ok(HttpFlowStepOutcome::Error(
                json!({ "error": { "code": "source.target_auth" } }),
            ));
        }
        Some(HttpFlowStatusAction::TargetRateLimit) => {
            return Ok(HttpFlowStepOutcome::Error(json!({
                "error": {
                    "code": "source.target_rate_limit",
                    "retry_after_seconds": http_flow_retry_after_seconds(state, headers)
                }
            })));
        }
        Some(HttpFlowStatusAction::Timeout) => {
            return Ok(HttpFlowStepOutcome::Error(
                json!({ "error": { "code": "source.timeout" } }),
            ));
        }
        None => {}
    }

    if status.is_success() {
        return Ok(HttpFlowStepOutcome::Bind);
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(HttpFlowStepOutcome::NotFound);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(HttpFlowStepOutcome::Error(
            json!({ "error": { "code": "source.target_auth" } }),
        ));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Ok(HttpFlowStepOutcome::Error(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": http_flow_retry_after_seconds(state, headers)
            }
        })));
    }
    if status == reqwest::StatusCode::REQUEST_TIMEOUT {
        return Ok(HttpFlowStepOutcome::Error(
            json!({ "error": { "code": "source.timeout" } }),
        ));
    }
    Ok(HttpFlowStepOutcome::Error(
        json!({ "error": { "code": "source.unavailable" } }),
    ))
}

fn http_flow_retry_after_seconds(state: &AppState, headers: &reqwest::header::HeaderMap) -> u64 {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(state.config.limits.retry_after_seconds)
}

async fn execute_http_json_lookup(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    request: &Value,
) -> Result<Value, SourceExecutionError> {
    let http_json = source
        .http_json
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let credential = state
        .credentials
        .get(source_id)
        .cloned()
        .unwrap_or(Value::Null);
    let public_credential = public_credential(source, &credential);
    let cache_key = http_json_cache_key(state, source_id, request)?;
    if let Some(cache_key) = cache_key.as_deref() {
        if let Some(value) = http_json_cache_get(state, source_id, cache_key).await {
            return Ok(value);
        }
        record_metric_with_items(state, source_id, "source_cache_miss", Duration::ZERO, 1).await;
    }
    let bindings = http_json_bindings(request, &public_credential, None);
    let base_url = eval_http_json_string(&http_json.base_url, bindings.clone())?;
    let prepared =
        prepare_http_json_request(state, source_id, source, &base_url, &http_json.path).await?;
    let mut builder = match http_json.method {
        HttpJsonMethod::Get => prepared.client.get(prepared.url),
        HttpJsonMethod::Post => prepared
            .client
            .post(prepared.url)
            .json(&http_json_request_body(request)),
    };
    for (name, expr) in &http_json.query {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.query(&[(name.as_str(), value)]);
    }
    for (name, expr) in &http_json.headers {
        let value = eval_http_json_string(expr, bindings.clone())?;
        builder = builder.header(name.as_str(), value);
    }
    builder = apply_http_json_auth(
        state,
        source_id,
        source,
        builder,
        http_json.auth.as_ref(),
        &credential,
    )
    .await?;
    if let Some(error) = acquire_http_json_rate_or_error(state, source_id).await {
        return Ok(error);
    }
    let response = builder.send().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(json!({ "error": { "code": "source.target_auth" } }));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(state.config.limits.retry_after_seconds);
        remember_source_backoff_seconds(state, source_id, retry_after_seconds).await;
        return Ok(json!({
            "error": {
                "code": "source.target_rate_limit",
                "retry_after_seconds": retry_after_seconds
            }
        }));
    }
    if !status.is_success() {
        return Ok(json!({ "error": { "code": "source.unavailable" } }));
    }
    let body = read_limited_json_response(response, state.config.limits.max_output_bytes).await?;
    let records = eval_http_json_value(
        &http_json.response.records,
        http_json_bindings(request, &public_credential, Some(body)),
    )?;
    if !records.is_array() {
        return Err(SourceExecutionError::HttpJson);
    }
    if let Some(cache_key) = cache_key.as_deref() {
        http_json_cache_put(state, source_id, source, cache_key, &records).await;
    }
    Ok(records)
}

fn credential_secret<'a>(
    credential: &'a Value,
    secret_ref: &HttpJsonSecretRef,
) -> Result<&'a str, SourceExecutionError> {
    credential
        .get(&secret_ref.secret)
        .and_then(Value::as_str)
        .ok_or(SourceExecutionError::HttpJson)
}

fn http_json_request_body(request: &Value) -> Value {
    json!({
        "source_id": request.get("source_id").cloned().unwrap_or(Value::Null),
        "dataset": request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": request.get("entity").cloned().unwrap_or(Value::Null),
        "lookup": request.get("lookup").cloned().unwrap_or(Value::Null),
        "fields": request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "limit": request.get("limit").cloned().unwrap_or(Value::Null),
        "purpose": request.get("purpose").cloned().unwrap_or(Value::Null),
        "correlation_id": request.get("correlation_id").cloned().unwrap_or(Value::Null),
    })
}

fn http_json_batch_request_body(request: &Value) -> Value {
    json!({
        "source_id": request.get("source_id").cloned().unwrap_or(Value::Null),
        "dataset": request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": request.get("entity").cloned().unwrap_or(Value::Null),
        "query_signature": request.get("query_signature").cloned().unwrap_or_else(|| json!([])),
        "items": request.get("items").cloned().unwrap_or_else(|| json!([])),
        "fields": request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "purpose": request.get("purpose").cloned().unwrap_or(Value::Null),
        "correlation_id": request.get("correlation_id").cloned().unwrap_or(Value::Null),
    })
}

async fn apply_http_json_auth(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    mut builder: reqwest::RequestBuilder,
    auth: Option<&HttpJsonAuthConfig>,
    credential: &Value,
) -> Result<reqwest::RequestBuilder, SourceExecutionError> {
    if let Some(auth) = auth {
        match auth.kind {
            HttpJsonAuthKind::Bearer => {
                let token_ref = auth.token.as_ref().ok_or(SourceExecutionError::HttpJson)?;
                let token = credential_secret(credential, token_ref)?;
                builder = builder.bearer_auth(token);
            }
            HttpJsonAuthKind::Basic => {
                let username_ref = auth
                    .username
                    .as_ref()
                    .ok_or(SourceExecutionError::HttpJson)?;
                let password_ref = auth
                    .password
                    .as_ref()
                    .ok_or(SourceExecutionError::HttpJson)?;
                let username = credential_secret(credential, username_ref)?;
                let password = credential_secret(credential, password_ref)?;
                builder = builder.basic_auth(username, Some(password));
            }
            HttpJsonAuthKind::ApiKeyHeader => {
                // Header name and secret-field name are config-validated at
                // startup; the resolved value is the secret, never logged.
                let header = auth
                    .header
                    .as_deref()
                    .ok_or(SourceExecutionError::HttpJson)?;
                let token_ref = auth.token.as_ref().ok_or(SourceExecutionError::HttpJson)?;
                let token = credential_secret(credential, token_ref)?;
                builder = builder.header(header, token);
            }
            HttpJsonAuthKind::ApiKeyQuery => {
                // reqwest percent-encodes and appends the parameter. The cache
                // key is built from request fields (not the URL), and the URL is
                // never logged, so the secret does not leak via either path.
                let param = auth
                    .query_param
                    .as_deref()
                    .ok_or(SourceExecutionError::HttpJson)?;
                let token_ref = auth.token.as_ref().ok_or(SourceExecutionError::HttpJson)?;
                let token = credential_secret(credential, token_ref)?;
                builder = builder.query(&[(param, token)]);
            }
            HttpJsonAuthKind::OAuth2ClientCredentials => {
                let token =
                    oauth2_client_credentials_token(state, source_id, source, auth, credential)
                        .await?;
                builder = builder.bearer_auth(token);
            }
        }
    }
    Ok(builder)
}

async fn oauth2_client_credentials_token(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    auth: &HttpJsonAuthConfig,
    credential: &Value,
) -> Result<String, SourceExecutionError> {
    let cache_key = oauth2_token_cache_key(source_id, auth)?;
    if let Some(token) = cached_oauth2_access_token(state, &cache_key).await {
        return Ok(token);
    }

    let fetch_lock = oauth2_token_fetch_lock(state, &cache_key).await;
    let _fetch_guard = fetch_lock.lock().await;
    if let Some(token) = cached_oauth2_access_token(state, &cache_key).await {
        return Ok(token);
    }

    let token_url = auth
        .token_url
        .as_deref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let token_url = reqwest::Url::parse(token_url).map_err(|_| SourceExecutionError::HttpJson)?;
    ensure_allowed_base_url(source_id, source, &token_url)
        .map_err(|_| SourceExecutionError::HttpJson)?;
    if token_url.fragment().is_some() {
        return Err(SourceExecutionError::HttpJson);
    }
    let client = http_json_client_for(state, source_id, source, &token_url).await?;
    let client_id_ref = auth
        .client_id
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let client_secret_ref = auth
        .client_secret
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let client_id = credential_secret(credential, client_id_ref)?;
    let client_secret = credential_secret(credential, client_secret_ref)?;
    let mut params = BTreeMap::new();
    params.insert("grant_type".to_string(), "client_credentials".to_string());
    params.insert("client_id".to_string(), client_id.to_string());
    params.insert("client_secret".to_string(), client_secret.to_string());
    if let Some(scope) = auth
        .scope
        .as_deref()
        .filter(|scope| !scope.trim().is_empty())
    {
        params.insert("scope".to_string(), scope.to_string());
    }
    if let Some(audience) = auth
        .audience
        .as_deref()
        .filter(|audience| !audience.trim().is_empty())
    {
        params.insert("audience".to_string(), audience.to_string());
    }

    let request = client
        .post(token_url.clone())
        .header(reqwest::header::ACCEPT, "application/json");
    let request = match oauth2_request_format(auth) {
        "json" => request.json(&params),
        "form" => request.form(&params),
        _ => return Err(SourceExecutionError::HttpJson),
    };
    let response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })?;
    if !response.status().is_success() {
        return Err(SourceExecutionError::HttpJson);
    }
    let body = read_limited_json_response(response, state.config.limits.max_output_bytes).await?;
    let access_token = body
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or(SourceExecutionError::HttpJson)?
        .to_string();
    let expires_in = body
        .get("expires_in")
        .and_then(oauth2_expires_in_seconds)
        .unwrap_or(300);
    let refresh_skew = Duration::from_secs(auth.refresh_skew_seconds.unwrap_or(60));
    let ttl = Duration::from_secs(expires_in);
    let refresh_after = Instant::now()
        + ttl
            .checked_sub(refresh_skew)
            .unwrap_or_else(|| Duration::from_secs(0));
    state.oauth2_tokens.lock().await.insert(
        cache_key,
        CachedOAuth2Token {
            access_token: access_token.clone(),
            refresh_after,
        },
    );
    Ok(access_token)
}

async fn cached_oauth2_access_token(state: &AppState, cache_key: &str) -> Option<String> {
    let now = Instant::now();
    state
        .oauth2_tokens
        .lock()
        .await
        .get(cache_key)
        .filter(|token| token.refresh_after > now)
        .map(|token| token.access_token.clone())
}

async fn oauth2_token_fetch_lock(state: &AppState, cache_key: &str) -> Arc<Mutex<()>> {
    let mut locks = state.oauth2_token_locks.lock().await;
    locks
        .entry(cache_key.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn oauth2_expires_in_seconds(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn oauth2_request_format(auth: &HttpJsonAuthConfig) -> &str {
    auth.request_format
        .as_deref()
        .filter(|format| !format.trim().is_empty())
        .unwrap_or("form")
}

fn oauth2_token_cache_key(
    source_id: &str,
    auth: &HttpJsonAuthConfig,
) -> Result<String, SourceExecutionError> {
    let token_url = auth
        .token_url
        .as_deref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let client_id_ref = auth
        .client_id
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let client_secret_ref = auth
        .client_secret
        .as_ref()
        .ok_or(SourceExecutionError::HttpJson)?;
    let key = json!({
        "source_id": source_id,
        "token_url": token_url,
        "client_id_field": client_id_ref.secret.as_str(),
        "client_secret_field": client_secret_ref.secret.as_str(),
        "request_format": oauth2_request_format(auth),
        "scope": auth.scope.as_deref(),
        "audience": auth.audience.as_deref(),
    });
    let bytes = serde_json::to_vec(&key).map_err(|_| SourceExecutionError::HttpJson)?;
    Ok(registry_platform_config::sha256_uri(&bytes))
}

fn http_json_cache_key(
    state: &AppState,
    source_id: &str,
    request: &Value,
) -> Result<Option<String>, SourceExecutionError> {
    let Some(runtime) = state.source_runtime.get(source_id) else {
        return Err(SourceExecutionError::HttpJson);
    };
    let Some(source) = state.config.sources.get(source_id) else {
        return Err(SourceExecutionError::HttpJson);
    };
    if source.cache.is_none() {
        return Ok(None);
    }
    let key = json!({
        "source_config_hash": runtime.source_config_hash,
        "source_id": source_id,
        "dataset": request.get("dataset").cloned().unwrap_or(Value::Null),
        "entity": request.get("entity").cloned().unwrap_or(Value::Null),
        "lookup": request.get("lookup").cloned().unwrap_or(Value::Null),
        "fields": request.get("fields").cloned().unwrap_or_else(|| json!([])),
        "limit": request.get("limit").cloned().unwrap_or(Value::Null),
        "purpose": request.get("purpose").cloned().unwrap_or(Value::Null),
    });
    let bytes = serde_json::to_vec(&key).map_err(|_| SourceExecutionError::HttpJson)?;
    Ok(Some(registry_platform_config::sha256_uri(&bytes)))
}

async fn http_json_cache_get(state: &AppState, source_id: &str, key: &str) -> Option<Value> {
    let runtime = state.source_runtime.get(source_id)?;
    let now = Instant::now();
    let mut cache = runtime.cache.lock().await;
    let entry = cache.get_mut(key)?;
    if entry.expires_at <= now {
        cache.remove(key);
        return None;
    }
    entry.last_accessed = now;
    let value = entry.value.clone();
    drop(cache);
    record_metric_with_items(state, source_id, "source_cache_hit", Duration::ZERO, 1).await;
    Some(value)
}

async fn http_json_cache_put(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    key: &str,
    records: &Value,
) {
    let Some(ttl_ms) = http_json_cache_ttl_ms(source, records) else {
        return;
    };
    let Some(runtime) = state.source_runtime.get(source_id) else {
        return;
    };
    let mut cache = runtime.cache.lock().await;
    let now = Instant::now();
    cache.retain(|_, entry| entry.expires_at > now);
    cache.insert(
        key.to_string(),
        CacheEntry {
            expires_at: now + Duration::from_millis(ttl_ms),
            last_accessed: now,
            value: records.clone(),
        },
    );
    evict_http_json_cache_entries(&mut cache, source.cache.as_ref());
}

fn http_json_cache_ttl_ms(source: &SourceConfig, records: &Value) -> Option<u64> {
    let cache = source.cache.as_ref()?;
    match records.as_array()?.len() {
        0 => cache.not_found_ttl_ms,
        1 => cache.exact_match_ttl_ms,
        _ => None,
    }
}

fn evict_http_json_cache_entries(
    cache: &mut BTreeMap<String, CacheEntry>,
    config: Option<&SourceCacheConfig>,
) {
    let max_entries = config
        .and_then(|cache| cache.max_entries)
        .unwrap_or(DEFAULT_SOURCE_CACHE_MAX_ENTRIES);
    if cache.len() <= max_entries {
        return;
    }
    let mut entries = cache
        .iter()
        .map(|(key, entry)| (key.clone(), entry.last_accessed))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(_, last_accessed)| *last_accessed);
    for (key, _) in entries.into_iter().take(cache.len() - max_entries) {
        cache.remove(&key);
    }
}

async fn read_limited_json_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Value, SourceExecutionError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })? {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(SourceExecutionError::HttpJson);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| SourceExecutionError::HttpJson)
}

async fn read_limited_json_or_empty_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Value, SourceExecutionError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })? {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(SourceExecutionError::HttpJson);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&bytes).map_err(|_| SourceExecutionError::HttpJson)
}

async fn read_limited_optional_json_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Value, SourceExecutionError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            SourceExecutionError::HttpJsonTimeout
        } else {
            SourceExecutionError::HttpJson
        }
    })? {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Ok(Value::Null);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn public_credential(source: &SourceConfig, credential: &Value) -> Value {
    let Some(credential) = credential.as_object() else {
        return Value::Object(Map::new());
    };
    let mut public = Map::new();
    for field in &source.credential_public_fields {
        if let Some(value) = credential.get(field) {
            public.insert(field.clone(), value.clone());
        }
    }
    Value::Object(public)
}

fn http_json_bindings(
    request: &Value,
    public_credential: &Value,
    body: Option<Value>,
) -> StandaloneExpressionInput {
    let mut root_bindings = BTreeMap::new();
    for key in [
        "lookup",
        "fields",
        "limit",
        "purpose",
        "correlation_id",
        "dataset",
        "entity",
        "source_id",
        "items",
        "query_signature",
    ] {
        root_bindings.insert(
            key.to_string(),
            request.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    root_bindings.insert("credential_public".to_string(), public_credential.clone());
    root_bindings.insert("body".to_string(), body.unwrap_or(Value::Null));
    StandaloneExpressionInput::new(root_bindings)
}

fn http_flow_initial_bindings(flow: &HttpFlowSourceConfig) -> BTreeMap<String, Value> {
    let mut bindings = BTreeMap::new();
    for step in &flow.steps {
        if let Some(response) = &step.response {
            for name in response.bind.keys() {
                bindings.insert(name.clone(), Value::Null);
            }
        }
    }
    bindings
}

fn http_flow_bindings(
    request: &Value,
    public_credential: &Value,
    flow_bindings: &BTreeMap<String, Value>,
    body: Option<Value>,
    response_meta: Option<(reqwest::StatusCode, Value)>,
) -> StandaloneExpressionInput {
    let mut bindings = http_json_bindings(request, public_credential, body);
    for (name, value) in flow_bindings {
        bindings.root_bindings.insert(name.clone(), value.clone());
    }
    if let Some((status, headers)) = response_meta {
        bindings
            .root_bindings
            .insert("status".to_string(), json!(status.as_u16()));
        bindings
            .root_bindings
            .insert("headers".to_string(), headers);
    } else {
        bindings
            .root_bindings
            .insert("status".to_string(), Value::Null);
        bindings
            .root_bindings
            .insert("headers".to_string(), Value::Null);
    }
    bindings
}

fn http_flow_headers_value(headers: &reqwest::header::HeaderMap) -> Value {
    let mut object = Map::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            object.insert(name.as_str().to_ascii_lowercase(), json!(value));
        }
    }
    Value::Object(object)
}

fn http_json_batch_item_bindings(
    request: &Value,
    public_credential: &Value,
    item: &Value,
    body: Option<Value>,
) -> StandaloneExpressionInput {
    let mut bindings = http_json_bindings(request, public_credential, body);
    bindings
        .root_bindings
        .insert("item".to_string(), item.clone());
    bindings
}

fn http_json_batch_record_bindings(
    request: &Value,
    public_credential: &Value,
    record: &Value,
) -> StandaloneExpressionInput {
    let mut bindings = http_json_bindings(request, public_credential, None);
    bindings
        .root_bindings
        .insert("record".to_string(), record.clone());
    bindings
}

fn eval_http_json_string(
    expr: &HttpJsonCelExpression,
    bindings: StandaloneExpressionInput,
) -> Result<String, SourceExecutionError> {
    match eval_http_json_value(expr, bindings)? {
        Value::String(value) => Ok(value),
        Value::Number(number) => Ok(number.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(SourceExecutionError::HttpJson),
    }
}

fn eval_http_json_value(
    expr: &HttpJsonCelExpression,
    bindings: StandaloneExpressionInput,
) -> Result<Value, SourceExecutionError> {
    let runtime = MappingRuntime::new(RuntimeOptions::default());
    runtime
        .evaluate_cel_expression_with_input(&expr.cel, bindings)
        .map_err(|_| SourceExecutionError::HttpJson)
}

fn eval_http_flow_bool(
    expr: &HttpJsonCelExpression,
    bindings: StandaloneExpressionInput,
) -> Result<bool, SourceExecutionError> {
    match eval_http_json_value(expr, bindings)? {
        Value::Bool(value) => Ok(value),
        _ => Err(SourceExecutionError::HttpJson),
    }
}

async fn prepare_http_json_request(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    base_url: &str,
    path: &str,
) -> Result<PreparedHttpJsonRequest, SourceExecutionError> {
    let base = reqwest::Url::parse(base_url).map_err(|_| SourceExecutionError::HttpJson)?;
    ensure_allowed_base_url(source_id, source, &base)
        .map_err(|_| SourceExecutionError::HttpJson)?;
    let url = append_http_json_path(&base, path).map_err(|_| SourceExecutionError::HttpJson)?;
    ensure_same_origin(&base, &url).map_err(|_| SourceExecutionError::HttpJson)?;
    let client = http_json_client_for(state, source_id, source, &base).await?;
    Ok(PreparedHttpJsonRequest { url, client })
}

async fn http_json_client_for(
    state: &AppState,
    source_id: &str,
    source: &SourceConfig,
    base: &reqwest::Url,
) -> Result<reqwest::Client, SourceExecutionError> {
    let cache_key = format!("{}|{}", source_id, base.as_str().trim_end_matches('/'));
    if let Some(client) = state
        .http_json_clients
        .lock()
        .await
        .get(&cache_key)
        .cloned()
    {
        return Ok(client);
    }

    let resolved_addrs = ensure_http_json_url_policy(base, source)
        .await
        .map_err(|_| SourceExecutionError::HttpJson)?;
    let host = base
        .host_str()
        .ok_or(SourceExecutionError::HttpJson)?
        .to_string();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(state.config.limits.worker_timeout_ms))
        .resolve_to_addrs(&host, &resolved_addrs)
        .build()
        .map_err(|_| SourceExecutionError::HttpJson)?;
    let mut clients = state.http_json_clients.lock().await;
    let client = clients.entry(cache_key).or_insert(client).clone();
    Ok(client)
}

fn append_http_json_path(base: &reqwest::Url, path: &str) -> Result<reqwest::Url, ()> {
    if path.starts_with("//") {
        return Err(());
    }
    let suffix = path.trim_start_matches('/');
    if suffix
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(());
    }
    let base_path = base.path().trim_end_matches('/');
    let combined_path = if base_path.is_empty() || base_path == "/" {
        format!("/{suffix}")
    } else if suffix.is_empty() {
        base_path.to_string()
    } else {
        format!("{base_path}/{suffix}")
    };
    let mut url = base.clone();
    url.set_path(&combined_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn ensure_allowed_base_url(
    source_id: &str,
    source: &SourceConfig,
    base_url: &reqwest::Url,
) -> Result<(), SidecarError> {
    let normalized = base_url.as_str().trim_end_matches('/');
    if source
        .allowed_base_urls
        .iter()
        .map(|allowed| allowed.trim_end_matches('/'))
        .any(|allowed| allowed == normalized)
    {
        Ok(())
    } else {
        Err(SidecarError::Config(format!(
            "source {source_id} http_json base_url is not in allowed_base_urls"
        )))
    }
}

fn ensure_same_origin(base: &reqwest::Url, url: &reqwest::Url) -> Result<(), ()> {
    if base.scheme() == url.scheme()
        && base.host_str() == url.host_str()
        && base.port_or_known_default() == url.port_or_known_default()
    {
        Ok(())
    } else {
        Err(())
    }
}

async fn ensure_http_json_url_policy(
    url: &reqwest::Url,
    source: &SourceConfig,
) -> Result<Vec<SocketAddr>, ()> {
    let Some(host) = url.host_str() else {
        return Err(());
    };
    let port = url.port_or_known_default().ok_or(())?;
    if url.scheme() != "https" {
        if url.scheme() != "http" {
            return Err(());
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            ensure_ip_allowed(ip, source)?;
            if !ip.is_loopback() && !is_private_or_link_local_ip(ip) {
                return Err(());
            }
            return Ok(vec![SocketAddr::new(ip, port)]);
        } else if is_localhost_host(host) {
            if !source.allow_insecure_localhost {
                return Err(());
            }
        } else if !source.allow_insecure_private_network {
            return Err(());
        } else {
            // Resolve below and allow only private/link-local addresses for
            // plain HTTP service names.
        }
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        ensure_ip_allowed(ip, source)?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if is_localhost_host(host) {
        if source.allow_insecure_localhost || source.allow_insecure_private_network {
            return Ok(vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)]);
        }
        return Err(());
    }
    let mut resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| ())?;
    let mut addrs = Vec::new();
    for address in &mut resolved {
        let ip = canonical_ip(address.ip());
        ensure_ip_allowed(ip, source)?;
        if url.scheme() == "http" && !ip.is_loopback() && !is_private_or_link_local_ip(ip) {
            return Err(());
        }
        addrs.push(address);
    }
    if addrs.is_empty() {
        return Err(());
    }
    Ok(addrs)
}

fn ensure_ip_allowed(ip: IpAddr, source: &SourceConfig) -> Result<(), ()> {
    let ip = canonical_ip(ip);
    if is_cloud_metadata_ip(ip) {
        return Err(());
    }
    if ip.is_loopback() {
        return if source.allow_insecure_localhost || source.allow_insecure_private_network {
            Ok(())
        } else {
            Err(())
        };
    }
    if is_private_or_link_local_ip(ip) {
        return if source.allow_insecure_private_network {
            Ok(())
        } else {
            Err(())
        };
    }
    Ok(())
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(_) => ip,
    }
}

fn is_localhost_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn is_private_or_link_local_ip(ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast()
        }
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local() || ip.is_unspecified(),
    }
}

/// Compile every `script_rhai` source's engine once, keyed by `source_id`.
///
/// The compile uses the union of all targets' `visible_statuses` so the engine
/// surfaces any status some target allows; per-target gating then happens in the
/// host. A compile failure is a configuration error that fails startup. The
/// engine carries no script source in its error `Display`, so the message is
/// safe to surface.
fn compile_rhai_engines(
    config: &SidecarConfig,
) -> Result<BTreeMap<String, Arc<ScriptEngine>>, SidecarError> {
    let mut engines = BTreeMap::new();
    for (source_id, source) in &config.sources {
        if source.engine != SourceEngine::ScriptRhai {
            continue;
        }
        let rhai = source.rhai.as_ref().ok_or_else(|| {
            SidecarError::Config(format!(
                "source {source_id} engine script_rhai requires a rhai config"
            ))
        })?;
        let policy = rhai.limits.to_policy(rhai_union_visible_statuses(rhai));
        let engine =
            ScriptEngine::compile(&rhai.script, &rhai.entrypoint, &policy).map_err(|error| {
                SidecarError::Config(format!(
                    "source {source_id} rhai script failed to compile: {error}"
                ))
            })?;
        engines.insert(source_id.clone(), Arc::new(engine));
    }
    Ok(engines)
}

fn load_credentials(config: &SidecarConfig) -> Result<BTreeMap<String, Value>, SidecarError> {
    let mut credentials = BTreeMap::new();
    for (source_id, source) in &config.sources {
        if source.credential_env.trim().is_empty() {
            continue;
        }
        let raw =
            std::env::var(&source.credential_env).map_err(|_| SidecarError::MissingCredential {
                source_id: source_id.clone(),
                env: source.credential_env.clone(),
            })?;
        let credential =
            serde_json::from_str(&raw).map_err(|error| SidecarError::CredentialJson {
                source_id: source_id.clone(),
                env: source.credential_env.clone(),
                source: error,
            })?;
        // The single-`baseUrl` credential gate is an http_json/http_flow/fhir
        // shape. A `script_rhai` source binds its upstreams per-target via
        // `rhai.targets[*].base_url` (each validated against `allowed_base_urls`
        // up front), so it has no one credential `baseUrl` to pin here.
        if source.engine != SourceEngine::ScriptRhai {
            validate_credential_base_url(source_id, source, &credential)?;
        }
        credentials.insert(source_id.clone(), credential);
    }
    Ok(credentials)
}

fn validate_credential_base_url(
    source_id: &str,
    source: &SourceConfig,
    credential: &Value,
) -> Result<(), SidecarError> {
    if source.allowed_base_urls.is_empty() {
        return Ok(());
    }
    let Some(base_url) = credential.get("baseUrl").and_then(Value::as_str) else {
        return Err(SidecarError::CredentialBaseUrl {
            source_id: source_id.to_string(),
            env: source.credential_env.clone(),
        });
    };
    let normalized = base_url.trim_end_matches('/');
    if source
        .allowed_base_urls
        .iter()
        .map(|allowed| allowed.trim_end_matches('/'))
        .any(|allowed| allowed == normalized)
    {
        Ok(())
    } else {
        Err(SidecarError::CredentialBaseUrl {
            source_id: source_id.to_string(),
            env: source.credential_env.clone(),
        })
    }
}
