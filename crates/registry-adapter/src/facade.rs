// SPDX-License-Identifier: Apache-2.0

//! The served facade: one axum route per served profile operation. A call
//! authenticates the bearer token, resolves the caller to an access profile
//! that admits the operation and record type, runs the binding's route over
//! a fresh exchange, journals before answering, and renders the profile's
//! envelope or problem (`products/adapter/CONCEPT.md` sections 6 to 8).
//!
//! The caller's token never reaches the exchange: the route sees only the
//! record type, the record id, the page cursor and the page size the call
//! named.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, RawQuery};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put, MethodRouter};
use axum::{Extension, Router};
use deadpool_postgres::Pool;
use registry_adapter_core::{
    decode_slot, fixed_facade_problem_response, parse_envelope_template, problem_data_schema,
    resolve_problem, validate_result_schema, AdapterProfile, AdapterProject, AsyncStatusOutcome,
    BindingAsyncCompletion, ErrorClass, HttpMethod, ProfileAsyncCompletion, SlotForm,
    MAX_PROBLEM_DATA_BYTES, SLOT_PROBLEM_DATA, SLOT_PROBLEM_ERRORS, SLOT_RECORD,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Semaphore;

use crate::custody::{
    AsyncWriteContext, ResumeWriteContext, WriteExecutionContext, WriteResolution,
};
use crate::engine::component::http::uri::encode_path_segment;
use crate::engine::component::rest::continuation::{
    filter_digest, ContinuationCodec, CursorBinding, CursorRefusal,
};
use crate::engine::effective_contract::{
    EffectiveContract, RuntimeContractResponse, PIN_HEADER, PIN_PROBLEM_CODE,
    UNAVAILABLE_PROBLEM_CODE, WELL_KNOWN_PATH,
};
use crate::engine::envelope::CompiledEnvelope;
use crate::engine::exchange::MAX_IDEMPOTENCY_KEY_BYTES;
use crate::engine::exchange::{
    Exchange, CONTINUATION_PROPERTY, FILTERS_PROPERTY, NEXT_CONTINUATION_PROPERTY, PAGE_SIZE_HEADER,
};
use crate::engine::load::{Loaded, ServedOperation, ServedPagination};
use crate::engine::read_request::{parse_filter_text, ReadRefusal};
use crate::engine::route::{
    run_async_status_poll, run_served_route_until, AsyncStatusPollKind, RouteContext, RouteFailure,
    EXCHANGE_DEADLINE,
};
use crate::govstack::consultation::{CAPABILITIES_PATH, MOUNT_PATH};
use crate::govstack::correlation::RequestCorrelation;
use crate::idempotent::{
    PostgresIdempotencyStore, RecoveryLease, StatusLookup, StatusLookupRequest, StoredResponse,
    TerminalOutcome, VerifiedCallerIdentity, MAX_STORED_RESPONSE_BYTES,
};
use crate::journal::{self, JournalEvent};
use crate::serve::{Authenticator, Caller, CallerRefusal};

const REQUEST_ID_HEADER: &str = "x-registry-request-id";
const WRITE_REQUEST_DIGEST_DOMAIN: &[u8] = b"registry-adapter:write-request:v2\0";

/// A store-restored response identity. This private extension is the only
/// path that may replace the new physical attempt id at the outer response
/// boundary; caller request headers never create one.
#[derive(Clone)]
struct ReplayedResponseRequestId(String);

/// What every handler shares.
pub struct FacadeState {
    pub loaded: Loaded,
    pub effective_contract: EffectiveContract,
    pub authenticator: Authenticator,
    pub journal: Pool,
    /// Present only when this deployment explicitly configures exact write
    /// response retention and serves at least one write operation.
    pub idempotency: Option<PostgresIdempotencyStore>,
    /// Current artifact digest used to bind every asynchronous status row.
    pub artifact_digest: [u8; 32],
    /// Exact accepted-response and status-link lifetime.
    pub async_retention: Option<Duration>,
    /// One non-blocking status-poll permit pool per asynchronous binding.
    pub async_recovery: HashMap<String, Arc<Semaphore>>,
    /// Seals and opens pagination cursors; present when the runtime
    /// config declares `cursorKeyRef`, which a paginated operation needs.
    pub codec: Option<ContinuationCodec>,
}

/// The served operations of one facade path, by method: the indexes of
/// those that answer it, one per record type.
type PathMethods = Vec<(HttpMethod, Vec<usize>)>;

/// The router for every served operation: one handler per method and
/// path. Operations of one method and path differ only by record type, and
/// the handler dispatches on the record type the call names. A path
/// answered under another method refuses 405 with the methods it takes,
/// and a path no operation serves refuses 404; both answer the profile's
/// problem and journal nothing, since no caller was verified.
pub fn router(state: Arc<FacadeState>) -> Router {
    let mut by_path: Vec<(String, PathMethods)> = Vec::new();
    let mut async_status_paths: Vec<(String, Vec<usize>)> = Vec::new();
    for (index, operation) in state.loaded.served.iter().enumerate() {
        let methods = match by_path
            .iter_mut()
            .find(|(path, _)| *path == operation.method_path)
        {
            Some((_, methods)) => methods,
            None => {
                by_path.push((operation.method_path.clone(), Vec::new()));
                &mut by_path.last_mut().expect("the path was just pushed").1
            }
        };
        match methods
            .iter_mut()
            .find(|(method, _)| *method == operation.method)
        {
            Some((_, indexes)) => indexes.push(index),
            None => methods.push((operation.method, vec![index])),
        }
        if operation.async_completion.is_some() {
            let declared = state
                .loaded
                .profile
                .operations
                .get(operation.operation.as_str())
                .and_then(|profile_operation| profile_operation.async_completion.as_ref())
                .expect("a compiled asynchronous operation retains its profile contract");
            let path = declared.status_path.as_str();
            match async_status_paths
                .iter_mut()
                .find(|(existing, _)| existing == path)
            {
                Some((_, indexes)) => indexes.push(index),
                None => async_status_paths.push((path.to_owned(), vec![index])),
            }
        }
    }
    let mut router = Router::new();
    for (path, methods) in by_path {
        let mut routes: Option<MethodRouter> = None;
        let mut allowed = Vec::new();
        for (method, indexes) in methods {
            let shared = Arc::clone(&state);
            let indexes: Arc<[usize]> = indexes.into();
            let handler = move |correlation: Option<Extension<RequestCorrelation>>,
                                headers: HeaderMap,
                                params: Result<Path<HashMap<String, String>>, PathRejection>,
                                RawQuery(query): RawQuery,
                                body: Body| {
                let shared = Arc::clone(&shared);
                let indexes = Arc::clone(&indexes);
                async move {
                    let correlation = correlation.map(|Extension(value)| value);
                    // A path segment that is not UTF-8 never reaches a
                    // call: it answers the profile's bad-request problem,
                    // not the framework's bare rejection.
                    let Ok(Path(params)) = params else {
                        let request_id = correlation
                            .as_ref()
                            .map_or_else(new_id, |value| value.request_id().to_owned());
                        return facade_problem(
                            shared.loaded.problems(),
                            ErrorClass::FacadeInvalidRequest,
                            StatusCode::BAD_REQUEST,
                            "",
                            &request_id,
                        );
                    };
                    let index = dispatch(&shared.loaded.served, &indexes, &params);
                    handle(shared, index, correlation, headers, params, query, body).await
                }
            };
            allowed.push(match method {
                HttpMethod::Get => "GET",
                HttpMethod::Post => "POST",
                HttpMethod::Put => "PUT",
                HttpMethod::Patch => "PATCH",
            });
            routes = Some(match (routes.take(), method) {
                (None, HttpMethod::Post) => post(handler),
                (None, HttpMethod::Put) => put(handler),
                (None, HttpMethod::Get) => get(handler),
                (Some(existing), HttpMethod::Post) => existing.post(handler),
                (Some(existing), HttpMethod::Put) => existing.put(handler),
                (Some(existing), HttpMethod::Get) => existing.get(handler),
                (None, HttpMethod::Patch) => patch(handler),
                (Some(existing), HttpMethod::Patch) => existing.patch(handler),
            });
        }
        let Some(routes) = routes else { continue };
        let shared = Arc::clone(&state);
        let allow = allowed.join(", ");
        router = router.route(
            &path,
            routes.fallback(move |correlation: Option<Extension<RequestCorrelation>>| {
                let shared = Arc::clone(&shared);
                let allow = allow.clone();
                async move {
                    let request_id = correlation
                        .as_ref()
                        .map_or_else(new_id, |Extension(value)| value.request_id().to_owned());
                    let mut response = facade_problem(
                        shared.loaded.problems(),
                        ErrorClass::FacadeMethodNotAllowed,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "",
                        &request_id,
                    );
                    if let Ok(value) = HeaderValue::from_str(&allow) {
                        response.headers_mut().insert(header::ALLOW, value);
                    }
                    response
                }
            }),
        );
    }
    for (path, indexes) in async_status_paths {
        let shared = Arc::clone(&state);
        let method_fallback = Arc::clone(&state);
        let indexes: Arc<[usize]> = indexes.into();
        router = router.route(
            &path,
            get(
                move |headers: HeaderMap,
                      params: Result<Path<HashMap<String, String>>, PathRejection>,
                      RawQuery(query): RawQuery| {
                    let shared = Arc::clone(&shared);
                    let indexes = Arc::clone(&indexes);
                    async move {
                        let Ok(Path(params)) = params else {
                            return facade_problem(
                                shared.loaded.problems(),
                                ErrorClass::FacadeInvalidRequest,
                                StatusCode::BAD_REQUEST,
                                "",
                                &new_id(),
                            );
                        };
                        handle_async_status(shared, indexes, headers, params, query).await
                    }
                },
            )
            .fallback(move || {
                let shared = Arc::clone(&method_fallback);
                async move {
                    let mut response = facade_problem(
                        shared.loaded.problems(),
                        ErrorClass::FacadeMethodNotAllowed,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "",
                        &new_id(),
                    );
                    response
                        .headers_mut()
                        .insert(header::ALLOW, HeaderValue::from_static("GET"));
                    response
                }
            }),
        );
    }
    if state.loaded.project.consultation.is_some() || state.loaded.project.write.is_some() {
        let capabilities = Arc::clone(&state);
        let capabilities_method_fallback = Arc::clone(&state);
        router = router.route(
            CAPABILITIES_PATH,
            get(
                move |correlation: Option<Extension<RequestCorrelation>>, headers: HeaderMap| {
                    let shared = Arc::clone(&capabilities);
                    let correlation = correlation
                        .map_or_else(RequestCorrelation::server_created, |Extension(value)| value);
                    async move { caller_capabilities(shared, correlation, headers).await }
                },
            )
            .fallback(move |correlation: Option<Extension<RequestCorrelation>>| {
                let shared = Arc::clone(&capabilities_method_fallback);
                async move {
                    let request_id = correlation
                        .as_ref()
                        .map_or_else(new_id, |Extension(value)| value.request_id().to_owned());
                    let mut response = facade_problem(
                        shared.loaded.problems(),
                        ErrorClass::FacadeMethodNotAllowed,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "",
                        &request_id,
                    );
                    response
                        .headers_mut()
                        .insert(header::ALLOW, HeaderValue::from_static("GET"));
                    response
                }
            }),
        );
    }
    if state.loaded.project.consultation.is_some() || state.loaded.project.write.is_some() {
        router = Router::new().nest(
            MOUNT_PATH,
            router.layer(middleware::from_fn(crate::govstack::correlation::boundary)),
        );
    }
    let contract = Arc::clone(&state);
    let contract_method_fallback = Arc::clone(&state);
    router = router.route(
        WELL_KNOWN_PATH,
        get(move |headers: HeaderMap| {
            let shared = Arc::clone(&contract);
            async move { runtime_contract(shared, headers).await }
        })
        .fallback(move || {
            let shared = Arc::clone(&contract_method_fallback);
            async move {
                let mut response = facade_problem(
                    shared.loaded.problems(),
                    ErrorClass::FacadeMethodNotAllowed,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "",
                    &new_id(),
                );
                response
                    .headers_mut()
                    .insert(header::ALLOW, HeaderValue::from_static("GET"));
                response
            }
        }),
    );
    let unmatched = Arc::clone(&state);
    router.fallback(move |correlation: Option<Extension<RequestCorrelation>>| {
        let shared = Arc::clone(&unmatched);
        async move {
            let request_id = correlation
                .as_ref()
                .map_or_else(new_id, |Extension(value)| value.request_id().to_owned());
            facade_problem(
                shared.loaded.problems(),
                ErrorClass::FacadeNotFound,
                StatusCode::NOT_FOUND,
                "",
                &request_id,
            )
        }
    })
}

/// The served operation, among those of one method and path, that answers
/// the record type the call names. A record type no binding serves falls to
/// the first, whose handler authenticates the caller before it refuses the
/// call 404.
fn dispatch(
    served: &[ServedOperation],
    indexes: &[usize],
    params: &HashMap<String, String>,
) -> usize {
    indexes
        .iter()
        .copied()
        .find(|&index| {
            let operation = &served[index];
            params.get(&operation.record_type_parameter) == Some(&operation.record_type)
        })
        .unwrap_or(indexes[0])
}

/// Run one call to completion on its own task: a caller that disconnects
/// drops this future but cannot cancel an exchange part way, so the source
/// call and its journal rows always finish together.
async fn handle(
    state: Arc<FacadeState>,
    index: usize,
    correlation: Option<RequestCorrelation>,
    headers: HeaderMap,
    params: HashMap<String, String>,
    query: Option<String>,
    body: Body,
) -> Response {
    let fallback = Arc::clone(&state);
    // The id is minted before the task starts, so the fallback answer
    // carries the same request id the journal rows would have.
    let request_id = correlation
        .as_ref()
        .map_or_else(new_id, |value| value.request_id().to_owned());
    let fallback_id = request_id.clone();
    let fallback_record_type = params
        .get(&state.loaded.served[index].record_type_parameter)
        .cloned()
        .unwrap_or_default();
    let task = tokio::spawn(async move {
        answer(
            &state,
            index,
            request_id,
            correlation.as_ref(),
            &headers,
            &params,
            query.as_deref(),
            body,
        )
        .await
    });
    let response = match task.await {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "a facade call ended without an answer");
            facade_problem(
                fallback.loaded.problems(),
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &fallback_record_type,
                &fallback_id,
            )
        }
    };
    // A replay is a new physical attempt and keeps `fallback_id` in its
    // journal events. Its caller-visible response is exact prior custody, so
    // header and any profile-rendered body slot retain the original id.
    let response_id = response
        .extensions()
        .get::<ReplayedResponseRequestId>()
        .map(|replayed| replayed.0.clone())
        .unwrap_or(fallback_id);
    with_request_id(response, &response_id)
}

async fn handle_async_status(
    state: Arc<FacadeState>,
    indexes: Arc<[usize]>,
    headers: HeaderMap,
    params: HashMap<String, String>,
    query: Option<String>,
) -> Response {
    let physical_request_id = new_id();
    let fallback_id = physical_request_id.clone();
    let fallback = Arc::clone(&state);
    let task = tokio::spawn(async move {
        answer_async_status(
            &state,
            &indexes,
            physical_request_id,
            &headers,
            &params,
            query.as_deref(),
        )
        .await
    });
    let response = match task.await {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "an asynchronous status call ended without an answer");
            facade_problem(
                fallback.loaded.problems(),
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                "",
                &fallback_id,
            )
        }
    };
    let response_id = response
        .extensions()
        .get::<ReplayedResponseRequestId>()
        .map(|replayed| replayed.0.clone())
        .unwrap_or(fallback_id);
    with_request_id(response, &response_id)
}

async fn answer_async_status(
    state: &FacadeState,
    indexes: &[usize],
    physical_request_id: String,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
    query: Option<&str>,
) -> Response {
    let representative = &state.loaded.served[indexes[0]];
    let profile = state.loaded.problems();
    let caller = match authenticate(state, headers).await {
        Ok(caller) => caller,
        Err(refusal) => return refusal_response(profile, refusal, &physical_request_id),
    };
    if !accepts_json(headers) {
        return refuse_call(
            state,
            representative,
            &caller,
            &representative.record_type,
            &physical_request_id,
            ErrorClass::FacadeNotAcceptable,
            StatusCode::NOT_ACCEPTABLE,
        )
        .await;
    }
    if query.is_some_and(|value| !value.is_empty()) {
        return refuse_request(
            state,
            representative,
            &caller,
            &representative.record_type,
            &physical_request_id,
            Refusal::invalid_request("the asynchronous status operation takes no query parameters"),
        )
        .await;
    }
    if !effective_contract_matches(headers, &state.effective_contract.digest) {
        return refuse_contract_pin(state, representative, &caller, &physical_request_id).await;
    }
    let Some(status_id) = params.get("statusId") else {
        return refuse_call(
            state,
            representative,
            &caller,
            &representative.record_type,
            &physical_request_id,
            ErrorClass::FacadeNotFound,
            StatusCode::NOT_FOUND,
        )
        .await;
    };
    let Some(store) = state.idempotency.as_ref() else {
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &representative.record_type,
            &physical_request_id,
        );
    };
    let caller_identity = match VerifiedCallerIdentity::new(
        caller.issuer.clone(),
        caller.reference.clone(),
        caller.client_id.clone(),
    ) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::error!(%error, "the verified caller could not enter asynchronous status custody");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &representative.record_type,
                &physical_request_id,
            );
        }
    };
    let lookup = match store
        .lookup_status(
            StatusLookupRequest {
                caller: &caller_identity,
                deployment: state.loaded.runtime.id.as_str(),
                artifact_digest: state.artifact_digest,
                status_id,
            },
            SystemTime::now(),
        )
        .await
    {
        Ok(lookup) => lookup,
        Err(error) => {
            tracing::error!(%error, "asynchronous status custody failed");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &representative.record_type,
                &physical_request_id,
            );
        }
    };
    let metadata = match &lookup {
        StatusLookup::NotFound => {
            return refuse_call(
                state,
                representative,
                &caller,
                &representative.record_type,
                &physical_request_id,
                ErrorClass::FacadeNotFound,
                StatusCode::NOT_FOUND,
            )
            .await;
        }
        StatusLookup::Accepted(pending) => pending.metadata().clone(),
        StatusLookup::Terminal { metadata, .. } => metadata.clone(),
    };
    let Some(operation) = indexes
        .iter()
        .map(|index| &state.loaded.served[*index])
        .find(|operation| {
            operation.binding == metadata.binding_id()
                && operation.operation == metadata.profile_operation()
                && operation.record_type == metadata.record_type()
        })
    else {
        tracing::error!("asynchronous custody names no loaded binding");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &representative.record_type,
            &physical_request_id,
        );
    };
    if !admits_stored(
        &state.loaded.project,
        &caller,
        metadata.profile_operation(),
        metadata.record_type(),
    ) {
        return refuse_call(
            state,
            operation,
            &caller,
            metadata.record_type(),
            &physical_request_id,
            ErrorClass::FacadeForbidden,
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    let event = |kind: &'static str, detail: Option<Value>, at: SystemTime| {
        (
            JournalEvent {
                event_kind: kind,
                exchange_id: physical_request_id.clone(),
                operation: operation.operation.clone(),
                caller_ref: caller.reference.clone(),
                route_id: operation
                    .async_completion
                    .as_ref()
                    .expect("asynchronous operation")
                    .status
                    .route_id
                    .clone(),
                detail: detail.map(|value| value.to_string()),
            },
            at,
        )
    };
    if let StatusLookup::Terminal {
        outcome, response, ..
    } = lookup
    {
        let terminal_kind = match outcome {
            TerminalOutcome::Completed => "exchangeCompleted",
            TerminalOutcome::Failed => "exchangeFailed",
        };
        let events = vec![
            event("exchangeCreated", None, SystemTime::now()),
            event(terminal_kind, None, SystemTime::now()),
        ];
        if let Err(fault) = append_all(&state.journal, events).await {
            tracing::error!(%fault, "the terminal status replay could not be journaled");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                metadata.record_type(),
                &physical_request_id,
            );
        }
        return replay_response(response);
    }
    let StatusLookup::Accepted(pending) = lookup else {
        unreachable!("terminal and absent status lookups returned above")
    };
    let accepted_response = pending.response().clone();
    let created = event("exchangeCreated", None, SystemTime::now());
    let Some(semaphore) = state.async_recovery.get(&operation.binding) else {
        tracing::error!("asynchronous binding has no recovery admission pool");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            metadata.record_type(),
            &physical_request_id,
        );
    };
    let Ok(_permit) = Arc::clone(semaphore).try_acquire_owned() else {
        if let Err(fault) = append_all(&state.journal, vec![created]).await {
            tracing::error!(%fault, "the audit journal could not record a busy status lookup");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                metadata.record_type(),
                &physical_request_id,
            );
        }
        return replay_response(accepted_response);
    };
    let deadline_clock = tokio::time::Instant::now();
    let deadline_wall = SystemTime::now();
    let absolute_deadline = deadline_clock + EXCHANGE_DEADLINE;
    let requested_deadline = deadline_wall
        .checked_add(absolute_deadline.duration_since(deadline_clock))
        .expect("the fixed status deadline fits SystemTime");
    let recovery = match store
        .acquire_status_recovery(&pending, deadline_wall, requested_deadline)
        .await
    {
        Ok(RecoveryLease::Acquired(recovery)) => recovery,
        Ok(RecoveryLease::Busy) => {
            if let Err(fault) = append_all(&state.journal, vec![created]).await {
                tracing::error!(%fault, "the audit journal could not record a leased status lookup");
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    metadata.record_type(),
                    &physical_request_id,
                );
            }
            return replay_response(accepted_response);
        }
        Ok(RecoveryLease::Stale) => {
            // A concurrent poller can commit the terminal answer between the
            // lookup above and this lease. Answer from what custody holds now;
            // only a link that is gone answers 404.
            let relookup = store
                .lookup_status(
                    StatusLookupRequest {
                        caller: &caller_identity,
                        deployment: state.loaded.runtime.id.as_str(),
                        artifact_digest: state.artifact_digest,
                        status_id,
                    },
                    SystemTime::now(),
                )
                .await;
            let (events, response) = match relookup {
                Ok(StatusLookup::Terminal {
                    outcome, response, ..
                }) => {
                    let terminal_kind = match outcome {
                        TerminalOutcome::Completed => "exchangeCompleted",
                        TerminalOutcome::Failed => "exchangeFailed",
                    };
                    (
                        vec![created, event(terminal_kind, None, SystemTime::now())],
                        response,
                    )
                }
                Ok(StatusLookup::Accepted(_)) => (vec![created], accepted_response),
                Ok(StatusLookup::NotFound) => {
                    return refuse_call(
                        state,
                        operation,
                        &caller,
                        metadata.record_type(),
                        &physical_request_id,
                        ErrorClass::FacadeNotFound,
                        StatusCode::NOT_FOUND,
                    )
                    .await;
                }
                Err(error) => {
                    tracing::error!(%error, "asynchronous status custody failed");
                    return facade_problem(
                        profile,
                        ErrorClass::Facade,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        metadata.record_type(),
                        &physical_request_id,
                    );
                }
            };
            if let Err(fault) = append_all(&state.journal, events).await {
                tracing::error!(%fault, "the status replay after a lost lease could not be journaled");
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    metadata.record_type(),
                    &physical_request_id,
                );
            }
            return replay_response(response);
        }
        Err(error) => {
            tracing::error!(%error, "the asynchronous poll lease failed");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                metadata.record_type(),
                &physical_request_id,
            );
        }
    };
    let Some(source_id) = recovery.source_id() else {
        tracing::error!("accepted asynchronous custody has no source id");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            metadata.record_type(),
            &physical_request_id,
        );
    };
    let poll_started = tokio::time::Instant::now();
    let context = RouteContext {
        endpoints: &state.loaded.endpoints,
        scripts: &state.loaded.scripts,
        resolver: &state.loaded.resolver,
        resilience: &operation.resilience,
        routes: &state.loaded.routes,
        code_maps: state.loaded.code_maps.clone(),
        maximum_upstream_calls: operation.maximum_upstream_calls,
        job: crate::engine::job_sources::JobPageState::default(),
    };
    let polled = run_async_status_poll(
        &context,
        &state.loaded.profile,
        operation,
        AsyncStatusPollKind::Primary,
        source_id,
        &physical_request_id,
        absolute_deadline,
    )
    .await;
    let mut events = vec![created];
    for route_event in polled.events {
        events.push(event(
            route_event.kind,
            Some(route_event.detail),
            route_event.at,
        ));
    }
    let duration = u64::try_from(poll_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match polled.result {
        Ok(AsyncStatusOutcome::Pending {}) => {
            events.push(event(
                "recoveryChecked",
                Some(json!({"result": "pending", "pollOrdinal": 1, "durationMilliseconds": duration})),
                SystemTime::now(),
            ));
            return finish_nonterminal_poll(
                state,
                store,
                recovery,
                events,
                accepted_response,
                metadata.record_type(),
                &physical_request_id,
            )
            .await;
        }
        Err(failure) => {
            events.push(event(
                "recoveryCheckFailed",
                Some(json!({"class": failure.class.class(), "certainty": "uncertain"})),
                SystemTime::now(),
            ));
            return finish_nonterminal_poll(
                state,
                store,
                recovery,
                events,
                accepted_response,
                metadata.record_type(),
                &physical_request_id,
            )
            .await;
        }
        Ok(outcome) => {
            let terminal = render_recovery_terminal(
                state,
                operation,
                outcome,
                metadata.record_type(),
                recovery.response_request_id(),
            );
            let (response, outcome, result) = match terminal {
                Ok(terminal) => terminal,
                Err(class) => {
                    events.push(event(
                        "recoveryCheckFailed",
                        Some(json!({"class": class.class(), "certainty": "uncertain"})),
                        SystemTime::now(),
                    ));
                    return finish_nonterminal_poll(
                        state,
                        store,
                        recovery,
                        events,
                        accepted_response,
                        metadata.record_type(),
                        &physical_request_id,
                    )
                    .await;
                }
            };
            events.push(event(
                "recoveryChecked",
                Some(json!({"result": result, "pollOrdinal": 1, "durationMilliseconds": duration})),
                SystemTime::now(),
            ));
            events.push(event(
                match outcome {
                    TerminalOutcome::Completed => "exchangeCompleted",
                    TerminalOutcome::Failed => "exchangeFailed",
                },
                None,
                SystemTime::now(),
            ));
            match append_all_with_recovery(
                &state.journal,
                store,
                recovery,
                outcome,
                response,
                events,
            )
            .await
            {
                Ok(response) => response,
                Err(fault) => {
                    tracing::error!(%fault, "terminal recovery custody and journal could not commit");
                    facade_problem(
                        profile,
                        ErrorClass::Facade,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        metadata.record_type(),
                        &physical_request_id,
                    )
                }
            }
        }
    }
}

/// Return the immutable startup contract only to an authenticated machine
/// caller and only while the live journal migration set is exactly the set
/// this binary supports. This readiness check deliberately does not touch an
/// upstream source.
async fn runtime_contract(state: Arc<FacadeState>, headers: HeaderMap) -> Response {
    let request_id = new_id();
    if let Err(refusal) = authenticate(&state, &headers).await {
        return refusal_response(state.loaded.problems(), refusal, &request_id);
    }
    let journal_ready = match state.journal.get().await {
        Ok(client) => journal::ready(&client).await.unwrap_or(false),
        Err(_) => false,
    };
    if !journal_ready {
        tracing::error!("the effective contract journal readiness check failed");
        return contract_unavailable(&request_id);
    }
    match serde_json::to_value(RuntimeContractResponse::ready(&state.effective_contract)) {
        Ok(body) => with_request_id(json_response(StatusCode::OK, &body), &request_id),
        Err(error) => {
            tracing::error!(%error, "the effective contract response could not be serialized");
            contract_unavailable(&request_id)
        }
    }
}

/// Return only the built-in Consultation operations visible under the
/// authenticated caller's current machine scopes. Discovery remains
/// advisory: every operation request repeats current authorization.
async fn caller_capabilities(
    state: Arc<FacadeState>,
    correlation: RequestCorrelation,
    headers: HeaderMap,
) -> Response {
    let request_id = correlation.request_id().to_owned();
    let caller = match authenticate(&state, &headers).await {
        Ok(caller) => caller,
        Err(refusal) => return refusal_response(state.loaded.problems(), refusal, &request_id),
    };
    if !accepts_json(&headers) {
        return journal_capability_refusal(
            &state,
            &caller,
            &request_id,
            ErrorClass::FacadeNotAcceptable,
            StatusCode::NOT_ACCEPTABLE,
        )
        .await;
    }
    let journal_ready = match state.journal.get().await {
        Ok(client) => journal::ready(&client).await.unwrap_or(false),
        Err(_) => false,
    };
    if !journal_ready {
        tracing::error!("the Consultation capability journal readiness check failed");
        return consultation_unavailable(&request_id);
    }
    let document = match crate::govstack::consultation::caller_capabilities(
        &state.loaded.project,
        &state.loaded.served,
        |served| admits(&state.loaded.project, &caller, served),
    ) {
        Ok(document) => document,
        Err(error) => {
            tracing::error!(%error, "the caller capability document was refused");
            return journal_capability_refusal(
                &state,
                &caller,
                &request_id,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .await;
        }
    };
    let completed_at = SystemTime::now();
    let audit = ["exchangeCreated", "exchangeCompleted"]
        .into_iter()
        .map(|event_kind| {
            (
                JournalEvent {
                    event_kind,
                    exchange_id: request_id.clone(),
                    operation: "getCallerCapabilities".to_owned(),
                    caller_ref: caller.reference.clone(),
                    route_id: "consultation-capabilities".to_owned(),
                    detail: None,
                },
                completed_at,
            )
        })
        .collect();
    if let Err(fault) = append_all(&state.journal, audit).await {
        tracing::error!(%fault, "the capability discovery audit row could not commit");
        return facade_problem(
            state.loaded.problems(),
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
            &request_id,
        );
    }
    match serde_json::to_value(document) {
        Ok(body) => {
            let mut response = with_request_id(json_response(StatusCode::OK, &body), &request_id);
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            with_write_replay_window(&state, response)
        }
        Err(error) => {
            tracing::error!(%error, "the caller capability response could not be serialized");
            facade_problem(
                state.loaded.problems(),
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                "",
                &request_id,
            )
        }
    }
}

async fn journal_capability_refusal(
    state: &FacadeState,
    caller: &Caller,
    request_id: &str,
    class: ErrorClass,
    status: StatusCode,
) -> Response {
    let event = JournalEvent {
        event_kind: "callRefused",
        exchange_id: request_id.to_owned(),
        operation: "getCallerCapabilities".to_owned(),
        caller_ref: caller.reference.clone(),
        route_id: "consultation-capabilities".to_owned(),
        detail: Some(json!({"class": class.class(), "status": status.as_u16()}).to_string()),
    };
    if let Err(fault) = append_all(&state.journal, vec![(event, SystemTime::now())]).await {
        tracing::error!(%fault, "the capability discovery refusal could not be journaled");
        return facade_problem(
            state.loaded.problems(),
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
            request_id,
        );
    }
    facade_problem(state.loaded.problems(), class, status, "", request_id)
}

#[allow(clippy::too_many_arguments)]
async fn answer(
    state: &FacadeState,
    index: usize,
    request_id: String,
    correlation: Option<&RequestCorrelation>,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
    query: Option<&str>,
    body: Body,
) -> Response {
    let operation = &state.loaded.served[index];
    let profile = state.loaded.problems();
    let is_write = state
        .loaded
        .profile
        .operations
        .get(operation.operation.as_str())
        .is_some_and(|declared| !declared.is_read());
    let record_type = params
        .get(&operation.record_type_parameter)
        .cloned()
        .unwrap_or_default();
    let mut names_record_id = operation.record_id_parameter.is_some();
    let mut record_id = operation
        .record_id_parameter
        .as_ref()
        .and_then(|name| params.get(name))
        .cloned()
        .unwrap_or_default();

    let caller = match authenticate(state, headers).await {
        Ok(caller) => caller,
        Err(refusal) => return refusal_response(profile, refusal, &request_id),
    };
    if !accepts_json(headers) {
        return refuse_call(
            state,
            operation,
            &caller,
            &record_type,
            &request_id,
            ErrorClass::FacadeNotAcceptable,
            StatusCode::NOT_ACCEPTABLE,
        )
        .await;
    }
    if record_type != operation.record_type {
        return refuse_call(
            state,
            operation,
            &caller,
            &record_type,
            &request_id,
            ErrorClass::FacadeNotFound,
            StatusCode::NOT_FOUND,
        )
        .await;
    }
    if !admits(&state.loaded.project, &caller, operation) {
        return refuse_call(
            state,
            operation,
            &caller,
            &record_type,
            &request_id,
            ErrorClass::FacadeForbidden,
            StatusCode::FORBIDDEN,
        )
        .await;
    }
    if !effective_contract_matches(headers, &state.effective_contract.digest) {
        return refuse_contract_pin(state, operation, &caller, &request_id).await;
    }

    let govstack_write = operation.write_support.is_some();
    let mut native_condition = None;
    let mut semantic_condition = None;
    if govstack_write && operation.method == HttpMethod::Patch {
        let values: Vec<_> = headers.get_all(header::IF_MATCH).iter().collect();
        let refusal = if values.is_empty() {
            Some(Refusal::write(
                "precondition-required",
                StatusCode::PRECONDITION_REQUIRED,
            ))
        } else if values.len() != 1 {
            Some(Refusal::invalid_request("one strong If-Match is required"))
        } else if let Ok(value) = values[0].to_str() {
            semantic_condition = Some(value.to_owned());
            match write_validator_context(state, &record_type, &record_id).and_then(|context| {
                state.codec.as_ref().and_then(|codec| {
                    crate::govstack::write::unwrap_validator(value, context, codec).ok()
                })
            }) {
                Some(native) => {
                    native_condition = Some(native);
                    None
                }
                None if !crate::govstack::write::is_strong_etag(value) => {
                    Some(Refusal::invalid_request("one strong If-Match is required"))
                }
                None => Some(Refusal::write(
                    "precondition-failed",
                    StatusCode::PRECONDITION_FAILED,
                )),
            }
        } else {
            Some(Refusal::invalid_request("one strong If-Match is required"))
        };
        if let Some(refusal) = refusal {
            return refuse_request(
                state,
                operation,
                &caller,
                &record_type,
                &request_id,
                refusal,
            )
            .await;
        }
    }
    let mut inputs = RequestInputs::default();
    let mut write_request: Option<(Value, Vec<u8>)> = None;
    if matches!(
        operation.method,
        HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
    ) {
        let expected_media = if govstack_write && operation.method == HttpMethod::Patch {
            "application/merge-patch+json"
        } else {
            "application/json"
        };
        if !has_content_type(headers, expected_media) {
            return refuse_call(
                state,
                operation,
                &caller,
                &record_type,
                &request_id,
                ErrorClass::FacadeUnsupportedMediaType,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            )
            .await;
        }
        let bytes = match read_body(headers, body, operation.request_maximum_bytes).await {
            Ok(bytes) => bytes,
            Err(()) => {
                return refuse_call(
                    state,
                    operation,
                    &caller,
                    &record_type,
                    &request_id,
                    ErrorClass::FacadePayloadTooLarge,
                    StatusCode::PAYLOAD_TOO_LARGE,
                )
                .await;
            }
        };
        if query.is_some_and(|text| !text.is_empty()) {
            return refuse_request(
                state,
                operation,
                &caller,
                &record_type,
                &request_id,
                Refusal::invalid_request("a body-bearing operation takes no query parameters"),
            )
            .await;
        }
        let Ok(parsed) = serde_json::from_slice::<Value>(&bytes) else {
            return refuse_request(
                state,
                operation,
                &caller,
                &record_type,
                &request_id,
                Refusal::invalid_request("the request body is not JSON"),
            )
            .await;
        };
        if is_write {
            let Some(declared) = state
                .loaded
                .profile
                .operations
                .get(operation.operation.as_str())
            else {
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &record_type,
                    &request_id,
                );
            };
            let Some(template) = &declared.request_envelope else {
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &record_type,
                    &request_id,
                );
            };
            let captured = if govstack_write {
                capture_govstack_write(operation, &parsed)
            } else {
                capture_write_record(template.text(), &parsed).and_then(|captured| {
                    validate_write_record(operation, &captured, &record_id)?;
                    Ok(captured)
                })
            };
            match captured {
                Ok(captured) => {
                    if let Some(captured_id) = captured.record_id {
                        if !names_record_id {
                            names_record_id = true;
                            record_id = captured_id;
                        }
                    }
                    write_request = Some((captured.record, bytes.to_vec()));
                }
                Err(refusal) => {
                    return refuse_request(
                        state,
                        operation,
                        &caller,
                        &record_type,
                        &request_id,
                        refusal,
                    )
                    .await;
                }
            }
        } else {
            let Some(template) = &operation.request_template else {
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &record_type,
                    &request_id,
                );
            };
            match template.capture(&parsed, &operation.filters) {
                Ok(captured) => {
                    if let Some(id) = captured.record_id {
                        names_record_id = true;
                        record_id = id;
                    }
                    inputs.cursor = captured.cursor;
                    inputs.page_size = captured.page_size;
                    inputs.filters = captured.filters.unwrap_or_default();
                }
                Err(refusal) => {
                    return refuse_request(
                        state,
                        operation,
                        &caller,
                        &record_type,
                        &request_id,
                        match refusal {
                            ReadRefusal::Shape(reason) => Refusal::invalid_request(&reason),
                            ReadRefusal::Field(reason) => Refusal::invalid_field(&reason),
                        },
                    )
                    .await;
                }
            }
        }
    } else if operation.pagination.is_some() || !operation.filters.is_empty() {
        match query_inputs(operation, query) {
            Ok(parsed) => inputs = parsed,
            Err(refusal) => {
                return refuse_request(
                    state,
                    operation,
                    &caller,
                    &record_type,
                    &request_id,
                    refusal,
                )
                .await;
            }
        }
    } else if query.is_some_and(|text| !text.is_empty()) {
        return refuse_request(
            state,
            operation,
            &caller,
            &record_type,
            &request_id,
            Refusal::invalid_request("the operation takes no query parameters"),
        )
        .await;
    }

    if !is_write {
        if let Err(refusal) = require_declared_filters(operation, &inputs)
            .and_then(|()| validate_project_inputs(operation, &inputs))
        {
            return refuse_request(
                state,
                operation,
                &caller,
                &record_type,
                &request_id,
                refusal,
            )
            .await;
        }
    }

    if names_record_id && !is_path_segment_value(&record_id) {
        return refuse_call(
            state,
            operation,
            &caller,
            &record_type,
            &request_id,
            ErrorClass::OutcomeNotFound,
            StatusCode::NOT_FOUND,
        )
        .await;
    }

    let route_clock = tokio::time::Instant::now();
    let route_wall_clock = SystemTime::now();
    let route_deadline = route_clock + EXCHANGE_DEADLINE;
    let effect_deadline = route_wall_clock
        .checked_add(route_deadline.duration_since(route_clock))
        .expect("the fixed exchange deadline fits SystemTime");
    let mut exchange = Exchange::new(request_id.clone());
    if let Some(correlation) = correlation {
        if let Err(error) = correlation.install(&mut exchange) {
            tracing::error!(
                error,
                "the Consultation trace context could not be installed"
            );
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &record_type,
                &request_id,
            );
        }
    }
    let write_execution = if is_write {
        let Some((record, raw_body)) = write_request else {
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &record_type,
                &request_id,
            );
        };
        let key = if govstack_write {
            let mut values = headers.get_all("idempotency-key").iter();
            let key = values
                .next()
                .and_then(|value| value.to_str().ok())
                .and_then(|value| crate::govstack::write::parse_idempotency_key(value).ok());
            if values.next().is_some() {
                None
            } else {
                key
            }
        } else {
            idempotency_key(headers)
        };
        let Some(key) = key else {
            return refuse_request(
                state,
                operation,
                &caller,
                &record_type,
                &request_id,
                if govstack_write {
                    Refusal::invalid_request("the Idempotency-Key header is absent or invalid")
                        .with_detail(
                            "send one Idempotency-Key header whose value is a quoted string, \
                             such as Idempotency-Key: \"0b7d4c2e-1f3a-4e5b-9c6d-7e8f9a0b1c2d\"",
                        )
                } else {
                    Refusal::invalid_field("the Idempotency-Key header is absent or invalid")
                },
            )
            .await;
        };
        let Some(store) = state.idempotency.clone() else {
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &record_type,
                &request_id,
            );
        };
        let caller_identity = match VerifiedCallerIdentity::new(
            caller.issuer.clone(),
            caller.reference.clone(),
            caller.client_id.clone(),
        ) {
            Ok(identity) => identity,
            Err(error) => {
                tracing::error!(%error, "the verified caller could not enter the idempotency namespace");
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &record_type,
                    &request_id,
                );
            }
        };
        exchange.message.body = record;
        exchange
            .message
            .set_header("Idempotency-Key", Value::String(key.to_owned()));
        let concrete_operation = format!(
            "{}:{}:{}",
            operation.operation, operation.binding, record_type
        );
        let digest = if govstack_write {
            let method = if operation.method == HttpMethod::Patch {
                "PATCH"
            } else {
                "POST"
            };
            let target = if operation.method == HttpMethod::Patch {
                crate::govstack::write::record_location(&record_type, &record_id)
            } else {
                Ok(format!("{MOUNT_PATH}/v1/collections/{record_type}/records"))
            };
            let Ok(target) = target else {
                return refuse_request(
                    state,
                    operation,
                    &caller,
                    &record_type,
                    &request_id,
                    Refusal::invalid_request("the record identifier is not supported"),
                )
                .await;
            };
            let media = if operation.method == HttpMethod::Patch {
                "application/merge-patch+json"
            } else {
                "application/json"
            };
            let canonical_body = json!({"data": exchange.message.body});
            let Ok(digest) = crate::govstack::write::request_fingerprint(
                method,
                &target,
                media,
                &canonical_body,
                semantic_condition.as_deref(),
            ) else {
                return refuse_request(
                    state,
                    operation,
                    &caller,
                    &record_type,
                    &request_id,
                    Refusal::invalid_request("the write request cannot be canonicalized"),
                )
                .await;
            };
            let scope = crate::govstack::write::source_key_scope(
                &caller.issuer,
                &caller.reference,
                &caller.client_id,
                state.loaded.runtime.id.as_str(),
                method,
                &target,
                key,
            );
            let installed = crate::engine::exchange::SourceWriteInputs::try_new(
                scope,
                native_condition.as_deref(),
            )
            .and_then(|inputs| exchange.install_source_write_inputs(inputs));
            if installed.is_err() {
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &record_type,
                    &request_id,
                );
            }
            digest
        } else {
            write_request_digest(
                &state.loaded.deployment,
                &record_type,
                &record_id,
                &raw_body,
            )
        };
        let async_write = operation
            .async_completion
            .as_ref()
            .map(|completion| AsyncWriteContext {
                response_request_id: request_id.clone(),
                artifact_digest: state.artifact_digest,
                binding_id: operation.binding.clone(),
                profile_operation: operation.operation.clone(),
                record_type: operation.record_type.clone(),
                recovery_id: completion.uncertainty.as_ref().map(|_| new_recovery_id()),
                effect_deadline,
            });
        let context = match (async_write, operation.resume_step_count()) {
            (Some(async_write), None) => crate::custody::WriteExecutionContext::new_async(
                store,
                caller_identity,
                state.loaded.runtime.id.as_str().to_owned(),
                concrete_operation,
                digest,
                async_write,
            ),
            (None, Some(step_count)) => crate::custody::WriteExecutionContext::new_resume(
                store,
                caller_identity,
                state.loaded.runtime.id.as_str().to_owned(),
                concrete_operation,
                digest,
                ResumeWriteContext {
                    artifact_digest: state.artifact_digest,
                    source_digest: crate::custody::source_digest(&state.loaded, &operation.steps),
                    effect_deadline,
                    step_count,
                },
            ),
            (None, None) => crate::custody::WriteExecutionContext::new(
                store,
                caller_identity,
                state.loaded.runtime.id.as_str().to_owned(),
                concrete_operation,
                digest,
            ),
            (Some(_), Some(_)) => {
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &record_type,
                    &request_id,
                );
            }
        };
        exchange.install_write(
            context.clone() as std::sync::Arc<dyn crate::engine::exchange::WriteCustody>
        );
        Some(context)
    } else {
        None
    };
    let mut search_binding: Option<SearchBinding> = None;
    let mut requested_page_size: Option<u64> = None;
    if let Some(pagination) = &operation.pagination {
        match open_search(state, operation, pagination, &caller, &record_type, inputs) {
            Ok(search) => {
                exchange
                    .message
                    .set_header(PAGE_SIZE_HEADER, json!(search.page_size));
                exchange.set_property(FILTERS_PROPERTY, Value::Object(search.filters));
                if let Some(continuation) = search.continuation {
                    exchange.set_property(CONTINUATION_PROPERTY, continuation);
                }
                requested_page_size = Some(search.page_size);
                search_binding = Some(search.binding);
            }
            Err(refusal) => {
                return refuse_request(
                    state,
                    operation,
                    &caller,
                    &record_type,
                    &request_id,
                    refusal,
                )
                .await;
            }
        }
    } else if !inputs.filters.is_empty() {
        exchange.set_property(FILTERS_PROPERTY, Value::Object(inputs.filters));
    }
    exchange
        .message
        .set_header("recordType", Value::String(record_type.clone()));
    exchange
        .message
        .set_header("recordId", Value::String(record_id.clone()));
    let journal_event = |kind: &'static str, detail: Option<Value>| JournalEvent {
        event_kind: kind,
        exchange_id: request_id.clone(),
        operation: operation.operation.clone(),
        caller_ref: caller.reference.clone(),
        route_id: operation.route_id.clone(),
        detail: detail.map(|value| value.to_string()),
    };
    // The exchange is on record before the source is called: a call that
    // never completes still leaves its `exchangeCreated` behind.
    let created = vec![(journal_event("exchangeCreated", None), SystemTime::now())];
    if let Err(fault) = append_all(&state.journal, created).await {
        tracing::error!(%fault, "the audit journal could not record the exchange");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &record_type,
            &request_id,
        );
    }
    let mut events = Vec::new();

    let context = RouteContext {
        endpoints: &state.loaded.endpoints,
        scripts: &state.loaded.scripts,
        resolver: &state.loaded.resolver,
        resilience: &operation.resilience,
        routes: &state.loaded.routes,
        code_maps: state.loaded.code_maps.clone(),
        maximum_upstream_calls: operation.maximum_upstream_calls,
        job: crate::engine::job_sources::JobPageState::default(),
    };
    let outcome = run_served_route_until(
        &context,
        &state.loaded.profile,
        operation,
        exchange,
        route_deadline,
    )
    .await;
    for event in outcome.events {
        events.push((journal_event(event.kind, Some(event.detail)), event.at));
    }
    let write_resolution = match &write_execution {
        Some(context) => context.resolution().await,
        None => WriteResolution::Pending,
    };
    let uncertain_effect = match &write_execution {
        Some(context) => outcome.result.is_err() && context.has_uncertain_effect().await,
        None => false,
    };
    let recoverable_uncertainty = match &write_execution {
        Some(context) => {
            context.has_recoverable_uncertainty().await
                && (matches!(write_resolution, WriteResolution::Uncertain) || uncertain_effect)
        }
        None => false,
    };
    if recoverable_uncertainty {
        return run_uncertainty_recovery(
            state,
            UncertaintyRecoveryRequest {
                operation,
                caller: &caller,
                write: write_execution
                    .as_ref()
                    .expect("recoverable uncertainty has write custody"),
                events,
                physical_request_id: &request_id,
                absolute_deadline: route_deadline,
                deadline_wall: effect_deadline,
            },
        )
        .await;
    }
    if uncertain_effect {
        events.push((
            journal_event(
                "exchangeFailed",
                Some(exchange_failure_detail(profile, ErrorClass::FacadeConflict)),
            ),
            SystemTime::now(),
        ));
        if let Err(fault) = append_all(&state.journal, events).await {
            tracing::error!(%fault, "the uncertain-effect journal could not commit");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &record_type,
                &request_id,
            );
        }
        return facade_problem(
            profile,
            ErrorClass::FacadeConflict,
            StatusCode::CONFLICT,
            &record_type,
            &request_id,
        );
    }

    // The response body is built before the journal commits, so the
    // journal never records `exchangeCompleted` for an exchange whose body
    // the facade then failed to seal or render.
    let mut resume_host_validation_pending = false;
    let mut retry_later = false;
    let mut success_etag = None;
    let mut success_location = None;
    let mut success_bodyless = false;
    let rendered = match write_resolution.clone() {
        WriteResolution::Replay { outcome, response } => {
            let event = match outcome {
                TerminalOutcome::Completed => "exchangeCompleted",
                TerminalOutcome::Failed => "exchangeFailed",
            };
            events.push((journal_event(event, None), SystemTime::now()));
            Finished::Replay {
                response,
                failed: outcome == TerminalOutcome::Failed,
            }
        }
        WriteResolution::Accepted { response } => Finished::Replay {
            response,
            failed: false,
        },
        WriteResolution::Conflict
        | WriteResolution::ResponseExpired
        | WriteResolution::UnsupportedIncomplete
        | WriteResolution::Uncertain => {
            events.push((
                journal_event(
                    "exchangeFailed",
                    Some(exchange_failure_detail(profile, ErrorClass::FacadeConflict)),
                ),
                SystemTime::now(),
            ));
            Finished::FacadeProblem(ErrorClass::FacadeConflict, StatusCode::CONFLICT)
        }
        WriteResolution::InFlight | WriteResolution::ResumePending => {
            retry_later = true;
            events.push((
                journal_event(
                    "exchangeFailed",
                    Some(exchange_failure_detail(profile, ErrorClass::FacadeConflict)),
                ),
                SystemTime::now(),
            ));
            Finished::FacadeProblem(ErrorClass::FacadeConflict, StatusCode::CONFLICT)
        }
        WriteResolution::Mismatch => {
            events.push((
                journal_event(
                    "exchangeFailed",
                    Some(exchange_failure_detail(
                        profile,
                        ErrorClass::FacadeIdempotencyMismatch,
                    )),
                ),
                SystemTime::now(),
            ));
            Finished::FacadeProblem(
                ErrorClass::FacadeIdempotencyMismatch,
                StatusCode::UNPROCESSABLE_ENTITY,
            )
        }
        WriteResolution::Finished => Finished::Internal,
        WriteResolution::Pending | WriteResolution::Released => match outcome.result {
            Ok(done) if done.async_source_acceptance().is_some() => Finished::Accepted(
                done.async_source_acceptance()
                    .expect("the guarded acceptance is present")
                    .source_id
                    .clone(),
            ),
            Ok(done) if govstack_write => {
                match govstack_write_success(
                    state,
                    operation,
                    &done,
                    &record_id,
                    route_deadline.into_std(),
                ) {
                    Ok((body, etag, location)) => {
                        success_etag = Some(etag);
                        success_location = location;
                        success_bodyless = operation.method == HttpMethod::Patch;
                        events.push((journal_event("exchangeCompleted", None), SystemTime::now()));
                        Finished::Body(body)
                    }
                    Err(()) => {
                        // A source may have committed before returning an invalid receipt.
                        // Keep the native replay lease available rather than spend it on a
                        // fabricated terminal acknowledgement.
                        if let Some(write) = &write_execution {
                            if let Err(error) =
                                write.retain_resume_after_host_validation_failure().await
                            {
                                tracing::error!(%error, "the source receipt recovery lease could not be released");
                            }
                        }
                        resume_host_validation_pending = true;
                        retry_later = true;
                        events.push((journal_event("exchangeFailed", None), SystemTime::now()));
                        Finished::FacadeProblem(ErrorClass::FacadeConflict, StatusCode::CONFLICT)
                    }
                }
            }
            Ok(done) => {
                if is_companion_read(state, operation) {
                    success_etag = write_validator_context(state, &record_type, &record_id)
                        .and_then(|context| {
                            let native = done
                                .message
                                .body
                                .get("revisionIdentifier")
                                .and_then(Value::as_str)?;
                            let codec = state.codec.as_ref()?;
                            crate::govstack::write::wrap_validator(native, context, codec).ok()
                        });
                    if success_etag.is_none() {
                        events.push((journal_event("exchangeFailed", None), SystemTime::now()));
                        return audited_internal_failure(state, events, &record_type, &request_id)
                            .await;
                    }
                }
                match disclosed_slots(
                    operation,
                    &done.message.body,
                    requested_page_size,
                    &record_type,
                    &request_id,
                ) {
                    Ok(slots) => {
                        match seal_next(
                            state,
                            operation,
                            &caller,
                            search_binding,
                            requested_page_size.unwrap_or_default(),
                            &done,
                        )
                        .and_then(|next_cursor| {
                            render_success(operation, slots, next_cursor, &record_type, &request_id)
                        }) {
                            Ok(body) => {
                                events.push((
                                    journal_event("exchangeCompleted", None),
                                    SystemTime::now(),
                                ));
                                Finished::Body(body)
                            }
                            Err(error) => {
                                tracing::error!(%error, "the response could not be built");
                                events.push((
                                    journal_event(
                                        "exchangeFailed",
                                        Some(exchange_failure_detail(profile, ErrorClass::Facade)),
                                    ),
                                    SystemTime::now(),
                                ));
                                Finished::Internal
                            }
                        }
                    }
                    Err(violations) => {
                        tracing::error!(
                            violations,
                            "a route ended with a record its type does not declare"
                        );
                        if operation.resume_step_count().is_some() {
                            let retained = match write_execution.as_ref() {
                                Some(write) => write
                                    .retain_resume_after_host_validation_failure()
                                    .await
                                    .map_err(|error| error.to_string()),
                                None => Err("write custody is absent".to_owned()),
                            };
                            if let Err(error) = retained {
                                tracing::error!(
                                    %error,
                                    "the resumable write lease could not be released after host validation failed"
                                );
                            }
                            resume_host_validation_pending = true;
                            retry_later = true;
                            events.push((
                                journal_event(
                                    "exchangeFailed",
                                    Some(exchange_failure_detail(
                                        profile,
                                        ErrorClass::FacadeConflict,
                                    )),
                                ),
                                SystemTime::now(),
                            ));
                            Finished::FacadeProblem(
                                ErrorClass::FacadeConflict,
                                StatusCode::CONFLICT,
                            )
                        } else {
                            let failure = RouteFailure {
                                class: ErrorClass::DisclosureViolation,
                                message: None,
                                data: None,
                                auth: None,
                                code: None,
                                record: None,
                                evidence_diagnostic: None,
                            };
                            events.push((
                                journal_event(
                                    "exchangeFailed",
                                    Some(exchange_failure_detail(profile, failure.class)),
                                ),
                                SystemTime::now(),
                            ));
                            Finished::Route(failure)
                        }
                    }
                }
            }
            Err(failure) => {
                let failure = enforce_problem_data(profile.profile, failure);
                let mut detail = exchange_failure_detail(profile, failure.class);
                if let Some(auth) = &failure.auth {
                    detail["auth"] = auth.as_ref().clone();
                }
                events.push((
                    journal_event("exchangeFailed", Some(detail)),
                    SystemTime::now(),
                ));
                Finished::Route(failure)
            }
        },
    };
    let rendered = match rendered {
        Finished::Accepted(source_id) => {
            let Some(write) = write_execution.as_ref() else {
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &record_type,
                    &request_id,
                );
            };
            let Some(retention) = state.async_retention else {
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &record_type,
                    &request_id,
                );
            };
            let Some(profile_async) = state
                .loaded
                .profile
                .operations
                .get(operation.operation.as_str())
                .and_then(|declared| declared.async_completion.as_ref())
            else {
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &record_type,
                    &request_id,
                );
            };
            let acceptance_event = journal_event("exchangeAccepted", None);
            let Some(binding_completion) = state
                .loaded
                .project
                .bindings
                .iter()
                .find(|binding| binding.id.as_str() == operation.binding)
                .and_then(|binding| binding.async_completion)
            else {
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &record_type,
                    &request_id,
                );
            };
            let acceptance_mode = match binding_completion {
                BindingAsyncCompletion::StatusLink {} => "status-link",
                BindingAsyncCompletion::BoundedWait { .. } => "bounded-wait",
            };
            match append_all_with_acceptance(
                &state.journal,
                events,
                acceptance_event,
                write,
                operation,
                profile_async,
                &state.loaded.project.parameterized_parts,
                &source_id,
                &request_id,
                retention,
                acceptance_mode,
            )
            .await
            {
                Ok(committed) => match binding_completion {
                    BindingAsyncCompletion::StatusLink {} => return committed.response,
                    BindingAsyncCompletion::BoundedWait {
                        wait_timeout_milliseconds,
                        poll_interval_milliseconds,
                        maximum_polls,
                    } => {
                        return run_bounded_wait(
                            state,
                            operation,
                            &caller,
                            committed,
                            Duration::from_millis(wait_timeout_milliseconds.get()),
                            Duration::from_millis(poll_interval_milliseconds.get()),
                            maximum_polls.get(),
                        )
                        .await;
                    }
                },
                Err(fault) => {
                    tracing::error!(%fault, "the acceptance journal and response custody could not commit");
                    return facade_problem(
                        profile,
                        ErrorClass::Facade,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &record_type,
                        &request_id,
                    );
                }
            }
        }
        other => other,
    };
    let (mut response, mut terminal) = match rendered {
        Finished::Body(body) => {
            let status = state
                .loaded
                .profile
                .operations
                .get(operation.operation.as_str())
                .and_then(|declared| {
                    u16::try_from(declared.success_status.get())
                        .ok()
                        .and_then(|status| StatusCode::from_u16(status).ok())
                })
                .unwrap_or(StatusCode::OK);
            (
                json_response(status, &body),
                Some(TerminalOutcome::Completed),
            )
        }
        Finished::Internal => {
            warn_exchange_failed(ErrorClass::Facade, StatusCode::INTERNAL_SERVER_ERROR);
            (
                facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &record_type,
                    &request_id,
                ),
                Some(TerminalOutcome::Failed),
            )
        }
        Finished::Route(failure) => {
            let response = if govstack_write
                && operation.method == HttpMethod::Patch
                && failure.class == ErrorClass::OutcomeConflict
            {
                govstack_problem(
                    "precondition-failed",
                    StatusCode::PRECONDITION_FAILED,
                    &request_id,
                )
            } else if govstack_write && failure.class == ErrorClass::OutcomeConflict {
                govstack_problem("conflict", StatusCode::CONFLICT, &request_id)
            } else if govstack_write && failure.class == ErrorClass::OutcomeRejected {
                govstack_problem("bad-gateway", StatusCode::BAD_GATEWAY, &request_id)
            } else if govstack_write && failure.class == ErrorClass::OutcomeInvalidRequest {
                govstack_problem(
                    "invalid-content",
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &request_id,
                )
            } else {
                route_problem(profile, &failure, &record_type, &request_id)
            };
            warn_exchange_failed(failure.class, response.status());
            (response, Some(TerminalOutcome::Failed))
        }
        Finished::Accepted(_) => unreachable!("acceptance returned after its atomic commit"),
        Finished::Replay { response, failed } => {
            let response = if govstack_write && failed {
                match replay_govstack_failed_response(response) {
                    Ok(response) => response,
                    Err(()) => {
                        tracing::error!(
                            "custodied GovStack failure has no canonical Problem identity"
                        );
                        govstack_problem(
                            "internal-error",
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &request_id,
                        )
                    }
                }
            } else {
                replay_response(response)
            };
            (response, None)
        }
        Finished::FacadeProblem(class, status) => {
            warn_exchange_failed(class, status);
            (
                facade_problem(profile, class, status, &record_type, &request_id),
                Some(TerminalOutcome::Failed),
            )
        }
    };
    if govstack_write && matches!(write_resolution, WriteResolution::Mismatch) {
        response = govstack_problem(
            "idempotency-fingerprint-mismatch",
            StatusCode::UNPROCESSABLE_ENTITY,
            &request_id,
        );
    } else if govstack_write
        && matches!(
            write_resolution,
            WriteResolution::InFlight | WriteResolution::ResumePending
        )
    {
        response = govstack_problem("idempotency-in-flight", StatusCode::CONFLICT, &request_id);
    } else if govstack_write
        && response.status() == StatusCode::CONFLICT
        && response
            .extensions()
            .get::<ReplayedResponseRequestId>()
            .is_none()
    {
        response = govstack_problem("conflict", StatusCode::CONFLICT, &request_id);
    }
    if terminal == Some(TerminalOutcome::Completed) {
        if success_bodyless {
            response = no_store(StatusCode::NO_CONTENT.into_response());
        }
        if let Some(etag) = success_etag {
            response.headers_mut().insert(
                header::ETAG,
                HeaderValue::from_str(&etag).expect("validated strong validator"),
            );
        }
        if let Some(location) = success_location {
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_str(&location).expect("encoded record URI"),
            );
        }
    }
    if govstack_write {
        stamp_terminal_problem(&mut events, &response);
    }
    // Render the first attempt's effective trace before exact response custody.
    // Stored replays carry no mutable problem marker and keep their original body.
    if let Some(correlation) = correlation {
        response = correlation.finish(response);
    }
    if resume_host_validation_pending {
        terminal = None;
    }
    if retry_later {
        response = retryable_conflict(response);
    }
    let pending_write = (!resume_host_validation_pending
        && matches!(
            write_resolution,
            WriteResolution::Pending | WriteResolution::UnsupportedIncomplete
        ))
    .then_some(())
    .and(write_execution.as_ref());
    let (response, stored) = match pending_write {
        Some(_) => match prepare_write_response(response, &request_id).await {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::error!(%error, "the exact write response could not be prepared");
                events.retain(|(event, _)| {
                    !matches!(event.event_kind, "exchangeCompleted" | "exchangeFailed")
                });
                events.push((
                    journal_event(
                        "exchangeFailed",
                        Some(exchange_failure_detail(profile, ErrorClass::Facade)),
                    ),
                    SystemTime::now(),
                ));
                terminal = Some(TerminalOutcome::Failed);
                response = if govstack_write {
                    govstack_problem(
                        "internal-error",
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &request_id,
                    )
                } else {
                    bounded_internal_problem(&request_id)
                };
                stamp_terminal_problem(&mut events, &response);
                if govstack_write {
                    if let Some(correlation) = correlation {
                        response = correlation.finish(response);
                    }
                }
                prepare_write_response(response, &request_id)
                    .await
                    .expect("the fixed internal problem fits response custody")
            }
        },
        None => (response, None),
    };
    let pending_terminal = pending_write.zip(terminal);
    let committed = match (pending_terminal, stored) {
        (Some((context, terminal)), Some(stored)) => {
            append_all_with_write(&state.journal, events, context, terminal, stored).await
        }
        _ => append_all(&state.journal, events).await,
    };
    if let Err(fault) = committed {
        tracing::error!(%fault, "the audit journal and response custody could not commit");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &record_type,
            &request_id,
        );
    }
    if govstack_write {
        with_write_replay_window(state, response)
    } else {
        response
    }
}

fn with_replay_window_seconds(mut response: Response, seconds: u64) -> Response {
    response.headers_mut().insert(
        "x-registry-idempotency-replay-window-seconds",
        HeaderValue::from_str(&seconds.to_string()).expect("bounded decimal replay window"),
    );
    response
}

fn with_write_replay_window(state: &FacadeState, response: Response) -> Response {
    if state.loaded.project.write.is_some() && state.idempotency.is_some() {
        if let Some(policy) = state.loaded.runtime.idempotency.as_ref() {
            return with_replay_window_seconds(response, policy.response_retention_seconds.get());
        }
    }
    response
}

/// Log a failed exchange: the class and the status the caller got, nothing
/// else. The journal holds the exchange; the log tells an operator one failed.
fn warn_exchange_failed(class: ErrorClass, status: StatusCode) {
    tracing::warn!(
        class = class.class(),
        status = status.as_u16(),
        "an exchange failed"
    );
}

/// The terminal failure facts the journal may retain. The selected problem
/// code is the profile's exact closest match for the class, never one inferred
/// from an HTTP status. Both fields are closed metadata and carry no values
/// from the request, source, or response.
fn exchange_failure_detail(profile: Problems<'_>, class: ErrorClass) -> Value {
    let mut detail = json!({ "class": class.class() });
    if let Some(problem) = resolve_problem(profile.profile, class) {
        detail["problemCode"] = Value::String(problem.code.as_str().to_owned());
    }
    detail
}

/// Seconds a caller waits before retrying a 409 that can still succeed: a
/// duplicate of a write in flight, resumable progress, or an uncertain effect
/// a later safe check may prove. A spent key's 409 carries no `Retry-After`,
/// so its absence tells the caller to stop retrying that key.
const RETRYABLE_CONFLICT_RETRY_AFTER: HeaderValue = HeaderValue::from_static("5");

fn retryable_conflict(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, RETRYABLE_CONFLICT_RETRY_AFTER);
    response
}

/// How an exchange ended once the response was built, before the journal
/// commits it.
enum Finished {
    Body(Value),
    Accepted(String),
    Internal,
    Route(RouteFailure),
    Replay {
        response: StoredResponse,
        failed: bool,
    },
    FacadeProblem(ErrorClass, StatusCode),
}

/// Append `events` in one transaction, each stamped with its own instant.
/// The error is a fixed account of the fault (the SQLSTATE where the driver
/// reports one), never the driver's text, which can repeat server detail.
async fn append_all(pool: &Pool, events: Vec<(JournalEvent, SystemTime)>) -> Result<(), String> {
    let mut client = pool
        .get()
        .await
        .map_err(|_| "the journal connection pool gave no connection".to_owned())?;
    let transaction = client
        .transaction()
        .await
        .map_err(|error| journal_fault(&error))?;
    for (event, occurred_at) in events {
        journal::append(&transaction, event, occurred_at)
            .await
            .map_err(|error| match error {
                journal::JournalError::Query(error) => journal_fault(&error),
                _ => "the journal write failed".to_owned(),
            })?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| journal_fault(&error))
}

/// Commit the exact terminal response and the route's terminal journal rows
/// on one PostgreSQL transaction. Neither table can claim a terminal outcome
/// while the other remains non-terminal.
async fn append_all_with_write(
    pool: &Pool,
    events: Vec<(JournalEvent, SystemTime)>,
    context: &WriteExecutionContext,
    outcome: TerminalOutcome,
    response: StoredResponse,
) -> Result<(), String> {
    let mut client = pool
        .get()
        .await
        .map_err(|_| "the journal connection pool gave no connection".to_owned())?;
    let transaction = client
        .transaction()
        .await
        .map_err(|error| journal_fault(&error))?;
    context
        .finish_with_client(&transaction, outcome, response)
        .await
        .map_err(|error| error.to_string())?;
    for (event, occurred_at) in events {
        journal::append(&transaction, event, occurred_at)
            .await
            .map_err(|error| match error {
                journal::JournalError::Query(error) => journal_fault(&error),
                _ => "the journal write failed".to_owned(),
            })?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| journal_fault(&error))
}

/// Render and atomically commit one profile-owned 202 with the route events
/// that preceded it and the value-free `exchangeAccepted` event.
#[allow(clippy::too_many_arguments)]
async fn append_all_with_acceptance(
    pool: &Pool,
    events: Vec<(JournalEvent, SystemTime)>,
    mut acceptance_event: JournalEvent,
    context: &WriteExecutionContext,
    operation: &ServedOperation,
    profile_contract: &ProfileAsyncCompletion,
    parameterized_parts: &BTreeMap<registry_platform_yaml::ExternalId, String>,
    source_id: &str,
    request_id: &str,
    retention: Duration,
    mode: &'static str,
) -> Result<CommittedAcceptance, String> {
    let mut client = pool
        .get()
        .await
        .map_err(|_| "the journal connection pool gave no connection".to_owned())?;
    let transaction = client
        .transaction()
        .await
        .map_err(|error| journal_fault(&error))?;
    let accepted_at = SystemTime::now();
    let expires_at = accepted_at
        .checked_add(retention)
        .ok_or_else(|| "adapter.async-expiry: retention instant is invalid".to_owned())?;
    let expires_text = OffsetDateTime::from(expires_at)
        .format(&Rfc3339)
        .map_err(|_| "adapter.async-expiry: timestamp could not be formatted".to_owned())?;
    let declared = operation
        .async_completion
        .as_ref()
        .ok_or_else(|| "adapter.async-acceptance: compiled contract is absent".to_owned())?;
    let status_link = profile_contract
        .status_path
        .as_str()
        .replace("{statusId}", request_id);
    let mut slots = BTreeMap::new();
    slots.insert("statusLink", Value::String(status_link));
    slots.insert("statusExpiresAt", Value::String(expires_text.clone()));
    slots.insert("requestId", Value::String(request_id.to_owned()));
    let envelope = CompiledEnvelope::compile(
        profile_contract.accepted_envelope.text(),
        parameterized_parts,
    )?;
    let body = envelope.render(&slots)?;
    let response = json_response(StatusCode::ACCEPTED, &body);
    let (response, stored) = prepare_write_response(response, request_id).await?;
    let stored = stored.ok_or_else(|| "adapter.async-acceptance: custody is absent".to_owned())?;
    context
        .accept_with_client(&transaction, source_id, stored.clone(), accepted_at)
        .await
        .map_err(|error| error.to_string())?;
    acceptance_event.detail = Some(
        json!({
            "mode": mode,
            "profileOperation": operation.operation,
            "statusRoute": declared.status.route_id,
            "recoveryExpiry": expires_text,
        })
        .to_string(),
    );
    for (event, occurred_at) in events.into_iter().chain([(acceptance_event, accepted_at)]) {
        journal::append(&transaction, event, occurred_at)
            .await
            .map_err(|error| match error {
                journal::JournalError::Query(error) => journal_fault(&error),
                _ => "the journal write failed".to_owned(),
            })?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| journal_fault(&error))?;
    Ok(CommittedAcceptance {
        response,
        stored,
        accepted_at,
        expires_at,
    })
}

struct CommittedAcceptance {
    response: Response,
    stored: StoredResponse,
    accepted_at: SystemTime,
    expires_at: SystemTime,
}

async fn run_bounded_wait(
    state: &FacadeState,
    operation: &ServedOperation,
    caller: &Caller,
    committed: CommittedAcceptance,
    wait_timeout: Duration,
    poll_interval: Duration,
    maximum_polls: u64,
) -> Response {
    let profile = state.loaded.problems();
    let request_id = committed.stored.request_id().to_owned();
    let caller_identity = match VerifiedCallerIdentity::new(
        caller.issuer.clone(),
        caller.reference.clone(),
        caller.client_id.clone(),
    ) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::error!(%error, "the bounded wait caller could not enter status custody");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &operation.record_type,
                &request_id,
            );
        }
    };
    let Some(store) = state.idempotency.as_ref() else {
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &operation.record_type,
            &request_id,
        );
    };
    let deadline_wall = committed
        .accepted_at
        .checked_add(wait_timeout)
        .map(|deadline| deadline.min(committed.expires_at));
    let Some(deadline_wall) = deadline_wall else {
        return committed.response;
    };
    let deadline_clock = tokio::time::Instant::now();
    let now_wall = SystemTime::now();
    let Ok(remaining) = deadline_wall.duration_since(now_wall) else {
        return committed.response;
    };
    let absolute_deadline = deadline_clock + remaining;
    let lookup = match store
        .lookup_status(
            StatusLookupRequest {
                caller: &caller_identity,
                deployment: state.loaded.runtime.id.as_str(),
                artifact_digest: state.artifact_digest,
                status_id: &request_id,
            },
            now_wall,
        )
        .await
    {
        Ok(StatusLookup::Accepted(pending)) => pending,
        Ok(StatusLookup::Terminal { response, .. }) => return replay_response(response),
        Ok(StatusLookup::NotFound) => {
            tracing::error!("fresh asynchronous acceptance was absent from status custody");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &operation.record_type,
                &request_id,
            );
        }
        Err(error) => {
            tracing::error!(%error, "bounded-wait status custody failed");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &operation.record_type,
                &request_id,
            );
        }
    };
    let Some(semaphore) = state.async_recovery.get(&operation.binding) else {
        tracing::error!("asynchronous binding has no recovery admission pool");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &operation.record_type,
            &request_id,
        );
    };
    let Ok(_permit) = Arc::clone(semaphore).try_acquire_owned() else {
        return replay_response(committed.stored);
    };
    let recovery = match store
        .acquire_status_recovery(&lookup, now_wall, deadline_wall)
        .await
    {
        Ok(RecoveryLease::Acquired(recovery)) => recovery,
        Ok(RecoveryLease::Busy | RecoveryLease::Stale) => {
            return replay_response(committed.stored);
        }
        Err(error) => {
            tracing::error!(%error, "the bounded-wait recovery lease failed");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &operation.record_type,
                &request_id,
            );
        }
    };
    let Some(source_id) = recovery.source_id() else {
        tracing::error!("accepted asynchronous custody has no source id");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &operation.record_type,
            &request_id,
        );
    };
    let source_id = source_id.to_owned();
    let event = |kind: &'static str, detail: Option<Value>, at: SystemTime| {
        (
            JournalEvent {
                event_kind: kind,
                exchange_id: request_id.clone(),
                operation: operation.operation.clone(),
                caller_ref: caller.reference.clone(),
                route_id: operation
                    .async_completion
                    .as_ref()
                    .expect("asynchronous operation")
                    .status
                    .route_id
                    .clone(),
                detail: detail.map(|value| value.to_string()),
            },
            at,
        )
    };
    let context = RouteContext {
        endpoints: &state.loaded.endpoints,
        scripts: &state.loaded.scripts,
        resolver: &state.loaded.resolver,
        resilience: &operation.resilience,
        routes: &state.loaded.routes,
        code_maps: state.loaded.code_maps.clone(),
        maximum_upstream_calls: operation.maximum_upstream_calls,
        job: crate::engine::job_sources::JobPageState::default(),
    };
    let mut recovery = Some(recovery);
    for poll_ordinal in 1..=maximum_polls {
        if tokio::time::Instant::now() >= absolute_deadline {
            break;
        }
        let poll_started = tokio::time::Instant::now();
        let polled = run_async_status_poll(
            &context,
            &state.loaded.profile,
            operation,
            AsyncStatusPollKind::Primary,
            &source_id,
            &request_id,
            absolute_deadline,
        )
        .await;
        let mut events = Vec::new();
        for route_event in polled.events {
            events.push(event(
                route_event.kind,
                Some(route_event.detail),
                route_event.at,
            ));
        }
        let duration = u64::try_from(poll_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match polled.result {
            Ok(AsyncStatusOutcome::Pending {}) => {
                events.push(event(
                    "recoveryChecked",
                    Some(json!({
                        "result": "pending",
                        "pollOrdinal": poll_ordinal,
                        "durationMilliseconds": duration
                    })),
                    SystemTime::now(),
                ));
                if poll_ordinal == maximum_polls {
                    return finish_nonterminal_poll(
                        state,
                        store,
                        recovery.take().expect("the recovery lease is live"),
                        events,
                        committed.stored,
                        &operation.record_type,
                        &request_id,
                    )
                    .await;
                }
                if let Err(fault) = append_all(&state.journal, events).await {
                    tracing::error!(%fault, "the bounded-wait journal could not commit");
                    return facade_problem(
                        profile,
                        ErrorClass::Facade,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &operation.record_type,
                        &request_id,
                    );
                }
            }
            Err(failure) => {
                events.push(event(
                    "recoveryCheckFailed",
                    Some(json!({"class": failure.class.class(), "certainty": "uncertain"})),
                    SystemTime::now(),
                ));
                return finish_nonterminal_poll(
                    state,
                    store,
                    recovery.take().expect("the recovery lease is live"),
                    events,
                    committed.stored,
                    &operation.record_type,
                    &request_id,
                )
                .await;
            }
            Ok(outcome) => {
                let terminal = render_recovery_terminal(
                    state,
                    operation,
                    outcome,
                    &operation.record_type,
                    recovery
                        .as_ref()
                        .expect("the recovery lease is live")
                        .response_request_id(),
                );
                let (response, outcome, result) = match terminal {
                    Ok(terminal) => terminal,
                    Err(class) => {
                        events.push(event(
                            "recoveryCheckFailed",
                            Some(json!({"class": class.class(), "certainty": "uncertain"})),
                            SystemTime::now(),
                        ));
                        return finish_nonterminal_poll(
                            state,
                            store,
                            recovery.take().expect("the recovery lease is live"),
                            events,
                            committed.stored,
                            &operation.record_type,
                            &request_id,
                        )
                        .await;
                    }
                };
                events.push(event(
                    "recoveryChecked",
                    Some(json!({
                        "result": result,
                        "pollOrdinal": poll_ordinal,
                        "durationMilliseconds": duration
                    })),
                    SystemTime::now(),
                ));
                events.push(event(
                    match outcome {
                        TerminalOutcome::Completed => "exchangeCompleted",
                        TerminalOutcome::Failed => "exchangeFailed",
                    },
                    None,
                    SystemTime::now(),
                ));
                return match append_all_with_recovery(
                    &state.journal,
                    store,
                    recovery.take().expect("the recovery lease is live"),
                    outcome,
                    response,
                    events,
                )
                .await
                {
                    Ok(response) => response,
                    Err(fault) => {
                        tracing::error!(%fault, "bounded-wait terminal custody could not commit");
                        facade_problem(
                            profile,
                            ErrorClass::Facade,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &operation.record_type,
                            &request_id,
                        )
                    }
                };
            }
        }
        let wake = tokio::time::Instant::now() + poll_interval;
        if wake >= absolute_deadline {
            break;
        }
        tokio::time::sleep_until(wake).await;
    }
    let recovery = recovery.expect("the recovery lease is live");
    if let Err(error) = store.release_recovery(recovery).await {
        tracing::error!(%error, "the bounded-wait recovery lease could not be released");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &operation.record_type,
            &request_id,
        );
    }
    replay_response(committed.stored)
}

struct UncertaintyRecoveryRequest<'a> {
    operation: &'a ServedOperation,
    caller: &'a Caller,
    write: &'a Arc<WriteExecutionContext>,
    events: Vec<(JournalEvent, SystemTime)>,
    physical_request_id: &'a str,
    absolute_deadline: tokio::time::Instant,
    deadline_wall: SystemTime,
}

async fn run_uncertainty_recovery(
    state: &FacadeState,
    request: UncertaintyRecoveryRequest<'_>,
) -> Response {
    let UncertaintyRecoveryRequest {
        operation,
        caller,
        write,
        mut events,
        physical_request_id,
        absolute_deadline,
        deadline_wall,
    } = request;
    let profile = state.loaded.problems();
    let Some(store) = state.idempotency.as_ref() else {
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &operation.record_type,
            physical_request_id,
        );
    };
    let Some(semaphore) = state.async_recovery.get(&operation.binding) else {
        tracing::error!("asynchronous binding has no recovery admission pool");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &operation.record_type,
            physical_request_id,
        );
    };
    let recovery_event = |kind: &'static str, detail: Option<Value>, at: SystemTime| {
        (
            JournalEvent {
                event_kind: kind,
                exchange_id: physical_request_id.to_owned(),
                operation: operation.operation.clone(),
                caller_ref: caller.reference.clone(),
                route_id: operation
                    .async_completion
                    .as_ref()
                    .and_then(|completion| completion.uncertainty.as_ref())
                    .expect("recoverable uncertainty has a compiled route")
                    .status
                    .route_id
                    .clone(),
                detail: detail.map(|value| value.to_string()),
            },
            at,
        )
    };
    let conflict = |mut events: Vec<(JournalEvent, SystemTime)>| {
        events.push((
            JournalEvent {
                event_kind: "exchangeFailed",
                exchange_id: physical_request_id.to_owned(),
                operation: operation.operation.clone(),
                caller_ref: caller.reference.clone(),
                route_id: operation.route_id.clone(),
                detail: Some(
                    exchange_failure_detail(profile, ErrorClass::FacadeConflict).to_string(),
                ),
            },
            SystemTime::now(),
        ));
        events
    };
    let Ok(_permit) = Arc::clone(semaphore).try_acquire_owned() else {
        if let Err(fault) = append_all(&state.journal, conflict(events)).await {
            tracing::error!(%fault, "the uncertain-effect journal could not commit");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &operation.record_type,
                physical_request_id,
            );
        }
        return retryable_conflict(facade_problem(
            profile,
            ErrorClass::FacadeConflict,
            StatusCode::CONFLICT,
            &operation.record_type,
            physical_request_id,
        ));
    };
    let recovery = match write
        .acquire_uncertain_recovery(SystemTime::now(), deadline_wall)
        .await
    {
        Ok(RecoveryLease::Acquired(recovery)) => recovery,
        Ok(lease @ (RecoveryLease::Busy | RecoveryLease::Stale)) => {
            if let Err(fault) = append_all(&state.journal, conflict(events)).await {
                tracing::error!(%fault, "the uncertain-effect journal could not commit");
                return facade_problem(
                    profile,
                    ErrorClass::Facade,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &operation.record_type,
                    physical_request_id,
                );
            }
            let problem = facade_problem(
                profile,
                ErrorClass::FacadeConflict,
                StatusCode::CONFLICT,
                &operation.record_type,
                physical_request_id,
            );
            // Another checker holds the lease and may still prove the outcome;
            // an expired or uncorrelated effect is spent.
            return match lease {
                RecoveryLease::Busy => retryable_conflict(problem),
                _ => problem,
            };
        }
        Err(error) => {
            tracing::error!(%error, "the uncertainty recovery lease failed");
            return facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &operation.record_type,
                physical_request_id,
            );
        }
    };
    let Some(recovery_id) = recovery.recovery_id().map(str::to_owned) else {
        tracing::error!("uncertain effect custody has no source correlation");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &operation.record_type,
            physical_request_id,
        );
    };
    let context = RouteContext {
        endpoints: &state.loaded.endpoints,
        scripts: &state.loaded.scripts,
        resolver: &state.loaded.resolver,
        resilience: &operation.resilience,
        routes: &state.loaded.routes,
        code_maps: state.loaded.code_maps.clone(),
        maximum_upstream_calls: operation.maximum_upstream_calls,
        job: crate::engine::job_sources::JobPageState::default(),
    };
    let poll_started = tokio::time::Instant::now();
    let polled = run_async_status_poll(
        &context,
        &state.loaded.profile,
        operation,
        AsyncStatusPollKind::UncertaintyRecovery,
        &recovery_id,
        physical_request_id,
        absolute_deadline,
    )
    .await;
    for route_event in polled.events {
        events.push(recovery_event(
            route_event.kind,
            Some(route_event.detail),
            route_event.at,
        ));
    }
    let duration = u64::try_from(poll_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match polled.result {
        Ok(AsyncStatusOutcome::Pending {}) => {
            events.push(recovery_event(
                "recoveryChecked",
                Some(json!({
                    "result": "pending",
                    "pollOrdinal": 1,
                    "durationMilliseconds": duration
                })),
                SystemTime::now(),
            ));
        }
        Err(failure) => {
            events.push(recovery_event(
                "recoveryCheckFailed",
                Some(json!({"class": failure.class.class(), "certainty": "uncertain"})),
                SystemTime::now(),
            ));
        }
        Ok(outcome) => {
            let terminal = render_recovery_terminal(
                state,
                operation,
                outcome,
                &operation.record_type,
                recovery.response_request_id(),
            );
            if let Ok((response, outcome, result)) = terminal {
                events.push(recovery_event(
                    "recoveryChecked",
                    Some(json!({
                        "result": result,
                        "pollOrdinal": 1,
                        "durationMilliseconds": duration
                    })),
                    SystemTime::now(),
                ));
                events.push(recovery_event(
                    match outcome {
                        TerminalOutcome::Completed => "exchangeCompleted",
                        TerminalOutcome::Failed => "exchangeFailed",
                    },
                    None,
                    SystemTime::now(),
                ));
                return match append_all_with_recovery(
                    &state.journal,
                    store,
                    recovery,
                    outcome,
                    response,
                    events,
                )
                .await
                {
                    Ok(response) => response,
                    Err(fault) => {
                        tracing::error!(%fault, "uncertainty terminal custody could not commit");
                        facade_problem(
                            profile,
                            ErrorClass::Facade,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &operation.record_type,
                            physical_request_id,
                        )
                    }
                };
            }
            events.push(recovery_event(
                "recoveryCheckFailed",
                Some(json!({
                    "class": ErrorClass::DisclosureViolation.class(),
                    "certainty": "uncertain"
                })),
                SystemTime::now(),
            ));
        }
    }
    if let Err(fault) = append_all(&state.journal, conflict(events)).await {
        tracing::error!(%fault, "the uncertain-effect journal could not commit");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &operation.record_type,
            physical_request_id,
        );
    }
    if let Err(error) = store.release_recovery(recovery).await {
        tracing::error!(%error, "the uncertainty recovery lease could not be released");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &operation.record_type,
            physical_request_id,
        );
    }
    retryable_conflict(facade_problem(
        profile,
        ErrorClass::FacadeConflict,
        StatusCode::CONFLICT,
        &operation.record_type,
        physical_request_id,
    ))
}

async fn finish_nonterminal_poll(
    state: &FacadeState,
    store: &PostgresIdempotencyStore,
    recovery: Box<crate::idempotent::RecoveryExecution>,
    events: Vec<(JournalEvent, SystemTime)>,
    accepted_response: StoredResponse,
    record_type: &str,
    physical_request_id: &str,
) -> Response {
    if let Err(fault) = append_all(&state.journal, events).await {
        tracing::error!(%fault, "the asynchronous status journal could not commit");
        return facade_problem(
            state.loaded.problems(),
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            record_type,
            physical_request_id,
        );
    }
    if let Err(error) = store.release_recovery(recovery).await {
        tracing::error!(%error, "the asynchronous status lease could not be released");
        return facade_problem(
            state.loaded.problems(),
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            record_type,
            physical_request_id,
        );
    }
    replay_response(accepted_response)
}

async fn append_all_with_recovery(
    pool: &Pool,
    store: &PostgresIdempotencyStore,
    recovery: Box<crate::idempotent::RecoveryExecution>,
    outcome: TerminalOutcome,
    response: Response,
    events: Vec<(JournalEvent, SystemTime)>,
) -> Result<Response, String> {
    let response_request_id = recovery.response_request_id().to_owned();
    let (mut response, stored) = prepare_write_response(response, &response_request_id).await?;
    let stored = stored.ok_or_else(|| "adapter.async-recovery: custody is absent".to_owned())?;
    let mut client = pool
        .get()
        .await
        .map_err(|_| "the journal connection pool gave no connection".to_owned())?;
    let transaction = client
        .transaction()
        .await
        .map_err(|error| journal_fault(&error))?;
    store
        .finish_recovery_with_client(&transaction, recovery, outcome, stored, SystemTime::now())
        .await
        .map_err(|error| error.to_string())?;
    for (event, occurred_at) in events {
        journal::append(&transaction, event, occurred_at)
            .await
            .map_err(|error| match error {
                journal::JournalError::Query(error) => journal_fault(&error),
                _ => "the journal write failed".to_owned(),
            })?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| journal_fault(&error))?;
    response
        .extensions_mut()
        .insert(ReplayedResponseRequestId(response_request_id));
    Ok(response)
}

fn journal_fault(error: &tokio_postgres::Error) -> String {
    match error.code() {
        Some(code) => format!("the journal write failed with SQLSTATE {}", code.code()),
        None => "the journal write failed without a SQLSTATE".to_owned(),
    }
}

async fn authenticate(state: &FacadeState, headers: &HeaderMap) -> Result<Caller, CallerRefusal> {
    let Some(token) = bearer_token(headers) else {
        state.authenticator.log_header_refusal();
        return Err(CallerRefusal::Unauthenticated);
    };
    state.authenticator.authenticate(token).await
}

/// The bearer credential of the `Authorization` header, if it carries one.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// Whether some access profile the caller's scopes satisfy admits the
/// operation on the record type. A profile that names no scope admits
/// nobody: an empty requirement is not a satisfied one.
fn admits(project: &AdapterProject, caller: &Caller, operation: &ServedOperation) -> bool {
    project.access_profiles.iter().any(|profile| {
        !profile.scopes.is_empty()
            && profile
                .scopes
                .iter()
                .all(|scope| caller.scopes.iter().any(|held| held == scope.as_str()))
            && profile
                .operations
                .iter()
                .any(|id| id.as_str() == operation.operation)
            && profile
                .record_types
                .iter()
                .any(|name| name.as_str() == operation.record_type)
    })
}

fn admits_stored(
    project: &AdapterProject,
    caller: &Caller,
    profile_operation: &str,
    record_type: &str,
) -> bool {
    project.access_profiles.iter().any(|profile| {
        !profile.scopes.is_empty()
            && profile
                .scopes
                .iter()
                .all(|scope| caller.scopes.iter().any(|held| held == scope.as_str()))
            && profile
                .operations
                .iter()
                .any(|id| id.as_str() == profile_operation)
            && profile
                .record_types
                .iter()
                .any(|name| name.as_str() == record_type)
    })
}

fn refusal_response(profile: Problems<'_>, refusal: CallerRefusal, request_id: &str) -> Response {
    let (class, status) = match refusal {
        CallerRefusal::Unauthenticated => {
            (ErrorClass::FacadeUnauthenticated, StatusCode::UNAUTHORIZED)
        }
        CallerRefusal::Unavailable if profile.profile.is_govstack_consultation() => {
            return consultation_unavailable(request_id);
        }
        CallerRefusal::Unavailable => (ErrorClass::Facade, StatusCode::SERVICE_UNAVAILABLE),
    };
    let mut response = facade_problem(profile, class, status, "", request_id);
    if status == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

/// The members of a record a route may wrap its domain fields in, beside the
/// source's identifiers.
const RECORD_WRAPPER_MEMBERS: [&str; 3] = ["recordIdentifier", "revisionIdentifier", "domainData"];

/// A record as the facade serves it, checked against the closed schema of
/// the bound record type. A route may end with a record that wraps its domain
/// fields under `domainData` beside the source's identifiers (exactly those
/// three members, `domainData` required); the facade's record is then the
/// domain fields. Any other body is the record itself. A record carrying a
/// field the record type does not declare, missing a declared one or typed
/// differently is a disclosure violation, never served. The error is the
/// count of violations: key names stay out of every log and journal.
#[cfg(test)]
fn disclosed_record(body: &Value, schema: &Value) -> Result<Value, usize> {
    disclosed_parts(body, schema).map(|(record, _)| record)
}

/// [`disclosed_record`] and the source's record identifier, when the route's
/// record was wrapped beside one. The body is checked as raw declared domain
/// data first, so a declared domain field named `recordIdentifier` keeps its
/// ordinary meaning. Only a body that fails that schema may be interpreted as
/// the normalized route wrapper. An identifier that is not a string is a
/// disclosure violation.
fn disclosed_parts(body: &Value, schema: &Value) -> Result<(Value, Option<String>), usize> {
    let direct_violations = registry_adapter_core::validate_result_schema(body, schema);
    if direct_violations.is_empty() {
        return Ok((body.clone(), None));
    }
    let (record, identifier) = match body {
        Value::Object(map) if map.contains_key("recordIdentifier") => {
            let wrapper_shaped = map.len() <= RECORD_WRAPPER_MEMBERS.len()
                && map
                    .keys()
                    .all(|key| RECORD_WRAPPER_MEMBERS.contains(&key.as_str()));
            match (map.get("domainData"), map.get("recordIdentifier")) {
                (Some(domain), Some(Value::String(id))) if wrapper_shaped => {
                    (domain, Some(id.clone()))
                }
                _ => return Err(1),
            }
        }
        _ => return Err(direct_violations.len()),
    };
    let violations = registry_adapter_core::validate_result_schema(record, schema);
    if violations.is_empty() {
        Ok((record.clone(), identifier))
    } else {
        Err(violations.len())
    }
}

/// A project transformation always reaches the facade in the engine's known
/// normalized wrapper. Its checked JSON Schema governs `domainData`; it must
/// never be applied to the wrapper itself, and the generic profile heuristic
/// must not decide whether the wrapper is raw caller-visible data.
fn schema_bound_disclosed_parts(
    body: &Value,
    schema: &crate::engine::public_schema::CheckedPublicSchema,
) -> Result<(Value, Option<String>), usize> {
    let Value::Object(map) = body else {
        return Err(1);
    };
    let wrapper_shaped = map.len() <= RECORD_WRAPPER_MEMBERS.len()
        && map
            .keys()
            .all(|key| RECORD_WRAPPER_MEMBERS.contains(&key.as_str()))
        && map.get("revisionIdentifier").is_none_or(Value::is_string);
    let (Some(domain), Some(Value::String(identifier))) =
        (map.get("domainData"), map.get("recordIdentifier"))
    else {
        return Err(1);
    };
    if !wrapper_shaped || !schema.validates(domain) {
        return Err(1);
    }
    Ok((domain.clone(), Some(identifier.clone())))
}

/// One record as the response envelope receives it: the disclosed record
/// itself, or, when the operation declares an item envelope, that template
/// filled for the record. A template that names `recordId` over a record the
/// route returned without an identifier is a disclosure violation.
fn disclosed_item(
    operation: &ServedOperation,
    body: &Value,
    record_type: &str,
    request_id: &str,
) -> Result<Value, usize> {
    let (record, identifier) = match &operation.project_transform {
        Some(transform) => schema_bound_disclosed_parts(body, transform.schema())?,
        None => disclosed_parts(body, &operation.record_schema)?,
    };
    let Some(item) = &operation.item_envelope else {
        return Ok(record);
    };
    let mut slots: BTreeMap<&str, Value> = BTreeMap::new();
    slots.insert("record", record);
    slots.insert("recordType", Value::String(record_type.to_owned()));
    slots.insert("requestId", Value::String(request_id.to_owned()));
    match identifier {
        Some(id) => {
            slots.insert("recordId", Value::String(id));
        }
        None if item.names_record_id => return Err(1),
        None => {}
    }
    item.envelope.render(&slots).map_err(|_| 1)
}

/// The slots the response envelope is filled from: one record, or every
/// record of a page, each checked by [`disclosed_record`]. A page larger
/// than the size the caller asked for is a disclosure violation: the
/// caller never receives more records than it requested.
pub(crate) fn disclosed_slots(
    operation: &ServedOperation,
    body: &Value,
    page_size: Option<u64>,
    record_type: &str,
    request_id: &str,
) -> Result<BTreeMap<&'static str, Value>, usize> {
    let mut slots = BTreeMap::new();
    if operation.pagination.is_some() {
        let Value::Array(records) = body else {
            return Err(1);
        };
        if page_size.is_some_and(|size| records.len() as u64 > size) {
            return Err(records.len());
        }
        let disclosed = records
            .iter()
            .map(|record| disclosed_item(operation, record, record_type, request_id))
            .collect::<Result<Vec<_>, _>>()?;
        slots.insert("records", Value::Array(disclosed));
    } else {
        slots.insert(
            "record",
            disclosed_item(operation, body, record_type, request_id)?,
        );
    }
    Ok(slots)
}

fn render_recovery_terminal(
    state: &FacadeState,
    operation: &ServedOperation,
    outcome: AsyncStatusOutcome,
    record_type: &str,
    response_request_id: &str,
) -> Result<(Response, TerminalOutcome, &'static str), ErrorClass> {
    match outcome {
        AsyncStatusOutcome::Succeeded { result } => {
            let slots = disclosed_slots(operation, &result, None, record_type, response_request_id)
                .map_err(|_| ErrorClass::DisclosureViolation)?;
            let body = render_success(operation, slots, None, record_type, response_request_id)
                .map_err(|_| ErrorClass::Facade)?;
            let status = state
                .loaded
                .profile
                .operations
                .get(operation.operation.as_str())
                .and_then(|declared| declared.async_completion.as_ref())
                .and_then(|completion| {
                    StatusCode::from_u16(completion.completed_status.get() as u16).ok()
                })
                .ok_or(ErrorClass::Facade)?;
            Ok((
                json_response(status, &body),
                TerminalOutcome::Completed,
                "succeeded",
            ))
        }
        AsyncStatusOutcome::Failed { class, data } => {
            let data = data
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| ErrorClass::DisclosureViolation)?;
            let failure = enforce_problem_data(
                &state.loaded.profile,
                RouteFailure {
                    class,
                    message: None,
                    data,
                    auth: None,
                    code: None,
                    record: None,
                    evidence_diagnostic: None,
                },
            );
            Ok((
                route_problem(
                    state.loaded.problems(),
                    &failure,
                    record_type,
                    response_request_id,
                ),
                TerminalOutcome::Failed,
                "failed",
            ))
        }
        AsyncStatusOutcome::Pending {} => Err(ErrorClass::Facade),
    }
}

/// Whether a caller-supplied identifier can stand as one path segment of the
/// source call: its percent-encoded form must pass the canonical-path rule
/// the outbound origin pin applies. An empty identifier is not one. The
/// length of the whole rendered link is bounded where the route renders it,
/// since the URL bound covers the link, not the identifier alone.
fn is_path_segment_value(record_id: &str) -> bool {
    encode_path_segment(record_id).is_some()
}

/// The inputs of one read as the caller supplied them, from the query
/// string of a GET or the body of a read over POST.
#[derive(Default)]
pub(crate) struct RequestInputs {
    pub(crate) cursor: Option<String>,
    pub(crate) page_size: Option<u64>,
    pub(crate) filters: serde_json::Map<String, Value>,
}

/// What a search request carries once validated.
struct SearchInputs {
    page_size: u64,
    continuation: Option<Value>,
    filters: serde_json::Map<String, Value>,
    binding: SearchBinding,
}

/// What the cursor the route's answer may be sealed under is bound to.
struct SearchBinding {
    filters: crate::engine::component::rest::continuation::FilterDigest,
}

/// Why a request was refused: the class and status the caller sees, and a
/// value-free reason for the journal. A fixed `detail` tells the caller how
/// to correct the request.
#[derive(Debug)]
pub(crate) struct Refusal {
    class: ErrorClass,
    status: StatusCode,
    reason: String,
    write_problem: Option<&'static str>,
    validation_pointer: Option<&'static str>,
    detail: Option<&'static str>,
}

trait LoadedProblems {
    #[must_use]
    fn problems(&self) -> Problems<'_>;
}

impl LoadedProblems for crate::engine::load::Loaded {
    /// The problems view the facade answers refusals from: the facade's
    /// own projection of the compiled authored state.
    fn problems(&self) -> Problems<'_> {
        Problems {
            profile: &self.profile,
            envelope: &self.problem_envelope,
        }
    }
}

impl Refusal {
    fn with_detail(self, detail: &'static str) -> Self {
        Self {
            detail: Some(detail),
            ..self
        }
    }

    fn invalid_field_at(reason: &str, pointer: &'static str) -> Self {
        Self {
            validation_pointer: Some(pointer),
            ..Self::invalid_field(reason)
        }
    }

    fn write(code: &'static str, status: StatusCode) -> Self {
        Self {
            class: ErrorClass::FacadeInvalidRequest,
            status,
            reason: code.to_owned(),
            write_problem: Some(code),
            validation_pointer: None,
            detail: None,
        }
    }

    fn invalid_request(reason: &str) -> Self {
        Self {
            class: ErrorClass::FacadeInvalidRequest,
            status: StatusCode::BAD_REQUEST,
            reason: reason.to_owned(),
            write_problem: None,
            validation_pointer: None,
            detail: None,
        }
    }

    fn invalid_field(reason: &str) -> Self {
        Self {
            class: ErrorClass::FacadeInvalidField,
            status: StatusCode::UNPROCESSABLE_ENTITY,
            reason: reason.to_owned(),
            write_problem: None,
            validation_pointer: None,
            detail: None,
        }
    }

    fn invalid_cursor(reason: &str) -> Self {
        Self {
            class: ErrorClass::FacadeInvalidCursor,
            status: StatusCode::BAD_REQUEST,
            reason: reason.to_owned(),
            write_problem: None,
            validation_pointer: None,
            detail: None,
        }
    }
}

/// Read the cursor, page size, and declared filters from a GET's query
/// string. Any other parameter, a repeated one, or a page size that is not
/// an integer is refused; a filter whose text is not of its declared type
/// is a field fault.
pub(crate) fn query_inputs(
    operation: &ServedOperation,
    query: Option<&str>,
) -> Result<RequestInputs, Refusal> {
    let pagination = operation.pagination.as_ref();
    let mut inputs = RequestInputs::default();
    let mut seen: Vec<String> = Vec::new();
    for (name, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        if seen.iter().any(|earlier| *earlier == name) {
            return Err(Refusal::invalid_request("a repeated query parameter"));
        }
        seen.push(name.clone().into_owned());
        if pagination.is_some_and(|declared| name == declared.cursor_parameter) {
            inputs.cursor = Some(value.into_owned());
        } else if pagination.is_some_and(|declared| name == declared.page_size_parameter) {
            inputs.page_size = Some(
                value
                    .parse::<u64>()
                    .map_err(|_| Refusal::invalid_request("the page size is not an integer"))?,
            );
        } else if let Some(filter) = operation.filters.iter().find(|filter| filter.name == name) {
            let parsed = parse_filter_text(&value, filter.field_type).ok_or_else(|| {
                Refusal::invalid_field("a filter value does not have its declared type")
            })?;
            inputs.filters.insert(filter.name.clone(), parsed);
        } else {
            return Err(Refusal::invalid_request("an undeclared query parameter"));
        }
    }
    Ok(inputs)
}

/// Every filter a binding declares is required caller input, independent of
/// pagination and of whether the read carries its inputs in a GET query or a
/// POST body. Missing declared input is an invalid field, refused before an
/// exchange or source call.
pub(crate) fn require_declared_filters(
    operation: &ServedOperation,
    inputs: &RequestInputs,
) -> Result<(), Refusal> {
    if operation
        .filters
        .iter()
        .any(|filter| !inputs.filters.contains_key(&filter.name))
    {
        return Err(Refusal::invalid_field("a declared filter is absent"));
    }
    Ok(())
}

/// Hold a Consultation Lookup or Search input object against its exact
/// project-owned schema after capture and before the exchange is journaled or
/// any source step can run. Filter derivation controls native mapping; it does
/// not replace full constraints such as lengths and string patterns.
pub(crate) fn validate_project_inputs(
    operation: &ServedOperation,
    inputs: &RequestInputs,
) -> Result<(), Refusal> {
    if operation
        .project_input_schema
        .as_ref()
        .is_some_and(|schema| !schema.validates(&Value::Object(inputs.filters.clone())))
    {
        return Err(Refusal::invalid_field(
            "the caller input does not satisfy its declared schema",
        ));
    }
    Ok(())
}

/// Validate a search's inputs against the operation's declared pagination
/// and restore the continuation its cursor carries. A cursor carries the
/// page size of the call that minted it: a call that names no size reuses
/// it, and one that names another is refused as an invalid cursor. A call
/// with neither a cursor nor a size takes the profile's default size, and
/// is refused when there is none.
fn open_search(
    state: &FacadeState,
    operation: &ServedOperation,
    pagination: &ServedPagination,
    caller: &Caller,
    record_type: &str,
    inputs: RequestInputs,
) -> Result<SearchInputs, Refusal> {
    // The digest leaves the page size out: the cursor carries it, so a
    // call may omit it, and a supplied size is compared to the carried one.
    let filters = filter_digest(
        &json!({"recordType": record_type, "filters": inputs.filters}),
        0,
    )
    .map_err(|error| Refusal::invalid_request(&error.to_string()))?;
    let codec = state
        .codec
        .as_ref()
        .ok_or_else(|| Refusal::invalid_request("the runtime has no cursor key"))?;
    let (continuation, carried_size) = match &inputs.cursor {
        Some(cursor) => {
            let binding = cursor_binding(state, operation, caller, filters);
            let sealed = codec
                .open(cursor, &binding, SystemTime::now())
                .map_err(|refusal: CursorRefusal| Refusal::invalid_cursor(refusal.reason()))?;
            let (size, continuation) =
                unwrap_continuation(sealed).ok_or_else(|| Refusal::invalid_cursor("malformed"))?;
            (Some(continuation), Some(size))
        }
        None => (None, None),
    };
    if let Some(supplied) = inputs.page_size {
        if !(pagination.page_size_minimum..=pagination.page_size_maximum).contains(&supplied) {
            return Err(Refusal::invalid_request(
                "the page size is outside the profile's bounds",
            ));
        }
    }
    let page_size = match (inputs.page_size, carried_size) {
        (Some(supplied), Some(carried)) if supplied != carried => {
            return Err(Refusal::invalid_cursor(
                "the page size differs from the cursor's",
            ));
        }
        (Some(size), _) | (None, Some(size)) => size,
        (None, None) => pagination.page_size_default.ok_or_else(|| {
            Refusal::invalid_request("the page size is absent and the profile declares no default")
        })?,
    };
    Ok(SearchInputs {
        page_size,
        continuation,
        filters: inputs.filters,
        binding: SearchBinding { filters },
    })
}

/// The members a sealed cursor value carries: the continuation the route
/// set and the page size of the call that minted it.
const CURSOR_CONTINUATION_MEMBER: &str = "c";
const CURSOR_PAGE_SIZE_MEMBER: &str = "s";

pub(crate) fn wrap_continuation(continuation: &Value, page_size: u64) -> Value {
    json!({CURSOR_CONTINUATION_MEMBER: continuation, CURSOR_PAGE_SIZE_MEMBER: page_size})
}

pub(crate) fn unwrap_continuation(sealed: Value) -> Option<(u64, Value)> {
    let Value::Object(mut members) = sealed else {
        return None;
    };
    let size = members.get(CURSOR_PAGE_SIZE_MEMBER)?.as_u64()?;
    let continuation = members.remove(CURSOR_CONTINUATION_MEMBER)?;
    Some((size, continuation))
}

/// Whether the `Accept` header admits a JSON reply: absent, or a range
/// covering `application/json` with a non-zero quality.
fn accepts_json(headers: &HeaderMap) -> bool {
    let values: Vec<&str> = headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    if values.is_empty() {
        return true;
    }
    values
        .iter()
        .flat_map(|value| value.split(','))
        .any(|range| {
            let mut parts = range.split(';');
            let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            let refused = parts.any(|parameter| {
                let parameter = parameter.trim().to_ascii_lowercase();
                parameter
                    .strip_prefix("q=")
                    .is_some_and(|quality| quality.trim().parse::<f64>().is_ok_and(|q| q <= 0.0))
            });
            !refused && matches!(media.as_str(), "*/*" | "application/*" | "application/json")
        })
}

fn has_content_type(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case(expected))
}

/// Read a request body of at most `limit` bytes. A declared length past
/// the bound, or a body that runs past it, is refused before it is held.
/// A body that fails to read for another reason has no reader left to
/// answer, so it is refused the same way.
async fn read_body(headers: &HeaderMap, body: Body, limit: usize) -> Result<axum::body::Bytes, ()> {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > limit) {
        return Err(());
    }
    axum::body::to_bytes(body, limit).await.map_err(|_| ())
}

pub(crate) fn capture_govstack_write(
    operation: &ServedOperation,
    body: &Value,
) -> Result<CapturedWriteRequest, Refusal> {
    let object = body
        .as_object()
        .ok_or_else(|| Refusal::invalid_request("the write input must be an object"))?;
    // SourceReference is optional in the standard, but needs source-owned
    // evidence validation. This source profile refuses it explicitly.
    if object.contains_key("source") {
        return Err(Refusal::invalid_field_at(
            "this source does not support source references",
            "/source",
        ));
    }
    if object.len() != 1 || !object.contains_key("data") {
        return Err(Refusal::invalid_request(
            "only the declared data member is writable",
        ));
    }
    let data = object["data"]
        .as_object()
        .ok_or_else(|| Refusal::invalid_request("the data member must be an object"))?;
    if operation.method == HttpMethod::Patch && data.is_empty() {
        return Err(Refusal::invalid_field(
            "an Update requires a nonempty domain merge patch",
        ));
    }
    let schema = operation
        .project_input_schema
        .as_ref()
        .ok_or_else(|| Refusal::invalid_request("the Write input schema is unavailable"))?;
    if !schema.validates(&object["data"]) {
        return Err(Refusal::invalid_field(
            "the domain input does not match its selected schema",
        ));
    }
    Ok(CapturedWriteRequest {
        record: object["data"].clone(),
        record_id: None,
    })
}

fn write_validator_context<'a>(
    state: &'a FacadeState,
    collection: &'a str,
    record: &'a str,
) -> Option<crate::govstack::write::ValidatorContext<'a>> {
    let metadata =
        crate::govstack::write::metadata::collection_metadata(&state.loaded.project, collection)
            .ok()?;
    Some(crate::govstack::write::ValidatorContext {
        registry: metadata.registry,
        collection,
        record,
        view: metadata.view.unwrap_or("write-receipt"),
        closure: crate::govstack::write::metadata::validator_closure(&state.loaded, collection)
            .ok()?,
    })
}

fn is_companion_read(state: &FacadeState, operation: &ServedOperation) -> bool {
    state
        .loaded
        .project
        .write
        .as_ref()
        .and_then(|write| write.collections.get(&operation.record_type))
        .and_then(|collection| collection.update.as_ref())
        .is_some_and(|update| update.companion_read.as_str() == operation.binding)
}

fn govstack_write_success(
    state: &FacadeState,
    operation: &ServedOperation,
    done: &Exchange,
    path_record: &str,
    deadline: std::time::Instant,
) -> Result<(Value, String, Option<String>), ()> {
    let metadata =
        crate::govstack::write::metadata::resolve_runtime_write(&state.loaded, operation)
            .map_err(|_| ())?;
    let result = done.final_source_result().ok_or(())?;
    if metadata.capability == crate::govstack::write::attachment::WriteCapability::Update
        && result.key != path_record
    {
        return Err(());
    }
    let create = operation.method == HttpMethod::Post;
    let context = crate::govstack::write::ValidatorContext {
        registry: metadata.registry,
        collection: metadata.collection,
        record: if create { &result.key } else { path_record },
        view: metadata.view.unwrap_or("write-receipt"),
        closure: metadata.closure,
    };
    let receipt = crate::govstack::write::render_receipt(
        result,
        context,
        state.codec.as_ref().ok_or(())?,
        create,
    )
    .map_err(|_| ())?;
    // Validate using the same pinned output projection as the companion GET.
    let companion = metadata.companion_read.or_else(|| {
        let update = state
            .loaded
            .project
            .write
            .as_ref()?
            .collections
            .get(&operation.record_type)?
            .update
            .as_ref()?;
        state
            .loaded
            .served
            .iter()
            .find(|served| served.binding == update.companion_read.as_str())
    });
    if let Some(companion) = companion {
        companion
            .project_transform
            .as_ref()
            .ok_or(())?
            .apply(
                &state.loaded.code_maps,
                &Value::Object(result.data.clone()),
                deadline,
            )
            .map_err(|_| ())?;
    }
    Ok((receipt.body, receipt.etag, receipt.location))
}

pub(crate) fn govstack_problem(code: &str, status: StatusCode, request_id: &str) -> Response {
    govstack_problem_at(code, status, request_id, "/data")
}

fn govstack_problem_at(
    code: &str,
    status: StatusCode,
    request_id: &str,
    pointer: &str,
) -> Response {
    let mut body = json!({"type": format!("https://govstack.global/problems/digital-registries/{code}"),
        "title": code.replace('-', " "), "status": status.as_u16(), "traceId": request_id});
    if code == "invalid-content" {
        body["errors"] =
            json!([{"pointer": pointer, "message": "the submitted field is not valid"}]);
    }
    let mut response = json_response(status, &body);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    crate::govstack::correlation::mark_problem(&mut response, body);
    response
}

fn stamp_terminal_problem(events: &mut [(JournalEvent, SystemTime)], response: &Response) {
    let Some(code) = crate::govstack::correlation::problem_type(response) else {
        return;
    };
    for (event, _) in events
        .iter_mut()
        .filter(|(event, _)| event.event_kind == "exchangeFailed")
    {
        let mut detail: serde_json::Map<String, Value> = event
            .detail
            .as_deref()
            .map(|text| serde_json::from_str(text).expect("host journal detail is a JSON object"))
            .unwrap_or_default();
        detail.insert("problemCode".to_owned(), Value::String(code.to_owned()));
        detail.insert("status".to_owned(), json!(response.status().as_u16()));
        event.detail = Some(Value::Object(detail).to_string());
    }
}

async fn audited_internal_failure(
    state: &FacadeState,
    events: Vec<(JournalEvent, SystemTime)>,
    record_type: &str,
    request_id: &str,
) -> Response {
    if let Err(fault) = append_all(&state.journal, events).await {
        tracing::error!(%fault, "the invalid source guard journal could not commit");
    }
    facade_problem(
        state.loaded.problems(),
        ErrorClass::Facade,
        StatusCode::INTERNAL_SERVER_ERROR,
        record_type,
        request_id,
    )
}

fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    headers.get("idempotency-key")?.to_str().ok().filter(|key| {
        !key.is_empty() && key.len() <= MAX_IDEMPOTENCY_KEY_BYTES && !key.contains('\0')
    })
}

/// Bind the key to the exact governed artifact revision and validated write
/// request. The concrete operation already namespaces the key; the record
/// type and identifier are repeated here so an update cannot reuse a key for
/// another record even if a profile's body envelope omits the identifier.
fn write_request_digest(
    artifact_revision: &str,
    record_type: &str,
    record_id: &str,
    body: &[u8],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(WRITE_REQUEST_DIGEST_DOMAIN);
    for part in [
        artifact_revision.as_bytes(),
        record_type.as_bytes(),
        record_id.as_bytes(),
        body,
    ] {
        let length = u64::try_from(part.len()).expect("facade request bounds fit u64");
        digest.update(length.to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

/// The caller-filled values an authored write request envelope may carry.
pub(crate) struct CapturedWriteRequest {
    pub(crate) record: Value,
    pub(crate) record_id: Option<String>,
}

/// Read the required `{{record}}` and optional authored `{{recordId}}` slot
/// from a write request envelope while enforcing its complete literal and
/// structural shape. No caller member outside the declared template enters
/// the exchange.
pub(crate) fn capture_write_record(
    template: &str,
    body: &Value,
) -> Result<CapturedWriteRequest, Refusal> {
    let parsed = parse_envelope_template(template)
        .map_err(|_| Refusal::invalid_request("the write request envelope is invalid"))?;
    let mut record = None;
    let mut record_id = None;
    match_write_node(&parsed, body, &mut record, &mut record_id)?;
    let record =
        record.ok_or_else(|| Refusal::invalid_request("the write request carries no record"))?;
    Ok(CapturedWriteRequest { record, record_id })
}

/// Check the extracted raw domain record and separately authored identity
/// before either can enter the exchange. A path-bound operation and a body
/// identity must name the same record. The request digest still binds the
/// path independently when the profile carries no body identity.
pub(crate) fn validate_write_record(
    operation: &ServedOperation,
    captured: &CapturedWriteRequest,
    path_record_id: &str,
) -> Result<(), Refusal> {
    let violations = validate_result_schema(&captured.record, &operation.record_schema);
    if !violations.is_empty() {
        return Err(Refusal::invalid_field(
            "the write record does not match its declared schema",
        ));
    }
    if captured
        .record_id
        .as_deref()
        .is_some_and(|identifier| !is_path_segment_value(identifier))
    {
        return Err(Refusal::invalid_field(
            "the write record identifier is not one path segment",
        ));
    }
    if operation.record_id_parameter.is_some()
        && captured
            .record_id
            .as_deref()
            .is_some_and(|identifier| identifier != path_record_id)
    {
        return Err(Refusal::invalid_field(
            "the write record identifier does not match the request path",
        ));
    }
    Ok(())
}

fn match_write_node(
    template: &Value,
    body: &Value,
    record: &mut Option<Value>,
    record_id: &mut Option<String>,
) -> Result<(), Refusal> {
    if let Value::String(text) = template {
        if let Some((name, _form)) = decode_slot(text) {
            match name {
                SLOT_RECORD if record.is_none() => {
                    *record = Some(body.clone());
                    return Ok(());
                }
                "recordId" if record_id.is_none() => {
                    let Some(identifier) = body.as_str() else {
                        return Err(Refusal::invalid_field(
                            "the write record identifier is not a string",
                        ));
                    };
                    *record_id = Some(identifier.to_owned());
                    return Ok(());
                }
                _ => {
                    return Err(Refusal::invalid_request(
                        "the write request envelope carries an unsupported or repeated slot",
                    ));
                }
            }
        }
    }
    match (template, body) {
        (Value::Object(template), Value::Object(body)) => {
            if body.keys().any(|key| !template.contains_key(key)) {
                return Err(Refusal::invalid_request(
                    "the write request object differs from the declared shape",
                ));
            }
            for (key, child) in template {
                let Some(value) = body.get(key) else {
                    if matches!(
                        child.as_str().and_then(decode_slot),
                        Some((_, SlotForm::Optional))
                    ) {
                        continue;
                    }
                    return Err(Refusal::invalid_request(
                        "the write request is missing a declared member",
                    ));
                };
                match_write_node(child, value, record, record_id)?;
            }
            Ok(())
        }
        (Value::Array(template), Value::Array(body)) if template.len() == body.len() => {
            for (child, value) in template.iter().zip(body) {
                match_write_node(child, value, record, record_id)?;
            }
            Ok(())
        }
        (Value::Array(_), Value::Array(_)) => Err(Refusal::invalid_request(
            "the write request array differs from the declared shape",
        )),
        (Value::Object(_), _) | (Value::Array(_), _) => Err(Refusal::invalid_request(
            "the write request member has the wrong JSON type",
        )),
        (literal, value) if literal == value => Ok(()),
        (literal, value) if json_type(literal) != json_type(value) => Err(
            Refusal::invalid_request("the write request member has the wrong JSON type"),
        ),
        _ => Err(Refusal::invalid_field(
            "the write request member differs from the contract value",
        )),
    }
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

async fn prepare_write_response(
    response: Response,
    request_id: &str,
) -> Result<(Response, Option<StoredResponse>), String> {
    let (parts, body) = response.into_parts();
    let semantic = |name| -> Result<Option<Vec<u8>>, String> {
        let mut values = parts.headers.get_all(name).iter();
        let value = values.next().map(|value| value.as_bytes().to_vec());
        if values.next().is_some() {
            return Err("adapter.idempotency-response: repeated semantic header".to_owned());
        }
        Ok(value)
    };
    let content_type = semantic(header::CONTENT_TYPE)?;
    let location = semantic(header::LOCATION)?;
    let etag = semantic(header::ETAG)?;
    let body = axum::body::to_bytes(body, MAX_STORED_RESPONSE_BYTES)
        .await
        .map_err(|_| "adapter.idempotency-response: body exceeds custody bound".to_owned())?;
    let stored = match (parts.status, content_type, location, etag) {
        (StatusCode::NO_CONTENT, Some(content_type), None, None) => StoredResponse::new(
            parts.status.as_u16(),
            content_type,
            body.to_vec(),
            request_id,
        ),
        (_, content_type, location, etag) => StoredResponse::with_semantic_headers(
            parts.status.as_u16(),
            content_type,
            location,
            etag,
            body.to_vec(),
            request_id,
        ),
    }
    .map_err(|error| error.to_string())?;
    Ok((Response::from_parts(parts, Body::from(body)), Some(stored)))
}

fn replay_response(stored: StoredResponse) -> Response {
    replay_response_ref(&stored)
}

fn replay_govstack_failed_response(stored: StoredResponse) -> Result<Response, ()> {
    let mut response = replay_response_ref(&stored);
    crate::govstack::correlation::mark_stored_problem_identity(
        &mut response,
        stored.status(),
        stored.content_type_header(),
        stored.body(),
    )?;
    Ok(response)
}

fn replay_response_ref(stored: &StoredResponse) -> Response {
    let status = StatusCode::from_u16(stored.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = Response::new(Body::from(stored.body().to_vec()));
    *response.status_mut() = status;
    // These bytes passed the closed custody constructor on capture and load.
    for (name, value) in [
        (header::CONTENT_TYPE, stored.content_type_header()),
        (header::LOCATION, stored.location()),
        (header::ETAG, stored.etag()),
    ] {
        if let Some(value) = value {
            response.headers_mut().insert(
                name,
                HeaderValue::from_bytes(value).expect("custodied semantic header"),
            );
        }
    }
    response
        .extensions_mut()
        .insert(ReplayedResponseRequestId(stored.request_id().to_owned()));
    no_store(response)
}

fn cursor_binding<'a>(
    state: &'a FacadeState,
    operation: &'a ServedOperation,
    caller: &'a Caller,
    filters: crate::engine::component::rest::continuation::FilterDigest,
) -> CursorBinding<'a> {
    CursorBinding {
        operation: &operation.operation,
        binding_id: &operation.binding,
        issuer: state.loaded.runtime.oidc.issuer.as_str(),
        subject: &caller.reference,
        deployment: &state.loaded.deployment,
        filters,
    }
}

/// Seal the continuation the route set for the next page; `None` on the
/// last page and for an operation that is not paginated.
fn seal_next(
    state: &FacadeState,
    operation: &ServedOperation,
    caller: &Caller,
    binding: Option<SearchBinding>,
    page_size: u64,
    done: &Exchange,
) -> Result<Option<String>, String> {
    let (Some(binding), Some(codec)) = (binding, state.codec.as_ref()) else {
        return Ok(None);
    };
    let cursor_binding = cursor_binding(state, operation, caller, binding.filters);
    let wrapped = done
        .property(NEXT_CONTINUATION_PROPERTY)
        .filter(|value| !value.is_null())
        .map(|continuation| wrap_continuation(continuation, page_size));
    codec
        .seal(wrapped.as_ref(), &cursor_binding, SystemTime::now())
        .map_err(|error| error.to_string())
}

/// Answer a verified caller's refused call (403, or a record type the
/// operation does not serve) after journaling it as `callRefused` with the
/// class and status only. The refusal is also logged, so an operator sees it
/// without reading the journal.
async fn refuse_call(
    state: &FacadeState,
    operation: &ServedOperation,
    caller: &Caller,
    record_type: &str,
    request_id: &str,
    class: ErrorClass,
    status: StatusCode,
) -> Response {
    let profile = state.loaded.problems();
    tracing::warn!(
        class = class.class(),
        status = status.as_u16(),
        "a verified caller's call was refused"
    );
    let event = JournalEvent {
        event_kind: "callRefused",
        exchange_id: request_id.to_owned(),
        operation: operation.operation.clone(),
        caller_ref: caller.reference.clone(),
        route_id: operation.route_id.clone(),
        detail: Some(json!({ "class": class.class(), "status": status.as_u16() }).to_string()),
    };
    if let Err(fault) = append_all(&state.journal, vec![(event, SystemTime::now())]).await {
        tracing::error!(%fault, "the audit journal could not record the refusal");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            record_type,
            request_id,
        );
    }
    facade_problem(profile, class, status, record_type, request_id)
}

/// Refuse a verified and admitted call whose supplied whole-contract pin is
/// wrong or ambiguous. The fixed protocol problem is released only after the
/// value-free refusal row commits. A journal failure is itself the protocol's
/// fixed unavailable problem, never a profile-authored problem.
async fn refuse_contract_pin(
    state: &FacadeState,
    operation: &ServedOperation,
    caller: &Caller,
    request_id: &str,
) -> Response {
    tracing::warn!(
        code = PIN_PROBLEM_CODE,
        status = StatusCode::PRECONDITION_FAILED.as_u16(),
        "a verified caller's effective contract pin was refused"
    );
    let event = JournalEvent {
        event_kind: "callRefused",
        exchange_id: request_id.to_owned(),
        operation: operation.operation.clone(),
        caller_ref: caller.reference.clone(),
        route_id: operation.route_id.clone(),
        detail: Some(
            json!({
                "code": PIN_PROBLEM_CODE,
                "status": StatusCode::PRECONDITION_FAILED.as_u16(),
            })
            .to_string(),
        ),
    };
    if let Err(fault) = append_all(&state.journal, vec![(event, SystemTime::now())]).await {
        tracing::error!(%fault, "the audit journal could not record the contract refusal");
        return contract_unavailable(request_id);
    }
    protocol_problem(
        StatusCode::PRECONDITION_FAILED,
        PIN_PROBLEM_CODE,
        "Effective contract precondition failed",
        request_id,
    )
}

/// Answer a refused request as the class and status of its [`Refusal`],
/// journaling the refusal first with its value-free reason.
async fn refuse_request(
    state: &FacadeState,
    operation: &ServedOperation,
    caller: &Caller,
    record_type: &str,
    request_id: &str,
    refusal: Refusal,
) -> Response {
    let profile = state.loaded.problems();
    let event = |kind: &'static str, detail: Option<Value>| {
        (
            JournalEvent {
                event_kind: kind,
                exchange_id: request_id.to_owned(),
                operation: operation.operation.clone(),
                caller_ref: caller.reference.clone(),
                route_id: operation.route_id.clone(),
                detail: detail.map(|value| value.to_string()),
            },
            SystemTime::now(),
        )
    };
    let mut failure = exchange_failure_detail(profile, refusal.class);
    failure["reason"] = Value::String(refusal.reason);
    if operation.write_support.is_some() {
        let code = refusal.write_problem.or_else(|| {
            (refusal.status == StatusCode::UNPROCESSABLE_ENTITY).then_some("invalid-content")
        });
        if let Some(code) = code {
            failure["problemCode"] = Value::String(format!(
                "https://govstack.global/problems/digital-registries/{code}"
            ));
            failure["status"] = json!(refusal.status.as_u16());
        }
    }
    let events = vec![
        event("exchangeCreated", None),
        event("exchangeFailed", Some(failure)),
    ];
    if let Err(fault) = append_all(&state.journal, events).await {
        tracing::error!(%fault, "the audit journal could not record the refusal");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            record_type,
            request_id,
        );
    }
    warn_exchange_failed(refusal.class, refusal.status);
    if let Some(code) = refusal.write_problem {
        return govstack_problem(code, refusal.status, request_id);
    }
    if operation.write_support.is_some() && refusal.status == StatusCode::UNPROCESSABLE_ENTITY {
        return govstack_problem_at(
            "invalid-content",
            refusal.status,
            request_id,
            refusal.validation_pointer.unwrap_or("/data"),
        );
    }
    if refusal.status == StatusCode::UNPROCESSABLE_ENTITY
        && profile.profile.is_govstack_consultation()
    {
        let pointer = crate::govstack::consultation::validation_pointer(&operation.operation);
        facade_validation_problem(
            profile,
            refusal.class,
            refusal.status,
            record_type,
            request_id,
            pointer,
        )
    } else {
        facade_problem_with_detail(
            profile,
            refusal.class,
            refusal.status,
            record_type,
            request_id,
            refusal.detail,
        )
    }
}

/// The rendered success body: the next cursor (when the route set one) and
/// the request-scoped slots joined to the disclosed ones, filled into the
/// operation's response envelope.
pub(crate) fn render_success(
    operation: &ServedOperation,
    mut slots: BTreeMap<&'static str, Value>,
    next_cursor: Option<String>,
    record_type: &str,
    request_id: &str,
) -> Result<Value, String> {
    if let Some(cursor) = next_cursor.filter(|_| operation.pagination.is_some()) {
        slots.insert("nextCursor", Value::String(cursor));
    }
    slots.insert("recordType", Value::String(record_type.to_owned()));
    slots.insert("requestId", Value::String(request_id.to_owned()));
    operation.response_envelope.render(&slots)
}

/// Render one route failure through the profile's selected problem. Public
/// for the runtime conformance suite; live serving and fixture replay call
/// this same function so their validation and fail-closed behavior cannot
/// diverge.
#[doc(hidden)]
pub fn route_problem(
    profile: Problems<'_>,
    failure: &RouteFailure,
    record_type: &str,
    request_id: &str,
) -> Response {
    problem_response(
        profile,
        ProblemRender {
            class: failure.class,
            status_override: None,
            detail: failure.message.as_deref(),
            data: failure.data.as_ref(),
            validation_pointer: None,
        },
        record_type,
        request_id,
    )
}

/// A facade-level problem whose HTTP status the failure fixes (401, 403,
/// 404 and the like), filled into the profile's problem for the class.
pub(crate) fn facade_problem(
    profile: Problems<'_>,
    class: ErrorClass,
    status: StatusCode,
    record_type: &str,
    request_id: &str,
) -> Response {
    facade_problem_with_detail(profile, class, status, record_type, request_id, None)
}

fn facade_problem_with_detail(
    profile: Problems<'_>,
    class: ErrorClass,
    status: StatusCode,
    record_type: &str,
    request_id: &str,
    detail: Option<&str>,
) -> Response {
    let fixed = fixed_facade_problem_response(class, status.as_u16())
        .expect("the facade emits only declared fixed class/status pairs");
    problem_response(
        profile,
        ProblemRender {
            class: fixed.class,
            status_override: Some(
                StatusCode::from_u16(fixed.status)
                    .expect("fixed facade statuses are valid HTTP statuses"),
            ),
            detail,
            data: None,
            validation_pointer: None,
        },
        record_type,
        request_id,
    )
}

fn facade_validation_problem(
    profile: Problems<'_>,
    class: ErrorClass,
    status: StatusCode,
    record_type: &str,
    request_id: &str,
    pointer: &str,
) -> Response {
    let fixed = fixed_facade_problem_response(class, status.as_u16())
        .expect("the facade emits only declared fixed class/status pairs");
    problem_response(
        profile,
        ProblemRender {
            class: fixed.class,
            status_override: Some(status),
            detail: None,
            data: None,
            validation_pointer: Some(pointer),
        },
        record_type,
        request_id,
    )
}

/// Fixed fallback when a profile-rendered terminal write response cannot fit
/// the idempotency custody bound. It is deliberately independent of authored
/// envelope size so the failure itself can be stored and replayed atomically
/// with `exchangeFailed`.
fn bounded_internal_problem(request_id: &str) -> Response {
    let mut response = json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        &json!({ "status": 500, "requestId": request_id }),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

/// What a problem reply needs: the profile's declared problems and its
/// compiled problem envelope.
#[derive(Clone, Copy)]
pub struct Problems<'a> {
    pub profile: &'a AdapterProfile,
    pub envelope: &'a CompiledEnvelope,
}

struct ProblemRender<'a> {
    class: ErrorClass,
    status_override: Option<StatusCode>,
    detail: Option<&'a str>,
    data: Option<&'a Value>,
    validation_pointer: Option<&'a str>,
}

/// The profile's problem for `class`: the declared problem whose class is
/// the closest ancestor of (or equal to) the raised class. Without a match
/// the response is a bare 500 with no body detail.
fn problem_response(
    problems: Problems<'_>,
    render: ProblemRender<'_>,
    record_type: &str,
    request_id: &str,
) -> Response {
    let Some(mut problem) = resolve_problem(problems.profile, render.class) else {
        return with_request_id(
            no_store(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            request_id,
        );
    };
    let mut detail = render.detail;
    let mut data = render.data;
    let valid_data = data.is_none_or(|value| problem_data_is_valid(problem, value));
    let mut status_override = render.status_override;
    if !valid_data {
        let Some(disclosure) = resolve_problem(problems.profile, ErrorClass::DisclosureViolation)
        else {
            return with_request_id(
                no_store(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
                request_id,
            );
        };
        problem = disclosure;
        detail = None;
        data = None;
        status_override = None;
    }
    let status = status_override.unwrap_or_else(|| {
        StatusCode::from_u16(u16::try_from(problem.status.get()).unwrap_or(500))
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    });
    let mut slots: BTreeMap<&str, Value> = BTreeMap::new();
    slots.insert(
        "problemCode",
        Value::String(problem.code.as_str().to_owned()),
    );
    slots.insert("problemTitle", Value::String(problem.title.clone()));
    slots.insert("status", json!(status.as_u16()));
    slots.insert("recordType", Value::String(record_type.to_owned()));
    slots.insert("requestId", Value::String(request_id.to_owned()));
    if let Some(detail) = detail {
        slots.insert("problemDetail", Value::String(detail.to_owned()));
    }
    if let Some(data) = data {
        slots.insert(SLOT_PROBLEM_DATA, data.clone());
    }
    if problems.profile.is_govstack_consultation() && status == StatusCode::UNPROCESSABLE_ENTITY {
        slots.insert(
            SLOT_PROBLEM_ERRORS,
            json!([{
                "pointer": render.validation_pointer.unwrap_or("/request"),
                "message": "the field does not satisfy the declared schema"
            }]),
        );
    }
    match problems.envelope.render(&slots) {
        Ok(rendered) => {
            let mut response = json_response(status, &rendered);
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/problem+json"),
            );
            if problems.profile.is_govstack_consultation() {
                crate::govstack::correlation::mark_problem(&mut response, rendered);
            }
            with_request_id(response, request_id)
        }
        Err(error) => {
            tracing::error!(%error, "the problem envelope could not be rendered");
            with_request_id(no_store(status.into_response()), request_id)
        }
    }
}

/// Drop invalid problem data and its authored detail before either the
/// journal or response sees the failure. The facade renderer repeats the
/// check as a release-boundary defense, while live serving and replay use
/// this normalization so their selected class and problem code also match
/// the fixed value-free refusal.
pub(crate) fn enforce_problem_data(
    profile: &AdapterProfile,
    failure: RouteFailure,
) -> RouteFailure {
    let valid = failure.data.as_ref().is_none_or(|data| {
        resolve_problem(profile, failure.class)
            .is_some_and(|problem| problem_data_is_valid(problem, data))
    });
    if valid {
        failure
    } else {
        RouteFailure::of(ErrorClass::DisclosureViolation)
    }
}

fn problem_data_is_valid(problem: &registry_adapter_core::Problem, data: &Value) -> bool {
    serde_json::to_vec(data).is_ok_and(|bytes| bytes.len() <= MAX_PROBLEM_DATA_BYTES)
        && problem_data_schema(problem)
            .is_some_and(|schema| validate_result_schema(data, &schema).is_empty())
}

fn contract_unavailable(request_id: &str) -> Response {
    protocol_problem(
        StatusCode::SERVICE_UNAVAILABLE,
        UNAVAILABLE_PROBLEM_CODE,
        "Effective contract unavailable",
        request_id,
    )
}

fn consultation_unavailable(request_id: &str) -> Response {
    let body = crate::govstack::consultation::service_unavailable_problem(request_id);
    let mut response = json_response(StatusCode::SERVICE_UNAVAILABLE, &body);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    crate::govstack::correlation::mark_problem(&mut response, body);
    with_request_id(response, request_id)
}

fn protocol_problem(
    status: StatusCode,
    code: &'static str,
    title: &'static str,
    request_id: &str,
) -> Response {
    let mut response = json_response(
        status,
        &json!({
            "code": code,
            "status": status.as_u16(),
            "title": title,
            "requestId": request_id,
        }),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    with_request_id(response, request_id)
}

pub(crate) fn json_response(status: StatusCode, body: &Value) -> Response {
    let mut response = (status, body.to_string()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    no_store(response)
}

/// Mark a reply as never to be stored: every reply the facade makes, a
/// refusal included, discloses or concerns a protected read.
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn with_request_id(mut response: Response, request_id: &str) -> Response {
    let value = HeaderValue::from_str(request_id)
        .expect("an Adapter-generated request id is a valid response header value");
    response.headers_mut().insert(
        axum::http::HeaderName::from_static(REQUEST_ID_HEADER),
        value,
    );
    response
}

/// A missing header preserves native-client compatibility. A present header
/// is accepted only when it occurs once, is text, and exactly matches the
/// immutable whole-contract digest cached at startup.
fn effective_contract_matches(headers: &HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(PIN_HEADER).iter();
    let Some(first) = values.next() else {
        return true;
    };
    values.next().is_none() && first.to_str().is_ok_and(|value| value == expected)
}

fn new_id() -> String {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).expect("the operating system supplies randomness");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn new_recovery_id() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system supplies randomness");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "facade_generated_properties.rs"]
mod generated_properties;

#[cfg(test)]
mod tests {
    use super::*;

    fn example_project(scopes: Value) -> AdapterProject {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/examples/dhis2-tracker/project.yaml");
        let text = std::fs::read_to_string(path).expect("the example project reads");
        #[allow(
            clippy::disallowed_methods,
            reason = "the test reads a committed example, pack or fixture to build its input; it reads no operator configuration"
        )]
        let mut value: Value = serde_norway::from_str(&text).expect("the example project parses");
        for profile in value["accessProfiles"].as_array_mut().expect("profiles") {
            profile["scopes"] = scopes.clone();
        }
        value
            .as_object_mut()
            .expect("a mapping")
            .retain(|key, _| key != "apiVersion" && key != "kind");
        serde_json::from_value(value).expect("the project deserializes")
    }

    fn served(operation: &str, record_type: &str) -> ServedOperation {
        ServedOperation {
            operation: operation.to_owned(),
            method_path: String::new(),
            record_type_parameter: String::new(),
            record_id_parameter: None,
            binding: String::new(),
            record_type: record_type.to_owned(),
            route_id: String::new(),
            steps: std::sync::Arc::new(Vec::new()),
            resume: None,
            resilience: crate::engine::resilience::ResilienceRuntime::empty(),
            maximum_upstream_calls: 1,
            item_envelope: None,
            response_envelope: crate::engine::envelope::CompiledEnvelope::compile(
                "{}",
                &BTreeMap::new(),
            )
            .expect("an empty envelope compiles"),
            record_schema: json!({}),
            pagination: None,
            method: HttpMethod::Get,
            request_template: None,
            request_maximum_bytes: crate::engine::load::DEFAULT_REQUEST_MAXIMUM_BYTES,
            filters: Vec::new(),
            async_completion: None,
            project_transform: None,
            project_input_schema: None,
            project_input_transform: None,
            write_support: None,
            read_support: None,
            source_input: None,
            item_projection: None,
            target_contract: None,
        }
    }

    fn consultation_project() -> AdapterProject {
        let generic = example_project(json!(["records.read"]));
        let mut value = serde_json::to_value(generic).expect("project JSON");
        let object = value.as_object_mut().expect("project object");
        object.remove("profile");
        object.insert(
            "consultation".to_owned(),
            json!({
                "contract": "https://registry.example/contracts/1.0.0-draft/openapi.yaml",
                "collections": [{
                    "recordType": "person",
                    "registry": "https://registry.example/registries/people",
                    "view": "person-public",
                    "dataSchema": "person-public",
                    "lookup": {"selector": "by-id", "inputSchema": "lookup-id"},
                    "search": {"search": "by-criteria", "inputSchema": "search-criteria"}
                }]
            }),
        );
        for profile in value["accessProfiles"].as_array_mut().expect("profiles") {
            if profile["id"] == "records-reader" {
                profile["operations"] = json!(["retrieve", "list"]);
            }
        }
        serde_json::from_value(value).expect("consultation project")
    }

    #[test]
    fn a_call_reaches_the_operation_of_the_record_type_it_names() {
        let mut person = served("records-get", "person");
        person.record_type_parameter = "type".to_owned();
        let mut household = served("records-get", "household");
        household.record_type_parameter = "type".to_owned();
        let operations = [person, household];
        let params = |record_type: &str| {
            HashMap::from([
                ("type".to_owned(), record_type.to_owned()),
                ("record_id".to_owned(), "r1".to_owned()),
            ])
        };

        assert_eq!(dispatch(&operations, &[0, 1], &params("person")), 0);
        assert_eq!(dispatch(&operations, &[0, 1], &params("household")), 1);
        assert_eq!(
            dispatch(&operations, &[0, 1], &params("canary-type")),
            0,
            "an unbound record type falls to the first operation, which \
             authenticates before it refuses 404"
        );
    }

    #[test]
    fn terminal_audit_uses_the_actual_govstack_problem_identity() {
        let response = govstack_problem(
            "precondition-failed",
            StatusCode::PRECONDITION_FAILED,
            "0123456789abcdef0123456789abcdef",
        );
        let mut events = vec![(JournalEvent {
            event_kind: "exchangeFailed", exchange_id: "attempt".to_owned(), operation: "update".to_owned(),
            caller_ref: "caller".to_owned(), route_id: "route".to_owned(),
            detail: Some(json!({"class": "outcome.conflict", "problemCode": "old-profile-code", "auth": {"kind": "verified"}}).to_string()),
        }, SystemTime::now())];
        stamp_terminal_problem(&mut events, &response);
        let detail: Value = serde_json::from_str(events[0].0.detail.as_deref().unwrap()).unwrap();
        assert_eq!(
            detail["problemCode"],
            "https://govstack.global/problems/digital-registries/precondition-failed"
        );
        assert_eq!(detail["status"], 412);
        assert_eq!(detail["class"], "outcome.conflict");
        assert_eq!(detail["auth"]["kind"], "verified");
    }

    #[tokio::test]
    async fn write_semantic_validation_and_fingerprint_mismatch_have_distinct_contracts() {
        let request_id = "0123456789abcdef0123456789abcdef";
        for (code, has_errors) in [
            ("invalid-content", true),
            ("idempotency-fingerprint-mismatch", false),
        ] {
            let response = govstack_problem(code, StatusCode::UNPROCESSABLE_ENTITY, request_id);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let problem: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                problem["type"],
                format!("https://govstack.global/problems/digital-registries/{code}")
            );
            assert_eq!(problem["status"], 422);
            assert_eq!(problem.get("errors").is_some(), has_errors);
            if has_errors {
                assert_eq!(problem["errors"][0]["pointer"], "/data");
            }
        }
    }

    #[test]
    fn replay_window_header_publishes_decimal_seconds_without_changing_the_body() {
        let response = with_replay_window_seconds(
            json_response(StatusCode::OK, &json!({"collections": []})),
            86400,
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-registry-idempotency-replay-window-seconds")
                .unwrap(),
            "86400"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[tokio::test]
    async fn custodied_write_problem_keeps_original_trace_body_on_a_new_attempt() {
        let first = RequestCorrelation::server_created();
        let second = RequestCorrelation::server_created();
        let response = first.finish(govstack_problem(
            "precondition-failed",
            StatusCode::PRECONDITION_FAILED,
            first.request_id(),
        ));
        let (_, stored) = prepare_write_response(response, first.request_id())
            .await
            .expect("capture first effective trace");
        let stored = stored.expect("custody");
        let original_body = stored.body().to_vec();
        let response = second.finish(replay_response(stored));
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), original_body);
        let problem: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["traceId"], first.trace_id().as_str());
        assert_ne!(first.trace_id(), second.trace_id());
    }

    #[tokio::test]
    async fn write_response_custody_keeps_semantic_headers_and_bodyless_update() {
        let request_id = "0123456789abcdef0123456789abcdef";
        let mut update = no_store(StatusCode::NO_CONTENT.into_response());
        update
            .headers_mut()
            .insert(header::ETAG, HeaderValue::from_static("\"committed\""));
        let (first, stored) = prepare_write_response(update, request_id)
            .await
            .expect("capture 204");
        assert_eq!(first.status(), StatusCode::NO_CONTENT);
        let replay = replay_response(stored.expect("custody"));
        assert_eq!(replay.status(), StatusCode::NO_CONTENT);
        assert_eq!(replay.headers().get(header::CONTENT_TYPE), None);
        assert_eq!(
            replay.headers().get(header::ETAG),
            Some(&HeaderValue::from_static("\"committed\""))
        );
        assert!(axum::body::to_bytes(replay.into_body(), 1024)
            .await
            .unwrap()
            .is_empty());

        let mut created = json_response(StatusCode::CREATED, &json!({"recordId": "r1"}));
        created.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_static("/govstack/registries/v1/collections/people/records/r1"),
        );
        created
            .headers_mut()
            .insert(header::ETAG, HeaderValue::from_static("\"created\""));
        let (_, stored) = prepare_write_response(created, request_id)
            .await
            .expect("capture 201");
        let replay = replay_response(stored.expect("custody"));
        assert_eq!(replay.status(), StatusCode::CREATED);
        assert_eq!(
            replay.headers().get(header::LOCATION).unwrap(),
            "/govstack/registries/v1/collections/people/records/r1"
        );
        assert_eq!(replay.headers().get(header::ETAG).unwrap(), "\"created\"");
        assert_eq!(
            replay.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let mut generic = Response::new(Body::from(br#"{"legacy":true}"#.as_slice()));
        *generic.status_mut() = StatusCode::NO_CONTENT;
        generic.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let (_, stored) = prepare_write_response(generic, request_id)
            .await
            .expect("capture the historical generic 204 shape");
        let replay = replay_response(stored.expect("generic custody"));
        assert_eq!(replay.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            replay.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            axum::body::to_bytes(replay.into_body(), 1024)
                .await
                .unwrap(),
            br#"{"legacy":true}"#.as_slice()
        );
    }

    #[test]
    fn govstack_write_capture_checks_only_the_declared_domain_before_source_effects() {
        let mut operation = served("update", "person");
        operation.method = HttpMethod::Patch;
        operation.project_input_schema = Some(Arc::new(
            crate::engine::public_schema::check_public_schema(json!({
                "$id": "https://registry.example/schemas/1/person-patch.json",
                "type": "object", "additionalProperties": false,
                "properties": {"name": {"type": "string"}, "note": {"type": ["string", "null"]}}
            }))
            .expect("input schema"),
        ));
        let captured = capture_govstack_write(&operation, &json!({"data": {"note": null}}))
            .expect("null removes an optional field");
        assert_eq!(captured.record, json!({"note": null}));
        let source = capture_govstack_write(&operation, &json!({"data": {"name": "Ada"}, "source": {"system": "https://source.example", "revision": "r1"}}))
            .err().expect("unsupported source evidence is explicit");
        assert_eq!(source.validation_pointer, Some("/source"));
        for body in [
            json!({"data": {}}),
            json!({"data": []}),
            json!({"data": {"unknown": true}}),
            json!({"data": {"name": "Ada"}, "recordId": "chosen"}),
            json!({"data": {"name": "Ada"}, "source": {"system": "https://source.example", "revision": "r1"}}),
        ] {
            assert!(capture_govstack_write(&operation, &body).is_err());
        }
    }

    #[test]
    fn capability_projection_is_filtered_by_current_machine_scopes() {
        let project = consultation_project();
        let mut retrieve = served("retrieve", "person");
        retrieve.route_id = "https://source.internal/private?credential=PRIVATE-CANARY".to_owned();
        let operations = [
            retrieve,
            served("list", "person"),
            served("search", "person"),
        ];
        let caller = Caller {
            reference: "machine-subject".to_owned(),
            issuer: "https://issuer.example".to_owned(),
            client_id: "registry-client".to_owned(),
            scopes: vec!["records.read".to_owned()],
        };
        let document =
            crate::govstack::consultation::caller_capabilities(&project, &operations, |served| {
                admits(&project, &caller, served)
            })
            .expect("bounded capability document");
        assert_eq!(document.collections.len(), 1);
        assert_eq!(document.collections[0].collection_id, "person");
        let ids = document.collections[0]
            .operations
            .iter()
            .map(|operation| operation.operation_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["retrievePerson", "listPerson"]);
        assert!(document.collections[0]
            .operations
            .iter()
            .all(|operation| operation.contract
                == "https://registry.example/contracts/1.0.0-draft/openapi.yaml"));
        let public = serde_json::to_string(&document).expect("capabilities serialize");
        assert!(!public.contains("source.internal"), "{public}");
        assert!(!public.contains("PRIVATE-CANARY"), "{public}");
        assert!(!public.contains("credential"), "{public}");
    }

    #[tokio::test]
    async fn consultation_invalid_field_is_a_bounded_validation_problem() {
        let profile = crate::govstack::consultation::built_in_profile();
        let envelope = CompiledEnvelope::compile(profile.problem_envelope.text(), &BTreeMap::new())
            .expect("maintained problem envelope compiles");
        let response = facade_validation_problem(
            Problems {
                profile: &profile,
                envelope: &envelope,
            },
            ErrorClass::FacadeInvalidField,
            StatusCode::UNPROCESSABLE_ENTITY,
            "people",
            "0123456789abcdef0123456789abcdef",
            "/criteria",
        );
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("bounded problem body");
        let body: Value = serde_json::from_slice(&bytes).expect("problem JSON");
        assert_eq!(body["errors"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["errors"][0]["pointer"], "/criteria");
        assert!(body["errors"][0]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }

    #[tokio::test]
    async fn consultation_readiness_failure_uses_its_service_unavailable_problem() {
        let response = consultation_unavailable("0123456789abcdef0123456789abcdef");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("bounded problem body");
        let body: Value = serde_json::from_slice(&bytes).expect("problem JSON");
        assert_eq!(
            body["type"],
            crate::govstack::consultation::SERVICE_UNAVAILABLE_PROBLEM_CODE
        );
        assert_eq!(body["title"], "the service is unavailable");
        assert_eq!(body["status"], 503);
        assert_eq!(body["traceId"], "0123456789abcdef0123456789abcdef");
    }

    #[tokio::test]
    async fn consultation_auth_backend_failure_uses_its_service_unavailable_problem() {
        let profile = crate::govstack::consultation::built_in_profile();
        let envelope = CompiledEnvelope::compile(profile.problem_envelope.text(), &BTreeMap::new())
            .expect("maintained problem envelope compiles");
        let response = refusal_response(
            Problems {
                profile: &profile,
                envelope: &envelope,
            },
            CallerRefusal::Unavailable,
            "0123456789abcdef0123456789abcdef",
        );
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("bounded problem body");
        let body: Value = serde_json::from_slice(&bytes).expect("problem JSON");
        assert_eq!(
            body["type"],
            crate::govstack::consultation::SERVICE_UNAVAILABLE_PROBLEM_CODE
        );
        assert_eq!(body["status"], 503);
    }

    #[tokio::test]
    async fn a_configured_profile_named_like_the_built_in_gets_no_govstack_problems() {
        let built_in = crate::govstack::consultation::built_in_profile();
        let profile: AdapterProfile =
            serde_json::from_value(serde_json::to_value(&built_in).expect("serializes"))
                .expect("a configured profile with the built-in id parses");
        let envelope = CompiledEnvelope::compile(profile.problem_envelope.text(), &BTreeMap::new())
            .expect("problem envelope compiles");
        let response = refusal_response(
            Problems {
                profile: &profile,
                envelope: &envelope,
            },
            CallerRefusal::Unavailable,
            "0123456789abcdef0123456789abcdef",
        );
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("bounded problem body");
        let body: Value = serde_json::from_slice(&bytes).expect("problem JSON");
        assert_ne!(
            body["type"],
            crate::govstack::consultation::SERVICE_UNAVAILABLE_PROBLEM_CODE
        );
    }

    #[test]
    fn an_access_profile_with_no_scopes_admits_nobody() {
        let caller = Caller {
            reference: "caller".to_owned(),
            issuer: "https://issuer.example.invalid".to_owned(),
            client_id: "case-portal".to_owned(),
            scopes: vec!["records.read".to_owned()],
        };
        let operation = served("records-get", "person");
        assert!(admits(
            &example_project(json!(["records.read"])),
            &caller,
            &operation
        ));
        assert!(!admits(&example_project(json!([])), &caller, &operation));
    }

    fn person_schema() -> Value {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["name"],
            "properties": { "name": { "type": "string" } }
        })
    }

    #[test]
    fn a_wrapped_record_discloses_only_its_declared_domain_fields() {
        let wrapped = json!({
            "recordIdentifier": "r1",
            "revisionIdentifier": "v1",
            "domainData": { "name": "A" }
        });
        assert_eq!(
            disclosed_record(&wrapped, &person_schema()),
            Ok(json!({ "name": "A" }))
        );
    }

    #[test]
    fn a_record_with_an_undeclared_or_missing_or_mistyped_field_is_refused() {
        let schema = person_schema();
        assert!(disclosed_record(&json!({ "name": "A", "ssn": "1" }), &schema).is_err());
        assert!(disclosed_record(&json!({}), &schema).is_err());
        assert!(disclosed_record(&json!({ "name": 3 }), &schema).is_err());
        let leaking =
            json!({ "recordIdentifier": "r1", "domainData": { "name": "A", "ssn": "1" } });
        assert!(disclosed_record(&leaking, &schema).is_err());
    }

    #[test]
    fn a_wrapper_with_an_extra_member_or_no_domain_data_is_refused() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        });
        let extra = json!({ "recordIdentifier": "r1", "domainData": {}, "internal": "x" });
        assert!(disclosed_record(&extra, &schema).is_err());
        let bare = json!({ "recordIdentifier": "r1", "name": "A" });
        assert!(disclosed_record(&bare, &schema).is_err());
    }

    #[test]
    fn a_declared_domain_field_named_record_identifier_stays_raw_domain_data() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["name", "recordIdentifier"],
            "properties": {
                "name": {"type": "string"},
                "recordIdentifier": {"type": "string"}
            }
        });
        let record = json!({"name": "Ada", "recordIdentifier": "domain-value"});
        assert_eq!(disclosed_record(&record, &schema), Ok(record));
    }

    #[test]
    fn an_item_envelope_fills_the_record_and_its_identifier() {
        let mut operation = served("records-get", "person");
        operation.record_schema = person_schema();
        operation.item_envelope = Some(crate::engine::load::ServedItem {
            envelope: CompiledEnvelope::compile(
                r#"{"recordId": "{{recordId}}", "data": {{record}}}"#,
                &BTreeMap::new(),
            )
            .unwrap(),
            names_record_id: true,
        });
        let wrapped = json!({
            "recordIdentifier": "r-1",
            "domainData": { "name": "A" },
        });
        assert_eq!(
            disclosed_item(&operation, &wrapped, "person", "id").unwrap(),
            json!({ "recordId": "r-1", "data": { "name": "A" } })
        );
        // A bare record carries no identifier for the template to name.
        assert!(disclosed_item(&operation, &json!({ "name": "A" }), "person", "id").is_err());
        // An identifier that is not a string is never served.
        let numeric = json!({ "recordIdentifier": 7, "domainData": { "name": "A" } });
        assert!(disclosed_item(&operation, &numeric, "person", "id").is_err());
    }

    #[test]
    fn a_write_request_envelope_releases_only_its_record_slot() {
        let template = r#"{"kind":"person","payload":{{record}}}"#;
        let record = json!({ "name": "A", "active": true });
        let body = json!({ "kind": "person", "payload": record });
        let Ok(captured) = capture_write_record(template, &body) else {
            panic!("declared write body must be captured");
        };
        assert_eq!(captured.record, record);
        assert_eq!(captured.record_id, None);
        assert!(capture_write_record(
            template,
            &json!({ "kind": "person", "payload": {}, "extra": true })
        )
        .is_err());
        assert!(
            capture_write_record(template, &json!({ "kind": "other", "payload": {} })).is_err()
        );

        let identity_template = r#"{"command":{"target":"{{recordId}}","payload":{{record}}}}"#;
        let Ok(captured) = capture_write_record(
            identity_template,
            &json!({
                "command": {
                    "target": "person-1",
                    "payload": {"name": "Ada", "recordIdentifier": "domain-value"}
                }
            }),
        ) else {
            panic!("the profile-owned identity field must be captured separately");
        };
        assert_eq!(captured.record_id.as_deref(), Some("person-1"));
        assert_eq!(
            captured.record,
            json!({"name": "Ada", "recordIdentifier": "domain-value"})
        );

        let optional_identity = r#"{"command":{"target":"{{?recordId}}","payload":{{record}}}}"#;
        let Ok(captured) = capture_write_record(
            optional_identity,
            &json!({"command": {"payload": {"name": "Ada"}}}),
        ) else {
            panic!("an omitted optional body identity must leave path identity in control");
        };
        assert_eq!(captured.record_id, None);
        assert_eq!(captured.record, json!({"name": "Ada"}));
    }

    #[test]
    fn a_write_record_is_schema_checked_and_cannot_disagree_with_its_path() {
        let mut operation = served("records-update", "person");
        operation.record_id_parameter = Some("record_id".to_owned());
        operation.record_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["name", "recordIdentifier"],
            "properties": {
                "name": {"type": "string"},
                "recordIdentifier": {"type": "string"}
            }
        });

        let record = json!({"name": "Ada", "recordIdentifier": "domain-value"});
        let matching = CapturedWriteRequest {
            record: record.clone(),
            record_id: Some("person-1".to_owned()),
        };
        assert!(validate_write_record(&operation, &matching, "person-1").is_ok());

        let mismatched = CapturedWriteRequest {
            record: record.clone(),
            record_id: Some("person-2".to_owned()),
        };
        assert!(validate_write_record(&operation, &mismatched, "person-1").is_err());

        let undeclared = CapturedWriteRequest {
            record: json!({"name": "Ada", "recordIdentifier": "domain-value", "private": true}),
            record_id: Some("person-1".to_owned()),
        };
        assert!(validate_write_record(&operation, &undeclared, "person-1").is_err());

        let path_only = CapturedWriteRequest {
            record,
            record_id: None,
        };
        assert!(
            validate_write_record(&operation, &path_only, "person-1").is_ok(),
            "a profile may place the path identity outside its domain record body"
        );
    }

    #[test]
    fn a_write_request_digest_binds_body_record_type_and_record_id() {
        let first = write_request_digest("sha256:revision-a", "person", "p-1", br#"{"name":"A"}"#);
        assert_ne!(
            first,
            write_request_digest("sha256:revision-a", "person", "p-2", br#"{"name":"A"}"#)
        );
        assert_ne!(
            first,
            write_request_digest("sha256:revision-a", "permit", "p-1", br#"{"name":"A"}"#)
        );
        assert_ne!(
            first,
            write_request_digest("sha256:revision-a", "person", "p-1", br#"{"name":"B"}"#)
        );
        assert_ne!(
            first,
            write_request_digest("sha256:revision-b", "person", "p-1", br#"{"name":"A"}"#)
        );
    }

    #[tokio::test]
    async fn an_oversized_terminal_response_has_a_bounded_storable_failure() {
        let request_id = "00000000000000000000000000000001";
        let mut oversized = Response::new(Body::from(vec![b'x'; MAX_STORED_RESPONSE_BYTES + 1]));
        *oversized.status_mut() = StatusCode::CREATED;
        oversized.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(prepare_write_response(oversized, request_id).await.is_err());

        let (response, stored) =
            prepare_write_response(bounded_internal_problem(request_id), request_id)
                .await
                .expect("the fixed failure fits response custody");
        let stored = stored.expect("a terminal write response is retained");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(stored.status(), StatusCode::INTERNAL_SERVER_ERROR.as_u16());
        assert_eq!(stored.content_type(), b"application/problem+json");
        assert_eq!(
            serde_json::from_slice::<Value>(stored.body()).unwrap(),
            json!({ "status": 500, "requestId": request_id })
        );
        assert_eq!(stored.request_id(), request_id);
        assert!(stored.body().len() < MAX_STORED_RESPONSE_BYTES);
    }
}
