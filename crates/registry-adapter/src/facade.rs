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
use std::time::SystemTime;

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, RawQuery};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, MethodRouter};
use axum::Router;
use deadpool_postgres::Pool;
use registry_adapter_core::{
    decode_slot, parse_envelope_template, AdapterProfile, AdapterProject, ErrorClass, HttpMethod,
    Problem, SLOT_PROBLEM_CODE, SLOT_RECORD,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::component::http::uri::encode_path_segment;
use crate::component::rest::continuation::{
    filter_digest, ContinuationCodec, CursorBinding, CursorRefusal,
};
use crate::effective_contract::{
    EffectiveContract, RuntimeContractResponse, PIN_HEADER, PIN_PROBLEM_CODE,
    UNAVAILABLE_PROBLEM_CODE, WELL_KNOWN_PATH,
};
use crate::envelope::CompiledEnvelope;
use crate::exchange::{
    Exchange, WriteExecutionContext, WriteResolution, CONTINUATION_PROPERTY, FILTERS_PROPERTY,
    NEXT_CONTINUATION_PROPERTY, PAGE_SIZE_HEADER,
};
use crate::idempotent::{
    PostgresIdempotencyStore, StoredResponse, TerminalOutcome, VerifiedCallerIdentity,
    MAX_IDEMPOTENCY_KEY_BYTES, MAX_STORED_RESPONSE_BYTES,
};
use crate::journal::{self, JournalEvent};
use crate::load::{Loaded, ServedOperation, ServedPagination};
use crate::read_request::{parse_filter_text, ReadRefusal};
use crate::route::{run_route, RouteContext, RouteFailure};
use crate::serve::{Authenticator, Caller, CallerRefusal};

const REQUEST_ID_HEADER: &str = "x-registry-request-id";
const WRITE_REQUEST_DIGEST_DOMAIN: &[u8] = b"registry-adapter:write-request:v2\0";

/// What every handler shares.
pub struct FacadeState {
    pub loaded: Loaded,
    pub effective_contract: EffectiveContract,
    pub authenticator: Authenticator,
    pub journal: Pool,
    /// Present only when this deployment explicitly configures exact write
    /// response retention and serves at least one write operation.
    pub idempotency: Option<PostgresIdempotencyStore>,
    /// Seals and opens pagination cursors; present when the runtime
    /// config declares `cursorKeyRef`, which a paginated operation needs.
    pub codec: Option<ContinuationCodec>,
}

/// The router for every served operation: one handler per method and
/// path. A path answered under another method refuses 405 with the methods
/// it takes, and a path no operation serves refuses 404; both answer the
/// profile's problem and journal nothing, since no caller was verified.
pub fn router(state: Arc<FacadeState>) -> Router {
    let mut by_path: Vec<(String, Vec<usize>)> = Vec::new();
    for (index, operation) in state.loaded.served.iter().enumerate() {
        match by_path
            .iter_mut()
            .find(|(path, _)| *path == operation.method_path)
        {
            Some((_, indexes)) => indexes.push(index),
            None => by_path.push((operation.method_path.clone(), vec![index])),
        }
    }
    let mut router = Router::new();
    for (path, indexes) in by_path {
        let mut routes: Option<MethodRouter> = None;
        let mut allowed = Vec::new();
        for index in indexes {
            let shared = Arc::clone(&state);
            let handler = move |headers: HeaderMap,
                                params: Result<Path<HashMap<String, String>>, PathRejection>,
                                RawQuery(query): RawQuery,
                                body: Body| {
                let shared = Arc::clone(&shared);
                async move {
                    // A path segment that is not UTF-8 never reaches a
                    // call: it answers the profile's bad-request problem,
                    // not the framework's bare rejection.
                    let Ok(Path(params)) = params else {
                        return facade_problem(
                            shared.loaded.problems(),
                            ErrorClass::FacadeInvalidRequest,
                            StatusCode::BAD_REQUEST,
                            "",
                            &new_id(),
                        );
                    };
                    handle(shared, index, headers, params, query, body).await
                }
            };
            let method = state.loaded.served[index].method;
            allowed.push(if method == HttpMethod::Post {
                "POST"
            } else {
                "GET"
            });
            routes = Some(match (routes.take(), method) {
                (None, HttpMethod::Post) => post(handler),
                (None, _) => get(handler),
                (Some(existing), HttpMethod::Post) => existing.post(handler),
                (Some(existing), _) => existing.get(handler),
            });
        }
        let Some(routes) = routes else { continue };
        let shared = Arc::clone(&state);
        let allow = allowed.join(", ");
        router = router.route(
            &path,
            routes.fallback(move || {
                let shared = Arc::clone(&shared);
                let allow = allow.clone();
                async move {
                    let mut response = facade_problem(
                        shared.loaded.problems(),
                        ErrorClass::FacadeMethodNotAllowed,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "",
                        &new_id(),
                    );
                    if let Ok(value) = HeaderValue::from_str(&allow) {
                        response.headers_mut().insert(header::ALLOW, value);
                    }
                    response
                }
            }),
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
    router.fallback(move || {
        let shared = Arc::clone(&unmatched);
        async move {
            facade_problem(
                shared.loaded.problems(),
                ErrorClass::FacadeNotFound,
                StatusCode::NOT_FOUND,
                "",
                &new_id(),
            )
        }
    })
}

/// Run one call to completion on its own task: a caller that disconnects
/// drops this future but cannot cancel an exchange part way, so the source
/// call and its journal rows always finish together.
async fn handle(
    state: Arc<FacadeState>,
    index: usize,
    headers: HeaderMap,
    params: HashMap<String, String>,
    query: Option<String>,
    body: Body,
) -> Response {
    let fallback = Arc::clone(&state);
    // The id is minted before the task starts, so the fallback answer
    // carries the same request id the journal rows would have.
    let request_id = new_id();
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
    with_request_id(response, &fallback_id)
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

async fn answer(
    state: &FacadeState,
    index: usize,
    request_id: String,
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

    let mut inputs = RequestInputs::default();
    let mut write_request: Option<(Value, Vec<u8>)> = None;
    if operation.method == HttpMethod::Post {
        if !has_json_content_type(headers) {
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
                Refusal::invalid_request("a read over POST takes no query parameters"),
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
            match capture_write_record(template.text(), &parsed) {
                Ok(record) => write_request = Some((record, bytes.to_vec())),
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
        if let Err(refusal) = require_declared_filters(operation, &inputs) {
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

    let mut exchange = Exchange::new(request_id.clone());
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
        let Some(key) = idempotency_key(headers) else {
            return refuse_request(
                state,
                operation,
                &caller,
                &record_type,
                &request_id,
                Refusal::invalid_field("the Idempotency-Key header is absent or invalid"),
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
        let digest = write_request_digest(
            &state.loaded.deployment,
            &record_type,
            &record_id,
            &raw_body,
        );
        Some(exchange.prepare_write(
            store,
            caller_identity,
            state.loaded.runtime.id.as_str().to_owned(),
            concrete_operation,
            digest,
        ))
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
        .set_header("recordId", Value::String(record_id));
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
    };
    let outcome = run_route(&context, &operation.steps, exchange).await;
    for event in outcome.events {
        events.push((journal_event(event.kind, Some(event.detail)), event.at));
    }
    let write_resolution = match &write_execution {
        Some(context) => context.resolution().await,
        None => WriteResolution::Pending,
    };

    // The response body is built before the journal commits, so the
    // journal never records `exchangeCompleted` for an exchange whose body
    // the facade then failed to seal or render.
    let rendered = match write_resolution.clone() {
        WriteResolution::Replay(response) => {
            events.push((journal_event("exchangeCompleted", None), SystemTime::now()));
            Finished::Replay(response)
        }
        WriteResolution::Conflict | WriteResolution::ResponseExpired => {
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
            Ok(done) => match disclosed_slots(
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
                    let failure = RouteFailure {
                        class: ErrorClass::DisclosureViolation,
                        message: None,
                        auth: None,
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
            },
            Err(failure) => {
                let mut detail = exchange_failure_detail(profile, failure.class);
                if let Some(auth) = &failure.auth {
                    detail["auth"] = auth.clone();
                }
                events.push((
                    journal_event("exchangeFailed", Some(detail)),
                    SystemTime::now(),
                ));
                Finished::Route(failure)
            }
        },
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
            let response = route_problem(profile, &failure, &record_type, &request_id);
            warn_exchange_failed(failure.class, response.status());
            (response, Some(TerminalOutcome::Failed))
        }
        Finished::Replay(response) => (replay_response(response), None),
        Finished::FacadeProblem(class, status) => {
            warn_exchange_failed(class, status);
            (
                facade_problem(profile, class, status, &record_type, &request_id),
                None,
            )
        }
    };
    let pending_write = matches!(write_resolution, WriteResolution::Pending)
        .then_some(())
        .and(write_execution.as_ref());
    let (response, stored) = match pending_write {
        Some(_) => match prepare_write_response(response).await {
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
                response = bounded_internal_problem(&request_id);
                prepare_write_response(response)
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
    if let Some(problem) = select_problem(profile.profile, class) {
        detail["problemCode"] = Value::String(problem.code.as_str().to_owned());
    }
    detail
}

/// How an exchange ended once the response was built, before the journal
/// commits it.
enum Finished {
    Body(Value),
    Internal,
    Route(RouteFailure),
    Replay(StoredResponse),
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

fn refusal_response(profile: Problems<'_>, refusal: CallerRefusal, request_id: &str) -> Response {
    let (class, status) = match refusal {
        CallerRefusal::Unauthenticated => {
            (ErrorClass::FacadeUnauthenticated, StatusCode::UNAUTHORIZED)
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
/// record was wrapped beside one. An identifier that is not a string is a
/// disclosure violation.
fn disclosed_parts(body: &Value, schema: &Value) -> Result<(Value, Option<String>), usize> {
    let mut identifier = None;
    let record = match body {
        Value::Object(map) if map.contains_key("recordIdentifier") => {
            let wrapper_shaped = map.len() <= RECORD_WRAPPER_MEMBERS.len()
                && map
                    .keys()
                    .all(|key| RECORD_WRAPPER_MEMBERS.contains(&key.as_str()));
            match (map.get("domainData"), map.get("recordIdentifier")) {
                (Some(domain), Some(Value::String(id))) if wrapper_shaped => {
                    identifier = Some(id.clone());
                    domain
                }
                _ => return Err(1),
            }
        }
        other => other,
    };
    let violations = registry_adapter_core::validate_result_schema(record, schema);
    if violations.is_empty() {
        Ok((record.clone(), identifier))
    } else {
        Err(violations.len())
    }
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
    let (record, identifier) = disclosed_parts(body, &operation.record_schema)?;
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
    filters: crate::component::rest::continuation::FilterDigest,
}

/// Why a request was refused: the class and status the caller sees, and a
/// value-free reason for the journal.
pub(crate) struct Refusal {
    class: ErrorClass,
    status: StatusCode,
    reason: String,
}

impl Refusal {
    fn invalid_request(reason: &str) -> Self {
        Self {
            class: ErrorClass::FacadeInvalidRequest,
            status: StatusCode::BAD_REQUEST,
            reason: reason.to_owned(),
        }
    }

    fn invalid_field(reason: &str) -> Self {
        Self {
            class: ErrorClass::FacadeInvalidField,
            status: StatusCode::UNPROCESSABLE_ENTITY,
            reason: reason.to_owned(),
        }
    }

    fn invalid_cursor(reason: &str) -> Self {
        Self {
            class: ErrorClass::FacadeInvalidCursor,
            status: StatusCode::BAD_REQUEST,
            reason: reason.to_owned(),
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

/// Whether the request declares `application/json` as its body type.
fn has_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
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

/// Read the one `{{record}}` slot from a write request envelope while
/// enforcing its complete literal and structural shape. No caller member
/// outside the declared template enters the exchange.
fn capture_write_record(template: &str, body: &Value) -> Result<Value, Refusal> {
    let parsed = parse_envelope_template(template)
        .map_err(|_| Refusal::invalid_request("the write request envelope is invalid"))?;
    let mut record = None;
    match_write_node(&parsed, body, &mut record)?;
    record.ok_or_else(|| Refusal::invalid_request("the write request carries no record"))
}

fn match_write_node(
    template: &Value,
    body: &Value,
    record: &mut Option<Value>,
) -> Result<(), Refusal> {
    if let Value::String(text) = template {
        if let Some((name, _form)) = decode_slot(text) {
            if name != SLOT_RECORD || record.is_some() {
                return Err(Refusal::invalid_request(
                    "the write request envelope carries an unsupported slot",
                ));
            }
            *record = Some(body.clone());
            return Ok(());
        }
    }
    match (template, body) {
        (Value::Object(template), Value::Object(body)) => {
            if body.len() != template.len() || body.keys().any(|key| !template.contains_key(key)) {
                return Err(Refusal::invalid_request(
                    "the write request object differs from the declared shape",
                ));
            }
            for (key, child) in template {
                let Some(value) = body.get(key) else {
                    return Err(Refusal::invalid_request(
                        "the write request is missing a declared member",
                    ));
                };
                match_write_node(child, value, record)?;
            }
            Ok(())
        }
        (Value::Array(template), Value::Array(body)) if template.len() == body.len() => {
            for (child, value) in template.iter().zip(body) {
                match_write_node(child, value, record)?;
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
) -> Result<(Response, Option<StoredResponse>), String> {
    let (parts, body) = response.into_parts();
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .ok_or_else(|| "adapter.idempotency-response: content type absent".to_owned())?
        .as_bytes()
        .to_vec();
    let body = axum::body::to_bytes(body, MAX_STORED_RESPONSE_BYTES)
        .await
        .map_err(|_| "adapter.idempotency-response: body exceeds custody bound".to_owned())?;
    let stored = StoredResponse::new(parts.status.as_u16(), content_type, body.to_vec())
        .map_err(|error| error.to_string())?;
    Ok((Response::from_parts(parts, Body::from(body)), Some(stored)))
}

fn replay_response(stored: StoredResponse) -> Response {
    let status = StatusCode::from_u16(stored.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, stored.body().to_vec()).into_response();
    if let Ok(content_type) = HeaderValue::from_bytes(stored.content_type()) {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
    }
    no_store(response)
}

fn cursor_binding<'a>(
    state: &'a FacadeState,
    operation: &'a ServedOperation,
    caller: &'a Caller,
    filters: crate::component::rest::continuation::FilterDigest,
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
    facade_problem(
        profile,
        refusal.class,
        refusal.status,
        record_type,
        request_id,
    )
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

pub(crate) fn route_problem(
    profile: Problems<'_>,
    failure: &RouteFailure,
    record_type: &str,
    request_id: &str,
) -> Response {
    problem_response(
        profile,
        failure.class,
        None,
        failure.message.as_deref(),
        record_type,
        request_id,
    )
}

/// A facade-level problem whose HTTP status the failure fixes (401, 403,
/// 404 and the like), filled into the profile's problem for the class.
fn facade_problem(
    profile: Problems<'_>,
    class: ErrorClass,
    status: StatusCode,
    record_type: &str,
    request_id: &str,
) -> Response {
    problem_response(profile, class, Some(status), None, record_type, request_id)
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

/// The profile's problem for `class`: the declared problem whose class is
/// the closest ancestor of (or equal to) the raised class. Without a match
/// the response is a bare 500 with no body detail.
fn problem_response(
    problems: Problems<'_>,
    class: ErrorClass,
    status_override: Option<StatusCode>,
    detail: Option<&str>,
    record_type: &str,
    request_id: &str,
) -> Response {
    let Some(problem) = select_problem(problems.profile, class) else {
        return with_request_id(
            no_store(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            request_id,
        );
    };
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
    match problems.envelope.render(&slots) {
        Ok(rendered) => {
            let mut response = json_response(status, &rendered);
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/problem+json"),
            );
            with_request_id(response, request_id)
        }
        Err(error) => {
            tracing::error!(%error, "the problem envelope could not be rendered");
            with_request_id(no_store(status.into_response()), request_id)
        }
    }
}

fn contract_unavailable(request_id: &str) -> Response {
    protocol_problem(
        StatusCode::SERVICE_UNAVAILABLE,
        UNAVAILABLE_PROBLEM_CODE,
        "Effective contract unavailable",
        request_id,
    )
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

pub(crate) fn select_problem(profile: &AdapterProfile, class: ErrorClass) -> Option<&Problem> {
    let mut best: Option<(usize, &Problem)> = None;
    for problem in profile.problems.iter() {
        for declared in problem.classes.iter() {
            if class.is_within(*declared) {
                let depth = declared.class().split('.').count();
                if best.is_none_or(|(held, _)| depth > held) {
                    best = Some((depth, problem));
                }
            }
        }
    }
    debug_assert!(profile.problem_envelope.mentions(SLOT_PROBLEM_CODE));
    best.map(|(_, problem)| problem)
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
        #[allow(clippy::disallowed_methods)]
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
            resilience: crate::resilience::ResilienceRuntime::empty(),
            maximum_upstream_calls: 1,
            item_envelope: None,
            response_envelope: crate::envelope::CompiledEnvelope::compile("{}", &BTreeMap::new())
                .expect("an empty envelope compiles"),
            record_schema: json!({}),
            pagination: None,
            method: HttpMethod::Get,
            request_template: None,
            request_maximum_bytes: crate::load::DEFAULT_REQUEST_MAXIMUM_BYTES,
            filters: Vec::new(),
        }
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
        let schema = json!({ "type": "object" });
        let extra = json!({ "recordIdentifier": "r1", "domainData": {}, "internal": "x" });
        assert!(disclosed_record(&extra, &schema).is_err());
        let bare = json!({ "recordIdentifier": "r1", "name": "A" });
        assert!(disclosed_record(&bare, &schema).is_err());
    }

    #[test]
    fn an_item_envelope_fills_the_record_and_its_identifier() {
        let mut operation = served("records-get", "person");
        operation.record_schema = person_schema();
        operation.item_envelope = Some(crate::load::ServedItem {
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
        assert_eq!(captured, record);
        assert!(capture_write_record(
            template,
            &json!({ "kind": "person", "payload": {}, "extra": true })
        )
        .is_err());
        assert!(
            capture_write_record(template, &json!({ "kind": "other", "payload": {} })).is_err()
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
        let mut oversized = Response::new(Body::from(vec![b'x'; MAX_STORED_RESPONSE_BYTES + 1]));
        *oversized.status_mut() = StatusCode::CREATED;
        oversized.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(prepare_write_response(oversized).await.is_err());

        let (response, stored) = prepare_write_response(bounded_internal_problem("request-1"))
            .await
            .expect("the fixed failure fits response custody");
        let stored = stored.expect("a terminal write response is retained");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(stored.status(), StatusCode::INTERNAL_SERVER_ERROR.as_u16());
        assert_eq!(stored.content_type(), b"application/problem+json");
        assert_eq!(
            serde_json::from_slice::<Value>(stored.body()).unwrap(),
            json!({ "status": 500, "requestId": "request-1" })
        );
        assert!(stored.body().len() < MAX_STORED_RESPONSE_BYTES);
    }
}
