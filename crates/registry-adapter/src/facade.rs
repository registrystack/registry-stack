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
    AdapterProfile, AdapterProject, ErrorClass, HttpMethod, Problem, SLOT_PROBLEM_CODE,
};
use serde_json::{json, Value};

use crate::component::http::uri::encode_path_segment;
use crate::component::rest::continuation::{
    filter_digest, ContinuationCodec, CursorBinding, CursorRefusal,
};
use crate::envelope::CompiledEnvelope;
use crate::exchange::{
    Exchange, CONTINUATION_PROPERTY, FILTERS_PROPERTY, NEXT_CONTINUATION_PROPERTY, PAGE_SIZE_HEADER,
};
use crate::journal::{self, JournalEvent};
use crate::load::{Loaded, ServedOperation, ServedPagination};
use crate::read_request::{parse_filter_text, ReadRefusal};
use crate::route::{run_route, RouteContext, RouteFailure};
use crate::serve::{Authenticator, Caller, CallerRefusal};

/// What every handler shares.
pub struct FacadeState {
    pub loaded: Loaded,
    pub authenticator: Authenticator,
    pub journal: Pool,
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
    match task.await {
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

    let mut inputs = RequestInputs::default();
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
    } else if operation.pagination.is_some() {
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
        maximum_upstream_calls: operation.maximum_upstream_calls,
    };
    let outcome = run_route(&context, &operation.steps, exchange).await;
    for event in outcome.events {
        events.push((journal_event(event.kind, Some(event.detail)), event.at));
    }

    // The response body is built before the journal commits, so the
    // journal never records `exchangeCompleted` for an exchange whose body
    // the facade then failed to seal or render.
    let rendered = match outcome.result {
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
                        events.push((journal_event("exchangeCompleted", None), SystemTime::now()));
                        Finished::Body(body)
                    }
                    Err(error) => {
                        tracing::error!(%error, "the response could not be built");
                        events.push((
                            journal_event(
                                "exchangeFailed",
                                Some(json!({ "class": ErrorClass::Facade.class() })),
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
                        Some(json!({ "class": failure.class.class() })),
                    ),
                    SystemTime::now(),
                ));
                Finished::Route(failure)
            }
        },
        Err(failure) => {
            let mut detail = json!({ "class": failure.class.class() });
            if let Some(auth) = &failure.auth {
                detail["auth"] = auth.clone();
            }
            events.push((
                journal_event("exchangeFailed", Some(detail)),
                SystemTime::now(),
            ));
            Finished::Route(failure)
        }
    };
    // Journal first: a response is never sent for an exchange the journal
    // could not record. The rest of the exchange commits as one unit.
    if let Err(fault) = append_all(&state.journal, events).await {
        tracing::error!(%fault, "the audit journal could not record the exchange");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &record_type,
            &request_id,
        );
    }
    match rendered {
        Finished::Body(body) => json_response(StatusCode::OK, &body),
        Finished::Internal => {
            warn_exchange_failed(ErrorClass::Facade, StatusCode::INTERNAL_SERVER_ERROR);
            facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                &record_type,
                &request_id,
            )
        }
        Finished::Route(failure) => {
            let response = route_problem(profile, &failure, &record_type, &request_id);
            warn_exchange_failed(failure.class, response.status());
            response
        }
    }
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

/// How an exchange ended once the response was built, before the journal
/// commits it.
enum Finished {
    Body(Value),
    Internal,
    Route(RouteFailure),
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
fn disclosed_slots(
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
struct RequestInputs {
    cursor: Option<String>,
    page_size: Option<u64>,
    filters: serde_json::Map<String, Value>,
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
struct Refusal {
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
fn query_inputs(
    operation: &ServedOperation,
    query: Option<&str>,
) -> Result<RequestInputs, Refusal> {
    let pagination = operation
        .pagination
        .as_ref()
        .ok_or_else(|| Refusal::invalid_request("the operation takes no query parameters"))?;
    let mut inputs = RequestInputs::default();
    let mut seen: Vec<String> = Vec::new();
    for (name, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        if seen.iter().any(|earlier| *earlier == name) {
            return Err(Refusal::invalid_request("a repeated query parameter"));
        }
        seen.push(name.clone().into_owned());
        if name == pagination.cursor_parameter {
            inputs.cursor = Some(value.into_owned());
        } else if name == pagination.page_size_parameter {
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
    // Every filter the binding declares is required: a search that leaves
    // one out is refused here, before any script runs or source is called.
    if operation
        .filters
        .iter()
        .any(|filter| !inputs.filters.contains_key(&filter.name))
    {
        return Err(Refusal::invalid_field("a declared filter is absent"));
    }
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

fn wrap_continuation(continuation: &Value, page_size: u64) -> Value {
    json!({CURSOR_CONTINUATION_MEMBER: continuation, CURSOR_PAGE_SIZE_MEMBER: page_size})
}

fn unwrap_continuation(sealed: Value) -> Option<(u64, Value)> {
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
    let events = vec![
        event("exchangeCreated", None),
        event(
            "exchangeFailed",
            Some(json!({
                "class": refusal.class.class(),
                "reason": refusal.reason,
            })),
        ),
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
fn render_success(
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

fn route_problem(
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
        return no_store(StatusCode::INTERNAL_SERVER_ERROR.into_response());
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
            response
        }
        Err(error) => {
            tracing::error!(%error, "the problem envelope could not be rendered");
            no_store(status.into_response())
        }
    }
}

fn select_problem(profile: &AdapterProfile, class: ErrorClass) -> Option<&Problem> {
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

fn json_response(status: StatusCode, body: &Value) -> Response {
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

fn new_id() -> String {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).expect("the operating system supplies randomness");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

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
}
