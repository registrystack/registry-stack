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

use axum::extract::{Path, RawQuery};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use deadpool_postgres::Pool;
use registry_adapter_core::{
    AdapterProfile, AdapterProject, ErrorClass, Problem, SLOT_PROBLEM_CODE,
};
use serde_json::{json, Value};

use crate::component::rest::continuation::{
    filter_digest, ContinuationCodec, CursorBinding, CursorRefusal,
};
use crate::envelope::CompiledEnvelope;
use crate::exchange::{
    Exchange, CONTINUATION_PROPERTY, FILTERS_PROPERTY, NEXT_CONTINUATION_PROPERTY, PAGE_SIZE_HEADER,
};
use crate::journal::{self, JournalEvent};
use crate::load::{Loaded, ServedOperation, ServedPagination};
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

/// The router for every served operation.
pub fn router(state: Arc<FacadeState>) -> Router {
    let mut router = Router::new();
    for index in 0..state.loaded.served.len() {
        let shared = Arc::clone(&state);
        let path = shared.loaded.served[index].method_path.clone();
        router = router.route(
            &path,
            get(
                move |headers: HeaderMap,
                      Path(params): Path<HashMap<String, String>>,
                      RawQuery(query): RawQuery| {
                    let shared = Arc::clone(&shared);
                    async move { handle(shared, index, headers, params, query).await }
                },
            ),
        );
    }
    router
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
) -> Response {
    let operation = &state.loaded.served[index];
    let profile = state.loaded.problems();
    let record_type = params
        .get(&operation.record_type_parameter)
        .cloned()
        .unwrap_or_default();
    let record_id = operation
        .record_id_parameter
        .as_ref()
        .and_then(|name| params.get(name))
        .cloned()
        .unwrap_or_default();

    let caller = match authenticate(state, headers).await {
        Ok(caller) => caller,
        Err(refusal) => return refusal_response(profile, refusal, &request_id),
    };
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

    if !is_path_segment_value(&record_id) {
        return refuse_request(
            state,
            operation,
            &caller,
            &record_type,
            &request_id,
            "the record identifier is not a usable path value",
        )
        .await;
    }

    let mut exchange = Exchange::new(request_id.clone());
    let mut search_binding: Option<SearchBinding> = None;
    let mut requested_page_size: Option<u64> = None;
    if let Some(pagination) = &operation.pagination {
        match open_search(state, operation, pagination, &caller, &record_type, query) {
            Ok(search) => {
                exchange
                    .message
                    .set_header(PAGE_SIZE_HEADER, json!(search.page_size));
                exchange.set_property(FILTERS_PROPERTY, json!({}));
                if let Some(continuation) = search.continuation {
                    exchange.set_property(CONTINUATION_PROPERTY, continuation);
                }
                requested_page_size = Some(search.page_size);
                search_binding = Some(search.binding);
            }
            Err(reason) => {
                return refuse_request(
                    state,
                    operation,
                    &caller,
                    &record_type,
                    &request_id,
                    &reason,
                )
                .await;
            }
        }
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
        Ok(done) => match disclosed_slots(operation, &done.message.body, requested_page_size) {
            Ok(slots) => {
                match seal_next(state, operation, &caller, search_binding, &done).and_then(
                    |next_cursor| {
                        render_success(operation, slots, next_cursor, &record_type, &request_id)
                    },
                ) {
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
            events.push((
                journal_event(
                    "exchangeFailed",
                    Some(json!({ "class": failure.class.class() })),
                ),
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
        Finished::Internal => facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &record_type,
            &request_id,
        ),
        Finished::Route(failure) => route_problem(profile, &failure, &record_type, &request_id),
    }
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
fn disclosed_record(body: &Value, schema: &Value) -> Result<Value, usize> {
    let record = match body {
        Value::Object(map) if map.contains_key("recordIdentifier") => {
            let wrapper_shaped = map.len() <= RECORD_WRAPPER_MEMBERS.len()
                && map
                    .keys()
                    .all(|key| RECORD_WRAPPER_MEMBERS.contains(&key.as_str()));
            match map.get("domainData") {
                Some(domain) if wrapper_shaped => domain,
                _ => return Err(1),
            }
        }
        other => other,
    };
    let violations = registry_adapter_core::validate_result_schema(record, schema);
    if violations.is_empty() {
        Ok(record.clone())
    } else {
        Err(violations.len())
    }
}

/// The slots the response envelope is filled from: one record, or every
/// record of a page, each checked by [`disclosed_record`]. A page larger
/// than the size the caller asked for is a disclosure violation: the
/// caller never receives more records than it requested.
fn disclosed_slots(
    operation: &ServedOperation,
    body: &Value,
    page_size: Option<u64>,
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
            .map(|record| disclosed_record(record, &operation.record_schema))
            .collect::<Result<Vec<_>, _>>()?;
        slots.insert("records", Value::Array(disclosed));
    } else {
        slots.insert("record", disclosed_record(body, &operation.record_schema)?);
    }
    Ok(slots)
}

/// Whether a caller-supplied identifier can stand as one path segment of the
/// source call: a `.` or `..` would be collapsed by the outbound URI parser
/// into a different path. A record id the operation does not take is empty
/// and passes.
fn is_path_segment_value(record_id: &str) -> bool {
    record_id != "." && record_id != ".."
}

/// What a search request carries once validated.
struct SearchInputs {
    page_size: u64,
    continuation: Option<Value>,
    binding: SearchBinding,
}

/// What the cursor the route's answer may be sealed under is bound to.
struct SearchBinding {
    filters: crate::component::rest::continuation::FilterDigest,
}

/// Validate a search's query against the operation's declared pagination
/// and restore the continuation its cursor carries. Only the cursor and
/// page-size parameters exist (the person-search binding declares no
/// filters), so any other, a repeated one, or a missing or out-of-bounds
/// page size is refused. The reason is value-free, for the journal.
fn open_search(
    state: &FacadeState,
    operation: &ServedOperation,
    pagination: &ServedPagination,
    caller: &Caller,
    record_type: &str,
    query: Option<&str>,
) -> Result<SearchInputs, String> {
    let mut cursor: Option<String> = None;
    let mut limit: Option<String> = None;
    for (name, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        let slot = if name == pagination.cursor_parameter {
            &mut cursor
        } else if name == pagination.page_size_parameter {
            &mut limit
        } else {
            return Err("an undeclared query parameter".to_owned());
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err("a repeated query parameter".to_owned());
        }
    }
    let page_size = limit
        .ok_or("the page size is absent and the profile declares no default")?
        .parse::<u64>()
        .map_err(|_| "the page size is not an integer".to_owned())?;
    if !(pagination.page_size_minimum..=pagination.page_size_maximum).contains(&page_size) {
        return Err("the page size is outside the profile's bounds".to_owned());
    }
    let filters = filter_digest(
        &json!({"recordType": record_type, "filters": {}}),
        u32::try_from(page_size).map_err(|_| "the page size is too large".to_owned())?,
    )
    .map_err(|error| error.to_string())?;
    let codec = state
        .codec
        .as_ref()
        .ok_or("the runtime has no cursor key")?;
    let continuation = match cursor {
        Some(cursor) => {
            let binding = cursor_binding(state, operation, caller, filters);
            Some(
                codec
                    .open(&cursor, &binding, SystemTime::now())
                    .map_err(|refusal: CursorRefusal| refusal.reason().to_owned())?,
            )
        }
        None => None,
    };
    Ok(SearchInputs {
        page_size,
        continuation,
        binding: SearchBinding { filters },
    })
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
    done: &Exchange,
) -> Result<Option<String>, String> {
    let (Some(binding), Some(codec)) = (binding, state.codec.as_ref()) else {
        return Ok(None);
    };
    let cursor_binding = cursor_binding(state, operation, caller, binding.filters);
    codec
        .seal(
            done.property(NEXT_CONTINUATION_PROPERTY),
            &cursor_binding,
            SystemTime::now(),
        )
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

/// Answer a refused request as `facade.invalid-request`, journaling the
/// refusal first with its value-free reason.
async fn refuse_request(
    state: &FacadeState,
    operation: &ServedOperation,
    caller: &Caller,
    record_type: &str,
    request_id: &str,
    reason: &str,
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
                "class": ErrorClass::FacadeInvalidRequest.class(),
                "reason": reason,
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
    facade_problem(
        profile,
        ErrorClass::FacadeInvalidRequest,
        StatusCode::BAD_REQUEST,
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
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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
            status.into_response()
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
            steps: Vec::new(),
            maximum_upstream_calls: 1,
            response_envelope: crate::envelope::CompiledEnvelope::compile("{}", &BTreeMap::new())
                .expect("an empty envelope compiles"),
            record_schema: json!({}),
            pagination: None,
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
}
