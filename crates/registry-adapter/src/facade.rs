// SPDX-License-Identifier: Apache-2.0

//! The served facade: one axum route per served profile operation. A call
//! authenticates the bearer token, resolves the caller to an access profile
//! that admits the operation and record type, runs the binding's route over
//! a fresh exchange, journals before answering, and renders the profile's
//! envelope or problem (`products/adapter/CONCEPT.md` sections 6 to 8).
//!
//! The caller's token never reaches the exchange: the route sees only the
//! record type and record id the path named.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::SystemTime;

use axum::extract::Path;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use deadpool_postgres::Pool;
use registry_adapter_core::{
    AdapterProfile, AdapterProject, ErrorClass, Problem, SLOT_PROBLEM_CODE,
};
use serde_json::{json, Value};

use crate::exchange::Exchange;
use crate::journal::{self, JournalEvent};
use crate::load::{Loaded, ServedOperation};
use crate::route::{run_route, RouteContext, RouteFailure};
use crate::serve::{Authenticator, Caller, CallerRefusal};

/// What every handler shares.
pub struct FacadeState {
    pub loaded: Loaded,
    pub authenticator: Authenticator,
    pub journal: Pool,
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
                move |headers: HeaderMap, Path(params): Path<HashMap<String, String>>| {
                    let shared = Arc::clone(&shared);
                    async move { handle(&shared, index, &headers, &params).await }
                },
            ),
        );
    }
    router
}

async fn handle(
    state: &FacadeState,
    index: usize,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Response {
    let operation = &state.loaded.served[index];
    let profile = &state.loaded.profile;
    let request_id = new_id();
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
        return facade_problem(
            profile,
            ErrorClass::FacadeNotFound,
            StatusCode::NOT_FOUND,
            &record_type,
            &request_id,
        );
    }
    if !admits(&state.loaded.project, &caller, operation) {
        return facade_problem(
            profile,
            ErrorClass::FacadeForbidden,
            StatusCode::FORBIDDEN,
            &record_type,
            &request_id,
        );
    }

    let mut exchange = Exchange::new(request_id.clone());
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
    let mut events = vec![journal_event("exchangeCreated", None)];

    let context = RouteContext {
        endpoints: &state.loaded.endpoints,
        scripts: &state.loaded.scripts,
        resolver: &state.loaded.resolver,
        maximum_upstream_calls: operation.maximum_upstream_calls,
    };
    let outcome = run_route(&context, &operation.steps, exchange).await;
    for event in outcome.events {
        events.push(journal_event(event.kind, Some(event.detail)));
    }

    let rendered = match outcome.result {
        Ok(done) => {
            events.push(journal_event("exchangeCompleted", None));
            Ok(done)
        }
        Err(failure) => {
            events.push(journal_event(
                "exchangeFailed",
                Some(json!({ "class": failure.class.class() })),
            ));
            Err(failure)
        }
    };
    // Journal first: a response is never sent for an exchange the journal
    // could not record.
    if let Err(error) = append_all(&state.journal, events).await {
        tracing::error!(%error, "the audit journal could not record the exchange");
        return facade_problem(
            profile,
            ErrorClass::Facade,
            StatusCode::INTERNAL_SERVER_ERROR,
            &record_type,
            &request_id,
        );
    }
    match rendered {
        Ok(done) => success(profile, operation, &done, &record_type, &request_id),
        Err(failure) => route_problem(profile, &failure, &record_type, &request_id),
    }
}

async fn append_all(pool: &Pool, events: Vec<JournalEvent>) -> Result<(), String> {
    let client = pool.get().await.map_err(|error| error.to_string())?;
    for event in events {
        journal::append(&client, event, SystemTime::now())
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

async fn authenticate(state: &FacadeState, headers: &HeaderMap) -> Result<Caller, CallerRefusal> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(CallerRefusal::Unauthenticated)?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or(CallerRefusal::Unauthenticated)?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Err(CallerRefusal::Unauthenticated);
    }
    state.authenticator.authenticate(token).await
}

/// Whether some access profile the caller's scopes satisfy admits the
/// operation on the record type.
fn admits(project: &AdapterProject, caller: &Caller, operation: &ServedOperation) -> bool {
    project.access_profiles.iter().any(|profile| {
        profile
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

fn refusal_response(
    profile: &AdapterProfile,
    refusal: CallerRefusal,
    request_id: &str,
) -> Response {
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

fn success(
    profile: &AdapterProfile,
    operation: &ServedOperation,
    exchange: &Exchange,
    record_type: &str,
    request_id: &str,
) -> Response {
    // A route may end with a record that wraps its domain fields under
    // `domainData` beside the source's identifiers; the facade's record is
    // the domain fields.
    let body = &exchange.message.body;
    let record = match body {
        Value::Object(map) if map.contains_key("recordIdentifier") => map
            .get("domainData")
            .cloned()
            .unwrap_or_else(|| body.clone()),
        other => other.clone(),
    };
    let mut slots: BTreeMap<&str, Value> = BTreeMap::new();
    slots.insert("record", record);
    slots.insert("recordType", Value::String(record_type.to_owned()));
    slots.insert("requestId", Value::String(request_id.to_owned()));
    match render_envelope(&operation.response_envelope, &slots) {
        Ok(rendered) => json_response(StatusCode::OK, &rendered),
        Err(error) => {
            tracing::error!(%error, "the response envelope could not be rendered");
            facade_problem(
                profile,
                ErrorClass::Facade,
                StatusCode::INTERNAL_SERVER_ERROR,
                record_type,
                request_id,
            )
        }
    }
}

fn route_problem(
    profile: &AdapterProfile,
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
    profile: &AdapterProfile,
    class: ErrorClass,
    status: StatusCode,
    record_type: &str,
    request_id: &str,
) -> Response {
    problem_response(profile, class, Some(status), None, record_type, request_id)
}

/// The profile's problem for `class`: the declared problem whose class is
/// the closest ancestor of (or equal to) the raised class. Without a match
/// the response is a bare 500 with no body detail.
fn problem_response(
    profile: &AdapterProfile,
    class: ErrorClass,
    status_override: Option<StatusCode>,
    detail: Option<&str>,
    record_type: &str,
    request_id: &str,
) -> Response {
    let Some(problem) = select_problem(profile, class) else {
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
    match render_envelope(profile.problem_envelope.text(), &slots) {
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

/// A marker an absent optional slot leaves; the member holding it is
/// dropped from the rendered envelope.
const ABSENT: &str = "@@adapter-absent-slot@@";

/// Fill an envelope template. A `{{slot}}` or `{{?slot}}` standing alone
/// takes the slot's JSON value; one inside a string takes its text. A
/// missing required slot is a fault; a missing optional one drops the
/// member that carried it.
pub fn render_envelope(template: &str, slots: &BTreeMap<&str, Value>) -> Result<Value, String> {
    let mut out = String::new();
    let mut rest = template;
    let mut in_string = false;
    while let Some(start) = rest.find("{{") {
        let (before, after) = rest.split_at(start);
        for ch in before.chars() {
            if ch == '"' {
                in_string = !in_string;
            }
            out.push(ch);
        }
        // Escaped quotes inside strings do not occur in envelopes; a
        // backslash before the placeholder is not supported.
        let end = after.find("}}").ok_or("an unterminated placeholder")?;
        let inner = &after[2..end];
        let (name, optional) = match inner.strip_prefix('?') {
            Some(name) => (name, true),
            None => (inner, false),
        };
        match slots.get(name) {
            Some(value) => {
                if in_string {
                    let text = match value {
                        Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    let quoted = Value::String(text).to_string();
                    out.push_str(&quoted[1..quoted.len() - 1]);
                } else {
                    out.push_str(&value.to_string());
                }
            }
            None if optional => {
                if in_string {
                    out.push_str(ABSENT);
                } else {
                    out.push_str(&format!("\"{ABSENT}\""));
                }
            }
            None => return Err(format!("the slot {name} has no value")),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    let mut value: Value = serde_json::from_str(&out).map_err(|error| error.to_string())?;
    prune_absent(&mut value);
    Ok(value)
}

fn prune_absent(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map
                .iter()
                .filter(|(_, member)| member.as_str().is_some_and(|text| text.contains(ABSENT)))
                .map(|(key, _)| key.clone())
                .collect();
            for key in keys {
                map.remove(&key);
            }
            for member in map.values_mut() {
                prune_absent(member);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(prune_absent),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slots(pairs: &[(&'static str, Value)]) -> BTreeMap<&'static str, Value> {
        pairs.iter().cloned().collect()
    }

    #[test]
    fn a_bare_slot_takes_the_value_and_a_string_slot_takes_the_text() {
        let rendered = render_envelope(
            r#"{"data": {{record}}, "meta": {"type": "{{recordType}}"}}"#,
            &slots(&[("record", json!({"a": 1})), ("recordType", json!("person"))]),
        )
        .unwrap();
        assert_eq!(
            rendered,
            json!({"data": {"a": 1}, "meta": {"type": "person"}})
        );
    }

    #[test]
    fn an_absent_optional_slot_drops_its_member() {
        let template = r#"{"status": {{status}}, "detail": "{{?problemDetail}}"}"#;
        let without = render_envelope(template, &slots(&[("status", json!(404))])).unwrap();
        assert_eq!(without, json!({"status": 404}));
        let with = render_envelope(
            template,
            &slots(&[
                ("status", json!(404)),
                ("problemDetail", json!("gone \"x\"")),
            ]),
        )
        .unwrap();
        assert_eq!(with, json!({"status": 404, "detail": "gone \"x\""}));
    }

    #[test]
    fn a_missing_required_slot_is_a_fault() {
        assert!(render_envelope(r#"{"a": {{record}}}"#, &slots(&[])).is_err());
    }
}
