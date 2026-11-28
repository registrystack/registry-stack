// SPDX-License-Identifier: Apache-2.0

//! Request correlation at the Base Registry Engine HTTP boundary.

use std::time::Instant;

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::{Arc, Mutex, PoisonError};

use registry_platform_authcommon::{record_refusal, DeclaredScope, FailedCheck, RefusalNote};
use registry_platform_httpsec::{Problem, ProblemBody, TraceContext, TraceId};
use serde_json::Value;
use uuid::Uuid;

/// BReg-owned request identifier and the effective W3C trace context.
///
/// `request_id` is always freshly minted by Base Registry Engine. The trace may
/// retain one valid inbound `traceparent`, as defined by the shared platform
/// parser, but caller-supplied `tracestate` is never reflected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestCorrelation {
    request_id: Uuid,
    trace: TraceContext,
    declared_scope: DeclaredScopeSlot,
}

/// The operator-declared values of the scope check a request failed. A scope
/// refusal fills it, the recording layer reads it, and nothing in it is
/// written to the response. Every clone of one request's correlation shares
/// the slot.
#[derive(Clone, Debug, Default)]
pub(crate) struct DeclaredScopeSlot(Arc<Mutex<Option<DeclaredScope>>>);

impl DeclaredScopeSlot {
    pub(crate) fn set(&self, declared: DeclaredScope) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(declared);
    }

    fn get(&self) -> Option<DeclaredScope> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

// The slot is bookkeeping for the recording layer, not part of a
// correlation's identity.
impl PartialEq for DeclaredScopeSlot {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for DeclaredScopeSlot {}

impl RequestCorrelation {
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            trace: TraceContext::from_headers(headers),
            declared_scope: DeclaredScopeSlot::default(),
        }
    }

    #[must_use]
    pub fn breg_created() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            trace: TraceContext::server_created(),
            declared_scope: DeclaredScopeSlot::default(),
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    #[must_use]
    pub fn trace_id(&self) -> &TraceId {
        &self.trace.trace_id
    }

    pub(crate) fn declared_scope_slot(&self) -> DeclaredScopeSlot {
        self.declared_scope.clone()
    }

    fn apply_trace(&self, headers: &mut HeaderMap) {
        self.trace.apply(headers);
    }
}

/// Absolute deadline shared by HTTP work and database statement budgets.
#[derive(Clone, Copy)]
pub(crate) struct RequestDeadline(pub tokio::time::Instant);

/// Closed public problem metadata used by the correlation boundary.
///
/// Carrying this in response extensions lets the outer timeout/observation
/// layer render the shared [`ProblemBody`] with the exact effective trace ID
/// without parsing or trusting response bytes.
#[derive(Clone)]
pub(crate) struct PublicProblem {
    type_uri: String,
    title: &'static str,
    status: StatusCode,
    detail: &'static str,
    code: &'static str,
    field_path: Option<String>,
    declared_refusal: Option<(String, String)>,
    guard_reason: Option<String>,
    guard_label: Option<String>,
    declared_field: Option<(String, String)>,
    declared_constraint: Option<Box<crate::mutation::RowLocalConstraintViolation>>,
    timer_window_fields: Option<(String, String)>,
    statistical_detail: Option<(&'static str, &'static str)>,
    /// The acceptable search criteria of a refused list, as API field names.
    required_filters: Option<Vec<Vec<String>>>,
}

/// Build one value-free public problem. The boundary replaces this provisional
/// body with [`ProblemBody`] carrying the request's effective trace ID.
///
/// The type is resolved from the code, so every refusal names a type on the
/// shared Registry Stack identifier host and no caller can spell its own.
pub(crate) fn problem_response(
    status: StatusCode,
    title: &'static str,
    detail: &'static str,
    code: &'static str,
) -> Response {
    let type_uri = crate::problem::type_uri(code);
    let problem = PublicProblem {
        type_uri: type_uri.clone(),
        title,
        status,
        detail,
        code,
        field_path: None,
        declared_refusal: None,
        guard_reason: None,
        guard_label: None,
        declared_field: None,
        declared_constraint: None,
        timer_window_fields: None,
        statistical_detail: None,
        required_filters: None,
    };
    let mut response = Problem::new(&type_uri, title, status)
        .detail(detail)
        .with_extra("code", Value::String(code.to_owned()))
        .into_response();
    response.extensions_mut().insert(problem);
    response
}

/// Name the check a refusal failed. The member rides in the response
/// extensions to [`finish_response`], which counts it and writes the one
/// bounded log line. It is never serialized, so the answer's bytes do not
/// change.
pub(crate) fn note_refusal(response: Response, check: FailedCheck) -> Response {
    attach_refusal_note(response, RefusalNote::new(check))
}

/// [`note_refusal`] with a whole note, so a remedy reaches the log line.
pub(crate) fn attach_refusal_note(mut response: Response, note: RefusalNote) -> Response {
    response.extensions_mut().insert(note);
    response
}

/// Build one public problem with a safe action field path.
///
/// The field path is produced only from fixed envelope members or compiled
/// public names that were already admitted for this action surface.
pub(crate) fn problem_response_with_field_path(
    status: StatusCode,
    title: &'static str,
    detail: &'static str,
    code: &'static str,
    field_path: impl Into<String>,
) -> Response {
    let type_uri = crate::problem::type_uri(code);
    let field_path = field_path.into();
    let problem = PublicProblem {
        type_uri: type_uri.clone(),
        title,
        status,
        detail,
        code,
        field_path: Some(field_path.clone()),
        declared_refusal: None,
        guard_reason: None,
        guard_label: None,
        declared_field: None,
        declared_constraint: None,
        timer_window_fields: None,
        statistical_detail: None,
        required_filters: None,
    };
    let mut response = Problem::new(&type_uri, title, status)
        .detail(detail)
        .with_extra("code", Value::String(code.to_owned()))
        .with_extra("fieldPath", Value::String(field_path))
        .into_response();
    response.extensions_mut().insert(problem);
    response
}

/// Dependency locations come only from a matched compiled capability. Unknown
/// aliases never enter this field, and JSON Pointer escaping preserves one segment.
pub(crate) fn action_evidence_failure_response(capability: Option<String>) -> Response {
    let status = StatusCode::SERVICE_UNAVAILABLE;
    let code = "action.evidence_failed";
    let detail = "The declared Evidence dependency could not be accepted.";
    let path = capability
        .map(|id| format!("/evidence/{}", id.replace('~', "~0").replace('/', "~1")))
        .filter(|path| path.len() <= 256);
    if let Some(path) = path {
        problem_response_with_field_path(status, "Service Unavailable", detail, code, path)
    } else {
        problem_response(status, "Service Unavailable", detail, code)
    }
}

/// Render only a verified, package-declared refusal. Script-supplied strings
/// never reach this boundary; the evaluator resolves labels from the catalogue.
pub(crate) fn action_refusal_response(
    refusal: crate::action_handler::ActionHandlerRefusal,
) -> Response {
    let code = crate::problem::ProblemCode::ActionRefused;
    let mut response = problem_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        code.title(),
        code.description(),
        code.code(),
    );
    let problem = response
        .extensions_mut()
        .get_mut::<PublicProblem>()
        .expect("problem response carries public metadata");
    problem.field_path = refusal
        .field
        .map(|field| format!("/input/{}", field.replace('~', "~0").replace('/', "~1")));
    problem.declared_refusal = Some((refusal.code, refusal.label));
    response
}

/// Called only after the ordinary guard and boundary disclosure recheck. The
/// authored label, when the guard has one, replaces the generic `detail`.
pub(crate) fn action_guard_failure_response(
    reason: Option<String>,
    label: Option<String>,
) -> Response {
    let code = crate::problem::ProblemCode::ActionGuardFailed;
    let mut response = problem_response(
        StatusCode::PRECONDITION_FAILED,
        code.title(),
        code.description(),
        code.code(),
    );
    let problem = response
        .extensions_mut()
        .get_mut::<PublicProblem>()
        .expect("problem metadata");
    problem.guard_reason = reason;
    problem.guard_label = label;
    response
}

pub(crate) fn statistics_problem(
    code: crate::problem::ProblemCode,
    detail: Option<(&'static str, &'static str)>,
) -> Response {
    let mut response = problem_response(
        StatusCode::from_u16(code.status()).expect("catalogue status"),
        code.title(),
        code.description(),
        code.code(),
    );
    response
        .extensions_mut()
        .get_mut::<PublicProblem>()
        .expect("problem metadata")
        .statistical_detail = detail;
    response
}

pub(crate) fn field_pattern_response(entity: String, field: String) -> Response {
    let mut response = problem_response(
        StatusCode::CONFLICT,
        "Conflict",
        "The field does not conform to its declared storage pattern.",
        "mutation.conflict",
    );
    response
        .extensions_mut()
        .get_mut::<PublicProblem>()
        .expect("problem response carries public metadata")
        .declared_field = Some((entity, field));
    response
}

pub(crate) fn row_local_constraint_response(
    violation: Box<crate::mutation::RowLocalConstraintViolation>,
) -> Response {
    let mut response = problem_response(
        StatusCode::CONFLICT,
        "Conflict",
        "The mutation conflicts with current state.",
        "mutation.conflict",
    );
    response
        .extensions_mut()
        .get_mut::<PublicProblem>()
        .expect("problem response carries public metadata")
        .declared_constraint = Some(violation);
    response
}

/// Name both authored timer controls only after the owning API surface has
/// established read authority for both fields. A partial pair would reveal
/// one masked field and is therefore never rendered.
pub(crate) fn timer_window_response(at_field: String, not_after_field: String) -> Response {
    let mut response = problem_response(
        StatusCode::BAD_REQUEST,
        "Bad Request",
        "The request is invalid.",
        "request.invalid",
    );
    response
        .extensions_mut()
        .get_mut::<PublicProblem>()
        .expect("problem response carries public metadata")
        .timer_window_fields = Some((at_field, not_after_field));
    response
}

/// Refuse a list that did not pin one of the alternative search criteria its
/// grant requires. The alternatives are API field names the caller already
/// reads from the surface's `filterableFields`, so naming them discloses
/// nothing further. `requiredFilters` carries them, and the detail stays the
/// fixed description of the code, so it keeps within the documented bound.
pub(crate) fn filter_required_response(alternatives: Vec<Vec<String>>) -> Response {
    let code = crate::problem::ProblemCode::QueryFilterRequired;
    let mut response = problem_response(
        StatusCode::BAD_REQUEST,
        code.title(),
        code.description(),
        code.code(),
    );
    response
        .extensions_mut()
        .get_mut::<PublicProblem>()
        .expect("problem response carries public metadata")
        .required_filters = Some(alternatives);
    response
}

/// Observe a router that is not already owned by an outer correlation layer.
/// Nested use is deliberately idempotent so the production timeout wrapper
/// and focused test routers share one request ID and emit one log record.
pub(crate) async fn observe(mut request: Request<Body>, next: Next) -> Response {
    if request.extensions().get::<RequestCorrelation>().is_some() {
        return next.run(request).await;
    }
    let correlation = RequestCorrelation::from_headers(request.headers());
    request.extensions_mut().insert(correlation.clone());
    let method = method_name(request.method());
    let started = Instant::now();
    let response = next.run(request).await;
    finish_response(response, &correlation, method, started)
}

/// Establish correlation for an outer boundary such as the request timeout.
pub(crate) fn begin_request(request: &mut Request<Body>) -> (RequestCorrelation, bool) {
    if let Some(correlation) = request.extensions().get::<RequestCorrelation>() {
        return (correlation.clone(), false);
    }
    let correlation = RequestCorrelation::from_headers(request.headers());
    request.extensions_mut().insert(correlation.clone());
    (correlation, true)
}

/// Render correlated problem details, attach the effective trace, and emit one
/// closed operational request record when this layer owns the boundary.
pub(crate) fn finish_response(
    response: Response,
    correlation: &RequestCorrelation,
    method: &'static str,
    started: Instant,
) -> Response {
    let elapsed = started.elapsed();
    let problem = response.extensions().get::<PublicProblem>().cloned();
    let mut response = if let Some(problem) = &problem {
        let (mut parts, _) = response.into_parts();
        let body = ProblemBody {
            type_uri: problem.type_uri.clone(),
            title: problem.title,
            status: problem.status.as_u16(),
            detail: problem.detail,
            code: problem.code,
            trace_id: correlation.trace_id().clone(),
        };
        let mut value =
            serde_json::to_value(&body).expect("ProblemBody serialization is infallible");
        let object = value
            .as_object_mut()
            .expect("ProblemBody serializes as an object");
        if let Some(field_path) = &problem.field_path {
            object.insert("fieldPath".to_owned(), Value::String(field_path.clone()));
        }
        if let Some((code, label)) = &problem.declared_refusal {
            object.insert("refusalCode".to_owned(), Value::String(code.clone()));
            object.insert("detail".to_owned(), Value::String(label.clone()));
        }
        if let Some(reason) = &problem.guard_reason {
            object.insert("guardReason".to_owned(), Value::String(reason.clone()));
            // A label is authored beside its reason, so it rides only where the
            // reason does.
            if let Some(label) = &problem.guard_label {
                object.insert("detail".to_owned(), Value::String(label.clone()));
            }
        }
        if let Some((name, value)) = problem.statistical_detail {
            object.insert(name.to_owned(), Value::String(value.to_owned()));
        }
        if let Some((entity, field)) = &problem.declared_field {
            object.insert("recordType".to_owned(), Value::String(entity.clone()));
            object.insert("fieldId".to_owned(), Value::String(field.clone()));
        }
        if let Some(constraint) = &problem.declared_constraint {
            let constraint = constraint.as_ref();
            let (record_type, constraint_id, kind) = match constraint {
                crate::mutation::RowLocalConstraintViolation::Compare {
                    record_type,
                    constraint_id,
                    ..
                } => (record_type, constraint_id, "compare"),
                crate::mutation::RowLocalConstraintViolation::IntRange {
                    record_type,
                    constraint_id,
                    ..
                } => (record_type, constraint_id, "int-range"),
                crate::mutation::RowLocalConstraintViolation::Vocabulary {
                    record_type,
                    constraint_id,
                    ..
                } => (record_type, constraint_id, "vocabulary"),
            };
            object.insert("recordType".to_owned(), Value::String(record_type.clone()));
            object.insert(
                "constraintId".to_owned(),
                Value::String(constraint_id.clone()),
            );
            object.insert("constraintKind".to_owned(), Value::String(kind.to_owned()));
            match constraint {
                crate::mutation::RowLocalConstraintViolation::Compare { left, right, .. } => {
                    object.insert("left".to_owned(), Value::String(left.clone()));
                    object.insert("right".to_owned(), Value::String(right.clone()));
                }
                crate::mutation::RowLocalConstraintViolation::IntRange { field, .. }
                | crate::mutation::RowLocalConstraintViolation::Vocabulary { field, .. } => {
                    object.insert("field".to_owned(), Value::String(field.clone()));
                }
            }
        }
        if let Some(alternatives) = &problem.required_filters {
            object.insert(
                "requiredFilters".to_owned(),
                serde_json::json!(alternatives),
            );
        }
        if let Some((at_field, not_after_field)) = &problem.timer_window_fields {
            object.insert("atField".to_owned(), Value::String(at_field.clone()));
            object.insert(
                "notAfterField".to_owned(),
                Value::String(not_after_field.clone()),
            );
        }
        let body = serde_json::to_vec(&value).expect("ProblemBody serialization is infallible");
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.insert(
            CONTENT_TYPE,
            "application/problem+json"
                .parse()
                .expect("problem content type is valid"),
        );
        Response::from_parts(parts, Body::from(body))
    } else {
        response
    };
    if problem.is_some() {
        response.headers_mut().insert(
            CACHE_CONTROL,
            "no-store".parse().expect("cache policy is valid"),
        );
    }
    correlation.apply_trace(response.headers_mut());
    if let Some(problem) = &problem {
        if matches!(problem.status.as_u16(), 401 | 403)
            && response.extensions().get::<RefusalNote>().is_none()
        {
            debug_assert!(false, "a refusal was answered without its failed check");
            tracing::error!(
                code = problem.code,
                "a refusal was answered without its failed check"
            );
        }
    }
    record_noted_refusal(&response, correlation);

    let status = status_class(response.status());
    let problem_code = problem.as_ref().map_or("none", |problem| problem.code);
    tracing::info!(
        target: "registry_breg::request",
        method,
        request_id = %correlation.request_id(),
        trace_id = correlation.trace_id().as_str(),
        duration_ms = duration_milliseconds(elapsed),
        status,
        problem_code,
        "Base Registry Engine request served"
    );
    response
}

/// Count and log the refusal a response carries, if any. A handler that folds
/// several refused items into one answer calls this for each item, because the
/// folded answer is not itself a refusal.
pub(crate) fn record_noted_refusal(response: &Response, correlation: &RequestCorrelation) {
    if let Some(note) = response.extensions().get::<RefusalNote>().copied() {
        record_refusal_note(note, correlation);
    }
}

/// Count and log one refusal check on the operator side without attaching a
/// [`RefusalNote`] to the response. Used when a concealed `412` must stay
/// indistinguishable on the wire from an unknown target in development as well
/// as production, while still counting under its check in metrics and logs.
pub(crate) fn record_refusal_check(check: FailedCheck, correlation: &RequestCorrelation) {
    record_refusal_note(RefusalNote::new(check), correlation);
}

fn record_refusal_note(note: RefusalNote, correlation: &RequestCorrelation) {
    let declared = correlation.declared_scope.get();
    record_refusal!(
        crate::metrics::process_refusal_recorder(),
        note,
        trace_id = correlation.trace_id(),
        declared = declared.as_ref()
    );
}

pub(crate) fn method_name(method: &axum::http::Method) -> &'static str {
    match *method {
        axum::http::Method::GET => "GET",
        axum::http::Method::POST => "POST",
        axum::http::Method::PATCH => "PATCH",
        axum::http::Method::DELETE => "DELETE",
        axum::http::Method::HEAD => "HEAD",
        axum::http::Method::OPTIONS => "OPTIONS",
        _ => "OTHER",
    }
}

pub(crate) fn status_class(status: StatusCode) -> &'static str {
    if status.is_server_error() {
        "server-error"
    } else if status.is_client_error() {
        "client-error"
    } else {
        "success"
    }
}

fn duration_milliseconds(elapsed: std::time::Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod refusal_guard_tests {
    use super::*;

    fn refusal_statuses() -> [StatusCode; 2] {
        [
            StatusCode::from_u16(401).expect("401 is a status"),
            StatusCode::FORBIDDEN,
        ]
    }

    fn finish(response: Response) -> Response {
        let correlation = RequestCorrelation::from_headers(&HeaderMap::new());
        finish_response(response, &correlation, "GET", Instant::now())
    }

    #[test]
    fn a_401_or_403_with_its_check_is_answered_unchanged() {
        for status in refusal_statuses() {
            let response = note_refusal(
                problem_response(status, "Refused", "Refused.", "authentication.refused"),
                FailedCheck::CredentialMissing,
            );
            assert_eq!(finish(response).status(), status);
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn a_401_or_403_without_a_check_stops_a_debug_build() {
        for status in refusal_statuses() {
            let outcome = std::panic::catch_unwind(|| {
                finish(problem_response(
                    status,
                    "Refused",
                    "Refused.",
                    "authentication.refused",
                ))
            });
            assert!(outcome.is_err(), "{status} was answered without a check");
        }
    }

    #[test]
    fn a_404_without_a_check_is_an_unknown_route() {
        let response = finish(problem_response(
            StatusCode::NOT_FOUND,
            "Not Found",
            "The requested resource was not found.",
            "resource.not_found",
        ));
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    async fn body_of(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("the problem body reads");
        serde_json::from_slice(&bytes).expect("the problem body is JSON")
    }

    #[tokio::test]
    async fn a_guard_label_replaces_the_detail_only_beside_its_reason() {
        let label = "Only a submitted application can be approved.";
        let labelled = body_of(finish(note_refusal(
            action_guard_failure_response(Some("not-submitted".into()), Some(label.into())),
            FailedCheck::ActionGuard,
        )))
        .await;
        assert_eq!(labelled["code"], "action.guard_failed");
        assert_eq!(labelled["guardReason"], "not-submitted");
        assert_eq!(labelled["detail"], label);

        let plain = body_of(finish(note_refusal(
            action_guard_failure_response(Some("not-submitted".into()), None),
            FailedCheck::ActionGuard,
        )))
        .await;
        assert_eq!(plain["detail"], "The action guard was not satisfied.");

        // A label never rides without the reason it is authored beside.
        let orphan = body_of(finish(note_refusal(
            action_guard_failure_response(None, Some(label.into())),
            FailedCheck::ActionGuard,
        )))
        .await;
        assert_eq!(orphan["detail"], "The action guard was not satisfied.");
        assert!(orphan.get("guardReason").is_none());
        assert!(!orphan.to_string().contains(label));
    }

    #[test]
    fn record_refusal_check_counts_without_attaching_a_response_note() {
        let recorder = crate::metrics::process_refusal_recorder();
        let before = recorder
            .counter()
            .get(&[FailedCheck::ActionGuard.as_str()])
            .unwrap_or(0);
        let correlation = RequestCorrelation::from_headers(&HeaderMap::new());
        record_refusal_check(FailedCheck::ActionGuard, &correlation);
        let response = finish_response(
            problem_response(
                StatusCode::PRECONDITION_FAILED,
                "Precondition Failed",
                "The mutation precondition failed.",
                "precondition.failed",
            ),
            &correlation,
            "POST",
            Instant::now(),
        );
        let after = recorder
            .counter()
            .get(&[FailedCheck::ActionGuard.as_str()])
            .unwrap_or(0);
        assert!(after > before, "operator refusal counter must advance");
        assert!(
            response.extensions().get::<RefusalNote>().is_none(),
            "concealed 412 must carry no RefusalNote for development body rewriting"
        );
    }
}
