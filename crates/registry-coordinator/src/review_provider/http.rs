// SPDX-License-Identifier: Apache-2.0
//! The producer-facing Review protocol over the ordinary Coordinator runtime.
use crate::{
    access::{Action, Caller},
    deployment,
    http::{BoundedBody, HttpState},
    store::ReviewLookup,
    CoordinatorError, Result,
};
use axum::{
    extract::{
        rejection::{PathRejection, QueryRejection},
        Path, Query, State,
    },
    http::{
        header::{CONTENT_TYPE, RETRY_AFTER},
        HeaderMap, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use registry_review_protocol::{ReviewCancelRequest, ReviewCreateRequest, REVIEW_PROFILE_HEADER};
use serde::{de::DeserializeOwned, Deserialize};
use uuid::Uuid;

pub(crate) fn router() -> Router<HttpState> {
    Router::new()
        .route("/v1/review-requests", post(create))
        .route("/v1/review-requests/{request}", get(status))
        .route("/v1/review-requests/{request}/result", get(result))
        .route("/v1/review-requests/{request}/cancel", post(cancel))
        .route("/v1/review-results", get(feed))
}

async fn producer(s: &HttpState, headers: &HeaderMap, action: Action) -> Result<Caller> {
    let caller = crate::http::caller(s, headers).await?;
    caller.authorize(action, None)?;
    let values = headers
        .get_all(REVIEW_PROFILE_HEADER)
        .iter()
        .collect::<Vec<_>>();
    let profile = match values.as_slice() {
        [profile] => profile.to_str().ok(),
        _ => None,
    }
    .ok_or_else(|| {
        CoordinatorError::new(
            "access.denied",
            "select the admitted Review producer profile",
        )
    })?;
    caller.review_producer(profile)?;
    Ok(caller)
}

fn binding<'a>(caller: &'a Caller, headers: &HeaderMap) -> Result<&'a super::ReviewProducer> {
    caller.review_producer(
        headers
            .get(REVIEW_PROFILE_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
    )
}

fn key(headers: &HeaderMap) -> Result<&str> {
    let values = headers
        .get_all("idempotency-key")
        .iter()
        .collect::<Vec<_>>();
    match values.as_slice() {
        [key] => key.to_str().ok().filter(|key| {
            !key.is_empty() && key.len() <= 256 && !key.chars().any(char::is_control)
        }),
        _ => None,
    }
    .ok_or_else(|| CoordinatorError::new("start-key-invalid", "supply one bounded Idempotency-Key"))
}

async fn body<T: DeserializeOwned>(headers: &HeaderMap, body: BoundedBody) -> Result<T> {
    let bytes = body.map_err(|_| {
        CoordinatorError::new(
            "request.body-too-large",
            "supply a bounded Review JSON object",
        )
    })?;
    if bytes.len() > registry_review_protocol::MAXIMUM_CANONICAL_CREATE_BYTES {
        return Err(CoordinatorError::new(
            "request.body-too-large",
            "supply a bounded Review JSON object",
        ));
    }
    let content = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or_default();
    if content != "application/json"
        && !(content.starts_with("application/") && content.ends_with("+json"))
    {
        return Err(CoordinatorError::new(
            "request.content-type-invalid",
            "supply application/json",
        ));
    }
    let value = registry_platform_canonical_json::parse_json_strict(&bytes)
        .map_err(|_| CoordinatorError::new("request.invalid", "supply unambiguous Review JSON"))?;
    serde_json::from_value(value)
        .map_err(|_| CoordinatorError::new("request.invalid", "supply the declared Review fields"))
}

async fn create(State(s): State<HttpState>, headers: HeaderMap, input: BoundedBody) -> Response {
    let answer = async {
        let caller = producer(&s, &headers, Action::ReviewCreate).await?;
        let request: ReviewCreateRequest = body(&headers, input).await?;
        caller.authorize(Action::ReviewCreate, Some(&request.policy.id))?;
        if s.recovery_only {
            return Err(CoordinatorError::new(
                "recovery-only",
                "Review admissions are disabled during recovery",
            ));
        }
        let package = s.workflows.get(&request.policy.id).ok_or_else(|| {
            CoordinatorError::new(
                "workflow-absent",
                "this deployment does not serve the Review policy",
            )
        })?;
        deployment::check(&s.store, &s.runtime, s.workflows.digest()).await?;
        let runtime_binding = s.runtime.binding_digest_for(&package.definition.workflow)?;
        let accepted = s
            .store
            .admit_review_owned(
                &package.definition,
                request,
                &caller.actor,
                binding(&caller, &headers)?,
                key(&headers)?,
                &runtime_binding,
                &s.runtime,
            )
            .await?;
        Ok((StatusCode::CREATED, Json(accepted)).into_response())
    }
    .await;
    answer_response(answer)
}

async fn status(
    State(s): State<HttpState>,
    headers: HeaderMap,
    id: std::result::Result<Path<String>, PathRejection>,
) -> Response {
    answer_response(
        async {
            let caller = producer(&s, &headers, Action::ReviewRead).await?;
            let id = request_id(id)?;
            let view = s
                .store
                .review_request_owned(
                    id,
                    &caller.actor,
                    binding(&caller, &headers)?,
                    caller.authorized_workflows(Action::ReviewRead)?,
                )
                .await?;
            Ok(Json(view).into_response())
        }
        .await,
    )
}

async fn result(
    State(s): State<HttpState>,
    headers: HeaderMap,
    id: std::result::Result<Path<String>, PathRejection>,
) -> Response {
    let answer = async {
        let caller = producer(&s, &headers, Action::ReviewRead).await?;
        let id = request_id(id)?;
        match s
            .store
            .review_result_owned(
                id,
                &caller.actor,
                binding(&caller, &headers)?,
                caller.authorized_workflows(Action::ReviewRead)?,
            )
            .await
        {
            Ok(ReviewLookup::Available(result)) => Ok(Json(result).into_response()),
            Ok(ReviewLookup::Pending) => {
                Ok((StatusCode::ACCEPTED, [(RETRY_AFTER, "30")]).into_response())
            }
            Ok(ReviewLookup::Expired) => Ok(StatusCode::GONE.into_response()),
            Err(error) if error.code == "run-absent" => Ok(StatusCode::NOT_FOUND.into_response()),
            Err(error) => Err(error),
        }
    }
    .await;
    answer_response(answer)
}

async fn cancel(
    State(s): State<HttpState>,
    headers: HeaderMap,
    id: std::result::Result<Path<String>, PathRejection>,
    input: BoundedBody,
) -> Response {
    answer_response(
        async {
            let caller = producer(&s, &headers, Action::ReviewCancel).await?;
            let id = request_id(id)?;
            // Ownership is checked before parsing protected command content.
            let workflows = caller.authorized_workflows(Action::ReviewCancel)?;
            s.store
                .review_request_owned(id, &caller.actor, binding(&caller, &headers)?, workflows)
                .await
                .map_err(|error| {
                    if error.code == "payload-erased" {
                        CoordinatorError::new(
                            "review-result-expired",
                            "the owned Review result availability expired",
                        )
                    } else {
                        error
                    }
                })?;
            let cancellation: ReviewCancelRequest = body(&headers, input).await?;
            let result = s
                .store
                .cancel_review_owned(
                    id,
                    &caller.actor,
                    binding(&caller, &headers)?,
                    workflows,
                    key(&headers)?,
                    &cancellation,
                )
                .await?;
            Ok(Json(result).into_response())
        }
        .await,
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Feed {
    cursor: Option<Uuid>,
    limit: Option<u32>,
}

async fn feed(
    State(s): State<HttpState>,
    headers: HeaderMap,
    query: std::result::Result<Query<Feed>, QueryRejection>,
) -> Response {
    answer_response(
        async {
            let caller = producer(&s, &headers, Action::ReviewRead).await?;
            let Query(query) = query.map_err(|_| {
                CoordinatorError::new("request.invalid", "supply a bounded Review feed query")
            })?;
            let page = s
                .store
                .review_results_owned(
                    &caller.actor,
                    binding(&caller, &headers)?,
                    caller.authorized_workflows(Action::ReviewRead)?,
                    query.cursor,
                    query.limit.unwrap_or(20),
                )
                .await?;
            Ok(Json(page).into_response())
        }
        .await,
    )
}

fn request_id(path: std::result::Result<Path<String>, PathRejection>) -> Result<Uuid> {
    let Path(id) = path.map_err(|_| {
        CoordinatorError::new("request.invalid", "supply a bounded Review request UUID")
    })?;
    if id.len() > 45 {
        return Err(CoordinatorError::new(
            "request.invalid",
            "supply a bounded Review request UUID",
        ));
    }
    Uuid::parse_str(&id)
        .map_err(|_| CoordinatorError::new("request.invalid", "supply a Review request UUID"))
}

fn answer_response(answer: Result<Response>) -> Response {
    match answer {
        Ok(response) => response,
        Err(error) => {
            let unsupported = error.code == "request.invalid"
                && error.field.as_deref() == Some("$.resultConstraints");
            let mut response = crate::http::problem(error);
            if unsupported {
                response.headers_mut().insert(
                    registry_review_protocol::REVIEW_VALIDATION_PATH_HEADER,
                    axum::http::HeaderValue::from_static("$.resultConstraints"),
                );
                response.headers_mut().insert(
                    registry_review_protocol::REVIEW_VALIDATION_REASON_HEADER,
                    axum::http::HeaderValue::from_static("result-not-declared"),
                );
            }
            response
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn unsupported_constraints_name_the_shared_protocol_field_and_reason() {
        let response = super::answer_response(Err(crate::CoordinatorError::new(
            "request.invalid",
            "structured results are not declared",
        )
        .at("request", "$.resultConstraints")));
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()[registry_review_protocol::REVIEW_VALIDATION_PATH_HEADER],
            "$.resultConstraints"
        );
        assert_eq!(
            response.headers()[registry_review_protocol::REVIEW_VALIDATION_REASON_HEADER],
            "result-not-declared"
        );
    }
}
