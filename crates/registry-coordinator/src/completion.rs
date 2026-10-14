// SPDX-License-Identifier: Apache-2.0
//! The review completion receiver. Casework's completion destination for a
//! producer connection posts here when a review result exists. An event only
//! wakes the step waiting on that request: the step then reads the result with
//! the connection's producer credential, and only that read can settle it.

use crate::{
    http::problem, metrics::AuthenticationRefusal, protocol::AdapterSet, store::Store,
    CoordinatorError,
};
use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use registry_review_protocol::ReviewCompletion;
use uuid::Uuid;

/// Interpret one bounded external observation using the pinned pure Function.
/// The original saved command is the only correlation input; mappings are not
/// evaluated again while waiting. Invalid evidence remains a recovery hold.
pub(crate) fn interpret_poll(
    definition: &crate::definition::Definition,
    request: &crate::protocol::CallRequest,
    completion: &crate::definition::CompletionDefinition,
    response: serde_json::Value,
    synthetic: bool,
) -> crate::protocol::CompletionObservation {
    use crate::{definition::CompletionKind, protocol::CompletionObservation};
    let hold = || CompletionObservation::Hold {
        code: "completion-invalid-response".into(),
    };
    let CompletionKind::BoundedPoll { interpret, .. } = &completion.kind else {
        return hold();
    };
    let Some(operation) = definition.workflow.operations.values().find(|operation| {
        operation.uses == request.operation
            && operation.connection == request.connection
            && operation
                .completions
                .values()
                .any(|candidate| candidate == completion)
    }) else {
        return hold();
    };
    let Ok(schema) = crate::definition::compile_schema(&operation.output) else {
        return hold();
    };
    if crate::functions::check_value(&response).is_err() || !schema.is_valid(&response) {
        return hold();
    }
    let inputs = serde_json::json!({"command":request.input,"response":response});
    let Ok(value) = definition.evaluate_function(interpret, &inputs, synthetic) else {
        return CompletionObservation::Hold {
            code: "completion-interpretation-failed".into(),
        };
    };
    match value.get("state").and_then(serde_json::Value::as_str) {
        Some("pending") => CompletionObservation::Pending { retry_after: None },
        Some("complete" | "refused")
            if crate::contracts::completion_contract(completion)
                .check(&value)
                .is_ok() =>
        {
            CompletionObservation::Settled(value)
        }
        _ => hold(),
    }
}

/// The header naming the recipient binding Casework's destination declares.
pub const RECIPIENT_BINDING_HEADER: &str = "registry-recipient-binding";
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const MAXIMUM_BODY_BYTES: usize = 2048;
/// The oldest completion still accepted: Casework retries a delivery for at
/// most this long.
const OLDEST_COMPLETION_DAYS: i64 = 365;
/// The clock difference tolerated for a completion stamped in the future.
const FUTURE_COMPLETION_MINUTES: i64 = 5;

/// Accept one completion event. Every authentic, well-formed event answers 204
/// whether or not a step waits on its request, so the answer never reveals
/// which requests this deployment holds.
pub async fn receive_review_completion(
    store: &Store,
    adapters: &dyn AdapterSet,
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Response {
    let (connection, request) = match authenticate(adapters, headers, body, Utc::now()) {
        Ok(event) => event,
        Err(error) => {
            if error.code == "access.unauthenticated" {
                store
                    .metrics()
                    .record_authentication_refusal(AuthenticationRefusal::Refused);
            }
            return problem(error);
        }
    };
    match store.wake(&connection, request).await {
        Ok(()) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(_) => problem(CoordinatorError::new(
            "store-unavailable",
            "the completion could not be recorded; deliver it again later",
        )),
    }
}

/// The connection whose completion credential and recipient binding the
/// sender presented, and the request its event names. The sender is
/// authenticated before the media type or body is examined.
pub(crate) fn authenticate(
    adapters: &dyn AdapterSet,
    headers: &HeaderMap,
    body: Option<&[u8]>,
    now: DateTime<Utc>,
) -> Result<(String, Uuid), CoordinatorError> {
    let refused = || {
        CoordinatorError::new(
            "access.unauthenticated",
            "a configured completion credential and recipient binding are required",
        )
    };
    let token = single_header(headers, header::AUTHORIZATION.as_str())
        .and_then(|value| registry_platform_authcommon::parse_bearer_token(value).ok())
        .ok_or_else(refused)?;
    let recipient = single_header(headers, RECIPIENT_BINDING_HEADER).ok_or_else(refused)?;
    let connection = adapters
        .review_completion(token, recipient)
        .ok_or_else(refused)?;
    if single_header(headers, header::CONTENT_TYPE.as_str()) != Some("application/json") {
        return Err(CoordinatorError::new(
            "request.content-type-invalid",
            "supply application/json",
        ));
    }
    let invalid = || {
        CoordinatorError::new(
            "request.invalid",
            "supply one bounded review completion event",
        )
    };
    let key = single_header(headers, IDEMPOTENCY_KEY_HEADER).ok_or_else(invalid)?;
    let body = body
        .filter(|body| !body.is_empty() && body.len() <= MAXIMUM_BODY_BYTES)
        .ok_or_else(invalid)?;
    let value = registry_platform_canonical_json::parse_json_strict(body).map_err(|_| invalid())?;
    let event: ReviewCompletion = serde_json::from_value(value).map_err(|_| invalid())?;
    if key != event.event_id.to_string()
        || event.event_id.is_nil()
        || event.request_id.is_nil()
        || event.result_id.is_nil()
        || !completed_at_is_acceptable(event.completed_at, now)
    {
        return Err(invalid());
    }
    Ok((connection, event.request_id))
}

fn completed_at_is_acceptable(completed_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    completed_at >= now - chrono::Duration::days(OLDEST_COMPLETION_DAYS)
        && completed_at <= now + chrono::Duration::minutes(FUTURE_COMPLETION_MINUTES)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{CallOutcome, CallRequest};
    use async_trait::async_trait;
    use serde_json::json;

    const TOKEN: &str = "synthetic-completion-token-0123456789abcdef";
    const RECIPIENT: &str = "coordinator-v1";

    struct Receiver;

    #[async_trait]
    impl AdapterSet for Receiver {
        fn binding_digest(&self) -> &str {
            "fixture-binding"
        }

        async fn call(&self, _: &CallRequest) -> CallOutcome {
            unreachable!("the receiver never calls a product")
        }

        fn review_completion(&self, token: &str, recipient: &str) -> Option<String> {
            (token == TOKEN && recipient == RECIPIENT).then(|| "review".to_owned())
        }
    }

    fn headers(event: Uuid) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap(),
        );
        headers.insert(
            RECIPIENT_BINDING_HEADER,
            HeaderValue::from_static(RECIPIENT),
        );
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_str(&event.to_string()).unwrap(),
        );
        headers
    }

    fn body(event: Uuid, request: Uuid, completed_at: DateTime<Utc>) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": "review.completed",
            "eventId": event,
            "requestId": request,
            "resultId": Uuid::new_v4(),
            "completedAt": completed_at.to_rfc3339(),
        }))
        .unwrap()
    }

    fn code(result: Result<(String, Uuid), CoordinatorError>) -> String {
        match result {
            Ok(_) => "accepted".into(),
            Err(error) => error.code,
        }
    }

    #[test]
    fn an_authentic_event_names_its_connection_and_request() {
        let (event, request, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let accepted = authenticate(
            &Receiver,
            &headers(event),
            Some(&body(event, request, now)),
            now,
        )
        .unwrap();
        assert_eq!(accepted, ("review".to_owned(), request));
    }

    #[test]
    fn a_sender_without_the_configured_credential_and_binding_is_refused_before_its_body() {
        let event = Uuid::new_v4();
        let mut cases = Vec::new();
        let mut forged = headers(event);
        forged.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer another-synthetic-token-0123456789"),
        );
        cases.push(("forged token", forged));
        let mut basic = headers(event);
        basic.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic c3ludGhldGlj"),
        );
        cases.push(("another scheme", basic));
        let mut absent = headers(event);
        absent.remove(header::AUTHORIZATION);
        cases.push(("no credential", absent));
        let mut doubled = headers(event);
        doubled.append(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap(),
        );
        cases.push(("two credentials", doubled));
        let mut other = headers(event);
        other.insert(
            RECIPIENT_BINDING_HEADER,
            HeaderValue::from_static("another-recipient"),
        );
        cases.push(("another recipient", other));
        let mut unbound = headers(event);
        unbound.remove(RECIPIENT_BINDING_HEADER);
        cases.push(("no recipient", unbound));
        let mut two = headers(event);
        two.append(
            RECIPIENT_BINDING_HEADER,
            HeaderValue::from_static(RECIPIENT),
        );
        cases.push(("two recipients", two));
        for (case, headers) in cases {
            // The body is not even JSON: authentication answers first.
            assert_eq!(
                code(authenticate(&Receiver, &headers, Some(b"{"), Utc::now())),
                "access.unauthenticated",
                "{case}"
            );
        }
    }

    #[test]
    fn an_authenticated_event_needs_exactly_the_json_media_type() {
        let (event, now) = (Uuid::new_v4(), Utc::now());
        let body = body(event, Uuid::new_v4(), now);
        for media in [
            Some("text/plain"),
            Some("application/json; charset=utf-8"),
            None,
        ] {
            let mut headers = headers(event);
            match media {
                Some(media) => {
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(media));
                }
                None => {
                    headers.remove(header::CONTENT_TYPE);
                }
            }
            assert_eq!(
                code(authenticate(&Receiver, &headers, Some(&body), now)),
                "request.content-type-invalid",
                "{media:?}"
            );
        }
    }

    #[test]
    fn an_authenticated_event_must_be_one_bounded_well_formed_completion() {
        let (event, request, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let valid = body(event, request, now);
        let field = |name: &str, value: serde_json::Value| {
            let mut object: serde_json::Value = serde_json::from_slice(&valid).unwrap();
            object[name] = value;
            serde_json::to_vec(&object).unwrap()
        };
        let mut extra: serde_json::Value = serde_json::from_slice(&valid).unwrap();
        extra["result"] = json!({"status": "approved"});
        let cases: Vec<(&str, Option<Vec<u8>>)> = vec![
            ("no body", None),
            ("an empty body", Some(Vec::new())),
            (
                "an oversized body",
                Some(vec![b' '; MAXIMUM_BODY_BYTES + 1]),
            ),
            ("malformed JSON", Some(b"{".to_vec())),
            (
                "a duplicate member",
                Some(br#"{"type":"review.completed","type":"review.completed"}"#.to_vec()),
            ),
            (
                "another event type",
                Some(field("type", json!("review.cancelled"))),
            ),
            (
                "a nil request",
                Some(field("requestId", json!(Uuid::nil()))),
            ),
            ("a nil result", Some(field("resultId", json!(Uuid::nil())))),
            (
                "a carried result",
                Some(serde_json::to_vec(&extra).unwrap()),
            ),
            (
                "a stale completion",
                Some(field(
                    "completedAt",
                    json!((now - chrono::Duration::days(366)).to_rfc3339()),
                )),
            ),
            (
                "a future completion",
                Some(field(
                    "completedAt",
                    json!((now + chrono::Duration::minutes(6)).to_rfc3339()),
                )),
            ),
        ];
        for (case, body) in cases {
            assert_eq!(
                code(authenticate(
                    &Receiver,
                    &headers(event),
                    body.as_deref(),
                    now
                )),
                "request.invalid",
                "{case}"
            );
        }
        let mut replayed = headers(event);
        replayed.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
        );
        let mut unkeyed = headers(event);
        unkeyed.remove(IDEMPOTENCY_KEY_HEADER);
        for (case, headers) in [("another event key", replayed), ("no event key", unkeyed)] {
            assert_eq!(
                code(authenticate(&Receiver, &headers, Some(&valid), now)),
                "request.invalid",
                "{case}"
            );
        }
        let nil = Uuid::nil();
        assert_eq!(
            code(authenticate(
                &Receiver,
                &headers(nil),
                Some(&body(nil, request, now)),
                now
            )),
            "request.invalid",
            "a nil event"
        );
    }

    #[test]
    fn a_completion_within_its_delivery_window_is_accepted() {
        let now = Utc::now();
        for completed_at in [
            now - chrono::Duration::days(OLDEST_COMPLETION_DAYS),
            now,
            now + chrono::Duration::minutes(FUTURE_COMPLETION_MINUTES),
        ] {
            assert!(completed_at_is_acceptable(completed_at, now));
        }
    }

    #[test]
    fn a_refusal_carries_no_presented_value() {
        let event = Uuid::new_v4();
        let mut forged = headers(event);
        forged.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer forged-canary-token-0123456789"),
        );
        let request = Uuid::new_v4();
        for headers in [forged, headers(Uuid::new_v4())] {
            let error = authenticate(
                &Receiver,
                &headers,
                Some(&body(event, request, Utc::now())),
                Utc::now(),
            )
            .unwrap_err();
            let rendered = format!("{} {:?}", error.message, error.suggested_action);
            for secret in [
                "forged-canary",
                TOKEN,
                RECIPIENT,
                &event.to_string(),
                &request.to_string(),
            ] {
                assert!(!rendered.contains(secret), "{rendered}");
            }
        }
    }
}
