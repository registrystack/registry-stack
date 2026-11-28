// SPDX-License-Identifier: Apache-2.0
//! The review completion receiver. Casework's completion destination for a
//! producer connection posts here when a review result exists. An event only
//! wakes the step waiting on that request: the step then reads the result with
//! the connection's producer credential, and only that read can settle it.

use crate::{
    http::{problem, single_header, WEBHOOK_CHALLENGE},
    metrics::AuthenticationRefusal,
    protocol::AdapterSet,
    store::Store,
    CoordinatorError,
};
use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use registry_platform_authcommon::FailedCheck;
use registry_platform_crypto::delivery_signature::{
    self, DeliverySignatureError, SignedContent, DELIVERY_TOLERANCE,
};
use registry_review_protocol::ReviewCompletion;
use uuid::Uuid;

/// Interpret one bounded external observation using the pinned pure Function.
/// The original saved command is the only correlation input; mappings are not
/// evaluated again while waiting. Invalid evidence remains a recovery hold.
pub(crate) fn interpret_poll(
    definition: &crate::definition::Definition,
    request: &crate::protocol::CallRequest,
    reference: &crate::definition::CompletionReference,
    response: serde_json::Value,
    synthetic: bool,
) -> crate::protocol::CompletionObservation {
    use crate::{definition::CompletionKind, protocol::CompletionObservation};
    let hold = || CompletionObservation::Hold {
        code: "completion-invalid-response".into(),
    };
    let Ok(completion) = definition.completion(reference) else {
        return hold();
    };
    let CompletionKind::BoundedPoll { interpret, .. } = &completion.kind else {
        return hold();
    };
    let Some(crate::definition::Step::Call { call, .. }) =
        definition.workflow.steps.get(&reference.step)
    else {
        return hold();
    };
    if request.operation != call.operation || request.connection != call.connection {
        return hold();
    }
    let Ok(contract) = definition.operation_contract(call) else {
        return hold();
    };
    if contract.check_output(&response).is_err() {
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
        // The Function's complete interpretation envelope has been checked.
        // The worker or scenario checks the cached terminal contract once.
        Some("complete" | "refused") => CompletionObservation::Settled(value),
        _ => hold(),
    }
}

/// The header naming the recipient binding Casework's destination declares.
pub const RECIPIENT_BINDING_HEADER: &str = "registry-recipient-binding";
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
            let refused = error.code == "access.unauthenticated";
            let mut response = problem(error);
            if refused {
                store
                    .metrics()
                    .record_authentication_refusal(AuthenticationRefusal::Refused);
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(WEBHOOK_CHALLENGE),
                );
            }
            return response;
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

/// Verify the signature using the connection selected by the recipient binding,
/// then return that connection and the request to wake.
pub(crate) fn authenticate(
    adapters: &dyn AdapterSet,
    headers: &HeaderMap,
    body: Option<&[u8]>,
    now: DateTime<Utc>,
) -> Result<(String, Uuid), CoordinatorError> {
    let refused = |check: FailedCheck| {
        CoordinatorError::new(
            "access.unauthenticated",
            "a fresh signed completion for a configured recipient binding is required",
        )
        .failing(check)
    };
    let signature_refused = || refused(FailedCheck::DeliverySignature);
    let invalid = || {
        CoordinatorError::new(
            "request.invalid",
            "supply one bounded review completion event",
        )
    };
    let body = body.ok_or_else(invalid)?;
    if body.len() > MAXIMUM_BODY_BYTES {
        return Err(CoordinatorError::new(
            "request.body-too-large",
            format!("supply a review completion event of at most {MAXIMUM_BODY_BYTES} bytes"),
        ));
    }
    let recipient =
        single_header(headers, RECIPIENT_BINDING_HEADER).ok_or_else(signature_refused)?;
    let (connection, keys) = adapters
        .review_completion(recipient)
        .ok_or_else(signature_refused)?;
    let id = single_header(headers, "webhook-id").ok_or_else(signature_refused)?;
    let timestamp = single_header(headers, "webhook-timestamp").ok_or_else(signature_refused)?;
    let signature = single_header(headers, "webhook-signature").ok_or_else(signature_refused)?;
    delivery_signature::verify(
        keys,
        SignedContent {
            id,
            timestamp,
            signature,
            body,
        },
        now.into(),
        DELIVERY_TOLERANCE,
    )
    .map_err(|error| match error {
        DeliverySignatureError::StaleDelivery | DeliverySignatureError::InvalidTimestamp => {
            refused(FailedCheck::DeliveryFreshness)
        }
        _ => signature_refused(),
    })?;
    if single_header(headers, header::CONTENT_TYPE.as_str()) != Some("application/json") {
        return Err(CoordinatorError::new(
            "request.content-type-invalid",
            "supply application/json",
        ));
    }
    let value = registry_platform_canonical_json::parse_json_strict(body).map_err(|_| invalid())?;
    let id_matches = value["eventId"].as_str() == Some(id);
    let event: ReviewCompletion = serde_json::from_value(value).map_err(|_| invalid())?;
    if !id_matches
        || event.event_id.is_nil()
        || event.request_id.is_nil()
        || event.result_id.is_nil()
        || !completed_at_is_acceptable(event.completed_at, now)
    {
        return Err(invalid());
    }
    Ok((connection.to_owned(), event.request_id))
}

fn completed_at_is_acceptable(completed_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    completed_at >= now - chrono::Duration::days(OLDEST_COMPLETION_DAYS)
        && completed_at <= now + chrono::Duration::minutes(FUTURE_COMPLETION_MINUTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{CallOutcome, CallRequest};
    use async_trait::async_trait;
    use serde_json::json;

    use registry_platform_crypto::delivery_signature::{sign, DeliveryKey, DeliveryKeys};

    const RECIPIENT: &str = "coordinator-v1";

    struct Receiver(DeliveryKeys);

    fn receiver() -> Receiver {
        Receiver(DeliveryKeys::new(DeliveryKey::new(&[0x29; 32]).unwrap(), None).unwrap())
    }

    #[async_trait]
    impl AdapterSet for Receiver {
        fn binding_digest(&self) -> &str {
            "fixture-binding"
        }

        async fn call(&self, _: &CallRequest) -> CallOutcome {
            unreachable!("the receiver never calls a product")
        }

        fn review_completion(&self, recipient: &str) -> Option<(&str, &DeliveryKeys)> {
            (recipient == RECIPIENT).then_some(("review", &self.0))
        }
    }

    fn headers(
        receiver: &Receiver,
        event: Uuid,
        body: &[u8],
        delivered_at: DateTime<Utc>,
    ) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let id = event.to_string();
        let timestamp = delivered_at.timestamp().to_string();
        let signature = sign(
            &receiver.0,
            &id,
            delivered_at.timestamp().try_into().unwrap(),
            body,
        )
        .unwrap();
        for (name, value) in [
            (RECIPIENT_BINDING_HEADER, RECIPIENT),
            ("content-type", "application/json"),
            ("webhook-id", &id),
            ("webhook-timestamp", &timestamp),
            ("webhook-signature", &signature),
        ] {
            headers.insert(name, HeaderValue::from_str(value).unwrap());
        }
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
    fn a_completion_signed_with_its_connection_key_is_accepted() {
        let (event, request, now) = (Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let receiver = receiver();
        let body = body(event, request, now);
        let headers = headers(&receiver, event, &body, now);
        assert_eq!(
            authenticate(&receiver, &headers, Some(&body), now).unwrap(),
            ("review".to_owned(), request)
        );
    }

    #[test]
    fn an_unknown_recipient_binding_gets_the_signature_refusal() {
        let receiver = receiver();
        let (event, now) = (Uuid::new_v4(), Utc::now());
        let body = body(event, Uuid::new_v4(), now);
        let original = headers(&receiver, event, &body, now);
        for (name, value) in [
            (RECIPIENT_BINDING_HEADER, "other-recipient"),
            ("webhook-signature", "v1,invalid"),
        ] {
            let mut headers = original.clone();
            headers.insert(name, HeaderValue::from_static(value));
            let refusal = authenticate(&receiver, &headers, Some(&body), now).unwrap_err();
            assert_eq!(refusal.code, "access.unauthenticated");
            assert_eq!(refusal.check, Some(FailedCheck::DeliverySignature));
        }
        for name in [
            RECIPIENT_BINDING_HEADER,
            "webhook-id",
            "webhook-timestamp",
            "webhook-signature",
        ] {
            let mut repeated = original.clone();
            repeated.append(name, original[name].clone());
            let mut missing = original.clone();
            missing.remove(name);
            for headers in [repeated, missing] {
                let refusal = authenticate(&receiver, &headers, Some(&body), now).unwrap_err();
                assert_eq!(
                    refusal.check,
                    Some(FailedCheck::DeliverySignature),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn oversized_completions_are_refused_independently_of_the_recipient() {
        let receiver = receiver();
        let now = Utc::now();
        let body = vec![b'x'; MAXIMUM_BODY_BYTES + 1];
        for recipient in [RECIPIENT, "other-recipient"] {
            let mut headers = headers(&receiver, Uuid::new_v4(), &body, now);
            headers.insert(
                RECIPIENT_BINDING_HEADER,
                HeaderValue::from_static(recipient),
            );
            assert_eq!(
                code(authenticate(&receiver, &headers, Some(&body), now)),
                "request.body-too-large"
            );
        }
    }

    #[test]
    fn a_completion_whose_event_id_differs_from_webhook_id_is_refused() {
        let receiver = receiver();
        let now = Utc::now();
        let body = body(Uuid::new_v4(), Uuid::new_v4(), now);
        let headers = headers(&receiver, Uuid::new_v4(), &body, now);
        assert_eq!(
            code(authenticate(&receiver, &headers, Some(&body), now)),
            "request.invalid"
        );
    }

    #[test]
    fn the_completion_window_is_300_seconds_in_both_directions() {
        let receiver = receiver();
        let (event, now) = (
            Uuid::new_v4(),
            DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        );
        let body = body(event, Uuid::new_v4(), now);
        for delta in [-301_i64, -300, 300, 301] {
            let headers = headers(
                &receiver,
                event,
                &body,
                now + chrono::Duration::seconds(delta),
            );
            let result = authenticate(&receiver, &headers, Some(&body), now);
            if delta.abs() == 301 {
                assert_eq!(
                    result.unwrap_err().check,
                    Some(FailedCheck::DeliveryFreshness)
                );
            } else {
                result.unwrap();
            }
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
            let receiver = receiver();
            let mut headers = headers(&receiver, event, &body, now);
            match media {
                Some(media) => {
                    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(media));
                }
                None => {
                    headers.remove(header::CONTENT_TYPE);
                }
            }
            assert_eq!(
                code(authenticate(&receiver, &headers, Some(&body), now)),
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
        let receiver = receiver();
        for (case, body) in cases {
            let headers = headers(&receiver, event, body.as_deref().unwrap_or_default(), now);
            let expected = if case == "an oversized body" {
                "request.body-too-large"
            } else {
                "request.invalid"
            };
            assert_eq!(
                code(authenticate(&receiver, &headers, body.as_deref(), now)),
                expected,
                "{case}"
            );
        }
        let nil = Uuid::nil();
        let body = body(nil, request, now);
        let headers = headers(&receiver, nil, &body, now);
        assert_eq!(
            code(authenticate(&receiver, &headers, Some(&body), now)),
            "request.invalid"
        );
    }
}
