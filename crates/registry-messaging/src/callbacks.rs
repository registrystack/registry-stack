// SPDX-License-Identifier: Apache-2.0

//! The provider callback routes (spec 7.4): verify one delivery callback
//! with the provider's configured verifier, read it with the provider
//! package's receipt script, and apply the receipt to the message it names.
//!
//! No bearer token is involved. The path names the provider, the verifier
//! its runtime configuration names decides whether the request is that
//! provider's. The callback rate is charged before the bounded body is
//! buffered; the verifier then authenticates the raw request before a receipt
//! script or store sees it. A path naming no receiving provider, a request
//! that does not verify, and a token segment on a provider whose verifier is
//! not `path-token` (or none on one whose verifier is) all answer
//! `callback.unverified` alike, so the route reveals neither which providers
//! receive callbacks nor why a request was refused.
//!
//! A verified callback answers 204 when its receipt was applied, changed
//! nothing, reported nothing this runtime records, or named no message:
//! only the counters on the metrics listener tell those apart. A callback
//! the receipt script cannot read answers `callback.unreadable`, and one
//! that cannot be read or recorded for want of the store or the script
//! answers `service.unavailable`, so the provider retries it.
//!
//! The body limit is the request edge's default. The receipt script runs on
//! the blocking pool under its own budget. Logs name a configured provider
//! id, an outcome, and a value-free reason only: never the path token, a
//! header, the query, the body, or the provider's reference.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use registry_messaging_core::{
    verify_callback, CallbackRequest, ProblemCode, Receipt, PROVIDER_CALLBACK_PATH,
};

use crate::http::{rate_limited_response, read_request_body, HttpError, HttpState};
use crate::http_provider::ReceiptScriptError;
use crate::limits::LimitRefusal;
use crate::metrics::{CallbackOutcome, LimitKind};
use crate::receipts::ReceiptOutcome;

const FORM_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";

/// `POST /v1/provider-callbacks/{provider_id}`.
pub(crate) async fn receive(
    State(state): State<HttpState>,
    Path(provider_id): Path<String>,
    request: Request,
) -> Result<StatusCode, Response> {
    answer(&state, &provider_id, None, request).await
}

/// `POST /v1/provider-callbacks/{provider_id}/{token}`.
pub(crate) async fn receive_with_token(
    State(state): State<HttpState>,
    Path((provider_id, token)): Path<(String, String)>,
    request: Request,
) -> Result<StatusCode, Response> {
    answer(&state, &provider_id, Some(token), request).await
}

/// Charge the callback to its provider's rate, then count it by its outcome
/// and answer it. A callback the rate refuses is counted as a limit refusal
/// only: it was never verified, so it has no outcome.
async fn answer(
    state: &HttpState,
    provider_id: &str,
    token: Option<String>,
    request: Request,
) -> Result<StatusCode, Response> {
    let routed = state
        .callbacks
        .contains_key(provider_id)
        .then_some(provider_id);
    match state.callback_limits.check(routed).await {
        Ok(()) => {}
        Err(LimitRefusal::Exceeded { retry_after }) => {
            state.metrics.record_limit_refusal(LimitKind::Callback);
            return Err(rate_limited_response(retry_after));
        }
        Err(LimitRefusal::Unavailable) => {
            tracing::error!("the Messaging callback-rate limiter could not decide");
            state.metrics.record_callback(CallbackOutcome::Unavailable);
            return Err(HttpError(ProblemCode::ServiceUnavailable).into_response());
        }
    }
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let body = read_request_body(request)
        .await
        .map_err(IntoResponse::into_response)?;
    let (outcome, answer) =
        match receive_callback(state, provider_id, token, &uri, &headers, body).await {
            Ok(outcome) => (outcome, Ok(StatusCode::NO_CONTENT)),
            Err((outcome, problem)) => (outcome, Err(HttpError(problem).into_response())),
        };
    state.metrics.record_callback(outcome);
    answer
}

type Refusal = (CallbackOutcome, ProblemCode);

const fn unverified() -> Refusal {
    (CallbackOutcome::Unverified, ProblemCode::CallbackUnverified)
}

const fn unavailable() -> Refusal {
    (
        CallbackOutcome::Unavailable,
        ProblemCode::ServiceUnavailable,
    )
}

async fn receive_callback(
    state: &HttpState,
    provider_id: &str,
    token: Option<String>,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<CallbackOutcome, Refusal> {
    let Some(receiver) = state.callbacks.get(provider_id).map(Arc::clone) else {
        tracing::warn!("a provider callback named no provider that receives callbacks");
        return Err(unverified());
    };
    if receiver.uses_path_token() != token.is_some() {
        tracing::warn!(
            provider = provider_id,
            "a provider callback arrived on the route its verifier does not use"
        );
        return Err(unverified());
    }
    let path = PROVIDER_CALLBACK_PATH.replace("{provider_id}", provider_id);
    let callback = OwnedCallback {
        url: receiver.request_url(&path, uri.query()),
        form_parameters: if media_type(headers).is_some_and(|media| media == FORM_MEDIA_TYPE) {
            url::form_urlencoded::parse(&body).into_owned().collect()
        } else {
            Vec::new()
        },
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect(),
        body,
        path_token: token,
    };
    if let Err(refusal) =
        callback.with_request(|request| verify_callback(&receiver.verifier(), request))
    {
        tracing::warn!(
            provider = provider_id,
            reason = %refusal,
            "a provider callback did not verify"
        );
        return Err(unverified());
    }
    let Some(service) = state.messages.as_deref() else {
        return Err(unavailable());
    };
    let reader = Arc::clone(&receiver);
    let read = tokio::task::spawn_blocking(move || {
        callback.with_request(|request| reader.provider().receipt(request))
    })
    .await
    .map_err(|error| {
        tracing::error!(error = %error, provider = provider_id, "a receipt script task failed");
        unavailable()
    })?;
    let receipt: Receipt = match read {
        Ok(Some(receipt)) => receipt,
        Ok(None) => return Ok(CallbackOutcome::Ignored),
        Err(ReceiptScriptError::NotDeclared) => {
            tracing::error!(
                provider = provider_id,
                "a provider that receives callbacks has no receipt script"
            );
            return Err(unavailable());
        }
        Err(error) => {
            tracing::warn!(
                provider = provider_id,
                reason = %error,
                "a verified provider callback could not be read"
            );
            return Err((CallbackOutcome::Unreadable, ProblemCode::CallbackUnreadable));
        }
    };
    let recorded = service
        .messages()
        .record_receipt(provider_id, &receipt)
        .await
        .map_err(|error| {
            tracing::error!(
                error = %error,
                provider = provider_id,
                "the Messaging store could not record a receipt"
            );
            unavailable()
        })?;
    Ok(match recorded {
        ReceiptOutcome::Applied { .. } => CallbackOutcome::Applied,
        ReceiptOutcome::Unchanged { .. } => CallbackOutcome::Unchanged,
        ReceiptOutcome::Unmatched => {
            tracing::info!(
                provider = provider_id,
                "a verified receipt named no message of this provider"
            );
            CallbackOutcome::Unmatched
        }
        ReceiptOutcome::Ambiguous => {
            tracing::warn!(
                provider = provider_id,
                "a verified receipt named more than one message of this provider and was not \
                 applied"
            );
            CallbackOutcome::Ambiguous
        }
    })
}

/// The media type of the request body, lowercased, without parameters.
fn media_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|media| media.trim().to_ascii_lowercase())
}

/// A received callback, owned so the receipt script can read it on the
/// blocking pool.
struct OwnedCallback {
    url: String,
    form_parameters: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Bytes,
    path_token: Option<String>,
}

impl OwnedCallback {
    fn with_request<T>(&self, read: impl FnOnce(&CallbackRequest<'_>) -> T) -> T {
        let form_parameters: Vec<(&str, &str)> = self
            .form_parameters
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        read(&CallbackRequest {
            method: "POST",
            url: &self.url,
            form_parameters: &form_parameters,
            body: &self.body,
            headers: &headers,
            path_token: self.path_token.as_deref(),
        })
    }
}
