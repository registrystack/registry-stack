// SPDX-License-Identifier: Apache-2.0
//! The Casework review producer binding. One connection is one producer: it
//! submits review requests, cancels them, and reads their results with the
//! producer's own credential. Casework owns the review; Coordinator holds only
//! the accepted request a call step returned.

use std::sync::Arc;

use registry_casework_client::{
    submission_digest, CaseworkAuth, CaseworkClient, CaseworkClientError, CaseworkProblemCode,
    ReviewCancelRequest, ReviewCreateRequest, ReviewRequestAccepted, ReviewResultResponse,
};
use registry_platform_httputil::client::{PrivateKeyJwt, TokenProvider};
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::{
    adapters::{refused, retryable, token_failure, valid_key},
    protocol::{CallOutcome, CallRequest, Operation, ReviewRead},
};

/// The input of `cancel-review-request`: the accepted request a submit step
/// returned and the reason Casework records with the cancellation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) struct CancelReviewInput {
    request: ReviewRequestAccepted,
    reason: String,
}

/// How Casework's completion destination for this producer authenticates:
/// the bearer token it sends and the recipient binding it names.
pub(crate) struct CompletionSender {
    pub(crate) token: Zeroizing<String>,
    pub(crate) recipient: String,
}

impl CompletionSender {
    /// Both values must match, each compared in time that depends only on
    /// their lengths.
    fn matches(&self, token: &str, recipient: &str) -> bool {
        let token_matches = registry_platform_crypto::mac::constant_time_eq(
            self.token.as_bytes(),
            token.as_bytes(),
        );
        let recipient_matches = registry_platform_crypto::mac::constant_time_eq(
            self.recipient.as_bytes(),
            recipient.as_bytes(),
        );
        token_matches && recipient_matches
    }
}

pub(crate) struct CaseworkConnection {
    client: CaseworkClient,
    tokens: Arc<PrivateKeyJwt>,
    profile: String,
    producer: String,
    completion: Option<CompletionSender>,
    result_check_seconds: u32,
}

impl CaseworkConnection {
    pub(crate) fn new(
        client: CaseworkClient,
        tokens: PrivateKeyJwt,
        profile: String,
        producer: String,
        completion: Option<CompletionSender>,
        result_check_seconds: u32,
    ) -> Self {
        Self {
            client,
            tokens: Arc::new(tokens),
            profile,
            producer,
            completion,
            result_check_seconds,
        }
    }

    pub(crate) fn result_check_seconds(&self) -> u32 {
        self.result_check_seconds
    }

    pub(crate) fn completion_matches(&self, token: &str, recipient: &str) -> bool {
        self.completion
            .as_ref()
            .is_some_and(|sender| sender.matches(token, recipient))
    }

    /// Read the result of an accepted request. The client holds a 200 answer
    /// to the accepted request's identifier, subject, policy and submission
    /// digest, so a result for anything else is refused as invalid-response.
    pub(crate) async fn read_result(&self, accepted: &Value) -> ReviewRead {
        let Ok(accepted) = serde_json::from_value::<ReviewRequestAccepted>(accepted.clone()) else {
            return ReviewRead::Failed(refused("invalid-command"));
        };
        let token = match self.tokens.bearer_token().await {
            Ok(token) => token,
            Err(error) => return ReviewRead::Failed(token_failure(&error)),
        };
        match self
            .client
            .review_result(CaseworkAuth::new(&token, &self.profile), &accepted)
            .await
        {
            Ok(ReviewResultResponse::Available(answer)) => match serde_json::to_value(answer.value)
            {
                Ok(value) => ReviewRead::Settled(value),
                Err(_) => ReviewRead::Failed(refused("invalid-response")),
            },
            Ok(ReviewResultResponse::Pending { .. }) => ReviewRead::Pending,
            Ok(ReviewResultResponse::ConcealedOrUnknown { .. }) => ReviewRead::Unknown,
            Ok(ReviewResultResponse::Expired { .. }) => ReviewRead::Expired,
            Err(error) => ReviewRead::Failed(read_failure(error)),
        }
    }

    pub(crate) async fn call(&self, request: &CallRequest) -> CallOutcome {
        let Some(key) = request
            .idempotency_key
            .as_deref()
            .filter(|key| valid_key(key))
        else {
            return refused("invalid-command");
        };
        match request.operation {
            Operation::SubmitReviewRequest => {
                let Ok(input) =
                    serde_json::from_value::<ReviewCreateRequest>(request.input.clone())
                else {
                    return refused("invalid-command");
                };
                // Casework binds the digest to the producer and to the
                // subject's source namespace, so a recovered acceptance for
                // other content or another producer is never taken as this one.
                let Ok(expected) = submission_digest(&self.producer, &input.subject.source, &input)
                else {
                    return refused("invalid-command");
                };
                let token = match self.tokens.bearer_token().await {
                    Ok(token) => token,
                    Err(error) => return token_failure(&error),
                };
                match self
                    .client
                    .create_or_recover_review_request(
                        CaseworkAuth::new(&token, &self.profile),
                        key,
                        &input,
                        &expected,
                    )
                    .await
                {
                    Ok(answer) => success(answer.value),
                    Err(error) => failure(error),
                }
            }
            Operation::CancelReviewRequest => {
                let Ok(input) = serde_json::from_value::<CancelReviewInput>(request.input.clone())
                else {
                    return refused("invalid-command");
                };
                let cancellation = ReviewCancelRequest {
                    subject: input.request.subject.clone(),
                    reason: input.reason,
                };
                let token = match self.tokens.bearer_token().await {
                    Ok(token) => token,
                    Err(error) => return token_failure(&error),
                };
                // A request that already ended answers `already-terminal`
                // with its result; either answer leaves nothing to withdraw.
                match self
                    .client
                    .cancel_review_request(
                        CaseworkAuth::new(&token, &self.profile),
                        &input.request,
                        key,
                        &cancellation,
                    )
                    .await
                {
                    Ok(answer) => success(answer.value),
                    Err(error) => failure(error),
                }
            }
            _ => refused("operation-unbound"),
        }
    }
}

fn success<T: serde::Serialize>(value: T) -> CallOutcome {
    match serde_json::to_value(value) {
        Ok(value) => CallOutcome::Success(value),
        Err(_) => CallOutcome::Uncertain {
            code: "invalid-response".into(),
        },
    }
}

/// A result read changes nothing, so an answer that cannot be read is refused
/// rather than held, and an outage repeats the read, including one an
/// intermediary answers outside Casework's catalogue.
fn read_failure(error: CaseworkClientError) -> CallOutcome {
    match error {
        CaseworkClientError::Transport { .. } => retryable("transport-unavailable"),
        CaseworkClientError::Problem { status: 429, .. }
        | CaseworkClientError::Protocol { status: 429, .. } => retryable("rate-limited"),
        CaseworkClientError::Problem { status, .. }
        | CaseworkClientError::Protocol { status, .. }
            if status == 408 || status >= 500 =>
        {
            retryable("transport-unavailable")
        }
        CaseworkClientError::Protocol { .. } => refused("invalid-response"),
        CaseworkClientError::Problem {
            status: 401 | 403, ..
        } => refused("product-forbidden"),
        CaseworkClientError::InvalidRequest { .. } => refused("invalid-command"),
        _ => refused("product-refused"),
    }
}

/// Both review calls are keyed mutations: an answer that does not match the
/// request, or an exchange whose outcome is unknown, holds the step for the
/// same-key recovery an operator chooses.
fn failure(error: CaseworkClientError) -> CallOutcome {
    match error {
        CaseworkClientError::Protocol { .. } => CallOutcome::Uncertain {
            code: "invalid-response".into(),
        },
        CaseworkClientError::Problem {
            code: CaseworkProblemCode::IdempotencyExpired,
            ..
        } => CallOutcome::ReceiptExpired,
        error if error.is_outcome_unknown() => CallOutcome::Uncertain {
            code: "transport-uncertain".into(),
        },
        CaseworkClientError::Transport { .. } => retryable("transport-unavailable"),
        CaseworkClientError::Problem { status: 429, .. } => retryable("rate-limited"),
        CaseworkClientError::Problem {
            status: 401 | 403, ..
        } => refused("product-forbidden"),
        CaseworkClientError::Problem { status: 404, .. } => refused("product-not-found"),
        CaseworkClientError::InvalidRequest { .. } => refused("invalid-command"),
        _ => refused("product-refused"),
    }
}
