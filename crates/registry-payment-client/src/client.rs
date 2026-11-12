// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use registry_payment_protocol::{
    CollectionAccepted, CollectionStatus, PaymentProblem, ReadCollection, RecordReceipt,
    RegistryReceipt, RequestCollection,
};
use registry_platform_httpsec::response_trace_id;
use registry_platform_httputil::client::{
    build_client, classify_keyed_attempt, read_failure_kind, retry_keyed_mutation,
    send_failure_kind, BearerToken, KeyedMutationAttempt, OutboundOptions, RetryAfter,
    ServiceBaseUrl,
};
use registry_platform_httputil::{
    read_bounded, retry_after_seconds, url::append_path_segments, validate_response_headers,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Response, StatusCode, Url};
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::{PaymentClientConfig, PaymentClientError, PaymentProtocolFailure};

const JSON_MEDIA_TYPE: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";
const MAXIMUM_PROBLEM_BYTES: u64 = 8 * 1024;
const MAXIMUM_RETRY_AFTER_SECONDS: u64 = 86_400;

/// One completed call with its validated response trace identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentComplete<T> {
    pub value: T,
    pub trace_id: String,
}

pub struct PaymentClient {
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
    connection: String,
    maximum_response_bytes: u64,
    maximum_mutation_retries: u8,
}

impl fmt::Debug for PaymentClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaymentClient")
            .field("base_url", &"<validated service URL>")
            .field("connection", &"<validated local identifier>")
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .field("maximum_mutation_retries", &self.maximum_mutation_retries)
            .finish_non_exhaustive()
    }
}

impl PaymentClient {
    pub fn new(config: PaymentClientConfig) -> Result<Self, PaymentClientError> {
        let base_url = config.validate()?;
        let http = build_client(OutboundOptions {
            request_timeout: config.attempt_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config.trusted_root_certificates.as_deref(),
        })
        .map_err(|_| PaymentClientError::configuration("the HTTP client could not be built"))?;
        Ok(Self {
            http,
            base_url,
            connection: config.connection,
            maximum_response_bytes: config.maximum_response_bytes,
            maximum_mutation_retries: config.maximum_mutation_retries,
        })
    }

    /// Request one collection attempt for the exact authoritative bill.
    pub async fn request_collection(
        &self,
        token: &BearerToken,
        idempotency_key: &str,
        request: &RequestCollection,
    ) -> Result<PaymentComplete<CollectionAccepted>, PaymentClientError> {
        validate_key(idempotency_key)?;
        request
            .validate()
            .map_err(|_| PaymentClientError::invalid_request("the bill identity is invalid"))?;
        let builder = self
            .http
            .post(self.collections_url()?)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE)
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
            .json(request);
        let answer: PaymentComplete<CollectionAccepted> =
            self.send_keyed_json(builder, StatusCode::ACCEPTED).await?;
        validate_acceptance(
            &answer.value,
            request,
            StatusCode::ACCEPTED,
            &answer.trace_id,
        )?;
        Ok(answer)
    }

    /// Read the retained acceptance for the exact original key and request.
    /// This is one read-only exchange and is never retried automatically.
    pub async fn collection_receipt(
        &self,
        token: &BearerToken,
        idempotency_key: &str,
        request: &RequestCollection,
    ) -> Result<PaymentComplete<CollectionAccepted>, PaymentClientError> {
        validate_key(idempotency_key)?;
        request
            .validate()
            .map_err(|_| PaymentClientError::invalid_request("the bill identity is invalid"))?;
        let builder = self
            .http
            .post(self.path_url(&["collections", "receipt"])?)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE)
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
            .json(request);
        let answer = self.json_answer(builder, StatusCode::OK).await?;
        validate_acceptance(&answer.value, request, StatusCode::OK, &answer.trace_id)?;
        Ok(answer)
    }

    /// Read current provider state for one accepted collection.
    pub async fn read_collection(
        &self,
        token: &BearerToken,
        request: &ReadCollection,
    ) -> Result<PaymentComplete<CollectionStatus>, PaymentClientError> {
        validate_collection_id(request.collection_id)?;
        let builder = self
            .http
            .get(self.path_url(&["collections", &request.collection_id.to_string()])?)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE);
        let answer: PaymentComplete<CollectionStatus> =
            self.json_answer(builder, StatusCode::OK).await?;
        answer
            .value
            .validate()
            .map_err(|_| body_protocol(StatusCode::OK, Some(answer.trace_id.clone())))?;
        if answer.value.collection_id != request.collection_id {
            return Err(correlation_protocol(StatusCode::OK, Some(answer.trace_id)));
        }
        Ok(answer)
    }

    /// Record the confirmed provider receipt under a separate keyed command.
    pub async fn record_receipt(
        &self,
        token: &BearerToken,
        idempotency_key: &str,
        request: &RecordReceipt,
    ) -> Result<PaymentComplete<RegistryReceipt>, PaymentClientError> {
        validate_key(idempotency_key)?;
        validate_collection_id(request.collection_id)?;
        let builder = self
            .http
            .post(self.path_url(&[
                "collections",
                &request.collection_id.to_string(),
                "record-receipt",
            ])?)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE)
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
            .json(request);
        let answer: PaymentComplete<RegistryReceipt> =
            self.send_keyed_json(builder, StatusCode::OK).await?;
        answer
            .value
            .validate()
            .map_err(|_| body_protocol(StatusCode::OK, Some(answer.trace_id.clone())))?;
        if answer.value.collection_id != request.collection_id {
            return Err(correlation_protocol(StatusCode::OK, Some(answer.trace_id)));
        }
        Ok(answer)
    }

    fn collections_url(&self) -> Result<Url, PaymentClientError> {
        self.path_url(&["collections"])
    }

    fn path_url(&self, suffix: &[&str]) -> Result<Url, PaymentClientError> {
        let mut segments = vec!["v1", "payments", self.connection.as_str()];
        segments.extend_from_slice(suffix);
        append_path_segments(self.base_url.as_url(), &segments)
            .map_err(|_| PaymentClientError::configuration("the service base URL is not usable"))
    }

    async fn json_answer<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        expected: StatusCode,
    ) -> Result<PaymentComplete<T>, PaymentClientError> {
        let response = self.send(request).await?;
        self.json_response(response, expected).await
    }

    async fn send_keyed_json<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        expected: StatusCode,
    ) -> Result<PaymentComplete<T>, PaymentClientError> {
        let request = &request;
        retry_keyed_mutation(self.maximum_mutation_retries, || async move {
            let Some(attempt) = request.try_clone() else {
                return KeyedMutationAttempt::Settled(Err(PaymentClientError::invalid_request(
                    "the request could not be prepared for sending",
                )));
            };
            let response = match self.send(attempt).await {
                Ok(response) => response,
                Err(error) => return keyed_attempt(Err(error), None, RetryAfter::Absent),
            };
            let status = response.status();
            let retry_after = RetryAfter::from_headers(response.headers());
            keyed_attempt(
                self.json_response(response, expected).await,
                Some(status),
                retry_after,
            )
        })
        .await
    }

    async fn json_response<T: DeserializeOwned>(
        &self,
        response: Response,
        expected: StatusCode,
    ) -> Result<PaymentComplete<T>, PaymentClientError> {
        let status = response.status();
        if status != expected {
            return Err(self.problem_or_status(response).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        if !exact_media_type(response.headers(), JSON_MEDIA_TYPE) {
            return Err(protocol(
                status,
                PaymentProtocolFailure::MediaType,
                Some(trace_id),
            ));
        }
        let body = read_bounded(response, self.maximum_response_bytes)
            .await
            .map_err(|error| PaymentClientError::Transport {
                kind: read_failure_kind(&error),
            })?;
        let value = registry_platform_canonical_json::parse_json_strict(&body)
            .ok()
            .and_then(|value| serde_json::from_value(value).ok())
            .ok_or_else(|| body_protocol(status, Some(trace_id.clone())))?;
        Ok(PaymentComplete { value, trace_id })
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Response, PaymentClientError> {
        let response = request
            .send()
            .await
            .map_err(|error| PaymentClientError::Transport {
                kind: send_failure_kind(&error),
            })?;
        validate_response_headers(response.headers()).map_err(|_| {
            protocol(
                response.status(),
                PaymentProtocolFailure::HeaderBounds,
                None,
            )
        })?;
        Ok(response)
    }

    async fn problem_or_status(&self, response: Response) -> PaymentClientError {
        let status = response.status();
        let trace = response_trace(status, response.headers()).ok();
        let retry_after = (status == StatusCode::TOO_MANY_REQUESTS)
            .then(|| retry_after_seconds(response.headers(), MAXIMUM_RETRY_AFTER_SECONDS))
            .flatten();
        if !exact_media_type(response.headers(), PROBLEM_MEDIA_TYPE) {
            return protocol(status, PaymentProtocolFailure::Status, trace);
        }
        let body = match read_bounded(response, MAXIMUM_PROBLEM_BYTES).await {
            Ok(value) => value,
            Err(error) => {
                return PaymentClientError::Transport {
                    kind: read_failure_kind(&error),
                }
            }
        };
        let document = registry_platform_canonical_json::parse_json_strict(&body)
            .ok()
            .and_then(|value| serde_json::from_value::<PaymentProblem>(value).ok());
        match document {
            Some(document) => domain_problem(status, trace, document, retry_after),
            None => protocol(status, PaymentProtocolFailure::Problem, trace),
        }
    }
}

fn validate_acceptance(
    answer: &CollectionAccepted,
    request: &RequestCollection,
    status: StatusCode,
    trace_id: &str,
) -> Result<(), PaymentClientError> {
    answer
        .validate()
        .map_err(|_| body_protocol(status, Some(trace_id.to_owned())))?;
    if answer.bill_id != request.bill_id || answer.bill_version != request.bill_version {
        return Err(correlation_protocol(status, Some(trace_id.to_owned())));
    }
    Ok(())
}

fn validate_collection_id(value: Uuid) -> Result<(), PaymentClientError> {
    if value.is_nil() {
        Err(PaymentClientError::invalid_request(
            "the collection identifier is nil",
        ))
    } else {
        Ok(())
    }
}

fn validate_key(value: &str) -> Result<(), PaymentClientError> {
    if (1..=128).contains(&value.len()) && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        Ok(())
    } else {
        Err(PaymentClientError::invalid_request(
            "the idempotency key is not 1 to 128 visible ASCII characters",
        ))
    }
}

fn keyed_attempt<T>(
    result: Result<T, PaymentClientError>,
    status: Option<StatusCode>,
    retry_after: RetryAfter,
) -> KeyedMutationAttempt<T, PaymentClientError> {
    classify_keyed_attempt(
        result,
        status,
        retry_after,
        PaymentClientError::is_outcome_unknown,
        PaymentClientError::resend_may_settle,
    )
}

fn domain_problem(
    status: StatusCode,
    trace_id: Option<String>,
    document: PaymentProblem,
    retry_after: Option<u64>,
) -> PaymentClientError {
    if document.status != status.as_u16()
        || document.code.status() != status.as_u16()
        || document.type_uri != document.code.type_uri()
        || document.title != document.code.as_str()
    {
        return protocol(status, PaymentProtocolFailure::Problem, trace_id);
    }
    PaymentClientError::Problem {
        status: status.as_u16(),
        code: document.code,
        trace_id,
        retry_after_seconds: retry_after.filter(|_| status == StatusCode::TOO_MANY_REQUESTS),
    }
}

fn response_trace(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<String, PaymentClientError> {
    response_trace_id(headers)
        .map(|value| value.as_str().to_owned())
        .map_err(|_| protocol(status, PaymentProtocolFailure::TraceContext, None))
}

fn exact_media_type(headers: &reqwest::header::HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    matches!(
        (values.next(), values.next()),
        (Some(value), None) if value.as_bytes() == expected.as_bytes()
    )
}

fn body_protocol(status: StatusCode, trace_id: Option<String>) -> PaymentClientError {
    protocol(status, PaymentProtocolFailure::Body, trace_id)
}

fn correlation_protocol(status: StatusCode, trace_id: Option<String>) -> PaymentClientError {
    protocol(status, PaymentProtocolFailure::Correlation, trace_id)
}

fn protocol(
    status: StatusCode,
    failure: PaymentProtocolFailure,
    trace_id: Option<String>,
) -> PaymentClientError {
    PaymentClientError::Protocol {
        status: status.as_u16(),
        failure,
        trace_id,
    }
}
