use std::fmt;

use registry_platform_httpsec::{response_trace_id, ProblemDocument};
use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, BearerToken, OutboundOptions,
    ServiceBaseUrl,
};
use registry_platform_httputil::{
    read_bounded, url::append_path_segments, validate_response_headers,
};
use registry_review_protocol::{
    review_cancel_path, review_request_path, review_result_path, ReviewCancelRequest,
    ReviewCancelResponse, ReviewCreateRequest, ReviewRequestAccepted, ReviewRequestView,
    ReviewResult, ReviewResultFeedPage, SubmissionDigest, REVIEW_REQUESTS_PATH,
    REVIEW_RESULTS_FEED_PATH,
};
use reqwest::header::{HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{RequestBuilder, Response, StatusCode, Url};
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::model::check_result_page;
use crate::{
    ReviewClientConfig, ReviewClientError, ReviewComplete, ReviewProtocolFailure,
    ReviewResultResponse, ReviewResultsQuery,
};

const JSON_MEDIA_TYPE: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const CASEWORK_PROFILE_HEADER: &str = "registry-casework-profile";
const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 128;
const MAXIMUM_PROBLEM_BYTES: u64 = 8 * 1024;
const PROBLEM_TYPE_BASE: &str = "https://id.registrystack.org/problems/registry-casework/";

pub struct ReviewClient {
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
    max_response_bytes: u64,
    profile: HeaderValue,
}

impl fmt::Debug for ReviewClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewClient")
            .field("base_url", &"<validated service URL>")
            .field("max_response_bytes", &self.max_response_bytes)
            .field("profile", &"<configured>")
            .finish_non_exhaustive()
    }
}

impl ReviewClient {
    pub fn new(config: ReviewClientConfig) -> Result<Self, ReviewClientError> {
        let base_url = config.validate()?;
        let profile = HeaderValue::from_str(
            config
                .profile
                .as_deref()
                .expect("validated review client profile"),
        )
        .map_err(|_| ReviewClientError::configuration("the Casework profile is invalid"))?;
        let http = build_client(OutboundOptions {
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config.trusted_root_certificates.as_deref(),
        })
        .map_err(|_| ReviewClientError::configuration("the HTTP client could not be built"))?;
        Ok(Self {
            http,
            base_url,
            max_response_bytes: config.max_response_bytes,
            profile,
        })
    }

    /// Create a request, or recover its accepted binding by repeating the exact
    /// request and idempotency key within the service's recovery window.
    ///
    /// The client performs exactly one exchange. Ambiguous failures are left to
    /// the caller's durable retry schedule.
    pub async fn create_or_recover_request(
        &self,
        token: &BearerToken,
        idempotency_key: &str,
        request: &ReviewCreateRequest,
        expected_submission_digest: &SubmissionDigest,
    ) -> Result<ReviewComplete<ReviewRequestAccepted>, ReviewClientError> {
        request
            .check()
            .map_err(|_| ReviewClientError::invalid_request("the review request is invalid"))?;
        validate_idempotency_key(idempotency_key)?;
        let key = HeaderValue::from_str(idempotency_key)
            .map_err(|_| ReviewClientError::invalid_request("the idempotency key is invalid"))?;
        let url = self.url_from_constant(REVIEW_REQUESTS_PATH)?;
        let outgoing = self
            .authorized(self.http.post(url).json(request), token)
            .header(HeaderName::from_static(IDEMPOTENCY_KEY_HEADER), key);
        let complete = self
            .send_json_one_of(outgoing, &[StatusCode::OK, StatusCode::CREATED])
            .await?;
        check_accepted(
            &complete.value,
            &request.kind,
            &request.subject,
            expected_submission_digest,
            &complete.trace_id,
        )?;
        Ok(complete)
    }

    pub async fn request(
        &self,
        token: &BearerToken,
        request_id: Uuid,
    ) -> Result<ReviewComplete<ReviewRequestView>, ReviewClientError> {
        let url = self.url_from_constant(&review_request_path(request_id))?;
        let complete = self
            .send_json(self.authorized(self.http.get(url), token), StatusCode::OK)
            .await?;
        check_request_view(&complete.value, request_id, &complete.trace_id)?;
        Ok(complete)
    }

    pub async fn result(
        &self,
        token: &BearerToken,
        expected: &ReviewRequestAccepted,
    ) -> Result<ReviewResultResponse, ReviewClientError> {
        let request_id = expected.request_id;
        let url = self.url_from_constant(&review_result_path(request_id))?;
        let response = self
            .send(self.authorized(self.http.get(url), token))
            .await?;
        let status = response.status();
        let trace_id = response_trace(status, response.headers())?;
        match status {
            StatusCode::OK => {
                if !exact_media_type(response.headers(), JSON_MEDIA_TYPE) {
                    return Err(protocol(
                        status,
                        ReviewProtocolFailure::MediaType,
                        Some(trace_id),
                    ));
                }
                let result: ReviewResult = self.read_json(response, status, &trace_id).await?;
                result.check().map_err(|_| {
                    protocol(status, ReviewProtocolFailure::Body, Some(trace_id.clone()))
                })?;
                if result.request_id != request_id
                    || result.subject != expected.subject
                    || result.policy != expected.policy
                    || result.submission_digest != expected.submission_digest
                {
                    return Err(protocol(
                        status,
                        ReviewProtocolFailure::Body,
                        Some(trace_id),
                    ));
                }
                Ok(ReviewResultResponse::Available(Box::new(ReviewComplete {
                    value: result,
                    trace_id,
                })))
            }
            StatusCode::ACCEPTED | StatusCode::NOT_FOUND | StatusCode::GONE => {
                self.require_empty(response, status, &trace_id).await?;
                Ok(match status {
                    StatusCode::ACCEPTED => ReviewResultResponse::Pending { trace_id },
                    StatusCode::NOT_FOUND => ReviewResultResponse::ConcealedOrUnknown { trace_id },
                    StatusCode::GONE => ReviewResultResponse::Expired { trace_id },
                    _ => unreachable!("the status match is closed above"),
                })
            }
            _ => Err(self.problem_or_status(response, Some(trace_id)).await),
        }
    }

    pub async fn requester_results(
        &self,
        token: &BearerToken,
        query: &ReviewResultsQuery<'_>,
    ) -> Result<ReviewComplete<ReviewResultFeedPage>, ReviewClientError> {
        query.check().map_err(ReviewClientError::invalid_request)?;
        let url = self.url_from_constant(REVIEW_RESULTS_FEED_PATH)?;
        let request = self.authorized(self.http.get(url).query(query), token);
        let complete = self.send_json(request, StatusCode::OK).await?;
        check_result_page(&complete.value).map_err(|_| {
            protocol(
                StatusCode::OK,
                ReviewProtocolFailure::Body,
                Some(complete.trace_id.clone()),
            )
        })?;
        Ok(complete)
    }

    pub async fn cancel_request(
        &self,
        token: &BearerToken,
        request_id: Uuid,
        idempotency_key: &str,
        cancellation: &ReviewCancelRequest,
    ) -> Result<ReviewComplete<ReviewCancelResponse>, ReviewClientError> {
        cancellation
            .check()
            .map_err(|_| ReviewClientError::invalid_request("the cancellation is invalid"))?;
        validate_idempotency_key(idempotency_key)?;
        let key = HeaderValue::from_str(idempotency_key)
            .map_err(|_| ReviewClientError::invalid_request("the idempotency key is invalid"))?;
        let url = self.url_from_constant(&review_cancel_path(request_id))?;
        let request = self
            .authorized(self.http.post(url).json(cancellation), token)
            .header(HeaderName::from_static(IDEMPOTENCY_KEY_HEADER), key);
        let complete: ReviewComplete<ReviewCancelResponse> =
            self.send_json(request, StatusCode::OK).await?;
        let result = match &complete.value {
            ReviewCancelResponse::Cancelled { result }
            | ReviewCancelResponse::AlreadyTerminal { result } => result,
        };
        result.check().map_err(|_| {
            protocol(
                StatusCode::OK,
                ReviewProtocolFailure::Body,
                Some(complete.trace_id.clone()),
            )
        })?;
        if result.request_id != request_id || result.subject != cancellation.subject {
            return Err(protocol(
                StatusCode::OK,
                ReviewProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        if matches!(
            &complete.value,
            ReviewCancelResponse::Cancelled { result }
                if result.status != registry_review_protocol::ReviewResultStatus::Cancelled
        ) {
            return Err(protocol(
                StatusCode::OK,
                ReviewProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    fn authorized(&self, request: RequestBuilder, token: &BearerToken) -> RequestBuilder {
        request
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(
                HeaderName::from_static(CASEWORK_PROFILE_HEADER),
                self.profile.clone(),
            )
            .header(ACCEPT, JSON_MEDIA_TYPE)
    }

    fn url_from_constant(&self, path: &str) -> Result<Url, ReviewClientError> {
        let segments = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
        append_path_segments(self.base_url.as_url(), &segments)
            .map_err(|_| ReviewClientError::invalid_request("a route identifier is invalid"))
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        expected_status: StatusCode,
    ) -> Result<ReviewComplete<T>, ReviewClientError> {
        self.send_json_one_of(request, &[expected_status]).await
    }

    async fn send_json_one_of<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        expected_statuses: &[StatusCode],
    ) -> Result<ReviewComplete<T>, ReviewClientError> {
        let response = self.send(request).await?;
        let status = response.status();
        if !expected_statuses.contains(&status) {
            return Err(self.problem_or_status(response, None).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        if !exact_media_type(response.headers(), JSON_MEDIA_TYPE) {
            return Err(protocol(
                status,
                ReviewProtocolFailure::MediaType,
                Some(trace_id),
            ));
        }
        let value = self.read_json(response, status, &trace_id).await?;
        Ok(ReviewComplete { value, trace_id })
    }

    async fn read_json<T: DeserializeOwned>(
        &self,
        response: Response,
        status: StatusCode,
        trace_id: &str,
    ) -> Result<T, ReviewClientError> {
        let body = read_bounded(response, self.max_response_bytes)
            .await
            .map_err(|error| ReviewClientError::Transport {
                kind: read_failure_kind(&error),
            })?;
        let value = registry_platform_canonical_json::parse_json_strict(&body).map_err(|_| {
            protocol(
                status,
                ReviewProtocolFailure::Body,
                Some(trace_id.to_owned()),
            )
        })?;
        serde_json::from_value(value).map_err(|_| {
            protocol(
                status,
                ReviewProtocolFailure::Body,
                Some(trace_id.to_owned()),
            )
        })
    }

    async fn require_empty(
        &self,
        response: Response,
        status: StatusCode,
        trace_id: &str,
    ) -> Result<(), ReviewClientError> {
        if response.headers().contains_key(CONTENT_TYPE) {
            return Err(protocol(
                status,
                ReviewProtocolFailure::MediaType,
                Some(trace_id.to_owned()),
            ));
        }
        let body =
            read_bounded(response, 1)
                .await
                .map_err(|error| ReviewClientError::Transport {
                    kind: read_failure_kind(&error),
                })?;
        if !body.is_empty() {
            return Err(protocol(
                status,
                ReviewProtocolFailure::Body,
                Some(trace_id.to_owned()),
            ));
        }
        Ok(())
    }

    async fn send(&self, request: RequestBuilder) -> Result<Response, ReviewClientError> {
        let response = request
            .send()
            .await
            .map_err(|error| ReviewClientError::Transport {
                kind: send_failure_kind(&error),
            })?;
        validate_response_headers(response.headers())
            .map_err(|_| protocol(response.status(), ReviewProtocolFailure::HeaderBounds, None))?;
        Ok(response)
    }

    async fn problem_or_status(
        &self,
        response: Response,
        known_trace_id: Option<String>,
    ) -> ReviewClientError {
        let status = response.status();
        let trace_id = known_trace_id.or_else(|| response_trace(status, response.headers()).ok());
        if !exact_media_type(response.headers(), PROBLEM_MEDIA_TYPE) {
            return protocol(status, ReviewProtocolFailure::Status, trace_id);
        }
        let body = match read_bounded(response, MAXIMUM_PROBLEM_BYTES).await {
            Ok(value) => value,
            Err(error) => {
                return ReviewClientError::Transport {
                    kind: read_failure_kind(&error),
                }
            }
        };
        let document = match ProblemDocument::parse_exact(&body, MAXIMUM_PROBLEM_BYTES as usize) {
            Ok(value) => value,
            Err(_) => return protocol(status, ReviewProtocolFailure::Problem, trace_id),
        };
        let valid_code = !document.code.is_empty()
            && document.code.len() <= 128
            && document.code.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            });
        let expected_type = format!("{PROBLEM_TYPE_BASE}{}", document.code.replace('.', "/"));
        if document.status != status.as_u16()
            || trace_id.as_deref() != Some(document.trace_id.as_str())
            || !valid_code
            || document.type_uri != expected_type
        {
            return protocol(status, ReviewProtocolFailure::Problem, trace_id);
        }
        ReviewClientError::Problem {
            status: status.as_u16(),
            trace_id,
        }
    }
}

fn check_accepted(
    value: &ReviewRequestAccepted,
    expected_kind: &str,
    expected_subject: &registry_review_protocol::SubjectBinding,
    expected_submission_digest: &SubmissionDigest,
    trace_id: &str,
) -> Result<(), ReviewClientError> {
    value.subject.check().map_err(|_| {
        protocol(
            StatusCode::CREATED,
            ReviewProtocolFailure::Body,
            Some(trace_id.to_owned()),
        )
    })?;
    value.policy.check().map_err(|_| {
        protocol(
            StatusCode::CREATED,
            ReviewProtocolFailure::Body,
            Some(trace_id.to_owned()),
        )
    })?;
    if value.policy.id != expected_kind
        || value.subject != *expected_subject
        || value.submission_digest != *expected_submission_digest
    {
        return Err(protocol(
            StatusCode::CREATED,
            ReviewProtocolFailure::Body,
            Some(trace_id.to_owned()),
        ));
    }
    Ok(())
}

fn check_request_view(
    value: &ReviewRequestView,
    expected_request_id: Uuid,
    trace_id: &str,
) -> Result<(), ReviewClientError> {
    value.subject.check().map_err(|_| {
        protocol(
            StatusCode::OK,
            ReviewProtocolFailure::Body,
            Some(trace_id.to_owned()),
        )
    })?;
    value.policy.check().map_err(|_| {
        protocol(
            StatusCode::OK,
            ReviewProtocolFailure::Body,
            Some(trace_id.to_owned()),
        )
    })?;
    let active_stage_is_consistent = match value.lifecycle {
        registry_review_protocol::ReviewRequestLifecycle::Reviewing => value.active_stage.is_some(),
        _ => value.active_stage.is_none(),
    };
    if value.request_id != expected_request_id
        || !active_stage_is_consistent
        || value.requester_reference.is_empty()
        || value.requester_reference.len() > 256
        || value.requester_reference.chars().any(char::is_control)
        || value.active_stage.as_ref().is_some_and(|stage| {
            stage.is_empty() || stage.len() > 128 || stage.chars().any(char::is_control)
        })
        || value.updated_at < value.created_at
    {
        return Err(protocol(
            StatusCode::OK,
            ReviewProtocolFailure::Body,
            Some(trace_id.to_owned()),
        ));
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), ReviewClientError> {
    if value.is_empty()
        || value.len() > MAXIMUM_IDEMPOTENCY_KEY_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ReviewClientError::invalid_request(
            "the idempotency key is invalid",
        ));
    }
    Ok(())
}

fn response_trace(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<String, ReviewClientError> {
    response_trace_id(headers)
        .map(|value| value.as_str().to_owned())
        .map_err(|_| protocol(status, ReviewProtocolFailure::TraceContext, None))
}

fn exact_media_type(headers: &reqwest::header::HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    matches!((values.next(), values.next()), (Some(value), None) if value.as_bytes() == expected.as_bytes())
}

fn protocol(
    status: StatusCode,
    failure: ReviewProtocolFailure,
    trace_id: Option<String>,
) -> ReviewClientError {
    ReviewClientError::Protocol {
        status: status.as_u16(),
        failure,
        trace_id,
    }
}
