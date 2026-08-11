use registry_platform_httpsec::{response_trace_id, ProblemDefinition, ProblemDocument, TraceId};
use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, OutboundOptions, ServiceBaseUrl,
};
use registry_platform_httputil::{
    read_bounded, retry_after_seconds, url::append_path_segments, validate_response_headers,
};
use registry_relay_http_contract::{ProblemCode, PROBLEM_MEDIA_TYPE};
use reqwest::header::{HeaderMap, CONTENT_TYPE, ETAG};
use reqwest::{Response, StatusCode, Url};

use crate::{ProtocolFailure, RelayClientConfig, RelayClientError, StrongEtag};

const MAXIMUM_PROBLEM_BYTES: usize = 4 * 1024;
const MAXIMUM_RETRY_AFTER_SECONDS: u64 = 60;

pub(crate) struct Transport {
    pub(crate) http: reqwest::Client,
    pub(crate) base_url: ServiceBaseUrl,
    pub(crate) max_response_bytes: u64,
}

impl Transport {
    pub(crate) fn new(config: &RelayClientConfig) -> Result<Self, RelayClientError> {
        let base_url = ServiceBaseUrl::new(config.base_url.clone())
            .map_err(|_| RelayClientError::configuration("the service base URL is not usable"))?;
        let http = build_client(OutboundOptions {
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config
                .trusted_root_certificates
                .as_deref()
                .map(Vec::as_slice),
        })
        .map_err(RelayClientError::configuration)?;
        Ok(Self {
            http,
            base_url,
            max_response_bytes: config.max_response_bytes,
        })
    }

    pub(crate) fn url(&self, segments: &[&str]) -> Result<Url, RelayClientError> {
        append_path_segments(self.base_url.as_url(), segments)
            .map_err(|_| RelayClientError::configuration("a route identifier cannot be encoded"))
    }

    pub(crate) async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<Response, RelayClientError> {
        let response = request
            .send()
            .await
            .map_err(|error| RelayClientError::transport(send_failure_kind(&error)))?;
        validate_response_headers(response.headers()).map_err(|_| {
            RelayClientError::protocol(
                response.status().as_u16(),
                ProtocolFailure::HeaderBounds,
                None,
            )
        })?;
        Ok(response)
    }

    pub(crate) async fn read(
        &self,
        response: Response,
        maximum: u64,
    ) -> Result<Vec<u8>, RelayClientError> {
        read_bounded(response, maximum.min(self.max_response_bytes))
            .await
            .map_err(|error| RelayClientError::transport(read_failure_kind(&error)))
    }

    /// Inspect the actual 304 message body without treating Content-Length as
    /// its size. RFC 9110 permits Content-Length on a 304 to describe the
    /// selected representation that a 200 response would have carried.
    pub(crate) async fn not_modified_body_is_empty(
        &self,
        mut response: Response,
    ) -> Result<bool, RelayClientError> {
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            let error = registry_platform_httputil::BoundedReadError::Transport(error);
            RelayClientError::transport(read_failure_kind(&error))
        })? {
            if !chunk.is_empty() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

pub(crate) fn trace_id(
    status: StatusCode,
    headers: &HeaderMap,
) -> Result<TraceId, RelayClientError> {
    response_trace_id(headers).map_err(|_| {
        RelayClientError::protocol(status.as_u16(), ProtocolFailure::TraceContext, None)
    })
}

pub(crate) fn exact_media_type(headers: &HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    matches!((values.next(), values.next()), (Some(value), None) if value.as_bytes() == expected.as_bytes())
}

pub(crate) fn response_etag(
    status: StatusCode,
    headers: &HeaderMap,
) -> Result<Option<StrongEtag>, RelayClientError> {
    let mut values = headers.get_all(ETAG).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(RelayClientError::protocol(
            status.as_u16(),
            ProtocolFailure::EntityTag,
            None,
        ));
    }
    let value = value.to_str().map_err(|_| {
        RelayClientError::protocol(status.as_u16(), ProtocolFailure::EntityTag, None)
    })?;
    StrongEtag::parse(value)
        .map(Some)
        .map_err(|_| RelayClientError::protocol(status.as_u16(), ProtocolFailure::EntityTag, None))
}

pub(crate) async fn problem(response: Response, transport: &Transport) -> RelayClientError {
    let status = response.status();
    let headers = response.headers().clone();
    let trace = match trace_id(status, &headers) {
        Ok(trace) => trace,
        Err(error) => return error,
    };
    if !exact_media_type(&headers, PROBLEM_MEDIA_TYPE) {
        return RelayClientError::protocol(
            status.as_u16(),
            ProtocolFailure::MediaType,
            Some(trace),
        );
    }
    let retry = (status == StatusCode::TOO_MANY_REQUESTS)
        .then(|| retry_after_seconds(&headers, MAXIMUM_RETRY_AFTER_SECONDS))
        .flatten();
    let body = match transport.read(response, MAXIMUM_PROBLEM_BYTES as u64).await {
        Ok(value) => value,
        Err(error) => return error,
    };
    let document = match ProblemDocument::parse_exact(&body, MAXIMUM_PROBLEM_BYTES) {
        Ok(value) => value,
        Err(_) => {
            return RelayClientError::protocol(
                status.as_u16(),
                ProtocolFailure::Problem,
                Some(trace),
            )
        }
    };
    let definitions = ProblemCode::ALL
        .iter()
        .map(|code| ProblemDefinition {
            type_uri: code.type_uri(),
            title: code.title(),
            status: code.status(),
            detail: code.detail(),
            code: code.code(),
        })
        .collect::<Vec<_>>();
    let Some(index) = document.definition_index(&definitions) else {
        return RelayClientError::protocol(status.as_u16(), ProtocolFailure::Problem, Some(trace));
    };
    let code = ProblemCode::ALL[index];
    if code.status() != status.as_u16() || trace != document.trace_id {
        return RelayClientError::protocol(status.as_u16(), ProtocolFailure::Problem, Some(trace));
    }
    RelayClientError::Problem {
        status: status.as_u16(),
        code,
        trace_id: trace,
        retry_after_seconds: retry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn entity_tags_are_exact_strong_sha256_tags() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ETAG,
            HeaderValue::from_static(
                "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
            ),
        );
        assert!(response_etag(StatusCode::OK, &headers).unwrap().is_some());
        for invalid in [
            "W/\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
            "\"ABCDEF\"",
        ] {
            headers.insert(ETAG, HeaderValue::from_str(invalid).unwrap());
            assert!(response_etag(StatusCode::OK, &headers).is_err());
        }
    }
}
