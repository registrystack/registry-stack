use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, OutboundOptions, ServiceBaseUrl,
};
use registry_platform_httputil::{
    read_bounded, url::append_path_segments, validate_response_headers,
};
use reqwest::header::{HeaderMap, CONTENT_TYPE};
use reqwest::{Response, Url};

use crate::{BRegProtocolFailure, BaseRegistryClientConfig, BaseRegistryClientError};

pub(crate) struct Transport {
    pub(crate) http: reqwest::Client,
    pub(crate) base_url: ServiceBaseUrl,
    pub(crate) max_response_bytes: u64,
}

impl Transport {
    pub(crate) fn new(config: &BaseRegistryClientConfig) -> Result<Self, BaseRegistryClientError> {
        let base_url = ServiceBaseUrl::new(config.base_url.clone()).map_err(|_| {
            BaseRegistryClientError::configuration("the service base URL is not usable")
        })?;
        let http = build_client(OutboundOptions {
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config
                .trusted_root_certificates
                .as_deref()
                .map(Vec::as_slice),
        })
        .map_err(BaseRegistryClientError::configuration)?;
        Ok(Self {
            http,
            base_url,
            max_response_bytes: config.max_response_bytes,
        })
    }

    pub(crate) fn url(&self, segments: &[&str]) -> Result<Url, BaseRegistryClientError> {
        append_path_segments(self.base_url.as_url(), segments).map_err(|_| {
            BaseRegistryClientError::configuration("a route identifier cannot be encoded")
        })
    }

    pub(crate) async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<Response, BaseRegistryClientError> {
        let response = request
            .send()
            .await
            .map_err(|error| BaseRegistryClientError::transport(send_failure_kind(&error)))?;
        validate_response_headers(response.headers()).map_err(|_| {
            BaseRegistryClientError::protocol(
                response.status().as_u16(),
                BRegProtocolFailure::HeaderBounds,
                None,
            )
        })?;
        Ok(response)
    }

    pub(crate) async fn read(
        &self,
        response: Response,
        maximum: u64,
    ) -> Result<Vec<u8>, BaseRegistryClientError> {
        read_bounded(response, maximum.min(self.max_response_bytes))
            .await
            .map_err(|error| BaseRegistryClientError::transport(read_failure_kind(&error)))
    }
}

pub(crate) fn exact_media_type(headers: &HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    matches!((values.next(), values.next()), (Some(value), None) if value.as_bytes() == expected.as_bytes())
}
