// SPDX-License-Identifier: Apache-2.0
//! Thin Node.js binding over the bounded Registry Discovery Rust client.

#![deny(unsafe_code)]

use std::{sync::Arc, time::Duration};

use napi::{
    bindgen_prelude::{Buffer, Either},
    Error, Result,
};
use napi_derive::napi;
use registry_discovery_client::{
    DiscoveryClient as CoreClient, DiscoveryClientConfig, DiscoveryClientError, DiscoveryProblem,
    EvidenceTypeResolveRequest, SelectionRequest, ServiceFilters, ServiceSearchResponse,
    ServiceSearchSelectionExt,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

const MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BYTES: usize = 4 * 1024 * 1024;

#[napi(object)]
pub struct DiscoveryClientOptions {
    pub base_url: String,
    pub request_timeout_milliseconds: Option<u32>,
    pub connect_timeout_milliseconds: Option<u32>,
    pub maximum_response_bytes: Option<u32>,
    pub trusted_root_certificates: Option<Buffer>,
}

fn error(source: DiscoveryClientError) -> Error {
    let value = match source {
        DiscoveryClientError::Configuration => json!({
            "kind": "configuration",
            "message": "the Discovery client configuration is invalid"
        }),
        DiscoveryClientError::Query => json!({
            "kind": "query",
            "message": "the Discovery query is invalid"
        }),
        DiscoveryClientError::NoMatchingService => json!({
            "kind": "no_matching_service",
            "message": "no advertised service matched the exact selection"
        }),
        DiscoveryClientError::AmbiguousSelection => json!({
            "kind": "ambiguous_selection",
            "message": "the exact selection is ambiguous"
        }),
        DiscoveryClientError::CapabilityMismatch => json!({
            "kind": "capability_mismatch",
            "message": "the selected advertised capability does not match the service"
        }),
        DiscoveryClientError::Transport { kind } => json!({
            "kind": "transport",
            "transportKind": kind.kind(),
            "message": "the Discovery exchange did not complete"
        }),
        DiscoveryClientError::Problem { status, problem } => json!({
            "kind": "problem",
            "status": status,
            "problem": problem_name(problem),
            "message": "Discovery refused the request"
        }),
        DiscoveryClientError::Protocol => json!({
            "kind": "protocol",
            "message": "the Discovery response did not satisfy its closed wire contract"
        }),
        _ => json!({
            "kind": "client",
            "message": "the Discovery client returned an unsupported failure"
        }),
    };
    Error::from_reason(serde_json::to_string(&value).unwrap_or_else(|_| {
        r#"{"kind":"protocol","message":"Discovery failed safely"}"#.to_owned()
    }))
}

fn problem_name(problem: DiscoveryProblem) -> &'static str {
    match problem {
        DiscoveryProblem::InvalidRequest => "invalid_request",
        DiscoveryProblem::NotFound => "not_found",
        DiscoveryProblem::ResultBoundExceeded => "result_bound_exceeded",
        DiscoveryProblem::Unavailable => "unavailable",
        _ => "unknown",
    }
}

fn decode<T: DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| error(DiscoveryClientError::Query))
}

fn encode<T: Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| error(DiscoveryClientError::Protocol))
}

fn selection(response: Value, request: Value) -> Result<Value> {
    let response: ServiceSearchResponse = decode(response)?;
    let request: SelectionRequest = decode(request)?;
    encode(&response.select_exact(request).map_err(error)?)
}

#[napi]
pub fn select_exact(response: Value, request: Value) -> Result<Value> {
    selection(response, request)
}

#[napi]
pub struct DiscoveryClient {
    inner: Arc<CoreClient>,
}

#[napi]
impl DiscoveryClient {
    #[napi(constructor)]
    pub fn new(options: Either<String, DiscoveryClientOptions>) -> Result<Self> {
        let options = match options {
            Either::A(base_url) => DiscoveryClientOptions {
                base_url,
                request_timeout_milliseconds: None,
                connect_timeout_milliseconds: None,
                maximum_response_bytes: None,
                trusted_root_certificates: None,
            },
            Either::B(options) => options,
        };
        let base_url = url::Url::parse(&options.base_url)
            .map_err(|_| error(DiscoveryClientError::Configuration))?;
        let mut config = DiscoveryClientConfig::new(base_url);
        if let Some(milliseconds) = options.request_timeout_milliseconds {
            config = config.with_request_timeout(Duration::from_millis(milliseconds.into()));
        }
        if let Some(milliseconds) = options.connect_timeout_milliseconds {
            config = config.with_connect_timeout(Duration::from_millis(milliseconds.into()));
        }
        if let Some(maximum) = options.maximum_response_bytes {
            config = config.with_maximum_response_bytes(maximum.into());
        }
        if let Some(certificates) = options.trusted_root_certificates {
            if certificates.len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BYTES {
                return Err(error(DiscoveryClientError::Configuration));
            }
            config = config.with_trusted_root_certificates(certificates.to_vec());
        }
        Ok(Self {
            inner: Arc::new(CoreClient::new(config).map_err(error)?),
        })
    }

    #[napi]
    pub async fn resolve_evidence_types(&self, request: Value) -> Result<Value> {
        let request: EvidenceTypeResolveRequest = decode(request)?;
        encode(
            &self
                .inner
                .resolve_evidence_types(request)
                .await
                .map_err(error)?,
        )
    }

    #[napi]
    pub async fn search_services(&self, filters: Value) -> Result<Value> {
        let filters: ServiceFilters = decode(filters)?;
        encode(&self.inner.search_services(filters).await.map_err(error)?)
    }

    #[napi]
    pub fn select_exact(&self, response: Value, request: Value) -> Result<Value> {
        selection(response, request)
    }
}
