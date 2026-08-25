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
    renew_unchanged_service_selection, validate_service_selection_structure,
    DiscoveryClient as CoreClient, DiscoveryClientConfig, DiscoveryClientError, DiscoveryProblem,
    EvidenceSelectionRequest, EvidenceServiceQuery, EvidenceTypeResolveRequest,
    EvidenceTypeResolveResponse, EvidenceTypeResolveSelectionExt, RelaySelectionRequest,
    RelayServiceQuery, SelectionRequest, ServiceFilters, ServiceSearchResponse,
    ServiceSearchSelectionExt, ServiceSelection,
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
        DiscoveryClientError::NoMatchingAlternative => json!({
            "kind": "no_matching_alternative",
            "message": "no Evidence Type alternative matched the selection"
        }),
        DiscoveryClientError::AmbiguousAlternative => json!({
            "kind": "ambiguous_alternative",
            "message": "the Evidence Type alternative selection is ambiguous"
        }),
        DiscoveryClientError::CapabilityMismatch => json!({
            "kind": "capability_mismatch",
            "message": "the selected advertised capability does not match the service"
        }),
        DiscoveryClientError::LocalAcceptanceRefused => json!({
            "kind": "local_acceptance_refused",
            "message": "the relying application refused the advertised service"
        }),
        DiscoveryClientError::SelectionChanged => json!({
            "kind": "selection_changed",
            "message": "the current advertised service changed and requires new acceptance"
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

fn evidence_alternative(response: Value, evidence_type_list_id: Option<String>) -> Result<Value> {
    let response: EvidenceTypeResolveResponse = decode(response)?;
    let context = match evidence_type_list_id {
        Some(id) => response.select_alternative(&id),
        None => response.select_only_alternative(),
    }
    .map_err(error)?;
    encode(&context)
}

#[napi]
pub fn select_evidence_alternative(
    response: Value,
    evidence_type_list_id: Option<String>,
) -> Result<Value> {
    evidence_alternative(response, evidence_type_list_id)
}

#[napi]
pub fn select_evidence_service(response: Value, request: Value) -> Result<Value> {
    let response: ServiceSearchResponse = decode(response)?;
    let request: EvidenceSelectionRequest = decode(request)?;
    encode(&response.select_evidence(request).map_err(error)?)
}

#[napi]
pub fn select_relay_service(response: Value, request: Value) -> Result<Value> {
    let response: ServiceSearchResponse = decode(response)?;
    let request: RelaySelectionRequest = decode(request)?;
    encode(&response.select_relay(request).map_err(error)?)
}

#[napi]
pub fn validate_selection_structure(selection: Value) -> Result<Value> {
    let selection: ServiceSelection = decode(selection)?;
    validate_service_selection_structure(&selection).map_err(error)?;
    encode(&selection)
}

#[napi]
pub fn validate_selection(selection: Value) -> Result<Value> {
    validate_selection_structure(selection)
}

#[napi]
pub fn renew_unchanged_selection(previous: Value, current: Value) -> Result<Value> {
    let previous: ServiceSelection = decode(previous)?;
    let current: ServiceSelection = decode(current)?;
    encode(&renew_unchanged_service_selection(&previous, &current).map_err(error)?)
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
    pub async fn search_evidence_services(&self, query: Value) -> Result<Value> {
        let query: EvidenceServiceQuery = decode(query)?;
        encode(
            &self
                .inner
                .search_evidence_services(query)
                .await
                .map_err(error)?,
        )
    }

    #[napi]
    pub async fn search_relay_services(&self, query: Value) -> Result<Value> {
        let query: RelayServiceQuery = decode(query)?;
        encode(
            &self
                .inner
                .search_relay_services(query)
                .await
                .map_err(error)?,
        )
    }

    #[napi]
    pub fn select_exact(&self, response: Value, request: Value) -> Result<Value> {
        selection(response, request)
    }

    #[napi]
    pub fn select_evidence_alternative(
        &self,
        response: Value,
        evidence_type_list_id: Option<String>,
    ) -> Result<Value> {
        evidence_alternative(response, evidence_type_list_id)
    }

    #[napi]
    pub fn select_evidence_service(&self, response: Value, request: Value) -> Result<Value> {
        select_evidence_service(response, request)
    }

    #[napi]
    pub fn select_relay_service(&self, response: Value, request: Value) -> Result<Value> {
        select_relay_service(response, request)
    }
}
