// SPDX-License-Identifier: Apache-2.0
//! One-exchange bounded HTTP operations against Registry Discovery.

use std::time::Duration;

use registry_discovery::query::{service_matches_filters, validate_service_filters};
use registry_discovery::{
    valid_digest, valid_uri_identifier, validate_service, EvidenceTypeResolveRequest,
    EvidenceTypeResolveResponse, ServiceFilters, ServiceKind, ServiceSearchResponse,
    MAXIMUM_EVIDENCE_TYPES_PER_ALTERNATIVE, MAXIMUM_QUERY_BYTES, MAXIMUM_RESULT_ALTERNATIVES,
    MAXIMUM_RESULT_RECORDS,
};
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, OutboundOptions, ServiceBaseUrl,
};
use registry_platform_httputil::{read_bounded, validate_response_headers};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{DiscoveryClientError, DiscoveryProblem};

const JSON: &str = "application/json";
const PROBLEM_JSON: &str = "application/problem+json";
const MAXIMUM_PROBLEM_BYTES: u64 = 4 * 1024;
const MAXIMUM_REQUEST_BYTES: usize = 64 * 1024;
const DEFAULT_MAXIMUM_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

pub struct DiscoveryClientConfig {
    base_url: url::Url,
    request_timeout: Duration,
    connect_timeout: Duration,
    maximum_response_bytes: u64,
    trusted_root_certificates: Option<Zeroizing<Vec<u8>>>,
}

impl DiscoveryClientConfig {
    #[must_use]
    pub fn new(base_url: url::Url) -> Self {
        Self {
            base_url,
            request_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            maximum_response_bytes: DEFAULT_MAXIMUM_RESPONSE_BYTES,
            trusted_root_certificates: None,
        }
    }

    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_maximum_response_bytes(mut self, maximum: u64) -> Self {
        self.maximum_response_bytes = maximum;
        self
    }

    #[must_use]
    pub fn with_trusted_root_certificates(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.trusted_root_certificates = Some(Zeroizing::new(pem.into()));
        self
    }
}

impl std::fmt::Debug for DiscoveryClientConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiscoveryClientConfig")
            .field("base_url", &"<configured Discovery URL>")
            .field("request_timeout", &self.request_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .field(
                "has_trusted_root_certificates",
                &self.trusted_root_certificates.is_some(),
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct DiscoveryClient {
    base_url: ServiceBaseUrl,
    http: reqwest::Client,
    maximum_response_bytes: u64,
}

impl DiscoveryClient {
    pub fn new(config: DiscoveryClientConfig) -> Result<Self, DiscoveryClientError> {
        if config.request_timeout.is_zero()
            || config.connect_timeout.is_zero()
            || config.maximum_response_bytes == 0
            || config.maximum_response_bytes > 16 * 1024 * 1024
        {
            return Err(DiscoveryClientError::Configuration);
        }
        let base_url = ServiceBaseUrl::new(config.base_url)
            .map_err(|_| DiscoveryClientError::Configuration)?;
        let http = build_client(OutboundOptions {
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: Some("registry-discovery-client"),
            trusted_root_certificates: config
                .trusted_root_certificates
                .as_deref()
                .map(Vec::as_slice),
        })
        .map_err(|_| DiscoveryClientError::Configuration)?;
        Ok(Self {
            base_url,
            http,
            maximum_response_bytes: config.maximum_response_bytes,
        })
    }

    pub async fn resolve_evidence_types(
        &self,
        request: EvidenceTypeResolveRequest,
    ) -> Result<EvidenceTypeResolveResponse, DiscoveryClientError> {
        validate_resolve_request(&request)?;
        let response: EvidenceTypeResolveResponse = self
            .exchange(
                Method::POST,
                "v1/evidence-types/resolve",
                None,
                Some(&request),
            )
            .await?;
        validate_resolve_response(&request, &response)?;
        Ok(response)
    }

    pub async fn search_services(
        &self,
        filters: ServiceFilters,
    ) -> Result<ServiceSearchResponse, DiscoveryClientError> {
        validate_service_filters(&filters).map_err(|_| DiscoveryClientError::Query)?;
        let query = service_query(&filters)?;
        let response: ServiceSearchResponse = self
            .exchange(
                Method::GET,
                "v1/services",
                Some(&query),
                Option::<&()>::None,
            )
            .await?;
        validate_search_response(&filters, &response)?;
        Ok(response)
    }

    async fn exchange<T, B>(
        &self,
        method: Method,
        path: &str,
        query: Option<&str>,
        body: Option<&B>,
    ) -> Result<T, DiscoveryClientError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let mut url = self
            .base_url
            .join(path)
            .map_err(|_| DiscoveryClientError::Configuration)?;
        if let Some(query) = query {
            url.set_query((!query.is_empty()).then_some(query));
        }
        let mut request = self.http.request(method, url).header(ACCEPT, JSON);
        if let Some(body) = body {
            let bytes = serde_json::to_vec(body).map_err(|_| DiscoveryClientError::Query)?;
            if bytes.len() > MAXIMUM_REQUEST_BYTES {
                return Err(DiscoveryClientError::Query);
            }
            request = request.header(CONTENT_TYPE, JSON).body(bytes);
        }
        let response = request
            .send()
            .await
            .map_err(|error| DiscoveryClientError::transport(send_failure_kind(&error)))?;
        validate_response_headers(response.headers())
            .map_err(|_| DiscoveryClientError::Protocol)?;
        let status = response.status();
        let content_type = response_content_type(response.headers());
        let maximum = if status.is_success() {
            self.maximum_response_bytes
        } else {
            MAXIMUM_PROBLEM_BYTES
        };
        let bytes = read_bounded(response, maximum)
            .await
            .map_err(|error| DiscoveryClientError::transport(read_failure_kind(&error)))?;
        if status.is_success() {
            if content_type.as_deref() != Some(JSON) {
                return Err(DiscoveryClientError::Protocol);
            }
            strict_decode(&bytes)
        } else {
            if content_type.as_deref() != Some(PROBLEM_JSON) {
                return Err(DiscoveryClientError::Protocol);
            }
            Err(problem_from_response(status, &bytes)?)
        }
    }
}

fn response_content_type(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok()?,
        _ => return None,
    };
    value.split(';').next().map(str::trim).map(str::to_owned)
}

fn strict_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DiscoveryClientError> {
    let value = parse_json_strict(bytes).map_err(|_| DiscoveryClientError::Protocol)?;
    serde_json::from_value(value).map_err(|_| DiscoveryClientError::Protocol)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProblemBody {
    #[serde(rename = "type")]
    type_uri: String,
    title: String,
    status: u16,
}

fn problem_from_response(
    status: StatusCode,
    bytes: &[u8],
) -> Result<DiscoveryClientError, DiscoveryClientError> {
    let body: ProblemBody = strict_decode(bytes)?;
    if body.status != status.as_u16() || body.title.is_empty() || body.title.len() > 128 {
        return Err(DiscoveryClientError::Protocol);
    }
    let problem = match body.type_uri.as_str() {
        "https://registrystack.org/problems/discovery/invalid-request"
            if status == StatusCode::BAD_REQUEST =>
        {
            DiscoveryProblem::InvalidRequest
        }
        "https://registrystack.org/problems/discovery/not-found"
            if status == StatusCode::NOT_FOUND =>
        {
            DiscoveryProblem::NotFound
        }
        "https://registrystack.org/problems/discovery/result-bound-exceeded"
            if status == StatusCode::UNPROCESSABLE_ENTITY =>
        {
            DiscoveryProblem::ResultBoundExceeded
        }
        "https://registrystack.org/problems/discovery/unavailable"
            if status == StatusCode::SERVICE_UNAVAILABLE =>
        {
            DiscoveryProblem::Unavailable
        }
        _ => return Err(DiscoveryClientError::Protocol),
    };
    Ok(DiscoveryClientError::Problem {
        status: status.as_u16(),
        problem,
    })
}

fn validate_resolve_request(
    request: &EvidenceTypeResolveRequest,
) -> Result<(), DiscoveryClientError> {
    if !valid_uri_identifier(&request.requirement_id)
        || request
            .jurisdiction
            .as_deref()
            .is_some_and(|value| !valid_uri_identifier(value))
    {
        return Err(DiscoveryClientError::Query);
    }
    Ok(())
}

fn validate_resolve_response(
    request: &EvidenceTypeResolveRequest,
    response: &EvidenceTypeResolveResponse,
) -> Result<(), DiscoveryClientError> {
    if response.requirement_id != request.requirement_id
        || response.jurisdiction != request.jurisdiction
        || !valid_digest(&response.mapping_revision)
        || response.alternatives.len() > MAXIMUM_RESULT_ALTERNATIVES
    {
        return Err(DiscoveryClientError::Protocol);
    }
    for alternative in &response.alternatives {
        if !valid_uri_identifier(&alternative.evidence_type_list_id)
            || alternative.evidence_type_ids.is_empty()
            || alternative.evidence_type_ids.len() > MAXIMUM_EVIDENCE_TYPES_PER_ALTERNATIVE
            || alternative
                .evidence_type_ids
                .iter()
                .any(|value| !valid_uri_identifier(value))
            || alternative
                .evidence_type_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || !valid_uri_identifier(&alternative.mapping_id)
            || !valid_uri_identifier(&alternative.mapping_authority_id)
        {
            return Err(DiscoveryClientError::Protocol);
        }
    }
    if response
        .alternatives
        .windows(2)
        .any(|pair| pair[0].evidence_type_list_id >= pair[1].evidence_type_list_id)
    {
        return Err(DiscoveryClientError::Protocol);
    }
    Ok(())
}

fn validate_search_response(
    filters: &ServiceFilters,
    response: &ServiceSearchResponse,
) -> Result<(), DiscoveryClientError> {
    if !valid_digest(&response.catalog_revision)
        || response.items.len() > MAXIMUM_RESULT_RECORDS
        || response
            .items
            .windows(2)
            .any(|pair| pair[0].record_id >= pair[1].record_id)
    {
        return Err(DiscoveryClientError::Protocol);
    }
    for service in &response.items {
        validate_service(service).map_err(|_| DiscoveryClientError::Protocol)?;
        if !service_matches_filters(service, filters) {
            return Err(DiscoveryClientError::Protocol);
        }
    }
    Ok(())
}

fn service_query(filters: &ServiceFilters) -> Result<String, DiscoveryClientError> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for value in &filters.record_id {
        serializer.append_pair("recordId", value);
    }
    for value in &filters.service_id {
        serializer.append_pair("serviceId", value);
    }
    for value in &filters.service_kind {
        serializer.append_pair(
            "serviceKind",
            match value {
                ServiceKind::Evidence => "evidence",
                ServiceKind::Relay => "relay",
            },
        );
    }
    for (name, values) in [
        ("jurisdiction", &filters.jurisdiction),
        ("conformsTo", &filters.conforms_to),
        ("evidenceType", &filters.evidence_type),
        ("semanticClass", &filters.semantic_class),
        ("operationFamily", &filters.operation_family),
    ] {
        for value in values {
            serializer.append_pair(name, value);
        }
    }
    let query = serializer.finish();
    if query.len() > MAXIMUM_QUERY_BYTES {
        return Err(DiscoveryClientError::Query);
    }
    Ok(query)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::header::LOCATION;
    use axum::http::{Request, Response};
    use axum::routing::any;
    use axum::Router;
    use registry_discovery::{catalog_revision, ServiceRecord};
    use serde_json::json;
    use tokio::net::TcpListener;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    #[derive(Clone, Copy)]
    enum Mode {
        Valid,
        Redirect,
        Oversized,
    }

    #[derive(Clone)]
    struct TestState {
        mode: Mode,
        redirected: Arc<AtomicUsize>,
    }

    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log capture").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            CapturedLogWriter(Arc::clone(&self.0))
        }
    }

    fn service() -> ServiceRecord {
        ServiceRecord {
            record_id: "record-a".into(),
            binding_id: "urn:binding:a".into(),
            service_id: "urn:service".into(),
            service_kind: ServiceKind::Evidence,
            title: "Evidence".into(),
            description: "Evidence service".into(),
            endpoint_url: "https://provider.example/evidence".into(),
            publisher_id: None,
            operator_id: None,
            registry_authority_id: None,
            legal_issuer_id: None,
            technical_provider_id: None,
            jurisdictions: vec!["urn:jurisdiction".into()],
            conforms_to: vec!["urn:profile".into()],
            evidence_type_ids: vec!["urn:evidence".into()],
            semantic_class_ids: Vec::new(),
            operation_family_ids: Vec::new(),
            origin_id: "origin-a".into(),
            origin_url: "https://provider.example/catalog.jsonld".into(),
            origin_content_digest: format!("sha256:{}", "1".repeat(64)),
            origin_fetched_at: "2026-08-14T00:00:00Z".into(),
        }
    }

    async fn handler(State(state): State<TestState>, request: Request<Body>) -> Response<Body> {
        match state.mode {
            Mode::Redirect => {
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::FOUND;
                response.headers_mut().insert(
                    LOCATION,
                    "/redirected".parse().expect("valid redirect location"),
                );
                response
            }
            Mode::Oversized => json_response(json!({ "padding": "x".repeat(8192) })),
            Mode::Valid if request.uri().path().ends_with("evidence-types/resolve") => {
                json_response(json!({
                    "requirementId": "urn:requirement",
                    "mappingRevision": format!("sha256:{}", "2".repeat(64)),
                    "alternatives": []
                }))
            }
            Mode::Valid => {
                let service = service();
                json_response(json!({
                    "catalogRevision": catalog_revision(std::slice::from_ref(&service)).unwrap(),
                    "items": [service]
                }))
            }
        }
    }

    async fn redirected(State(state): State<TestState>) -> Response<Body> {
        state.redirected.fetch_add(1, Ordering::SeqCst);
        json_response(json!({}))
    }

    fn json_response(value: serde_json::Value) -> Response<Body> {
        let mut response = Response::new(Body::from(serde_json::to_vec(&value).unwrap()));
        response.headers_mut().insert(
            CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static(JSON),
        );
        response
    }

    async fn client(mode: Mode, maximum: u64) -> (DiscoveryClient, TestState) {
        let state = TestState {
            mode,
            redirected: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new()
            .route("/redirected", any(redirected))
            .route("/{*path}", any(handler))
            .with_state(state.clone());
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config =
            DiscoveryClientConfig::new(url::Url::parse(&format!("http://{address}")).unwrap())
                .with_maximum_response_bytes(maximum);
        (DiscoveryClient::new(config).unwrap(), state)
    }

    #[tokio::test]
    async fn real_client_resolves_and_searches_in_one_exact_exchange_each() {
        let (client, _) = client(Mode::Valid, 1024 * 1024).await;
        let resolved = client
            .resolve_evidence_types(EvidenceTypeResolveRequest {
                requirement_id: "urn:requirement".into(),
                jurisdiction: None,
            })
            .await
            .unwrap();
        assert!(resolved.alternatives.is_empty());

        let mut filters = ServiceFilters::default();
        filters.evidence_type.push("urn:evidence".into());
        let searched = client.search_services(filters).await.unwrap();
        assert_eq!(searched.items[0].record_id, "record-a");
    }

    #[test]
    fn resolve_response_refuses_an_over_bound_evidence_type_list() {
        let request = EvidenceTypeResolveRequest {
            requirement_id: "urn:example:requirement".into(),
            jurisdiction: None,
        };
        let response = EvidenceTypeResolveResponse {
            requirement_id: request.requirement_id.clone(),
            jurisdiction: None,
            mapping_revision: format!("sha256:{}", "2".repeat(64)),
            alternatives: vec![registry_discovery::ResolvedAlternative {
                evidence_type_list_id: "urn:example:list".into(),
                evidence_type_ids: (0..=MAXIMUM_EVIDENCE_TYPES_PER_ALTERNATIVE)
                    .map(|index| format!("urn:example:evidence:{index:03}"))
                    .collect(),
                mapping_id: "urn:example:mapping".into(),
                mapping_authority_id: "urn:example:authority".into(),
            }],
        };

        assert_eq!(
            validate_resolve_response(&request, &response),
            Err(DiscoveryClientError::Protocol)
        );
    }

    #[test]
    fn query_serialization_preserves_fragment_iris_as_values() {
        let fragment = "https://example.org/vocabulary#RegisteredBusiness";
        let mut filters = ServiceFilters::default();
        filters.semantic_class.push(fragment.into());

        let query = service_query(&filters).expect("valid fragment IRI filter");
        assert!(!query.contains('#'));
        assert_eq!(
            url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>(),
            [("semanticClass".into(), fragment.into())]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn client_diagnostics_never_log_request_values() {
        let query_canary = "urn:example:secret-filter-canary";
        let requirement_canary = "urn:example:secret-requirement-canary";
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::INFO)
            .with_writer(logs.clone())
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let (client, _) = client(Mode::Valid, 1024 * 1024).await;

        let mut filters = ServiceFilters::default();
        filters.evidence_type.push(query_canary.into());
        let _ = client.search_services(filters).await;
        let _ = client
            .resolve_evidence_types(EvidenceTypeResolveRequest {
                requirement_id: requirement_canary.into(),
                jurisdiction: None,
            })
            .await;

        let rendered = String::from_utf8(logs.0.lock().expect("log capture").clone())
            .expect("JSON logs are UTF-8");
        assert!(!rendered.contains(query_canary));
        assert!(!rendered.contains(requirement_canary));
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let (client, state) = client(Mode::Redirect, 1024).await;
        assert_eq!(
            client.search_services(ServiceFilters::default()).await,
            Err(DiscoveryClientError::Protocol)
        );
        assert_eq!(state.redirected.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn response_bytes_are_bounded() {
        let (client, _) = client(Mode::Oversized, 1024).await;
        assert!(matches!(
            client.search_services(ServiceFilters::default()).await,
            Err(DiscoveryClientError::Transport {
                kind: registry_platform_httputil::TransportKind::ResponseTooLarge
            })
        ));
    }

    #[test]
    fn config_debug_never_renders_the_full_url() {
        let config = DiscoveryClientConfig::new(
            url::Url::parse("https://secret-host-canary.invalid/private-path").unwrap(),
        );
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("secret-host-canary"));
        assert!(!rendered.contains("private-path"));
    }

    #[test]
    fn production_client_requires_https_and_permits_only_explicit_loopback_http() {
        let public_http = DiscoveryClientConfig::new(
            url::Url::parse("http://discovery.example.invalid").unwrap(),
        );
        assert!(matches!(
            DiscoveryClient::new(public_http),
            Err(DiscoveryClientError::Configuration)
        ));
        let loopback =
            DiscoveryClientConfig::new(url::Url::parse("http://127.0.0.1:8080").unwrap());
        assert!(DiscoveryClient::new(loopback).is_ok());
    }
}
