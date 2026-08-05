//! Contract tests for exact, source-neutral HTTP/JSON execution.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use registry_evidence::bundle::{Bundle, BundleError, RuntimeDocument};
use registry_evidence::config::{
    AcquisitionPosture, HttpMethod, OutboundTlsConfig, PreparationChannelPolicy, PreparationLimits,
    SourceConfig, RESERVED_HEADER_CONTRACT_CASES,
};
use registry_evidence::kernel::{EvidenceConstruction, OfflineKernel, ValueProjection};
use registry_evidence::model::{LookupResult, PublicValue, SelectorValue, SubjectBinding};
use registry_evidence::rhai_runtime::{
    CalendarDate, EvaluationContext, LegalLocalTime, QueryPair, RequestPartRequirement,
    RequestParts, RequestPartsBounds, RequestPartsLimits, RhaiRuntime, RhaiRuntimeError,
    UtcInstant, MAXIMUM_ARRAY_ITEMS, MAXIMUM_JSON_BODY_DEPTH, MAXIMUM_QUERY_NAME_BYTES,
    MAXIMUM_QUERY_PAIRS, MAXIMUM_QUERY_VALUE_BYTES, MAXIMUM_REQUEST_PARTS_BYTES,
    MAXIMUM_STRING_BYTES,
};
use registry_evidence::secrets::{SecretProvider, SecretResolver};
use registry_evidence::signing::{jwks_document, EvidenceSigner};
use registry_evidence::source::{
    project_fixture_response, ResolvedSourceSelector, SourceError, SourceExecutor, SourceStatus,
};
use registry_evidence::verifier::{verify_flattened_jws, EvidenceVerificationPolicy};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SHAPE_EVIDENCE_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"source-shape-evidence-key"}"#;

fn source_config(
    base_url: &str,
    authentication: Value,
    path_fields: Value,
    fixed_headers: Value,
    projection: Value,
) -> SourceConfig {
    serde_json::from_value(json!({
        "transport": "http-json",
        "baseUrl": base_url,
        "posture": "record-transformed",
        "authentication": authentication,
        "request": {
            "method": "POST",
            "pathTemplate": "/v1/records/{record}",
            "pathBindings": {
                "record": {"role": "subject", "profile": "record-v1", "field": "record_id"}
            },
            "fixedHeaders": fixed_headers,
            "selectorInputs": [{
                "role": "subject",
                "alternatives": [{"profile": "record-v1", "fields": path_fields}]
            }],
            "prepareScript": "adapters/prepare.rhai",
            "adapterParameters": {},
            "adapterParametersSchema": "schemas/parameters.schema.yaml",
            "preparationLimits": {
                "query": "allowed",
                "jsonBody": "allowed",
                "maximumQueryPairs": 8,
                "maximumQueryNameBytes": 64,
                "maximumQueryValueBytes": 256,
                "maximumJsonDepth": 8,
                "maximumCollectionItems": 32,
                "maximumStringBytes": 512,
                "maximumNormalizedBytes": 4096
            },
            "projection": projection,
            "redirects": "deny",
            "timeoutMilliseconds": 1000,
            "maximumResponseBytes": 65536,
            "concurrencyLimit": 4
        },
        "responseSchema": "schemas/response.schema.yaml",
        "extractScript": "adapters/extract.rhai",
        "factSchema": "schemas/facts.schema.yaml"
    }))
    .expect("source config deserializes")
}

fn fixed_source(base_url: &str, authentication: Value) -> SourceConfig {
    let mut source = source_config(
        base_url,
        authentication,
        json!(["record_id"]),
        json!([]),
        json!(["/ok"]),
    );
    source.request.path = Some("/data".into());
    source.request.path_template = None;
    source.request.path_bindings = Default::default();
    source.request.method = registry_evidence::config::HttpMethod::POST;
    source
}

fn oauth_source(
    base_url: &str,
    token_endpoint: &str,
    placement: &str,
    maximum_cache_seconds: u64,
) -> SourceConfig {
    oauth_source_with_assumed_lifetime(
        base_url,
        token_endpoint,
        placement,
        maximum_cache_seconds,
        None,
    )
}

fn oauth_source_with_assumed_lifetime(
    base_url: &str,
    token_endpoint: &str,
    placement: &str,
    maximum_cache_seconds: u64,
    assumed_lifetime_seconds: Option<u64>,
) -> SourceConfig {
    let mut authentication = json!({
        "kind": "oauth2-client-credentials",
        "tokenEndpoint": token_endpoint,
        "clientIdRef": "secret:file/oauth-client-id",
        "clientSecretRef": "secret:file/oauth-client-secret",
        "scope": "fixture.read",
        "credentialPlacement": placement,
        "maximumCacheSeconds": maximum_cache_seconds
    });
    if let Some(seconds) = assumed_lifetime_seconds {
        authentication["assumedLifetimeSeconds"] = json!(seconds);
    }
    fixed_source(base_url, authentication)
}

fn selector(value: &str) -> ResolvedSourceSelector {
    ResolvedSourceSelector {
        role: "subject".into(),
        profile: "record-v1".into(),
        values: BTreeMap::from([("record_id".into(), SelectorValue::String(value.into()))]),
    }
}

fn parts() -> RequestParts {
    RequestParts {
        query: vec![
            QueryPair {
                name: "filter".into(),
                value: "first value".into(),
            },
            QueryPair {
                name: "filter".into(),
                value: "second/value%".into(),
            },
        ],
        body: Some(json!({"limit": 1, "requested": ["status"]})),
    }
}

fn resolver(entries: &[(&str, &str)]) -> (TempDir, Arc<SecretResolver>) {
    let root = tempfile::tempdir().expect("temporary secret root");
    for (name, value) in entries {
        let path = root.path().join(name);
        fs::write(&path, value).expect("write synthetic secret");
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("protect secret");
    }
    let resolver = SecretResolver::new([SecretProvider::File], root.path())
        .map(Arc::new)
        .expect("resolver builds");
    (root, resolver)
}

fn encoded_parameters(bytes: &[u8]) -> Vec<(String, String)> {
    url::form_urlencoded::parse(bytes)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn query_parameters(url: &url::Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn contains_parameter(parameters: &[(String, String)], name: &str, value: &str) -> bool {
    parameters
        .iter()
        .any(|(actual_name, actual_value)| actual_name == name && actual_value == value)
}

fn request_limits(config: &PreparationLimits) -> RequestPartsLimits {
    fn channel(policy: PreparationChannelPolicy) -> RequestPartRequirement {
        match policy {
            PreparationChannelPolicy::Required => RequestPartRequirement::Required,
            PreparationChannelPolicy::Allowed => RequestPartRequirement::Optional,
            PreparationChannelPolicy::Forbidden => RequestPartRequirement::Forbidden,
        }
    }

    fn configured(value: Option<u64>, fallback: usize) -> usize {
        value
            .map(|value| usize::try_from(value).expect("configured limit fits usize"))
            .unwrap_or(fallback)
    }

    RequestPartsLimits::new(
        channel(config.query),
        channel(config.json_body),
        RequestPartsBounds {
            maximum_query_pairs: configured(config.maximum_query_pairs, MAXIMUM_QUERY_PAIRS),
            maximum_query_name_bytes: configured(
                config.maximum_query_name_bytes,
                MAXIMUM_QUERY_NAME_BYTES,
            ),
            maximum_query_value_bytes: configured(
                config.maximum_query_value_bytes,
                MAXIMUM_QUERY_VALUE_BYTES,
            ),
            maximum_json_depth: configured(config.maximum_json_depth, MAXIMUM_JSON_BODY_DEPTH),
            maximum_collection_items: configured(
                config.maximum_collection_items,
                MAXIMUM_ARRAY_ITEMS,
            ),
            maximum_string_bytes: configured(config.maximum_string_bytes, MAXIMUM_STRING_BYTES),
            maximum_normalized_bytes: configured(
                config.maximum_normalized_bytes,
                MAXIMUM_REQUEST_PARTS_BYTES,
            ),
        },
    )
    .expect("fixture preparation limits satisfy the production ABI")
}

fn shape_selectors(shape: &str) -> (Value, Vec<ResolvedSourceSelector>) {
    let (profile, values, resolved) = match shape {
        "flat-rest" => (
            "opaque-coordinates-v1",
            json!({"alpha": "synthetic-alpha", "delta": 42}),
            BTreeMap::from([
                (
                    "alpha".into(),
                    SelectorValue::String("synthetic-alpha".into()),
                ),
                ("delta".into(), SelectorValue::Integer(42)),
            ]),
        ),
        "nested-paged-rest" => (
            "civil-record-reference-v1",
            json!({"record_reference": "B0000000001"}),
            BTreeMap::from([(
                "record_reference".into(),
                SelectorValue::String("B0000000001".into()),
            )]),
        ),
        "opencrvs-event-search-json" => (
            "civil-record-reference-v1",
            json!({"record_reference": "TRACKING-CANARY-0001"}),
            BTreeMap::from([(
                "record_reference".into(),
                SelectorValue::String("TRACKING-CANARY-0001".into()),
            )]),
        ),
        _ => panic!("source-shape index contains an unknown profile"),
    };
    (
        json!({"subject": {"profile": profile, "values": values}}),
        vec![ResolvedSourceSelector {
            role: "subject".into(),
            profile: profile.into(),
            values: resolved,
        }],
    )
}

fn source_shape_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/fixtures/source-shapes")
}

fn copy_fixture_tree(source: &Path, target: &Path) {
    fs::create_dir(target).expect("fixture directory is copied");
    for entry in fs::read_dir(source).expect("fixture directory is readable") {
        let entry = entry.expect("fixture entry is readable");
        let destination = target.join(entry.file_name());
        if entry
            .file_type()
            .expect("fixture entry type is readable")
            .is_dir()
        {
            copy_fixture_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("fixture file is copied");
        }
    }
}

#[cfg(unix)]
fn make_fixture_bundle_read_only(path: &Path) {
    for entry in fs::read_dir(path).expect("fixture bundle is readable") {
        let entry = entry.expect("fixture bundle entry is readable");
        let child = entry.path();
        if entry
            .file_type()
            .expect("fixture bundle entry type is readable")
            .is_dir()
        {
            make_fixture_bundle_read_only(&child);
        } else {
            fs::set_permissions(child, fs::Permissions::from_mode(0o444))
                .expect("fixture bundle file becomes read-only");
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o555))
        .expect("fixture bundle directory becomes read-only");
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is UTF-8"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

async fn spawn_private_ca_tls_server(
    server_subject_alt_name: &str,
) -> (std::net::SocketAddr, Vec<u8>, JoinHandle<()>) {
    let mut ca_parameters =
        CertificateParams::new(Vec::<String>::new()).expect("private CA parameters are valid");
    ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("private CA key generates");
    let ca_certificate = ca_parameters
        .self_signed(&ca_key)
        .expect("private CA certificate generates");

    let server_parameters = CertificateParams::new(vec![server_subject_alt_name.to_owned()])
        .expect("server certificate parameters are valid");
    let server_key = KeyPair::generate().expect("server key generates");
    let server_certificate = server_parameters
        .signed_by(&server_key, &ca_certificate, &ca_key)
        .expect("private CA signs server certificate");
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_certificate.der().clone()], private_key)
        .expect("TLS server configuration builds");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TLS test server binds");
    let address = listener.local_addr().expect("TLS server address");
    let handle = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };
        let mut request = Vec::with_capacity(1_024);
        loop {
            let mut chunk = [0_u8; 512];
            let Ok(read) = stream.read(&mut chunk).await else {
                return;
            };
            if read == 0 || request.len() + read > 8_192 {
                return;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let _ = stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
            )
            .await;
        let _ = stream.shutdown().await;
    });
    (
        address,
        pem("CERTIFICATE", ca_certificate.der().as_ref()).into_bytes(),
        handle,
    )
}

/// Accepts TCP connections, counts each one, and resets it (`RST`, not a
/// graceful close) before any HTTP bytes are exchanged. Used to prove that a
/// transport failure on a source's very first connection attempt does not
/// trigger a second, silent connection.
async fn spawn_reset_on_connect_server() -> (std::net::SocketAddr, Arc<AtomicUsize>, JoinHandle<()>)
{
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reset server binds");
    let address = listener.local_addr().expect("reset server address");
    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&attempts);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = stream.set_zero_linger();
            drop(stream);
        }
    });
    (address, attempts, handle)
}

#[tokio::test]
async fn exact_request_applies_path_query_body_headers_auth_and_projection_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/records/A%20B"))
        .and(header("accept", "application/vnd.registry+json"))
        .and(header("x-fixed-contract", "v1"))
        .and(header("x-source-key", "api-key-canary"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "ignored": "private-canary",
            "results": [{
                "status": "ACTIVE",
                "declaration": {
                    "mother.personReference": "P-1",
                    "private": "private-canary"
                }
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (_root, secrets) = resolver(&[("api-key", "api-key-canary")]);
    let source = source_config(
        &server.uri(),
        json!({"kind": "static-api-key", "headerName": "X-Source-Key", "valueRef": "secret:file/api-key"}),
        json!(["record_id"]),
        json!([
            {"name": "Accept", "value": "application/vnd.registry+json"},
            {"name": "X-Fixed-Contract", "value": "v1"}
        ]),
        json!([
            "/total",
            "/results/*/status",
            "/results/*/declaration/mother.personReference"
        ]),
    );
    let executor = SourceExecutor::new(&source, secrets).expect("executor builds");
    let response = executor
        .execute(&[selector("A B")], &parts())
        .await
        .expect("source succeeds");
    assert_eq!(
        response,
        json!({
            "total": 1,
            "results": [{
                "status": "ACTIVE",
                "declaration": {"mother.personReference": "P-1"}
            }]
        })
    );
    let requests = server.received_requests().await.expect("requests recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url.query(),
        Some("filter=first%20value&filter=second%2Fvalue%25")
    );
    assert_eq!(
        requests[0]
            .url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect::<Vec<_>>(),
        vec![
            ("filter".into(), "first value".into()),
            ("filter".into(), "second/value%".into())
        ]
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].body).expect("JSON body"),
        json!({"limit": 1, "requested": ["status"]})
    );
}

#[test]
fn materialized_request_reuses_path_template_query_and_body_without_auth_material() {
    let (_root, secrets) = resolver(&[]);
    let source = source_config(
        "http://127.0.0.1:18080",
        json!({"kind": "static-bearer", "tokenRef": "secret:file/missing-token"}),
        json!(["record_id"]),
        json!([{"name": "X-Fixed-Contract", "value": "fixed-header-canary"}]),
        json!(["/ok"]),
    );
    let executor = SourceExecutor::new(&source, secrets).expect("executor builds without secrets");
    let materialized = executor
        .materialize_request(&[selector("A B")], &parts())
        .expect("request materializes without credential access");
    assert_eq!(materialized.path(), "/v1/records/A%20B");
    assert_eq!(
        materialized.query(),
        Some("filter=first%20value&filter=second%2Fvalue%25")
    );
    assert_eq!(
        materialized.body(),
        Some(&json!({"limit": 1, "requested": ["status"]}))
    );

    let diagnostic = format!("{materialized:?}");
    for protected in [
        "127.0.0.1",
        "A%20B",
        "first%20value",
        "second%2Fvalue%25",
        "status",
        "fixed-header-canary",
        "missing-token",
    ] {
        assert!(!diagnostic.contains(protected));
    }
}

#[tokio::test]
async fn local_unauthenticated_loopback_source_sends_no_authentication_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1)
        .mount(&server)
        .await;
    let (_root, secrets) = resolver(&[]);
    let source = fixed_source(&server.uri(), json!({"kind": "none"}));
    let executor = SourceExecutor::new(&source, secrets).expect("local source plan compiles");

    executor
        .credentials_ready()
        .await
        .expect("credential-free readiness has no bootstrap");
    assert!(
        server
            .received_requests()
            .await
            .expect("request journal")
            .is_empty(),
        "readiness must not contact the source"
    );

    let response = executor
        .execute(&[selector("synthetic")], &parts())
        .await
        .expect("local source request succeeds");
    assert_eq!(response, json!({"ok": true}));

    let requests = server.received_requests().await.expect("request journal");
    assert_eq!(requests.len(), 1);
    assert!(
        !requests[0].headers.contains_key("authorization"),
        "credential-free source must not receive Authorization"
    );

    let forbidden_header = source_config(
        &server.uri(),
        json!({"kind": "none"}),
        json!(["record_id"]),
        json!([{"name": "Authorization", "value": "caller-controlled"}]),
        json!(["/ok"]),
    );
    assert_eq!(
        SourceExecutor::new(&forbidden_header, resolver(&[]).1).err(),
        Some(SourceError::InvalidPlan),
        "fixed headers cannot recreate authentication in local mode"
    );

    for invalid_origin in [
        "https://127.0.0.1:18081",
        "http://127.0.0.1",
        "http://localhost:18081",
    ] {
        let invalid = fixed_source(invalid_origin, json!({"kind": "none"}));
        assert_eq!(
            SourceExecutor::new(&invalid, resolver(&[]).1).err(),
            Some(SourceError::InvalidPlan),
            "executor rejected unauthenticated origin {invalid_origin}"
        );
    }
}

#[tokio::test]
async fn hostile_path_values_and_malformed_preparation_fail_before_transport_and_redact() {
    let server = MockServer::start().await;
    let (_root, secrets) = resolver(&[("token", "credential-canary")]);
    let source = source_config(
        &server.uri(),
        json!({"kind": "static-bearer", "tokenRef": "secret:file/token"}),
        json!(["record_id"]),
        json!([]),
        json!(["/ok"]),
    );
    let executor = SourceExecutor::new(&source, secrets).expect("executor builds");
    for hostile in [".", "..", "a/b", "a\\b", "a%2Fb", "a\nb"] {
        let error = executor
            .execute(
                &[selector(hostile)],
                &RequestParts {
                    query: vec![],
                    body: None,
                },
            )
            .await
            .expect_err("hostile path value fails");
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains(hostile));
        assert!(!diagnostic.contains("credential-canary"));
    }
    let error = executor
        .execute(
            &[selector("safe")],
            &RequestParts {
                query: vec![QueryPair {
                    name: "x\r\nInjected".into(),
                    value: "v".into(),
                }],
                body: None,
            },
        )
        .await
        .expect_err("header-style query injection fails");
    assert_eq!(error, SourceError::InvalidPlan);
    assert!(server
        .received_requests()
        .await
        .expect("requests")
        .is_empty());
}

#[tokio::test]
async fn path_binding_contract_rejects_empty_missing_and_extra_material_before_credentials() {
    let (_empty_root, empty_secrets) = resolver(&[]);
    let base = source_config(
        "http://127.0.0.1:18080",
        json!({"kind": "static-bearer", "tokenRef": "secret:file/missing-token"}),
        json!(["record_id"]),
        json!([]),
        json!(["/ok"]),
    );
    for (case_id, template) in [
        ("empty-placeholder", "/v1/records/{}"),
        ("missing-binding", "/v1/records/{missing}"),
        ("extra-binding", "/v1/records"),
    ] {
        let mut source = base.clone();
        source.request.path_template = Some(template.to_owned());
        assert_eq!(
            SourceExecutor::new(&source, Arc::clone(&empty_secrets)).err(),
            Some(SourceError::InvalidPlan),
            "{case_id}: invalid template/binding closure is rejected"
        );
    }

    let server = MockServer::start().await;
    let mut source = base;
    source.base_url = server.uri();
    let executor = SourceExecutor::new(&source, empty_secrets).expect("valid path plan compiles");
    let mut missing_field = selector("unused");
    missing_field.values.clear();
    let mut extra_field = selector("record");
    extra_field.values.insert(
        "extra".to_owned(),
        SelectorValue::String("canary".to_owned()),
    );
    let extra_role = ResolvedSourceSelector {
        role: "other".to_owned(),
        profile: "record-v1".to_owned(),
        values: BTreeMap::from([(
            "record_id".to_owned(),
            SelectorValue::String("canary".to_owned()),
        )]),
    };
    for (case_id, selectors, expected) in [
        (
            "empty-path-value",
            vec![selector("")],
            SourceError::InvalidSelectors,
        ),
        (
            "missing-path-field",
            vec![missing_field],
            SourceError::InvalidSelectors,
        ),
        (
            "extra-path-field",
            vec![extra_field],
            SourceError::InvalidSelectors,
        ),
        (
            "extra-selector-role",
            vec![selector("record"), extra_role],
            SourceError::InvalidSelectors,
        ),
        (
            "missing-selector-role",
            vec![],
            SourceError::InvalidSelectors,
        ),
    ] {
        let error = executor
            .execute(
                &selectors,
                &RequestParts {
                    query: vec![],
                    body: None,
                },
            )
            .await
            .expect_err("invalid path material fails before credentials");
        assert_eq!(error, expected, "{case_id}: exact source error");
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("canary"));
        assert!(!diagnostic.contains("missing-token"));
    }
    assert!(server
        .received_requests()
        .await
        .expect("request journal")
        .is_empty());
}

#[tokio::test]
async fn get_body_is_rejected_before_static_or_oauth_credential_acquisition() {
    let token_server = MockServer::start().await;
    let data_server = MockServer::start().await;
    let (_empty_root, empty_secrets) = resolver(&[]);

    let mut static_source = fixed_source(
        &data_server.uri(),
        json!({"kind": "static-bearer", "tokenRef": "secret:file/missing-token"}),
    );
    static_source.request.method = HttpMethod::GET;
    static_source.request.preparation_limits.json_body = PreparationChannelPolicy::Forbidden;
    let static_executor =
        SourceExecutor::new(&static_source, Arc::clone(&empty_secrets)).expect("valid GET builds");
    assert_eq!(
        static_executor
            .execute(
                &[selector("record")],
                &RequestParts {
                    query: vec![],
                    body: Some(json!({"prohibited": true})),
                },
            )
            .await,
        Err(SourceError::InvalidPlan)
    );

    let mut oauth = oauth_source(
        &data_server.uri(),
        &format!("{}/token", token_server.uri()),
        "form-body",
        60,
    );
    oauth.request.method = HttpMethod::GET;
    oauth.request.preparation_limits.json_body = PreparationChannelPolicy::Forbidden;
    let oauth_executor =
        SourceExecutor::new(&oauth, empty_secrets).expect("valid OAuth GET builds");
    assert_eq!(
        oauth_executor
            .execute(
                &[selector("record")],
                &RequestParts {
                    query: vec![],
                    body: Some(json!({"prohibited": true})),
                },
            )
            .await,
        Err(SourceError::InvalidPlan)
    );
    assert!(token_server
        .received_requests()
        .await
        .expect("token journal")
        .is_empty());
    assert!(data_server
        .received_requests()
        .await
        .expect("data journal")
        .is_empty());

    let mut invalid_get = static_source;
    invalid_get.request.preparation_limits.json_body = PreparationChannelPolicy::Allowed;
    assert_eq!(
        SourceExecutor::new(&invalid_get, resolver(&[]).1).err(),
        Some(SourceError::InvalidPlan)
    );
}

#[tokio::test]
async fn every_frozen_source_shape_executes_through_production_materialization_and_projection() {
    let root = source_shape_root();
    let index: Value = serde_norway::from_str(
        &fs::read_to_string(root.join("index.yaml")).expect("source-shape index is readable"),
    )
    .expect("source-shape index parses");
    let profiles = index["profiles"]
        .as_array()
        .expect("source-shape profiles are an array");
    let declared = profiles
        .iter()
        .map(|profile| profile["id"].as_str().expect("profile id"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        declared,
        BTreeSet::from([
            "flat-rest",
            "nested-paged-rest",
            "opencrvs-event-search-json",
        ])
    );

    let runtime = RhaiRuntime::new();
    let mut matched_facts = BTreeMap::new();
    for profile in profiles {
        let id = profile["id"].as_str().expect("profile id");
        let directory = root.join(profile["path"].as_str().expect("profile path"));
        let contract: Value = serde_norway::from_str(
            &fs::read_to_string(directory.join("contract.yaml"))
                .expect("source-shape contract is readable"),
        )
        .expect("source-shape contract parses");
        assert_eq!(contract["synthetic_only"], json!(true));
        let server = MockServer::start().await;
        let mut source_value = contract["validated_source_definition"].clone();
        source_value["baseUrl"] = json!(server.uri());
        if id == "opencrvs-event-search-json" {
            source_value["authentication"]["tokenEndpoint"] =
                json!(format!("{}/oauth/token", server.uri()));
        }
        let source: SourceConfig =
            serde_json::from_value(source_value).expect("validated source definition is typed");
        let preparation = runtime
            .compile_preparation(
                &fs::read_to_string(directory.join(source.request.prepare_script.as_str()))
                    .expect("preparation script is readable"),
            )
            .expect("preparation script compiles");
        let extraction = runtime
            .compile_extraction(
                &fs::read_to_string(directory.join(source.extract_script.as_str()))
                    .expect("extraction script is readable"),
            )
            .expect("extraction script compiles");
        let fact_schema_value: Value = serde_norway::from_str(
            &fs::read_to_string(directory.join(source.fact_schema.as_str()))
                .expect("fact schema is readable"),
        )
        .expect("fact schema parses");
        let fact_schema =
            jsonschema::JSONSchema::compile(&fact_schema_value).expect("fact schema compiles");
        let response_schema_value: Value = serde_norway::from_str(
            &fs::read_to_string(directory.join(source.response_schema.as_str()))
                .expect("response schema is readable"),
        )
        .expect("response schema parses");
        let response_schema = jsonschema::JSONSchema::options()
            .should_validate_formats(true)
            .compile(&response_schema_value)
            .expect("response schema compiles");
        let parameters = serde_json::to_value(&source.request.adapter_parameters)
            .expect("adapter parameters serialize");
        let (script_selectors, transport_selectors) = shape_selectors(id);
        let prepared = runtime
            .prepare(
                &preparation,
                &script_selectors,
                &parameters,
                &request_limits(&source.request.preparation_limits),
            )
            .expect("shape request preparation succeeds");
        let expected_request = &contract["request"];
        assert_eq!(
            prepared.body.as_ref(),
            match expected_request["body"].as_str() {
                Some("absent") => None,
                _ => Some(&expected_request["body"]),
            },
            "{id}: prepared body differs from the committed contract"
        );
        let expected_query = expected_request["query_order"]
            .as_array()
            .map(|order| {
                order
                    .iter()
                    .map(|name| {
                        let name = name.as_str().expect("query-order name");
                        (
                            name.to_owned(),
                            expected_request["query"][name]
                                .as_str()
                                .expect("query value")
                                .to_owned(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        assert!(
            prepared
                .query
                .iter()
                .map(|pair| (pair.name.clone(), pair.value.clone()))
                .eq(expected_query.clone()),
            "{id}: prepared query differs from the committed contract"
        );
        let (secret_entries, expected_authorization) = match id {
            "flat-rest" => (
                vec![("fixture-flat-rest-token", "shape-static-bearer-canary")],
                "Bearer shape-static-bearer-canary".to_owned(),
            ),
            "nested-paged-rest" => (
                vec![
                    ("fixture-nested-rest-username", "shape-basic-user-canary"),
                    (
                        "fixture-nested-rest-password",
                        "shape-basic-password-canary",
                    ),
                ],
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode("shape-basic-user-canary:shape-basic-password-canary")
                ),
            ),
            "opencrvs-event-search-json" => (
                vec![
                    (
                        "fixture-event-search-client-id",
                        "shape-oauth-client-canary",
                    ),
                    (
                        "fixture-event-search-client-secret",
                        "shape-oauth-secret-canary",
                    ),
                ],
                "Bearer shape-oauth-access-token-canary".to_owned(),
            ),
            _ => unreachable!("closed source-shape profiles"),
        };
        let (_secret_root, secrets) = resolver(&secret_entries);
        let executor = SourceExecutor::new(&source, secrets).expect("source plan compiles");
        let match_response: Value = serde_json::from_slice(
            &fs::read(directory.join("responses/match.json"))
                .expect("match response fixture is readable"),
        )
        .expect("match response fixture is JSON");
        if id == "opencrvs-event-search-json" {
            // The reference shape returns only access_token and token_type.
            // Adding a lifetime here would make the mock more compliant than
            // the provider it models and hide the assumed-lifetime path.
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "shape-oauth-access-token-canary",
                    "token_type": "Bearer"
                })))
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(method(
            expected_request["method"].as_str().expect("request method"),
        ))
        .and(path(
            expected_request["path"].as_str().expect("request path"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(match_response))
        .expect(1)
        .mount(&server)
        .await;
        let materialized = executor
            .materialize_request(&transport_selectors, &prepared)
            .expect("production request materialization succeeds");
        assert_eq!(
            materialized.path(),
            expected_request["path"].as_str().expect("request path")
        );
        assert_eq!(
            materialized.query().map(|query| {
                url::form_urlencoded::parse(query.as_bytes())
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect::<Vec<_>>()
            }),
            (!expected_query.is_empty()).then_some(expected_query.clone()),
            "{id}: production query materialization drifted"
        );
        assert_eq!(materialized.body(), prepared.body.as_ref());

        let projected = executor
            .execute(&transport_selectors, &prepared)
            .await
            .expect("frozen shape executes through the production transport");
        // Every committed cardinality response of the shape has to sit inside the
        // declared response schema, because the runtime refuses the response
        // before extraction otherwise.
        for case in ["match", "no-match", "ambiguous", "missing-fact"] {
            let recorded: Value = serde_json::from_slice(
                &fs::read(directory.join(format!("responses/{case}.json")))
                    .expect("cardinality response fixture is readable"),
            )
            .expect("cardinality response fixture is JSON");
            let recorded = project_fixture_response(&source, &recorded)
                .expect("cardinality response fixture projects");
            assert!(
                response_schema.is_valid(&recorded),
                "{id}: committed {case} response is outside the declared response schema"
            );
        }
        assert!(
            response_schema.is_valid(&projected),
            "{id}: transport-backed response is outside the declared response schema"
        );
        let facts = match runtime
            .extract(&extraction, &projected, &parameters, &fact_schema)
            .expect("projected transport response extracts")
        {
            LookupResult::Match(facts) => facts,
            _ => panic!("{id}: transport-backed match returned a non-match outcome"),
        };
        matched_facts.insert(id.to_owned(), facts.clone());

        let requests = server
            .received_requests()
            .await
            .expect("source-shape request journal is available");
        let data_requests = requests
            .iter()
            .filter(|request| {
                request.url.path() == expected_request["path"].as_str().expect("request path")
            })
            .collect::<Vec<_>>();
        assert_eq!(data_requests.len(), 1, "{id}: exact evidence-data count");
        let data_request = data_requests[0];
        assert_eq!(
            data_request.method.as_str(),
            expected_request["method"].as_str().expect("request method")
        );
        assert_eq!(
            query_parameters(&data_request.url),
            expected_query,
            "{id}: exact data query"
        );
        assert!(
            data_request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value == expected_authorization),
            "{id}: exact evidence-data authentication"
        );
        for (name, value) in expected_request["headers"]
            .as_object()
            .expect("reviewed request headers are an object")
        {
            if name == "authorization" {
                continue;
            }
            assert!(
                data_request
                    .headers
                    .get(name)
                    .and_then(|actual| actual.to_str().ok())
                    .is_some_and(|actual| actual == value.as_str().expect("header value")),
                "{id}: exact reviewed header {name}"
            );
        }
        match prepared.body.as_ref() {
            Some(expected) => assert_eq!(
                serde_json::from_slice::<Value>(&data_request.body)
                    .expect("evidence-data body is JSON"),
                *expected,
                "{id}: exact evidence-data body"
            ),
            None => assert!(data_request.body.is_empty(), "{id}: body remains absent"),
        }
        if id == "opencrvs-event-search-json" {
            let token_requests = requests
                .iter()
                .filter(|request| request.url.path() == "/oauth/token")
                .collect::<Vec<_>>();
            assert_eq!(token_requests.len(), 1, "exact OAuth bootstrap count");
            // The reference shape accepts the client credentials in the token
            // request body, so no credential may appear in the token URL.
            assert!(
                query_parameters(&token_requests[0].url).is_empty(),
                "OAuth bootstrap URL carries no query"
            );
            let form = encoded_parameters(&token_requests[0].body);
            assert!(
                form.len() == 4
                    && contains_parameter(&form, "grant_type", "client_credentials")
                    && contains_parameter(&form, "scope", "fixture.read")
                    && contains_parameter(&form, "client_id", "shape-oauth-client-canary")
                    && contains_parameter(&form, "client_secret", "shape-oauth-secret-canary"),
                "OAuth bootstrap body is the exact reviewed shape"
            );
            assert!(token_requests[0].headers.get("authorization").is_none());
            assert_eq!(
                token_requests[0]
                    .headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok()),
                Some("application/x-www-form-urlencoded")
            );
            assert_eq!(
                token_requests[0]
                    .headers
                    .get("accept")
                    .and_then(|value| value.to_str().ok()),
                Some("application/json")
            );
            assert_eq!(requests.len(), 2);
        } else {
            assert_eq!(requests.len(), 1);
        }

        let mut response_files = fs::read_dir(directory.join("responses"))
            .expect("response fixture directory is readable")
            .map(|entry| entry.expect("response fixture entry").path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .collect::<Vec<_>>();
        response_files.sort();
        let names = response_files
            .iter()
            .map(|path| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .expect("response fixture name")
            })
            .collect::<BTreeSet<_>>();
        for required in [
            "ambiguous.json",
            "error-envelope.json",
            "match.json",
            "missing-fact.json",
            "no-match.json",
        ] {
            assert!(
                names.contains(required),
                "{id}: required outcome {required} is absent"
            );
        }

        for response_path in response_files {
            let name = response_path
                .file_name()
                .and_then(|value| value.to_str())
                .expect("response fixture name");
            let response: Value = serde_json::from_slice(
                &fs::read(&response_path).expect("response fixture is readable"),
            )
            .expect("response fixture is JSON");
            let projected = project_fixture_response(&source, &response);
            if name == "error-envelope.json" {
                assert_eq!(projected, Err(SourceError::ErrorEnvelope));
                continue;
            }
            let projected = projected.expect("response projection succeeds");
            let lookup = runtime.extract(&extraction, &projected, &parameters, &fact_schema);
            match name {
                "match.json" => match lookup.expect("match extraction succeeds") {
                    LookupResult::Match(direct_facts) => assert_eq!(
                        direct_facts, facts,
                        "{id}: direct fixture and real transport extraction drifted"
                    ),
                    _ => panic!("{id}: match fixture returned a non-match outcome"),
                },
                "no-match.json" => assert!(matches!(lookup, Ok(LookupResult::NoMatch))),
                "ambiguous.json" => assert!(matches!(lookup, Ok(LookupResult::Ambiguous))),
                "missing-fact.json" => {
                    assert_eq!(lookup, Err(RhaiRuntimeError::FactSchema));
                }
                "inconsistent-cardinality.json" => {
                    assert_eq!(lookup, Err(RhaiRuntimeError::SourceProtocol));
                }
                _ => panic!("{id}: unclassified response fixture {name}"),
            }
        }
    }

    let acceptance_copy = tempfile::tempdir().expect("temporary acceptance bundle root");
    let acceptance_root = acceptance_copy.path().join("residence-region");
    copy_fixture_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/residence-region"),
        &acceptance_root,
    );
    make_fixture_bundle_read_only(&acceptance_root);
    let kernel = OfflineKernel::compile(Arc::new(
        Bundle::load(&acceptance_root).expect("immutable residence acceptance bundle loads"),
    ))
    .expect("residence acceptance kernel compiles");
    let requirement = "urn:example:fixture:requirement:residence-region:v1";
    let observed_at = "2026-08-02T00:00:00Z"
        .parse()
        .expect("fixed observation time parses");
    let private = PrivateJwk::parse(SHAPE_EVIDENCE_PRIVATE_JWK).expect("test signing key parses");
    let provider: Arc<dyn SigningProvider> =
        Arc::new(LocalJwkSigner::new(private).expect("test signing provider builds"));
    let signer = EvidenceSigner::initialize(provider, "source-shape-evidence-key")
        .await
        .expect("test signer passes its self-test");
    let jwks =
        jwks_document(signer.public_jwk(), std::iter::empty()).expect("test public key publishes");

    for shape in ["flat-rest", "nested-paged-rest"] {
        let values = kernel
            .derive_and_validate(
                requirement,
                matched_facts.get(shape).expect("shape match facts exist"),
                observed_at,
                ValueProjection {
                    audience: "https://relying.invalid/residence-procedure",
                    binding_key: b"source-shape-binding-key-32-bytes-minimum",
                    binding_key_version: 1,
                },
            )
            .expect("real residence derivation and immutable output gate succeed");
        assert_eq!(values.as_slice().len(), 1);
        assert_eq!(
            values.as_slice()[0].provides_value_for,
            "urn:example:fixture:concept:residence-region"
        );
        assert_eq!(
            values.as_slice()[0].value,
            PublicValue::String("REGION-NORTH".to_owned()),
            "{shape}: source-shape swap changed the governed controlled code"
        );
        let evidence = kernel
            .construct_evidence(
                requirement,
                values,
                EvidenceConstruction {
                    evidence_id: "urn:ulid:01J4BRXQ0ZZZZZZZZZZZZZZZZZ",
                    request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                    purpose: "fixture-routing",
                    audience: "https://relying.invalid/residence-procedure",
                    issued_at: observed_at,
                    observed_at,
                    subjects: vec![SubjectBinding {
                        role: "subject".to_owned(),
                        binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
                    }],
                },
            )
            .expect("real residence Evidence constructs");
        let jws = signer
            .sign_json(&evidence)
            .await
            .expect("real residence Evidence signs");
        let serialized = serde_json::to_vec(&jws).expect("flattened JWS serializes");
        let mut policy = EvidenceVerificationPolicy::from_accepted_transaction(
            &evidence,
            registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
            Duration::from_secs(31_536_000),
            observed_at,
            Duration::from_secs(0),
        );
        policy.issued_by = "urn:example:fixture:issuer:authority".to_owned();
        policy.provided_by = "urn:example:fixture:provider:evidence".to_owned();
        policy.requirement = requirement.to_owned();
        policy.evidence_type = "urn:example:fixture:evidence-type:residence-region:v1".to_owned();
        policy.purpose = "fixture-routing".to_owned();
        policy.audience = "https://relying.invalid/residence-procedure".to_owned();
        policy.configuration_revision = kernel.bundle().revision().to_owned();
        let verified = verify_flattened_jws(&serialized, &jwks, &policy)
            .expect("signed residence Evidence verifies under the exact relying policy");
        assert_eq!(
            verified.supported_values[0].value,
            PublicValue::String("REGION-NORTH".to_owned())
        );
    }
}

#[tokio::test]
async fn every_acquisition_posture_fixture_executes_with_one_bounded_request() {
    let fixture: Value = serde_norway::from_str(include_str!(
        "../../../products/evidence/fixtures/conformance/acquisition-postures.yaml"
    ))
    .expect("acquisition-posture fixture parses");
    let cases = fixture["cases"]
        .as_array()
        .expect("acquisition-posture cases are an array");
    let runtime = RhaiRuntime::new();
    let preparation = runtime
        .compile_preparation("fn prepare(selectors, parameters) { #{query: [], body: #{}} }")
        .expect("common posture preparation compiles");
    let mut executed = BTreeSet::new();

    for case in cases {
        let posture_name = case["posture"].as_str().expect("posture name");
        executed.insert(posture_name.to_owned());
        let (posture, derived_fact, expected_claim, expected_negative) = match posture_name {
            "source-derived" => (
                AcquisitionPosture::SourceDerived,
                "final_code",
                "acquisition and disclosure minimization",
                "source-returns-undeclared-field",
            ),
            "field-projected" => (
                AcquisitionPosture::FieldProjected,
                "fact_b",
                "strong acquisition and disclosure minimization",
                "fixed-projection-expanded",
            ),
            "record-transformed" => (
                AcquisitionPosture::RecordTransformed,
                "fact_a",
                "disclosure minimization only",
                "full-lifecycle-minimization-overclaim",
            ),
            _ => panic!("unknown acquisition posture fixture case"),
        };
        assert_eq!(case["expected_claim"], json!(expected_claim));
        assert_eq!(case["negative"], json!(expected_negative));
        let declared_facts = case["declared_facts"]
            .as_array()
            .expect("declared facts are an array")
            .iter()
            .map(|value| value.as_str().expect("declared fact").to_owned())
            .collect::<Vec<_>>();
        let mut response = case["source_response"].clone();
        response["result"]["undeclared_source_canary"] = json!("never-project-this-value");

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        let (_root, secrets) = resolver(&[("token", "synthetic-posture-token")]);
        let mut source = fixed_source(
            &server.uri(),
            json!({"kind": "static-bearer", "tokenRef": "secret:file/token"}),
        );
        source.posture = posture;
        source.request.projection = std::iter::once("/total".to_owned())
            .chain(declared_facts.iter().map(|fact| format!("/result/{fact}")))
            .collect();
        let prepared = runtime
            .prepare(
                &preparation,
                &json!({}),
                &json!({}),
                &request_limits(&source.request.preparation_limits),
            )
            .expect("common posture preparation succeeds");
        let projected = SourceExecutor::new(&source, secrets)
            .expect("posture source compiles")
            .execute(&[selector("record")], &prepared)
            .await
            .expect("posture source request succeeds");
        assert!(!serde_json::to_string(&projected)
            .expect("projected response serializes")
            .contains("never-project-this-value"));

        let facts_body = declared_facts
            .iter()
            .map(|fact| format!("{fact}: source_response[\"result\"][\"{fact}\"]"))
            .collect::<Vec<_>>()
            .join(",");
        let extraction = runtime
            .compile_extraction(&format!(
                "fn extract(source_response, parameters) {{ #{{outcome: \"match\", facts: #{{{facts_body}}}}} }}"
            ))
            .expect("posture extraction compiles");
        let properties = declared_facts
            .iter()
            .map(|fact| (fact.clone(), json!({})))
            .collect::<serde_json::Map<String, Value>>();
        let schema = jsonschema::JSONSchema::compile(&json!({
            "type": "object",
            "additionalProperties": false,
            "required": declared_facts,
            "properties": properties
        }))
        .expect("posture fact schema compiles");
        let facts = match runtime
            .extract(&extraction, &projected, &json!({}), &schema)
            .expect("posture extraction succeeds")
        {
            LookupResult::Match(facts) => facts,
            _ => panic!("posture extraction returned a non-match outcome"),
        };
        let derivation = runtime
            .compile_derivation(&format!(
                "fn derive(facts, selectors, evaluation_context) {{ [#{{concept_id: \"posture-result\", value: facts[\"{derived_fact}\"]}}] }}"
            ))
            .expect("posture derivation compiles");
        let derived = runtime
            .derive(
                &derivation,
                &facts,
                &json!({}),
                EvaluationContext::new(
                    UtcInstant::parse("2026-08-02T00:00:00Z").expect("instant"),
                    CalendarDate::parse("2026-08-02").expect("date"),
                    LegalLocalTime::parse("07:00:00+07:00").expect("local time"),
                    &json!({}),
                    BTreeMap::new(),
                )
                .expect("evaluation context"),
            )
            .expect("posture derivation succeeds");
        assert!(derived.len() == 1 && derived[0].concept_id == "posture-result");
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("request journal")
                .len(),
            1
        );
    }

    assert_eq!(
        executed,
        BTreeSet::from([
            "field-projected".to_owned(),
            "record-transformed".to_owned(),
            "source-derived".to_owned(),
        ])
    );
}

#[tokio::test]
async fn basic_bearer_and_static_api_key_headers_are_exact_and_failures_are_redacted() {
    let cases = [
        (
            json!({"kind": "basic", "usernameRef": "secret:file/user", "passwordRef": "secret:file/password"}),
            vec![("user", "basic-user"), ("password", "basic-password")],
            "authorization",
            format!(
                "Basic {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    "basic-user:basic-password"
                )
            ),
        ),
        (
            json!({"kind": "static-bearer", "tokenRef": "secret:file/token"}),
            vec![("token", "bearer-token")],
            "authorization",
            "Bearer bearer-token".into(),
        ),
        (
            json!({"kind": "static-api-key", "headerName": "X-Api-Key", "valueRef": "secret:file/key"}),
            vec![("key", "static-key")],
            "x-api-key",
            "static-key".into(),
        ),
    ];
    for (authentication, entries, header_name, header_value) in cases {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/data"))
            .and(header(header_name, header_value.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .expect(1)
            .mount(&server)
            .await;
        let (_root, secrets) = resolver(&entries);
        let source = fixed_source(&server.uri(), authentication);
        let executor = SourceExecutor::new(&source, secrets).expect("executor builds");
        executor
            .execute(
                &[selector("record")],
                &RequestParts {
                    query: vec![],
                    body: Some(json!({})),
                },
            )
            .await
            .expect("authenticated request succeeds");
    }
}

async fn assert_oauth_success_matrix_case(placement: &str, maximum_cache_seconds: u64) {
    let server = MockServer::start().await;
    let client_id = format!("client-id-{}", ulid::Ulid::new());
    let client_secret = format!("client-secret-{}", ulid::Ulid::new());
    let access_token = format!("access-token-{}", ulid::Ulid::new());
    let expected_token_requests: usize = if maximum_cache_seconds == 0 { 2 } else { 1 };

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": access_token.clone(),
            "token_type": "Bearer",
            "expires_in": 120,
            "scope": "fixture.read"
        })))
        .expect(expected_token_requests as u64)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(2)
        .mount(&server)
        .await;

    let (_root, secrets) = resolver(&[
        ("oauth-client-id", client_id.as_str()),
        ("oauth-client-secret", client_secret.as_str()),
    ]);
    let source = oauth_source(
        &server.uri(),
        &format!("{}/token", server.uri()),
        placement,
        maximum_cache_seconds,
    );
    let executor = SourceExecutor::new(&source, secrets).expect("OAuth executor builds");
    for _ in 0..2 {
        executor
            .execute(
                &[selector("record")],
                &RequestParts {
                    query: vec![],
                    body: Some(json!({})),
                },
            )
            .await
            .expect("OAuth-authenticated source request succeeds");
    }

    let requests = server.received_requests().await.expect("request journal");
    let token_requests = requests
        .iter()
        .filter(|request| request.url.path() == "/token")
        .collect::<Vec<_>>();
    let data_requests = requests
        .iter()
        .filter(|request| request.url.path() == "/data")
        .collect::<Vec<_>>();
    assert!(
        token_requests.len() == expected_token_requests,
        "unexpected OAuth token request count"
    );
    assert!(
        data_requests.len() == 2,
        "unexpected evidence-data request count"
    );
    assert!(data_requests.iter().all(|request| {
        request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == format!("Bearer {access_token}"))
    }));

    for request in token_requests {
        let query = query_parameters(&request.url);
        let form = encoded_parameters(&request.body);
        match placement {
            "basic-header" => {
                let expected = format!(
                    "Basic {}",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        format!("{client_id}:{client_secret}")
                    )
                );
                assert!(query.is_empty(), "Basic placement added token query fields");
                assert!(
                    form.len() == 2
                        && contains_parameter(&form, "grant_type", "client_credentials")
                        && contains_parameter(&form, "scope", "fixture.read"),
                    "Basic placement token form is not exact"
                );
                assert!(request
                    .headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value == expected));
            }
            "form-body" => {
                assert!(query.is_empty(), "form placement added token query fields");
                assert!(request.headers.get("authorization").is_none());
                assert!(
                    form.len() == 4
                        && contains_parameter(&form, "grant_type", "client_credentials")
                        && contains_parameter(&form, "scope", "fixture.read")
                        && contains_parameter(&form, "client_id", &client_id)
                        && contains_parameter(&form, "client_secret", &client_secret),
                    "form placement token body is not exact"
                );
            }
            _ => panic!("unknown non-secret test placement"),
        }
    }
}

#[tokio::test]
async fn oauth_client_credentials_placements_are_exact_and_cache_reuse_is_bounded() {
    for placement in ["basic-header", "form-body"] {
        assert_oauth_success_matrix_case(placement, 60).await;
        assert_oauth_success_matrix_case(placement, 0).await;
    }
}

/// A provider that omits `expires_in` still gets a bounded cache, and the
/// configured maximum still wins over the assumed lifetime.
#[tokio::test]
async fn oauth_assumed_lifetime_caches_an_omitted_provider_lifetime_and_stays_clamped() {
    for (maximum_cache_seconds, expected_token_requests) in [(60_u64, 1_u64), (0, 2)] {
        let server = MockServer::start().await;
        let access_token = format!("access-token-{}", ulid::Ulid::new());
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token.clone(),
                "token_type": "Bearer"
            })))
            .expect(expected_token_requests)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .expect(2)
            .mount(&server)
            .await;

        let (_root, secrets) = resolver(&[
            ("oauth-client-id", "assumed-lifetime-client-id"),
            ("oauth-client-secret", "assumed-lifetime-client-secret"),
        ]);
        let source = oauth_source_with_assumed_lifetime(
            &server.uri(),
            &format!("{}/token", server.uri()),
            "form-body",
            maximum_cache_seconds,
            Some(120),
        );
        let executor = SourceExecutor::new(&source, secrets).expect("OAuth executor builds");
        for _ in 0..2 {
            executor
                .execute(
                    &[selector("record")],
                    &RequestParts {
                        query: vec![],
                        body: Some(json!({})),
                    },
                )
                .await
                .expect("assumed lifetime authorizes the request");
        }
    }
}

#[tokio::test]
async fn oauth_credential_redaction_fixture_fails_closed_without_data_requests() {
    let fixture: Value = serde_norway::from_str(include_str!(
        "../../../products/evidence/fixtures/conformance/oauth-credential-redaction.yaml"
    ))
    .expect("OAuth redaction fixture parses");
    let declared = fixture["cases"]
        .as_array()
        .expect("fixture cases are an array")
        .iter()
        .map(|case| {
            case["id"]
                .as_str()
                .expect("fixture case has an id")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "malformed-token-json".to_owned(),
        "token-400".to_owned(),
        "token-401".to_owned(),
        "token-response-extra-field".to_owned(),
        "token-response-oversized".to_owned(),
        "token-response-wrong-access-token-field".to_owned(),
        "token-response-wrong-lifetime".to_owned(),
        "token-response-wrong-media-type".to_owned(),
        "token-response-wrong-scope".to_owned(),
        "token-response-omitted-lifetime".to_owned(),
        "token-response-omitted-lifetime-with-assumed-lifetime".to_owned(),
        "token-response-wrong-token-type".to_owned(),
        "token-success".to_owned(),
        "transport-connection-failure".to_owned(),
        "transport-timeout".to_owned(),
    ]);
    assert_eq!(
        declared, expected,
        "OAuth fixture and executable matrix drifted"
    );

    for case_id in declared {
        let server = MockServer::start().await;
        let client_id = format!("client-id-{}", ulid::Ulid::new());
        let client_secret = format!("client-secret-{}", ulid::Ulid::new());
        let access_token = format!("access-token-{}", ulid::Ulid::new());
        let response = match case_id.as_str() {
            "transport-connection-failure" => None,
            "token-success" => Some(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token.clone(),
                "token_type": "Bearer",
                "expires_in": 120,
                "scope": "fixture.read"
            }))),
            "token-400" => Some(
                ResponseTemplate::new(400).set_body_string(client_secret.clone()),
            ),
            "token-401" => Some(
                ResponseTemplate::new(401).set_body_string(client_secret.clone()),
            ),
            "malformed-token-json" => {
                Some(ResponseTemplate::new(200).set_body_raw("{invalid", "application/json"))
            }
            "token-response-oversized" => Some(ResponseTemplate::new(200).set_body_raw(
                format!(
                    "{{\"access_token\":\"{}\",\"token_type\":\"Bearer\",\"expires_in\":120}}",
                    "x".repeat(9_000)
                ),
                "application/json",
            )),
            "token-response-extra-field" => Some(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token.clone(),
                "token_type": "Bearer",
                "expires_in": 120,
                "unexpected": client_secret.clone()
            }))),
            "token-response-wrong-access-token-field" => {
                Some(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": 7,
                    "token_type": "Bearer",
                    "expires_in": 120
                })))
            }
            "token-response-wrong-token-type" => Some(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token.clone(),
                "token_type": "MAC",
                "expires_in": 120
            }))),
            "token-response-wrong-scope" => Some(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token.clone(),
                "token_type": "Bearer",
                "expires_in": 120,
                "scope": "other.scope"
            }))),
            "token-response-wrong-lifetime" => Some(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token.clone(),
                "token_type": "Bearer",
                "expires_in": 0
            }))),
            // The minimum RFC 6749 section 5.1 response. Accepted only when the
            // bundle states the lifetime to assume.
            "token-response-omitted-lifetime"
            | "token-response-omitted-lifetime-with-assumed-lifetime" => {
                Some(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": access_token.clone(),
                    "token_type": "Bearer"
                })))
            }
            "token-response-wrong-media-type" => Some(ResponseTemplate::new(200).set_body_raw(
                format!(
                    "{{\"access_token\":\"{access_token}\",\"token_type\":\"Bearer\",\"expires_in\":120}}"
                ),
                "text/plain",
            )),
            "transport-timeout" => Some(ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(100))
                .set_body_json(json!({
                    "access_token": access_token.clone(),
                    "token_type": "Bearer",
                    "expires_in": 120
                }))),
            _ => panic!("fixture contains an unknown case id: {case_id}"),
        };
        if let Some(response) = response {
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("POST"))
            .and(path("/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&server)
            .await;

        let (_root, secrets) = resolver(&[
            ("oauth-client-id", client_id.as_str()),
            ("oauth-client-secret", client_secret.as_str()),
        ]);
        let token_endpoint = if case_id == "transport-connection-failure" {
            "http://127.0.0.1:0/token".to_owned()
        } else {
            format!("{}/token", server.uri())
        };
        let assumed_lifetime_seconds =
            (case_id == "token-response-omitted-lifetime-with-assumed-lifetime").then_some(120);
        let mut source = oauth_source_with_assumed_lifetime(
            &server.uri(),
            &token_endpoint,
            "form-body",
            0,
            assumed_lifetime_seconds,
        );
        if case_id == "transport-timeout" {
            source.request.timeout_milliseconds = 20;
        }
        let executor = SourceExecutor::new(&source, secrets).expect("OAuth executor builds");
        let result = executor
            .execute(
                &[selector("record")],
                &RequestParts {
                    query: vec![],
                    body: Some(json!({})),
                },
            )
            .await;
        let expects_success = matches!(
            case_id.as_str(),
            "token-success" | "token-response-omitted-lifetime-with-assumed-lifetime"
        );
        if expects_success {
            assert!(result.is_ok(), "success fixture case {case_id} failed");
        } else {
            let expected_error = match case_id.as_str() {
                "transport-timeout" => SourceError::Timeout,
                "transport-connection-failure" => SourceError::Transport,
                _ => SourceError::Credential,
            };
            assert_eq!(result, Err(expected_error));
            let diagnostic = result
                .expect_err("failure fixture case returns an error")
                .to_string();
            assert!(!diagnostic.contains(&client_id));
            assert!(!diagnostic.contains(&client_secret));
            assert!(!diagnostic.contains(&access_token));
            assert!(!diagnostic.contains("/token?"));
        }

        let requests = server.received_requests().await.expect("request journal");
        let data_count = requests
            .iter()
            .filter(|request| request.url.path() == "/data")
            .count();
        if expects_success {
            assert!(
                data_count == 1,
                "successful token did not authorize one data request"
            );
        } else {
            assert!(
                data_count == 0,
                "token failure reached the evidence-data source"
            );
        }
        let token_request = requests
            .iter()
            .find(|request| request.url.path() == "/token");
        if case_id == "transport-connection-failure" {
            assert!(token_request.is_none());
            continue;
        }
        let token_request = token_request.expect("token request was journaled");
        // No placement may put a credential in the token URL, so the redaction
        // surface is the request body and the response, never the URL.
        assert!(
            query_parameters(&token_request.url).is_empty(),
            "token URL carried a query"
        );
        let form = encoded_parameters(&token_request.body);
        assert!(
            form.len() == 4
                && contains_parameter(&form, "grant_type", "client_credentials")
                && contains_parameter(&form, "scope", "fixture.read")
                && contains_parameter(&form, "client_id", &client_id)
                && contains_parameter(&form, "client_secret", &client_secret),
            "form placement did not deliver the exact closed credential request"
        );
    }
}

#[tokio::test]
async fn projection_missing_leaf_is_omitted_but_bad_intermediate_stops_before_extraction() {
    for (response, expected) in [
        (json!({"results": [{}]}), Ok(json!({"results": [{}]}))),
        (json!({}), Err(SourceError::ProjectionViolation)),
        (
            json!({"results": {}}),
            Err(SourceError::ProjectionViolation),
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        let (_root, secrets) = resolver(&[("token", "token")]);
        let mut source = fixed_source(
            &server.uri(),
            json!({"kind": "static-bearer", "tokenRef": "secret:file/token"}),
        );
        source.request.projection = vec!["/results/*/optional".into()];
        let executor = SourceExecutor::new(&source, secrets).expect("executor builds");
        assert_eq!(
            executor
                .execute(
                    &[selector("record")],
                    &RequestParts {
                        query: vec![],
                        body: Some(json!({}))
                    }
                )
                .await,
            expected
        );
    }
}

#[tokio::test]
async fn source_executor_failure_matrix_is_exact_single_request_and_value_free() {
    let cases = [
        ("http-401", SourceError::Status(SourceStatus::Unauthorized)),
        ("http-403", SourceError::Status(SourceStatus::Forbidden)),
        ("http-429", SourceError::Status(SourceStatus::RateLimited)),
        ("http-500", SourceError::Status(SourceStatus::ServerError)),
        ("redirect", SourceError::Redirect),
        ("timeout", SourceError::Timeout),
        ("invalid-json", SourceError::InvalidJson),
        ("wrong-media-type", SourceError::WrongMediaType),
        (
            "raw-oversized-before-projection",
            SourceError::ResponseTooLarge,
        ),
    ];

    for (case_id, expected_error) in cases {
        let server = MockServer::start().await;
        let response = match case_id {
            "http-401" => ResponseTemplate::new(401)
                .set_body_string("source-response-canary credential-canary"),
            "http-403" => ResponseTemplate::new(403)
                .set_body_string("source-response-canary credential-canary"),
            "http-429" => ResponseTemplate::new(429)
                .insert_header("retry-after", "60")
                .set_body_string("source-response-canary credential-canary"),
            "http-500" => ResponseTemplate::new(500)
                .set_body_string("source-response-canary credential-canary"),
            "redirect" => {
                ResponseTemplate::new(302).insert_header("location", "/redirect-target-canary")
            }
            "timeout" => ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(100))
                .set_body_json(json!({"ok": true})),
            "invalid-json" => ResponseTemplate::new(200)
                .set_body_raw("{source-response-canary", "application/json"),
            "wrong-media-type" => {
                ResponseTemplate::new(200).set_body_raw("source-response-canary", "text/plain")
            }
            "raw-oversized-before-projection" => ResponseTemplate::new(200).set_body_raw(
                format!(
                    "{{\"ok\":true,\"ignored\":\"source-response-canary{}\"}}",
                    "x".repeat(256)
                ),
                "application/json",
            ),
            _ => unreachable!("closed source failure cases"),
        };
        Mock::given(method("POST"))
            .and(path("/data"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let (_root, secrets) = resolver(&[("token", "credential-canary")]);
        let mut source = fixed_source(
            &server.uri(),
            json!({"kind": "static-bearer", "tokenRef": "secret:file/token"}),
        );
        if case_id == "timeout" {
            source.request.timeout_milliseconds = 20;
        }
        if case_id == "raw-oversized-before-projection" {
            source.request.maximum_response_bytes = 64;
        }
        let error = SourceExecutor::new(&source, secrets)
            .expect("failure-matrix source compiles")
            .execute(
                &[selector("record")],
                &RequestParts {
                    query: vec![],
                    body: Some(json!({})),
                },
            )
            .await
            .expect_err("failure-matrix case cannot succeed");
        assert_eq!(error, expected_error, "{case_id}: exact source error");
        let diagnostic = format!("{error:?} {error}");
        for canary in [
            "source-response-canary",
            "credential-canary",
            "redirect-target-canary",
        ] {
            assert!(
                !diagnostic.contains(canary),
                "{case_id}: diagnostics remain value-free"
            );
        }
        let requests = server.received_requests().await.expect("request journal");
        assert_eq!(requests.len(), 1, "{case_id}: exactly one request");
        assert_eq!(requests[0].url.path(), "/data");
    }
}

#[test]
fn forbidden_header_collisions_and_invalid_projection_contracts_fail_at_compilation() {
    let (_root, secrets) = resolver(&[("key", "secret")]);
    for header_name in RESERVED_HEADER_CONTRACT_CASES {
        let source = source_config(
            "http://127.0.0.1:18080",
            json!({"kind": "static-api-key", "headerName": "X-Api-Key", "valueRef": "secret:file/key"}),
            json!(["record_id"]),
            json!([{"name": header_name, "value": "forbidden"}]),
            json!(["/ok"]),
        );
        assert_eq!(
            SourceExecutor::new(&source, Arc::clone(&secrets)).err(),
            Some(SourceError::InvalidPlan),
            "reserved fixed header {header_name} is rejected"
        );
    }
    let duplicate = source_config(
        "http://127.0.0.1:18080",
        json!({"kind": "static-api-key", "headerName": "X-Api-Key", "valueRef": "secret:file/key"}),
        json!(["record_id"]),
        json!([
            {"name": "X-Reviewed-Header", "value": "one"},
            {"name": "x-reviewed-header", "value": "two"}
        ]),
        json!(["/ok"]),
    );
    assert_eq!(
        SourceExecutor::new(&duplicate, Arc::clone(&secrets)).err(),
        Some(SourceError::InvalidPlan),
        "fixed header names are unique case-insensitively"
    );
    let authentication_collision = source_config(
        "http://127.0.0.1:18080",
        json!({"kind": "static-api-key", "headerName": "X-Api-Key", "valueRef": "secret:file/key"}),
        json!(["record_id"]),
        json!([{"name": "x-api-key", "value": "fixed"}]),
        json!(["/ok"]),
    );
    assert_eq!(
        SourceExecutor::new(&authentication_collision, Arc::clone(&secrets)).err(),
        Some(SourceError::InvalidPlan),
        "fixed and authentication headers cannot collide"
    );
    for api_key_header in RESERVED_HEADER_CONTRACT_CASES {
        let source = source_config(
            "http://127.0.0.1:18080",
            json!({"kind": "static-api-key", "headerName": api_key_header, "valueRef": "secret:file/key"}),
            json!(["record_id"]),
            json!([]),
            json!(["/ok"]),
        );
        assert_eq!(
            SourceExecutor::new(&source, Arc::clone(&secrets)).err(),
            Some(SourceError::InvalidPlan),
            "reserved authentication header {api_key_header} is rejected"
        );
    }
    for projection in [
        json!(["/a", "/a/b"]),
        json!(["/a/0"]),
        json!(["/a/*/x", "/a/b"]),
    ] {
        let source = source_config(
            "http://127.0.0.1:18080",
            json!({"kind": "static-api-key", "headerName": "X-Api-Key", "valueRef": "secret:file/key"}),
            json!(["record_id"]),
            json!([]),
            projection,
        );
        assert_eq!(
            SourceExecutor::new(&source, Arc::clone(&secrets)).err(),
            Some(SourceError::InvalidPlan)
        );
    }
}

/// Every allowed selector set must carry the roles the path template binds.
///
/// The sets are not written by an operator. They are derived from authority
/// grants, one per grant, filtered to the roles the source declares. So a grant
/// that authorizes this requirement over a role the template does not bind
/// yields a set with no value for the placeholder. `materialize_url` needs one
/// for every placeholder, so that set fails every request it ever serves, while
/// startup and readiness both pass because some other grant covers the role.
/// Refuse the plan instead, at the point the mismatch is visible.
#[test]
fn an_allowed_selector_set_that_cannot_fill_the_path_template_is_refused() {
    let (_root, secrets) = resolver(&[("key", "api-key-value")]);
    let mut source = source_config(
        "http://127.0.0.1:18080",
        json!({"kind": "static-api-key", "headerName": "X-Api-Key", "valueRef": "secret:file/key"}),
        json!(["record_id"]),
        json!([]),
        json!(["/ok"]),
    );
    // The template binds `subject`; `parent` is declared but never bound.
    source.request.selector_inputs = serde_json::from_value(json!([
        {"role": "subject", "alternatives": [{"profile": "record-v1", "fields": ["record_id"]}]},
        {"role": "parent", "alternatives": [{"profile": "record-v1", "fields": ["record_id"]}]}
    ]))
    .expect("selector inputs deserialize");

    let complete = vec![vec![
        ("subject".to_owned(), "record-v1".to_owned()),
        ("parent".to_owned(), "record-v1".to_owned()),
    ]];
    SourceExecutor::new_with_selector_sets(&source, &complete, Arc::clone(&secrets))
        .expect("a set carrying every bound role compiles");

    let subject_only = vec![vec![("subject".to_owned(), "record-v1".to_owned())]];
    SourceExecutor::new_with_selector_sets(&source, &subject_only, Arc::clone(&secrets))
        .expect("a set carrying only the bound role compiles");

    // Legal-parent-relationship shape: one authority path over the parent, one
    // source path template bound to the child. The parent-only path is the one
    // that would fail every request.
    let parent_only = vec![vec![("parent".to_owned(), "record-v1".to_owned())]];
    assert_eq!(
        SourceExecutor::new_with_selector_sets(&source, &parent_only, Arc::clone(&secrets)).err(),
        Some(SourceError::InvalidPlan),
        "a set omitting the bound role has no value for the placeholder"
    );

    let mixed = vec![
        vec![
            ("subject".to_owned(), "record-v1".to_owned()),
            ("parent".to_owned(), "record-v1".to_owned()),
        ],
        vec![("parent".to_owned(), "record-v1".to_owned())],
    ];
    assert_eq!(
        SourceExecutor::new_with_selector_sets(&source, &mixed, secrets).err(),
        Some(SourceError::InvalidPlan),
        "one complete set must not excuse an incomplete one"
    );
}

#[tokio::test]
async fn private_ca_tls_handshake_succeeds_and_hostname_mismatch_fails() {
    let (address, ca_pem, server) = spawn_private_ca_tls_server("127.0.0.1").await;
    let directory = tempfile::tempdir().expect("temporary TLS directory");
    let configured_path = directory.path().join("private-ca.pem");
    fs::write(&configured_path, &ca_pem).expect("write configured private CA");
    let tls: OutboundTlsConfig = serde_json::from_value(json!({
        "systemRoots": true,
        "trustProfiles": {"private-pki": {"caBundleFile": configured_path}}
    }))
    .expect("TLS config deserializes");
    let mut source = fixed_source(
        &format!("https://127.0.0.1:{}", address.port()),
        json!({"kind": "static-bearer", "tokenRef": "secret:file/token"}),
    );
    source.tls_trust_profile = Some("private-pki".into());
    let (_root, secrets) = resolver(&[("token", "token")]);
    let mut captured = BTreeMap::from([("private-pki".into(), ca_pem)]);
    let executor = SourceExecutor::new_with_selector_sets_and_tls(
        &source,
        &[vec![("subject".into(), "record-v1".into())]],
        &tls,
        &captured,
        Arc::clone(&secrets),
    )
    .expect("private CA source compiles");
    fs::write(&configured_path, b"changed-after-capture").expect("mutate configured file");
    captured.insert("private-pki".into(), b"changed-after-compile".to_vec());
    executor
        .credentials_ready()
        .await
        .expect("captured TLS source remains credential-ready without reopening CA files");
    assert_eq!(
        executor
            .execute(
                &[selector("record")],
                &RequestParts {
                    query: vec![],
                    body: Some(json!({})),
                },
            )
            .await,
        Ok(json!({"ok": true}))
    );
    server.await.expect("trusted TLS server task completes");

    let (mismatch_address, mismatch_ca, mismatch_server) =
        spawn_private_ca_tls_server("localhost").await;
    let mut mismatch_source = source;
    mismatch_source.base_url = format!("https://127.0.0.1:{}", mismatch_address.port());
    let mismatch_captured = BTreeMap::from([("private-pki".into(), mismatch_ca)]);
    let mismatch = SourceExecutor::new_with_selector_sets_and_tls(
        &mismatch_source,
        &[vec![("subject".into(), "record-v1".into())]],
        &tls,
        &mismatch_captured,
        secrets,
    )
    .expect("hostname-mismatch source compiles")
    .execute(
        &[selector("record")],
        &RequestParts {
            query: vec![],
            body: Some(json!({})),
        },
    )
    .await;
    assert_eq!(mismatch, Err(SourceError::Transport));
    mismatch_server
        .await
        .expect("mismatched TLS server task completes");
}

#[tokio::test]
async fn a_reset_transport_failure_yields_exactly_one_connection_attempt() {
    let (address, attempts, server) = spawn_reset_on_connect_server().await;
    let source = fixed_source(
        &format!("http://127.0.0.1:{}", address.port()),
        json!({"kind": "static-bearer", "tokenRef": "secret:file/token"}),
    );
    let (_root, secrets) = resolver(&[("token", "token")]);
    let result = SourceExecutor::new(&source, secrets)
        .expect("reset-transport source compiles")
        .execute(
            &[selector("record")],
            &RequestParts {
                query: vec![],
                body: Some(json!({})),
            },
        )
        .await;
    assert_eq!(result, Err(SourceError::Transport));
    // Give the listener a moment to observe a second connection attempt, if
    // one were made, before asserting the final count.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "a reset transport failure must not be retried"
    );
    server.abort();
}

#[test]
fn private_ca_plan_rejects_unbound_missing_and_malformed_captures() {
    let directory = tempfile::tempdir().expect("temporary TLS directory");
    let configured_path = directory.path().join("private-ca.pem");
    let tls: OutboundTlsConfig = serde_json::from_value(json!({
        "systemRoots": true,
        "trustProfiles": {"private-pki": {"caBundleFile": configured_path}}
    }))
    .expect("TLS config deserializes");
    let mut source = fixed_source(
        "https://127.0.0.1:443",
        json!({"kind": "static-bearer", "tokenRef": "secret:file/token"}),
    );
    source.tls_trust_profile = Some("private-pki".into());
    let (_root, secrets) = resolver(&[("token", "token")]);
    let allowed = [vec![("subject".into(), "record-v1".into())]];
    let no_bindings = OutboundTlsConfig {
        system_roots: true,
        trust_profiles: Default::default(),
    };
    assert_eq!(
        SourceExecutor::new_with_selector_sets_and_tls(
            &source,
            &allowed,
            &no_bindings,
            &BTreeMap::new(),
            Arc::clone(&secrets),
        )
        .err(),
        Some(SourceError::InvalidPlan)
    );
    assert_eq!(
        SourceExecutor::new_with_selector_sets_and_tls(
            &source,
            &allowed,
            &tls,
            &BTreeMap::new(),
            Arc::clone(&secrets),
        )
        .err(),
        Some(SourceError::InvalidPlan)
    );
    assert_eq!(
        SourceExecutor::new_with_selector_sets_and_tls(
            &source,
            &allowed,
            &tls,
            &BTreeMap::from([("private-pki".into(), b"not-a-certificate".to_vec())]),
            secrets,
        )
        .err(),
        Some(SourceError::InvalidPlan)
    );
}

#[cfg(unix)]
#[test]
fn runtime_ca_capture_rejects_symlink_malformed_and_mutable_files() {
    use std::os::unix::fs::symlink;

    enum CaCase {
        Symlink,
        Malformed,
        Mutable,
    }
    for case in [CaCase::Symlink, CaCase::Malformed, CaCase::Mutable] {
        let directory = tempfile::tempdir().expect("temporary runtime directory");
        let secret_root = directory.path().join("secrets");
        fs::create_dir(&secret_root).expect("create secret root");
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
            .expect("protect secret root");
        let ca_path = directory.path().join("private-ca.pem");
        match case {
            CaCase::Symlink => {
                let target = directory.path().join("private-ca-target.pem");
                fs::write(
                    &target,
                    b"-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n",
                )
                .expect("write CA target");
                fs::set_permissions(&target, fs::Permissions::from_mode(0o444))
                    .expect("protect CA target");
                symlink(target, &ca_path).expect("create CA symlink");
            }
            CaCase::Malformed => {
                fs::write(&ca_path, b"not-a-certificate").expect("write malformed CA");
                fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o444))
                    .expect("protect malformed CA");
            }
            CaCase::Mutable => {
                fs::write(
                    &ca_path,
                    b"-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n",
                )
                .expect("write mutable CA");
                fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600))
                    .expect("leave CA mutable");
            }
        }
        let runtime_path = directory.path().join("runtime.yaml");
        fs::write(
            &runtime_path,
            format!(
                "version: 1\nbundleDirectory: /etc/registry-evidence/bundle\nlistener:\n  bindHost: 127.0.0.1\n  port: 8080\n  tlsTermination: operator-controlled-upstream\n  trustProxyIdentityHeaders: false\n  maximumRequestBytes: 65536\n  maximumConcurrentRequests: 64\n  requestTimeoutMilliseconds: 10000\n  shutdownGraceMilliseconds: 30000\nsecretProviders:\n  file: {{root: {}}}\nauditStorage:\n  path: /var/lib/registry-evidence/audit/evidence.jsonl\n  maximumFileBytes: 1073741824\noutboundTls:\n  systemRoots: true\n  trustProfiles:\n    private-pki: {{caBundleFile: {}}}\n",
                secret_root.display(),
                ca_path.display()
            ),
        )
        .expect("write runtime configuration");
        fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
            .expect("protect runtime configuration");
        let error = RuntimeDocument::load(&runtime_path).expect_err("unsafe CA capture fails");
        match case {
            CaCase::Symlink => assert_eq!(error, BundleError::InvalidPath),
            CaCase::Malformed => assert!(matches!(error, BundleError::InvalidArtifact(_))),
            // The CA bundle sits outside the bundle directory, so the refusal
            // has to name it. Re-freezing the bundle would not touch it.
            CaCase::Mutable => assert_eq!(
                error.artifact_fault().map(|fault| fault.fault().cause()),
                Some("the TLS CA bundle the runtime file names is writable")
            ),
        }
    }
}

#[test]
fn ambient_proxy_variables_are_ignored_in_an_isolated_process() {
    if std::env::var_os("EVIDENCE_PROXY_CHILD").is_some() {
        return;
    }
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("ambient_proxy_child")
        .arg("--nocapture")
        .env("EVIDENCE_PROXY_CHILD", "1")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .status()
        .expect("spawn isolated proxy test");
    assert!(status.success());
}

#[tokio::test]
async fn ambient_proxy_child() {
    if std::env::var_os("EVIDENCE_PROXY_CHILD").is_none() {
        return;
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "synthetic-proxy-test-access-token",
            "token_type": "Bearer",
            "expires_in": 60,
            "scope": "fixture.read"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (_root, secrets) = resolver(&[
        ("token", "token"),
        ("oauth-client-id", "synthetic-proxy-client"),
        ("oauth-client-secret", "synthetic-proxy-secret"),
    ]);
    let source = fixed_source(
        &server.uri(),
        json!({"kind": "static-bearer", "tokenRef": "secret:file/token"}),
    );
    SourceExecutor::new(&source, Arc::clone(&secrets))
        .expect("executor builds")
        .execute(
            &[selector("record")],
            &RequestParts {
                query: vec![],
                body: Some(json!({})),
            },
        )
        .await
        .expect("ambient proxy is ignored");
    let oauth = oauth_source(
        &server.uri(),
        &format!("{}/token", server.uri()),
        "basic-header",
        0,
    );
    SourceExecutor::new(&oauth, secrets)
        .expect("OAuth executor builds")
        .execute(
            &[selector("record")],
            &RequestParts {
                query: vec![],
                body: Some(json!({})),
            },
        )
        .await
        .expect("ambient proxy is ignored for token and evidence-data requests");
}
