//! Current Evidence source-contract coverage, through real shared packs.

use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use registry_adapter_core::{AdapterPack, EvidenceConnectionPolicy};
use registry_adapter_engine::artifacts::PackArtifactBytes;
use registry_adapter_engine::evidence::{
    compile_evidence_pack_with_protocols, compile_evidence_with_protocols, ConnectionPolicyReason,
    EvidenceAcquisitionIntent, EvidenceCompileInputs, EvidenceHookError, EvidenceHookFuture,
    EvidenceHostHooks, EvidenceLimits, EvidenceLookup, EvidenceProgram, EvidenceRuntimeBindings,
    EvidenceSendIntent,
};
use registry_evidence::bundle::{evidence_package_limits, Bundle, BundleError, RuntimeDocument};
use registry_evidence::config::SourceConfig;
use registry_evidence::model::LookupResult;
use registry_evidence::pack_source::{PackSourceError, PackSourceExecutor, SourceBindingReason};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use wiremock::matchers::{body_json, body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PRIVATE_TOKEN: &str = "source-contract-private-token";

fn load_bundle(name: &str) -> Bundle {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/fixtures/acceptance")
        .join(name);
    load_bundle_at(&root)
}

fn load_bundle_at(root: &std::path::Path) -> Bundle {
    let verified = registry_platform_config::verify_package(
        root,
        &evidence_package_limits(),
        "evidencectl package",
    )
    .expect("maintained fixture package verifies");
    Bundle::load_as_found(root, &verified).expect("maintained fixture bundle loads")
}

/// Load only the package's declared checksum closure. This keeps the test
/// independent of sibling agents staging additional digest directories next
/// to a maintained fixture while preserving the fixture's exact verified
/// bytes and checksum authority.
fn load_declared_fixture(name: &str) -> Bundle {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/fixtures/acceptance")
        .join(name);
    let scratch = tempfile::tempdir().unwrap();
    let sums = fs::read_to_string(source.join(registry_platform_config::SUM_FILE)).unwrap();
    fs::write(
        scratch.path().join(registry_platform_config::SUM_FILE),
        &sums,
    )
    .unwrap();
    for line in sums.lines() {
        let (_, relative) = line.split_once("  ").expect("checksum line");
        let destination = scratch.path().join(relative);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(source.join(relative), destination).unwrap();
    }
    load_bundle_at(scratch.path())
}

fn secret_resolver(entries: &[(&str, &str)]) -> (TempDir, Arc<SecretResolver>) {
    let root = tempfile::tempdir().expect("temporary secret root");
    for (name, value) in entries {
        let path = root.path().join(name);
        fs::write(&path, value).expect("write test secret");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("protect test secret");
    }
    let resolver =
        SecretResolver::new([SecretProvider::File], root.path()).expect("file secret resolver");
    (root, Arc::new(resolver))
}

fn static_policy(endpoint: &str, base_url: &str) -> EvidenceConnectionPolicy {
    serde_json::from_value(json!({
        "endpoint": endpoint,
        "baseUrl": base_url,
        "clientIdentity": "forbidden",
        "authentication": {"type": "static-authorization"}
    }))
    .expect("reviewed connection policy")
}

fn compile_adult(
    server: &MockServer,
    limits: EvidenceLimits,
    secret_name: &str,
    secrets: Arc<SecretResolver>,
) -> PackSourceExecutor {
    compile_adult_url(&server.uri(), limits, secret_name, secrets, BTreeMap::new())
}

fn compile_adult_url(
    base_url: &str,
    limits: EvidenceLimits,
    secret_name: &str,
    secrets: Arc<SecretResolver>,
    captured_ca_bundles: BTreeMap<String, Vec<u8>>,
) -> PackSourceExecutor {
    let bundle = load_bundle("adult-status");
    let source = bundle.config.sources.get("source-a").expect("source-a");
    let runtime = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id": source.connection(),
            "endpoints": [{
                "endpoint": "provider",
                "baseUrl": base_url,
                "credential": {
                    "type": "static-authorization",
                    "tokenRef": format!("secret:file/{secret_name}")
                },
                "maximumConcurrency": 1
            }],
            "allowedPrivateCidrs": []
        }))
        .expect("runtime binding"),
        secrets,
        captured_ca_bundles,
    );
    PackSourceExecutor::compile(
        source,
        bundle
            .source_pack("source-a")
            .expect("captured source pack"),
        &runtime,
        &[static_policy("provider", base_url)],
        limits,
    )
    .expect("adult source compiles through the shared pack engine")
}

async fn spawn_reset_server() -> (std::net::SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    // Reset before any HTTP bytes are exchanged so a second connection can
    // only be an implicit transport retry, never application behavior.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
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

type StalledRequest = Result<Vec<u8>, &'static str>;

async fn spawn_stalled_server() -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::sync::mpsc::UnboundedReceiver<StalledRequest>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&attempts);
    let (observed, requests) = tokio::sync::mpsc::unbounded_channel();
    let (ready, started) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        if ready.send(()).is_err() {
            return;
        }
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => {
                    observed
                        .send(Err("the stalled source listener failed"))
                        .expect("the stalled source observer remains active");
                    return;
                }
            };
            counted.fetch_add(1, Ordering::SeqCst);
            let observed = observed.clone();
            let _connection = connections.spawn(async move {
                let mut request = Vec::with_capacity(1024);
                let mut chunk = [0_u8; 1024];
                loop {
                    let size = match stream.read(&mut chunk).await {
                        Ok(size) => size,
                        Err(_) => {
                            observed
                                .send(Err("the stalled source request read failed"))
                                .expect("the stalled source observer remains active");
                            return;
                        }
                    };
                    if size == 0 {
                        observed
                            .send(Err("the stalled source request closed early"))
                            .expect("the stalled source observer remains active");
                        return;
                    }
                    request.extend_from_slice(&chunk[..size]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        if observed.send(Ok(request)).is_err() {
                            return;
                        }
                        return std::future::pending::<()>().await;
                    }
                    if request.len() > 16 * 1024 {
                        observed
                            .send(Err("the stalled source request headers were too large"))
                            .expect("the stalled source observer remains active");
                        return;
                    }
                }
            });
        }
    });
    started.await.expect("the stalled source server starts");
    (address, attempts, requests, handle)
}

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut result = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        result.push_str(std::str::from_utf8(chunk).unwrap());
        result.push('\n');
    }
    result.push_str(&format!("-----END {label}-----\n"));
    result
}

async fn spawn_private_ca_server(
    bind_ip: Ipv4Addr,
    subject_alt_name: &str,
    body: &'static [u8],
    expect_handshake: bool,
) -> (std::net::SocketAddr, Vec<u8>, JoinHandle<()>) {
    let mut ca_parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_certificate = ca_parameters.self_signed(&ca_key).unwrap();
    let server_parameters = CertificateParams::new(vec![subject_alt_name.to_owned()]).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server_certificate = server_parameters
        .signed_by(&server_key, &Issuer::from_params(&ca_parameters, &ca_key))
        .unwrap();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_certificate.der().clone()], private_key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        // Only this host receives TLS service. Other peers are dropped before
        // TLS; the private-interface TCP accept/drop port remains reachable.
        let stream = timeout(Duration::from_secs(10), async {
            loop {
                let (stream, peer) = listener.accept().await.expect("source TLS accept succeeds");
                if peer.ip() == IpAddr::V4(bind_ip) {
                    break stream;
                }
                drop(stream);
            }
        })
        .await
        .expect("the source TLS fixture receives its same-host connection");
        let mut stream = match acceptor.accept(stream).await {
            Ok(stream) => stream,
            Err(_error) if !expect_handshake => return,
            Err(error) => panic!("expected private-CA handshake: {error}"),
        };
        let mut request = Vec::new();
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
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let headers = std::str::from_utf8(&request[..header_end]).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.strip_prefix("content-length: ")
                    .or_else(|| line.strip_prefix("Content-Length: "))
            })
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let mut chunk = [0_u8; 512];
            let Ok(read) = stream.read(&mut chunk).await else {
                return;
            };
            if read == 0 || request.len() + read > 16_384 {
                return;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
    });
    (
        address,
        pem("CERTIFICATE", ca_certificate.der().as_ref()).into_bytes(),
        handle,
    )
}

fn compile_licence_tls(
    base_url: &str,
    allowed_private_cidr: &str,
    ca_pem: Vec<u8>,
    secrets: Arc<SecretResolver>,
) -> PackSourceExecutor {
    let bundle = load_bundle("professional-licence");
    let source = bundle.config.sources.get("source-c").unwrap();
    let runtime = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":source.connection(),
            "endpoints":[{
                "endpoint":"provider","baseUrl":base_url,
                "credential":{
                    "type":"basic","usernameRef":"secret:file/username",
                    "passwordRef":"secret:file/password"
                },
                "tlsTrustProfile":"private-pki"
            }],
            "outboundTls":{"trustProfiles":{"private-pki":{"caBundleFile":"/captured/private-ca.pem"}}},
            "allowedPrivateCidrs":[allowed_private_cidr]
        }))
        .unwrap(),
        secrets,
        BTreeMap::from([("private-pki".to_owned(), ca_pem)]),
    );
    PackSourceExecutor::compile(
        source,
        bundle.source_pack("source-c").unwrap(),
        &runtime,
        &[serde_json::from_value(json!({
            "endpoint":"provider","baseUrl":base_url,
            "tlsTrustProfile":"private-pki","clientIdentity":"forbidden",
            "authentication":{"type":"basic"}
        }))
        .unwrap()],
        EvidenceLimits::default(),
    )
    .unwrap()
}

fn compile_licence_tls_program(
    base_url: &str,
    allowed_private_cidr: &str,
    ca_pem: Vec<u8>,
    secrets: Arc<SecretResolver>,
) -> EvidenceProgram {
    let bundle = load_bundle("professional-licence");
    let source = bundle.config.sources.get("source-c").unwrap();
    let runtime = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":source.connection(),
            "endpoints":[{
                "endpoint":"provider","baseUrl":base_url,
                "credential":{
                    "type":"basic","usernameRef":"secret:file/username",
                    "passwordRef":"secret:file/password"
                },
                "tlsTrustProfile":"private-pki"
            }],
            "outboundTls":{"trustProfiles":{"private-pki":{"caBundleFile":"/captured/private-ca.pem"}}},
            "allowedPrivateCidrs":[allowed_private_cidr]
        }))
        .unwrap(),
        secrets,
        BTreeMap::from([("private-pki".to_owned(), ca_pem)]),
    );
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"provider","baseUrl":base_url,
        "tlsTrustProfile":"private-pki","clientIdentity":"forbidden",
        "authentication":{"type":"basic"}
    }))
    .unwrap();
    let closure = bundle.source_pack("source-c").unwrap();
    compile_evidence_with_protocols(
        &EvidenceCompileInputs {
            pack: &closure.pack(),
            route: source.route.as_str(),
            runtime: &runtime,
            connection_id: Some(source.connection()),
            connection: &[policy],
            pack_artifacts: &closure.artifacts(),
            limits: EvidenceLimits::default(),
        },
        &registry_evidence::host_protocol::registry().unwrap(),
    )
    .unwrap()
}

fn assigned_private_ipv4() -> Ipv4Addr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind route-selection socket");
    // UDP connect performs route selection without sending a datagram.
    socket
        .connect("192.0.2.1:9")
        .expect("select the host's outbound interface");
    let IpAddr::V4(address) = socket.local_addr().unwrap().ip() else {
        panic!("the source-contract TLS fixture requires an assigned private IPv4 interface");
    };
    assert!(
        address.is_private(),
        "the source-contract TLS fixture requires an assigned private IPv4 interface, got {address}"
    );
    address
}

fn wire_pack(authentication: Value) -> (AdapterPack, PackArtifactBytes) {
    let inputs = serde_json::to_vec(&json!({
        "type":"object","additionalProperties":false,"required":["record"],
        "properties":{"record":{"type":"string","minLength":1,"maxLength":64}}
    }))
    .unwrap();
    let facts = serde_json::to_vec(&json!({
        "type":"object","additionalProperties":false,"required":["ok"],
        "properties":{"ok":{"type":"boolean"}}
    }))
    .unwrap();
    let pack: AdapterPack = serde_json::from_value(json!({
        "id":"wire-contract","version":"1","testedVersions":[],
        "endpoints":[{
            "id":"provider","component":"http","authentication":authentication,
            "attemptTimeoutMilliseconds":1000,"maximumResponseBytes":4096,
            "requestHeaders":["x-fixed"],
            "operations":[{"id":"lookup","safeUpstream":true}],"testedVersions":[]
        }],
        "sourceRoutes":[{
            "id":"lookup","evidence":{
                "inputsSchema":{"path":"schemas/inputs.json","digest":registry_platform_config::sha256_uri(&inputs)},
                "factsSchema":{"path":"schemas/facts.json","digest":registry_platform_config::sha256_uri(&facts)}
            },
            "steps":[
                {"setHeader":{"name":"X-Fixed","value":{"constant":"reviewed"}}},
                {"to":{"uri":"http:provider","parameters":{
                    "httpMethod":"GET","path":"/records/{{record}}",
                    "pathParameters":{"record":{"jsonpath":"$.record"}},
                    "query":{"z":{"constant":"last"},"a":{"constant":"first"}},
                    "operation":"lookup"
                }}}
            ]
        }]
    }))
    .unwrap();
    (
        pack,
        PackArtifactBytes::new([
            ("schemas/inputs.json".to_owned(), inputs),
            ("schemas/facts.json".to_owned(), facts),
        ]),
    )
}

fn wire_program(
    server: &MockServer,
    pack_authentication: Value,
    runtime_credential: Value,
    policy_authentication: Value,
    secrets: Arc<SecretResolver>,
) -> EvidenceProgram {
    let (pack, artifacts) = wire_pack(pack_authentication);
    let runtime = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":"wire","endpoints":[{
                "endpoint":"provider","baseUrl":server.uri(),"credential":runtime_credential
            }],"allowedPrivateCidrs":[]
        }))
        .unwrap(),
        secrets,
        BTreeMap::new(),
    );
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"provider","baseUrl":server.uri(),"clientIdentity":"forbidden",
        "authentication":policy_authentication
    }))
    .unwrap();
    compile_evidence_with_protocols(
        &EvidenceCompileInputs {
            pack: &pack,
            route: "lookup",
            runtime: &runtime,
            connection_id: Some("wire"),
            connection: &[policy],
            pack_artifacts: &artifacts,
            limits: EvidenceLimits::default(),
        },
        &registry_evidence::host_protocol::registry().unwrap(),
    )
    .unwrap()
}

fn adult_inputs() -> Value {
    json!({
        "given_name": "Synthetic",
        "family_name": "Person",
        "birth_date": "2000-01-01"
    })
}

#[derive(Clone, Copy)]
enum Decision {
    Allow,
    Authority,
    Audit,
}

struct Hooks {
    decision: Decision,
    expected_pack: &'static str,
    expected_route: &'static str,
    acquisitions: AtomicUsize,
    credentials: AtomicUsize,
}

impl Hooks {
    fn new(decision: Decision) -> Arc<Self> {
        Self::for_program(decision, "fixture-adult", "lookup")
    }

    fn for_pack(decision: Decision, expected_pack: &'static str) -> Arc<Self> {
        Self::for_program(decision, expected_pack, "lookup")
    }

    fn for_program(
        decision: Decision,
        expected_pack: &'static str,
        expected_route: &'static str,
    ) -> Arc<Self> {
        Arc::new(Self {
            decision,
            expected_pack,
            expected_route,
            acquisitions: AtomicUsize::new(0),
            credentials: AtomicUsize::new(0),
        })
    }
}

impl EvidenceHostHooks for Hooks {
    fn before_acquisition<'a>(
        &'a self,
        intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            assert_eq!(intent.pack, self.expected_pack);
            assert_eq!(intent.route, self.expected_route);
            match self.decision {
                Decision::Allow => Ok(()),
                Decision::Authority => Err(EvidenceHookError::Authority),
                Decision::Audit => Err(EvidenceHookError::Audit),
            }
        })
    }

    fn before_credentials<'a>(&'a self, _: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
        self.credentials.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn captured_pack_owns_exact_body_headers_auth_json_projection_and_privacy() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .and(header("accept", "application/json"))
        .and(header("authorization", format!("Bearer {PRIVATE_TOKEN}")))
        .and(body_json(json!({
            "lookup": {
                "given_name": "Synthetic",
                "family_name": "Person",
                "birth_date": "2000-01-01"
            },
            "fields": ["date_of_birth"],
            "limit": 2
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "date_of_birth": "2000-01-01",
            "private_canary": "discard"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (_root, secrets) = secret_resolver(&[("token", PRIVATE_TOKEN)]);
    let executor = compile_adult(&server, EvidenceLimits::default(), "token", secrets);
    let hooks = Hooks::new(Decision::Allow);
    assert_eq!(
        executor
            .execute(adult_inputs(), Utc::now(), hooks.clone())
            .await
            .unwrap(),
        LookupResult::Match(BTreeMap::from([(
            "date_of_birth".to_owned(),
            json!("2000-01-01")
        )]))
    );
    assert_eq!(hooks.acquisitions.load(Ordering::SeqCst), 1);
    assert_eq!(hooks.credentials.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn input_schema_refuses_missing_extra_and_invalid_values_before_effects() {
    let server = MockServer::start().await;
    let (_root, secrets) = secret_resolver(&[("token", PRIVATE_TOKEN)]);
    let executor = compile_adult(&server, EvidenceLimits::default(), "token", secrets);
    let hooks = Hooks::new(Decision::Allow);
    for invalid in [
        json!({"given_name":"Synthetic","family_name":"Person"}),
        json!({"given_name":"Synthetic","family_name":"Person","birth_date":"2000-01-01","extra":"private"}),
        json!({"given_name":"","family_name":"Person","birth_date":"2000-01-01"}),
    ] {
        assert_eq!(
            executor.execute(invalid, Utc::now(), hooks.clone()).await,
            Err(PackSourceError::Inputs)
        );
    }
    assert_eq!(hooks.acquisitions.load(Ordering::SeqCst), 0);
    assert_eq!(hooks.credentials.load(Ordering::SeqCst), 0);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn authority_and_access_audit_precede_credentials_and_source_effects() {
    let server = MockServer::start().await;
    let empty = tempfile::tempdir().unwrap();
    let secrets = Arc::new(SecretResolver::new([SecretProvider::File], empty.path()).unwrap());
    let executor = compile_adult(&server, EvidenceLimits::default(), "missing", secrets);
    for (decision, expected) in [
        (Decision::Authority, PackSourceError::Authority),
        (Decision::Audit, PackSourceError::Audit),
    ] {
        let hooks = Hooks::new(decision);
        assert_eq!(
            executor
                .execute(adult_inputs(), Utc::now(), hooks.clone())
                .await,
            Err(expected)
        );
        assert_eq!(hooks.acquisitions.load(Ordering::SeqCst), 1);
        assert_eq!(hooks.credentials.load(Ordering::SeqCst), 0);
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn missing_credentials_are_categorical_redacted_and_post_intent() {
    let server = MockServer::start().await;
    let empty = tempfile::tempdir().unwrap();
    let secrets = Arc::new(SecretResolver::new([SecretProvider::File], empty.path()).unwrap());
    let executor = compile_adult(&server, EvidenceLimits::default(), "private-name", secrets);
    let hooks = Hooks::new(Decision::Allow);
    let error = executor
        .execute(adult_inputs(), Utc::now(), hooks.clone())
        .await
        .unwrap_err();
    assert_eq!(error, PackSourceError::Credential);
    let rendered = error.to_string();
    for private in ["private-name", PRIVATE_TOKEN, server.uri().as_str()] {
        assert!(!rendered.contains(private));
    }
    assert_eq!(hooks.acquisitions.load(Ordering::SeqCst), 1);
    assert_eq!(hooks.credentials.load(Ordering::SeqCst), 1);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn maintained_basic_pack_owns_exact_query_and_basic_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/records"))
        .and(query_param("licence_reference", "LIC-0007"))
        .and(query_param("registry_region", "north"))
        .and(query_param("fields", "licence_state,valid_from,valid_until"))
        .and(query_param("limit", "2"))
        .and(header("authorization", "Basic c3ludGhldGljOnBhc3N3b3Jk"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total":1,
            "records":[{"licence_state":"active","valid_from":"2020-01-01","valid_until":"2030-01-01"}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let bundle = load_bundle("professional-licence");
    let source = bundle.config.sources.get("source-c").expect("source-c");
    let (_root, secrets) = secret_resolver(&[("username", "synthetic"), ("password", "password")]);
    let runtime = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":source.connection(),
            "endpoints":[{"endpoint":"provider","baseUrl":server.uri(),"credential":{
                "type":"basic","usernameRef":"secret:file/username","passwordRef":"secret:file/password"
            }}],
            "allowedPrivateCidrs":[]
        }))
        .unwrap(),
        secrets,
        BTreeMap::new(),
    );
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"provider","baseUrl":server.uri(),"clientIdentity":"forbidden",
        "authentication":{"type":"basic"}
    }))
    .unwrap();
    let executor = PackSourceExecutor::compile(
        source,
        bundle.source_pack("source-c").unwrap(),
        &runtime,
        &[policy],
        EvidenceLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        executor
            .execute(
                json!({"licence_reference":"LIC-0007","registry_region":"north"}),
                Utc::now(),
                Hooks::for_pack(Decision::Allow, "fixture-licence"),
            )
            .await
            .unwrap(),
        LookupResult::Match(_)
    ));
}

#[tokio::test]
async fn shared_pack_path_query_fixed_header_and_api_key_are_exact_on_the_wire() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/records/REC-0007"))
        .and(query_param("a", "first"))
        .and(query_param("z", "last"))
        .and(header("x-fixed", "reviewed"))
        .and(header("x-api-key", "private-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "lookup":"matched","facts":{"ok":true}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (_root, secrets) = secret_resolver(&[("api-key", "private-api-key")]);
    let program = wire_program(
        &server,
        json!({"type":"static-api-key","headerName":"X-Api-Key"}),
        json!({"type":"static-api-key","valueRef":"secret:file/api-key"}),
        json!({"type":"static-api-key"}),
        secrets,
    );
    let acquisition = program
        .begin_acquisition(Hooks::for_pack(Decision::Allow, "wire-contract"))
        .await
        .unwrap();
    assert_eq!(
        program
            .execute(&acquisition, json!({"record":"REC-0007"}))
            .await
            .unwrap(),
        EvidenceLookup::Matched {
            facts: json!({"ok":true})
        }
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.query(), Some("a=first&z=last"));
    assert!(requests[0].body.is_empty());
}

/// A custom Authorization scheme is pack-owned and sent verbatim. The none
/// form stays distinct and sends no Authorization header.
#[tokio::test]
async fn none_and_custom_scheme_authentication_have_exact_distinct_wire_shapes() {
    let none_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/records/NONE-0001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "lookup":"matched","facts":{"ok":true}
        })))
        .expect(1)
        .mount(&none_server)
        .await;
    let none_program = wire_program(
        &none_server,
        json!({"type":"none"}),
        json!({"type":"none"}),
        json!({"type":"none"}),
        Arc::new(SecretResolver::disabled()),
    );
    let acquisition = none_program
        .begin_acquisition(Hooks::for_pack(Decision::Allow, "wire-contract"))
        .await
        .unwrap();
    none_program
        .execute(&acquisition, json!({"record":"NONE-0001"}))
        .await
        .unwrap();
    let requests = none_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].headers.contains_key("authorization"));

    let scheme_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/records/TOKEN-0001"))
        .and(header("authorization", "Token private-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "lookup":"matched","facts":{"ok":true}
        })))
        .expect(1)
        .mount(&scheme_server)
        .await;
    let (_root, secrets) = secret_resolver(&[("token", "private-token")]);
    let scheme_program = wire_program(
        &scheme_server,
        json!({"type":"static-authorization","scheme":"Token"}),
        json!({"type":"static-authorization","tokenRef":"secret:file/token"}),
        json!({"type":"static-authorization"}),
        secrets,
    );
    let acquisition = scheme_program
        .begin_acquisition(Hooks::for_pack(Decision::Allow, "wire-contract"))
        .await
        .unwrap();
    scheme_program
        .execute(&acquisition, json!({"record":"TOKEN-0001"}))
        .await
        .unwrap();
}

#[tokio::test]
async fn hostile_path_input_is_refused_before_api_key_resolution_or_transport() {
    let server = MockServer::start().await;
    let (_root, secrets) = secret_resolver(&[("api-key", "private-api-key")]);
    let program = wire_program(
        &server,
        json!({"type":"static-api-key","headerName":"X-Api-Key"}),
        json!({"type":"static-api-key","valueRef":"secret:file/api-key"}),
        json!({"type":"static-api-key"}),
        secrets,
    );
    let hooks = Hooks::for_pack(Decision::Allow, "wire-contract");
    let acquisition = program.begin_acquisition(hooks.clone()).await.unwrap();
    let hostile = "../private/".repeat(8);
    assert!(hostile.len() > 64);
    let result = program
        .execute(&acquisition, json!({"record":hostile.clone()}))
        .await;
    assert!(matches!(
        &result,
        Err(registry_adapter_engine::evidence::EvidenceExecutionError::InputsInvalid)
    ));
    let diagnostic = format!("{result:?}");
    assert!(!diagnostic.contains(&hostile));
    assert!(!diagnostic.contains("private-api-key"));
    assert_eq!(hooks.credentials.load(Ordering::SeqCst), 0);
    assert!(server.received_requests().await.unwrap().is_empty());
}

fn two_endpoint_program(server: &MockServer, limits: EvidenceLimits) -> EvidenceProgram {
    let inputs = serde_json::to_vec(&json!({
        "type":"object","additionalProperties":false,"properties":{}
    }))
    .unwrap();
    let facts = serde_json::to_vec(&json!({
        "type":"object","additionalProperties":false,"required":["ok"],
        "properties":{"ok":{"type":"boolean"}}
    }))
    .unwrap();
    let pack: AdapterPack = serde_json::from_value(json!({
        "id":"two-endpoint","version":"1","testedVersions":[],
        "endpoints":[
            {"id":"first","component":"http","authentication":{"type":"none"},
             "attemptTimeoutMilliseconds":1000,"maximumResponseBytes":4096,
             "requestHeaders":[],"operations":[],"testedVersions":[]},
            {"id":"second","component":"http","authentication":{"type":"none"},
             "attemptTimeoutMilliseconds":1000,"maximumResponseBytes":4096,
             "requestHeaders":[],"operations":[],"testedVersions":[]}
        ],
        "sourceRoutes":[{"id":"lookup","evidence":{
            "inputsSchema":{"path":"schemas/inputs.json","digest":registry_platform_config::sha256_uri(&inputs)},
            "factsSchema":{"path":"schemas/facts.json","digest":registry_platform_config::sha256_uri(&facts)}
        },"steps":[
            {"to":{"uri":"http:first","parameters":{"httpMethod":"GET","path":"/first"}}},
            {"to":{"uri":"http:second","parameters":{"httpMethod":"GET","path":"/second"}}},
            {"setBody":{"constant":{"lookup":"matched","facts":{"ok":true}}}}
        ]}]
    }))
    .unwrap();
    let artifacts = PackArtifactBytes::new([
        ("schemas/inputs.json".to_owned(), inputs),
        ("schemas/facts.json".to_owned(), facts),
    ]);
    let runtime = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":"two-endpoint","endpoints":[
                {"endpoint":"first","baseUrl":server.uri(),"credential":{"type":"none"}},
                {"endpoint":"second","baseUrl":server.uri(),"credential":{"type":"none"}}
            ],"allowedPrivateCidrs":[]
        }))
        .unwrap(),
        Arc::new(SecretResolver::disabled()),
        BTreeMap::new(),
    );
    let policies = ["first", "second"].map(|endpoint| {
        serde_json::from_value(json!({
            "endpoint":endpoint,"baseUrl":server.uri(),"clientIdentity":"forbidden",
            "authentication":{"type":"none"}
        }))
        .unwrap()
    });
    compile_evidence_with_protocols(
        &EvidenceCompileInputs {
            pack: &pack,
            route: "lookup",
            runtime: &runtime,
            connection_id: Some("two-endpoint"),
            connection: &policies,
            pack_artifacts: &artifacts,
            limits,
        },
        &registry_evidence::host_protocol::registry().unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn first_endpoint_failure_stops_a_multi_endpoint_pack_before_later_sends() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/first"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/second"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "lookup":"matched","facts":{"ok":true}
        })))
        .expect(0)
        .mount(&server)
        .await;
    let program = two_endpoint_program(&server, EvidenceLimits::default());
    let acquisition = program
        .begin_acquisition(Hooks::for_pack(Decision::Allow, "two-endpoint"))
        .await
        .unwrap();
    assert!(matches!(
        program.execute(&acquisition, json!({})).await,
        Err(registry_adapter_engine::evidence::EvidenceExecutionError::Route(_))
    ));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/first");
}

#[tokio::test]
async fn one_acquisition_budget_accumulates_across_repeated_two_endpoint_executions() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/first"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/second"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    let program = two_endpoint_program(
        &server,
        EvidenceLimits::try_new(3, 5_000, 64 * 1024).unwrap(),
    );
    let acquisition = program
        .begin_acquisition(Hooks::for_pack(Decision::Allow, "two-endpoint"))
        .await
        .unwrap();

    assert_eq!(
        program
            .execute(&acquisition, json!({}))
            .await
            .expect("the first two-operation execution fits the shared budget"),
        EvidenceLookup::Matched {
            facts: json!({"ok":true})
        }
    );
    let error = program
        .execute(&acquisition, json!({}))
        .await
        .expect_err("the second execution cannot reset the shared acquisition budget");
    let registry_adapter_engine::evidence::EvidenceExecutionError::Route(failure) = error else {
        panic!("the fourth operation must be a route budget refusal");
    };
    assert_eq!(
        failure.class,
        registry_adapter_core::ErrorClass::BudgetExhausted
    );
    assert_eq!(failure.code, Some("evidence.budget-exhausted"));
    assert!(failure.message.is_none());
    assert!(failure.data.is_none());
    assert!(failure.auth.is_none());
    assert!(failure.evidence_diagnostic.is_none());

    let requests = server.received_requests().await.unwrap();
    let paths = requests
        .iter()
        .map(|request| request.url.path())
        .collect::<Vec<_>>();
    assert_eq!(paths, ["/first", "/second", "/first"]);
}

#[tokio::test]
async fn one_shared_data_operation_budget_stops_a_multi_endpoint_pack_before_send_two() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/civil-record-search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total":1,
            "records":[{
                "civil_record_reference":"CIVIL-0007",
                "reference_namespace":"urn:example:fixture:civil-record"
            }]
        })))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/persons/CIVIL-0007/unions"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let bundle = load_declared_fixture("surviving-spouse-status");
    let source = bundle.config.sources.get("survivorship-registers").unwrap();
    let (_root, secrets) = secret_resolver(&[
        ("civil", PRIVATE_TOKEN),
        ("union", PRIVATE_TOKEN),
        ("death", PRIVATE_TOKEN),
    ]);
    let endpoints = ["civil-records", "union-register", "death-register"];
    let runtime = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":source.connection(),
            "endpoints":endpoints.iter().zip(["civil","union","death"]).map(|(endpoint, token)| json!({
                "endpoint":endpoint,
                "baseUrl":server.uri(),
                "credential":{"type":"static-authorization","tokenRef":format!("secret:file/{token}")}
            })).collect::<Vec<_>>(),
            "allowedPrivateCidrs":[]
        }))
        .unwrap(),
        secrets,
        BTreeMap::new(),
    );
    let policies = endpoints
        .iter()
        .map(|endpoint| static_policy(endpoint, &server.uri()))
        .collect::<Vec<_>>();
    let result = PackSourceExecutor::compile_diagnosed(
        source,
        bundle.source_pack("survivorship-registers").unwrap(),
        &runtime,
        &policies,
        EvidenceLimits::try_new(1, 5_000, 64 * 1024).unwrap(),
    );
    assert_eq!(
        result.err().map(|error| error.reason()),
        Some(SourceBindingReason::OperationBudget)
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn dropping_an_in_flight_pack_acquisition_does_not_retry_its_send() {
    let (address, attempts, mut requests, server) = spawn_stalled_server().await;
    let (_root, secrets) = secret_resolver(&[("token", PRIVATE_TOKEN)]);
    let executor = Arc::new(compile_adult_url(
        &format!("http://{address}"),
        EvidenceLimits::try_new(1, 10_000, 64 * 1024).unwrap(),
        "token",
        secrets,
        BTreeMap::new(),
    ));
    let task = tokio::spawn({
        let executor = Arc::clone(&executor);
        async move {
            executor
                .execute(adult_inputs(), Utc::now(), Hooks::new(Decision::Allow))
                .await
        }
    });
    let request = timeout(Duration::from_secs(2), requests.recv()).await;
    let response_was_pending = !task.is_finished();
    task.abort();
    let cancellation = task.await;
    server.abort();
    let server_shutdown = server.await;

    let request = request
        .expect("the one send begins")
        .expect("the stalled source reports the request")
        .expect("the stalled source reads the request");
    assert!(
        response_was_pending,
        "the absent response keeps the send in flight until cancellation"
    );
    assert!(
        matches!(cancellation, Err(error) if error.is_cancelled()),
        "the in-flight acquisition is cancelled instead of completing"
    );
    assert!(matches!(server_shutdown, Err(error) if error.is_cancelled()));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(request.starts_with(b"POST /v1/facts HTTP/1.1\r\n"));
}

#[tokio::test]
async fn reset_on_the_first_connection_is_one_categorical_dependency_attempt() {
    let (address, attempts, server) = spawn_reset_server().await;
    let (root, secrets) = secret_resolver(&[("token", PRIVATE_TOKEN)]);
    let executor = compile_adult_url(
        &format!("http://{address}"),
        EvidenceLimits::try_new(1, 2_000, 64 * 1024).unwrap(),
        "token",
        secrets,
        BTreeMap::new(),
    );
    let error = executor
        .execute(adult_inputs(), Utc::now(), Hooks::new(Decision::Allow))
        .await
        .unwrap_err();
    assert_eq!(error, PackSourceError::Dependency);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    server.abort();
    drop(root);
}

#[tokio::test]
async fn captured_private_ca_succeeds_and_hostname_mismatch_fails_through_the_pack() {
    const BODY: &[u8] = br#"{"total":1,"records":[{"licence_state":"active","valid_from":"2020-01-01","valid_until":"2030-01-01"}]}"#;
    let private_ip = assigned_private_ipv4();
    let allowed_private_cidr = format!("{private_ip}/32");
    let (address, ca_pem, server) =
        spawn_private_ca_server(private_ip, &private_ip.to_string(), BODY, true).await;
    let (_root, secrets) = secret_resolver(&[("username", "synthetic"), ("password", "password")]);
    let executor = compile_licence_tls(
        &format!("https://{private_ip}:{}", address.port()),
        &allowed_private_cidr,
        ca_pem,
        Arc::clone(&secrets),
    );
    assert!(matches!(
        executor
            .execute(
                json!({"licence_reference":"LIC-0007","registry_region":"north"}),
                Utc::now(),
                Hooks::for_pack(Decision::Allow, "fixture-licence"),
            )
            .await
            .unwrap(),
        LookupResult::Match(_)
    ));
    server.await.unwrap();

    let (address, ca_pem, mismatch_server) =
        spawn_private_ca_server(private_ip, "192.0.2.2", BODY, false).await;
    let mismatch = compile_licence_tls(
        &format!("https://{private_ip}:{}", address.port()),
        &allowed_private_cidr,
        ca_pem,
        secrets,
    )
    .execute(
        json!({"licence_reference":"LIC-0007","registry_region":"north"}),
        Utc::now(),
        Hooks::for_pack(Decision::Allow, "fixture-licence"),
    )
    .await;
    assert_eq!(mismatch, Err(PackSourceError::Dependency));
    mismatch_server.await.unwrap();
}

#[tokio::test]
async fn private_ca_stage_reports_the_exact_engine_result_before_pack_mapping() {
    const BODY: &[u8] = br#"{"total":1,"records":[{"licence_state":"active","valid_from":"2020-01-01","valid_until":"2030-01-01"}]}"#;
    let private_ip = assigned_private_ipv4();
    let allowed_private_cidr = format!("{private_ip}/32");
    let (address, ca_pem, server) =
        spawn_private_ca_server(private_ip, &private_ip.to_string(), BODY, true).await;
    let (_root, secrets) = secret_resolver(&[("username", "synthetic"), ("password", "password")]);
    let program = compile_licence_tls_program(
        &format!("https://{private_ip}:{}", address.port()),
        &allowed_private_cidr,
        ca_pem,
        secrets,
    );
    let acquisition = program
        .begin_acquisition(Hooks::for_pack(Decision::Allow, "fixture-licence"))
        .await
        .unwrap();
    let result = program
        .execute(
            &acquisition,
            json!({"licence_reference":"LIC-0007","registry_region":"north"}),
        )
        .await;
    assert!(result.is_ok(), "exact TLS engine result: {result:?}");
    server.await.unwrap();
}

#[test]
fn current_private_ca_plan_refuses_unbound_and_missing_captures() {
    let bundle = load_bundle("professional-licence");
    let source = bundle.config.sources.get("source-c").unwrap();
    let (_root, secrets) = secret_resolver(&[("username", "synthetic"), ("password", "password")]);
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"provider", "baseUrl":"https://source.invalid",
        "tlsTrustProfile":"private-pki", "clientIdentity":"forbidden",
        "authentication":{"type":"basic"}
    }))
    .unwrap();

    let unbound = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":source.connection(), "endpoints":[{
                "endpoint":"provider", "baseUrl":"https://source.invalid",
                "credential":{
                    "type":"basic", "usernameRef":"secret:file/username",
                    "passwordRef":"secret:file/password"
                }
            }],
            "outboundTls":{"trustProfiles":{
                "private-pki":{"caBundleFile":"/captured/private-ca.pem"}
            }},
            "allowedPrivateCidrs":[]
        }))
        .unwrap(),
        Arc::clone(&secrets),
        BTreeMap::from([("private-pki".to_owned(), b"captured-ca".to_vec())]),
    );
    let error = PackSourceExecutor::compile_diagnosed(
        source,
        bundle.source_pack("source-c").unwrap(),
        &unbound,
        std::slice::from_ref(&policy),
        EvidenceLimits::default(),
    )
    .expect_err("a runtime binding without the reviewed trust profile is refused");
    assert_eq!(error.endpoint(), Some("provider"));
    assert_eq!(
        error.reason(),
        SourceBindingReason::Policy(ConnectionPolicyReason::TlsTrustProfileMismatch)
    );

    let missing_capture = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":source.connection(), "endpoints":[{
                "endpoint":"provider", "baseUrl":"https://source.invalid",
                "credential":{
                    "type":"basic", "usernameRef":"secret:file/username",
                    "passwordRef":"secret:file/password"
                },
                "tlsTrustProfile":"private-pki"
            }],
            "outboundTls":{"trustProfiles":{
                "private-pki":{"caBundleFile":"/captured/private-ca.pem"}
            }},
            "allowedPrivateCidrs":[]
        }))
        .unwrap(),
        secrets,
        BTreeMap::new(),
    );
    let error = PackSourceExecutor::compile_diagnosed(
        source,
        bundle.source_pack("source-c").unwrap(),
        &missing_capture,
        &[policy],
        EvidenceLimits::default(),
    )
    .expect_err("a trust profile with no captured CA bundle is refused");
    assert_eq!(error.endpoint(), Some("provider"));
    assert_eq!(
        error.reason(),
        SourceBindingReason::Policy(ConnectionPolicyReason::TrustMaterialUnavailable)
    );
    assert!(!error.to_string().contains("private-ca.pem"));
}

#[cfg(unix)]
#[test]
fn current_runtime_ca_capture_rejects_symlink_malformed_and_mutable_files() {
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
                "apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1\nkind: EvidenceRuntimeConfig\npackage:\n  root: /etc/registry-evidence/bundle\nlistener:\n  bind: 127.0.0.1:8080\n  tlsTermination: operator-controlled-upstream\n  trustProxyIdentityHeaders: false\n  maximumRequestBytes: 65536\n  maximumConcurrentRequests: 64\n  requestTimeoutMilliseconds: 10000\n  shutdownGraceMilliseconds: 30000\nsecretProviders:\n  file: {{root: {}}}\nsigner:\n  type: transit\n  unixSocketPath: /run/registry-evidence/transit-proxy.sock\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 7\n  attemptTimeoutMilliseconds: 2000\naudit:\n  path: /var/lib/registry-evidence/audit/evidence.jsonl\noutboundTls:\n  systemRoots: true\n  trustProfiles:\n    private-pki: {{caBundleFile: {}}}\n",
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
            CaCase::Mutable => assert_eq!(
                error.artifact_fault().map(|fault| fault.fault().cause()),
                Some("the TLS CA bundle the runtime file names is writable")
            ),
        }
    }
}

#[tokio::test]
async fn maintained_oauth_pack_uses_form_credentials_and_reuses_one_bounded_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=synthetic-client"))
        .and(body_string_contains("client_secret=synthetic-secret"))
        .and(body_string_contains("scope=recordsearch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token":"synthetic-access-token",
            "token_type":"Bearer"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/events/search"))
        .and(header("authorization", "Bearer synthetic-access-token"))
        .and(header("accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total":1,
            "results":[{
                "type":"birth","status":"REGISTERED",
                "trackingId":"TRACKING-SYNTHETIC-001","dateOfEvent":"2000-01-01",
                "private_canary":"discard"
            }]
        })))
        .expect(2)
        .mount(&server)
        .await;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle",
    );
    let bundle = load_bundle_at(&root);
    let source = bundle.config.sources.get("registered-birth-date").unwrap();
    let (_secret_root, secrets) = secret_resolver(&[
        ("client-id", "synthetic-client"),
        ("client-secret", "synthetic-secret"),
    ]);
    let token_endpoint = format!("{}/token", server.uri());
    let runtime = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":source.connection(),
            "endpoints":[{
                "endpoint":"events","baseUrl":server.uri(),
                "credential":{
                    "type":"oauth2-client-credentials",
                    "tokenEndpoint":token_endpoint,
                    "clientIdRef":"secret:file/client-id",
                    "clientSecretRef":"secret:file/client-secret",
                    "scope":"recordsearch","credentialPlacement":"form-body",
                    "maximumCacheSeconds":300,"assumedLifetimeSeconds":60
                }
            }],"allowedPrivateCidrs":[]
        }))
        .unwrap(),
        secrets,
        BTreeMap::new(),
    );
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"events","baseUrl":server.uri(),"clientIdentity":"forbidden",
        "authentication":{
            "type":"oauth2-client-credentials","tokenEndpoint":token_endpoint,
            "scope":"recordsearch","credentialPlacement":"form-body"
        }
    }))
    .unwrap();
    let closure = bundle.source_pack("registered-birth-date").unwrap();
    if let Err(error) = compile_evidence_pack_with_protocols(
        &closure.pack(),
        &source.route,
        &closure.artifacts(),
        EvidenceLimits::default(),
        &registry_evidence::host_protocol::registry().unwrap(),
    ) {
        panic!("maintained OpenCRVS Evidence pack must compile: {error:?}");
    }
    let executor = PackSourceExecutor::compile(
        source,
        closure,
        &runtime,
        &[policy],
        EvidenceLimits::default(),
    )
    .unwrap();
    for _ in 0..2 {
        let lookup = executor
            .execute(
                json!({"trackingId":"TRACKING-SYNTHETIC-001"}),
                Utc::now(),
                Hooks::for_program(Decision::Allow, "opencrvs-events", "evidence-birth-date"),
            )
            .await
            .unwrap();
        assert_eq!(
            lookup,
            LookupResult::Match(BTreeMap::from([
                (
                    "record_tracking_id".to_owned(),
                    json!("TRACKING-SYNTHETIC-001")
                ),
                ("date_of_birth".to_owned(), json!("2000-01-01")),
            ]))
        );
    }
}

async fn actual_pack_failure(
    response: ResponseTemplate,
    limits: EvidenceLimits,
) -> (PackSourceError, usize) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .respond_with(response)
        .expect(1)
        .mount(&server)
        .await;
    let (_root, secrets) = secret_resolver(&[("token", PRIVATE_TOKEN)]);
    let error = compile_adult(&server, limits, "token", secrets)
        .execute(adult_inputs(), Utc::now(), Hooks::new(Decision::Allow))
        .await
        .unwrap_err();
    let count = server.received_requests().await.unwrap().len();
    (error, count)
}

#[tokio::test]
async fn actual_pack_http_failures_keep_exact_categories_one_send_and_no_facts() {
    let defaults = EvidenceLimits::default();
    let cases = [
        (
            "unauthorized",
            ResponseTemplate::new(401).set_body_json(json!({"private":PRIVATE_TOKEN})),
            defaults,
            PackSourceError::Credential,
        ),
        (
            "server-error",
            ResponseTemplate::new(500).set_body_json(json!({"private":PRIVATE_TOKEN})),
            defaults,
            PackSourceError::Dependency,
        ),
        (
            "wrong-media",
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string("not-json"),
            defaults,
            PackSourceError::Protocol,
        ),
        (
            "bad-json",
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string("{"),
            defaults,
            PackSourceError::Protocol,
        ),
        (
            "oversize",
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(format!("{{\"padding\":\"{}\"}}", "x".repeat(70_000))),
            EvidenceLimits::try_new(5, 30_000, 1024 * 1024).unwrap(),
            PackSourceError::ResponseTooLarge,
        ),
        (
            "redirect",
            ResponseTemplate::new(302).insert_header("location", "/must-not-follow"),
            defaults,
            PackSourceError::Protocol,
        ),
    ];
    for (label, response, limits, expected) in cases {
        let (error, sends) = actual_pack_failure(response, limits).await;
        assert_eq!(error, expected, "{label}");
        assert_eq!(sends, 1, "{label} must make exactly one source send");
        assert!(!error.to_string().contains(PRIVATE_TOKEN), "{label}");
    }

    let (timeout_error, sends) = actual_pack_failure(
        ResponseTemplate::new(200)
            .set_delay(Duration::from_millis(3_500))
            .set_body_json(json!({"total":0})),
        EvidenceLimits::default(),
    )
    .await;
    assert_eq!(timeout_error, PackSourceError::Timeout);
    assert_eq!(sends, 1);
}

#[test]
fn retired_source_dsl_fields_are_closed_instead_of_compatibly_interpreted() {
    let bundle = load_bundle("adult-status");
    let source = bundle.config.sources.get("source-a").unwrap();
    let current = serde_json::to_value(source).unwrap();
    for (field, value) in [
        ("baseUrl", json!("https://caller.invalid")),
        (
            "authentication",
            json!({"type":"oauth2-client-credentials"}),
        ),
        ("request", json!({"method":"GET","path":"/v1/records"})),
        ("prepareScript", json!("adapters/prepare.rhai")),
        ("extractScript", json!("adapters/extract.rhai")),
        ("responseSchema", json!("schemas/response.yaml")),
        ("adapterParameters", json!({"private":"value"})),
    ] {
        let mut candidate = current.clone();
        candidate[field] = value;
        assert!(
            serde_json::from_value::<SourceConfig>(candidate).is_err(),
            "retired source field {field} must remain closed"
        );
    }
}

#[test]
fn pack_and_connection_authentication_authority_must_match() {
    let bundle = load_bundle("adult-status");
    let source = bundle.config.sources.get("source-a").unwrap();
    let (_root, secrets) = secret_resolver(&[("username", "u"), ("password", "p")]);
    let runtime = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":source.connection(),
            "endpoints":[{"endpoint":"provider","baseUrl":"https://source.invalid","credential":{
                "type":"basic","usernameRef":"secret:file/username","passwordRef":"secret:file/password"
            }}],"allowedPrivateCidrs":[]
        }))
        .unwrap(),
        secrets,
        BTreeMap::new(),
    );
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"provider","baseUrl":"https://source.invalid","clientIdentity":"forbidden",
        "authentication":{"type":"basic"}
    }))
    .unwrap();
    let error = PackSourceExecutor::compile_diagnosed(
        source,
        bundle.source_pack("source-a").unwrap(),
        &runtime,
        &[policy],
        EvidenceLimits::default(),
    )
    .expect_err("a policy whose authentication differs from the pack's is refused");
    assert_eq!(error.endpoint(), Some("provider"));
    assert_eq!(
        error.reason(),
        SourceBindingReason::Policy(ConnectionPolicyReason::AuthenticationMismatch)
    );
    assert!(!error.to_string().contains("secret:"));
}

#[test]
fn retained_pack_failures_are_value_free() {
    for error in [
        PackSourceError::Inputs,
        PackSourceError::Authority,
        PackSourceError::Audit,
        PackSourceError::Budget,
        PackSourceError::Protocol,
        PackSourceError::Dependency,
        PackSourceError::Credential,
        PackSourceError::Timeout,
        PackSourceError::ResponseTooLarge,
    ] {
        let rendered = error.to_string();
        assert!(!rendered.contains("private-canary"));
        assert!(!rendered.contains("source.invalid"));
        assert!(!rendered.contains("secret:file"));
    }
}
