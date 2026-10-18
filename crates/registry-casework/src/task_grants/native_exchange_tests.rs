//! Actual Casework approval -> native RFC 8693 exchange -> Evidence, BREG, and
//! Scheduling's real bearer authenticator, without a product crate dependency.
//! Credentials and protected response bodies stay in memory and never enter logs or argv.
//! Set the two disposable database variables and absolute Scheduling probe path
//! named by the ignore reason, then run
//! `cargo test --locked -p registry-casework --features postgres-test --lib
//! approved_casework_tasks_reach_evidence_breg_and_scheduling_through_stock_thunderid -- --ignored`.
use super::native_resource as resource;
use super::*;
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use registry_evidence::{runtime::EvidenceRuntime, server as evidence_server};
use registry_platform_config::{write_package, SecretProvider, SecretResolver};
use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider};
use registry_thunderid_tooling::{container::Session, description::*, local, render};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};
const CASEWORK_RESOURCE: &str = "urn:casework:native-task";
const BREG_RESOURCE: &str = "urn:breg:task-test";
const EVIDENCE_RESOURCE: &str = "urn:registry:evidence:fixture";
const SCHEDULING_RESOURCE: &str = "urn:registry:scheduling:fixture";
const EVIDENCE_REQUIREMENT: &str = "urn:example:fixture:requirement:adult-status:v1";
const EVIDENCE_AUDIENCE: &str = "https://relying.invalid/procedure";
const EVIDENCE_TAG: &str = "fixture-agency";
const AUTHORITY: &str = "https://casework.example";
const SCHEDULING_AUTH_PROBE_ENV: &str = "SCHEDULING_AUTH_PROBE_BIN";
const OIDC_NETWORK_PROBE_ENV: &str = "BREG_OIDC_NETWORK_PROBE_BIN";
const OIDC_NETWORK_PROBE_IMAGE_ENV: &str = "BREG_OIDC_NETWORK_PROBE_IMAGE";
const EVIDENCE_SIGNING_KEY: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;

/// Synthetic purpose-bound provider for the three native grant resources.
struct Source;
#[async_trait]
impl ReviewContextProvider for Source {
    fn provider_id(&self) -> &str {
        "source"
    }
    fn capabilities(&self) -> &[ReviewContextCapability] {
        &[
            ReviewContextCapability::HumanDisplay,
            ReviewContextCapability::ServiceStatus,
            ReviewContextCapability::TaskGrantContext,
        ]
    }
    async fn human_display(
        &self,
        request: HumanDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        Ok(HumanDisplayObservation {
            identity: request.identity.clone(),
            reviewable: true,
            display_reference: Some("Synthetic request".into()),
            fields: BTreeMap::new(),
        })
    }
    async fn service_status(
        &self,
        identity: &ReviewContextIdentity,
    ) -> Result<ServiceStatusObservation, ReviewContextError> {
        Ok(ServiceStatusObservation {
            identity: identity.clone(),
            reviewable: true,
        })
    }
    async fn task_grant_context(
        &self,
        request: &ServiceContextRequest,
    ) -> Result<ServiceContextObservation, ReviewContextError> {
        let values = match request.fields.as_slice() {
            [field] if field == "tenant" => BTreeMap::from([("tenant".into(), json!("tenant-a"))]),
            [birth_date, family_name, given_name]
                if birth_date == "birth_date"
                    && family_name == "family_name"
                    && given_name == "given_name" =>
            {
                BTreeMap::from([
                    ("birth_date".into(), json!("2000-01-01")),
                    ("family_name".into(), json!("Diallo")),
                    ("given_name".into(), json!("Amina")),
                ])
            }
            _ => panic!("unexpected governed task fields: {:?}", request.fields),
        };
        Ok(ServiceContextObservation {
            request: request.clone(),
            reviewable: true,
            fields: values,
        })
    }
}

fn key(kid: &str) -> registry_platform_crypto::PrivateJwk {
    let mut key = registry_platform_crypto::generate_private_jwk(
        registry_platform_crypto::GeneratedKeyAlgorithm::Rs384,
    )
    .unwrap();
    key.alg = Some("RS256".into());
    key.kid = Some(kid.into());
    key
}
fn private_key_value(key: &registry_platform_crypto::PrivateJwk) -> Value {
    json!({
        "kty": key.kty,
        "alg": key.alg,
        "kid": key.kid,
        "crv": key.crv,
        "x": key.x,
        "y": key.y,
        "n": key.n,
        "e": key.e,
        "d": key.d,
        "p": key.p,
        "q": key.q,
        "dp": key.dp,
        "dq": key.dq,
        "qi": key.qi,
    })
}
fn client(
    id: &str,
    key: &registry_platform_crypto::PrivateJwk,
    kind: Option<&str>,
    scopes: &[&str],
) -> local::LocalClient {
    local::LocalClient {
        client_id: id.into(),
        public_jwks: json!({"keys":[key.public()]}).to_string(),
        claims: kind
            .map(|kind| BTreeMap::from([("registry_actor_kind".into(), kind.into())]))
            .unwrap_or_default(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        allow_human_fixture: kind == Some("human"),
    }
}
struct Issuer {
    description: IssuerDescription,
    image: String,
    jwks: Value,
}
impl Issuer {
    fn session(&self) -> Session<'_> {
        Session {
            label: &self.description.session.label,
            id: &self.description.session.id,
            port: self.description.port,
            state_root: &self.description.state_root,
            image: &self.image,
        }
    }
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.description.port)
    }
}
impl Drop for Issuer {
    fn drop(&mut self) {
        let _ = local::stop(&self.session(), Path::new("docker"));
    }
}

struct EvidenceDeployment {
    base_url: String,
    _runtime: Arc<EvidenceRuntime>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    _prepared: PreparedEvidence,
    _source: MockServer,
}

impl Drop for EvidenceDeployment {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// A sealed Evidence bundle and its runtime file, unsealed again on drop so
/// the temporary root can be removed.
struct PreparedEvidence {
    bundle_root: PathBuf,
    runtime_path: PathBuf,
}

impl Drop for PreparedEvidence {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.runtime_path, fs::Permissions::from_mode(0o644));
        unseal(&self.bundle_root);
    }
}

async fn start_evidence(root: &Path, issuer: &Issuer) -> EvidenceDeployment {
    let source = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "date_of_birth": "2000-01-01"
        })))
        .mount(&source)
        .await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let prepared = prepare_evidence(root, &source.uri(), &issuer.url(), port);
    let runtime = Arc::new(
        EvidenceRuntime::initialize(&prepared.runtime_path)
            .await
            .unwrap(),
    );
    let served = Arc::clone(&runtime);
    let server =
        tokio::spawn(
            async move { evidence_server::serve(served, std::future::pending::<()>()).await },
        );
    let base_url = format!("http://127.0.0.1:{port}");
    let probe = reqwest::Client::builder().no_proxy().build().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if probe
                .get(format!("{base_url}/ready"))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    EvidenceDeployment {
        base_url,
        _runtime: runtime,
        server,
        _prepared: prepared,
        _source: source,
    }
}

/// Copy the adult-status acceptance bundle, point it at the local source and
/// issuer, write its runtime file and secrets, and seal the bundle.
fn prepare_evidence(
    root: &Path,
    source_origin: &str,
    issuer_origin: &str,
    port: u16,
) -> PreparedEvidence {
    let evidence_root = root.join("evidence-deployment");
    let bundle_root = evidence_root.join("bundle");
    let secret_root = evidence_root.join("secrets");
    let runtime_path = evidence_root.join("runtime.yaml");
    let audit_path = evidence_root.join("audit.jsonl");
    fs::create_dir_all(&bundle_root).unwrap();
    fs::create_dir_all(&secret_root).unwrap();
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700)).unwrap();
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/adult-status"),
        &bundle_root,
    );
    rewrite_evidence_fixture(
        &bundle_root,
        source_origin,
        issuer_origin,
        &format!("{issuer_origin}/oauth2/jwks"),
        &format!("http://127.0.0.1:{port}"),
    );
    write_secret(
        &secret_root,
        "audit-hash-key",
        "casework-evidence-audit-secret-32-bytes",
    );
    write_secret(
        &secret_root,
        "subject-binding-key",
        "casework-evidence-binding-secret-32-bytes",
    );
    write_secret(&secret_root, "signing-key", EVIDENCE_SIGNING_KEY);
    write_secret(&secret_root, "source-a-token", "source-fixture-token");
    fs::write(
        &runtime_path,
        format!(
            r#"apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1
kind: EvidenceRuntimeConfig
package:
  root: {bundle}
listener:
  bind: 127.0.0.1:{port}
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file:
    root: {secrets}
signer:
  type: local-jwk
  privateKeyRef: secret:file/signing-key
audit:
  path: {audit}
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
"#,
            bundle = bundle_root.display(),
            secrets = secret_root.display(),
            audit = audit_path.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444)).unwrap();
    refresh_package_envelope(&bundle_root);
    seal(&bundle_root);
    PreparedEvidence {
        bundle_root,
        runtime_path,
    }
}

// The cross-product journey above needs Docker and two databases; this proves
// without either that the rewritten Evidence fixture and runtime file still
// load through Evidence's own deployment loader.
#[test]
fn the_rewritten_evidence_deployment_loads_through_the_evidence_loader() {
    let root = canonical_tempdir();
    let prepared = prepare_evidence(
        root.path(),
        "http://127.0.0.1:9",
        "http://127.0.0.1:10",
        8080,
    );
    registry_evidence::bundle::DeploymentInputs::load(&prepared.runtime_path).unwrap();
}

/// The runtime configuration loaders refuse a path through a symbolic link,
/// and the system temporary root is one on some hosts.
fn canonical_tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
}

fn rewrite_evidence_fixture(
    bundle_root: &Path,
    source_origin: &str,
    issuer_origin: &str,
    issuer_jwks_uri: &str,
    public_origin: &str,
) {
    let path = bundle_root.join("evidence.yaml");
    let mut document = fs::read_to_string(&path).unwrap();
    for (from, to) in [
        ("assuranceProfile: evidence-grade", "assuranceProfile: local"),
        (
            "baseUrl: https://source.invalid",
            &format!("baseUrl: {source_origin}"),
        ),
        (
            "publicOrigin: https://evidence.invalid",
            &format!("publicOrigin: {public_origin}"),
        ),
        (
            "issuer: https://identity.invalid",
            &format!("issuer: {issuer_origin}"),
        ),
        (
            "audience: evidence-fixture",
            &format!("audience: {EVIDENCE_RESOURCE}"),
        ),
        (
            "uri: https://identity.invalid/.well-known/jwks.json",
            &format!("uri: {issuer_jwks_uri}"),
        ),
        ("algorithms: [ES256]", "algorithms: [RS256]"),
        (
            "allowedClients: unrestricted",
            "allowedClients: [evidence-task-agent, other-agent]",
        ),
        (
            "  statutory-caseworker-v1:\n    kind: statutory",
            "  casework:\n    requesterClients: [evidence-task-agent, other-agent]\n    grantSourceIssuer: https://casework.example\n    kind: statutory",
        ),
        (
            "        subjects: [{role: subject, selectorProfile: person-demographics-v1, valueOrigin: request}]",
            "        subjects:\n          - role: subject\n            selectorProfile: person-demographics-v1\n            valueOrigin: authenticated-grant\n            valueClaims: {given_name: identity.given_name, family_name: identity.family_name, birth_date: identity.birth_date}",
        ),
    ] {
        assert_eq!(document.matches(from).count(), 1, "fixture drift for {from}");
        document = document.replace(from, to);
    }
    fs::write(&path, document).unwrap();
    let config =
        registry_evidence::config::EvidenceConfig::parse_yaml(&fs::read(&path).unwrap()).unwrap();
    let discovery = registry_evidence::discovery::render(&config)
        .unwrap()
        .unwrap();
    fs::write(bundle_root.join("catalog.jsonld"), discovery).unwrap();
}

fn write_secret(root: &Path, name: &str, value: &str) {
    let path = root.join(name);
    fs::write(&path, value).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn copy_tree(source: &Path, target: &Path) {
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir(&destination).unwrap();
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}

/// Republish the staged Evidence package after its intended authored changes.
fn refresh_package_envelope(root: &Path) {
    let sum_file = root.join(registry_platform_config::SUM_FILE);
    if sum_file.exists() {
        fs::remove_file(&sum_file).unwrap();
    }
    registry_platform_config::write_sum_file(
        root,
        None,
        &registry_platform_config::PackageLimits {
            max_files: registry_evidence::bundle::MAX_BUNDLE_FILES,
            max_file_bytes: registry_evidence::bundle::MAX_ARTIFACT_BYTES,
            max_total_bytes: registry_evidence::bundle::MAX_BUNDLE_BYTES,
            max_depth: 3,
            max_path_bytes: 128,
        },
        "evidencectl package",
    )
    .unwrap();
}

fn seal(root: &Path) {
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let child = entry.path();
        if child.is_dir() {
            seal(&child);
        } else {
            fs::set_permissions(child, fs::Permissions::from_mode(0o444)).unwrap();
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o555)).unwrap();
}

fn unseal(root: &Path) {
    let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o755));
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_dir() {
            unseal(&child);
        } else {
            let _ = fs::set_permissions(child, fs::Permissions::from_mode(0o644));
        }
    }
}
fn start_issuer(
    root: &Path,
    casework_port: u16,
    human: &registry_platform_crypto::PrivateJwk,
    agent: &registry_platform_crypto::PrivateJwk,
    evidence_agent: &registry_platform_crypto::PrivateJwk,
    other_agent: &registry_platform_crypto::PrivateJwk,
    status: &registry_platform_crypto::PrivateJwk,
    seed: &registry_platform_crypto::PrivateJwk,
    other_seed: &registry_platform_crypto::PrivateJwk,
) -> Issuer {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let id = Uuid::new_v4().to_string();
    let session = SessionIdentity {
        label: format!("institutional-task-{}", &id[..12]),
        id,
    };
    let mut description = local::local_description(
        session.clone(),
        port,
        root.into(),
        CASEWORK_RESOURCE.into(),
        vec![
            client("human-client", human, Some("human"), &["casework:staff"]),
            client(
                "task-agent",
                agent,
                Some("agent"),
                &["casework:grants:assert"],
            ),
            client(
                "evidence-task-agent",
                evidence_agent,
                Some("agent"),
                &["casework:grants:assert"],
            ),
            client(
                "other-agent",
                other_agent,
                Some("agent"),
                &["casework:grants:assert"],
            ),
            client(
                "breg-status",
                status,
                Some("service"),
                &["casework:grants:status"],
            ),
        ],
    )
    .unwrap();
    let mut seed_client = client("seed-client", seed, Some("service"), &["records:get"]);
    seed_client.claims.extend([
        ("tenant_claim".into(), "tenant-a".into()),
        ("registry_purpose".into(), "maintain".into()),
    ]);
    let mut other_seed_client = client(
        "other-seed-client",
        other_seed,
        Some("service"),
        &["records:get"],
    );
    other_seed_client.claims.extend([
        ("tenant_claim".into(), "tenant-b".into()),
        ("registry_purpose".into(), "maintain".into()),
    ]);
    let target = local::local_description(
        SessionIdentity {
            label: session.label.clone(),
            id: Uuid::new_v4().to_string(),
        },
        port,
        root.into(),
        BREG_RESOURCE.into(),
        vec![seed_client, other_seed_client],
    )
    .unwrap();
    description.resource_servers.extend(target.resource_servers);
    description.roles.extend(target.roles);
    description.machine_clients.extend(target.machine_clients);
    description
        .schema_attributes
        .extend(target.schema_attributes);
    description.schema_attributes.sort();
    description.schema_attributes.dedup();
    let authority_server = description.resource_servers[0].id.clone();
    description.resource_servers.push(ResourceServer {
        id: Uuid::new_v4().to_string(),
        name: "Evidence task target".into(),
        identifier: EVIDENCE_RESOURCE.into(),
        description: "Evidence resource reached only after task exchange".into(),
        resources: vec![Resource {
            name: "Evidence".into(),
            handle: "evidence".into(),
            parent: None,
            description: "Evidence invocation".into(),
            actions: vec![Action {
                name: "Invoke".into(),
                handle: "invoke".into(),
                description: "Invoke one Evidence requirement".into(),
            }],
        }],
    });
    description.resource_servers.push(ResourceServer {
        id: Uuid::new_v4().to_string(),
        name: "Scheduling task target".into(),
        identifier: SCHEDULING_RESOURCE.into(),
        description: "Scheduling booking reached only after task exchange".into(),
        resources: vec![Resource {
            name: "Scheduling".into(),
            handle: "scheduling".into(),
            parent: None,
            description: "Scheduling commitment".into(),
            actions: vec![Action {
                name: "Commit".into(),
                handle: "commit".into(),
                description: "Commit bounded Scheduling capacity".into(),
            }],
        }],
    });
    description
        .machine_clients
        .iter_mut()
        .find(|c| c.client_id == "task-agent")
        .unwrap()
        .token_exchange = Some(TokenExchangeClient {
        assertion_resource_server_id: authority_server.clone(),
        assertion_scope: "casework:grants:assert".into(),
        ordinary_resource_permissions: Vec::new(),
    });
    let evidence_client = description
        .machine_clients
        .iter_mut()
        .find(|client| client.client_id == "evidence-task-agent")
        .unwrap();
    evidence_client.token_exchange = Some(TokenExchangeClient {
        assertion_resource_server_id: authority_server.clone(),
        assertion_scope: "casework:grants:assert".into(),
        ordinary_resource_permissions: Vec::new(),
    });
    // These static sentinels make the test prove that the exchange copied the
    // authority-signed values. A token built from registered client attributes
    // would fail the Evidence profile below.
    evidence_client.attributes.extend([
        ("evidence_tags".into(), json!(["must-not-survive"])),
        (
            "evidence_audience".into(),
            json!("https://must-not-survive.invalid"),
        ),
    ]);
    evidence_client
        .token_attributes
        .extend(["evidence_tags".into(), "evidence_audience".into()]);
    description
        .machine_clients
        .iter_mut()
        .find(|client| client.client_id == "other-agent")
        .unwrap()
        .token_exchange = Some(TokenExchangeClient {
        assertion_resource_server_id: authority_server,
        assertion_scope: "casework:grants:assert".into(),
        ordinary_resource_permissions: Vec::new(),
    });
    description
        .schema_attributes
        .extend(["evidence_tags".into(), "evidence_audience".into()]);
    description.schema_attributes.sort();
    description.schema_attributes.dedup();
    description.exchange_issuers.push(ExchangeIssuer {
        id: Uuid::new_v4().to_string(),
        name: "Casework task authority".into(),
        issuer: AUTHORITY.into(),
        jwks_endpoint: format!("http://host.docker.internal:{casework_port}/.well-known/jwks.json"),
        mapping: registry_thunderid_tooling::description::ExchangeMapping::InstitutionalGrant,
        clients: vec![],
        token_attributes: BTreeMap::new(),
    });
    std::fs::create_dir_all(root.join("secrets")).unwrap();
    for name in ["direct_auth_secret", "throwaway-bootstrap-password"] {
        let path = root.join("secrets").join(name);
        std::fs::write(&path, Uuid::new_v4().to_string()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    render::render(&description).unwrap();
    let pin = registry_thunderid_tooling::version::ThunderIdPin::load().unwrap();
    let mut issuer = Issuer {
        description,
        image: pin.image,
        jwks: Value::Null,
    };
    issuer.jwks = local::start(&issuer.session(), Path::new("docker"), &mut || false).unwrap();
    issuer
}

struct DockerNetwork {
    name: String,
    container: String,
}

impl Drop for DockerNetwork {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("docker")
            .args(["network", "rm", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[ignore = "requires Docker plus absolute BREG_OIDC_NETWORK_PROBE_BIN and a BREG_OIDC_NETWORK_PROBE_IMAGE containing its dynamic runtime"]
#[test]
fn configured_private_thunderid_is_discovered_on_an_owned_docker_network() {
    let probe = PathBuf::from(
        std::env::var_os(OIDC_NETWORK_PROBE_ENV)
            .expect("the Linux BReg OIDC runtime-config probe is required"),
    );
    assert!(probe.is_absolute() && probe.is_file());
    let probe_image = std::env::var(OIDC_NETWORK_PROBE_IMAGE_ENV)
        .expect("a pinned local image for running the Linux probe is required");
    assert!(!probe_image.trim().is_empty());

    let root = canonical_tempdir();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let issuer_key = key("private-network-client");
    let description = local::local_description(
        SessionIdentity {
            label: "casework-private-network-proof".into(),
            id: Uuid::new_v4().to_string(),
        },
        port,
        root.path().join("issuer"),
        "urn:private-network-proof".into(),
        vec![client(
            "private-network-client",
            &issuer_key,
            Some("service"),
            &["records:get"],
        )],
    )
    .unwrap();
    fs::create_dir_all(&description.state_root).unwrap();
    for name in ["direct_auth_secret", "throwaway-bootstrap-password"] {
        let path = description.state_root.join("secrets").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, Uuid::new_v4().to_string()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    render::render(&description).unwrap();
    let pin = registry_thunderid_tooling::version::ThunderIdPin::load().unwrap();
    let issuer = Issuer {
        description,
        image: pin.image,
        jwks: Value::Null,
    };
    local::start(&issuer.session(), Path::new("docker"), &mut || false).unwrap();
    local::stop(&issuer.session(), Path::new("docker")).unwrap();

    let deployment_path = issuer.description.state_root.join("deployment.yaml");
    let loopback_origin = format!("http://127.0.0.1:{port}");
    let mut deployment = fs::read_to_string(&deployment_path).unwrap();
    assert_eq!(deployment.matches(&loopback_origin).count(), 1);
    deployment = deployment.replace(&loopback_origin, "http://thunderid:8090");
    let loopback_passkey_origin = format!("\"127.0.0.1:{port}\"");
    assert_eq!(deployment.matches(&loopback_passkey_origin).count(), 1);
    deployment = deployment.replace(&loopback_passkey_origin, "\"thunderid:8090\"");
    fs::write(&deployment_path, deployment).unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let network_name = format!("registry-private-issuer-{}", &suffix[..12]);
    let container_name = format!("registry-private-issuer-{}", &suffix[12..24]);
    // Some developer daemons have consumed every automatic address-pool
    // subnet. Keep this proof independent of that ambient state by choosing
    // an explicit, test-owned RFC 1918 subnet and trying the bounded set until
    // Docker accepts a non-overlapping one.
    let subnet_seed = u8::from_str_radix(&suffix[..2], 16).unwrap();
    let network_created = (0..16).any(|attempt| {
        let third_octet = 240 + (subnet_seed.wrapping_add(attempt) % 16);
        let subnet = format!("172.30.{third_octet}.0/24");
        Command::new("docker")
            .args([
                "network",
                "create",
                "--driver",
                "bridge",
                "--subnet",
                &subnet,
                "--label",
                "registry.stack.test=private-issuer",
                &network_name,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    });
    assert!(
        network_created,
        "no owned private Docker subnet was available"
    );
    let _network = DockerNetwork {
        name: network_name.clone(),
        container: container_name.clone(),
    };
    let user = format!(
        "{}:{}",
        String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
            .unwrap()
            .trim(),
        String::from_utf8(Command::new("id").arg("-g").output().unwrap().stdout)
            .unwrap()
            .trim()
    );
    let state = &issuer.description.state_root;
    let mut run = Command::new("docker");
    run.args([
        "run",
        "-d",
        "--user",
        &user,
        "--name",
        &container_name,
        "--network",
        &network_name,
        "--network-alias",
        "thunderid",
        "--label",
        "registry.stack.test=private-issuer",
    ]);
    for (host, container) in [
        (state.join("database"), "/opt/thunderid/database"),
        (state.join("certs"), "/opt/thunderid/config/certs"),
        (state.join("secrets"), "/opt/thunderid/config/secrets"),
        (
            state.join("deployment.yaml"),
            "/opt/thunderid/deployment.yaml",
        ),
        (state.join("resources"), "/opt/thunderid/config/resources"),
    ] {
        run.args([
            "--mount",
            &format!("type=bind,src={},dst={container}", host.display()),
        ]);
    }
    assert!(run
        .arg(&issuer.image)
        .arg("./start.sh")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());

    let probe_root = root.path().join("probe");
    fs::create_dir_all(probe_root.join("secrets")).unwrap();
    fs::create_dir_all(probe_root.join("package")).unwrap();
    fs::set_permissions(
        probe_root.join("secrets"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let runtime_path = probe_root.join("runtime.json");
    fs::write(
        &runtime_path,
        serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/runtime/v1alpha1",
            "kind":"BRegRuntimeConfig",
            "listener":{"bind":"127.0.0.1:0"},
            "identity":{"environment":"test","instanceId":"private-issuer-proof","databaseId":"private-issuer-proof","databaseInitializationEnvironment":"test"},
            "secretProviders":{"file":{"root":"/probe/secrets"}},
            "database":{"runtimeUrlRef":"secret:file/runtime-database-url","migrationUrlRef":"secret:file/migration-database-url","pool":{"maximumConnections":1,"waitTimeoutMilliseconds":1000,"createTimeoutMilliseconds":1000,"recycleTimeoutMilliseconds":1000},"roles":{"migration":"registry_migration","runtime":"registry_runtime"}},
            "package":{"root":"/probe/package"},
            "authentication":{"oidc":{"issuer":"http://thunderid:8090","allowInsecureHttp":true,"audience":"urn:private-network-proof","allowedAlgorithm":"RS256","accessTokenType":"at+jwt","scopeClaim":"scope","scopeSeparator":" ","allowedClients":["private-network-client"],"maximumTokenLifetimeSeconds":3600,"leewayMilliseconds":60000,"jwksSource":{"type":"discovery"}},"authorityClaims":{"principal":"sub","purpose":"registry_purpose"}},
            "audit":{"hashKeyRef":"secret:file/audit-key","path":"/probe/audit.jsonl"},
            "cursor":{"secretRef":"secret:file/cursor-key"}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o600)).unwrap();

    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--user",
                &user,
                "--network",
                &network_name,
                "--mount",
                &format!("type=bind,src={},dst=/probe,readonly", probe_root.display()),
                "--mount",
                &format!(
                    "type=bind,src={},dst=/usr/local/bin/oidc-probe,readonly",
                    probe.display()
                ),
                "--entrypoint",
                "/usr/local/bin/oidc-probe",
                &probe_image,
                "/probe/runtime.json",
            ])
            .output()
            .unwrap();
        if output.status.success() {
            assert_eq!(output.stdout, b"allowed\n");
            assert!(output.stderr.is_empty());
            break;
        }
        let last_probe_error = String::from_utf8_lossy(&output.stderr);
        assert!(
            Command::new("docker")
                .args(["inspect", "--format", "{{.State.Running}}", &container_name])
                .output()
                .is_ok_and(|state| state.status.success() && state.stdout == b"true\n"),
            "the owned ThunderID container stopped before configured discovery"
        );
        assert!(
            Instant::now() < deadline,
            "configured discovery did not reach the owned private issuer: {last_probe_error}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}
fn provider(
    issuer: &str,
    client: &str,
    key: &registry_platform_crypto::PrivateJwk,
    resource: &str,
    scope: &str,
) -> PrivateKeyJwt {
    PrivateKeyJwt::new(
        PrivateKeyJwtConfig::new(
            format!("{issuer}/oauth2/token").parse().unwrap(),
            client,
            key.clone(),
        )
        .with_audience(issuer)
        .with_resource(resource)
        .with_scopes([scope]),
    )
    .unwrap()
}

async fn shorten_grant_deadline(fixture: &Fixture, grant_id: &str, seconds: i64) -> u64 {
    let grant_id = Uuid::parse_str(grant_id).unwrap();
    let row = fixture
        .admin
        .query_one(
            "WITH deadline AS (SELECT floor(extract(epoch FROM clock_timestamp()))::bigint+$2 AS value) \
             UPDATE casework_review_task_grants SET \
               expires_at=to_timestamp((SELECT value FROM deadline)), \
               record=jsonb_set(record,'{expiresAt}',to_jsonb((SELECT value FROM deadline))) \
             WHERE grant_id=$1 RETURNING record",
            &[&grant_id, &seconds],
        )
        .await
        .unwrap();
    row.get::<_, Value>(0)["expiresAt"].as_u64().unwrap()
}
fn bearer(token: &registry_platform_httputil::BearerToken) -> String {
    token
        .authorization_header_value()
        .to_str()
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap()
        .to_owned()
}

fn write_task_connection(
    root: &Path,
    name: &str,
    client_id: &str,
    key: &registry_platform_crypto::PrivateJwk,
    resource: &str,
    scopes: &[&str],
    casework_port: u16,
    issuer_url: &str,
) -> PathBuf {
    let key_name = format!("{name}-key.json");
    let key_file = root.join(&key_name);
    std::fs::write(
        &key_file,
        serde_json::to_vec(&private_key_value(key)).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut clients = serde_json::Map::new();
    clients.insert(
        client_id.to_owned(),
        json!({
            "assertionKeyRef": format!("secret:file/{key_name}"),
            "resource": resource,
            "scopes": scopes,
        }),
    );
    let connection_file = root.join(format!("{name}-connection.yaml"));
    std::fs::write(
        &connection_file,
        serde_json::to_vec(&json!({
            "apiVersion": registry_thunderid_tooling::task_connection::API_VERSION,
            "kind": registry_thunderid_tooling::task_connection::KIND,
            "caseworkUrl": format!("http://127.0.0.1:{casework_port}"),
            "tokenEndpoint": format!("{issuer_url}/oauth2/token"),
            "clientAssertionAudience": issuer_url,
            "bootstrapResource": CASEWORK_RESOURCE,
            "secretProviders": {"file": {"root": root}},
            "clients": clients,
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&connection_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    connection_file
}

fn acquired_bearer(header_file: &Path) -> String {
    let header = zeroize::Zeroizing::new(std::fs::read_to_string(header_file).unwrap());
    header
        .trim()
        .strip_prefix("Authorization: Bearer ")
        .unwrap()
        .to_owned()
}

fn payload(token: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

/// Cross the process boundary into Scheduling without introducing a product
/// crate dependency. The credential and public verifier material travel only
/// over stdin; the probe returns one non-sensitive verdict on stdout.
fn prove_scheduling_authentication(token: &str, issuer: &Issuer) {
    let probe = PathBuf::from(
        std::env::var_os(SCHEDULING_AUTH_PROBE_ENV)
            .expect("the absolute Scheduling authentication probe path is required"),
    );
    assert!(
        probe.is_absolute(),
        "the Scheduling probe path must be absolute"
    );
    let input = serde_json::to_vec(&json!({
        "token": token,
        "issuer": issuer.url(),
        "audience": SCHEDULING_RESOURCE,
        "client": "task-agent",
        "assertionIssuer": AUTHORITY,
        "jwks": issuer.jwks,
        "service": "registry-update",
        "location": "bangkok-counter",
        "action": "appointment.create"
    }))
    .unwrap();
    let mut child = Command::new(&probe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the Scheduling authentication probe starts");
    child
        .stdin
        .take()
        .expect("the Scheduling authentication probe has stdin")
        .write_all(&input)
        .expect("the Scheduling authentication probe reads its bounded input");
    let output = child
        .wait_with_output()
        .expect("the Scheduling authentication probe finishes");
    assert!(
        output.status.success(),
        "the exact exchanged bearer was refused by Scheduling"
    );
    assert_eq!(output.stdout, b"allowed\n");
    assert!(output.stderr.is_empty());
}
struct Fixture {
    app: Router,
    review_task: Uuid,
    admin: tokio_postgres::Client,
    schema: String,
}
async fn fixture(
    root: &Path,
    issuer: &Issuer,
    key: registry_platform_crypto::PrivateJwk,
) -> Fixture {
    let base = std::env::var("CASEWORK_ASSIGNMENT_TEST_DATABASE_URL")
        .expect("disposable Casework database required");
    let schema = format!("native_task_{}", Uuid::new_v4().simple());
    let (admin, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    admin
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let name = format!("NATIVE_TASK_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    std::env::set_var(&name, url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp").unwrap();
    let db_config = crate::DatabaseConfig {
        runtime_url_ref: format!("secret:env/{name}"),
        migration_url_ref: format!("secret:env/{name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let store = PostgresStore::connect_migration(&db_config, &secrets)
        .unwrap()
        .with_audit(crate::CaseworkAudit::capture().0);
    store.migrate().await.unwrap();
    std::env::remove_var(name);
    let human = issuer
        .description
        .machine_clients
        .iter()
        .find(|c| c.client_id == "human-client")
        .unwrap()
        .agent_id
        .clone();
    let agent = issuer
        .description
        .machine_clients
        .iter()
        .find(|c| c.client_id == "task-agent")
        .unwrap()
        .agent_id
        .clone();
    let evidence_agent = issuer
        .description
        .machine_clients
        .iter()
        .find(|c| c.client_id == "evidence-task-agent")
        .unwrap()
        .agent_id
        .clone();
    let breg: Value = serde_json::from_str(resource::PROJECT).unwrap();
    let operations = breg["accessProfiles"][1]["permissions"]["actions"][0]["operations"].clone();
    let template:TaskTemplate=serde_json::from_value(json!({"id":"draft","version":"1","label":"Prepare correction draft","eligibleTeams":["team"],"eligibleProfiles":["staff"],"source":"source","reviewPolicies":["external-review"],"agent":{"issuer":issuer.url(),"subject":agent},"client":"task-agent","resource":BREG_RESOURCE,"purpose":"review","scopes":["records:get"],"bounds":{"type":"breg","permissions":[{"collection":"sites","operations":["get"]},{"collection":"correction-requests","operations":["get"]},{"collection":"action:file-correction","operations":operations}]},"subjects":{"tenant_claim":"tenant"},"lifetimeSeconds":900})).unwrap();
    let evidence_template:TaskTemplate=serde_json::from_value(json!({"id":"evidence-check","version":"1","label":"Check adult status","eligibleTeams":["team"],"eligibleProfiles":["staff"],"source":"source","reviewPolicies":["external-review"],"agent":{"issuer":issuer.url(),"subject":evidence_agent},"client":"evidence-task-agent","resource":EVIDENCE_RESOURCE,"purpose":"fixture-eligibility","scopes":["evidence:invoke"],"bounds":{"type":"evidence","requirement":EVIDENCE_REQUIREMENT},"evidenceContext":{"requesterTags":[EVIDENCE_TAG],"audience":EVIDENCE_AUDIENCE},"subjects":{"birth_date":"birth_date","family_name":"family_name","given_name":"given_name"},"lifetimeSeconds":900})).unwrap();
    let scheduling_template:TaskTemplate=serde_json::from_value(json!({"id":"schedule-update","version":"1","label":"Book a registry update","eligibleTeams":["team"],"eligibleProfiles":["staff"],"source":"source","reviewPolicies":["external-review"],"agent":{"issuer":issuer.url(),"subject":agent},"client":"task-agent","resource":SCHEDULING_RESOURCE,"purpose":"schedule-registry-update","scopes":["scheduling:commit"],"bounds":{"type":"scheduling","permissions":[{"service":"registry-update","location":"bangkok-counter","actions":["appointment.create"]}]},"subjects":{"tenant_claim":"tenant"},"lifetimeSeconds":900})).unwrap();
    let mut context_schema = json!({
        "$id": "urn:registry:breg:review-context:source:synthetic-request:synthetic-review-context",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type":"object",
        "additionalProperties":false,
        "properties":{"tenant":{"type":"string"},"birth_date":{"type":"string"},"family_name":{"type":"string"},"given_name":{"type":"string"}},
        "x-registry-review-context": {
            "registryId": "native-task-source",
            "sourceNamespace": "source",
            "actionId": "synthetic-request",
            "contextId": "synthetic-review-context"
        }
    });
    let context_revision = ContentDigest::for_bytes(
        &registry_platform_canonical_json::canonicalize_json(&context_schema).unwrap(),
    );
    context_schema["x-registry-definition-revision"] = json!(context_revision.as_str());
    let context_schema_bytes = serde_json::to_string(&context_schema).unwrap();
    let context_contract = ReviewContextContract {
        id: context_schema["$id"].as_str().unwrap().into(),
        revision: context_revision,
        schema_digest: ContentDigest::for_bytes(context_schema_bytes.as_bytes()),
    };
    let context_export = registry_casework_breg::BregContextExport {
        api_version: registry_casework_breg::DESCRIPTION_API_VERSION.into(),
        kind: registry_casework_breg::DESCRIPTION_KIND.into(),
        source_namespace: "source".into(),
        action_id: "synthetic-request".into(),
        context_id: "synthetic-review-context".into(),
        contract: context_contract.clone(),
        schema: context_schema.clone(),
        schema_bytes: context_schema_bytes,
    };
    context_export.check().unwrap();
    let context_export_path = "context-providers/source.json";
    let mut project:CaseworkProject=serde_json::from_value(json!({"apiVersion":CASEWORK_API_VERSION,"kind":CASEWORK_KIND,"project":{"id":"native-tasks","version":"1"},"accessProfiles":{"staff":{"principalClaim":"sub","requiredScopes":["casework:staff"],"role":"staff"},"supervisor":{"principalClaim":"sub","requiredScopes":["casework:supervisor"],"role":"supervisor"},"administrator":{"principalClaim":"sub","requiredScopes":["casework:admin"],"role":"administrator"},"producer":{"principalClaim":"sub","requiredScopes":["casework:reviews:request"],"role":"requester"}},"queues":{"review":{"label":"Review"}},"teams":{"team":{"label":"Review team","serves":["review"],"memberProfiles":["staff"],"supervisorProfiles":["supervisor"]}},"contextProviders":{"source":{"deploymentRef":"source","sourceNamespace":"source","description":context_export_path,"capabilities":["human-display","service-status","task-grant-context"],"serviceProfiles":{"service-status":"status-reader","task-grant-context":"task-reader"}}},"reviewPolicies":{"external-review":{"version":"1","purpose":"approval","context":{"mode":"current-source","provider":"source","contract":context_contract},"stages":[{"id":"review","queue":"review","decidingProfiles":["staff"],"requiredApprovals":1,"excludeInitiator":true,"excludePreviousStageReviewers":false}],"retention":{"terminalRetentionDays":30,"accountabilityRetentionDays":90},"displaySchema":context_schema,"outcomes":{"approved":{"label":"Approve","settlement":"approved","reasonRequired":false,"publicReason":"optional"}}}},"trustedProducers":{"producer":{"profile":"producer","issuer":issuer.url(),"subject":"native-producer","trustedInitiatorIssuer":issuer.url(),"sourceNamespaces":["source"],"reviewPolicies":["external-review"],"retention":{"receiptRetentionDays":7}}}})).unwrap();
    project.task_templates = vec![template, evidence_template, scheduling_template];
    project.check().unwrap();

    let runtime_root = root.join("casework-runtime");
    let secret_root = runtime_root.join("secrets");
    let package_root = runtime_root.join("package");
    fs::create_dir_all(&secret_root).unwrap();
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700)).unwrap();
    write_package(
        &package_root,
        &BTreeMap::from([
            (
                crate::POLICY_FILE.to_owned(),
                serde_norway::to_string(&project).unwrap().into_bytes(),
            ),
            (
                context_export_path.to_owned(),
                serde_json::to_vec(&context_export).unwrap(),
            ),
        ]),
        None,
        &crate::package_limits(),
        crate::PACKAGE_COMMAND,
    )
    .unwrap();

    store
        .activate_task_templates(&project.task_templates)
        .await
        .unwrap();
    admin
        .execute(
            "INSERT INTO casework_teams(team_id,revision) VALUES('team',1)",
            &[],
        )
        .await
        .unwrap();
    admin.execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('team',$1,$2,'staff')",&[&issuer.url(),&human]).await.unwrap();
    admin.execute("INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('review','team',1)",&[]).await.unwrap();
    let review_request = Uuid::new_v4();
    let review_task = Uuid::new_v4();
    let snapshot = project.compile_policy("external-review").unwrap();
    admin.execute("INSERT INTO casework_review_requests(request_id,producer_id,producer_issuer,producer_subject,source_namespace,subject_source,subject_type,subject_id,subject_version,subject_digest,requester_reference,initiator_issuer,initiator_subject,context_strategy,context,policy_id,policy_version,policy_digest,policy_snapshot,submission_digest,lifecycle,active_stage_index,revision,created_at,updated_at) VALUES($1,'producer',$2,'producer','source','source','request','synthetic-request','proposal-1',$3,'native-review',$2,'initiator','current-source',$4,'external-review','1',$5,$6,$7,'reviewing',0,1,now(),now())",&[&review_request,&issuer.url(),&ContentDigest::for_bytes(b"synthetic-request").to_string(),&json!({"reference":"source:request:synthetic-request"}),&snapshot.identity.digest.to_string(),&serde_json::to_value(&snapshot).unwrap(),&ContentDigest::for_bytes(b"submission").to_string()]).await.unwrap();
    admin.execute("INSERT INTO casework_review_tasks(task_id,request_id,stage_index,stage_id,slot,queue_id,state,holder_issuer,holder_subject,assignment_kind,assignment_owner_issuer,assignment_owner_subject,revision,created_at,updated_at) VALUES($1,$2,0,'review',0,'review','claimed',$3,$4,'claim',$3,$4,1,now(),now())",&[&review_task,&review_request,&issuer.url(),&human]).await.unwrap();
    write_secret(
        &secret_root,
        "task-authority-key",
        &serde_json::to_string(&private_key_value(&key)).unwrap(),
    );
    let runtime_path = runtime_root.join("runtime.json");
    fs::write(
        &runtime_path,
        serde_json::to_vec(&json!({
            "apiVersion": crate::RUNTIME_CONFIG_API_VERSION,
            "kind": crate::RUNTIME_CONFIG_KIND,
            "identity": {"databaseId": "native-task-grant"},
            "package": {"root": package_root},
            "listener": {"bind": "127.0.0.1:0", "tlsTermination": "development-loopback", "networkExposure": "private-address"},
            "secretProviders": {"file": {"root": secret_root}},
            "database": {"runtimeUrlRef": "secret:file/runtime-url", "migrationUrlRef": "secret:file/migration-url"},
            "authentication": {"oidc": {
                "issuer": issuer.url(),
                "audience": CASEWORK_RESOURCE,
                "allowedClients": ["human-client", "task-agent", "evidence-task-agent", "breg-status"],
                "scopeClaim": "scope",
                "humanIdentity": {"claim": "registry_actor_kind", "value": "human"}
            }},
            "audit": {"path": runtime_root.join("audit.jsonl"), "hashKeyRef": "secret:file/audit-key"},
            "taskAuthority": {
                "issuer": AUTHORITY,
                "exchangeAudience": issuer.url(),
                "signingKeyRef": "secret:file/task-authority-key",
                "statusClients": {"breg-status": BREG_RESOURCE}
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o600)).unwrap();
    let runtime = crate::RuntimeConfig::load(&runtime_path).unwrap();
    let project = runtime.load_package().unwrap().project().clone();
    let secrets = crate::runtime::secret_resolver(&runtime).unwrap();
    let authority = TaskAuthority::load(
        runtime.task_authority.as_ref().unwrap(),
        &secrets,
        registry_platform_audit::AuditKeyHasher::unkeyed_dev_only(),
    )
    .unwrap();
    let service = crate::CaseworkService::new(
        store,
        project.clone(),
        [Arc::new(Source) as Arc<dyn ReviewContextProvider>],
    )
    .unwrap()
    .with_task_authority(Some(authority));
    let (verifier, keys) = runtime.oidc_verifier(&secrets).await.unwrap();
    let auth = crate::CaseworkAuthenticator::new(
        &project,
        verifier,
        keys,
        runtime.authentication.oidc.human_identity.clone(),
    );
    Fixture {
        app: crate::router(crate::HttpState {
            service,
            authenticator: Arc::new(auth),
            project: Arc::new(project),
        }),
        review_task,
        admin,
        schema,
    }
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    human: bool,
    body: Option<Value>,
    key: Option<&str>,
) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"));
    if human {
        req = req
            .header(CASEWORK_PROFILE_HEADER, "staff")
            .header(SOURCE_PROFILE_HEADER, "source-reader");
    }
    if let Some(key) = key {
        req = req
            .header(IF_MATCH_HEADER, "\"1\"")
            .header(IDEMPOTENCY_KEY_HEADER, key);
    }
    let data = if let Some(body) = body {
        req = req.header("content-type", "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(req.body(data).unwrap()).await.unwrap();
    (
        response.status(),
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap(),
    )
}

#[ignore = "requires Docker, disposable CASEWORK_ASSIGNMENT_TEST_DATABASE_URL and BREG_TEST_DATABASE_URL, and absolute SCHEDULING_AUTH_PROBE_BIN"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approved_casework_tasks_reach_evidence_breg_and_scheduling_through_stock_thunderid() {
    let root = canonical_tempdir();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let casework_port = listener.local_addr().unwrap().port();
    let (
        human_key,
        agent_key,
        evidence_agent_key,
        other_agent_key,
        status_key,
        seed_key,
        other_seed_key,
    ) = (
        key("human"),
        key("agent"),
        key("evidence-agent"),
        key("other-agent"),
        key("status"),
        key("seed"),
        key("other-seed"),
    );
    let (h, a, e, o, s, d, x) = (
        human_key.clone(),
        agent_key.clone(),
        evidence_agent_key.clone(),
        other_agent_key.clone(),
        status_key.clone(),
        seed_key.clone(),
        other_seed_key.clone(),
    );
    let path = root.path().to_path_buf();
    let issuer = tokio::task::spawn_blocking(move || {
        start_issuer(&path, casework_port, &h, &a, &e, &o, &s, &d, &x)
    })
    .await
    .unwrap();
    let f = fixture(root.path(), &issuer, key("casework-task-authority")).await;
    let serving = f.app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, serving).await.unwrap();
    });
    let human = bearer(
        &provider(
            &issuer.url(),
            "human-client",
            &human_key,
            CASEWORK_RESOURCE,
            "casework:staff",
        )
        .bearer_token()
        .await
        .unwrap(),
    );
    let base = format!("/v1/review-tasks/{}/task-grants", f.review_task);
    let (code, preview) = request(
        &f.app,
        "GET",
        &format!("/v1/review-tasks/{}/task-templates", f.review_task),
        &human,
        true,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(
        preview["templates"][0]["subjects"]["tenant_claim"],
        "tenant-a"
    );
    let evidence_preview = preview["templates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|template| template["id"] == "evidence-check")
        .unwrap();
    assert_eq!(
        evidence_preview["evidenceContext"],
        json!({"requesterTags":[EVIDENCE_TAG],"audience":EVIDENCE_AUDIENCE})
    );
    let (code, grant) = request(
        &f.app,
        "POST",
        &base,
        &human,
        true,
        Some(json!({"templateId":"draft","templateVersion":"1"})),
        Some("native-approval"),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let grant_id = grant["id"].as_str().unwrap();
    let bootstrap = bearer(
        &provider(
            &issuer.url(),
            "task-agent",
            &agent_key,
            CASEWORK_RESOURCE,
            "casework:grants:assert",
        )
        .bearer_token()
        .await
        .unwrap(),
    );
    assert!(payload(&bootstrap).get("registry_grant_id").is_none());
    let (code, issued) = request(
        &f.app,
        "POST",
        &format!("/v1/task-grants/{grant_id}/assertion"),
        &bootstrap,
        false,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let assertion_claims = payload(issued["assertion"].as_str().unwrap());
    assert!(assertion_claims.get("registry_grant_authority").is_none());
    assert!(assertion_claims
        .get("registry_grant_source_issuer")
        .is_none());
    let exchange = provider(
        &issuer.url(),
        "task-agent",
        &agent_key,
        BREG_RESOURCE,
        "records:get",
    );
    let connection_file = write_task_connection(
        root.path(),
        "breg-task",
        "task-agent",
        &agent_key,
        BREG_RESOURCE,
        &["records:get"],
        casework_port,
        &issuer.url(),
    );
    let private_output = root.path().join("product-private");
    use registry_thunderid_tooling::grant_file::acquire_to_header;
    assert!(acquire_to_header(
        &connection_file,
        &private_output,
        "unknown-client",
        grant_id
    )
    .await
    .is_err());
    assert!(acquire_to_header(
        &connection_file,
        &private_output,
        "task-agent",
        &Uuid::new_v4().to_string()
    )
    .await
    .is_err());
    let acquired = acquire_to_header(&connection_file, &private_output, "task-agent", grant_id)
        .await
        .unwrap();
    assert_eq!(
        acquired.grant_expires_at,
        grant["expiresAt"].as_u64().unwrap()
    );
    assert_eq!(
        std::fs::metadata(&acquired.header_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let token = acquired_bearer(&acquired.header_file);
    // A fresh command rerun uses the retained connection and preserves the immutable deadline.
    let acquired_again =
        acquire_to_header(&connection_file, &private_output, "task-agent", grant_id)
            .await
            .unwrap();
    assert_eq!(acquired_again.header_file, acquired.header_file);
    assert_eq!(acquired_again.grant_expires_at, acquired.grant_expires_at);
    let claims = payload(&token);
    assert_eq!(claims["registry_grant_id"], grant_id);
    assert_eq!(claims["registry_grant_source_issuer"], AUTHORITY);
    assert!(claims.get("registry_grant_authority").is_none());
    assert_eq!(claims["registry_grant_exp"], issued["grantExpiresAt"]);
    assert_eq!(claims["registry_grant_exp"], grant["expiresAt"]);
    assert_eq!(claims["identity"], json!({"tenant_claim":"tenant-a"}));
    assert_eq!(claims["registry_grant_bounds"], grant["bounds"]);
    assert_eq!(claims["scope"], "records:get");
    assert_eq!(claims["registry_purpose"], "review");
    assert_eq!(claims["registry_grant_client"], "task-agent");
    assert_eq!(claims["registry_grant_resource"], BREG_RESOURCE);
    assert!(claims["exp"].as_u64().unwrap() <= claims["iat"].as_u64().unwrap() + 300);
    let reexchanged = bearer(&exchange.exchange(&token).await.unwrap());
    let repeated = payload(&reexchanged);
    for name in [
        "registry_actor_kind",
        "registry_grant_id",
        "registry_grant_source_issuer",
        "registry_grant_client",
        "registry_grant_resource",
        "registry_grant_exp",
        "registry_grant_bounds",
        "registry_purpose",
        "identity",
        "scope",
    ] {
        assert_eq!(
            repeated[name], claims[name],
            "re-exchange must preserve {name}"
        );
    }
    let wrong_breg_token = bearer(
        &provider(
            &issuer.url(),
            "other-agent",
            &other_agent_key,
            BREG_RESOURCE,
            "records:get",
        )
        .exchange(issued["assertion"].as_str().unwrap())
        .await
        .unwrap(),
    );
    assert_eq!(
        payload(&wrong_breg_token)["registry_grant_client"],
        "task-agent"
    );
    let (code, scheduling_grant) = request(
        &f.app,
        "POST",
        &base,
        &human,
        true,
        Some(json!({"templateId":"schedule-update","templateVersion":"1"})),
        Some("native-scheduling-approval"),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let scheduling_grant_id = scheduling_grant["id"].as_str().unwrap();
    let scheduling_connection = write_task_connection(
        root.path(),
        "scheduling-task",
        "task-agent",
        &agent_key,
        SCHEDULING_RESOURCE,
        &["scheduling:commit"],
        casework_port,
        &issuer.url(),
    );
    let scheduling_output = root.path().join("scheduling-private");
    let scheduling_acquired = acquire_to_header(
        &scheduling_connection,
        &scheduling_output,
        "task-agent",
        scheduling_grant_id,
    )
    .await
    .unwrap();
    let scheduling_token = acquired_bearer(&scheduling_acquired.header_file);
    let scheduling_claims = payload(&scheduling_token);
    assert_eq!(
        scheduling_claims["registry_grant_bounds"],
        json!({"type":"scheduling","permissions":[{
            "service":"registry-update",
            "location":"bangkok-counter",
            "actions":["appointment.create"]
        }]})
    );
    assert_eq!(
        scheduling_claims["registry_grant_resource"],
        SCHEDULING_RESOURCE
    );
    assert_eq!(scheduling_claims["registry_grant_client"], "task-agent");
    assert_eq!(scheduling_claims["scope"], "scheduling:commit");
    prove_scheduling_authentication(&scheduling_token, &issuer);
    let evidence = start_evidence(root.path(), &issuer).await;
    let (code, evidence_grant) = request(
        &f.app,
        "POST",
        &base,
        &human,
        true,
        Some(json!({"templateId":"evidence-check","templateVersion":"1"})),
        Some("native-evidence-approval"),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(
        evidence_grant["evidenceContext"],
        json!({"requesterTags":[EVIDENCE_TAG],"audience":EVIDENCE_AUDIENCE})
    );
    let evidence_grant_id = evidence_grant["id"].as_str().unwrap();
    let evidence_deadline = shorten_grant_deadline(&f, evidence_grant_id, 30).await;
    let evidence_connection = write_task_connection(
        root.path(),
        "evidence-task",
        "evidence-task-agent",
        &evidence_agent_key,
        EVIDENCE_RESOURCE,
        &["evidence:invoke"],
        casework_port,
        &issuer.url(),
    );
    let evidence_output = root.path().join("evidence-private");
    let evidence_acquired = acquire_to_header(
        &evidence_connection,
        &evidence_output,
        "evidence-task-agent",
        evidence_grant_id,
    )
    .await
    .unwrap();
    let evidence_token = acquired_bearer(&evidence_acquired.header_file);

    // Acquire a second assertion explicitly for the adversarial exchange: it
    // must be the same approved grant assertion presented by another client.
    let evidence_bootstrap = bearer(
        &provider(
            &issuer.url(),
            "evidence-task-agent",
            &evidence_agent_key,
            CASEWORK_RESOURCE,
            "casework:grants:assert",
        )
        .bearer_token()
        .await
        .unwrap(),
    );
    let (code, evidence_assertion) = request(
        &f.app,
        "POST",
        &format!("/v1/task-grants/{evidence_grant_id}/assertion"),
        &evidence_bootstrap,
        false,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(evidence_assertion["grantExpiresAt"], evidence_deadline);
    let evidence_exchange = provider(
        &issuer.url(),
        "evidence-task-agent",
        &evidence_agent_key,
        EVIDENCE_RESOURCE,
        "evidence:invoke",
    );
    let wrong_evidence_token = bearer(
        &provider(
            &issuer.url(),
            "other-agent",
            &other_agent_key,
            EVIDENCE_RESOURCE,
            "evidence:invoke",
        )
        .exchange(evidence_assertion["assertion"].as_str().unwrap())
        .await
        .unwrap(),
    );
    assert_eq!(
        payload(&wrong_evidence_token)["registry_grant_client"],
        "evidence-task-agent"
    );
    let evidence_claims = payload(&evidence_token);
    assert_eq!(evidence_claims["registry_grant_id"], evidence_grant_id);
    assert_eq!(
        evidence_claims["registry_grant_bounds"],
        json!({"type":"evidence","requirement":EVIDENCE_REQUIREMENT})
    );
    assert_eq!(evidence_claims["evidence_tags"], json!([EVIDENCE_TAG]));
    assert_eq!(evidence_claims["evidence_audience"], EVIDENCE_AUDIENCE);
    assert_eq!(
        evidence_claims["identity"],
        json!({"birth_date":"2000-01-01","family_name":"Diallo","given_name":"Amina"})
    );
    let evidence_request = json!({
        "requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "requirement":EVIDENCE_REQUIREMENT,
        "purpose":"fixture-eligibility",
        "subjects":[{
            "role":"subject",
            "selector":{"profile":"person-demographics-v1"}
        }]
    });
    let evidence_response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}/v1/evidence", evidence.base_url))
        .header("authorization", format!("Bearer {evidence_token}"))
        .header("accept", "application/jose+json")
        .json(&evidence_request)
        .send()
        .await
        .unwrap();
    let evidence_status = evidence_response.status();
    let evidence_content_type = evidence_response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .cloned();
    let evidence_body = evidence_response.bytes().await.unwrap();
    assert_eq!(
        evidence_status,
        reqwest::StatusCode::OK,
        "Evidence refusal: {}",
        String::from_utf8_lossy(&evidence_body)
    );
    assert_eq!(
        evidence_content_type.as_ref().unwrap(),
        "application/jose+json"
    );
    let signed_evidence: Value = serde_json::from_slice(&evidence_body).unwrap();
    assert!(signed_evidence["protected"].is_string());
    assert!(signed_evidence["payload"].is_string());
    assert!(signed_evidence["signature"].is_string());
    let wrong_evidence_response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}/v1/evidence", evidence.base_url))
        .header("authorization", format!("Bearer {wrong_evidence_token}"))
        .header("accept", "application/jose+json")
        .json(&evidence_request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        wrong_evidence_response.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let db = resource::TestDatabase::create(8).await;
    let breg =
        resource::start_from_runtime(&db, root.path(), &issuer.url(), &status_key, casework_port)
            .await;
    let app = breg.app.clone();
    let registry = Arc::clone(&breg.registry);
    let seed = bearer(
        &provider(
            &issuer.url(),
            "seed-client",
            &seed_key,
            BREG_RESOURCE,
            "records:get",
        )
        .bearer_token()
        .await
        .unwrap(),
    );
    assert_eq!(payload(&seed)["registry_actor_kind"], "service");
    let other_seed = bearer(
        &provider(
            &issuer.url(),
            "other-seed-client",
            &other_seed_key,
            BREG_RESOURCE,
            "records:get",
        )
        .bearer_token()
        .await
        .unwrap(),
    );
    let old = resource::create(
        &app,
        "/v1/records/sites?accessProfile=steward",
        &seed,
        "old",
        json!({"tenant":"tenant-a","name":"old"}),
    )
    .await;
    let next = resource::create(
        &app,
        "/v1/records/sites?accessProfile=steward",
        &seed,
        "next",
        json!({"tenant":"tenant-a","name":"next"}),
    )
    .await;
    let adjacent = resource::create(
        &app,
        "/v1/records/sites?accessProfile=steward",
        &other_seed,
        "adjacent",
        json!({"tenant":"tenant-b","name":"adjacent"}),
    )
    .await;
    let placement = resource::create(
        &app,
        "/v1/records/placements?accessProfile=steward",
        &seed,
        "placement",
        json!({"tenant":"tenant-a","site":resource::id(&old)}),
    )
    .await;
    let permitted_read = resource::send(
        &app,
        axum::http::Method::GET,
        &format!(
            "/v1/records/sites/{}?accessProfile=submitter",
            resource::id(&old)
        ),
        &token,
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(
        permitted_read.status,
        StatusCode::OK,
        "{}",
        permitted_read.body
    );
    let adjacent_read = resource::send(
        &app,
        axum::http::Method::GET,
        &format!(
            "/v1/records/sites/{}?accessProfile=submitter",
            resource::id(&adjacent)
        ),
        &token,
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(adjacent_read.status, StatusCode::NOT_FOUND);
    let wrong_client_read = resource::send(
        &app,
        axum::http::Method::GET,
        &format!(
            "/v1/records/sites/{}?accessProfile=submitter",
            resource::id(&old)
        ),
        &wrong_breg_token,
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(wrong_client_read.status, StatusCode::UNAUTHORIZED);
    let correction = resource::send(
        &app,
        axum::http::Method::POST,
        "/v1/actions/file-correction?accessProfile=submitter",
        &token,
        Some("native-file-correction"),
        None,
        json!({"input":{"tenant":"tenant-a","placement":resource::id(&placement),"proposedSite":resource::id(&next),"reason":"Synthetic task correction"}}),
    )
    .await;
    assert_eq!(correction.status, StatusCode::OK, "{}", correction.body);
    let before = resource::counts(&db, &registry).await;
    let (code, _) = request(
        &f.app,
        "POST",
        &format!("{base}/{grant_id}/revoke"),
        &human,
        true,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let refused = resource::send(
        &app,
        axum::http::Method::POST,
        "/v1/actions/file-correction?accessProfile=submitter",
        &token,
        Some("revoked-write"),
        None,
        json!({"input":{"tenant":"tenant-a","placement":resource::id(&placement),"proposedSite":resource::id(&next),"reason":"Must not persist"}}),
    )
    .await;
    assert_eq!(refused.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(resource::counts(&db, &registry).await, before);
    let (code, _) = request(
        &f.app,
        "POST",
        &format!("/v1/task-grants/{grant_id}/assertion"),
        &bootstrap,
        false,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    let previous_header = std::fs::read(&acquired.header_file).unwrap();
    assert!(
        acquire_to_header(&connection_file, &private_output, "task-agent", grant_id)
            .await
            .is_err()
    );
    assert!(
        previous_header == std::fs::read(&acquired.header_file).unwrap(),
        "a refused grant command must not replace an existing header"
    );
    let (code, expiry_grant) = request(
        &f.app,
        "POST",
        &base,
        &human,
        true,
        Some(json!({"templateId":"draft","templateVersion":"1"})),
        Some("native-expiry-approval"),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let expiry_grant_id = expiry_grant["id"].as_str().unwrap();
    let breg_deadline = shorten_grant_deadline(&f, expiry_grant_id, 4).await;
    let (code, expiry_assertion) = request(
        &f.app,
        "POST",
        &format!("/v1/task-grants/{expiry_grant_id}/assertion"),
        &bootstrap,
        false,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(expiry_assertion["grantExpiresAt"], breg_deadline);
    let live_breg_token = bearer(
        &exchange
            .exchange(expiry_assertion["assertion"].as_str().unwrap())
            .await
            .unwrap(),
    );
    let live_read = resource::send(
        &app,
        axum::http::Method::GET,
        &format!(
            "/v1/records/sites/{}?accessProfile=submitter",
            resource::id(&old)
        ),
        &live_breg_token,
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(live_read.status, StatusCode::OK, "{}", live_read.body);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let final_deadline = breg_deadline.max(evidence_deadline);
    if final_deadline >= now {
        tokio::time::sleep(std::time::Duration::from_secs(final_deadline - now + 1)).await;
    }
    let expired_breg_token = bearer(&exchange.exchange(&live_breg_token).await.unwrap());
    let expired_breg_read = resource::send(
        &app,
        axum::http::Method::GET,
        &format!(
            "/v1/records/sites/{}?accessProfile=submitter",
            resource::id(&old)
        ),
        &expired_breg_token,
        None,
        None,
        Value::Null,
    )
    .await;
    assert_eq!(expired_breg_read.status, StatusCode::UNAUTHORIZED);
    let expired_evidence_token =
        bearer(&evidence_exchange.exchange(&evidence_token).await.unwrap());
    let expired_evidence_response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}/v1/evidence", evidence.base_url))
        .header("authorization", format!("Bearer {expired_evidence_token}"))
        .header("accept", "application/jose+json")
        .json(&evidence_request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        expired_evidence_response.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    drop(app);
    drop(breg);
    db.cleanup().await;
    server.abort();
    drop(f.app);
    f.admin
        .batch_execute(&format!("DROP SCHEMA {} CASCADE", f.schema))
        .await
        .unwrap();
    tokio::task::spawn_blocking(move || drop(issuer))
        .await
        .unwrap();
}
