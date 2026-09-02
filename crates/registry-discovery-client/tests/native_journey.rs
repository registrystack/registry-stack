// SPDX-License-Identifier: Apache-2.0
//! Complete local publication, Discovery, trust, and native-client journeys.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{SecondsFormat, TimeDelta, Utc};
use registry_discovery::{
    load_index, mapping_revision, router as discovery_router, CompiledEvidenceMapping, Directory,
    DiscoveryService, EvidenceTypeAlternative, EvidenceTypeResolveRequest, ServiceFilters,
    ServiceKind,
};
use registry_discovery_client::{
    accept_service_selection, validate_service_selection_structure, DiscoveryClient,
    DiscoveryClientConfig, EvidenceResolutionContext, EvidenceSelectionRequest,
    EvidenceTypeResolveSelectionExt, MatchedCapability, RelayCapabilityMatch,
    RelaySelectionRequest, RelayServiceQuery, ServiceSearchSelectionExt, ServiceSelection,
};
use registry_discoveryctl::{build_project_at, BuildError};
use registry_evidence::config::EvidenceConfig;
use registry_evidence_client::{
    AssuranceProfile, EvidenceClient, EvidenceClientConfig, EvidenceRequestSpec,
    EvidenceResponseFormat, ExpectedFormDocument, ExpectedOutputDocument,
    ExpectedScalarFormDocument, JwksDocument, SelectorValue, StaticToken as EvidenceToken,
    SubjectExpectations, SubjectRequest,
};
use registry_evidence_verifier::{
    EVIDENCE_JWS_CTY, EVIDENCE_JWS_MEDIA_TYPE, EVIDENCE_JWS_TYP, EVIDENCE_SCHEMA_V1,
};
use registry_platform_crypto::{sign, PrivateJwk};
use registry_platform_sqlite::materialize_fixture;
use registry_relay_client::{
    Conditional, ListRequest, RecordCollectionResponse, RelayClient, RelayClientConfig,
    StaticToken as RelayToken,
};
use registry_relay_v2::package::load_package;
use registry_relay_v2::tooling::{package_project, PackageOptions};
use serde_json::{json, Value};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;

const REQUIREMENT: &str = "urn:example:fixture:requirement:adult-status:v1";
const EVIDENCE_TYPE: &str = "urn:example:fixture:evidence-type:adult-status:v1";
const EVIDENCE_TYPE_LIST: &str = "urn:example:journey:list:adult-status";
const MAPPING: &str = "urn:example:journey:mapping:adult-status";
const MAPPING_AUTHORITY: &str = "urn:example:journey:mapping-authority";
const EVIDENCE_SERVICE: &str = "urn:example:fixture:service:evidence";
const UNTRUSTED_EVIDENCE_SERVICE: &str = "urn:example:fixture:service:untrusted";
const ISSUER: &str = "urn:example:fixture:issuer:authority";
const PROVIDER: &str = "urn:example:fixture:provider:evidence";
const JURISDICTION: &str = "urn:example:jurisdiction:acceptance";
const AUDIENCE: &str = "urn:example:journey:audience";
const PURPOSE: &str = "fixture-eligibility";
const CONCEPT: &str = "urn:example:fixture:concept:adult-status";
const RELAY_SERVICE: &str = "urn:example:registry:registered-businesses";
const RELAY_AUTHORITY: &str = "urn:example:institution:company-registrar";
const RELAY_SEMANTIC_CLASS: &str = "https://business.example.invalid/vocabulary/RegisteredBusiness";
const EVIDENCE_PROFILE: &str = "https://registrystack.org/evidence/profile/v1";
const EVIDENCE_SIGNED_JWS_PROFILE: &str =
    "https://registrystack.org/evidence/profile/v1/audience-scoped/signed-jws";
const REGISTRY_RECORD_PROFILE: &str = "https://id.registrystack.org/profiles/registry-record/v1";
const RELAY_PROFILE: &str = "https://registrystack.org/relay/profile/v3";
const RELAY_LIST_FAMILY: &str =
    "https://registrystack.org/discovery/operation-family/relay-v2/consultation-list";
const CONFIGURATION_REVISION: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const TEST_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256"}"#;

#[derive(Clone)]
struct ProviderState {
    signing_key: PrivateJwk,
    key_id: String,
    evidence_description: Arc<Vec<u8>>,
    untrusted_description: Arc<Vec<u8>>,
    relay_description: Arc<Vec<u8>>,
    invalid_description: Arc<Vec<u8>>,
    origin_requests: Arc<AtomicUsize>,
    evidence_requests: Arc<AtomicUsize>,
    relay_requests: Arc<AtomicUsize>,
    untrusted_native_requests: Arc<AtomicUsize>,
}

struct ProviderDeployment {
    base_url: String,
    trusted_jwks: JwksDocument,
    evidence_binding: PublishedBinding,
    untrusted_binding: PublishedBinding,
    relay_binding: PublishedBinding,
    origin_requests: Arc<AtomicUsize>,
    evidence_requests: Arc<AtomicUsize>,
    relay_requests: Arc<AtomicUsize>,
    untrusted_native_requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublishedBinding {
    binding_id: String,
    service_id: String,
    service_kind: ServiceKind,
    endpoint_url: String,
    conforms_to: Vec<String>,
    evidence_type_ids: Vec<String>,
    semantic_class_ids: Vec<String>,
    operation_family_ids: Vec<String>,
}

impl PublishedBinding {
    fn from_description(
        bytes: &[u8],
        service_kind: ServiceKind,
        matches: impl Fn(&registry_discovery_profile::ServiceDescription) -> bool,
    ) -> Self {
        let description = registry_discovery_profile::parse_description(bytes)
            .expect("the product-generated description satisfies the shared profile");
        let mut candidates = description
            .services()
            .iter()
            .filter(|service| matches(service));
        let service = candidates
            .next()
            .expect("the product publishes the required exact capability binding");
        assert!(
            candidates.next().is_none(),
            "one exact capability tuple identifies one provider binding"
        );
        Self {
            binding_id: service.binding_id().to_owned(),
            service_id: service.service_id().to_owned(),
            service_kind,
            endpoint_url: service.endpoint_url().to_owned(),
            conforms_to: service.conforms_to().to_vec(),
            evidence_type_ids: service.evidence_type_ids().to_vec(),
            semantic_class_ids: service.semantic_class_ids().to_vec(),
            operation_family_ids: service.operation_family_ids().to_vec(),
        }
    }

    fn assert_exact_record(&self, record: &registry_discovery::ServiceRecord) {
        assert_eq!(record.binding_id, self.binding_id);
        assert_eq!(record.service_id, self.service_id);
        assert_eq!(record.service_kind, self.service_kind);
        assert_eq!(record.endpoint_url, self.endpoint_url);
        assert_eq!(record.conforms_to, self.conforms_to);
        assert_eq!(record.evidence_type_ids, self.evidence_type_ids);
        assert_eq!(record.semantic_class_ids, self.semantic_class_ids);
        assert_eq!(record.operation_family_ids, self.operation_family_ids);
    }
}

struct DiscoveryDeployment {
    base_url: Url,
    task: JoinHandle<()>,
}

#[derive(Clone)]
struct NativeTrust {
    service_kind: ServiceKind,
    service_id: &'static str,
    endpoint_url: String,
    authority_id: &'static str,
    conforms_to: Vec<String>,
    evidence_type_ids: Vec<String>,
    semantic_class_ids: Vec<String>,
    operation_family_ids: Vec<String>,
    matched_capability: MatchedCapability,
    evidence_resolution: Option<EvidenceResolutionContext>,
    relay_capability_match: Option<RelayCapabilityMatch>,
}

impl NativeTrust {
    fn accepts(&self, selection: &ServiceSelection) -> bool {
        let authority_matches = match self.service_kind {
            ServiceKind::Evidence => {
                selection.legal_issuer_id.as_deref() == Some(self.authority_id)
            }
            ServiceKind::Relay => {
                selection.registry_authority_id.as_deref() == Some(self.authority_id)
            }
        };
        selection.service_kind == self.service_kind
            && selection.service_id == self.service_id
            && selection.endpoint_url == self.endpoint_url
            && authority_matches
            && selection.conforms_to == self.conforms_to
            && selection.evidence_type_ids == self.evidence_type_ids
            && selection.semantic_class_ids == self.semantic_class_ids
            && selection.operation_family_ids == self.operation_family_ids
            && selection.matched_capability == self.matched_capability
            && selection.evidence_resolution == self.evidence_resolution
            && selection.relay_capability_match == self.relay_capability_match
    }
}

fn expected_evidence_resolution() -> EvidenceResolutionContext {
    let mapping = CompiledEvidenceMapping {
        mapping_id: MAPPING.into(),
        mapping_authority_id: MAPPING_AUTHORITY.into(),
        requirement_id: REQUIREMENT.into(),
        jurisdiction: Some(JURISDICTION.into()),
        alternatives: vec![EvidenceTypeAlternative {
            evidence_type_list_id: EVIDENCE_TYPE_LIST.into(),
            evidence_type_ids: vec![EVIDENCE_TYPE.into()],
        }],
    };
    EvidenceResolutionContext {
        requirement_id: REQUIREMENT.into(),
        jurisdiction: Some(JURISDICTION.into()),
        mapping_revision: mapping_revision(&[mapping])
            .expect("the local mapping revision computes"),
        evidence_type_list_id: EVIDENCE_TYPE_LIST.into(),
        evidence_type_ids: vec![EVIDENCE_TYPE.into()],
        mapping_id: MAPPING.into(),
        mapping_authority_id: MAPPING_AUTHORITY.into(),
    }
}

#[derive(Default)]
struct CredentialFactory {
    constructions: AtomicUsize,
}

impl CredentialFactory {
    fn evidence(&self) -> Arc<EvidenceToken> {
        self.constructions.fetch_add(1, Ordering::SeqCst);
        Arc::new(
            EvidenceToken::new("synthetic-evidence-token")
                .expect("the local Evidence credential is usable"),
        )
    }

    fn relay(&self) -> Arc<RelayToken> {
        self.constructions.fetch_add(1, Ordering::SeqCst);
        Arc::new(
            RelayToken::new("synthetic-relay-token").expect("the local Relay credential is usable"),
        )
    }

    fn count(&self) -> usize {
        self.constructions.load(Ordering::SeqCst)
    }
}

async fn provider(State(state): State<ProviderState>, request: Request<Body>) -> Response<Body> {
    match request.uri().path() {
        "/origins/evidence.jsonld" => catalog_response(&state, &state.evidence_description),
        "/origins/untrusted.jsonld" => catalog_response(&state, &state.untrusted_description),
        "/origins/relay.jsonld" => catalog_response(&state, &state.relay_description),
        "/origins/invalid.jsonld" => catalog_response(&state, &state.invalid_description),
        "/evidence/v1/evidence" => evidence_response(state, request).await,
        "/relay/v2/resources/registered-business/records" => relay_response(state, request),
        path if path.starts_with("/untrusted-evidence/") => {
            state
                .untrusted_native_requests
                .fetch_add(1, Ordering::SeqCst);
            response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                b"unexpected",
            )
        }
        _ => response(StatusCode::NOT_FOUND, "text/plain", b"not found"),
    }
}

fn catalog_response(state: &ProviderState, bytes: &[u8]) -> Response<Body> {
    state.origin_requests.fetch_add(1, Ordering::SeqCst);
    response(
        StatusCode::OK,
        registry_discovery_profile::MEDIA_TYPE,
        bytes,
    )
}

async fn evidence_response(state: ProviderState, request: Request<Body>) -> Response<Body> {
    state.evidence_requests.fetch_add(1, Ordering::SeqCst);
    assert_eq!(
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer synthetic-evidence-token")
    );
    let bytes = to_bytes(request.into_body(), 64 * 1024)
        .await
        .expect("the local Evidence request is bounded");
    let request: Value = serde_json::from_slice(&bytes).expect("the maintained client sends JSON");
    let nonce = request["requestNonce"]
        .as_str()
        .expect("the maintained client sends its request nonce");
    let now = Utc::now();
    let payload = json!({
        "schema": EVIDENCE_SCHEMA_V1,
        "assuranceProfile": "local",
        "subjectBinding": "audience-scoped",
        "requestNonce": nonce,
        "id": "urn:example:journey:evidence:00000000-0000-4000-8000-000000000001",
        "type": "Evidence",
        "supportsRequirement": REQUIREMENT,
        "isConformantTo": EVIDENCE_TYPE,
        "issuedBy": ISSUER,
        "providedBy": PROVIDER,
        "issuedAt": timestamp(now),
        "observedAt": timestamp(now - TimeDelta::seconds(30)),
        "validUntil": timestamp(now + TimeDelta::seconds(300)),
        "purpose": PURPOSE,
        "audience": AUDIENCE,
        "configurationRevision": CONFIGURATION_REVISION,
        "subjects": [{
            "role": "subject",
            "binding": "urn:evidence:subject:v1_QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU"
        }],
        "supportedValues": [{"providesValueFor": CONCEPT, "value": true}],
    });
    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "ES256",
            "kid": state.key_id,
            "typ": EVIDENCE_JWS_TYP,
            "cty": EVIDENCE_JWS_CTY,
        }))
        .expect("the protected header serializes"),
    );
    let payload = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).expect("the local Evidence payload serializes"));
    let signing_input = [protected.as_bytes(), b".", payload.as_bytes()].concat();
    let signature =
        sign(&signing_input, &state.signing_key).expect("the deterministic local key signs");
    let body = serde_json::to_vec(&json!({
        "protected": protected,
        "payload": payload,
        "signature": URL_SAFE_NO_PAD.encode(signature),
    }))
    .expect("the flattened JWS serializes");
    response(StatusCode::OK, EVIDENCE_JWS_MEDIA_TYPE, &body)
}

fn relay_response(state: ProviderState, request: Request<Body>) -> Response<Body> {
    state.relay_requests.fetch_add(1, Ordering::SeqCst);
    assert_eq!(
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer synthetic-relay-token")
    );
    let body = serde_json::to_vec(&json!({
        "items": [{
            "recordIdentifier": "BIZ-SYNTH-0001",
            "revisionIdentifier": "revision-1",
            "lifecycleState": "active",
            "schemaReference": "https://business.example.invalid/schemas/registered-business",
            "semanticModelReference": RELAY_SEMANTIC_CLASS,
            "authorityIdentifier": RELAY_AUTHORITY,
            "recordedAt": "2026-08-14T00:00:00Z",
            "domainData": {"registeredName": "Example Company"}
        }],
        "pageInfo": {"nextCursor": null},
        "meta": {
            "registryIdentifier": "urn:example:registry:registered-businesses",
            "datasetIdentifier": "legal-entities",
            "entityTypeIdentifier": "company",
            "operationIdentifier": "registered-business-list",
            "accessProfile": "public",
            "family": "consultation",
            "pattern": "list",
            "disclosureProfile": "registered-business-public",
            "contractRevision": format!("sha256:{}", "1".repeat(64)),
            "sourceRevision": {
                "profile": "snapshot",
                "status": "versioned",
                "value": format!("sha256:{}", "2".repeat(64))
            },
            "selectedFields": ["registeredName"],
            "links": {
                "self": "/v2/resources/registered-business/records",
                "context": "/v2/artifacts/context",
                "schema": "/v2/artifacts/schema",
                "semanticModel": "/v2/artifacts/semantic-model"
            }
        }
    }))
    .expect("the local Relay collection serializes");
    response(StatusCode::OK, "application/json", &body)
}

fn response(status: StatusCode, media_type: &str, body: &[u8]) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, media_type)
        .header("traceparent", TRACEPARENT)
        .body(Body::from(body.to_vec()))
        .expect("the local response builds")
}

fn timestamp(instant: chrono::DateTime<Utc>) -> String {
    instant.to_rfc3339_opts(SecondsFormat::Secs, true)
}

async fn start_provider() -> ProviderDeployment {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the provider listener binds");
    let address = listener
        .local_addr()
        .expect("the provider listener has an address");
    let base_url = format!("http://{address}");

    let evidence_bytes = evidence_description(&base_url, false);
    let untrusted_evidence_bytes = evidence_description(&base_url, true);
    let relay_bytes = relay_description(&base_url);
    let evidence_binding =
        PublishedBinding::from_description(&evidence_bytes, ServiceKind::Evidence, |service| {
            service.evidence_type_ids() == [EVIDENCE_TYPE]
                && service.conforms_to() == [EVIDENCE_PROFILE, EVIDENCE_SIGNED_JWS_PROFILE]
        });
    let untrusted_binding = PublishedBinding::from_description(
        &untrusted_evidence_bytes,
        ServiceKind::Evidence,
        |service| {
            service.evidence_type_ids() == [EVIDENCE_TYPE]
                && service.conforms_to() == [EVIDENCE_PROFILE, EVIDENCE_SIGNED_JWS_PROFILE]
        },
    );
    let relay_binding =
        PublishedBinding::from_description(&relay_bytes, ServiceKind::Relay, |service| {
            service.semantic_class_ids() == [RELAY_SEMANTIC_CLASS]
                && service.operation_family_ids() == [RELAY_LIST_FAMILY]
        });
    assert_ne!(evidence_binding.binding_id, untrusted_binding.binding_id);
    let mut invalid: Value = serde_json::from_slice(&evidence_bytes)
        .expect("the generated Evidence description is JSON");
    invalid["@context"] = json!("https://attacker.invalid/context");
    let invalid_description = serde_json::to_vec(&invalid).expect("the invalid fixture serializes");

    let mut signing_key =
        PrivateJwk::parse(TEST_PRIVATE_JWK).expect("the deterministic test key parses");
    let key_id = signing_key
        .public()
        .jkt()
        .expect("the deterministic key has a thumbprint");
    signing_key.kid = Some(key_id.clone());
    let trusted_jwks = JwksDocument {
        keys: vec![serde_json::to_value(signing_key.public())
            .expect("the public verification key serializes")],
    };
    let origin_requests = Arc::new(AtomicUsize::new(0));
    let evidence_requests = Arc::new(AtomicUsize::new(0));
    let relay_requests = Arc::new(AtomicUsize::new(0));
    let untrusted_native_requests = Arc::new(AtomicUsize::new(0));
    let state = ProviderState {
        signing_key,
        key_id,
        evidence_description: Arc::new(evidence_bytes),
        untrusted_description: Arc::new(untrusted_evidence_bytes),
        relay_description: Arc::new(relay_bytes),
        invalid_description: Arc::new(invalid_description),
        origin_requests: origin_requests.clone(),
        evidence_requests: evidence_requests.clone(),
        relay_requests: relay_requests.clone(),
        untrusted_native_requests: untrusted_native_requests.clone(),
    };
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(provider)).with_state(state),
        )
        .await
        .expect("the provider server runs");
    });
    ProviderDeployment {
        base_url,
        trusted_jwks,
        evidence_binding,
        untrusted_binding,
        relay_binding,
        origin_requests,
        evidence_requests,
        relay_requests,
        untrusted_native_requests,
        task,
    }
}

fn evidence_description(provider_base: &str, untrusted: bool) -> Vec<u8> {
    let mut config = EvidenceConfig::parse_yaml(include_bytes!(
        "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
    ))
    .expect("the maintained Evidence acceptance configuration parses");
    config.assurance_profile = AssuranceProfile::Local;
    let publication = config
        .publication
        .as_mut()
        .expect("the maintained fixture publishes Discovery metadata");
    if untrusted {
        publication.service_id = UNTRUSTED_EVIDENCE_SERVICE.into();
        publication.endpoint_url = format!("{provider_base}/untrusted-evidence/");
    } else {
        publication.endpoint_url = format!("{provider_base}/evidence/");
    }
    config
        .validate()
        .expect("the local publication variant remains a valid Evidence configuration");
    registry_evidence::discovery::render(&config)
        .expect("Evidence publication generation succeeds")
        .expect("the configured Evidence description is generated")
}

fn relay_description(provider_base: &str) -> Vec<u8> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/relay-v2/acceptance/business-registry");
    let project = TempDir::new().expect("the Relay publication project creates");
    copy_tree(&source, project.path());
    let registry_path = project.path().join("registry.yaml");
    let registry = fs::read_to_string(&registry_path).expect("the Relay contract reads");
    let local_base = format!("{provider_base}/relay/");
    let registry = registry.replace("https://business.example.invalid/registry/", &local_base);
    fs::write(&registry_path, registry).expect("the local Relay base URI writes");
    materialize_fixture(
        &project.path().join("fixture.sqlite"),
        &fs::read_to_string(project.path().join("fixture.sql"))
            .expect("the Relay fixture SQL reads"),
    )
    .expect("the maintained Relay fixture materializes");
    let database = project.path().join("fixture.sqlite");
    let mut permissions = fs::metadata(&database)
        .expect("the Relay fixture has metadata")
        .permissions();
    permissions.set_mode(0o444);
    fs::set_permissions(&database, permissions).expect("the Relay fixture becomes read-only");

    let package = project.path().join("package-output");
    let report = package_project(&PackageOptions {
        project_root: project.path().to_path_buf(),
        output_dir: package.clone(),
    })
    .expect("the maintained Relay package operation runs");
    assert!(report.is_success(), "Relay packaging refused: {report:?}");
    let verified = load_package(
        &package
            .canonicalize()
            .expect("the temporary Relay package path resolves without symlink traversal"),
    )
    .expect("the Relay package verifies before publication");
    let generated = verified
        .artifacts
        .get("artifacts/discovery.jsonld")
        .expect("the Relay package contains its public Discovery artifact");
    let packaged = fs::read(package.join("generated/artifacts/discovery.jsonld"))
        .expect("the exact packaged Relay description reads");
    assert_eq!(packaged, generated.content);
    let parsed = registry_discovery_profile::parse_description(&packaged)
        .expect("the packaged Relay description satisfies the shared profile");
    assert!(parsed
        .services()
        .iter()
        .all(|service| service.service_id() == RELAY_SERVICE));
    assert!(parsed.services().iter().any(|service| {
        service.semantic_class_ids() == [RELAY_SEMANTIC_CLASS]
            && service.operation_family_ids() == [RELAY_LIST_FAMILY]
    }));
    packaged
}

fn copy_tree(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).expect("the maintained Relay project reads") {
        let entry = entry.expect("the maintained Relay project entry reads");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().expect("the Relay entry has a file type");
        if file_type.is_dir() {
            fs::create_dir(&destination_path).expect("the copied Relay directory creates");
            copy_tree(&source_path, &destination_path);
        } else {
            assert!(
                file_type.is_file(),
                "Relay acceptance inputs contain only files"
            );
            fs::copy(&source_path, &destination_path).expect("the Relay fixture file copies");
        }
    }
}

fn write_authoring_project(root: &Path, provider: &ProviderDeployment, invalid: bool) {
    let invalid_origin = if invalid {
        format!(
            "  - originId: invalid-origin\n    catalogUrl: {}/origins/invalid.jsonld\n    profile: registry-discovery-v1alpha1\n    enabled: true\n",
            provider.base_url
        )
    } else {
        String::new()
    };
    fs::write(
        root.join("origins.yaml"),
        format!(
            "schemaVersion: registry-discovery/origins/v1alpha1\norigins:\n  - originId: evidence-origin\n    catalogUrl: {base}/origins/evidence.jsonld\n    profile: registry-discovery-v1alpha1\n    enabled: true\n  - originId: untrusted-origin\n    catalogUrl: {base}/origins/untrusted.jsonld\n    profile: registry-discovery-v1alpha1\n    enabled: true\n  - originId: relay-origin\n    catalogUrl: {base}/origins/relay.jsonld\n    profile: registry-discovery-v1alpha1\n    enabled: true\n{invalid_origin}",
            base = provider.base_url,
        ),
    )
    .expect("approved origins write");
    let mappings = root.join("mappings");
    if !mappings.exists() {
        fs::create_dir(&mappings).expect("the Discovery mapping directory creates");
    }
    fs::write(
        mappings.join("adult-status.yaml"),
        format!(
            "schemaVersion: registry-discovery/evidence-mapping/v1alpha1\nmappingId: urn:example:journey:mapping:adult-status\nmappingAuthorityId: urn:example:journey:mapping-authority\nrequirementId: {REQUIREMENT}\njurisdiction: {JURISDICTION}\nalternatives:\n  - evidenceTypeListId: urn:example:journey:list:adult-status\n    evidenceTypeIds:\n      - {EVIDENCE_TYPE}\n"
        ),
    )
    .expect("the Discovery mapping writes");
}

async fn start_discovery(index_path: &Path) -> DiscoveryDeployment {
    let index = load_index(index_path).expect("the built immutable index activates");
    let directory = Directory::new(index, 100, 100).expect("the bounded directory builds");
    let service = Arc::new(
        DiscoveryService::new(directory, 1024 * 1024)
            .expect("the Discovery response limit is valid"),
    );
    let app = discovery_router(service, 64 * 1024, Duration::from_secs(5))
        .expect("the real Discovery router builds");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the Discovery listener binds");
    let address = listener
        .local_addr()
        .expect("the Discovery listener has an address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the Discovery server runs");
    });
    DiscoveryDeployment {
        base_url: Url::parse(&format!("http://{address}")).expect("the Discovery URL parses"),
        task,
    }
}

fn evidence_client_if_trusted(
    trust: &NativeTrust,
    selection: &ServiceSelection,
    credentials: &CredentialFactory,
    trusted_jwks: JwksDocument,
) -> Option<EvidenceClient> {
    let accepted =
        accept_service_selection(selection, |candidate| trust.accepts(candidate)).ok()?;
    let token = credentials.evidence();
    let config =
        EvidenceClientConfig::new(accepted.base_url().clone(), token, trusted_jwks, Vec::new());
    Some(EvidenceClient::new(config).expect("the trusted Evidence client builds"))
}

fn relay_client_if_trusted(
    trust: &NativeTrust,
    selection: &ServiceSelection,
    credentials: &CredentialFactory,
) -> Option<RelayClient> {
    let accepted =
        accept_service_selection(selection, |candidate| trust.accepts(candidate)).ok()?;
    let token = credentials.relay();
    let config = RelayClientConfig::new(accepted.base_url().clone()).with_token_provider(token);
    Some(RelayClient::new(config).expect("the trusted Relay client builds"))
}

fn evidence_spec(selection: &ServiceSelection) -> EvidenceRequestSpec {
    let resolution = selection
        .evidence_resolution
        .as_ref()
        .expect("the selected Evidence service retains its complete resolution");
    let MatchedCapability::EvidenceType(evidence_type) = &selection.matched_capability else {
        panic!("the Evidence selection retains its matched Evidence Type");
    };
    EvidenceRequestSpec {
        response_format: EvidenceResponseFormat::SignedJws,
        requirement: resolution.requirement_id.clone(),
        purpose: PURPOSE.into(),
        audience: AUDIENCE.into(),
        evidence_type: evidence_type.clone(),
        issued_by: ISSUER.into(),
        provided_by: PROVIDER.into(),
        configuration_revision: CONFIGURATION_REVISION.into(),
        expected_assurance_profile: AssuranceProfile::Local,
        subjects: vec![SubjectRequest {
            role: "subject".into(),
            selector_profile: "person-demographics-v1".into(),
            selector_values: Some(vec![(
                "person_reference".into(),
                SelectorValue::from("synthetic-record-001"),
            )]),
        }],
        holder_keys: Vec::new(),
        expected_outputs: vec![ExpectedOutputDocument {
            handle: "adult-status".into(),
            concept: CONCEPT.into(),
            required: true,
            form: ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean),
        }],
        maximum_assertion_lifetime_seconds: 300,
        clock_skew_seconds: 60,
        subject_expectations: SubjectExpectations::AcceptFirstUse,
    }
}

#[tokio::test]
async fn complete_evidence_and_relay_journeys_build_select_trust_and_invoke_natively() {
    let provider = start_provider().await;
    let project = TempDir::new().expect("the Discovery authoring project creates");
    write_authoring_project(project.path(), &provider, false);
    let index_path = project.path().join("discovery-index.json");
    build_project_at(
        project.path(),
        &index_path,
        true,
        OffsetDateTime::UNIX_EPOCH,
    )
    .await
    .expect("discoveryctl builds every approved local origin");
    assert_eq!(provider.origin_requests.load(Ordering::SeqCst), 3);

    let valid_index = fs::read(&index_path).expect("the valid immutable index reads");
    write_authoring_project(project.path(), &provider, true);
    let invalid = build_project_at(
        project.path(),
        &index_path,
        true,
        OffsetDateTime::UNIX_EPOCH,
    )
    .await;
    assert!(matches!(invalid, Err(BuildError::Description)));
    assert_eq!(
        fs::read(&index_path).expect("the prior index remains visible"),
        valid_index,
        "one invalid approved origin must leave the complete prior index byte-identical"
    );

    let discovery = start_discovery(&index_path).await;
    let client = DiscoveryClient::new(
        DiscoveryClientConfig::new(discovery.base_url.clone())
            .with_connect_timeout(Duration::from_secs(1))
            .with_request_timeout(Duration::from_secs(1)),
    )
    .expect("the bounded local Discovery client builds");
    let resolved = client
        .resolve_evidence_types(EvidenceTypeResolveRequest {
            requirement_id: REQUIREMENT.into(),
            jurisdiction: Some(JURISDICTION.into()),
        })
        .await
        .expect("the real Discovery router resolves the exact requirement");
    assert_eq!(resolved.alternatives.len(), 1);
    assert_eq!(resolved.alternatives[0].evidence_type_ids, [EVIDENCE_TYPE]);
    let evidence_resolution = resolved
        .select_only_alternative()
        .expect("the one complete Evidence Type alternative is explicit");
    assert_eq!(evidence_resolution, expected_evidence_resolution());
    assert_eq!(
        evidence_resolution.evidence_type_list_id,
        EVIDENCE_TYPE_LIST
    );
    assert_eq!(evidence_resolution.mapping_id, MAPPING);
    assert_eq!(evidence_resolution.mapping_authority_id, MAPPING_AUTHORITY);

    let evidence_search = client
        .search_evidence_services(
            evidence_resolution
                .service_query_for(EVIDENCE_TYPE)
                .expect("the required Evidence Type creates one exact search"),
        )
        .await
        .expect("the real Discovery router searches the resolved Evidence Type");
    assert!(
        evidence_search.items.len() > 2,
        "multiple format and origin bindings require an exact record choice"
    );
    let trusted_evidence_record = evidence_search
        .items
        .iter()
        .find(|record| record.binding_id == provider.evidence_binding.binding_id)
        .expect("the maintained Evidence publication is indexed");
    provider
        .evidence_binding
        .assert_exact_record(trusted_evidence_record);
    let untrusted_evidence_record = evidence_search
        .items
        .iter()
        .find(|record| record.binding_id == provider.untrusted_binding.binding_id)
        .expect("the explicitly untrusted advertisement is indexed separately");
    provider
        .untrusted_binding
        .assert_exact_record(untrusted_evidence_record);
    let evidence_selection = evidence_search
        .select_evidence(
            EvidenceSelectionRequest::new(trusted_evidence_record.record_id.clone(), EVIDENCE_TYPE)
                .with_resolution(evidence_resolution.clone()),
        )
        .expect("the relying application selects one exact Evidence record");
    let untrusted_selection = evidence_search
        .select_evidence(
            EvidenceSelectionRequest::new(
                untrusted_evidence_record.record_id.clone(),
                EVIDENCE_TYPE,
            )
            .with_resolution(evidence_resolution),
        )
        .expect("the untrusted advertisement can still be selected as inert public data");

    let relay_search = client
        .search_relay_services(
            RelayServiceQuery::for_semantic_class(RELAY_SEMANTIC_CLASS)
                .with_operation_family(RELAY_LIST_FAMILY)
                .with_jurisdiction(JURISDICTION),
        )
        .await
        .expect("the real Discovery router searches the exact Relay semantic class");
    assert_eq!(relay_search.items.len(), 1);
    let [relay_record] = relay_search.items.as_slice() else {
        panic!("the exact Relay tuple has one unambiguous result");
    };
    assert_eq!(relay_record.service_id, RELAY_SERVICE);
    provider.relay_binding.assert_exact_record(relay_record);
    let relay_selection = relay_search
        .select_relay(RelaySelectionRequest::new(
            relay_record.record_id.clone(),
            RelayCapabilityMatch::for_semantic_class(RELAY_SEMANTIC_CLASS)
                .with_operation_family(RELAY_LIST_FAMILY),
        ))
        .expect("the relying application selects the exact Relay record");

    let saved = serde_json::to_vec(&(evidence_selection, relay_selection))
        .expect("the inert selections persist");
    discovery.task.abort();
    let _ = discovery.task.await;
    assert!(
        client
            .search_services(ServiceFilters::default())
            .await
            .is_err(),
        "Discovery is unavailable before saved selections drive native clients"
    );
    let (evidence_selection, relay_selection): (
        registry_discovery_client::EvidenceServiceSelection,
        registry_discovery_client::RelayServiceSelection,
    ) = serde_json::from_slice(&saved).expect("saved selections reload without Discovery");
    let evidence_selection = evidence_selection.into_selection();
    let relay_selection = relay_selection.into_selection();
    validate_service_selection_structure(&evidence_selection)
        .expect("the persisted Evidence selection revalidates structurally before trust");
    validate_service_selection_structure(&relay_selection)
        .expect("the persisted Relay selection revalidates structurally before trust");
    assert_eq!(
        evidence_selection.binding_id,
        provider.evidence_binding.binding_id
    );
    assert_eq!(
        relay_selection.binding_id,
        provider.relay_binding.binding_id
    );

    let evidence_trust = NativeTrust {
        service_kind: ServiceKind::Evidence,
        service_id: EVIDENCE_SERVICE,
        endpoint_url: format!("{}/evidence/", provider.base_url),
        authority_id: ISSUER,
        conforms_to: vec![EVIDENCE_PROFILE.into(), EVIDENCE_SIGNED_JWS_PROFILE.into()],
        evidence_type_ids: vec![EVIDENCE_TYPE.into()],
        semantic_class_ids: Vec::new(),
        operation_family_ids: Vec::new(),
        matched_capability: MatchedCapability::EvidenceType(EVIDENCE_TYPE.into()),
        evidence_resolution: Some(expected_evidence_resolution()),
        relay_capability_match: None,
    };
    let rejected_credentials = CredentialFactory::default();
    assert!(evidence_client_if_trusted(
        &evidence_trust,
        untrusted_selection.selection(),
        &rejected_credentials,
        provider.trusted_jwks.clone(),
    )
    .is_none());
    assert_eq!(rejected_credentials.count(), 0);
    assert_eq!(provider.evidence_requests.load(Ordering::SeqCst), 0);
    assert_eq!(provider.relay_requests.load(Ordering::SeqCst), 0);
    assert_eq!(provider.untrusted_native_requests.load(Ordering::SeqCst), 0);

    let credentials = CredentialFactory::default();
    let evidence_client = evidence_client_if_trusted(
        &evidence_trust,
        &evidence_selection,
        &credentials,
        provider.trusted_jwks.clone(),
    )
    .expect("existing adopter-owned Evidence trust accepts the saved selection");
    let prepared = evidence_client
        .prepare(evidence_spec(&evidence_selection))
        .expect("the relying-party Evidence policy closes before I/O");
    let verified = evidence_client
        .request_and_verify(&prepared)
        .await
        .expect("the maintained Evidence client and verifier accept the direct response");
    assert_eq!(
        verified.evidence().request_nonce.as_deref(),
        Some(prepared.request_nonce())
    );

    let relay_trust = NativeTrust {
        service_kind: ServiceKind::Relay,
        service_id: RELAY_SERVICE,
        endpoint_url: format!("{}/relay/", provider.base_url),
        authority_id: RELAY_AUTHORITY,
        conforms_to: vec![REGISTRY_RECORD_PROFILE.into(), RELAY_PROFILE.into()],
        evidence_type_ids: Vec::new(),
        semantic_class_ids: vec![RELAY_SEMANTIC_CLASS.into()],
        operation_family_ids: vec![RELAY_LIST_FAMILY.into()],
        matched_capability: MatchedCapability::SemanticClass(RELAY_SEMANTIC_CLASS.into()),
        evidence_resolution: None,
        relay_capability_match: Some(RelayCapabilityMatch {
            semantic_class_id: Some(RELAY_SEMANTIC_CLASS.into()),
            operation_family_id: Some(RELAY_LIST_FAMILY.into()),
        }),
    };
    let relay_client = relay_client_if_trusted(&relay_trust, &relay_selection, &credentials)
        .expect("existing adopter-owned Relay trust accepts the saved selection");
    let records = relay_client
        .list_records("registered-business", &ListRequest::default(), None)
        .await
        .expect("the maintained Relay client invokes the selected consultation-list binding");
    match records {
        Conditional::Complete(complete) => {
            let RecordCollectionResponse::Json(records) = complete.value.value else {
                panic!("the selected JSON list binding returned another representation");
            };
            assert_eq!(records.items.len(), 1);
            assert_eq!(records.items[0].record_identifier, "BIZ-SYNTH-0001");
            assert_eq!(
                records.items[0].semantic_model_reference,
                RELAY_SEMANTIC_CLASS
            );
        }
        Conditional::NotModified(_) => panic!("the local Relay returned a complete collection"),
    }

    assert_eq!(credentials.count(), 2);
    assert_eq!(provider.evidence_requests.load(Ordering::SeqCst), 1);
    assert_eq!(provider.relay_requests.load(Ordering::SeqCst), 1);
    assert_eq!(provider.untrusted_native_requests.load(Ordering::SeqCst), 0);
    provider.task.abort();
}
