//! End-to-end retention proofs for the normalized authoring compiler.
//!
//! Runtime acceptance tests cover the retained capability surface in depth.
//! These tests keep a narrower boundary: authored project and target authority
//! enter the pure compiler, then the resulting package is activated and served
//! by the real runtime. The assertions below would fail if lowering dropped a
//! capability or widened either the package or target authority ceiling.

#![allow(
    clippy::disallowed_methods,
    reason = "the test reads one published fixture to retain governed package fields while replacing only the compiler-owned model"
)]

use std::{
    collections::BTreeMap,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum_test::TestServer;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::Utc;
use jsonwebtoken::{jwk::JwkSet, Algorithm};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use registry_evidence_authoring::{
    compile,
    project::{AcquisitionPosture, EvidenceProject, PackReference},
    target::{self, EvidenceTargetAuthority},
};
use registry_platform_crypto::document_signature::test_support::TestTransit;
use registry_platform_crypto::{sign, PrivateJwk};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use registry_platform_yaml::LocalId;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt as _},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_rustls::{
    rustls::{
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

use crate::{
    auth::{AuthenticationClaimsConfig, Authenticator},
    authority::{self, AuthorityDocument},
    binding::{
        subject_binding, SelectorField, SelectorScalar, SubjectBindingInput, SubjectBindingScope,
    },
    bundle::{Bundle, DeploymentInputs},
    config::AssuranceProfile,
    model::{
        EvidenceRequest, EvidenceRequestBatch, EvidenceRequestBatchItem, FlattenedJws,
        HolderPublicKey, RequestedSelector, RequestedSubject, SdJwtVcBatchEnvelope, SelectorValue,
        UnsignedEvidenceEnvelope,
    },
    runtime::EvidenceRuntime,
    server::build_app,
    verifier::{
        verify_flattened_jws, verify_sd_jwt_vc, verify_sd_jwt_vc_presentation,
        EvidenceVerificationPolicy, ExpectedOutput, ExpectedSubject,
        HolderBoundPresentationPolicyDocument,
    },
    EVIDENCE_REQUEST_BATCH_MEDIA_TYPE, EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE,
    EVIDENCE_SD_JWT_VC_MEDIA_TYPE, EVIDENCE_UNSIGNED_MEDIA_TYPE,
};
use registry_evidence_verifier::{
    model::{
        Evidence, EvidenceRequestBatchResponse, EvidenceRequestBatchResponseItem, PublicValue,
    },
    verifier::ExpectedValueForm,
};

const AUTH_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","alg":"ES256","kid":"acceptance-auth-key"}"#;
pub(crate) const EVIDENCE_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
pub(crate) const EVIDENCE_PUBLIC_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
const HOLDER_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","alg":"ES256","kid":"holder-proof-key"}"#;
const TOKEN_ISSUER: &str = "https://identity.invalid";
const TOKEN_AUDIENCE: &str = "evidence-fixture";
pub(crate) const EVIDENCE_AUDIENCE: &str = "https://relying.invalid/procedure";
const SOURCE_TOKEN: &str = "normalized-source-token-canary";
const SUBJECT_BINDING_SECRET: &str = "normalized-subject-binding-secret-32-bytes";
const REQUIREMENT_AUDIENCE: &str = "urn:example:normalized:requirement:audience";
const REQUIREMENT_HOLDER: &str = "urn:example:normalized:requirement:holder";
const REQUIREMENT_CONTEXT: &str = "urn:example:normalized:requirement:context";
const REQUIREMENT_GRANT: &str = "urn:example:normalized:requirement:grant";
const REQUIREMENT_ACTOR: &str = "urn:example:normalized:requirement:actor";
const REQUIREMENT_CLASSIC: &str = "urn:example:normalized:requirement:classic-chain";
const REQUIREMENT_SET: &str = "urn:example:normalized:requirement:fetch-set";
const CONCEPT_AUDIENCE: &str = "urn:example:normalized:concept:active:audience";
const CONCEPT_HOLDER: &str = "urn:example:normalized:concept:active:holder";
const CONCEPT_GRANT: &str = "urn:example:normalized:concept:active:grant";
const CONCEPT_ACTOR: &str = "urn:example:normalized:concept:active:actor";
const CONCEPT_CLASSIC: &str = "urn:example:normalized:concept:active:classic";
const CONCEPT_SET: &str = "urn:example:normalized:concept:active:fetch-set";

struct NormalizedRuntime {
    transit: TestTransit,
    _source_tls: TlsSourceProxy,
    _temporary: TempDir,
    runtime: Arc<EvidenceRuntime>,
    source: MockServer,
    audit_path: PathBuf,
}

struct TlsSourceProxy {
    origin: String,
    allowed_private_cidr: String,
    authority_pem: Vec<u8>,
    listener_address: SocketAddr,
    worker: JoinHandle<()>,
}

fn same_host_ipv4_peer(bound: SocketAddr, peer: SocketAddr) -> bool {
    matches!(
        (bound.ip(), peer.ip()),
        (IpAddr::V4(bound), IpAddr::V4(peer)) if bound == peer
    )
}

#[tokio::test]
async fn normalized_tls_source_proxy_rejects_every_non_host_peer_before_tls() {
    let private = Ipv4Addr::new(10, 64, 0, 7);
    let bound = SocketAddr::new(IpAddr::V4(private), 443);
    assert!(same_host_ipv4_peer(
        bound,
        SocketAddr::new(IpAddr::V4(private), 49152)
    ));
    assert!(!same_host_ipv4_peer(
        bound,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152)
    ));
    assert!(!same_host_ipv4_peer(
        bound,
        SocketAddr::new(IpAddr::V6(private.to_ipv6_mapped()), 49152)
    ));
    let ipv6 = private.to_ipv6_mapped();
    assert!(!same_host_ipv4_peer(
        SocketAddr::new(IpAddr::V6(ipv6), 443),
        SocketAddr::new(IpAddr::V6(ipv6), 49152)
    ));

    let source = MockServer::start().await;
    let proxy = TlsSourceProxy::start(*source.address()).await;
    let socket = TcpSocket::new_v4().expect("non-host peer socket opens");
    socket
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("non-host peer binds to loopback");
    let mut rejected = socket
        .connect(proxy.listener_address())
        .await
        .expect("loopback peer reaches the private listener");
    let mut byte = [0_u8; 1];
    let outcome = timeout(Duration::from_secs(1), rejected.read(&mut byte))
        .await
        .expect("non-host peer is rejected without waiting");
    match outcome {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("non-host peer received bytes or stayed connected: {other:?}"),
    }
    assert!(
        source
            .received_requests()
            .await
            .expect("source request journal is available")
            .is_empty(),
        "a rejected peer reaches no upstream source"
    );
}

impl TlsSourceProxy {
    async fn start(upstream: std::net::SocketAddr) -> Self {
        const MAXIMUM_CONNECTIONS: usize = 8;

        let source_address = assigned_private_ipv4();
        let mut authority_parameters =
            CertificateParams::new(Vec::<String>::new()).expect("source CA parameters");
        authority_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let authority_key = KeyPair::generate().expect("source CA key");
        let authority_certificate = authority_parameters
            .self_signed(&authority_key)
            .expect("source CA certificate");
        let server_key = KeyPair::generate().expect("source TLS key");
        let server_certificate = CertificateParams::new(vec![source_address.to_string()])
            .expect("source TLS parameters")
            .signed_by(
                &server_key,
                &Issuer::from_params(&authority_parameters, &authority_key),
            )
            .expect("source CA signs the TLS certificate");
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![server_certificate.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("source TLS configuration");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind((source_address, 0))
            .await
            .expect("source TLS proxy binds");
        let address = listener.local_addr().expect("source TLS proxy address");
        let connection_slots = Arc::new(Semaphore::new(MAXIMUM_CONNECTIONS));
        let worker = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                while let Some(completed) = connections.try_join_next() {
                    if let Err(error) = completed {
                        eprintln!("normalized source TLS connection task failed: {error}");
                    }
                }
                let (stream, peer) = listener
                    .accept()
                    .await
                    .unwrap_or_else(|error| panic!("normalized source TLS accept failed: {error}"));
                if !same_host_ipv4_peer(address, peer) {
                    drop(stream);
                    continue;
                }
                let permit = match Arc::clone(&connection_slots).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(error) => {
                        eprintln!("normalized source TLS connection bound reached: {error}");
                        drop(stream);
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let mut downstream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            eprintln!("normalized source TLS handshake failed: {error}");
                            return;
                        }
                    };
                    let mut upstream = match TcpStream::connect(upstream).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            eprintln!("normalized source proxy connection failed: {error}");
                            return;
                        }
                    };
                    if let Err(error) = copy_bidirectional(&mut downstream, &mut upstream).await {
                        eprintln!("normalized source proxy copy failed: {error}");
                    }
                });
            }
        });
        Self {
            origin: format!("https://{address}"),
            allowed_private_cidr: format!("{source_address}/32"),
            authority_pem: certificate_pem(authority_certificate.der()),
            listener_address: address,
            worker,
        }
    }

    const fn listener_address(&self) -> SocketAddr {
        self.listener_address
    }
}

fn assigned_private_ipv4() -> Ipv4Addr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind route-selection socket");
    socket
        .connect("192.0.2.1:9")
        .expect("select the host's outbound interface");
    let IpAddr::V4(address) = socket.local_addr().expect("route-selection address").ip() else {
        panic!("the normalized TLS fixture requires an assigned private IPv4 interface");
    };
    assert!(
        address.is_private(),
        "the normalized TLS fixture requires an assigned private IPv4 interface"
    );
    address
}

impl Drop for TlsSourceProxy {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

fn certificate_pem(certificate: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(certificate);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("certificate PEM is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem.into_bytes()
}

#[tokio::test]
async fn normalized_compiler_retains_formats_authority_and_holder_proof() {
    let fixture = normalized_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

    Mock::given(method("POST"))
        .and(path("/records"))
        .and(header(
            "authorization",
            format!("Bearer {SOURCE_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": true})))
        .expect(5)
        .mount(&fixture.source)
        .await;

    let audience = request(
        REQUIREMENT_AUDIENCE,
        "audience-check",
        Some("request-record"),
    );
    let signed = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .json(&audience)
        .await;
    signed.assert_status_ok();
    let signed_bytes = signed.as_bytes();
    let policy = verification_policy(&fixture.runtime, &audience, signed_bytes);
    verify_flattened_jws(signed_bytes, fixture.runtime.jwks(), &policy)
        .expect("the normalized signed response verifies independently");

    let unsigned = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_UNSIGNED_MEDIA_TYPE)
        .json(&audience)
        .await;
    unsigned.assert_status_ok();
    let unsigned: UnsignedEvidenceEnvelope =
        serde_json::from_str(&unsigned.text()).expect("unsigned envelope parses");
    assert_eq!(unsigned.evidence.supports_requirement, REQUIREMENT_AUDIENCE);

    let credential = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&audience)
        .await;
    credential.assert_status_ok();
    verify_sd_jwt_vc(credential.as_bytes(), fixture.runtime.jwks(), &policy)
        .expect("the normalized audience-scoped credential verifies independently");

    let holder = PrivateJwk::parse(HOLDER_PRIVATE_JWK).expect("holder key parses");
    let holder_public = holder.public();
    let holder_thumbprint = holder_public.jkt().expect("holder thumbprint computes");
    let mut holder_request = request(REQUIREMENT_HOLDER, "holder-check", Some("holder-record"));
    holder_request.holder_keys = vec![holder_key(&holder_public)];
    let issued = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&holder_request)
        .await;
    issued.assert_status_ok();
    let credential = issued.text();
    let payload = released_credential_payload(&credential);
    assert_eq!(payload["subjectBinding"], "holder-bound");
    assert!(payload.get("audience").is_none());
    assert!(payload.get("requestNonce").is_none());

    let challenge = fresh_nonce();
    let verifier_audience = "https://verifier.invalid/normalized-proof";
    let expected_binding = subject_binding(
        SUBJECT_BINDING_SECRET.as_bytes(),
        1,
        SubjectBindingInput {
            trust_domain: &fixture.runtime.bundle().config.service.trust_domain,
            scope: SubjectBindingScope::HolderKeyThumbprint(&holder_thumbprint),
            purpose: "holder-check",
            role: "subject",
            profile: "record-by-id",
            fields: &[SelectorField {
                name: "record-id",
                value: SelectorScalar::String("holder-record"),
            }],
        },
    )
    .expect("trusted holder binding state derives independently");
    assert_eq!(payload["subjects"][0]["binding"], expected_binding);
    let wallet =
        registry_platform_sdjwt::SdJwtIssuer::from_jwk(holder).expect("holder signer initializes");
    let proof = wallet
        .sign_compact_jwt(
            "kb+jwt",
            json!({
                "aud": verifier_audience,
                "nonce": challenge,
                "iat": Utc::now().timestamp(),
                "sd_hash": URL_SAFE_NO_PAD.encode(
                    registry_platform_sdjwt::presentation_disclosure_hash(&credential)
                )
            }),
        )
        .await
        .expect("holder proof signs");
    let config = &fixture.runtime.bundle().config;
    let holder_policy: HolderBoundPresentationPolicyDocument = serde_json::from_value(json!({
        "apiVersion": "id.registrystack.org/formats/evidence/holder-bound-verification-policy/v1",
        "kind": "EvidenceHolderBoundVerificationPolicy",
        "subjectBinding": "holder-bound",
        "expectedAssuranceProfile": config.assurance_profile,
        "issuedBy": config.issuer.id,
        "providedBy": config.service.provider_id,
        "requirement": REQUIREMENT_HOLDER,
        "evidenceType": "urn:example:normalized:evidence:holder",
        "expectedIssuancePurpose": "holder-check",
        "configurationRevision": fixture.runtime.bundle().configuration_revision(REQUIREMENT_HOLDER).expect("holder definition revision"),
        "expectedSubjects": [{"role": "subject", "binding": expected_binding}],
        "expectedOutputs": [{"handle": "active", "concept": CONCEPT_HOLDER, "required": true, "form": {"type": "boolean"}}],
        "revokedKeyIds": [],
        "maximumAssertionLifetimeSeconds": 300,
        "keyBindingAudience": verifier_audience,
        "keyBindingNonce": challenge,
        "maximumKeyBindingAgeSeconds": 300,
        "clockSkewSeconds": 30,
        "expectedHolderKeyThumbprint": holder_thumbprint
    }))
    .expect("holder policy parses");
    verify_sd_jwt_vc_presentation(
        format!("{credential}{proof}").as_bytes(),
        fixture.runtime.jwks(),
        &holder_policy
            .try_into_policy(Utc::now())
            .expect("holder policy bounds are valid"),
    )
    .expect("the holder proves possession to the independent verifier");

    let mut holder_batch_request = holder_request.clone();
    holder_batch_request.holder_keys = holder_keys(2);
    let batch = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)
        .json(&holder_batch_request)
        .await;
    batch.assert_status_ok();
    let batch: SdJwtVcBatchEnvelope =
        serde_json::from_str(&batch.text()).expect("holder batch parses");
    assert_eq!(batch.credentials.len(), 2);

    let before = fixture
        .source
        .received_requests()
        .await
        .expect("source journal is available")
        .len();
    let mut above_ceiling = holder_request;
    above_ceiling.holder_keys = holder_keys(3);
    let refused = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)
        .json(&above_ceiling)
        .await;
    assert_eq!(refused.status_code(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(refused.json::<Value>()["code"], "evidence.invalid-request");
    assert_eq!(
        fixture
            .source
            .received_requests()
            .await
            .expect("source journal is available")
            .len(),
        before,
        "the package holder-batch ceiling is enforced before source access"
    );
    assert_eq!(
        fixture.transit.signatures(),
        7,
        "two startup probes and five released representations use Transit"
    );
}

#[tokio::test]
async fn normalized_compiler_retains_sequential_request_batch_and_authenticated_provenance() {
    let fixture = normalized_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

    for (record_id, active) in [("batch-a", true), ("batch-b", false), ("batch-c", true)] {
        Mock::given(method("POST"))
            .and(path("/records"))
            .and(header(
                "authorization",
                format!("Bearer {SOURCE_TOKEN}").as_str(),
            ))
            .and(body_json(json!({"record_id": record_id})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": active})))
            .expect(1)
            .mount(&fixture.source)
            .await;
    }
    let request_batch = EvidenceRequestBatch {
        requirement: REQUIREMENT_AUDIENCE.to_owned(),
        expected_configuration_revision: None,
        purpose: "audience-check".to_owned(),
        items: ["batch-a", "batch-b", "batch-c"]
            .into_iter()
            .map(|record| EvidenceRequestBatchItem {
                request_nonce: fresh_nonce(),
                subjects: vec![subject(Some(record))],
            })
            .collect(),
    };
    let sequential = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&request_batch)
        .await;
    sequential.assert_status_ok();
    let sequential: EvidenceRequestBatchResponse =
        serde_json::from_str(&sequential.text()).expect("request batch parses");
    let evidence = sequential
        .items
        .iter()
        .map(|item| match item {
            EvidenceRequestBatchResponseItem::Evidence { evidence } => decode_evidence(evidence),
            EvidenceRequestBatchResponseItem::EvidenceNotAvailable => {
                panic!("the synthetic source resolves every member")
            }
        })
        .collect::<Vec<_>>();
    let values = evidence
        .iter()
        .map(|evidence| evidence.supported_values[0].value.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        values,
        vec![
            PublicValue::Boolean(true),
            PublicValue::Boolean(false),
            PublicValue::Boolean(true)
        ],
        "sequential acquisitions retain logical request order"
    );
    assert_eq!(
        evidence
            .iter()
            .map(|evidence| evidence.request_nonce.as_deref())
            .collect::<Vec<_>>(),
        request_batch
            .items
            .iter()
            .map(|item| Some(item.request_nonce.as_str()))
            .collect::<Vec<_>>(),
        "each response retains the nonce of the request in the same logical position"
    );
    let physical = fixture
        .source
        .received_requests()
        .await
        .expect("source journal is available");
    assert_eq!(
        physical.len(),
        3,
        "the maintained baseline performs one complete pack acquisition per item"
    );
    assert_eq!(
        physical
            .iter()
            .map(|request| {
                let body: Value =
                    serde_json::from_slice(&request.body).expect("source body is JSON");
                body["record_id"]
                    .as_str()
                    .expect("the minimized record id is present")
                    .to_owned()
            })
            .collect::<Vec<_>>(),
        vec![
            "batch-a".to_owned(),
            "batch-b".to_owned(),
            "batch-c".to_owned()
        ],
        "the pack receives only the minimized selector in request order"
    );

    fixture.source.reset().await;
    Mock::given(method("POST"))
        .and(path("/records"))
        .and(body_json(json!({"record_id": "context-record"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": true})))
        .expect(1)
        .mount(&fixture.source)
        .await;
    let context = request(REQUIREMENT_CONTEXT, "context-check", None);
    let context_token = access_token(Some(
        json!({"verified_context": {"record_id": "context-record"}}),
    ));
    let context_response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {context_token}"))
        .json(&context)
        .await;
    context_response.assert_status_ok();

    let before = fixture
        .source
        .received_requests()
        .await
        .expect("source journal is available")
        .len();
    let signatures_before = fixture.transit.signatures();
    let substituted = request(
        REQUIREMENT_CONTEXT,
        "context-check",
        Some("caller-substitution"),
    );
    let refused = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {context_token}"))
        .json(&substituted)
        .await;
    assert_eq!(refused.status_code(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(
        fixture
            .source
            .received_requests()
            .await
            .expect("source journal is available")
            .len(),
        before,
        "caller values cannot replace authenticated context"
    );
    assert_eq!(
        fixture.transit.signatures(),
        signatures_before,
        "the refused authenticated-context substitution reaches no signer"
    );

    fixture.source.reset().await;
    Mock::given(method("POST"))
        .and(path("/records"))
        .and(body_json(json!({"record_id": "grant-record"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": true})))
        .expect(1)
        .mount(&fixture.source)
        .await;
    let grant = request(REQUIREMENT_GRANT, "grant-check", None);
    let grant_token = access_token(Some(task_grant_claims("grant-record")));
    let grant_response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {grant_token}"))
        .json(&grant)
        .await;
    grant_response.assert_status_ok();
    let grant_bytes = grant_response.as_bytes();
    let grant_policy = verification_policy_for(
        &fixture.runtime,
        &grant,
        grant_bytes,
        "urn:example:normalized:evidence:grant",
        CONCEPT_GRANT,
    );
    verify_flattened_jws(grant_bytes, fixture.runtime.jwks(), &grant_policy)
        .expect("the actor-neutral task profile issues independently verifiable Evidence");
    let grant_jws: FlattenedJws =
        serde_json::from_slice(grant_bytes).expect("grant response is JWS");
    let grant_evidence = decode_evidence(&grant_jws);
    assert_eq!(grant_evidence.supports_requirement, REQUIREMENT_GRANT);

    let before = fixture
        .source
        .received_requests()
        .await
        .expect("source journal is available")
        .len();
    let signatures_before = fixture.transit.signatures();
    let mut wrong_client_claims = task_grant_claims("grant-record");
    wrong_client_claims["registry_grant_client"] = json!("other-client");
    let wrong_client = access_token(Some(wrong_client_claims));
    let refused = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {wrong_client}"))
        .json(&grant)
        .await;
    assert_eq!(refused.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(refused.json::<Value>()["code"], "evidence.denied");
    assert_eq!(
        fixture
            .source
            .received_requests()
            .await
            .expect("source journal is available")
            .len(),
        before,
        "a grant issued for another client reaches no source"
    );
    assert_eq!(
        fixture.transit.signatures(),
        signatures_before,
        "a grant issued for another client reaches no signer"
    );

    let before = fixture
        .source
        .received_requests()
        .await
        .expect("source journal is available")
        .len();
    let signatures_before = fixture.transit.signatures();
    let wrong_task = access_token(Some(task_grant_claims_for(
        "grant-record",
        REQUIREMENT_CONTEXT,
    )));
    let refused = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {wrong_task}"))
        .json(&grant)
        .await;
    assert_eq!(refused.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(refused.json::<Value>()["code"], "evidence.denied");
    assert_eq!(
        fixture
            .source
            .received_requests()
            .await
            .expect("source journal is available")
            .len(),
        before,
        "a task grant outside the compiled authority tuple reaches no source"
    );
    assert_eq!(
        fixture.transit.signatures(),
        signatures_before,
        "the refused task grant reaches no signer"
    );

    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    for private in [
        "context-record",
        "caller-substitution",
        "grant-record",
        "other-client",
        "batch-a",
        "batch-b",
        "batch-c",
    ] {
        assert!(!audit.contains(private), "audit disclosed {private}");
    }
}

#[tokio::test]
async fn normalized_authority_without_profile_actor_retains_definition_actor_ceiling() {
    let fixture = normalized_runtime_with_actor_profile().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

    Mock::given(method("POST"))
        .and(path("/records"))
        .and(header(
            "authorization",
            format!("Bearer {SOURCE_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": true})))
        .expect(2)
        .mount(&fixture.source)
        .await;

    let signatures_before = fixture.transit.signatures();
    for (actor_kind, record_id) in [
        ("service", "service-actor-private"),
        ("human", "human-actor-private"),
    ] {
        let evidence_request = request(REQUIREMENT_ACTOR, "actor-check", Some(record_id));
        let response = http
            .post("/v1/evidence")
            .add_header(
                "authorization",
                format!("Bearer {}", access_token_for_actor(actor_kind, None)),
            )
            .json(&evidence_request)
            .await;
        response.assert_status_ok();
        let bytes = response.as_bytes();
        let policy = verification_policy_for(
            &fixture.runtime,
            &evidence_request,
            bytes,
            "urn:example:normalized:evidence:actor",
            CONCEPT_ACTOR,
        );
        verify_flattened_jws(bytes, fixture.runtime.jwks(), &policy)
            .expect("each permitted actor receives independently verifiable Evidence");
    }
    assert_eq!(
        fixture.transit.signatures(),
        signatures_before + 2,
        "each permitted actor reaches the signer once"
    );

    let source_calls_before = fixture
        .source
        .received_requests()
        .await
        .expect("source journal is available")
        .len();
    let signatures_before = fixture.transit.signatures();
    let forbidden = request(
        REQUIREMENT_ACTOR,
        "actor-check",
        Some("agent-actor-private"),
    );
    let forbidden_token = access_token_for_actor(
        "agent",
        Some(task_grant_claims_for_purpose(
            "agent-actor-private",
            REQUIREMENT_ACTOR,
            "actor-check",
        )),
    );
    let response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {forbidden_token}"))
        .json(&forbidden)
        .await;
    assert_eq!(response.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], "evidence.denied");
    assert_eq!(
        fixture
            .source
            .received_requests()
            .await
            .expect("source journal is available")
            .len(),
        source_calls_before,
        "the actor outside the Definition ceiling reaches no Source"
    );
    assert_eq!(
        fixture.transit.signatures(),
        signatures_before,
        "the actor outside the Definition ceiling reaches no signer"
    );

    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    for private in [
        "service-actor-private",
        "human-actor-private",
        "agent-actor-private",
    ] {
        assert!(!audit.contains(private), "audit disclosed {private}");
    }
}

#[tokio::test]
async fn normalized_compiler_retains_classic_and_multimember_pack_acquisition() {
    let fixture = normalized_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let search_response = json!({
        "found": true,
        "search_ok": true,
        "classic_ref": "classic-private-ref",
        "left_ref": "left-private-ref",
        "right_ref": "right-private-ref"
    });

    Mock::given(method("POST"))
        .and(path("/search"))
        .and(body_json(json!({"record_id": "selector-private-record"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(search_response))
        .expect(2)
        .mount(&fixture.source)
        .await;
    Mock::given(method("POST"))
        .and(path("/classic-fetch"))
        .and(body_json(json!({
            "classic_ref": "classic-private-ref",
            "left_ref": "left-private-ref",
            "right_ref": "right-private-ref",
            "search_ok": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": true})))
        .expect(1)
        .mount(&fixture.source)
        .await;
    Mock::given(method("POST"))
        .and(path("/set-left"))
        .and(body_json(json!({"resolved_ref": "left-private-ref"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": true})))
        .expect(1)
        .mount(&fixture.source)
        .await;
    Mock::given(method("POST"))
        .and(path("/set-right"))
        .and(body_json(json!({"resolved_ref": "right-private-ref"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": true})))
        .expect(1)
        .mount(&fixture.source)
        .await;

    let signatures_before = fixture.transit.signatures();
    for (requirement, purpose, concept) in [
        (REQUIREMENT_CLASSIC, "classic-check", CONCEPT_CLASSIC),
        (REQUIREMENT_SET, "fetch-set-check", CONCEPT_SET),
    ] {
        let evidence_request = request(requirement, purpose, Some("selector-private-record"));
        let response = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {}", access_token(None)))
            .json(&evidence_request)
            .await;
        response.assert_status_ok();
        let bytes = response.as_bytes();
        let evidence_type = format!(
            "urn:example:normalized:evidence:{}",
            purpose.trim_end_matches("-check")
        );
        let policy = verification_policy_for(
            &fixture.runtime,
            &evidence_request,
            bytes,
            &evidence_type,
            concept,
        );
        verify_flattened_jws(bytes, fixture.runtime.jwks(), &policy)
            .expect("normalized multi-source Evidence verifies independently");
        let jws: FlattenedJws = serde_json::from_slice(bytes).expect("response is JWS JSON");
        let evidence = decode_evidence(&jws);
        assert_eq!(
            evidence.supported_values[0].value,
            PublicValue::Boolean(true)
        );
        let released = serde_json::to_string(&evidence).expect("Evidence serializes");
        for private in [
            "selector-private-record",
            "classic-private-ref",
            "left-private-ref",
            "right-private-ref",
        ] {
            assert!(!released.contains(private), "Evidence disclosed {private}");
        }
    }
    assert_eq!(
        fixture.transit.signatures(),
        signatures_before + 2,
        "each complete acquisition signs exactly one response"
    );

    let source_requests = fixture
        .source
        .received_requests()
        .await
        .expect("source journal is available");
    assert_eq!(
        source_requests
            .iter()
            .map(|request| request.url.path())
            .collect::<Vec<_>>(),
        vec![
            "/search",
            "/classic-fetch",
            "/search",
            "/set-left",
            "/set-right"
        ],
        "compiled acquisition preserves declared source order"
    );
    fixture.source.reset().await;
    Mock::given(method("POST"))
        .and(path("/search"))
        .and(body_json(
            json!({"record_id": "unresolved-selector-private-record"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "found": false,
            "search_ok": false,
            "classic_ref": "unresolved-classic-private-ref",
            "left_ref": "unresolved-left-private-ref",
            "right_ref": "unresolved-right-private-ref"
        })))
        .expect(1)
        .mount(&fixture.source)
        .await;
    let signatures_before = fixture.transit.signatures();
    let unavailable = request(
        REQUIREMENT_SET,
        "fetch-set-check",
        Some("unresolved-selector-private-record"),
    );
    let response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .json(&unavailable)
        .await;
    assert_eq!(
        response.status_code(),
        axum::http::StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(response.json::<Value>()["code"], "evidence.unavailable");
    assert_eq!(
        fixture
            .source
            .received_requests()
            .await
            .expect("source journal is available")
            .iter()
            .map(|request| request.url.path())
            .collect::<Vec<_>>(),
        vec!["/search"],
        "a search no-match stops every fetch-set member"
    );
    assert_eq!(
        fixture.transit.signatures(),
        signatures_before,
        "a search no-match reaches no signer"
    );

    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    for private in [
        "selector-private-record",
        "classic-private-ref",
        "left-private-ref",
        "right-private-ref",
        "unresolved-selector-private-record",
        "unresolved-classic-private-ref",
        "unresolved-left-private-ref",
        "unresolved-right-private-ref",
    ] {
        assert!(!audit.contains(private), "audit disclosed {private}");
    }
}

async fn normalized_runtime() -> NormalizedRuntime {
    normalized_runtime_with(false).await
}

async fn normalized_runtime_with_actor_profile() -> NormalizedRuntime {
    normalized_runtime_with(true).await
}

async fn normalized_runtime_with(include_optional_actor_profile: bool) -> NormalizedRuntime {
    let source = MockServer::start().await;
    let source_tls = TlsSourceProxy::start(*source.address()).await;
    let temporary = tempfile::tempdir().expect("temporary normalized deployment");
    let package_root = temporary.path().join("package");
    let secret_root = temporary.path().join("secrets");
    let authority_root = temporary.path().join("authority");
    let runtime_path = temporary.path().join("runtime.yaml");
    let audit_path = temporary.path().join("audit.jsonl");
    let source_ca_path = temporary.path().join("source-ca.pem");
    fs::create_dir(&package_root).expect("package root is created");
    fs::create_dir(&secret_root).expect("secret root is created");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("secret root is private");
    fs::write(&source_ca_path, &source_tls.authority_pem).expect("source CA is written");
    fs::set_permissions(&source_ca_path, fs::Permissions::from_mode(0o400))
        .expect("source CA is immutable");

    let project = normalized_project();
    let pack_routes = pack_routes();
    let compiled = compile::compile_with_pack_routes(&project, &scripts(), &pack_routes)
        .expect("normalized project compiles against the exact checked pack closure");
    let mut bundle: Value = serde_norway::from_slice(include_bytes!(
        "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
    ))
    .expect("retained target governance parses");
    let bundle_object = bundle.as_object_mut().expect("bundle is an object");
    for model_member in [
        "project",
        "maximumHolderBoundBatchSize",
        "selectorProfiles",
        "sources",
        "requirements",
        "authorityProfiles",
    ] {
        bundle_object.remove(model_member);
    }
    bundle_object.remove("publication");
    bundle["service"]["providerId"] = json!("https://provider.normalized.invalid");
    bundle["service"]["publicOrigin"] = json!("https://provider.normalized.invalid");
    bundle["issuer"]["uri"] = json!("urn:example:normalized:issuer");
    bundle["responseFormats"] = json!([
        "signed-jws",
        "unsigned-json",
        "sd-jwt-vc",
        "sd-jwt-vc-batch"
    ]);
    bundle["sourceConnections"] = json!({
        "records": {
            "endpoints": [{
                "endpoint": "provider",
                "baseUrl": source_tls.origin.clone(),
                "authentication": {"type": "static-authorization"},
                "clientIdentity": "forbidden",
                "tlsTrustProfile": "source-pki"
            }]
        }
    });
    bundle["authorityProfiles"] = json!({});
    for (name, value) in compiled
        .model
        .as_object()
        .expect("compiled model is an object")
    {
        bundle[name] = value.clone();
    }
    fs::write(
        package_root.join("evidence.yaml"),
        serde_norway::to_string(&bundle).expect("bundle serializes"),
    )
    .expect("bundle configuration is written");
    for (relative, bytes) in compiled.artifacts {
        let path = package_root.join(relative);
        fs::create_dir_all(path.parent().expect("artifact has a parent"))
            .expect("artifact directory is created");
        fs::write(path, bytes).expect("compiled artifact is written");
    }
    let fixture_path = package_root.join("fixtures/normalized-cases.yaml");
    fs::create_dir_all(fixture_path.parent().expect("fixture has a parent"))
        .expect("fixture directory is created");
    fs::write(
        fixture_path,
        r#"apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1
kind: EvidenceFixture
syntheticOnly: true
common: {}
privacyExpectation: {}
cases:
  - {id: positive}
  - {id: negative-false}
  - {id: boundary-on}
  - {id: missing-fact}
  - {id: no-match}
  - {id: ambiguous}
  - {id: source-failure}
  - {id: anti-reconstruction}
"#,
    )
    .expect("complete synthetic fixture is written");
    let public_key_path =
        package_root.join("public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json");
    fs::create_dir_all(public_key_path.parent().expect("public key has a parent"))
        .expect("public key directory is created");
    fs::write(public_key_path, EVIDENCE_PUBLIC_JWK).expect("public key is written");
    registry_platform_config::write_sum_file(
        &package_root,
        None,
        &crate::bundle::evidence_package_limits(),
        "evidencectl package",
    )
    .expect("package checksum envelope is written");
    make_read_only(&package_root);

    crate::kernel::OfflineKernel::compile(Arc::new(
        Bundle::load(&package_root).expect("normalized package loads for kernel compilation"),
    ))
    .expect("normalized artifacts compile in the runtime kernel");
    let bundle = Bundle::load(&package_root).expect("normalized package loads");
    let authority = normalized_authority(include_optional_actor_profile);
    let mut outside_ceiling = serde_json::to_value(&authority).expect("authority serializes");
    outside_ceiling["accessProfiles"]["direct"]["grants"][0]["representations"] =
        json!(["sd-jwt-vc-batch"]);
    let outside_ceiling: EvidenceTargetAuthority =
        serde_json::from_value(outside_ceiling).expect("outside-ceiling authority is structural");
    assert!(
        target::compile_authority(&outside_ceiling, &project).is_err(),
        "target authority cannot exceed the normalized package ceiling"
    );
    let compiled_authority = target::compile_authority(&authority, &project)
        .expect("normalized authority compiles inside project ceilings");
    assert!(
        compiled_authority["accessProfiles"]["task"]
            .get("actorKind")
            .is_none(),
        "the compiler retains an actor-neutral authenticated-grant profile"
    );
    if include_optional_actor_profile {
        assert!(
            compiled_authority["accessProfiles"]["actor-open"]
                .get("actorKind")
                .is_none(),
            "the compiler retains an actor-neutral request profile"
        );
    }
    let authority_bytes =
        serde_norway::to_string(&compiled_authority).expect("compiled authority serializes");
    let authority = AuthorityDocument::parse("compiled-authority.yaml", authority_bytes.as_bytes())
        .expect("runtime authority parses the compiler output");
    authority::activate(
        &authority_root,
        "local",
        &bundle.config,
        bundle.package_digest(),
        &authority,
    )
    .expect("compiled target authority activates for this exact package");

    write_secret(&secret_root, "source-token", SOURCE_TOKEN);
    let transit = TestTransit::start(
        &temporary.path().join("transit.sock"),
        "transit",
        "evidence-signing",
        1,
        &serde_json::from_str::<PrivateJwk>(EVIDENCE_PRIVATE_JWK).expect("private JWK parses"),
    )
    .expect("start the test Transit proxy");
    write_secret(
        &secret_root,
        "audit-hash-key",
        "normalized-audit-hash-secret-32-bytes",
    );
    write_secret(&secret_root, "subject-binding-key", SUBJECT_BINDING_SECRET);
    fs::write(
        &runtime_path,
        format!(
            r#"apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1
kind: EvidenceRuntimeConfig
package:
  root: {}
listener:
  bind: 127.0.0.1:8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file:
    root: {}
signer:
  type: transit
  unixSocketPath: {}
  mount: transit
  keyName: evidence-signing
  keyVersion: 1
  attemptTimeoutMilliseconds: 2000
audit:
  path: {}
  rotateBytes: 10485760
authority:
  root: {}
  target: local
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
sourceConnections:
  records:
    id: records
    endpoints:
      - endpoint: provider
        baseUrl: {}
        credential: {{type: static-authorization, tokenRef: secret:file/source-token}}
        tlsTrustProfile: source-pki
    outboundTls:
      trustProfiles:
        source-pki: {{caBundleFile: {}}}
    allowedPrivateCidrs: [{}]
"#,
            package_root.display(),
            secret_root.display(),
            transit.socket_path().display(),
            audit_path.display(),
            authority_root.display(),
            source_tls.origin.as_str(),
            source_ca_path.display(),
            source_tls.allowed_private_cidr.as_str()
        ),
    )
    .expect("runtime configuration is written");
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o400))
        .expect("runtime configuration is sealed");
    DeploymentInputs::load(&runtime_path).expect("package and authority ceilings both load");
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&runtime_path, authenticator())
            .await
            .expect("normalized runtime initializes"),
    );
    NormalizedRuntime {
        transit,
        _source_tls: source_tls,
        _temporary: temporary,
        runtime,
        source,
        audit_path,
    }
}

fn normalized_project() -> EvidenceProject {
    let mut document = json!({
        "id": "normalized-retention",
        "maximumHolderBoundBatchSize": 2,
        "selectorProfiles": {
            "record-by-id": {
                "maximumAggregateBytes": 64,
                "fields": {"record-id": {"type": "string", "minimumBytes": 1, "maximumBytes": 64}}
            }
        },
        "functions": [
            {"id": "derive-active", "interface": "assertion-derive/v1", "source": "functions/derive.rhai"},
            {"id": "derive-classic", "interface": "assertion-derive/v1", "source": "functions/derive-classic.rhai"},
            {"id": "derive-members", "interface": "assertion-derive/v1", "source": "functions/derive-members.rhai"}
        ],
        "sources": {
            "records": {
                "pack": {"id": "normalized-retention", "version": "1"},
                "route": "records",
                "connection": "records",
                "inputs": {
                    "recordId": {"selector": {"role": "subject", "profile": "record-by-id", "field": "record-id"}}
                },
                "acquisitionPosture": "record-transformed"
            },
            "classic": {
                "pack": {"id": "normalized-retention", "version": "1"},
                "route": "classic",
                "connection": "records",
                "inputs": {
                    "recordId": {"selector": {"role": "subject", "profile": "record-by-id", "field": "record-id"}}
                },
                "acquisitionPosture": "record-transformed"
            },
            "members": {
                "pack": {"id": "normalized-retention", "version": "1"},
                "route": "members",
                "connection": "records",
                "inputs": {
                    "recordId": {"selector": {"role": "subject", "profile": "record-by-id", "field": "record-id"}}
                },
                "acquisitionPosture": "record-transformed"
            }
        },
        "assertionDefinitions": {
            "audience": definition(
                REQUIREMENT_AUDIENCE,
                "audience-check",
                "audience-scoped",
                ["request"],
                ["service"],
                ["signed-jws", "unsigned-json", "sd-jwt-vc"]
            ),
            "holder": definition(
                REQUIREMENT_HOLDER,
                "holder-check",
                "holder-bound",
                ["request"],
                ["service"],
                ["sd-jwt-vc", "sd-jwt-vc-batch"]
            ),
            "context": definition(
                REQUIREMENT_CONTEXT,
                "context-check",
                "audience-scoped",
                ["authenticated-context"],
                ["service"],
                ["signed-jws"]
            ),
            "grant": definition(
                REQUIREMENT_GRANT,
                "grant-check",
                "audience-scoped",
                ["authenticated-grant"],
                ["agent"],
                ["signed-jws"]
            )
        }
    });
    document["assertionDefinitions"]["actor"] = definition(
        REQUIREMENT_ACTOR,
        "actor-check",
        "audience-scoped",
        ["request"],
        ["service", "human"],
        ["signed-jws"],
    );
    let mut classic = definition(
        REQUIREMENT_CLASSIC,
        "classic-check",
        "audience-scoped",
        ["request"],
        ["service"],
        ["signed-jws"],
    );
    classic["acquisition"] = json!({"source": "classic"});
    classic["derive"] = json!({"function": "derive-classic"});
    document["assertionDefinitions"]["classic"] = classic;
    let mut fetch_set = definition(
        REQUIREMENT_SET,
        "fetch-set-check",
        "audience-scoped",
        ["request"],
        ["service"],
        ["signed-jws"],
    );
    fetch_set["acquisition"] = json!({"source": "members"});
    fetch_set["derive"] = json!({"function": "derive-members"});
    document["assertionDefinitions"]["fetch-set"] = fetch_set;
    serde_json::from_value(document).expect("normalized project is structurally valid")
}

fn pack_routes() -> Vec<compile::CheckedPackRoute> {
    const ROUTE_SCRIPT: &str = r#"fn required(value) {
    if value == () { throw "source_protocol_error"; }
    value
}

fn record_request(exchange) {
    #{record_id: exchange.body.recordId}
}

fn record_result(exchange) {
    #{lookup: "matched", facts: #{active: required(exchange.body["active"])}}
}

fn search_request(exchange) {
    #{record_id: exchange.body.recordId}
}

fn search_no_match(exchange) {
    required(exchange.body["found"]) == false
}

fn classic_ref(exchange) { required(exchange.body["classic_ref"]) }
fn left_ref(exchange) { required(exchange.body["left_ref"]) }
fn right_ref(exchange) { required(exchange.body["right_ref"]) }
fn search_ok(exchange) { required(exchange.body["search_ok"]) }

fn classic_request(exchange) {
    #{
        classic_ref: exchange.properties.classicRef,
        left_ref: exchange.properties.leftRef,
        right_ref: exchange.properties.rightRef,
        search_ok: exchange.properties.searchOk
    }
}

fn classic_result(exchange) {
    #{lookup: "matched", facts: #{classic_active: required(exchange.body["active"])}}
}

fn left_request(exchange) {
    #{resolved_ref: exchange.properties.leftRef}
}

fn left_active(exchange) { required(exchange.body["active"]) }

fn right_request(exchange) {
    #{resolved_ref: exchange.properties.rightRef}
}

fn members_result(exchange) {
    #{lookup: "matched", facts: #{
        members_active: exchange.properties.searchOk
            && exchange.properties.leftActive
            && required(exchange.body["active"])
    }}
}
"#;

    let inputs_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["recordId"],
        "properties": {
            "recordId": {"type": "string", "minLength": 1, "maxLength": 64}
        }
    });
    let records_facts = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["active"],
        "properties": {"active": {"type": "boolean"}}
    });
    let classic_facts = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["classic_active"],
        "properties": {"classic_active": {"type": "boolean"}}
    });
    let members_facts = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["members_active"],
        "properties": {"members_active": {"type": "boolean"}}
    });
    let artifacts = BTreeMap::from([
        (
            "schemas/inputs.json".to_owned(),
            serde_json::to_vec(&inputs_schema).expect("pack inputs schema serializes"),
        ),
        (
            "schemas/records-facts.json".to_owned(),
            serde_json::to_vec(&records_facts).expect("record facts schema serializes"),
        ),
        (
            "schemas/classic-facts.json".to_owned(),
            serde_json::to_vec(&classic_facts).expect("classic facts schema serializes"),
        ),
        (
            "schemas/members-facts.json".to_owned(),
            serde_json::to_vec(&members_facts).expect("member facts schema serializes"),
        ),
        (
            "scripts/routes.rhai".to_owned(),
            ROUTE_SCRIPT.as_bytes().to_vec(),
        ),
    ]);
    let digest = |path: &str| {
        registry_platform_config::sha256_uri(
            artifacts
                .get(path)
                .unwrap_or_else(|| panic!("pack artifact {path} exists")),
        )
    };
    let evidence_contract = |facts_path: &str| {
        json!({
            "inputsSchema": {
                "path": "schemas/inputs.json",
                "digest": digest("schemas/inputs.json")
            },
            "factsSchema": {"path": facts_path, "digest": digest(facts_path)},
            "acquisitionPosture": "record-transformed"
        })
    };
    let pack = json!({
        "apiVersion": "id.registrystack.org/formats/adapter/pack/v1alpha1",
        "kind": "AdapterPack",
        "id": "normalized-retention",
        "version": "1",
        "testedVersions": [],
        "endpoints": [{
            "id": "provider",
            "component": "http",
            "authentication": {"type": "static-authorization"},
            "attemptTimeoutMilliseconds": 2000,
            "maximumResponseBytes": 16384,
            "requestHeaders": ["accept"],
            "operations": [{"id": "lookup", "safeUpstream": true}]
        }],
        "scripts": [{
            "path": "scripts/routes.rhai",
            "digest": digest("scripts/routes.rhai")
        }],
        "sourceRoutes": [
            {
                "id": "records",
                "evidence": evidence_contract("schemas/records-facts.json"),
                "steps": [
                    {"setHeader": {"name": "accept", "value": {"constant": "application/json"}}},
                    {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "record_request"}}},
                    {"to": {"uri": "http:provider", "parameters": {
                        "httpMethod": "POST",
                        "path": "/records",
                        "operation": "lookup",
                        "body": {"jsonpath": "$"}
                    }}},
                    {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "record_result"}}}
                ]
            },
            {
                "id": "classic",
                "evidence": evidence_contract("schemas/classic-facts.json"),
                "steps": [
                    {"setHeader": {"name": "accept", "value": {"constant": "application/json"}}},
                    {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "search_request"}}},
                    {"to": {"uri": "http:provider", "parameters": {
                        "httpMethod": "POST",
                        "path": "/search",
                        "operation": "lookup",
                        "body": {"jsonpath": "$"}
                    }}},
                    {"choice": {
                        "when": [{
                            "rhai": {"file": "scripts/routes.rhai", "entrypoint": "search_no_match"},
                            "steps": [
                                {"setBody": {"constant": {"lookup": "no-match"}}},
                                {"stop": {}}
                            ]
                        }],
                        "otherwise": {"steps": [
                            {"setProperty": {"name": "classicRef", "value": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "classic_ref"}}}},
                            {"setProperty": {"name": "leftRef", "value": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "left_ref"}}}},
                            {"setProperty": {"name": "rightRef", "value": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "right_ref"}}}},
                            {"setProperty": {"name": "searchOk", "value": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "search_ok"}}}},
                            {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "classic_request"}}},
                            {"to": {"uri": "http:provider", "parameters": {
                                "httpMethod": "POST",
                                "path": "/classic-fetch",
                                "operation": "lookup",
                                "body": {"jsonpath": "$"}
                            }}},
                            {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "classic_result"}}}
                        ]}
                    }}
                ]
            },
            {
                "id": "members",
                "evidence": evidence_contract("schemas/members-facts.json"),
                "steps": [
                    {"setHeader": {"name": "accept", "value": {"constant": "application/json"}}},
                    {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "search_request"}}},
                    {"to": {"uri": "http:provider", "parameters": {
                        "httpMethod": "POST",
                        "path": "/search",
                        "operation": "lookup",
                        "body": {"jsonpath": "$"}
                    }}},
                    {"choice": {
                        "when": [{
                            "rhai": {"file": "scripts/routes.rhai", "entrypoint": "search_no_match"},
                            "steps": [
                                {"setBody": {"constant": {"lookup": "no-match"}}},
                                {"stop": {}}
                            ]
                        }],
                        "otherwise": {"steps": [
                            {"setProperty": {"name": "leftRef", "value": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "left_ref"}}}},
                            {"setProperty": {"name": "rightRef", "value": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "right_ref"}}}},
                            {"setProperty": {"name": "searchOk", "value": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "search_ok"}}}},
                            {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "left_request"}}},
                            {"to": {"uri": "http:provider", "parameters": {
                                "httpMethod": "POST",
                                "path": "/set-left",
                                "operation": "lookup",
                                "body": {"jsonpath": "$"}
                            }}},
                            {"setProperty": {"name": "leftActive", "value": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "left_active"}}}},
                            {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "right_request"}}},
                            {"to": {"uri": "http:provider", "parameters": {
                                "httpMethod": "POST",
                                "path": "/set-right",
                                "operation": "lookup",
                                "body": {"jsonpath": "$"}
                            }}},
                            {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "members_result"}}}
                        ]}
                    }}
                ]
            }
        ]
    });
    let pack_bytes = serde_json::to_vec(&pack).expect("normalized Adapter pack serializes");
    let pack_digest = registry_platform_config::sha256_uri(&pack_bytes);
    let pack_reference = PackReference {
        id: LocalId::new("normalized-retention").expect("pack id is valid"),
        version: "1".to_owned(),
    };
    let checked = |route: &str, facts_schema: Value| compile::CheckedPackRoute {
        pack: pack_reference.clone(),
        route: LocalId::new(route).expect("route id is valid"),
        digest: pack_digest.clone(),
        inputs_schema: inputs_schema.clone(),
        facts_schema,
        acquisition_posture: AcquisitionPosture::RecordTransformed,
        pack_bytes: pack_bytes.clone(),
        artifacts: artifacts.clone(),
    };
    vec![
        checked("records", records_facts),
        checked("classic", classic_facts),
        checked("members", members_facts),
    ]
}

fn definition<const O: usize, const A: usize, const R: usize>(
    requirement: &str,
    purpose: &str,
    binding: &str,
    origins: [&str; O],
    actor_kinds: [&str; A],
    representations: [&str; R],
) -> Value {
    json!({
        "question": "Is the synthetic record active?",
        "semantics": {
            "requirement": requirement,
            "kind": "criterion",
            "evidenceType": format!("urn:example:normalized:evidence:{}", purpose.trim_end_matches("-check")),
            "referenceFrameworks": ["urn:example:normalized:framework"]
        },
        "purpose": purpose,
        "grantCeiling": {
            "authorities": ["organizational"],
            "actorKinds": actor_kinds.as_slice(),
            "valueOrigins": origins.as_slice(),
            "audiences": [EVIDENCE_AUDIENCE]
        },
        "subjects": [{"role": "subject", "selectors": ["record-by-id"]}],
        "acquisition": {"source": "records"},
        "derive": {"function": "derive-active"},
        "outputs": {"active": {"concept": format!("urn:example:normalized:concept:active:{}", purpose.trim_end_matches("-check")), "type": "boolean"}},
        "validitySeconds": 300,
        "subjectBinding": binding,
        "representations": representations.as_slice(),
        "fixtures": "fixtures/normalized-cases.yaml"
    })
}

fn normalized_authority(include_optional_actor_profile: bool) -> EvidenceTargetAuthority {
    let mut document = json!({
        "target": "local",
        "project": "normalized-retention",
        "accessProfiles": {
            "direct": {
                "authority": "organizational",
                "actorKind": "service",
                "requesterTags": ["fixture-agency"],
                "grants": [
                    grant("audience", "audience-check", "audience-scoped", "request", ["signed-jws", "unsigned-json", "sd-jwt-vc"], None),
                    grant("holder", "holder-check", "holder-bound", "request", ["sd-jwt-vc", "sd-jwt-vc-batch"], None),
                    grant("context", "context-check", "audience-scoped", "authenticated-context", ["signed-jws"], Some("verified_context.record_id")),
                    grant("classic", "classic-check", "audience-scoped", "request", ["signed-jws"], None),
                    grant("fetch-set", "fetch-set-check", "audience-scoped", "request", ["signed-jws"], None)
                ]
            },
            "task": {
                "authority": "organizational",
                "requesterTags": ["fixture-agency"],
                "requesterClients": ["evidence-task-agent"],
                "grantSourceIssuer": "https://tasks.invalid",
                "grants": [
                    grant("grant", "grant-check", "audience-scoped", "authenticated-grant", ["signed-jws"], Some("grant.record_id"))
                ]
            }
        }
    });
    if include_optional_actor_profile {
        document["accessProfiles"]["actor-open"] = json!({
            "authority": "organizational",
            "requesterTags": ["fixture-agency"],
            "grants": [
                grant("actor", "actor-check", "audience-scoped", "request", ["signed-jws"], None)
            ]
        });
    }
    serde_json::from_value(document).expect("normalized target authority is structurally valid")
}

fn grant<const R: usize>(
    definition: &str,
    purpose: &str,
    binding: &str,
    origin: &str,
    representations: [&str; R],
    claim: Option<&str>,
) -> Value {
    let mut subject = json!({
        "role": "subject",
        "selectorProfile": "record-by-id",
        "valueOrigin": origin
    });
    if let Some(claim) = claim {
        subject["valueClaims"] = json!({"record-id": claim});
    }
    json!({
        "definition": definition,
        "purpose": purpose,
        "audienceFrom": "authenticated-requester",
        "representations": representations.as_slice(),
        "subjectBinding": binding,
        "subjects": [subject]
    })
}

fn scripts() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "functions/derive.rhai".to_owned(),
            r#"fn derive(facts, selectors, context) {
    [#{output: "active", value: facts["active"]}]
}"#
            .to_owned(),
        ),
        (
            "functions/derive-classic.rhai".to_owned(),
            r#"fn derive(facts, selectors, context) {
    [#{output: "active", value: facts.classic_active}]
}"#
            .to_owned(),
        ),
        (
            "functions/derive-members.rhai".to_owned(),
            r#"fn derive(facts, selectors, context) {
    [#{output: "active", value: facts.members_active}]
}"#
            .to_owned(),
        ),
    ])
}

pub(crate) fn authenticator() -> Authenticator {
    let private = PrivateJwk::parse(AUTH_PRIVATE_JWK).expect("authentication key parses");
    let jwks: JwkSet = serde_json::from_value(json!({"keys": [private.public()]}))
        .expect("static authentication JWKS parses");
    let fetcher = Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults()));
    let verifier = Arc::new(TokenVerifier::new(
        TokenVerifierConfig::access_token_profile(
            TOKEN_ISSUER,
            vec![TOKEN_AUDIENCE.to_owned()],
            vec![Algorithm::ES256],
            vec!["at+jwt".to_owned()],
        )
        .with_allowed_clients(vec!["evidence-task-agent".to_owned()]),
        fetcher,
    ));
    Authenticator::new(
        verifier,
        AuthenticationClaimsConfig {
            principal_claim: "sub".to_owned(),
            requester_tags_claim: "evidence_tags".to_owned(),
            evidence_audience_claim: "evidence_audience".to_owned(),
            contextual_claims: registry_platform_oidc::ClaimNames::default(),
            actor_claim: None,
        },
    )
    .with_resources(vec![TOKEN_AUDIENCE.to_owned()])
}

pub(crate) fn access_token(extra: Option<Value>) -> String {
    access_token_for_actor("service", extra)
}

fn access_token_for_actor(actor_kind: &str, extra: Option<Value>) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": "normalized-requester",
        "iat": now - 1,
        "exp": now + 298,
        "client_id": "evidence-task-agent",
        "registry_actor_kind": actor_kind,
        "evidence_tags": ["fixture-agency"],
        "evidence_audience": EVIDENCE_AUDIENCE
    });
    if let Some(Value::Object(extra)) = extra {
        claims
            .as_object_mut()
            .expect("claims are an object")
            .extend(extra);
    }
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({"alg": "ES256", "kid": "acceptance-auth-key", "typ": "at+jwt"}))
            .expect("JWT header serializes"),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims serialize"));
    let signing_input = format!("{header}.{payload}");
    let key = PrivateJwk::parse(AUTH_PRIVATE_JWK).expect("authentication key parses");
    let signature =
        URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes(), &key).expect("JWT signs"));
    format!("{signing_input}.{signature}")
}

fn task_grant_claims(record_id: &str) -> Value {
    task_grant_claims_for(record_id, REQUIREMENT_GRANT)
}

fn task_grant_claims_for(record_id: &str, requirement: &str) -> Value {
    task_grant_claims_for_purpose(record_id, requirement, "grant-check")
}

fn task_grant_claims_for_purpose(record_id: &str, requirement: &str, purpose: &str) -> Value {
    let now = Utc::now().timestamp();
    json!({
        "registry_actor_kind": "agent",
        "registry_grant_id": "normalized-task-grant",
        "registry_grant_source_issuer": "https://tasks.invalid",
        "registry_grant_client": "evidence-task-agent",
        "registry_grant_resource": TOKEN_AUDIENCE,
        "registry_purpose": purpose,
        "registry_grant_exp": now + 298,
        "registry_grant_bounds": {"type": "evidence", "requirement": requirement},
        "registry_approver": "h:normalized-approver",
        "grant": {"record_id": record_id}
    })
}

fn request(requirement: &str, purpose: &str, record_id: Option<&str>) -> EvidenceRequest {
    EvidenceRequest {
        request_nonce: fresh_nonce(),
        requirement: requirement.to_owned(),
        expected_configuration_revision: None,
        purpose: purpose.to_owned(),
        subjects: vec![subject(record_id)],
        holder_keys: Vec::new(),
    }
}

fn subject(record_id: Option<&str>) -> RequestedSubject {
    RequestedSubject {
        role: "subject".to_owned(),
        selector: RequestedSelector {
            profile: "record-by-id".to_owned(),
            values: record_id.map(|value| {
                BTreeMap::from([(
                    "record-id".to_owned(),
                    SelectorValue::String(value.to_owned()),
                )])
            }),
        },
    }
}

pub(crate) fn fresh_nonce() -> String {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&ulid::Ulid::generate().to_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

fn holder_key(public: &registry_platform_crypto::PublicJwk) -> HolderPublicKey {
    serde_json::from_value(serde_json::to_value(public).expect("public JWK serializes"))
        .expect("public JWK is an acceptable holder key")
}

fn holder_keys(count: usize) -> Vec<HolderPublicKey> {
    const COORDINATES: [(&str, &str); 3] = [
        (
            "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        ),
        (
            "RGUpcejDhxZcjveUXQ_f5ROhMoVgUsZA8lAQgGj_p_c",
            "qGIQUPRR3_DU1U4AtI9TTqsxy5sVZFYQe3S1whoMCVQ",
        ),
        (
            "Kh89S0sAKyna9LcIUwqbidX9F2fYAfEHo9yVnjnxz_8",
            "g_V0Cd3L9dBM6mV3A2opGUcpiLsUlZEYgGMlvy-BLlE",
        ),
    ];
    COORDINATES
        .into_iter()
        .take(count)
        .map(|(x, y)| {
            serde_json::from_value(json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}))
                .expect("holder key is valid")
        })
        .collect()
}

fn released_credential_payload(credential: &str) -> Value {
    let payload = credential
        .split('~')
        .next()
        .expect("credential carries an issuer JWT")
        .split('.')
        .nth(1)
        .expect("issuer JWT carries a payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("payload decodes"))
        .expect("payload parses")
}

pub(crate) fn decode_evidence(jws: &FlattenedJws) -> Evidence {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&jws.payload)
            .expect("JWS payload decodes"),
    )
    .expect("JWS payload is Evidence")
}

fn verification_policy(
    runtime: &EvidenceRuntime,
    request: &EvidenceRequest,
    serialized: &[u8],
) -> EvidenceVerificationPolicy {
    verification_policy_for(
        runtime,
        request,
        serialized,
        "urn:example:normalized:evidence:audience",
        CONCEPT_AUDIENCE,
    )
}

fn verification_policy_for(
    runtime: &EvidenceRuntime,
    request: &EvidenceRequest,
    serialized: &[u8],
    evidence_type: &str,
    concept: &str,
) -> EvidenceVerificationPolicy {
    let jws: FlattenedJws = serde_json::from_slice(serialized).expect("response is JWS JSON");
    let evidence = decode_evidence(&jws);
    let mut policy = EvidenceVerificationPolicy::from_accepted_transaction(
        &evidence,
        &request.request_nonce,
        300,
        Utc::now(),
        30,
    )
    .expect("transaction can seed bounded relying-party state");
    policy.assurance_profile = AssuranceProfile::EvidenceGrade;
    policy.issued_by = runtime.bundle().config.issuer.id.clone();
    policy.provided_by = runtime.bundle().config.service.provider_id.clone();
    policy.requirement = request.requirement.clone();
    policy.evidence_type = evidence_type.to_owned();
    policy.purpose = request.purpose.clone();
    policy.audience = EVIDENCE_AUDIENCE.to_owned();
    policy.configuration_revision = runtime
        .bundle()
        .configuration_revision(&request.requirement)
        .expect("definition revision exists")
        .to_owned();
    policy.expected_subjects = evidence
        .subjects
        .iter()
        .map(|subject| ExpectedSubject {
            role: subject.role.clone(),
            binding: subject.binding.clone(),
        })
        .collect();
    policy.expected_outputs = vec![ExpectedOutput {
        handle: "active".to_owned(),
        concept: concept.to_owned(),
        required: true,
        form: ExpectedValueForm::Boolean,
    }];
    policy
}

pub(crate) fn write_secret(root: &Path, name: &str, value: &str) {
    let path = root.join(name);
    fs::write(&path, value).expect("synthetic secret is written");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("synthetic secret is owner-only");
}

pub(crate) fn make_read_only(root: &Path) {
    for entry in fs::read_dir(root).expect("package directory is readable") {
        let path = entry.expect("package member is readable").path();
        if path.is_dir() {
            make_read_only(&path);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o500))
                .expect("package directory is sealed");
        } else {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
                .expect("package file is sealed");
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o500)).expect("package root is sealed");
}
