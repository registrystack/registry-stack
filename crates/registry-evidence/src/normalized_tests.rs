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
    io::{Read as _, Write as _},
    os::unix::fs::PermissionsExt as _,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use axum_test::TestServer;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::Utc;
use jsonwebtoken::{jwk::JwkSet, Algorithm};
use p256::ecdsa::{
    signature::hazmat::PrehashSigner as _, Signature as P256Signature, SigningKey as P256SigningKey,
};
use registry_evidence_authoring::{
    compile,
    project::EvidenceProject,
    target::{self, EvidenceTargetAuthority},
};
use registry_platform_crypto::{sign, PrivateJwk};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use serde_json::{json, Value};
use tempfile::TempDir;
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
const EVIDENCE_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
const EVIDENCE_PUBLIC_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
const HOLDER_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","alg":"ES256","kid":"holder-proof-key"}"#;
const TOKEN_ISSUER: &str = "https://identity.invalid";
const TOKEN_AUDIENCE: &str = "evidence-fixture";
const EVIDENCE_AUDIENCE: &str = "https://relying.invalid/procedure";
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
    transit: TransitServer,
    _temporary: TempDir,
    runtime: Arc<EvidenceRuntime>,
    source: MockServer,
    audit_path: PathBuf,
}

struct TransitServer {
    stop: Arc<AtomicBool>,
    signatures: Arc<AtomicUsize>,
    socket: PathBuf,
    worker: Option<thread::JoinHandle<()>>,
}

impl TransitServer {
    fn start(root: &Path) -> Self {
        let socket = root.join("transit.sock");
        let listener = UnixListener::bind(&socket).expect("bind synthetic Transit socket");
        listener
            .set_nonblocking(true)
            .expect("synthetic Transit listener is nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let signatures = Arc::new(AtomicUsize::new(0));
        let worker_stop = Arc::clone(&stop);
        let worker_signatures = Arc::clone(&signatures);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if worker_stop.load(Ordering::Acquire) {
                            break;
                        }
                        stream
                            .set_nonblocking(false)
                            .expect("synthetic Transit connection is blocking");
                        serve_transit_request(&mut stream, &worker_signatures);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("synthetic Transit accept failed: {error}"),
                }
            }
        });
        Self {
            stop,
            signatures,
            socket,
            worker: Some(worker),
        }
    }

    fn signatures(&self) -> usize {
        self.signatures.load(Ordering::Acquire)
    }
}

impl Drop for TransitServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = UnixStream::connect(&self.socket);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("synthetic Transit server stops");
        }
    }
}

fn serve_transit_request(stream: &mut UnixStream, signatures: &AtomicUsize) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("synthetic Transit read timeout");
    let Some((method, path, body)) = read_transit_request(stream) else {
        return;
    };
    let document = match (method.as_str(), path.as_str()) {
        ("GET", "/v1/transit/keys/evidence-signing") => transit_metadata(),
        ("POST", "/v1/transit/sign/evidence-signing/sha2-256") => {
            let response = transit_signature(&body);
            signatures.fetch_add(1, Ordering::AcqRel);
            response
        }
        _ => panic!("unexpected synthetic Transit request {method} {path}"),
    };
    let bytes = serde_json::to_vec(&document).expect("synthetic Transit response serializes");
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )
    .expect("synthetic Transit response headers write");
    stream
        .write_all(&bytes)
        .expect("synthetic Transit response body writes");
}

fn read_transit_request(stream: &mut UnixStream) -> Option<(String, String, Vec<u8>)> {
    let mut request = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 4096];
        let read = match stream.read(&mut chunk) {
            Ok(0) if request.is_empty() => return None,
            Err(error)
                if request.is_empty()
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
            {
                return None;
            }
            Ok(read) => read,
            Err(error) => panic!("read Transit request: {error}"),
        };
        assert_ne!(read, 0, "Transit request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        assert!(request.len() <= 128 * 1024, "Transit request is bounded");
        if let Some(position) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&request[..header_end]).expect("Transit headers are UTF-8");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("x-vault-request: true"),
        "Transit request marks the trusted proxy hop"
    );
    let mut lines = headers.lines();
    let mut request_line = lines
        .next()
        .expect("Transit request line")
        .split_whitespace();
    let method = request_line.next().expect("Transit method").to_owned();
    let path = request_line.next().expect("Transit path").to_owned();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().expect("content length"))
        .unwrap_or(0);
    assert!(content_length <= 64 * 1024, "Transit body is bounded");
    while request.len() < header_end + content_length {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).expect("read Transit request body");
        assert_ne!(read, 0, "Transit request body ended early");
        request.extend_from_slice(&chunk[..read]);
    }
    Some((
        method,
        path,
        request[header_end..header_end + content_length].to_vec(),
    ))
}

fn transit_metadata() -> Value {
    json!({
        "data": {
            "type": "ecdsa-p256",
            "derived": false,
            "exportable": false,
            "allow_plaintext_backup": false,
            "supports_signing": true,
            "latest_version": 1,
            "min_encryption_version": 1,
            "keys": {"1": {"public_key": transit_public_pem()}}
        }
    })
}

fn transit_signature(body: &[u8]) -> Value {
    let request: Value = serde_json::from_slice(body).expect("Transit signing request is JSON");
    assert_eq!(request["key_version"], "1");
    assert_eq!(request["marshaling_algorithm"], "jws");
    assert_eq!(request["prehashed"], true);
    let digest = STANDARD
        .decode(request["input"].as_str().expect("Transit input is present"))
        .expect("Transit input is standard base64");
    assert_eq!(digest.len(), 32, "Transit signs one SHA-256 digest");
    let private: Value = serde_json::from_str(EVIDENCE_PRIVATE_JWK).expect("private JWK parses");
    let scalar = URL_SAFE_NO_PAD
        .decode(private["d"].as_str().expect("private scalar is present"))
        .expect("private scalar is base64url");
    let key = P256SigningKey::from_slice(&scalar).expect("private scalar is P-256");
    let signature: P256Signature = key
        .sign_prehash(&digest)
        .expect("synthetic Transit signs the prehash");
    json!({
        "data": {
            "signature": format!("vault:v1:{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
        }
    })
}

fn transit_public_pem() -> String {
    let public: Value = serde_json::from_str(EVIDENCE_PUBLIC_JWK).expect("public JWK parses");
    let x = URL_SAFE_NO_PAD
        .decode(public["x"].as_str().expect("public x is present"))
        .expect("public x is base64url");
    let y = URL_SAFE_NO_PAD
        .decode(public["y"].as_str().expect("public y is present"))
        .expect("public y is base64url");
    assert_eq!(x.len(), 32);
    assert_eq!(y.len(), 32);
    let mut spki = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    spki.extend_from_slice(&x);
    spki.extend_from_slice(&y);
    let encoded = STANDARD.encode(spki);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("PEM base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n")
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
async fn normalized_compiler_retains_source_batch_and_authenticated_provenance() {
    let fixture = normalized_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

    Mock::given(method("POST"))
        .and(path("/records"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"slot": 2, "result": {"outcome": "match", "facts": {"active": true}}},
                {"slot": 0, "result": {"outcome": "match", "facts": {"active": true}}},
                {"slot": 1, "result": {"outcome": "match", "facts": {"active": false}}}
            ]
        })))
        .expect(1)
        .mount(&fixture.source)
        .await;
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
    let optimized = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&request_batch)
        .await;
    optimized.assert_status_ok();
    let optimized: EvidenceRequestBatchResponse =
        serde_json::from_str(&optimized.text()).expect("request batch parses");
    let values = optimized
        .items
        .iter()
        .map(|item| match item {
            EvidenceRequestBatchResponseItem::Evidence { evidence } => {
                decode_evidence(evidence).supported_values[0].value.clone()
            }
            EvidenceRequestBatchResponseItem::EvidenceNotAvailable => {
                panic!("the synthetic source resolves every member")
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        values,
        vec![
            PublicValue::Boolean(true),
            PublicValue::Boolean(false),
            PublicValue::Boolean(true)
        ],
        "opaque slots restore logical request order"
    );
    assert_eq!(
        fixture
            .source
            .received_requests()
            .await
            .expect("source journal is available")
            .len(),
        1,
        "the compiled source-batch capability makes one physical call"
    );
    let physical = fixture
        .source
        .received_requests()
        .await
        .expect("source journal is available");
    let body: Value = serde_json::from_slice(&physical[0].body).expect("batch body is JSON");
    assert_eq!(
        body["requests"]
            .as_array()
            .expect("batch carries logical requests")
            .len(),
        3
    );
    assert_eq!(
        body["requests"][1]["selectors"]["subject"]["values"]["record-id"], "batch-b",
        "the normalized batch function receives minimized selector provenance"
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
async fn normalized_compiler_retains_classic_and_set_search_acquisition() {
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
    let temporary = tempfile::tempdir().expect("temporary normalized deployment");
    let package_root = temporary.path().join("package");
    let secret_root = temporary.path().join("secrets");
    let authority_root = temporary.path().join("authority");
    let runtime_path = temporary.path().join("runtime.yaml");
    let audit_path = temporary.path().join("audit.jsonl");
    fs::create_dir(&package_root).expect("package root is created");
    fs::create_dir(&secret_root).expect("secret root is created");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("secret root is private");

    let project = normalized_project();
    let compiled = compile::compile(&project, &scripts()).expect("normalized project compiles");
    let mut bundle: Value = serde_norway::from_slice(include_bytes!(
        "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
    ))
    .expect("retained target governance parses");
    let bundle_object = bundle.as_object_mut().expect("bundle is an object");
    for model_member in [
        "project",
        "acquisitionCapabilities",
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
            "baseUrl": source.uri(),
            "authentication": {"type": "static-authorization", "tokenRef": "secret:file/source-token"},
            "maximumConcurrency": 8
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
    for compiled_source in bundle["sources"]
        .as_object_mut()
        .expect("compiled sources are an object")
        .values_mut()
    {
        compiled_source["baseUrl"] = json!(source.uri());
        compiled_source["authentication"] =
            json!({"type": "static-authorization", "tokenRef": "secret:file/source-token"});
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
    let transit = TransitServer::start(temporary.path());
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
acquisitionCapabilities: [source-batch, search-then-fetch-set]
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
"#,
            package_root.display(),
            secret_root.display(),
            transit.socket.display(),
            audit_path.display(),
            authority_root.display()
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
        _temporary: temporary,
        runtime,
        source,
        audit_path,
    }
}

fn normalized_project() -> EvidenceProject {
    let mut document = json!({
        "id": "normalized-retention",
        "acquisitionCapabilities": ["source-batch", "search-then-fetch-set"],
        "maximumHolderBoundBatchSize": 2,
        "selectorProfiles": {
            "record-by-id": {
                "maximumAggregateBytes": 64,
                "fields": {"record-id": {"type": "string", "minimumBytes": 1, "maximumBytes": 64}}
            }
        },
        "functions": [
            {"id": "prepare-record", "interface": "source-prepare/v1", "source": "functions/prepare.rhai"},
            {"id": "extract-record", "interface": "source-extract/v1", "source": "functions/extract.rhai"},
            {"id": "prepare-record-batch", "interface": "source-prepare/v1", "source": "functions/prepare-batch.rhai"},
            {"id": "extract-record-batch", "interface": "source-extract/v1", "source": "functions/extract-batch.rhai"},
            {"id": "derive-active", "interface": "assertion-derive/v1", "source": "functions/derive.rhai"}
        ],
        "sources": {
            "records": {
                "type": "http-json",
                "connection": "records",
                "acquisitionPosture": "record-transformed",
                "selectors": [{"role": "subject", "profiles": ["record-by-id"]}],
                "request": {"method": "POST", "path": "/records", "fixedHeaders": [{"name": "Accept", "value": "application/json"}]},
                "response": {
                    "projection": ["/active"],
                    "shape": {"type": "object", "required": ["active"], "properties": {"active": {"type": "boolean"}}},
                    "maximumBytes": 4096
                },
                "prepare": {"function": "prepare-record"},
                "extract": {"function": "extract-record"},
                "facts": {"active": {"type": "boolean"}},
                "limits": {"attemptTimeoutMilliseconds": 2000, "maximumConcurrency": 8},
                "adapterParameters": {},
                "adapterParametersSchema": {"type": "object", "additionalProperties": false, "properties": {}, "required": []},
                "preparationLimits": {"query": "forbidden", "jsonBody": "required", "maximumJsonDepth": 8, "maximumCollectionItems": 16, "maximumStringBytes": 128, "maximumNormalizedBytes": 4096},
                "batch": {
                    "maximumItems": 4,
                    "prepare": {"function": "prepare-record-batch"},
                    "extract": {"function": "extract-record-batch"},
                    "response": {
                        "projection": ["/results/*"],
                        "shape": {
                            "type": "object",
                            "required": ["results"],
                            "properties": {
                                "results": {
                                    "type": "array",
                                    "maxItems": 4,
                                    "items": {
                                        "type": "object",
                                        "required": ["slot", "result"],
                                        "properties": {
                                            "slot": {"type": "integer", "minimum": 0, "maximum": 3},
                                            "result": {
                                                "type": "object",
                                                "required": ["outcome", "facts"],
                                                "properties": {
                                                    "outcome": {"type": "string", "values": ["match", "no_match", "ambiguous"]},
                                                    "facts": {
                                                        "type": "object",
                                                        "required": ["active"],
                                                        "properties": {"active": {"type": "boolean"}}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
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
    document["functions"]
        .as_array_mut()
        .expect("Functions are a sequence")
        .extend([
            json!({"id": "prepare-search", "interface": "source-prepare/v1", "source": "functions/prepare-search.rhai"}),
            json!({"id": "extract-search", "interface": "source-extract/v1", "source": "functions/extract-search.rhai"}),
            json!({"id": "prepare-classic-fetch", "interface": "source-prepare/v1", "source": "functions/prepare-classic-fetch.rhai"}),
            json!({"id": "extract-classic-fetch", "interface": "source-extract/v1", "source": "functions/extract-classic-fetch.rhai"}),
            json!({"id": "prepare-set-left", "interface": "source-prepare/v1", "source": "functions/prepare-set-left.rhai"}),
            json!({"id": "extract-set-left", "interface": "source-extract/v1", "source": "functions/extract-set-left.rhai"}),
            json!({"id": "prepare-set-right", "interface": "source-prepare/v1", "source": "functions/prepare-set-right.rhai"}),
            json!({"id": "extract-set-right", "interface": "source-extract/v1", "source": "functions/extract-set-right.rhai"}),
            json!({"id": "derive-classic", "interface": "assertion-derive/v1", "source": "functions/derive-classic.rhai"}),
            json!({"id": "derive-set", "interface": "assertion-derive/v1", "source": "functions/derive-set.rhai"}),
        ]);
    document["sources"]["search"] = chained_source(
        "/search",
        "prepare-search",
        "extract-search",
        ["found", "search_ok", "classic_ref", "left_ref", "right_ref"],
        json!({
            "found": {"type": "boolean"},
            "search_ok": {"type": "boolean"},
            "classic_ref": {"type": "string", "minimumBytes": 1, "maximumBytes": 64},
            "left_ref": {"type": "string", "minimumBytes": 1, "maximumBytes": 64},
            "right_ref": {"type": "string", "minimumBytes": 1, "maximumBytes": 64}
        }),
        json!({
            "search_ok": {"type": "boolean"},
            "classic_ref": {"type": "string", "minimumBytes": 1, "maximumBytes": 64},
            "left_ref": {"type": "string", "minimumBytes": 1, "maximumBytes": 64},
            "right_ref": {"type": "string", "minimumBytes": 1, "maximumBytes": 64}
        }),
    );
    document["sources"]["classic-fetch"] = chained_source(
        "/classic-fetch",
        "prepare-classic-fetch",
        "extract-classic-fetch",
        ["active"],
        json!({"active": {"type": "boolean"}}),
        json!({"classic_active": {"type": "boolean"}}),
    );
    document["sources"]["set-left"] = chained_source(
        "/set-left",
        "prepare-set-left",
        "extract-set-left",
        ["active"],
        json!({"active": {"type": "boolean"}}),
        json!({"left_active": {"type": "boolean"}}),
    );
    document["sources"]["set-right"] = chained_source(
        "/set-right",
        "prepare-set-right",
        "extract-set-right",
        ["active"],
        json!({"active": {"type": "boolean"}}),
        json!({"right_active": {"type": "boolean"}}),
    );
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
    classic["acquisition"] =
        json!({"type": "search-then-fetch", "search": "search", "fetch": "classic-fetch"});
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
    fetch_set["acquisition"] = json!({
        "type": "search-then-fetch-set",
        "search": "search",
        "fetch": [
            {"source": "set-left", "factInputs": ["left_ref"]},
            {"source": "set-right", "factInputs": ["right_ref"]}
        ],
        "maximumAcquisitionMilliseconds": 8000
    });
    fetch_set["derive"] = json!({"function": "derive-set"});
    document["assertionDefinitions"]["fetch-set"] = fetch_set;
    serde_json::from_value(document).expect("normalized project is structurally valid")
}

fn chained_source<const N: usize>(
    path: &str,
    prepare: &str,
    extract: &str,
    projected: [&str; N],
    properties: Value,
    facts: Value,
) -> Value {
    let projection = projected
        .iter()
        .map(|name| format!("/{name}"))
        .collect::<Vec<_>>();
    let required = projected.to_vec();
    json!({
        "type": "http-json",
        "connection": "records",
        "acquisitionPosture": "record-transformed",
        "selectors": [{"role": "subject", "profiles": ["record-by-id"]}],
        "request": {"method": "POST", "path": path, "fixedHeaders": [{"name": "Accept", "value": "application/json"}]},
        "response": {
            "projection": projection,
            "shape": {"type": "object", "required": required, "properties": properties},
            "maximumBytes": 4096
        },
        "prepare": {"function": prepare},
        "extract": {"function": extract},
        "facts": facts,
        "limits": {"attemptTimeoutMilliseconds": 2000, "maximumConcurrency": 8},
        "adapterParameters": {},
        "adapterParametersSchema": {"type": "object", "additionalProperties": false, "properties": {}, "required": []},
        "preparationLimits": {"query": "forbidden", "jsonBody": "required", "maximumJsonDepth": 8, "maximumCollectionItems": 16, "maximumStringBytes": 128, "maximumNormalizedBytes": 4096}
    })
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
        "acquisition": {"type": "single", "source": "records"},
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
            "functions/prepare.rhai".to_owned(),
            r#"fn prepare(selectors, context) {
    #{query: [], body: #{record_id: selectors["subject"]["values"]["record-id"]}}
}"#
            .to_owned(),
        ),
        (
            "functions/extract.rhai".to_owned(),
            r#"fn extract(response, context) {
    #{outcome: "match", facts: #{active: response["active"]}}
}"#
            .to_owned(),
        ),
        (
            "functions/prepare-batch.rhai".to_owned(),
            r#"fn prepare(items, context) {
    #{query: [], body: #{requests: items}}
}"#
            .to_owned(),
        ),
        (
            "functions/extract-batch.rhai".to_owned(),
            r#"fn extract(response, context) {
    response["results"]
}"#
            .to_owned(),
        ),
        (
            "functions/derive.rhai".to_owned(),
            r#"fn derive(facts, selectors, context) {
    [#{output: "active", value: facts["active"]}]
}"#
            .to_owned(),
        ),
        (
            "functions/prepare-search.rhai".to_owned(),
            r#"fn prepare(selectors, context) {
    #{query: [], body: #{record_id: selectors["subject"]["values"]["record-id"]}}
}"#
            .to_owned(),
        ),
        (
            "functions/extract-search.rhai".to_owned(),
            r#"fn extract(response, context) {
    if !response["found"] { return #{outcome: "no_match"}; }
    #{outcome: "match", facts: #{
        search_ok: response["search_ok"],
        classic_ref: response["classic_ref"],
        left_ref: response["left_ref"],
        right_ref: response["right_ref"]
    }}
}"#
            .to_owned(),
        ),
        (
            "functions/prepare-classic-fetch.rhai".to_owned(),
            r#"fn prepare(selectors, context) {
    #{query: [], body: #{
        classic_ref: context.prior_facts.classic_ref,
        left_ref: context.prior_facts.left_ref,
        right_ref: context.prior_facts.right_ref,
        search_ok: context.prior_facts.search_ok
    }}
}"#
            .to_owned(),
        ),
        (
            "functions/extract-classic-fetch.rhai".to_owned(),
            r#"fn extract(response, context) {
    #{outcome: "match", facts: #{classic_active: response["active"]}}
}"#
            .to_owned(),
        ),
        (
            "functions/prepare-set-left.rhai".to_owned(),
            r#"fn prepare(selectors, context) {
    #{query: [], body: #{resolved_ref: context.prior_facts.left_ref}}
}"#
            .to_owned(),
        ),
        (
            "functions/extract-set-left.rhai".to_owned(),
            r#"fn extract(response, context) {
    #{outcome: "match", facts: #{left_active: response["active"]}}
}"#
            .to_owned(),
        ),
        (
            "functions/prepare-set-right.rhai".to_owned(),
            r#"fn prepare(selectors, context) {
    #{query: [], body: #{resolved_ref: context.prior_facts.right_ref}}
}"#
            .to_owned(),
        ),
        (
            "functions/extract-set-right.rhai".to_owned(),
            r#"fn extract(response, context) {
    #{outcome: "match", facts: #{right_active: response["active"]}}
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
            "functions/derive-set.rhai".to_owned(),
            r#"fn derive(facts, selectors, context) {
    [#{output: "active", value:
        facts.search_ok
        && facts.classic_ref == "classic-private-ref"
        && facts.left_ref == "left-private-ref"
        && facts.right_ref == "right-private-ref"
        && facts.left_active
        && facts.right_active
    }]
}"#
            .to_owned(),
        ),
    ])
}

fn authenticator() -> Authenticator {
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

fn access_token(extra: Option<Value>) -> String {
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

fn fresh_nonce() -> String {
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

fn decode_evidence(jws: &FlattenedJws) -> Evidence {
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

fn write_secret(root: &Path, name: &str, value: &str) {
    let path = root.join(name);
    fs::write(&path, value).expect("synthetic secret is written");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("synthetic secret is owner-only");
}

fn make_read_only(root: &Path) {
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
