#![cfg(unix)]

//! Proof that this client and a real Evidence deployment agree.
//!
//! Every case here drives the actual runtime over loopback HTTP: the real
//! bundle loader, the real authenticator, the real authorization and selector
//! path, the real signer, and the real problem contract. The client's own
//! request types, discovery types, and problem parser are asserted against that
//! runtime rather than against a stub of this crate's making, so a disagreement
//! about a member name, a media type, a status code, or a policy field fails
//! here.
//!
//! The deployment is the tracked synthetic acceptance fixture, rewritten for the
//! local assurance profile. An externally driven runtime has to use the public
//! `initialize` seam, which builds the deployed authenticator and therefore
//! requires a loopback token issuer, which only the local profile permits.
//! Nothing in the fixture names a source product.

use std::{
    error::Error,
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use registry_evidence::{runtime::EvidenceRuntime, server};
use registry_evidence_client::{
    AssuranceProfile, ConceptForm, DefinitionCardinality, DefinitionKind, EvidenceClient,
    EvidenceClientConfig, EvidenceClientError, EvidenceDefinitionsDocument, EvidenceRequestSpec,
    PublicValue, SelectorField, SelectorValue, SelectorValueOrigin, StaticToken,
    SubjectExpectations, SubjectRequest, TransportKind, VerificationError,
    EVIDENCE_DEFINITIONS_SCHEMA_V1,
};
use registry_platform_crypto::{sign, PrivateJwk};
use serde_json::{json, Value};
use url::Url;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

/// Vocabulary the tracked acceptance fixture publishes.
const TOKEN_AUDIENCE: &str = "evidence-fixture";
const CONFIGURED_TAG: &str = "fixture-agency";
const REQUIREMENT: &str = "urn:example:fixture:requirement:adult-status:v1";
const SIGNING_KEY_ID: &str = "fixture-key-2026-01";

/// Vocabulary this suite chooses.
const RELYING_AUDIENCE: &str = "https://relying.invalid/procedure";
const PRINCIPAL: &str = "client-suite-principal";
const AUTH_KEY_ID: &str = "client-suite-auth-key";
const SOURCE_BEARER: &str = "source-bearer-canary";

/// Prefix the runtime gives every published subject binding.
const BINDING_PREFIX: &str = "urn:evidence:subject:v1_";

/// The requirement states a validity of exactly one day. The verifier refuses an
/// assertion whose lifetime exceeds the policy's own maximum, and the comparison
/// is strict, so the exact configured validity is an accepted policy.
const MAXIMUM_ASSERTION_LIFETIME_SECONDS: u64 = 86_400;
const CLOCK_SKEW_SECONDS: u64 = 30;

/// A source answer that resolves to exactly one record.
fn resolved_source_answer() -> Value {
    json!({"total": 1, "date_of_birth": "2000-01-01"})
}

/// A source answer that resolves to no record. The public contract collapses
/// this with ambiguity and with a missing fact into one unavailable answer.
fn unresolved_source_answer() -> Value {
    json!({"total": 0})
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

/// The first exchange has no binding to pin, so it adopts the one the response
/// carries; the second pins what the first exposed. This is the whole documented
/// workflow, against a deployment that computes bindings with a secret the
/// relying party never holds.
#[tokio::test]
async fn first_use_acceptance_then_pinning_completes_two_verified_exchanges() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let first = client.prepare(spec(
            &definitions,
            "first-use",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let accepted = client.request_and_verify(&first).await?;

        let pinned = accepted.pinned_subject_expectations();
        let second = client.prepare(spec(
            &definitions,
            "first-use",
            SubjectExpectations::Pinned(pinned.clone()),
        ))?;
        let repinned = client.request_and_verify(&second).await?;
        Ok((
            accepted,
            pinned,
            repinned,
            first.request_nonce().to_owned(),
            second.request_nonce().to_owned(),
        ))
    }
    .await;
    let (accepted, pinned, repinned, first_nonce, second_nonce) =
        proof.expect("the deployment answers and the response verifies");

    let evidence = accepted.evidence();
    assert_eq!(evidence.assurance_profile, AssuranceProfile::Local);
    assert_eq!(evidence.supports_requirement, REQUIREMENT);
    assert_eq!(evidence.audience, RELYING_AUDIENCE);
    assert_eq!(evidence.request_nonce, first_nonce);
    assert_eq!(evidence.subjects.len(), 1);
    assert_eq!(evidence.subjects[0].role, "subject");
    assert!(
        evidence.subjects[0].binding.starts_with(BINDING_PREFIX),
        "the published binding uses the versioned prefix"
    );
    assert_eq!(evidence.supported_values.len(), 1);
    assert_eq!(
        evidence.supported_values[0].value,
        PublicValue::Boolean(true)
    );
    assert!(
        accepted
            .operation()
            .is_some_and(|operation| operation.bytes().all(|byte| byte.is_ascii_alphanumeric())),
        "the exchange carries an opaque correlation identifier"
    );

    // Persisting the accepted bindings and pinning them is what turns the next
    // answer about another subject into a verification failure.
    assert_eq!(pinned.len(), 1);
    assert_eq!(pinned[0].role, "subject");
    assert_eq!(pinned[0].binding, evidence.subjects[0].binding);
    assert_eq!(repinned.evidence().request_nonce, second_nonce);
    assert_eq!(
        repinned.evidence().subjects[0].binding,
        evidence.subjects[0].binding,
        "the same subject keeps the same binding across exchanges"
    );
    assert_ne!(
        first_nonce, second_nonce,
        "each prepared request is its own"
    );
}

/// The property pinning exists for: once a binding is pinned, an assertion about
/// another subject is refused even though it is correctly signed, correctly
/// scoped, and answers this exact request.
#[tokio::test]
async fn a_pinned_binding_refuses_an_assertion_about_another_subject() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let request = client.prepare(spec(
            &definitions,
            "known-subject",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let known = client.request_and_verify(&request).await?;

        // The same request shape, a different subject, and the first subject's
        // binding pinned.
        let other = client.prepare(spec(
            &definitions,
            "other-subject",
            SubjectExpectations::Pinned(known.pinned_subject_expectations()),
        ))?;
        Ok((
            known.pinned_subject_expectations(),
            client.request_and_verify(&other).await,
        ))
    }
    .await;
    let (pinned, refusal) = proof.expect("both exchanges reach the deployment");

    assert_eq!(
        refusal.expect_err("the pinned expectation refuses the other subject"),
        EvidenceClientError::Verification(VerificationError::Policy),
    );
    assert!(pinned[0].binding.starts_with(BINDING_PREFIX));
}

/// Discovery is authoring input, and these are the client's own closed types
/// reading it. A runtime that renamed a member, changed a case convention, or
/// published a shape outside the closed set would fail to deserialize.
#[tokio::test]
async fn discovery_publishes_shapes_this_client_parses_exactly() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());
    let definitions = client
        .discover()
        .await
        .expect("the deployment publishes the requester's definitions");

    assert_eq!(definitions.schema, EVIDENCE_DEFINITIONS_SCHEMA_V1);
    assert_eq!(definitions.assurance_profile, AssuranceProfile::Local);
    assert!(definitions.configuration_revision.starts_with("sha256:"));
    assert_eq!(definitions.definitions.len(), 1);

    let definition = definitions
        .definition(REQUIREMENT)
        .expect("the requester is entitled to the fixture requirement");
    assert_eq!(definition.kind, DefinitionKind::Criterion);
    assert_eq!(definition.purpose, "fixture-eligibility");
    assert_eq!(definition.subjects.len(), 1);
    assert_eq!(
        definition.subjects[0].cardinality,
        DefinitionCardinality::One
    );
    assert_eq!(
        definition.subjects[0].selector.value_origin,
        SelectorValueOrigin::Request
    );
    assert!(
        !definition.subjects[0].selector.fields.is_empty(),
        "a request-origin selector publishes its fields"
    );
    assert_eq!(definition.concepts.len(), 1);
    assert_eq!(definition.concepts[0].form, ConceptForm::Boolean);
    assert!(
        definition.concepts[0].scalar_expected_output().is_some(),
        "a boolean concept yields a scalar expectation"
    );
}

/// The published key set is discovery, not a trust anchor: this proves the
/// fetched document is the deployment's own, which is what makes an out-of-band
/// review of it meaningful. Verification still uses only the pinned set.
#[tokio::test]
async fn the_published_key_set_is_the_deployments_own() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());
    let published = client
        .fetch_jwks()
        .await
        .expect("the deployment publishes its verification keys");

    assert_eq!(&published, deployment.runtime.jwks());
    assert_eq!(published.keys.len(), 1);
    assert_eq!(published.keys[0]["kid"], json!(SIGNING_KEY_ID));
    assert_eq!(
        published.keys[0].get("d"),
        None,
        "the published key set carries no private material"
    );
}

/// A credential the issuer did not sign is refused, and the refusal names only
/// the closed public code.
#[tokio::test]
async fn a_tampered_credential_is_refused_without_detail() {
    let deployment = start(resolved_source_answer()).await;
    let mut tampered = deployment.token();
    let last = tampered.pop().expect("the credential has a signature");
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    let client = deployment.client(&tampered);

    let error = client
        .discover()
        .await
        .expect_err("a credential that fails signature verification is refused");
    let EvidenceClientError::Denied {
        status,
        code,
        operation,
        retry_after_seconds,
    } = error
    else {
        panic!("the refusal maps onto the denied failure");
    };
    assert_eq!(status, 401);
    assert_eq!(code, "authentication_failed");
    assert!(operation.is_some_and(|operation| !operation.is_empty()));
    assert_eq!(retry_after_seconds, None);
}

/// A valid credential the deployment does not entitle is refused at the request
/// endpoint. Discovery answers it, with nothing in it.
#[tokio::test]
async fn a_credential_without_the_configured_tag_is_refused() {
    let deployment = start(resolved_source_answer()).await;
    let entitled = deployment.client(&deployment.token());
    let unentitled = deployment.client(&deployment.token_with_tags(&["other-agency"]));

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = entitled.discover().await?;
        let visible = unentitled.discover().await?;
        let prepared = unentitled.prepare(spec(
            &definitions,
            "unentitled",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        Ok((visible, unentitled.request_and_verify(&prepared).await))
    }
    .await;
    let (visible, refusal) = proof.expect("both callers authenticate");

    assert!(
        visible.definitions.is_empty(),
        "discovery lists only what the caller may invoke"
    );
    let EvidenceClientError::Denied { status, code, .. } =
        refusal.expect_err("an unentitled caller cannot request evidence")
    else {
        panic!("the refusal maps onto the denied failure");
    };
    assert_eq!(status, 403);
    assert_eq!(code, "not_authorized");
}

/// The unavailable answer is its own failure, distinct from a refusal, and it
/// must not be read as a statement about the subject.
#[tokio::test]
async fn a_request_the_deployment_cannot_answer_reports_no_evidence() {
    let deployment = start(unresolved_source_answer()).await;
    let client = deployment.client(&deployment.token());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let prepared = client.prepare(spec(
            &definitions,
            "unresolved",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        Ok(client.request_and_verify(&prepared).await)
    }
    .await;
    let refusal = proof.expect("the deployment answers");

    let EvidenceClientError::NotAvailable { operation } =
        refusal.expect_err("an unresolved request produces no evidence")
    else {
        panic!("the unavailable answer maps onto its own failure");
    };
    assert!(operation.is_some_and(|operation| !operation.is_empty()));
}

/// A nonce identifies exactly one request. A real signed response that verifies
/// against its own prepared request must not verify against another one, which
/// is why a retry has to be a fresh `prepare` rather than a resend.
#[tokio::test]
async fn a_response_cannot_verify_against_another_prepared_request() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let sent = client.prepare(spec(
            &definitions,
            "nonce-check",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let other = client.prepare(spec(
            &definitions,
            "nonce-check",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let response = client.send(&sent).await?;
        Ok((
            client.verify(&sent, &response),
            client.verify(&other, &response),
        ))
    }
    .await;
    let (own, foreign) = proof.expect("the deployment answers the request that was sent");

    own.expect("the response verifies against the request it answered");
    assert_eq!(
        foreign.expect_err("the response cannot answer a request it never saw"),
        EvidenceClientError::Verification(VerificationError::Policy),
    );
}

/// The same bytes that verify from the deployment are refused when they arrive
/// under a media type the response contract does not use. The real runtime
/// cannot emit that, so the replay comes from a stub; the bytes are the
/// runtime's own.
#[tokio::test]
async fn a_response_under_the_wrong_media_type_is_refused() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let prepared = client.prepare(spec(
            &definitions,
            "media-type",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        let response = client.send(&prepared).await?;
        client.verify(&prepared, &response)?;

        let replay = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/evidence"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(response.body().to_vec(), "application/json"),
            )
            .mount(&replay)
            .await;
        let replayed = EvidenceClient::new(EvidenceClientConfig::new(
            Url::parse(&replay.uri())?,
            Arc::new(StaticToken::new(deployment.token())?),
            deployment.runtime.jwks().clone(),
        ))?;
        // A prepared request is good for one send, and the one above is spent,
        // so the replay leg carries its own. The media type is refused before
        // anything about the request is compared to anything in the response.
        let replayed_request = replayed.prepare(spec(
            &definitions,
            "media-type",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        Ok(replayed.send(&replayed_request).await)
    }
    .await;
    let refusal = proof.expect("the deployment answers and the stub replays");

    let EvidenceClientError::Protocol { status, code, .. } =
        refusal.expect_err("a response outside the contract's media type is refused")
    else {
        panic!("a contract violation maps onto the protocol failure");
    };
    assert_eq!(status, 200);
    assert_eq!(code, None);
}

/// The response bound is the relying party's, enforced before the body is
/// parsed.
#[tokio::test]
async fn a_response_beyond_the_configured_bound_is_refused() {
    let deployment = start(resolved_source_answer()).await;
    let client = deployment.client(&deployment.token());
    let bounded = deployment.bounded_client(&deployment.token(), 64);

    let proof: Result<_, Box<dyn Error>> = async {
        let definitions = client.discover().await?;
        let prepared = bounded.prepare(spec(
            &definitions,
            "bounded",
            SubjectExpectations::AcceptFirstUse,
        ))?;
        Ok(bounded.send(&prepared).await)
    }
    .await;
    let refusal = proof.expect("the deployment answers");

    assert_eq!(
        refusal.expect_err("a response past the bound is refused"),
        EvidenceClientError::Transport {
            kind: TransportKind::ResponseTooLarge
        },
    );
}

// ---------------------------------------------------------------------------
// Request specifications
// ---------------------------------------------------------------------------

/// Build a request specification from the deployment's own definitions
/// document.
///
/// Everything except the audience and the subject expectations comes from the
/// published definition, which is what a relying party reads once while
/// authoring its procedure. The audience is the relying party's own registered
/// identifier, which the deployment takes from the authenticated caller.
fn spec(
    definitions: &EvidenceDefinitionsDocument,
    subject_label: &str,
    subject_expectations: SubjectExpectations,
) -> EvidenceRequestSpec {
    let definition = definitions
        .definition(REQUIREMENT)
        .expect("the requester is entitled to the fixture requirement");
    EvidenceRequestSpec {
        requirement: definition.requirement.clone(),
        purpose: definition.purpose.clone(),
        audience: RELYING_AUDIENCE.to_owned(),
        evidence_type: definition.evidence_type.clone(),
        issued_by: definitions.issued_by.clone(),
        provided_by: definitions.provided_by.clone(),
        configuration_revision: definitions.configuration_revision.clone(),
        expected_assurance_profile: definitions.assurance_profile,
        subjects: definition
            .subjects
            .iter()
            .map(|subject| SubjectRequest {
                role: subject.role.clone(),
                selector_profile: subject.selector.profile.clone(),
                selector_values: Some(
                    subject
                        .selector
                        .fields
                        .iter()
                        .map(|field| {
                            (
                                field.name().to_owned(),
                                selector_value(field, subject_label),
                            )
                        })
                        .collect(),
                ),
            })
            .collect(),
        expected_outputs: definition
            .concepts
            .iter()
            .map(|concept| {
                concept
                    .scalar_expected_output()
                    .expect("the fixture publishes one scalar concept")
            })
            .collect(),
        maximum_assertion_lifetime_seconds: MAXIMUM_ASSERTION_LIFETIME_SECONDS,
        clock_skew_seconds: CLOCK_SKEW_SECONDS,
        subject_expectations,
    }
}

/// A synthetic value for one published selector field.
///
/// Selector values are the relying party's own lookup input. The fixed source in
/// this suite answers on method and path alone, so only the published field
/// metadata constrains them, and two different labels name two different
/// subjects to the deployment.
fn selector_value(field: &SelectorField, subject_label: &str) -> SelectorValue {
    match field {
        SelectorField::String {
            name,
            minimum_bytes,
            maximum_bytes,
        } => {
            let value = format!("synthetic-{subject_label}");
            let length = u64::try_from(value.len()).expect("the value length fits");
            assert!(
                (*minimum_bytes..=*maximum_bytes).contains(&length),
                "the synthetic value for {name} is within the published bounds"
            );
            SelectorValue::from(value)
        }
        SelectorField::Date { .. } => SelectorValue::from("2000-01-01"),
        SelectorField::Integer { minimum, .. } => SelectorValue::from(*minimum),
        SelectorField::Boolean { .. } => SelectorValue::from(true),
        SelectorField::ControlledCode { name, .. } => {
            panic!("the fixture selector profile publishes no controlled code field: {name}")
        }
    }
}

// ---------------------------------------------------------------------------
// The deployment harness
// ---------------------------------------------------------------------------

/// One real Evidence deployment, serving on loopback for the life of one test.
struct Deployment {
    /// Both the token issuer's key source and the deployment's fixed source.
    /// One server keeps the issuer on the canonical loopback origin the local
    /// assurance profile requires, and its uri is that origin.
    _source: MockServer,
    issuer: String,
    auth_key: PrivateJwk,
    base_url: Url,
    runtime: Arc<EvidenceRuntime>,
    bundle_root: PathBuf,
    runtime_path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    /// Held so the deployment on disk outlives the runtime that reads it.
    _directory: tempfile::TempDir,
}

impl Deployment {
    /// A client pinned to this deployment's published verification keys.
    ///
    /// Pinning the runtime's own key set is the out-of-band review this suite
    /// stands in for: the keys are taken from the runtime object, not from the
    /// response being verified.
    fn client(&self, access_token: &str) -> EvidenceClient {
        self.build_client(access_token, None)
    }

    /// The same client under a smaller response bound.
    fn bounded_client(&self, access_token: &str, max_response_bytes: u64) -> EvidenceClient {
        self.build_client(access_token, Some(max_response_bytes))
    }

    fn build_client(&self, access_token: &str, max_response_bytes: Option<u64>) -> EvidenceClient {
        let mut config = EvidenceClientConfig::new(
            self.base_url.clone(),
            Arc::new(StaticToken::new(access_token).expect("the credential is header-safe")),
            self.runtime.jwks().clone(),
        );
        if let Some(max_response_bytes) = max_response_bytes {
            config = config.with_max_response_bytes(max_response_bytes);
        }
        EvidenceClient::new(config).expect("the client configuration is usable")
    }

    /// A credential the deployment entitles.
    fn token(&self) -> String {
        self.token_with_tags(&[CONFIGURED_TAG])
    }

    /// A credential this issuer signed, carrying the requester tags given.
    fn token_with_tags(&self, requester_tags: &[&str]) -> String {
        let now = Utc::now().timestamp();
        let claims = json!({
            "iss": self.issuer,
            "aud": TOKEN_AUDIENCE,
            "sub": PRINCIPAL,
            "iat": now - 1,
            "exp": now + 3600,
            "evidence_tags": requester_tags,
            "evidence_audience": RELYING_AUDIENCE,
        });
        let header = json!({"alg": "EdDSA", "kid": AUTH_KEY_ID, "typ": "at+jwt"});
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("the header serializes")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("the claims serialize")),
        );
        let signature = sign(signing_input.as_bytes(), &self.auth_key).expect("the issuer signs");
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        // A drop cannot await the graceful stop, so the task is abandoned
        // rather than joined. The temporary deployment it reads is removed
        // below, and the process ends with the test binary.
        self.server.abort();
        // The runtime requires an immutable deployment, so the staged tree was
        // sealed. Restoring write permission is what lets the temporary
        // directory be removed; a failure here leaves a directory behind for
        // the test host to reclaim, and a drop has nowhere to report it.
        let _ = fs::set_permissions(&self.runtime_path, fs::Permissions::from_mode(0o644));
        unseal(&self.bundle_root);
    }
}

/// Stage, seal, load, and serve one deployment whose fixed source answers with
/// `source_answer`.
async fn start(source_answer: Value) -> Deployment {
    let source = MockServer::start().await;
    let issuer = source.uri();
    let auth_key = generate_key(AUTH_KEY_ID);

    // The issuer's key set and the fixed source share this origin. Under the
    // local assurance profile the authentication issuer must be a canonical
    // loopback HTTP origin, which is exactly what a wiremock server publishes.
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"keys": [auth_key.public()]})),
        )
        .mount(&source)
        .await;
    // Matched on method and path only. The request the adapter builds is the
    // runtime's own contract, proven by the runtime's suite; re-pinning it here
    // would test the fixture rather than this client.
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(source_answer))
        .mount(&source)
        .await;

    // Hold the allocation while the matching deployment is authored, and
    // release it only immediately before the service binds it.
    let reservation = TcpListener::bind(("127.0.0.1", 0)).expect("reserve a loopback port");
    let port = reservation
        .local_addr()
        .expect("read the reserved address")
        .port();

    let directory = tempfile::tempdir().expect("temporary deployment root");
    let bundle_root = directory.path().join("bundle");
    let secret_root = directory.path().join("secrets");
    let runtime_path = directory.path().join("runtime.yaml");
    let audit_path = directory.path().join("audit.jsonl");
    fs::create_dir(&bundle_root).expect("create the bundle root");
    fs::create_dir(&secret_root).expect("create the secret root");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("the secret root is owner-only");
    copy_tree(&fixture_root(), &bundle_root);
    rewrite_for_local_profile(&bundle_root, &issuer);

    write_secret(
        &secret_root,
        "audit-hash-key",
        "audit-hash-secret-canary-32-bytes-minimum",
    );
    write_secret(
        &secret_root,
        "subject-binding-key",
        "subject-binding-secret-canary-32-bytes-minimum",
    );
    write_secret(&secret_root, "signing-key", &private_jwk(SIGNING_KEY_ID));
    write_secret(&secret_root, "source-a-token", SOURCE_BEARER);
    fs::write(
        &runtime_path,
        runtime_document(port, &bundle_root, &secret_root, &audit_path),
    )
    .expect("write the runtime configuration");
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
        .expect("the runtime configuration is immutable");
    seal(&bundle_root);

    let runtime = Arc::new(
        EvidenceRuntime::initialize(&runtime_path)
            .await
            .expect("the staged local deployment initializes"),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let served = Arc::clone(&runtime);
    drop(reservation);
    let server = tokio::spawn(async move {
        server::serve(served, async {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let deployment = Deployment {
        _source: source,
        issuer,
        auth_key,
        base_url: Url::parse(&format!("http://127.0.0.1:{port}")).expect("the base URL parses"),
        runtime,
        bundle_root,
        runtime_path,
        shutdown: Some(shutdown_tx),
        server,
        _directory: directory,
    };
    await_readiness(&deployment).await;
    deployment
}

/// Wait until the deployment reports itself ready, or fail with the reason it
/// did not.
async fn await_readiness(deployment: &Deployment) {
    let probe = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .expect("the readiness probe client builds");
    let ready = deployment
        .base_url
        .join("ready")
        .expect("the readiness URL resolves");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                !deployment.server.is_finished(),
                "the deployment stopped before it reported readiness"
            );
            if probe
                .get(ready.clone())
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the deployment reports readiness");
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/fixtures/acceptance/adult-status")
}

/// Point the staged bundle at this test's issuer and source, and lower it to the
/// local assurance profile.
///
/// The local profile is what permits a loopback token issuer. Every other
/// security decision in the bundle, including authentication, authorization,
/// selector validation, subject binding, signing, and audit, is unchanged.
fn rewrite_for_local_profile(bundle_root: &Path, origin: &str) {
    let configuration_path = bundle_root.join("evidence.yaml");
    let mut document =
        fs::read_to_string(&configuration_path).expect("the staged configuration is readable");
    replace_exact(
        &mut document,
        "assuranceProfile: evidence-grade",
        "assuranceProfile: local",
        1,
    );
    replace_exact(
        &mut document,
        "baseUrl: https://source.invalid",
        &format!("baseUrl: {origin}"),
        1,
    );
    replace_exact(
        &mut document,
        "issuer: https://identity.invalid",
        &format!("issuer: {origin}"),
        1,
    );
    replace_exact(
        &mut document,
        "jwksUri: https://identity.invalid/.well-known/jwks.json",
        &format!("jwksUri: {origin}/.well-known/jwks.json"),
        1,
    );
    fs::write(&configuration_path, document).expect("the local configuration is written");
}

fn runtime_document(
    port: u16,
    bundle_root: &Path,
    secret_root: &Path,
    audit_path: &Path,
) -> String {
    format!(
        r#"version: 1
bundleDirectory: {bundle}
listener:
  bindHost: 127.0.0.1
  port: {port}
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file:
    root: {secrets}
auditStorage:
  path: {audit}
  maximumFileBytes: 10485760
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
"#,
        bundle = bundle_root.display(),
        secrets = secret_root.display(),
        audit = audit_path.display(),
    )
}

/// A fresh Ed25519 private JWK under the identifier the reader expects.
fn private_jwk(key_id: &str) -> String {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("the test host supplies randomness");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": key_id,
        "d": URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
    })
    .to_string()
}

fn generate_key(key_id: &str) -> PrivateJwk {
    PrivateJwk::parse(&private_jwk(key_id)).expect("the generated key parses")
}

fn replace_exact(document: &mut String, from: &str, to: &str, expected: usize) {
    assert_eq!(
        document.matches(from).count(),
        expected,
        "fixture drift for {from}"
    );
    *document = document.replace(from, to);
}

fn write_secret(secret_root: &Path, name: &str, value: &str) {
    let path = secret_root.join(name);
    fs::write(&path, value.as_bytes()).expect("write the synthetic secret");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("the synthetic secret is owner-only");
}

fn copy_tree(source: &Path, target: &Path) {
    for entry in fs::read_dir(source).expect("the tracked fixture is readable") {
        let entry = entry.expect("the fixture entry is readable");
        let destination = target.join(entry.file_name());
        if entry
            .file_type()
            .expect("the fixture file type is readable")
            .is_dir()
        {
            fs::create_dir(&destination).expect("copy the fixture directory");
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy the fixture file");
        }
    }
}

/// Make the staged bundle immutable, as the runtime requires.
fn seal(root: &Path) {
    for entry in fs::read_dir(root).expect("the staged bundle is readable") {
        let entry = entry.expect("the staged entry is readable");
        let child = entry.path();
        if entry
            .file_type()
            .expect("the staged file type is readable")
            .is_dir()
        {
            seal(&child);
            fs::set_permissions(&child, fs::Permissions::from_mode(0o555))
                .expect("the bundle directory is immutable");
        } else {
            fs::set_permissions(&child, fs::Permissions::from_mode(0o444))
                .expect("the bundle file is immutable");
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o555))
        .expect("the bundle root is immutable");
}

/// Restore write permission so the temporary directory can be removed.
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
            let _ = fs::set_permissions(&child, fs::Permissions::from_mode(0o644));
        }
    }
}
