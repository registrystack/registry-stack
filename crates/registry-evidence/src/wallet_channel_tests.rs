//! The holder-presented channel through the whole runtime: `build_app`, the
//! real deployment loader, a pack that reaches the `wallet-presentation-v1`
//! host protocol, and a wiremock double of the OpenID4VP read endpoint that
//! serves the closed read response the protocol parses.
#![cfg(feature = "wallet-presentation")]
use super::*;
use crate::model::ChannelKind;
use registry_evidence_client::{
    ChannelPolicy, EvidenceRequestSpec, EvidenceResponseFormat, ExpectedFormDocument,
    ExpectedOutputDocument, ExpectedScalarFormDocument, PreparedEvidenceRequest,
    RetainedEvidenceVerification, SubjectExpectations, SubjectRequest,
};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use sha2::{Digest, Sha256};

const ISSUER: &str = "https://issuer.example";
const CREDENTIAL_TYPE: &str = "https://issuer.example/vct/identity";
const TRUST_ENTRY: &str = "agency-a";
const CLIENT_ID: &str = "x509_san_dns:verifier.example";
const POLICY_ID: &str = "identity-check";
const QUERY_ID: &str = "identity";
const PRESENTATION_NONCE: &str = "oid4vp-nonce-7d1f3a9c-canary";
const SESSION_REFERENCE: &str = "session-reference-5521-canary";
const SECOND_SESSION_REFERENCE: &str = "session-reference-8847-canary";
const APPLICANT_ISSUER: &str = "https://idp.example";
const APPLICANT_SUBJECT: &str = "applicant-0042-canary";
const OTHER_APPLICANT_SUBJECT: &str = "applicant-9999-canary";
const BIRTH_DATE_CLAIM: &str = "2001-02-03";
const TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
const WALLET_TOKEN: &str = "wallet-read-token-canary";
pub(super) const ADULT_REQUIREMENT: &str = "urn:example:fixture:requirement:adult-status:v1";
const ELIGIBILITY_PURPOSE: &str = "fixture-eligibility";
pub(super) const SESSION_PROFILE: &str = "session-reference-v1";
const WALLET_POLICY_ONE_DAY: u32 = 86_400;

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn object(value: Value) -> serde_json::Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => panic!("not an object"),
    }
}

fn compact(
    header: &serde_json::Map<String, Value>,
    payload: &serde_json::Map<String, Value>,
    key: &PrivateJwk,
) -> String {
    let input = format!(
        "{}.{}",
        b64(&serde_json::to_vec(header).unwrap()),
        b64(&serde_json::to_vec(payload).unwrap())
    );
    let signature = sign(input.as_bytes(), key).unwrap();
    format!("{input}.{}", b64(&signature))
}

/// An SD-JWT VC issuer the channel trusts, pinned by key.
pub(super) struct TrustedIssuer {
    key: PrivateJwk,
}

impl TrustedIssuer {
    pub(super) fn generate() -> Self {
        Self {
            key: generate_private_jwk(GeneratedKeyAlgorithm::Ed25519).unwrap(),
        }
    }

    fn keys(&self) -> Value {
        let mut public = serde_json::to_value(self.key.public()).unwrap();
        public["kid"] = json!("issuer-key-1");
        json!({"jwks": [public]})
    }
}

/// The instants one presentation is built around, in Unix seconds.
#[derive(Clone, Copy)]
struct Times {
    now: i64,
    issued_at: i64,
    expires_at: i64,
}

impl Times {
    /// A credential issued a little before now that outlives the assertion.
    fn long_lived() -> Self {
        let now = Utc::now().timestamp();
        Self {
            now,
            issued_at: now - 100,
            expires_at: now + 3600,
        }
    }

    fn expiring_in(seconds: i64) -> Self {
        let mut times = Self::long_lived();
        times.expires_at = times.now + seconds;
        times
    }
}

/// A key-bound presentation of the identity credential, signed by `signer`.
fn presentation(signer: &PrivateJwk, times: Times) -> String {
    let holder = generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap();
    let mut holder_public = serde_json::to_value(holder.public()).unwrap();
    holder_public.as_object_mut().unwrap().remove("kid");
    holder_public.as_object_mut().unwrap().remove("alg");
    let disclosure =
        b64(
            &serde_json::to_vec(&json!(["salt-birthdate", "birthdate", BIRTH_DATE_CLAIM])).unwrap(),
        );
    let digest = b64(&Sha256::digest(disclosure.as_bytes()));
    let payload = object(json!({
        "iss": ISSUER, "vct": CREDENTIAL_TYPE,
        "iat": times.issued_at, "exp": times.expires_at,
        "cnf": {"jwk": holder_public},
        "_sd": [digest], "_sd_alg": "sha-256",
    }));
    let header = object(json!({"alg": "EdDSA", "typ": "dc+sd-jwt", "kid": "issuer-key-1"}));
    let mut out = compact(&header, &payload, signer);
    out.push('~');
    out.push_str(&disclosure);
    out.push('~');
    let claims = object(json!({
        "iat": times.now, "aud": CLIENT_ID, "nonce": PRESENTATION_NONCE,
        "sd_hash": b64(&Sha256::digest(out.as_bytes())),
    }));
    let kb_header = object(json!({"alg": "ES256", "typ": "kb+jwt"}));
    out.push_str(&compact(&kb_header, &claims, &holder));
    out
}

fn applicant() -> Value {
    json!({"issuer": APPLICANT_ISSUER, "subject": APPLICANT_SUBJECT})
}

/// The closed read response the oid4vp service answers with.
fn read_response(presentation: &str, created_by: &Value, now: i64) -> Value {
    json!({
        "presentation": {QUERY_ID: [presentation]},
        "context": {
            "nonce": PRESENTATION_NONCE,
            "clientId": CLIENT_ID,
            "responseUri": "https://verifier.example/response",
            "responseKeyThumbprint": "thumbprint",
            "policyId": POLICY_ID,
            "createdBy": created_by,
            "receivedAt": DateTime::from_timestamp(now, 0).unwrap().to_rfc3339(),
        }
    })
}

fn wallet_response(body: &Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("traceparent", TRACEPARENT)
        .set_body_raw(serde_json::to_vec(body).unwrap(), "application/json")
}

/// The read request the route must send for the applicant, exactly.
fn expected_read_request(reference: &str) -> Value {
    json!({"reference": reference, "principal": applicant()})
}

async fn mount_read(wallet: &MockServer, response: ResponseTemplate, expected: u64) {
    mount_read_for(wallet, SESSION_REFERENCE, response, expected).await;
}

async fn mount_read_for(
    wallet: &MockServer,
    reference: &str,
    response: ResponseTemplate,
    expected: u64,
) {
    Mock::given(method("POST"))
        .and(path("/v1/presentations/read"))
        .and(header("accept", "application/json"))
        .and(header(
            "authorization",
            format!("Bearer {WALLET_TOKEN}").as_str(),
        ))
        .and(body_json(expected_read_request(reference)))
        .respond_with(response)
        .expect(expected)
        .mount(wallet)
        .await;
}

/// The deployment variants a proof needs.
pub(super) struct Deployment {
    pub(super) maximum_credential_age_seconds: u32,
    /// The claims the protocol configuration projects from a presentation.
    pub(super) disclosed_claims: &'static [&'static str],
    /// Edits the governed configuration before it is sealed.
    pub(super) edit: fn(&mut Value),
    /// Whether the edited configuration is expected to be readable, so its
    /// discovery description can be regenerated.
    pub(super) regenerate_discovery: bool,
}

impl Deployment {
    pub(super) fn standard() -> Self {
        Self {
            maximum_credential_age_seconds: WALLET_POLICY_ONE_DAY,
            disclosed_claims: &["birthdate"],
            edit: |_| {},
            regenerate_discovery: true,
        }
    }

    fn with_maximum_credential_age(seconds: u32) -> Self {
        Self {
            maximum_credential_age_seconds: seconds,
            ..Self::standard()
        }
    }
}

pub(super) struct WalletRuntime {
    prepared: PreparedFixture,
    source: MockServer,
    wallet: MockServer,
    pub(super) runtime: Arc<EvidenceRuntime>,
}

impl WalletRuntime {
    pub(super) async fn start(issuer: &TrustedIssuer, deployment: &Deployment) -> Self {
        let (source, wallet, prepared) = prepare_wallet_deployment(issuer, deployment).await;
        let runtime = Arc::new(
            EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
                .await
                .expect("the holder-presented deployment initializes"),
        );
        Self {
            prepared,
            source,
            wallet,
            runtime,
        }
    }

    fn http(&self) -> TestServer {
        TestServer::new(build_app(Arc::clone(&self.runtime)))
    }

    fn audit(&self) -> String {
        fs::read_to_string(&self.prepared.audit_path).expect("audit is readable")
    }

    async fn source_requests(&self) -> usize {
        self.source
            .received_requests()
            .await
            .expect("the source journal is available")
            .len()
    }

    async fn wallet_requests(&self) -> usize {
        self.wallet
            .received_requests()
            .await
            .expect("the read endpoint journal is available")
            .len()
    }
}

/// The acceptance bundle with a second Source that reaches the wallet
/// presentation protocol, a session-reference selector profile and grant, and
/// both channels declared on the adult-status requirement.
async fn prepare_wallet_deployment(
    issuer: &TrustedIssuer,
    deployment: &Deployment,
) -> (MockServer, MockServer, PreparedFixture) {
    let source = MockServer::start().await;
    let wallet = MockServer::start().await;
    let prepared = prepare_fixture_with_pack_variant(
        "wallet-channel-binding-secret-32-bytes-minimum",
        &source.uri(),
        &FixtureCeilings::deployment_defaults(),
        AcceptancePackVariant::Base,
        |_| {},
    );
    make_writable(&prepared.bundle_root);
    make_file_writable(&prepared.runtime_path);

    let (pack_digest, prefix) = install_wallet_pack(&prepared.bundle_root, issuer, deployment);
    let config_path = prepared.bundle_root.join("evidence.yaml");
    let mut config: Value = serde_norway::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    declare_wallet_channel(&mut config, &wallet.uri(), &pack_digest, &prefix);
    (deployment.edit)(&mut config);
    fs::write(&config_path, serde_norway::to_string(&config).unwrap()).unwrap();
    if deployment.regenerate_discovery {
        regenerate_discovery_description(&prepared.bundle_root);
    }
    bind_wallet_connection(&prepared, &wallet.uri());
    refresh_package_envelope(&prepared.bundle_root);
    make_file_read_only(&prepared.runtime_path);
    make_read_only(&prepared.bundle_root);
    (source, wallet, prepared)
}

/// Write the wallet pack closure into the bundle and return its digest and
/// artifact prefix.
fn install_wallet_pack(
    bundle_root: &Path,
    issuer: &TrustedIssuer,
    deployment: &Deployment,
) -> (String, String) {
    const REQUEST: &str = r#"fn wallet_request(exchange) {
    let input = exchange.body;
    #{reference: input.session_reference, principal: #{issuer: input.applicant_issuer, subject: input.applicant_subject}}
}
"#;
    const LOOKUP: &str = r#"fn wallet_lookup(exchange) {
    let birth_date = exchange.body["values"]["birthdate"];
    if birth_date == () { throw "source_protocol_error"; }
    #{lookup: "matched", facts: #{date_of_birth: birth_date}}
}
"#;
    let protocol = serde_json::to_vec(&json!({
        "policyId": POLICY_ID,
        "clientId": CLIENT_ID,
        "credentialQueryId": QUERY_ID,
        "trust": [{
            "id": TRUST_ENTRY, "issuer": ISSUER,
            "vct": [CREDENTIAL_TYPE], "keys": issuer.keys()
        }],
        "deny": {"issuers": [], "certificateSha256": []},
        "policy": {"vct": [CREDENTIAL_TYPE], "keyBindingRequired": true},
        "disclosedClaims": deployment.disclosed_claims,
        "status": "not-checked",
        "maximumCredentialAgeSeconds": deployment.maximum_credential_age_seconds,
        "subjectLink": "possession"
    }))
    .unwrap();
    let text = json!({"type": "string"});
    let inputs = serde_json::to_vec(&json!({
        "type": "object", "additionalProperties": false,
        "required": ["session_reference", "applicant_issuer", "applicant_subject"],
        "properties": {
            "session_reference": text, "applicant_issuer": text, "applicant_subject": text
        }
    }))
    .unwrap();
    let facts = fs::read(bundle_root.join("schemas/adult-status-facts.schema.yaml"))
        .expect("the adult-status facts schema is readable");
    let artifacts = BTreeMap::from([
        ("protocols/wallet-presentation.json", protocol),
        ("schemas/wallet-inputs.json", inputs),
        ("schemas/wallet-facts.json", facts),
        ("scripts/wallet-request.rhai", REQUEST.as_bytes().to_vec()),
        ("scripts/wallet-lookup.rhai", LOOKUP.as_bytes().to_vec()),
    ]);
    let digest = |path: &str| registry_platform_config::sha256_uri(&artifacts[path]);
    let pack = json!({
        "apiVersion": "id.registrystack.org/formats/adapter/pack/v1alpha1",
        "kind": "AdapterPack",
        "id": "wallet-pack",
        "version": "1",
        "testedVersions": [],
        "endpoints": [{
            "id": "wallet",
            "component": "http",
            "authentication": {"type": "static-authorization"},
            "attemptTimeoutMilliseconds": 3000,
            "maximumResponseBytes": 65536,
            "requestHeaders": [],
            "responseHeaders": [],
            "operations": [{"id": "read", "safeUpstream": true}],
            "hostProtocol": {
                "id": "wallet-presentation-v1",
                "config": {
                    "path": "protocols/wallet-presentation.json",
                    "digest": digest("protocols/wallet-presentation.json")
                }
            },
            "testedVersions": []
        }],
        "sourceRoutes": [{
            "id": "wallet",
            "evidence": {
                "inputsSchema": {"path": "schemas/wallet-inputs.json", "digest": digest("schemas/wallet-inputs.json")},
                "factsSchema": {"path": "schemas/wallet-facts.json", "digest": digest("schemas/wallet-facts.json")},
                "acquisitionPosture": "field-projected"
            },
            "steps": [
                {"setBody": {"rhai": {"file": "scripts/wallet-request.rhai", "entrypoint": "wallet_request"}}},
                {"to": {"uri": "http:wallet", "parameters": {"httpMethod": "POST", "path": "/v1/presentations/read", "operation": "read", "body": {"jsonpath": "$"}}}},
                {"setBody": {"rhai": {"file": "scripts/wallet-lookup.rhai", "entrypoint": "wallet_lookup"}}}
            ]
        }],
        "scripts": [
            {"path": "scripts/wallet-request.rhai", "digest": digest("scripts/wallet-request.rhai")},
            {"path": "scripts/wallet-lookup.rhai", "digest": digest("scripts/wallet-lookup.rhai")}
        ],
        "capabilities": {
            "components": ["http"],
            "languages": ["constant", "jsonpath", "rhai"],
            "eips": ["setBody", "to"]
        }
    });
    let pack_bytes = serde_json::to_vec(&pack).unwrap();
    let pack_digest = registry_platform_config::sha256_uri(&pack_bytes);
    let prefix = format!(
        "adapter-packs/wallet-pack/{}",
        pack_digest.strip_prefix("sha256:").unwrap()
    );
    let root = bundle_root.join(&prefix);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("pack.yaml"), pack_bytes).unwrap();
    for (relative, bytes) in &artifacts {
        let target = root.join(relative);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
    (pack_digest, prefix)
}

/// Declare the session-reference selector profile, its Source, its grant and
/// the second channel on the adult-status requirement.
fn declare_wallet_channel(
    config: &mut Value,
    wallet_origin: &str,
    pack_digest: &str,
    prefix: &str,
) {
    let field =
        |maximum: u32| json!({"type": "string", "minimumBytes": 1, "maximumBytes": maximum});
    config["selectorProfiles"][SESSION_PROFILE] = json!({
        "maximumAggregateBytes": 640,
        "fields": {
            "session_reference": field(128),
            "applicant_issuer": field(256),
            "applicant_subject": field(128),
        }
    });
    config["sourceConnections"]["wallet"] = json!({"endpoints": [{
        "endpoint": "wallet", "baseUrl": wallet_origin,
        "clientIdentity": "forbidden", "authentication": {"type": "static-authorization"}
    }]});
    let binding = |name: &str| json!({"selector": {"role": "subject", "profile": SESSION_PROFILE, "field": name}});
    config["sources"]["wallet-source"] = json!({
        "pack": {"id": "wallet-pack", "version": "1", "digest": pack_digest, "artifactPrefix": prefix},
        "route": "wallet",
        "connection": "wallet",
        "inputs": {
            "session_reference": binding("session_reference"),
            "applicant_issuer": binding("applicant_issuer"),
            "applicant_subject": binding("applicant_subject"),
        },
        "posture": "field-projected",
        "factSchema": "schemas/adult-status-facts.schema.yaml",
    });
    config["authorityProfiles"][AUTHORITY]["grants"]
        .as_array_mut()
        .expect("the authority profile declares grants")
        .push(json!({
            "requirement": ADULT_REQUIREMENT,
            "purpose": ELIGIBILITY_PURPOSE,
            "audienceFrom": "authenticated-requester",
            "responseFormats": ["signed-jws"],
            "subjects": [{
                "role": "subject",
                "selectorProfile": SESSION_PROFILE,
                "valueOrigin": "request",
            }],
        }));
    let requirement = configuration_requirement_mut(config, "adult-status");
    requirement["acquisition"] = json!({
        "source": "source-a",
        "holderPresented": {"source": "wallet-source", "selectorProfiles": [SESSION_PROFILE]},
    });
    // A holder-presented definition answers only as signed JWS.
    requirement["representations"] = json!(["signed-jws"]);
    requirement["subjectRoles"][0]["selectorProfiles"]
        .as_array_mut()
        .expect("the role lists its selector profiles")
        .push(json!(SESSION_PROFILE));
}

/// Bind the wallet connection in the runtime file and write its credential.
fn bind_wallet_connection(prepared: &PreparedFixture, wallet_origin: &str) {
    write_secret(
        &prepared.temporary.path().join("secrets"),
        "wallet-token",
        WALLET_TOKEN,
    );
    let mut runtime: Value =
        serde_norway::from_slice(&fs::read(&prepared.runtime_path).unwrap()).unwrap();
    runtime["sourceConnections"]["wallet"] = json!({
        "id": "wallet",
        "endpoints": [{
            "endpoint": "wallet",
            "baseUrl": wallet_origin,
            "credential": {"type": "static-authorization", "tokenRef": "secret:file/wallet-token"},
        }],
        "allowedPrivateCidrs": [],
    });
    fs::write(
        &prepared.runtime_path,
        serde_norway::to_string(&runtime).unwrap(),
    )
    .unwrap();
}

fn session_request() -> EvidenceRequest {
    session_request_for(SESSION_REFERENCE)
}

fn session_request_for(reference: &str) -> EvidenceRequest {
    request(
        ADULT_REQUIREMENT,
        ELIGIBILITY_PURPOSE,
        vec![requested_subject(
            "subject",
            SESSION_PROFILE,
            Some([
                ("session_reference", reference),
                ("applicant_issuer", APPLICANT_ISSUER),
                ("applicant_subject", APPLICANT_SUBJECT),
            ]),
        )],
    )
}

fn bearer(request: axum_test::TestRequest) -> axum_test::TestRequest {
    request.add_header("authorization", format!("Bearer {}", access_token(None)))
}

fn authorized(request: axum_test::TestRequest) -> axum_test::TestRequest {
    bearer(request).add_header("accept", EVIDENCE_JWS_MEDIA_TYPE)
}

/// The relying party's client-side specification for the adult-status
/// definition on the session-reference profile. The expectations come from the
/// loaded bundle, independently of the response they will judge.
fn client_spec(runtime: &EvidenceRuntime) -> EvidenceRequestSpec {
    let config = &runtime.bundle().config;
    let requirement = config
        .requirements
        .iter()
        .find(|requirement| requirement.id == ADULT_REQUIREMENT)
        .expect("the adult-status requirement is loaded");
    EvidenceRequestSpec {
        response_format: EvidenceResponseFormat::SignedJws,
        requirement: requirement.id.clone(),
        purpose: ELIGIBILITY_PURPOSE.to_owned(),
        audience: EVIDENCE_AUDIENCE.to_owned(),
        evidence_type: requirement.evidence_type.clone(),
        issued_by: config.issuer.id.clone(),
        provided_by: config.service.provider_id.clone(),
        configuration_revision: runtime
            .bundle()
            .configuration_revision(ADULT_REQUIREMENT)
            .expect("the loaded requirement has a revision")
            .to_owned(),
        expected_assurance_profile: config.assurance_profile,
        subjects: vec![SubjectRequest {
            role: "subject".to_owned(),
            selector_profile: SESSION_PROFILE.to_owned(),
            selector_values: Some(vec![
                ("session_reference".to_owned(), SESSION_REFERENCE.into()),
                ("applicant_issuer".to_owned(), APPLICANT_ISSUER.into()),
                ("applicant_subject".to_owned(), APPLICANT_SUBJECT.into()),
            ]),
        }],
        holder_keys: Vec::new(),
        expected_outputs: vec![ExpectedOutputDocument {
            handle: "is_adult".to_owned(),
            concept: "urn:example:fixture:concept:adult-status".to_owned(),
            required: true,
            form: ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean),
        }],
        maximum_assertion_lifetime_seconds: 300,
        clock_skew_seconds: 30,
        subject_expectations: SubjectExpectations::AcceptFirstUse,
    }
}

fn instant_of(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).unwrap()
}

/// Request the adult-status assertion on the session-reference profile through
/// the relying party's client, returning both verification contexts and the
/// raw response: one under the default channel policy, one accepting
/// holder-presented.
async fn client_exchange(
    fixture: &WalletRuntime,
    http: &TestServer,
) -> (
    RetainedEvidenceVerification,
    RetainedEvidenceVerification,
    Vec<u8>,
) {
    let prepared =
        PreparedEvidenceRequest::prepare(client_spec(&fixture.runtime), Vec::new()).expect("spec");
    let jwks = serde_json::from_value(serde_json::to_value(fixture.runtime.jwks()).unwrap())
        .expect("the published key set is the client's trusted set");
    let default_policy = RetainedEvidenceVerification::from_prepared(&prepared, jwks).unwrap();
    let prepared = prepared
        .with_channel_policy(ChannelPolicy {
            accepted_channels: vec![ChannelKind::HolderPresented],
            maximum_credential_age_seconds: None,
        })
        .expect("the channel policy is in bounds");
    let jwks = serde_json::from_value(serde_json::to_value(fixture.runtime.jwks()).unwrap())
        .expect("the published key set is the client's trusted set");
    let accepting = RetainedEvidenceVerification::from_prepared(&prepared, jwks).unwrap();
    let body: Value = serde_json::from_slice(&prepared.claim_request_json().unwrap()).unwrap();
    let response = authorized(http.post("/v1/evidence")).json(&body).await;
    response.assert_status_ok();
    (default_policy, accepting, response.as_bytes().to_vec())
}

fn decoded(response: &[u8]) -> Evidence {
    decode_evidence(&serde_json::from_slice::<FlattenedJws>(response).expect("a flattened JWS"))
}

fn valid_until(evidence: &Evidence) -> DateTime<Utc> {
    evidence
        .valid_until
        .parse()
        .expect("validUntil is RFC 3339")
}

#[tokio::test]
async fn a_holder_presented_request_returns_a_signed_assertion_that_states_its_channel() {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, &Deployment::standard()).await;
    let times = Times::expiring_in(120);
    mount_read(
        &fixture.wallet,
        wallet_response(&read_response(
            &presentation(&issuer.key, times),
            &applicant(),
            times.now,
        )),
        1,
    )
    .await;
    let http = fixture.http();

    let (default_policy, accepting, response) = client_exchange(&fixture, &http).await;

    let verified = accepting
        .verify_as_of(&response, Utc::now())
        .expect("a relying party that accepts holder-presented verifies the assertion");
    assert_eq!(verified.channel(), ChannelKind::HolderPresented);
    let credential = verified
        .presented_credential()
        .expect("a holder-presented assertion carries its credential");
    assert_eq!(credential.trust_entry, TRUST_ENTRY);
    assert_eq!(credential.issuer, ISSUER);
    assert_eq!(credential.credential_type, CREDENTIAL_TYPE);
    assert_eq!(
        credential.issued_at.parse::<DateTime<Utc>>().unwrap(),
        instant_of(times.issued_at)
    );

    // The credential expires before the requirement's own validity does, so
    // its expiry is what bounds the assertion.
    let evidence = decoded(&response);
    assert_eq!(valid_until(&evidence), instant_of(times.expires_at));

    default_policy
        .verify_as_of(&response, Utc::now())
        .expect_err("the default channel policy accepts source assertions only");

    assert_eq!(fixture.wallet_requests().await, 1);
    assert_eq!(
        fixture.source_requests().await,
        0,
        "a holder-presented request never reaches the source channel's upstream"
    );
    fixture.wallet.verify().await;
    let audit = fixture.audit();
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 1);
    for canary in [PRESENTATION_NONCE, SESSION_REFERENCE, BIRTH_DATE_CLAIM] {
        assert!(!audit.contains(canary), "{canary} reached the audit");
    }
}

#[tokio::test]
async fn the_credential_age_bound_caps_the_assertion_validity() {
    let issuer = TrustedIssuer::generate();
    // The credential was issued 100 seconds ago and may be used for 190, so
    // the age bound ends 90 seconds from now; its own expiry is an hour away.
    let fixture =
        WalletRuntime::start(&issuer, &Deployment::with_maximum_credential_age(190)).await;
    let times = Times::long_lived();
    mount_read(
        &fixture.wallet,
        wallet_response(&read_response(
            &presentation(&issuer.key, times),
            &applicant(),
            times.now,
        )),
        1,
    )
    .await;
    let http = fixture.http();

    let (_, accepting, response) = client_exchange(&fixture, &http).await;

    accepting
        .verify_as_of(&response, Utc::now())
        .expect("the assertion verifies");
    assert_eq!(
        valid_until(&decoded(&response)),
        instant_of(times.issued_at + 190)
    );
}

#[tokio::test]
async fn a_source_profile_request_reaches_only_the_source_channel() {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, &Deployment::standard()).await;
    mount_adult_source(&fixture.source, None).await;
    let http = fixture.http();

    let response = authorized(http.post("/v1/evidence"))
        .json(&adult_request())
        .await;

    response.assert_status_ok();
    let evidence = decoded(response.as_bytes());
    assert_eq!(evidence.channel, ChannelKind::Source);
    assert!(evidence.presented_credential.is_none());
    assert_eq!(fixture.source_requests().await, 1);
    assert_eq!(
        fixture.wallet_requests().await,
        0,
        "a source request never reaches the presentation acquisition"
    );
}

/// A two-item batch naming two distinct session references.
fn two_session_batch() -> EvidenceRequestBatch {
    let mut batch = request_batch_from_request(&session_request(), 2);
    batch.items[1].subjects = session_request_for(SECOND_SESSION_REFERENCE).subjects;
    batch
}

#[tokio::test]
async fn a_holder_presented_batch_states_the_channel_on_every_item() {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, &Deployment::standard()).await;
    let times = Times::expiring_in(120);
    for reference in [SESSION_REFERENCE, SECOND_SESSION_REFERENCE] {
        mount_read_for(
            &fixture.wallet,
            reference,
            wallet_response(&read_response(
                &presentation(&issuer.key, times),
                &applicant(),
                times.now,
            )),
            1,
        )
        .await;
    }
    let http = fixture.http();

    let response = bearer(http.post("/v1/evidence/batch"))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&two_session_batch())
        .await;

    response.assert_status_ok();
    let batch: EvidenceRequestBatchResponse = response.json();
    assert_eq!(batch.items.len(), 2);
    for item in &batch.items {
        let evidence = match item {
            EvidenceRequestBatchResponseItem::Evidence { evidence } => decode_evidence(evidence),
            EvidenceRequestBatchResponseItem::EvidenceNotAvailable => {
                panic!("every item carries an assertion")
            }
        };
        assert_eq!(evidence.channel, ChannelKind::HolderPresented);
        let credential = evidence
            .presented_credential
            .as_ref()
            .expect("each item carries the presented credential");
        assert_eq!(credential.trust_entry, TRUST_ENTRY);
        assert_eq!(credential.issuer, ISSUER);
        assert_eq!(credential.credential_type, CREDENTIAL_TYPE);
        assert_eq!(
            valid_until(&evidence),
            instant_of(times.expires_at),
            "each item is capped at the credential expiry"
        );
    }
    assert_eq!(fixture.wallet_requests().await, 2);
    assert_eq!(fixture.source_requests().await, 0);
    fixture.wallet.verify().await;
}

/// The wallet protocol service consumes a held presentation on its first
/// successful read, so a second read of one reference answers 404. Two batch
/// items naming one reference must never both yield an assertion.
#[tokio::test]
async fn a_batch_naming_one_session_twice_yields_no_assertion_from_the_repeat() {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, &Deployment::standard()).await;
    let times = Times::expiring_in(120);
    Mock::given(method("POST"))
        .and(path("/v1/presentations/read"))
        .and(body_json(expected_read_request(SESSION_REFERENCE)))
        .respond_with(wallet_response(&read_response(
            &presentation(&issuer.key, times),
            &applicant(),
            times.now,
        )))
        .up_to_n_times(1)
        .expect(1)
        .mount(&fixture.wallet)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/presentations/read"))
        .and(body_json(expected_read_request(SESSION_REFERENCE)))
        .respond_with(
            ResponseTemplate::new(404)
                .insert_header("traceparent", TRACEPARENT)
                .set_body_raw(
                    br#"{"type":"about:blank","title":"unknown reference","status":404}"#.to_vec(),
                    "application/problem+json",
                ),
        )
        .expect(1)
        .mount(&fixture.wallet)
        .await;
    let http = fixture.http();

    let response = bearer(http.post("/v1/evidence/batch"))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&request_batch_from_request(&session_request(), 2))
        .await;

    // A dependency failure on any item aborts the whole batch: the item that
    // read the held presentation releases no assertion either.
    response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let problem: Value = response.json();
    assert_eq!(problem["code"], json!("source.unavailable"));
    let audit = fixture.audit();
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    for canary in [PRESENTATION_NONCE, SESSION_REFERENCE, BIRTH_DATE_CLAIM] {
        assert!(!format!("{problem}{audit}").contains(canary), "{canary}");
    }
    assert_eq!(fixture.wallet_requests().await, 2);
    assert_eq!(fixture.source_requests().await, 0);
    fixture.wallet.verify().await;
}

#[tokio::test]
async fn a_source_profile_batch_reaches_only_the_source_channel() {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, &Deployment::standard()).await;
    mount_adult_source_expecting(&fixture.source, None, 2).await;
    let http = fixture.http();

    let response = bearer(http.post("/v1/evidence/batch"))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&adult_request_batch(2))
        .await;

    response.assert_status_ok();
    let batch: EvidenceRequestBatchResponse = response.json();
    assert_eq!(batch.items.len(), 2);
    for item in &batch.items {
        match item {
            EvidenceRequestBatchResponseItem::Evidence { evidence } => {
                assert_eq!(decode_evidence(evidence).channel, ChannelKind::Source);
            }
            EvidenceRequestBatchResponseItem::EvidenceNotAvailable => {
                panic!("every item carries an assertion")
            }
        }
    }
    assert_eq!(fixture.source_requests().await, 2);
    assert_eq!(fixture.wallet_requests().await, 0);
}

/// Serve `response` from the read endpoint to a holder-presented request and
/// check that nothing is released and nothing presented reaches the audit or
/// the problem.
async fn assert_dependency_failure(fixture: &WalletRuntime, response: ResponseTemplate) {
    mount_read(&fixture.wallet, response, 1).await;
    let http = fixture.http();

    let refused = authorized(http.post("/v1/evidence"))
        .json(&session_request())
        .await;

    refused.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let problem: Value = refused.json();
    assert_eq!(problem["code"], json!("source.unavailable"));
    let audit = fixture.audit();
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    assert_eq!(audit.matches("\"phase\":\"transient-failure\"").count(), 1);
    assert!(audit.contains("\"decision\":\"dependency-failure\""));
    assert!(
        !audit.contains("no-match"),
        "a failed presentation is never recorded as a no-match"
    );
    let outward = format!("{problem}{audit}");
    for canary in [
        PRESENTATION_NONCE,
        SESSION_REFERENCE,
        BIRTH_DATE_CLAIM,
        APPLICANT_SUBJECT,
        OTHER_APPLICANT_SUBJECT,
        WALLET_TOKEN,
        "salt-birthdate",
    ] {
        assert!(!outward.contains(canary), "{canary} was disclosed");
    }
    assert_eq!(fixture.wallet_requests().await, 1);
    assert_eq!(fixture.source_requests().await, 0);
    fixture.wallet.verify().await;
}

#[tokio::test]
async fn a_credential_from_an_untrusted_issuer_is_a_dependency_failure() {
    let issuer = TrustedIssuer::generate();
    let untrusted = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, &Deployment::standard()).await;
    let times = Times::long_lived();
    assert_dependency_failure(
        &fixture,
        wallet_response(&read_response(
            &presentation(&untrusted.key, times),
            &applicant(),
            times.now,
        )),
    )
    .await;
}

/// A presentation received long before the read, replayed by a verifier
/// service that kept it, is as stale as its receipt: the credential and the
/// key-binding proof are all current relative to `received_at`.
#[tokio::test]
async fn a_presentation_received_beyond_the_result_window_is_a_dependency_failure() {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, &Deployment::standard()).await;
    let now = Utc::now().timestamp();
    let received = now - 5_000;
    let times = Times {
        now: received,
        issued_at: received - 100,
        expires_at: now + 3_600,
    };
    assert_dependency_failure(
        &fixture,
        wallet_response(&read_response(
            &presentation(&issuer.key, times),
            &applicant(),
            received,
        )),
    )
    .await;
}

#[tokio::test]
async fn a_presentation_received_in_the_future_is_a_dependency_failure() {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, &Deployment::standard()).await;
    let now = Utc::now().timestamp();
    let received = now + 5_000;
    let times = Times {
        now: received,
        issued_at: now - 100,
        expires_at: now + 10_000,
    };
    assert_dependency_failure(
        &fixture,
        wallet_response(&read_response(
            &presentation(&issuer.key, times),
            &applicant(),
            received,
        )),
    )
    .await;
}

#[tokio::test]
async fn a_disclosure_the_configuration_does_not_project_is_dropped() {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(
        &issuer,
        &Deployment {
            disclosed_claims: &[],
            ..Deployment::standard()
        },
    )
    .await;
    let times = Times::long_lived();
    // The presentation discloses `birthdate` anyway; the projection is empty,
    // so the pack script finds no value to derive from.
    assert_dependency_failure(
        &fixture,
        wallet_response(&read_response(
            &presentation(&issuer.key, times),
            &applicant(),
            times.now,
        )),
    )
    .await;
}

#[tokio::test]
async fn a_session_created_by_another_principal_is_a_dependency_failure() {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, &Deployment::standard()).await;
    let times = Times::long_lived();
    let other = json!({"issuer": APPLICANT_ISSUER, "subject": OTHER_APPLICANT_SUBJECT});
    assert_dependency_failure(
        &fixture,
        wallet_response(&read_response(
            &presentation(&issuer.key, times),
            &other,
            times.now,
        )),
    )
    .await;
}

#[tokio::test]
async fn a_session_with_no_presentation_yet_is_a_dependency_failure() {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, &Deployment::standard()).await;
    assert_dependency_failure(
        &fixture,
        ResponseTemplate::new(409)
            .insert_header("traceparent", TRACEPARENT)
            .set_body_raw(
                br#"{"type":"about:blank","title":"not presented yet","status":409}"#.to_vec(),
                "application/problem+json",
            ),
    )
    .await;
}

#[tokio::test]
async fn a_read_response_without_a_trace_context_is_a_dependency_failure() {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, &Deployment::standard()).await;
    let times = Times::long_lived();
    let body = read_response(&presentation(&issuer.key, times), &applicant(), times.now);
    assert_dependency_failure(
        &fixture,
        ResponseTemplate::new(200)
            .set_body_raw(serde_json::to_vec(&body).unwrap(), "application/json"),
    )
    .await;
}

#[tokio::test]
async fn two_channels_that_accept_one_selector_profile_refuse_at_startup() {
    let issuer = TrustedIssuer::generate();
    let deployment = Deployment {
        // The holder-presented channel also lists the source channel's own
        // profile.
        edit: |config| {
            config["requirements"][0]["acquisition"]["holderPresented"]["selectorProfiles"] =
                json!([SESSION_PROFILE, "person-demographics-v1"]);
        },
        regenerate_discovery: false,
        ..Deployment::standard()
    };
    let (_source, _wallet, prepared) = prepare_wallet_deployment(&issuer, &deployment).await;

    match crate::bundle::DeploymentInputs::load(&prepared.runtime_path) {
        Err(crate::bundle::BundleError::Refused(report)) => {
            let first = report
                .diagnostics()
                .first()
                .expect("a refusal carries a diagnostic");
            assert_eq!(first.path, "/requirements/0/acquisition");
        }
        Ok(_) => panic!("the deployment loader accepted two channels on one profile"),
        Err(other) => panic!("the loader refused for another reason: {other:?}"),
    }
    let started =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await;
    assert!(
        matches!(started, Err(RuntimeInitializationError::Bundle)),
        "the runtime does not start"
    );
}

/// The startup refusal once a valid wallet deployment's acquisition is edited
/// after loading. The loader's own rules reject most misassignments first, so
/// the runtime's source-build gate is exercised on the loaded bundle.
async fn startup_refusal_after(
    edit: fn(&mut crate::config::AcquisitionConfig),
) -> Result<(), RuntimeInitializationError> {
    let issuer = TrustedIssuer::generate();
    let (_source, _wallet, prepared) =
        prepare_wallet_deployment(&issuer, &Deployment::standard()).await;
    let (mut bundle, _runtime) = crate::bundle::DeploymentInputs::load(&prepared.runtime_path)
        .expect("the wallet deployment loads")
        .into_parts();
    edit(&mut bundle.config.requirements[0].acquisition);
    crate::runtime::refuse_misassigned_channel_sources(&bundle)
}

fn assert_channel_refusal(
    refusal: Result<(), RuntimeInitializationError>,
    expected_pointer: &str,
    expected_cause: &str,
) {
    match refusal {
        Err(RuntimeInitializationError::ChannelSource { pointer, cause }) => {
            assert_eq!(pointer, expected_pointer);
            assert_eq!(cause, expected_cause);
        }
        other => panic!("expected a channel Source refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_holder_presented_source_that_does_not_use_the_wallet_protocol_is_refused() {
    let refusal = startup_refusal_after(|acquisition| {
        acquisition
            .holder_presented
            .as_mut()
            .expect("the requirement declares both channels")
            .source = "source-a".to_owned();
    })
    .await;
    assert_channel_refusal(
        refusal,
        "/requirements/0/acquisition/holderPresented/source",
        "a holder-presented Source must use the wallet presentation protocol",
    );
}

#[tokio::test]
async fn a_source_channel_source_that_uses_the_wallet_protocol_is_refused() {
    let refusal = startup_refusal_after(|acquisition| {
        acquisition.source = "wallet-source".to_owned();
    })
    .await;
    assert_channel_refusal(
        refusal,
        "/requirements/0/acquisition/source",
        "a source-channel Source must not use the wallet presentation protocol",
    );
}

#[tokio::test]
async fn correctly_assigned_channel_sources_are_not_refused() {
    assert!(startup_refusal_after(|_| {}).await.is_ok());
}
