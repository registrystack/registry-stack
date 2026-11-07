//! `wallet-presentation-v1` end to end through the Adapter engine: a double of
//! the wallet protocol service's read endpoint answers a sealed exchange, and
//! the protocol verifies the presented credential before any route step sees it.
#![cfg(feature = "wallet-presentation")]

use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use registry_adapter_core::AdapterPack;
use registry_adapter_engine::{
    artifacts::PackArtifactBytes,
    evidence::{
        compile_evidence_pack_with_protocols, EvidenceAcquisition, EvidenceExecutionError,
        EvidenceHostHooks, EvidenceLimits, EvidenceLookup,
    },
    replay::ReplayTranscript,
};
use registry_evidence::presented::PresentedFacts;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

const NOW: i64 = 1_800_000_000;
const ISS: &str = "https://issuer.example";
const VCT: &str = "https://issuer.example/vct/income";
const CLIENT_ID: &str = "x509_san_dns:verifier.example";
const POLICY_ID: &str = "income-check";
const QUERY_ID: &str = "income";
const NONCE: &str = "nonce-7d1f3a9c";
const REFERENCE: &str = "session-reference-5521";
const PRINCIPAL_ISSUER: &str = "https://idp.example";
const PRINCIPAL_SUBJECT: &str = "caseworker-0042";
const FAMILY_NAME: &str = "Tane-family-canary";
const GIVEN_NAME: &str = "Aroha-given-canary";
const TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => panic!("not an object"),
    }
}

fn instant(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).unwrap()
}

fn compact(header: &Map<String, Value>, payload: &Map<String, Value>, key: &PrivateJwk) -> String {
    let input = format!(
        "{}.{}",
        b64(&serde_json::to_vec(header).unwrap()),
        b64(&serde_json::to_vec(payload).unwrap())
    );
    let signature = sign(input.as_bytes(), key).unwrap();
    format!("{input}.{}", b64(&signature))
}

fn disclosure(salt: &str, name: &str, value: &str) -> (String, String) {
    let encoded = b64(&serde_json::to_vec(&json!([salt, name, value])).unwrap());
    let digest = b64(&Sha256::digest(encoded.as_bytes()));
    (encoded, digest)
}

fn ca_params(name: &str, path_len: Option<u8>) -> CertificateParams {
    let mut params = CertificateParams::new(vec![]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.is_ca = match path_len {
        Some(n) => IsCa::Ca(BasicConstraints::Constrained(n)),
        None => IsCa::Ca(BasicConstraints::Unconstrained),
    };
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    validity(&mut params);
    params
}

fn validity(params: &mut CertificateParams) {
    let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap();
    params.not_before = now - Duration::days(30);
    params.not_after = now + Duration::days(365);
}

/// PKCS#8 v1 wrapper for a raw Ed25519 seed.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

fn pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

/// How the issuer's key reaches the verifier.
struct Issuer {
    key: PrivateJwk,
    header: Map<String, Value>,
    keys: Value,
    /// DER of every certificate in the `x5c` header, leaf first.
    certificates: Vec<Vec<u8>>,
}

impl Issuer {
    fn pinned() -> Self {
        let key = generate_private_jwk(GeneratedKeyAlgorithm::Ed25519).unwrap();
        let mut public = serde_json::to_value(key.public()).unwrap();
        public["kid"] = json!("issuer-key-1");
        Self {
            header: object(json!({"alg": "EdDSA", "typ": "dc+sd-jwt", "kid": "issuer-key-1"})),
            keys: json!({"jwks": [public]}),
            key,
            certificates: Vec::new(),
        }
    }

    /// An issuer with an `x5c` chain (leaf, intermediate) to a fresh root.
    fn certified() -> Self {
        let root =
            CertifiedIssuer::self_signed(ca_params("root", None), KeyPair::generate().unwrap())
                .unwrap();
        let inter = CertifiedIssuer::signed_by(
            ca_params("intermediate", Some(0)),
            KeyPair::generate().unwrap(),
            &root,
        )
        .unwrap();
        let key = generate_private_jwk(GeneratedKeyAlgorithm::Ed25519).unwrap();
        let seed = URL_SAFE_NO_PAD.decode(key.d.as_deref().unwrap()).unwrap();
        let der = [ED25519_PKCS8_PREFIX.as_slice(), seed.as_slice()].concat();
        let leaf_key = KeyPair::try_from(der.as_slice()).unwrap();
        let mut params = CertificateParams::new(vec!["issuer.example".to_owned()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "issuer leaf");
        params.distinguished_name = dn;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        validity(&mut params);
        let leaf = params.signed_by(&leaf_key, &inter).unwrap();
        let certificates = vec![leaf.der().to_vec(), inter.der().to_vec()];
        let chain: Vec<String> = certificates
            .iter()
            .map(|der| STANDARD.encode(der))
            .collect();
        Self {
            header: object(json!({"alg": "EdDSA", "typ": "dc+sd-jwt", "x5c": chain})),
            keys: json!({"x5c": {
                "anchorsPem": [pem(root.der())],
                "leafKeyTypes": ["ed25519"]
            }}),
            key,
            certificates,
        }
    }
}

/// One presentation under construction; a test changes only what it exercises.
struct Credential {
    issuer: Issuer,
    payload: Map<String, Value>,
    disclosures: Vec<String>,
    holder: PrivateJwk,
    kb_overrides: Map<String, Value>,
}

impl Credential {
    fn new(issuer: Issuer) -> Self {
        let holder = generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap();
        let mut holder_public = serde_json::to_value(holder.public()).unwrap();
        holder_public.as_object_mut().unwrap().remove("kid");
        holder_public.as_object_mut().unwrap().remove("alg");
        let mut credential = Self {
            issuer,
            payload: object(json!({
                "iss": ISS, "vct": VCT, "iat": NOW - 100, "exp": NOW + 3600,
                "cnf": {"jwk": holder_public},
            })),
            disclosures: Vec::new(),
            holder,
            kb_overrides: Map::new(),
        };
        credential.disclose("family_name", FAMILY_NAME);
        credential.disclose("given_name", GIVEN_NAME);
        credential
    }

    fn disclose(&mut self, name: &str, value: &str) {
        let (encoded, digest) = disclosure(&format!("salt-{name}"), name, value);
        let sd = self
            .payload
            .entry("_sd")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .unwrap();
        sd.push(json!(digest));
        self.payload.insert("_sd_alg".to_owned(), json!("sha-256"));
        self.disclosures.push(encoded);
    }

    fn build(&self) -> String {
        let mut out = compact(&self.issuer.header, &self.payload, &self.issuer.key);
        out.push('~');
        for disclosure in &self.disclosures {
            out.push_str(disclosure);
            out.push('~');
        }
        let mut claims = object(json!({
            "iat": NOW, "aud": CLIENT_ID, "nonce": NONCE,
            "sd_hash": b64(&Sha256::digest(out.as_bytes())),
        }));
        for (name, value) in &self.kb_overrides {
            if value.is_null() {
                claims.remove(name);
            } else {
                claims.insert(name.clone(), value.clone());
            }
        }
        let header = object(json!({"alg": "ES256", "typ": "kb+jwt"}));
        out.push_str(&compact(&header, &claims, &self.holder));
        out
    }
}

fn channel_config(issuer: &Issuer) -> Value {
    json!({
        "policyId": POLICY_ID,
        "clientId": CLIENT_ID,
        "credentialQueryId": QUERY_ID,
        "trust": [{"id": "agency-a", "issuer": ISS, "vct": [VCT], "keys": issuer.keys}],
        "deny": {"issuers": [], "certificateSha256": []},
        "policy": {"vct": [VCT], "keyBindingRequired": true},
        "disclosedClaims": ["family_name", "absent_claim"],
        "status": "not-checked",
        "maximumCredentialAgeSeconds": 86400,
        "subjectLink": "attribute-match"
    })
}

fn principal() -> Value {
    json!({"issuer": PRINCIPAL_ISSUER, "subject": PRINCIPAL_SUBJECT})
}

fn read_context() -> Value {
    json!({
        "nonce": NONCE,
        "clientId": CLIENT_ID,
        "responseUri": "https://verifier.example/response",
        "responseKeyThumbprint": "thumbprint",
        "policyId": POLICY_ID,
        "createdBy": principal(),
        "receivedAt": instant(NOW).to_rfc3339(),
    })
}

fn read_response(presentation: &str) -> Value {
    json!({"presentation": {QUERY_ID: [presentation]}, "context": read_context()})
}

/// What the double of the read endpoint answers.
struct Wire {
    status: u16,
    headers: Value,
    body: Vec<u8>,
}

impl Wire {
    fn ok(body: &Value) -> Self {
        Self {
            status: 200,
            headers: json!({"content-type": "application/json", "traceparent": TRACEPARENT}),
            body: serde_json::to_vec(body).unwrap(),
        }
    }
}

/// How the route reaches the endpoint.
#[derive(Clone, Copy)]
enum Route {
    Read,
    Get,
    ReadWithQuery,
}

struct Run {
    config: Value,
    authentication: Value,
    route: Route,
    inputs: Value,
    wire: Wire,
    at: i64,
}

impl Run {
    fn new(credential: &Credential) -> Self {
        Self {
            config: channel_config(&credential.issuer),
            authentication: json!({"type": "static-authorization"}),
            route: Route::Read,
            inputs: json!({"reference": REFERENCE, "principal": principal()}),
            wire: Wire::ok(&read_response(&credential.build())),
            at: NOW,
        }
    }

    fn respond(&mut self, body: &Value) {
        self.wire = Wire::ok(body);
    }
}

struct Hooks;
impl EvidenceHostHooks for Hooks {
    fn before_acquisition<'a>(
        &'a self,
        _intent: registry_adapter_engine::evidence::EvidenceAcquisitionIntent,
    ) -> registry_adapter_engine::evidence::EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

struct Outcome {
    result: Result<EvidenceLookup, EvidenceExecutionError>,
    acquisition: Option<EvidenceAcquisition>,
}

impl Outcome {
    fn facts(&self) -> Value {
        match &self.result {
            Ok(EvidenceLookup::Matched { facts }) => facts["body"].clone(),
            other => panic!("expected a matched lookup, got {other:?}"),
        }
    }

    async fn presented(&self) -> Option<PresentedFacts> {
        let attachment = self
            .acquisition
            .as_ref()?
            .trusted_protocol_attachment()
            .await?;
        attachment
            .downcast::<PresentedFacts>()
            .ok()
            .map(|facts| (*facts).clone())
    }

    /// The failure is a dependency failure that released no fact and no
    /// attachment, and its diagnostics hold nothing presented.
    async fn assert_refused(&self) {
        let error = self
            .result
            .as_ref()
            .expect_err("the lookup must be refused");
        let text = format!("{error} {error:?}");
        for canary in [
            FAMILY_NAME,
            GIVEN_NAME,
            NONCE,
            REFERENCE,
            PRINCIPAL_SUBJECT,
            "salt-",
            "issuer-key-1",
        ] {
            assert!(!text.contains(canary), "{canary} leaked into {text}");
        }
        assert!(self.presented().await.is_none());
    }
}

fn pack_for(run: &Run) -> (AdapterPack, PackArtifactBytes) {
    let config = serde_json::to_vec(&run.config).unwrap();
    let script =
        br#"fn read(exchange) { #{lookup: "matched", facts: #{body: exchange.body}} }"#.to_vec();
    let inputs = serde_json::to_vec(&json!({
        "type": "object", "additionalProperties": false,
        "properties": {
            "reference": {"type": "string"},
            "principal": {
                "type": "object", "additionalProperties": false,
                "properties": {
                    "issuer": {"type": "string"}, "subject": {"type": "string"},
                    "extra": {"type": "string"}
                }
            },
            "expectedFamilyName": {"type": "string"}
        }
    }))
    .unwrap();
    let text = json!({"type": "string"});
    let facts = serde_json::to_vec(&json!({
        "type": "object", "additionalProperties": false, "required": ["body"],
        "properties": {"body": {
            "type": "object", "additionalProperties": false,
            "properties": {
                "lookup": text,
                "values": {
                    "type": "object", "additionalProperties": false,
                    "properties": {"family_name": text, "absent_claim": text}
                },
                "verification": {
                    "type": "object", "additionalProperties": false,
                    "properties": {
                        "trustEntry": text, "credentialType": text, "issuedAt": text
                    }
                }
            }
        }}
    }))
    .unwrap();
    let digest = |bytes: &[u8]| registry_platform_config::sha256_uri(bytes);
    let call = match run.route {
        Route::Read => json!({"httpMethod": "POST", "operation": "read",
            "path": "/v1/presentations/read", "body": {"jsonpath": "$"}}),
        Route::Get => json!({"httpMethod": "GET", "operation": "read",
            "path": "/v1/presentations/read"}),
        Route::ReadWithQuery => json!({"httpMethod": "POST", "operation": "read",
            "path": "/v1/presentations/read", "body": {"jsonpath": "$"},
            "query": {"probe": {"constant": "1"}}}),
    };
    let pack: AdapterPack = serde_json::from_value(json!({
        "id": "wallet-pack", "version": "1", "testedVersions": [],
        "endpoints": [{
            "id": "wallet", "component": "http",
            "authentication": run.authentication,
            "attemptTimeoutMilliseconds": 1000,
            "maximumResponseBytes": 65536,
            "requestHeaders": [], "responseHeaders": [],
            "operations": [{"id": "read", "safeUpstream": true}],
            "testedVersions": [],
            "hostProtocol": {
                "id": "wallet-presentation-v1",
                "config": {"path": "protocol.json", "digest": digest(&config)}
            }
        }],
        "scripts": [{"path": "scripts/wallet.rhai", "digest": digest(&script)}],
        "sourceRoutes": [{
            "id": "wallet",
            "evidence": {
                "inputsSchema": {"path": "inputs.json", "digest": digest(&inputs)},
                "factsSchema": {"path": "facts.json", "digest": digest(&facts)}
            },
            "steps": [
                {"to": {"uri": "http:wallet", "parameters": call}},
                {"setBody": {"rhai": {"file": "scripts/wallet.rhai", "entrypoint": "read"}}}
            ]
        }]
    }))
    .expect("pack");
    let artifacts = PackArtifactBytes::new([
        ("protocol.json".to_owned(), config),
        ("scripts/wallet.rhai".to_owned(), script),
        ("inputs.json".to_owned(), inputs),
        ("facts.json".to_owned(), facts),
    ]);
    (pack, artifacts)
}

fn compile(run: &Run) -> Result<registry_adapter_engine::evidence::EvidencePackProgram, String> {
    let (pack, artifacts) = pack_for(run);
    compile_evidence_pack_with_protocols(
        &pack,
        "wallet",
        &artifacts,
        EvidenceLimits::default(),
        &registry_evidence::host_protocol::registry().unwrap(),
    )
    .map_err(|error| format!("{error:?}"))
}

async fn execute(run: Run) -> Outcome {
    let checked = compile(&run).expect("the pack compiles");
    let mut response = json!({
        "status": run.wire.status,
        "rawBodyBase64": STANDARD.encode(&run.wire.body),
    });
    response["headers"] = run.wire.headers.clone();
    // The sealed exchange records the request the route sends, so a request
    // the protocol should refuse would otherwise be answered successfully.
    let mut request = json!({
        "endpoint": "wallet", "method": "POST", "path": "/v1/presentations/read",
        "headers": {"accept": "application/json"},
        "body": run.inputs
    });
    match run.route {
        Route::Read => {}
        Route::Get => {
            request["method"] = json!("GET");
            request.as_object_mut().unwrap().remove("body");
        }
        Route::ReadWithQuery => request["query"] = json!("probe=1"),
    }
    let transcript = Arc::new(ReplayTranscript::from_exchanges(
        serde_json::from_value(json!([{"type": "endpoint", "endpoint": "wallet"}])).unwrap(),
        serde_json::from_value(json!([{"request": request, "response": response}])).unwrap(),
    ));
    let program = checked.bind_replay(Arc::clone(&transcript)).unwrap();
    let acquisition = program
        .begin_acquisition_at(Arc::new(Hooks), instant(run.at))
        .await
        .expect("acquisition");
    let result = program.execute(&acquisition, run.inputs).await;
    Outcome {
        result,
        acquisition: Some(acquisition),
    }
}

// ---- compile refusals -------------------------------------------------------

#[test]
fn compile_refuses_an_endpoint_without_authentication() {
    let credential = Credential::new(Issuer::pinned());
    let mut run = Run::new(&credential);
    assert!(compile(&run).is_ok(), "the complete configuration compiles");
    run.authentication = json!({"type": "none"});
    assert!(compile(&run).is_err());
}

#[test]
fn compile_refuses_incomplete_unsafe_and_unknown_configuration() {
    let credential = Credential::new(Issuer::pinned());
    type Change = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Change)> = vec![
        (
            "status required",
            Box::new(|c| c["status"] = json!("required")),
        ),
        (
            "status absent",
            Box::new(|c| drop(c.as_object_mut().unwrap().remove("status"))),
        ),
        (
            "key binding not required",
            Box::new(|c| c["policy"]["keyBindingRequired"] = json!(false)),
        ),
        (
            "deny absent",
            Box::new(|c| drop(c.as_object_mut().unwrap().remove("deny"))),
        ),
        (
            "deny issuers absent",
            Box::new(|c| drop(c["deny"].as_object_mut().unwrap().remove("issuers"))),
        ),
        (
            "age absent",
            Box::new(|c| {
                drop(
                    c.as_object_mut()
                        .unwrap()
                        .remove("maximumCredentialAgeSeconds"),
                )
            }),
        ),
        (
            "age zero",
            Box::new(|c| c["maximumCredentialAgeSeconds"] = json!(0)),
        ),
        (
            "age above ten years",
            Box::new(|c| c["maximumCredentialAgeSeconds"] = json!(315_360_001)),
        ),
        ("unknown member", Box::new(|c| c["surprise"] = json!(true))),
        ("empty trust", Box::new(|c| c["trust"] = json!([]))),
        (
            "subject link absent",
            Box::new(|c| drop(c.as_object_mut().unwrap().remove("subjectLink"))),
        ),
    ];
    for (name, change) in cases {
        let mut run = Run::new(&credential);
        change(&mut run.config);
        assert!(compile(&run).is_err(), "{name} must not compile");
    }
}

// ---- request refusals ---------------------------------------------------------

/// The sealed exchange would answer the request successfully, so only the
/// protocol can have refused it.
async fn assert_request_refused(run: Run) {
    execute(run).await.assert_refused().await;
}

#[tokio::test]
async fn the_request_refuses_an_extra_body_member() {
    let credential = Credential::new(Issuer::pinned());
    let mut run = Run::new(&credential);
    run.inputs["expectedFamilyName"] = json!("Tane");
    assert_request_refused(run).await;

    let mut run = Run::new(&credential);
    run.inputs["principal"]["extra"] = json!("x");
    assert_request_refused(run).await;
}

#[tokio::test]
async fn the_request_refuses_a_missing_principal_or_reference() {
    let credential = Credential::new(Issuer::pinned());
    let mut run = Run::new(&credential);
    run.inputs = json!({"reference": REFERENCE});
    assert_request_refused(run).await;

    let mut run = Run::new(&credential);
    run.inputs = json!({"principal": principal()});
    assert_request_refused(run).await;
}

#[tokio::test]
async fn the_request_refuses_a_query_string_and_a_get() {
    let credential = Credential::new(Issuer::pinned());
    let mut run = Run::new(&credential);
    run.route = Route::ReadWithQuery;
    assert_request_refused(run).await;

    let mut run = Run::new(&credential);
    run.route = Route::Get;
    assert_request_refused(run).await;
}

// ---- verification -------------------------------------------------------------

#[tokio::test]
async fn a_verified_presentation_projects_only_declared_claims_and_attaches_facts() {
    let credential = Credential::new(Issuer::pinned());
    let outcome = execute(Run::new(&credential)).await;
    assert_eq!(
        outcome.facts(),
        json!({
            "lookup": "matched",
            "values": {"family_name": FAMILY_NAME},
            "verification": {
                "trustEntry": "agency-a",
                "credentialType": VCT,
                "issuedAt": instant(NOW - 100).to_rfc3339(),
            }
        }),
        "only the declared claims that are present, plus the closed verification object"
    );
    let text = outcome.facts().to_string();
    for hidden in [GIVEN_NAME, NONCE, "cnf", "salt-", "x5c", "kid"] {
        assert!(!text.contains(hidden), "{hidden} reached the route");
    }
    let facts = outcome.presented().await.expect("PresentedFacts attached");
    // The credential's own `exp` (NOW + 3600) is earlier than iat + one day.
    assert_eq!(facts.expires_at(), instant(NOW + 3600));
    let presented = facts.credential();
    assert_eq!(presented.trust_entry, "agency-a");
    assert_eq!(presented.issuer, ISS);
    assert_eq!(presented.credential_type, VCT);
    assert_eq!(
        presented.issued_at,
        instant(NOW - 100).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    );
    assert_eq!(
        presented.subject_link,
        registry_evidence::model::SubjectLinkMode::AttributeMatch
    );
}

#[tokio::test]
async fn an_x5c_credential_under_a_trusted_anchor_verifies() {
    let credential = Credential::new(Issuer::certified());
    let outcome = execute(Run::new(&credential)).await;
    assert_eq!(outcome.facts()["verification"]["trustEntry"], "agency-a");
}

#[tokio::test]
async fn the_age_bound_caps_validity_when_the_credential_has_no_expiry() {
    let mut credential = Credential::new(Issuer::pinned());
    credential.payload.remove("exp");
    let outcome = execute(Run::new(&credential)).await;
    outcome.facts();
    let facts = outcome.presented().await.unwrap();
    assert_eq!(facts.expires_at(), instant(NOW - 100 + 86_400));
}

#[tokio::test]
async fn the_earlier_of_expiry_and_the_age_bound_applies() {
    let mut credential = Credential::new(Issuer::pinned());
    credential
        .payload
        .insert("exp".into(), json!(NOW + 10 * 86_400));
    let outcome = execute(Run::new(&credential)).await;
    let facts = outcome.presented().await.unwrap();
    assert_eq!(facts.expires_at(), instant(NOW - 100 + 86_400));
}

#[tokio::test]
async fn an_untrusted_issuer_is_refused() {
    let credential = Credential::new(Issuer::pinned());
    let mut run = Run::new(&credential);
    run.config["trust"][0]["issuer"] = json!("https://another-issuer.example");
    execute(run).await.assert_refused().await;
}

#[tokio::test]
async fn a_denied_issuer_is_refused() {
    let credential = Credential::new(Issuer::pinned());
    let mut run = Run::new(&credential);
    run.config["deny"]["issuers"] = json!([ISS]);
    execute(run).await.assert_refused().await;
}

#[tokio::test]
async fn a_denied_intermediate_under_a_trusted_anchor_is_refused() {
    let credential = Credential::new(Issuer::certified());
    let mut run = Run::new(&credential);
    assert!(
        matches!(
            execute(Run::new(&credential)).await.result,
            Ok(EvidenceLookup::Matched { .. })
        ),
        "the chain is valid without the deny-list"
    );
    let intermediate: [u8; 32] = Sha256::digest(&credential.issuer.certificates[1]).into();
    let hex: String = intermediate
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    run.config["deny"]["certificateSha256"] = json!([hex]);
    execute(run).await.assert_refused().await;
}

#[tokio::test]
async fn a_key_binding_for_another_session_is_refused() {
    let mut credential = Credential::new(Issuer::pinned());
    credential
        .kb_overrides
        .insert("nonce".into(), json!("another-nonce"));
    execute(Run::new(&credential)).await.assert_refused().await;

    let mut credential = Credential::new(Issuer::pinned());
    credential
        .kb_overrides
        .insert("aud".into(), json!("x509_san_dns:other.example"));
    execute(Run::new(&credential)).await.assert_refused().await;
}

#[tokio::test]
async fn a_context_for_another_channel_or_principal_is_refused() {
    let credential = Credential::new(Issuer::pinned());
    for (member, value) in [
        ("clientId", json!("x509_san_dns:other.example")),
        ("policyId", json!("another-policy")),
        (
            "createdBy",
            json!({"issuer": PRINCIPAL_ISSUER, "subject": "someone-else"}),
        ),
        (
            "createdBy",
            json!({"issuer": "https://other-idp.example", "subject": PRINCIPAL_SUBJECT}),
        ),
    ] {
        let mut run = Run::new(&credential);
        let mut body = read_response(&credential.build());
        body["context"][member] = value;
        run.respond(&body);
        execute(run).await.assert_refused().await;
    }
}

#[tokio::test]
async fn a_presentation_that_is_not_exactly_one_string_under_the_configured_query_is_refused() {
    let credential = Credential::new(Issuer::pinned());
    let presentation = credential.build();
    let bodies = [
        json!({"presentation": {QUERY_ID: [presentation, presentation]}, "context": read_context()}),
        json!({"presentation": {QUERY_ID: []}, "context": read_context()}),
        json!({"presentation": {QUERY_ID: [presentation], "other": [presentation]}, "context": read_context()}),
        json!({"presentation": {"other": [presentation]}, "context": read_context()}),
        json!({"presentation": {}, "context": read_context()}),
        json!({"presentation": {QUERY_ID: [presentation]}, "context": read_context(), "extra": 1}),
    ];
    for body in bodies {
        let mut run = Run::new(&credential);
        run.respond(&body);
        execute(run).await.assert_refused().await;
    }
}

#[tokio::test]
async fn a_credential_older_than_the_maximum_age_is_refused() {
    let credential = Credential::new(Issuer::pinned());
    let mut run = Run::new(&credential);
    run.config["maximumCredentialAgeSeconds"] = json!(99);
    execute(run).await.assert_refused().await;

    // A credential whose age equals the bound has no validity left.
    let mut run = Run::new(&credential);
    run.config["maximumCredentialAgeSeconds"] = json!(100);
    execute(run).await.assert_refused().await;

    let mut run = Run::new(&credential);
    run.config["maximumCredentialAgeSeconds"] = json!(101);
    let outcome = execute(run).await;
    outcome.facts();
    assert_eq!(
        outcome.presented().await.unwrap().expires_at(),
        instant(NOW + 1)
    );
}

#[tokio::test]
async fn an_expired_credential_at_the_injected_instant_is_refused() {
    let credential = Credential::new(Issuer::pinned());
    let mut run = Run::new(&credential);
    run.at = NOW + 3600 + 3600;
    run.config["maximumCredentialAgeSeconds"] = json!(31_536_000);
    execute(run).await.assert_refused().await;
}

#[tokio::test]
async fn a_credential_without_an_issue_time_is_refused_never_defaulted() {
    let mut credential = Credential::new(Issuer::pinned());
    credential.payload.remove("iat");
    execute(Run::new(&credential)).await.assert_refused().await;
}

#[tokio::test]
async fn a_credential_that_expires_inside_the_clock_skew_window_is_refused() {
    let mut credential = Credential::new(Issuer::pinned());
    // Past `exp` by less than the clock skew: the verifier tolerates it, the
    // protocol must not hand out an assertion that is already over.
    credential.payload.insert("exp".into(), json!(NOW - 10));
    execute(Run::new(&credential)).await.assert_refused().await;
}

#[tokio::test]
async fn the_read_endpoint_refusals_and_malformed_answers_are_refused() {
    let credential = Credential::new(Issuer::pinned());
    for status in [401_u16, 404, 409, 500] {
        let mut run = Run::new(&credential);
        run.wire.status = status;
        execute(run).await.assert_refused().await;
    }
    let mut run = Run::new(&credential);
    run.wire.body = b"not json".to_vec();
    execute(run).await.assert_refused().await;

    let mut run = Run::new(&credential);
    run.wire.headers = json!({"content-type": "text/plain", "traceparent": TRACEPARENT});
    execute(run).await.assert_refused().await;

    let mut run = Run::new(&credential);
    run.wire.headers = json!({"content-type": "application/json"});
    execute(run).await.assert_refused().await;
}
