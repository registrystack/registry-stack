//! End-to-end proof that a delegated token Mint issues is bound to one subject.
//!
//! The claim is narrow and worth stating precisely: a client that is registered
//! for delegation asks Mint for a token *for a named person*, and the resulting
//! token can only ever produce evidence about that person. Not because the
//! client is well behaved, but because Evidence reads the subject out of the
//! token and refuses to read it from the request at all.
//!
//! Nothing here stubs a boundary. The Mint router is the real one, the bundle is
//! the demonstration bundle under `demo/evidence-bundle`, and the authorization
//! decision is Evidence's own `match_entitlement` and `resolve_selectors`.

use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

use axum_test::TestServer;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_evidence::{
    auth::{AuthenticatedContext, AuthenticationClaimsConfig, Authenticator},
    bundle::Bundle,
    config::{AuthorityKind, ValueOrigin},
    model::{EvidenceRequest, RequestedSelector, RequestedSubject, SelectorValue},
    selector::{authorize_and_resolve, AuthorizationError, ResolvedSelectorValue},
};
use registry_mint::{
    config::MintConfig,
    server::{build_app, MintService},
    CLIENT_ASSERTION_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS, ON_BEHALF_OF_CLAIM,
};
use registry_platform_crypto::PrivateJwk;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use serde_json::{json, Value};

/// These four must agree with `demo/evidence-bundle/evidence.yaml`. If they ever
/// drift, this test is the thing that says so.
const ISSUER: &str = "https://localhost:8443";
const EVIDENCE_AUDIENCE: &str = "evidence.demo.invalid";
const ACTOR_CLAIM: &str = "evidence_actor";
const REQUIREMENT: &str = "urn:example:demo:requirement:residence-region:v1";
const PURPOSE: &str = "demo-routing";
const ASSERTION_AUDIENCE: &str = "https://localhost:8443/token";

const AGENT: &str = "urn:example:demo:agent:appointment-scheduler";

fn key_pair(seed: u8) -> (PrivateJwk, Value, Value) {
    let seed_bytes = [seed; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
    let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
    let d = URL_SAFE_NO_PAD.encode(seed_bytes);
    let kid = format!("key-{seed}");
    let public = json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x});
    let private_document =
        json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x, "d": d});
    let private = PrivateJwk::parse(&private_document.to_string()).expect("private JWK parses");
    (private, public, private_document)
}

struct Deployment {
    _directory: tempfile::TempDir,
    service: Arc<MintService>,
    audit_path: std::path::PathBuf,
}

/// A Mint deployment whose claim names, issuer, and audience are the ones the
/// demonstration bundle expects.
async fn deployment() -> Deployment {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path();
    fs::create_dir(root.join("secrets")).expect("create secrets directory");
    fs::create_dir(root.join("clients")).expect("create clients directory");

    let (_, _, signing_document) = key_pair(9);
    let signing_path = root.join("secrets/signing.jwk");
    fs::write(&signing_path, signing_document.to_string()).expect("write signing key");
    fs::set_permissions(&signing_path, fs::Permissions::from_mode(0o600))
        .expect("restrict signing key");
    let audit_key_path = root.join("secrets/audit-hmac-key");
    fs::write(&audit_key_path, "0123456789abcdef0123456789abcdef").expect("write audit key");
    fs::set_permissions(&audit_key_path, fs::Permissions::from_mode(0o600))
        .expect("restrict audit key");
    let audit_path = root.join("audit/mint.jsonl");

    // The delegated caller: it may act as one agent, over exactly three
    // selector fields, minted at exactly the paths the bundle reads.
    let (_, scheduler_public, _) = key_pair(1);
    fs::write(
        root.join("clients/scheduler.yaml"),
        format!(
            "clientId: scheduler\nprincipal: urn:example:demo:principal:scheduler\nevidenceAudience: https://scheduler.demo.invalid\nrequesterTags: [demo-agent]\nkeys: [{scheduler_public}]\ndelegation:\n  actors: [{AGENT}]\n  subjectClaims:\n    given_name: identity.given_name\n    family_name: identity.family_name\n    birth_date: identity.birth_date\n"
        ),
    )
    .expect("write delegated client");

    // The same authority, without delegation. Its tokens carry no actor.
    let (_, desk_public, _) = key_pair(2);
    fs::write(
        root.join("clients/service-desk.yaml"),
        format!(
            "clientId: service-desk\nprincipal: urn:example:demo:principal:service-desk\nevidenceAudience: https://service-desk.demo.invalid\nrequesterTags: [demo-agent]\nkeys: [{desk_public}]\n"
        ),
    )
    .expect("write undelegated client");

    let config_path = root.join("mint.yaml");
    fs::write(
        &config_path,
        format!(
            r#"
version: 1
issuer: {ISSUER}
listener: {{address: 127.0.0.1, port: 0}}
signing:
  algorithm: EdDSA
  activeKeyId: key-9
  activeKeyFile: secrets/signing.jwk
audit:
  path: audit/mint.jsonl
  maximumFileBytes: 1073741824
  hashKeyFile: secrets/audit-hmac-key
  hashKeyVersion: 1
accessTokens:
  audiences: [{EVIDENCE_AUDIENCE}]
  lifetimeSeconds: 300
  claims:
    principal: sub
    requesterTags: evidence_tags
    evidenceAudience: evidence_audience
    grantId: evidence_grant_id
    grantAuthority: evidence_authority
    actor: {ACTOR_CLAIM}
clientAssertion:
  audience: {ASSERTION_AUDIENCE}
  algorithms: [EdDSA]
clients:
  directory: clients
"#
        ),
    )
    .expect("write config");

    let config = MintConfig::load(&config_path).expect("the deployment configuration is valid");
    let service = Arc::new(
        MintService::load(config)
            .await
            .expect("the deployment loads"),
    );
    Deployment {
        _directory: directory,
        service,
        audit_path,
    }
}

fn sign_assertion(private: &PrivateJwk, claims: &Value) -> String {
    let kid = private.kid.clone().expect("the test key has a kid");
    let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
    let encode = |value: &Value| {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("value serializes"))
    };
    let signing_input = format!("{}.{}", encode(&header), encode(claims));
    let signature =
        registry_platform_crypto::sign(signing_input.as_bytes(), private).expect("the key signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn assertion_claims(client_id: &str, jti: &str) -> Value {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    json!({
        "iss": client_id,
        "sub": client_id,
        "aud": ASSERTION_AUDIENCE,
        "iat": now,
        "exp": now + 120,
        "jti": jti,
    })
}

/// The delegation request, carried inside the client's own signed assertion so
/// the values are covered by the client's signature rather than travelling as
/// unauthenticated form parameters.
fn delegated_claims(jti: &str, subject: &[(&str, &str)]) -> Value {
    let mut claims = assertion_claims("scheduler", jti);
    claims[ON_BEHALF_OF_CLAIM] = json!({
        "actor": AGENT,
        "subject": subject
            .iter()
            .map(|(field, value)| ((*field).to_owned(), json!(value)))
            .collect::<serde_json::Map<_, _>>(),
    });
    claims
}

fn token_form(assertion: &str) -> Vec<(String, String)> {
    vec![
        (
            "grant_type".to_owned(),
            GRANT_TYPE_CLIENT_CREDENTIALS.to_owned(),
        ),
        (
            "client_assertion_type".to_owned(),
            CLIENT_ASSERTION_TYPE.to_owned(),
        ),
        ("client_assertion".to_owned(), assertion.to_owned()),
    ]
}

async fn mint_token(http: &TestServer, assertion: &str) -> String {
    let response = http.post("/token").form(&token_form(assertion)).await;
    response.assert_status_ok();
    response.json::<Value>()["access_token"]
        .as_str()
        .expect("the response carries an access token")
        .to_owned()
}

/// Evidence's authenticator over the key set Mint published, configured exactly
/// as the demonstration bundle configures it.
fn evidence_authenticator(jwks: &Value) -> Authenticator {
    let key_set: jsonwebtoken::jwk::JwkSet =
        serde_json::from_value(jwks.clone()).expect("Mint publishes a parsable JWK set");
    let verifier_config = TokenVerifierConfig::access_token_profile(
        ISSUER.to_owned(),
        vec![EVIDENCE_AUDIENCE.to_owned()],
        vec![jsonwebtoken::Algorithm::EdDSA],
        vec!["at+jwt".to_owned()],
    );
    Authenticator::new(
        Arc::new(TokenVerifier::new(
            verifier_config,
            Arc::new(JwksFetcher::new_static(
                key_set,
                JwksFetcherConfig::defaults(),
            )),
        )),
        AuthenticationClaimsConfig {
            principal_claim: "sub".to_owned(),
            requester_tags_claim: "evidence_tags".to_owned(),
            evidence_audience_claim: "evidence_audience".to_owned(),
            grant_id_claim: "evidence_grant_id".to_owned(),
            grant_authority_claim: "evidence_authority".to_owned(),
            actor_claim: Some(ACTOR_CLAIM.to_owned()),
        },
    )
}

struct LoadedBundle {
    _directory: tempfile::TempDir,
    bundle: Bundle,
}

/// Evidence refuses a writable bundle, so the demonstration bundle is copied to
/// a temporary root and frozen before loading.
fn demo_bundle() -> LoadedBundle {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path().join("bundle");
    fs::create_dir(&root).expect("create bundle root");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("demo/evidence-bundle"),
        &root,
    );
    make_read_only(&root);
    let bundle = Bundle::load(&root).expect("the demonstration bundle loads");
    LoadedBundle {
        _directory: directory,
        bundle,
    }
}

fn copy_tree(source: &Path, target: &Path) {
    for entry in fs::read_dir(source).expect("the demonstration bundle is readable") {
        let entry = entry.expect("bundle entry is readable");
        let destination = target.join(entry.file_name());
        if entry.file_type().expect("entry type is readable").is_dir() {
            fs::create_dir(&destination).expect("bundle directory is copied");
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("bundle file is copied");
        }
    }
}

fn make_read_only(path: &Path) {
    for entry in fs::read_dir(path).expect("copied bundle is readable") {
        let entry = entry.expect("bundle entry is readable");
        let child = entry.path();
        if entry.file_type().expect("entry type is readable").is_dir() {
            make_read_only(&child);
            fs::set_permissions(&child, fs::Permissions::from_mode(0o555))
                .expect("bundle directory is immutable");
        } else {
            fs::set_permissions(&child, fs::Permissions::from_mode(0o444))
                .expect("bundle file is immutable");
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o555)).expect("bundle root is immutable");
}

/// The request a delegated caller sends: it names the requirement, the purpose,
/// and the *shape* of the subject, and carries no selector values at all.
fn subject_bound_request() -> EvidenceRequest {
    EvidenceRequest {
        // The nonce is a caller correlation value that never reaches
        // authorization, which is the only thing under test here.
        request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE.to_owned(),
        requirement: REQUIREMENT.to_owned(),
        purpose: PURPOSE.to_owned(),
        subjects: vec![RequestedSubject {
            role: "subject".to_owned(),
            selector: RequestedSelector {
                profile: "demographics-v1".to_owned(),
                values: None,
            },
        }],
        // A holder key belongs to the SD-JWT VC response format and never
        // reaches authorization, which is the only thing under test here.
        holder_key: None,
    }
}

fn resolved_values(
    authorization: &registry_evidence::selector::ResolvedAuthorization,
) -> BTreeMap<String, String> {
    authorization
        .subjects
        .iter()
        .flat_map(|subject| subject.fields.iter())
        .map(|field| {
            let value = match &field.value {
                ResolvedSelectorValue::String(value) => value.clone(),
                ResolvedSelectorValue::Date(value) => value.to_string(),
                other => format!("{other:?}"),
            };
            (field.name.clone(), value)
        })
        .collect()
}

async fn context_for(http: &TestServer, jwks: &Value, assertion: &str) -> AuthenticatedContext {
    let token = mint_token(http, assertion).await;
    evidence_authenticator(jwks)
        .authenticate(&token)
        .await
        .expect("Evidence accepts a token Mint issued")
}

/// The whole point, in one test: the subject the client named to Mint is the
/// subject Evidence resolves, and the client never names it again.
#[tokio::test]
async fn a_delegated_token_authorizes_evidence_about_exactly_its_own_subject() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));
    let jwks = http.get("/.well-known/jwks.json").await.json::<Value>();
    let loaded = demo_bundle();

    let (private, _, _) = key_pair(1);
    let assertion = sign_assertion(
        &private,
        &delegated_claims(
            "jti-1",
            &[
                ("given_name", "Amara"),
                ("family_name", "Okafor"),
                ("birth_date", "1998-04-02"),
            ],
        ),
    );
    let context = context_for(&http, &jwks, &assertion).await;
    assert_eq!(context.actor(), Some(AGENT));

    let audit = fs::read_to_string(&deployment.audit_path).expect("read Mint audit");
    assert!(audit.contains("\"phase\":\"token-release\""));
    assert!(audit.contains("\"decision\":\"issued\""));
    assert!(audit.contains("\"clientPseudonym\":\"hmac-sha256:v1:"));
    assert!(audit.contains("\"authorityPseudonym\":\"hmac-sha256:v1:"));
    assert!(audit.contains("\"subjectPseudonym\":\"hmac-sha256:v1:"));
    for protected in [
        "scheduler",
        "urn:example:demo:principal:scheduler",
        AGENT,
        "Amara",
        "Okafor",
        "1998-04-02",
        &assertion,
    ] {
        assert!(
            !audit.contains(protected),
            "Mint audit retained protected token input"
        );
    }

    let authorization = authorize_and_resolve(&loaded.bundle, &subject_bound_request(), &context)
        .expect("a delegated token authorizes its own subject");

    assert_eq!(authorization.authority_kind, AuthorityKind::Delegated);
    assert_eq!(authorization.subjects.len(), 1);
    assert_eq!(
        authorization.subjects[0].value_origin,
        ValueOrigin::AuthenticatedContext
    );
    assert_eq!(
        resolved_values(&authorization),
        BTreeMap::from([
            ("given_name".to_owned(), "Amara".to_owned()),
            ("family_name".to_owned(), "Okafor".to_owned()),
            ("birth_date".to_owned(), "1998-04-02".to_owned()),
        ])
    );
}

/// The containment Jeremi asked for. A client holding a token for one person
/// cannot reach a second person by putting their details in the request: the
/// request is refused for carrying selector values at all, so there is no
/// version of this request that reaches a different subject.
#[tokio::test]
async fn a_delegated_token_cannot_be_pointed_at_a_different_subject() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));
    let jwks = http.get("/.well-known/jwks.json").await.json::<Value>();
    let loaded = demo_bundle();

    let (private, _, _) = key_pair(1);
    let assertion = sign_assertion(
        &private,
        &delegated_claims(
            "jti-1",
            &[
                ("given_name", "Amara"),
                ("family_name", "Okafor"),
                ("birth_date", "1998-04-02"),
            ],
        ),
    );
    let context = context_for(&http, &jwks, &assertion).await;

    let mut request = subject_bound_request();
    request.subjects[0].selector.values = Some(BTreeMap::from([
        (
            "given_name".to_owned(),
            SelectorValue::String("Kofi".to_owned()),
        ),
        (
            "family_name".to_owned(),
            SelectorValue::String("Mensah".to_owned()),
        ),
        (
            "birth_date".to_owned(),
            SelectorValue::String("1971-11-30".to_owned()),
        ),
    ]));

    let error = authorize_and_resolve(&loaded.bundle, &request, &context)
        .expect_err("a request carrying its own selector values is refused");
    assert_eq!(error, AuthorizationError::Selector);

    // And repeating the caller's own subject does not help either: the refusal
    // is for supplying values, not for supplying the wrong ones.
    let mut echoed = subject_bound_request();
    echoed.subjects[0].selector.values = Some(BTreeMap::from([
        (
            "given_name".to_owned(),
            SelectorValue::String("Amara".to_owned()),
        ),
        (
            "family_name".to_owned(),
            SelectorValue::String("Okafor".to_owned()),
        ),
        (
            "birth_date".to_owned(),
            SelectorValue::String("1998-04-02".to_owned()),
        ),
    ]));
    assert_eq!(
        authorize_and_resolve(&loaded.bundle, &echoed, &context)
            .expect_err("supplying values is refused even when they match"),
        AuthorizationError::Selector
    );
}

/// Two tokens from the same client and the same key resolve to two different
/// people, so the binding is a property of the token rather than of the client.
#[tokio::test]
async fn each_token_carries_its_own_subject() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));
    let jwks = http.get("/.well-known/jwks.json").await.json::<Value>();
    let loaded = demo_bundle();
    let (private, _, _) = key_pair(1);

    let first = sign_assertion(
        &private,
        &delegated_claims(
            "jti-1",
            &[
                ("given_name", "Amara"),
                ("family_name", "Okafor"),
                ("birth_date", "1998-04-02"),
            ],
        ),
    );
    let second = sign_assertion(
        &private,
        &delegated_claims(
            "jti-2",
            &[
                ("given_name", "Kofi"),
                ("family_name", "Mensah"),
                ("birth_date", "1971-11-30"),
            ],
        ),
    );

    let first = context_for(&http, &jwks, &first).await;
    let second = context_for(&http, &jwks, &second).await;

    let resolve = |context: &AuthenticatedContext| {
        resolved_values(
            &authorize_and_resolve(&loaded.bundle, &subject_bound_request(), context)
                .expect("each delegated token authorizes its own subject"),
        )
    };
    assert_eq!(resolve(&first)["given_name"], "Amara");
    assert_eq!(resolve(&second)["given_name"], "Kofi");
}

/// A token with no actor cannot produce evidence from the subject-bound grant,
/// because there is nowhere for the subject to come from: the grant reads it
/// from claims the token does not carry, and refuses to read it from the
/// request.
///
/// Note the shape of the refusal. Evidence confines an *actor-bearing* token to
/// `kind: delegated` profiles, but it does not conversely require an actor to
/// reach one, so this token matches the grant and is stopped at selector
/// resolution rather than at entitlement matching. Nothing leaks either way, but
/// the two are not interchangeable: were this grant to gain a subject role whose
/// values come from the request, an undelegated token would reach it.
#[tokio::test]
async fn an_undelegated_token_cannot_use_the_delegated_grant() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));
    let jwks = http.get("/.well-known/jwks.json").await.json::<Value>();
    let loaded = demo_bundle();

    let (private, _, _) = key_pair(2);
    let assertion = sign_assertion(&private, &assertion_claims("service-desk", "jti-1"));
    let context = context_for(&http, &jwks, &assertion).await;
    assert_eq!(context.actor(), None);

    assert_eq!(
        authorize_and_resolve(&loaded.bundle, &subject_bound_request(), &context)
            .expect_err("an undelegated token has no subject to resolve"),
        AuthorizationError::Selector
    );

    // Supplying the subject in the request does not rescue it: the grant refuses
    // request-borne selector values from any caller.
    let mut request = subject_bound_request();
    request.subjects[0].selector.values = Some(BTreeMap::from([
        (
            "given_name".to_owned(),
            SelectorValue::String("Amara".to_owned()),
        ),
        (
            "family_name".to_owned(),
            SelectorValue::String("Okafor".to_owned()),
        ),
        (
            "birth_date".to_owned(),
            SelectorValue::String("1998-04-02".to_owned()),
        ),
    ]));
    assert_eq!(
        authorize_and_resolve(&loaded.bundle, &request, &context)
            .expect_err("an undelegated token cannot name a subject either"),
        AuthorizationError::Selector
    );
}

/// Mint refuses the request before it ever becomes a token: the actor is not one
/// this registration may act as.
#[tokio::test]
async fn mint_refuses_an_actor_the_registration_does_not_permit() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));

    let (private, _, _) = key_pair(1);
    let mut claims = delegated_claims(
        "jti-1",
        &[
            ("given_name", "Amara"),
            ("family_name", "Okafor"),
            ("birth_date", "1998-04-02"),
        ],
    );
    claims[ON_BEHALF_OF_CLAIM]["actor"] = json!("urn:example:demo:agent:someone-else");
    let assertion = sign_assertion(&private, &claims);

    let response = http.post("/token").form(&token_form(&assertion)).await;
    assert_eq!(response.status_code(), 401);
    assert_eq!(response.json::<Value>(), json!({"error": "invalid_client"}));
    let audit = fs::read_to_string(&deployment.audit_path).expect("read Mint audit");
    assert!(audit.contains("\"phase\":\"denial\""));
    assert!(audit.contains("\"safeErrorCategory\":\"invalid_client\""));
    assert!(!audit.contains("someone-else"));
}

/// A signed access token is not released unless its audit record is durable.
#[tokio::test]
async fn an_unwritable_audit_chain_prevents_token_release() {
    let deployment = deployment().await;
    fs::set_permissions(&deployment.audit_path, fs::Permissions::from_mode(0o400))
        .expect("make audit unwritable");
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));

    let (private, _, _) = key_pair(2);
    let assertion = sign_assertion(
        &private,
        &assertion_claims("service-desk", "jti-audit-down"),
    );
    let response = http.post("/token").form(&token_form(&assertion)).await;
    assert_eq!(response.status_code(), 500);
    assert_eq!(response.json::<Value>(), json!({"error": "server_error"}));

    let readiness = http.get("/ready").await;
    assert_eq!(readiness.status_code(), 503);
}

/// The other direction: an undelegated registration cannot obtain a subject
/// binding by asking for one.
#[tokio::test]
async fn mint_refuses_a_delegation_from_an_undelegated_client() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));

    let (private, _, _) = key_pair(2);
    let mut claims = assertion_claims("service-desk", "jti-1");
    claims[ON_BEHALF_OF_CLAIM] = json!({
        "actor": AGENT,
        "subject": {"given_name": "Amara", "family_name": "Okafor", "birth_date": "1998-04-02"},
    });
    let assertion = sign_assertion(&private, &claims);

    let response = http.post("/token").form(&token_form(&assertion)).await;
    assert_eq!(response.status_code(), 401);
    assert_eq!(response.json::<Value>(), json!({"error": "invalid_client"}));
}
